<?php

namespace RiloArbabillah\LaravelCrowdSec\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Database\Eloquent\Builder;
use RiloArbabillah\LaravelCrowdSec\Models\AuditLog;
use RiloArbabillah\LaravelCrowdSec\Models\BlockedIp;
use RiloArbabillah\LaravelCrowdSec\Models\IpBehavior;
use RiloArbabillah\LaravelCrowdSec\Models\SecurityEvent;

class CrowdSecCleanup extends Command
{
    protected $signature = 'crowdsec:cleanup
                           {--dry-run : Show what would be deleted without actually deleting}
                           {--expired : Clean up expired bans only}
                           {--old-events : Clean up old security events only}
                           {--old-behaviors : Clean up old behavior records only}
                           {--audit-logs : Clean up audit logs past the retention period only}';

    protected $description = 'Clean up expired bans, old events, and behavior records';

    protected const DELETE_CHUNK_SIZE = 1000;

    public function handle(): int
    {
        $dryRun = $this->option('dry-run');

        // If any specific option is set, only run those. Otherwise, run all.
        $anySpecific = $this->option('expired')
            || $this->option('old-events')
            || $this->option('old-behaviors')
            || $this->option('audit-logs');

        $cleanupExpired = ! $anySpecific || $this->option('expired');
        $cleanupEvents = ! $anySpecific || $this->option('old-events');
        $cleanupBehaviors = ! $anySpecific || $this->option('old-behaviors');
        $cleanupAuditLogs = (! $anySpecific || $this->option('audit-logs')) && $this->shouldCleanupAuditLogs();

        $totalCleaned = 0;
        $eventDays = $this->retentionDays('events_days');
        $behaviorDays = $this->retentionDays('behavior_days');
        $blockDays = $this->retentionDays('blocked_ips_days');
        $blockCountResetDays = $this->retentionDays('block_count_reset_days');

        // Clean up expired bans, then purge long-inactive block rows
        if ($cleanupExpired) {
            $expiredCount = BlockedIp::expired()->count();
            $inactiveBlocks = BlockedIp::where('is_active', false)->where('updated_at', '<', now()->subDays($blockDays));

            if ($dryRun) {
                $this->info("[DRY RUN] Would clean up {$expiredCount} expired bans");
                $this->info("[DRY RUN] Would delete {$inactiveBlocks->count()} inactive bans older than {$blockDays} days");
            } else {
                $deleted = BlockedIp::expired()->update(['is_active' => false]);
                $this->info("Cleaned up {$deleted} expired bans");
                $totalCleaned += $deleted;

                $purged = $this->deleteInChunks($inactiveBlocks);
                $this->info("Deleted {$purged} inactive bans older than {$blockDays} days");
                $totalCleaned += $purged;
            }
        }

        // Clean up old security events
        if ($cleanupEvents) {
            $oldEvents = SecurityEvent::where('created_at', '<', now()->subDays($eventDays));

            if ($dryRun) {
                $this->info("[DRY RUN] Would delete {$oldEvents->count()} old security events");
            } else {
                $deleted = $this->deleteInChunks($oldEvents);
                $this->info("Deleted {$deleted} old security events");
                $totalCleaned += $deleted;
            }
        }

        // Clean up old behavior records, and reset escalation for IPs not
        // blocked recently (a busy shared/NAT IP never goes inactive)
        if ($cleanupBehaviors) {
            $oldBehaviors = IpBehavior::where('last_activity', '<', now()->subDays($behaviorDays));
            $staleEscalation = $this->staleEscalationQuery($blockCountResetDays);

            if ($dryRun) {
                $this->info("[DRY RUN] Would delete {$oldBehaviors->count()} old behavior records");
                $this->info("[DRY RUN] Would reset block escalation for {$staleEscalation->count()} IPs");
            } else {
                $deleted = $this->deleteInChunks($oldBehaviors);
                $this->info("Deleted {$deleted} old behavior records");
                $totalCleaned += $deleted;

                $reset = $staleEscalation->update(['block_count' => 0]);
                $this->info("Reset block escalation for {$reset} IPs not blocked in {$blockCountResetDays} days");
                $totalCleaned += $reset;
            }
        }

        // Clean up old audit logs based on retention settings
        if ($cleanupAuditLogs) {
            $retentionDays = (int) config('crowdsec-scenarios.audit.retention_days', 365);
            $oldAuditLogs = AuditLog::where('created_at', '<', now()->subDays($retentionDays));

            if ($dryRun) {
                $this->info("[DRY RUN] Would delete {$oldAuditLogs->count()} audit log records older than {$retentionDays} days");
            } else {
                $deleted = $this->deleteInChunks($oldAuditLogs);
                $this->info("Deleted {$deleted} audit log records older than {$retentionDays} days");
                $totalCleaned += $deleted;
            }
        }

        if ($dryRun) {
            $this->warn('No changes were made (dry run mode)');
        } else {
            $this->info("Cleanup completed successfully! Total records processed: {$totalCleaned}");
        }

        return Command::SUCCESS;
    }

    protected function retentionDays(string $key): int
    {
        return max(1, (int) config("crowdsec-scenarios.retention.{$key}", 30));
    }

    /**
     * Delete in bounded batches so large tables are not locked by one long
     * DELETE.
     *
     * @param  Builder<covariant \Illuminate\Database\Eloquent\Model>  $query
     */
    protected function deleteInChunks(Builder $query): int
    {
        $total = 0;

        do {
            $deleted = (clone $query)->limit(self::DELETE_CHUNK_SIZE)->delete();
            $total += $deleted;
        } while ($deleted >= self::DELETE_CHUNK_SIZE);

        return $total;
    }

    /**
     * IPs with escalation whose block row was not refreshed within $days.
     *
     * @return Builder<IpBehavior>
     */
    protected function staleEscalationQuery(int $days): Builder
    {
        $behaviors = (new IpBehavior)->getTable();
        $blocks = (new BlockedIp)->getTable();

        return IpBehavior::where('block_count', '>', 0)
            ->whereNotExists(function ($query) use ($behaviors, $blocks, $days): void {
                $query->selectRaw('1')
                    ->from($blocks)
                    ->whereColumn("{$blocks}.ip", "{$behaviors}.ip")
                    ->where("{$blocks}.updated_at", '>=', now()->subDays($days));
            });
    }

    protected function shouldCleanupAuditLogs(): bool
    {
        return (bool) config('crowdsec-scenarios.audit.enabled', false);
    }
}

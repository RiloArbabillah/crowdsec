<?php

namespace RiloArbabillah\LaravelCrowdSec\Console\Commands;

use Illuminate\Console\Command;
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
                           {--old-behaviors : Clean up old behavior records only}';

    protected $description = 'Clean up expired bans, old events, and behavior records';

    public function handle(): int
    {
        $dryRun = $this->option('dry-run');

        // If any specific option is set, only run those. Otherwise, run all.
        $anySpecific = $this->option('expired')
            || $this->option('old-events')
            || $this->option('old-behaviors');

        $cleanupExpired = ! $anySpecific || $this->option('expired');
        $cleanupEvents = ! $anySpecific || $this->option('old-events');
        $cleanupBehaviors = ! $anySpecific || $this->option('old-behaviors');
        $cleanupAuditLogs = ! $anySpecific || $this->shouldCleanupAuditLogs();

        $totalCleaned = 0;

        // Clean up expired bans
        if ($cleanupExpired) {
            $expiredCount = BlockedIp::expired()->count();

            if ($dryRun) {
                $this->info("[DRY RUN] Would clean up {$expiredCount} expired bans");
            } else {
                $deleted = BlockedIp::expired()->update(['is_active' => false]);
                $this->info("Cleaned up {$deleted} expired bans");
                $totalCleaned += $deleted;
            }
        }

        // Clean up old security events (older than 30 days)
        if ($cleanupEvents) {
            $oldEventsCount = SecurityEvent::where('created_at', '<', now()->subDays(30))->count();

            if ($dryRun) {
                $this->info("[DRY RUN] Would delete {$oldEventsCount} old security events");
            } else {
                $deleted = SecurityEvent::where('created_at', '<', now()->subDays(30))->delete();
                $this->info("Deleted {$deleted} old security events");
                $totalCleaned += $deleted;
            }
        }

        // Clean up old behavior records (older than 30 days)
        if ($cleanupBehaviors) {
            $oldBehaviorsCount = IpBehavior::where('last_activity', '<', now()->subDays(30))->count();

            if ($dryRun) {
                $this->info("[DRY RUN] Would delete {$oldBehaviorsCount} old behavior records");
            } else {
                $deleted = IpBehavior::cleanup(30);
                $this->info("Deleted {$deleted} old behavior records");
                $totalCleaned += $deleted;
            }
        }

        // Clean up old audit logs based on retention settings
        if ($cleanupAuditLogs) {
            $retentionDays = (int) config('crowdsec-scenarios.audit.retention_days', 365);
            $cutoff = now()->subDays($retentionDays);
            $oldAuditLogCount = AuditLog::where('created_at', '<', $cutoff)->count();

            if ($dryRun) {
                $this->info("[DRY RUN] Would delete {$oldAuditLogCount} audit log records older than {$retentionDays} days");
            } else {
                $deleted = AuditLog::where('created_at', '<', $cutoff)->delete();
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

    protected function shouldCleanupAuditLogs(): bool
    {
        return (bool) config('crowdsec-scenarios.audit.enabled', false);
    }
}

<?php

namespace Simenawan\LaravelCrowdSec\Console\Commands;

use Illuminate\Console\Command;
use Simenawan\LaravelCrowdSec\Models\BlockedIp;
use Simenawan\LaravelCrowdSec\Models\IpBehavior;
use Simenawan\LaravelCrowdSec\Models\SecurityEvent;

class CrowdSecCleanup extends Command
{
    protected $signature = 'crowdsec:cleanup
                           {--dry-run : Show what would be deleted without actually deleting}
                           {--expired : Clean up expired bans}
                           {--old-events : Clean up old security events}
                           {--old-behaviors : Clean up old behavior records}';

    protected $description = 'Clean up expired bans, old events, and behavior records';

    public function handle(): int
    {
        $dryRun = $this->option('dry-run');

        // Default to true if option not specified, otherwise use the option value
        $cleanupExpired = ! $this->hasOption('expired') || $this->option('expired');
        $cleanupEvents = ! $this->hasOption('old-events') || $this->option('old-events');
        $cleanupBehaviors = ! $this->hasOption('old-behaviors') || $this->option('old-behaviors');

        // Clean up expired bans
        if ($cleanupExpired) {
            $expiredCount = BlockedIp::expired()->count();

            if ($dryRun) {
                $this->info("[DRY RUN] Would clean up {$expiredCount} expired bans");
            } else {
                $deleted = BlockedIp::expired()->update(['is_active' => false]);
                $this->info("Cleaned up {$deleted} expired bans");
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
            }
        }

        if (! $dryRun) {
            $this->info('Cleanup completed successfully!');
        }

        return Command::SUCCESS;
    }
}

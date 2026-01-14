<?php

namespace Simenawan\LaravelCrowdSec\Console\Commands;

use Illuminate\Console\Command;
use Simenawan\LaravelCrowdSec\Models\BlockedIp;
use Simenawan\LaravelCrowdSec\Models\SecurityEvent;

class CrowdSecStats extends Command
{
    protected $signature = 'crowdsec:stats
                           {--json : Output as JSON}';

    protected $description = 'Display CrowdSec protection statistics';

    public function handle(): int
    {
        $asJson = $this->option('json');

        $stats = $this->getStats();

        if ($asJson) {
            $this->output->writeln(json_encode($stats, JSON_PRETTY_PRINT));
        } else {
            $this->displayStats($stats);
        }

        return Command::SUCCESS;
    }

    protected function getStats(): array
    {
        return [
            'blocked_ips' => [
                'active' => BlockedIp::active()->count(),
                'expired' => BlockedIp::expired()->count(),
                'expiring_soon' => BlockedIp::expiringSoon()->count(),
            ],
            'events' => [
                'today' => SecurityEvent::whereDate('created_at', today())->count(),
                'week' => SecurityEvent::where('created_at', '>=', now()->subWeek())->count(),
                'month' => SecurityEvent::where('created_at', '>=', now()->subMonth())->count(),
            ],
            'threats' => [
                'sql_injection' => SecurityEvent::where('event_type', 'like', '%sql_injection%')->where('created_at', '>=', now()->subDay())->count(),
                'xss' => SecurityEvent::where('event_type', 'like', '%xss%')->where('created_at', '>=', now()->subDay())->count(),
                'path_traversal' => SecurityEvent::where('event_type', 'like', '%path_traversal%')->where('created_at', '>=', now()->subDay())->count(),
                'brute_force' => SecurityEvent::where('event_type', 'like', '%brute_force%')->where('created_at', '>=', now()->subDay())->count(),
                'behavior_threshold' => SecurityEvent::where('event_type', 'like', '%behavior_threshold%')->where('created_at', '>=', now()->subDay())->count(),
            ],
            'top_attackers' => SecurityEvent::selectRaw('ip, COUNT(*) as count')
                ->where('created_at', '>=', now()->subDay())
                ->groupBy('ip')
                ->orderByDesc('count')
                ->limit(10)
                ->get()
                ->map(fn ($item) => ['ip' => $item->ip, 'count' => $item->count])
                ->values()
                ->toArray(),
        ];
    }

    protected function displayStats(array $stats): void
    {
        $this->info('=== CrowdSec Protection Statistics ===');
        $this->newLine();

        // Blocked IPs
        $this->info('Blocked IPs:');
        $this->line("  Active: {$stats['blocked_ips']['active']}");
        $this->line("  Expired: {$stats['blocked_ips']['expired']}");
        $this->line("  Expiring soon: {$stats['blocked_ips']['expiring_soon']}");
        $this->newLine();

        // Events
        $this->info('Security Events:');
        $this->line("  Today: {$stats['events']['today']}");
        $this->line("  This week: {$stats['events']['week']}");
        $this->line("  This month: {$stats['events']['month']}");
        $this->newLine();

        // Threats today
        $this->info('Threats Detected Today:');
        foreach ($stats['threats'] as $threat => $count) {
            $this->line('  '.ucfirst(str_replace('_', ' ', $threat)).": {$count}");
        }
        $this->newLine();

        // Top attackers
        $this->info('Top 10 Attackers (Last 24h):');
        $i = 1;
        foreach ($stats['top_attackers'] as $item) {
            $this->line("  {$i}. {$item['ip']} - {$item['count']} events");
            $i++;
        }
    }
}

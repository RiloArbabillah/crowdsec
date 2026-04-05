<?php

namespace RiloArbabillah\LaravelCrowdSec\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use RiloArbabillah\LaravelCrowdSec\Services\CrowdSecService;

class CrowdSecDoctor extends Command
{
    protected $signature = 'crowdsec:doctor
                           {--json : Output results as JSON for CI integration}';

    protected $description = 'Run health checks on CrowdSec configuration, database, and services';

    protected array $results = [];

    protected int $score = 100;

    public function handle(): int
    {
        $this->runAllChecks();

        if ($this->option('json')) {
            $this->outputJson();
        } else {
            $this->outputTable();
        }

        return $this->score >= 70 ? self::SUCCESS : self::FAILURE;
    }

    public function runAllChecks(): void
    {
        $this->results = [];
        $this->score = 100;

        $this->checkPackageEnabled();
        $this->checkDatabaseMigrations();
        $this->checkRegexPatterns();
        $this->checkCacheConnection();
        $this->checkNotifications();
        $this->checkGeoIpProvider();
        $this->checkApiConfig();
        $this->checkDashboardConfig();
        $this->checkWhitelist();
        $this->checkLoginRoutes();
        $this->checkHoneypotRoutes();
        $this->checkBlockedMethods();
    }

    public function getResults(): array
    {
        return $this->results;
    }

    public function getScore(): int
    {
        return $this->score;
    }

    protected function checkPackageEnabled(): void
    {
        $enabled = config('crowdsec-scenarios.enabled', false);
        $this->addResult(
            'Package status',
            $enabled ? 'pass' : 'warn',
            $enabled ? 'Enabled' : 'Disabled — WAF protection is off',
            $enabled ? 0 : 10,
        );
    }

    protected function checkDatabaseMigrations(): void
    {
        $tables = ['blocked_ips', 'ip_behaviors', 'security_events'];
        $found = 0;

        foreach ($tables as $table) {
            if (Schema::hasTable($table)) {
                $found++;
            }
        }

        $total = count($tables);
        if ($found === $total) {
            $this->addResult('Database migrations', 'pass', "{$found}/{$total} tables found");
        } else {
            $missing = array_filter($tables, fn ($t) => ! Schema::hasTable($t));
            $this->addResult(
                'Database migrations',
                'fail',
                "Missing tables: " . implode(', ', $missing),
                20,
            );
        }
    }

    protected function checkRegexPatterns(): void
    {
        $scenarios = config('crowdsec-scenarios', []);
        $nonScenarioKeys = CrowdSecService::NON_SCENARIO_KEYS;
        $totalPatterns = 0;
        $errors = 0;
        $errorPatterns = [];

        foreach ($scenarios as $name => $config) {
            if (in_array($name, $nonScenarioKeys) || ! isset($config['patterns'])) {
                continue;
            }

            foreach ($config['patterns'] as $pattern) {
                $totalPatterns++;
                if (@preg_match($pattern, '') === false) {
                    $errors++;
                    $errorPatterns[] = "{$name}: {$pattern}";
                }
            }
        }

        if ($errors === 0) {
            $this->addResult('Regex patterns', 'pass', "{$totalPatterns} patterns, 0 errors");
        } else {
            $this->addResult(
                'Regex patterns',
                'fail',
                "{$errors} invalid patterns: " . implode('; ', array_slice($errorPatterns, 0, 3)),
                15,
            );
        }
    }

    protected function checkCacheConnection(): void
    {
        $enabled = config('crowdsec-scenarios.cache.enabled', false);

        if (! $enabled) {
            $this->addResult('Cache layer', 'warn', 'Disabled — enable for better performance', 5);
            return;
        }

        try {
            $store = config('crowdsec-scenarios.cache.store');
            $cache = $store ? Cache::store($store) : Cache::store();
            $cache->put('crowdsec:doctor:test', true, 5);
            $cache->forget('crowdsec:doctor:test');

            $driver = $store ?? config('cache.default');
            $this->addResult('Cache layer', 'pass', "Working (driver: {$driver})");
        } catch (\Throwable $e) {
            $this->addResult('Cache layer', 'fail', 'Connection error: ' . $e->getMessage(), 10);
        }
    }

    protected function checkNotifications(): void
    {
        $enabled = config('crowdsec-scenarios.notifications.enabled', false);

        if (! $enabled) {
            $this->addResult('Notifications', 'warn', 'Disabled — no alerts on threats', 5);
            return;
        }

        $channels = collect(config('crowdsec-scenarios.notifications.channels', ['mail']))
            ->map(fn ($channel) => strtolower(trim((string) $channel)))
            ->filter()
            ->unique()
            ->values();

        if ($channels->isEmpty()) {
            $this->addResult('Notifications', 'fail', 'Enabled but no notification channels configured', 10);
            return;
        }

        $recipients = collect(config('crowdsec-scenarios.notifications.recipients', []))
            ->map(fn ($recipient) => trim((string) $recipient))
            ->filter()
            ->values();

        $issues = [];

        if ($channels->contains('mail') && $recipients->isEmpty()) {
            $issues[] = 'Mail channel enabled but no recipients configured';
        }

        if ($channels->contains('slack')
            && trim((string) config('crowdsec-scenarios.notifications.slack_webhook_url', '')) === '') {
            $issues[] = 'Slack channel enabled but no webhook URL configured';
        }

        if (! empty($issues)) {
            $this->addResult('Notifications', 'fail', implode(' — ', $issues), 10);
            return;
        }

        $this->addResult(
            'Notifications',
            'pass',
            'Channels: ' . $channels->implode(', ') . ' — ' . $recipients->count() . ' mail recipient(s)',
        );
    }

    protected function checkGeoIpProvider(): void
    {
        $enabled = config('crowdsec-scenarios.geoip.enabled', false);

        if (! $enabled) {
            $this->addResult('GeoIP lookup', 'info', 'Disabled');
            return;
        }

        $provider = config('crowdsec-scenarios.geoip.provider', 'ip-api');
        $this->addResult('GeoIP lookup', 'pass', "Provider: {$provider}");
    }

    protected function checkApiConfig(): void
    {
        $enabled = config('crowdsec-scenarios.api.enabled', false);

        if (! $enabled) {
            $this->addResult('REST API', 'info', 'Disabled');
            return;
        }

        $middleware = config('crowdsec-scenarios.api.middleware', []);
        $hasAuth = collect($middleware)->contains(fn ($m) => str_contains($m, 'auth'));

        if (! $hasAuth) {
            $this->addResult('REST API', 'warn', 'Enabled without auth middleware — add auth:sanctum for production', 10);
        } else {
            $this->addResult('REST API', 'pass', 'Enabled with auth middleware');
        }
    }

    protected function checkDashboardConfig(): void
    {
        $enabled = config('crowdsec-scenarios.dashboard.enabled', false);

        if (! $enabled) {
            $this->addResult('Dashboard', 'info', 'Disabled');
            return;
        }

        $middleware = config('crowdsec-scenarios.dashboard.middleware', []);
        $path = config('crowdsec-scenarios.dashboard.path', 'crowdsec');
        $hasAuth = collect($middleware)->contains(fn ($m) => str_contains($m, 'auth'));

        if (! $hasAuth) {
            $this->addResult('Dashboard', 'warn', "Enabled at /{$path} without auth middleware", 10);
        } else {
            $this->addResult('Dashboard', 'pass', "Enabled at /{$path} with auth");
        }
    }

    protected function checkWhitelist(): void
    {
        $whitelist = config('crowdsec-scenarios.whitelist_ips', []);

        if (empty($whitelist)) {
            $this->addResult('Whitelist', 'warn', 'Empty — consider adding trusted IPs', 5);
        } elseif (count($whitelist) <= 2) {
            $this->addResult('Whitelist', 'pass', count($whitelist) . ' IP(s) — consider adding trusted proxies');
        } else {
            $this->addResult('Whitelist', 'pass', count($whitelist) . ' IP(s) configured');
        }
    }

    protected function checkLoginRoutes(): void
    {
        $routes = config('crowdsec-scenarios.login_routes', []);
        if (empty($routes)) {
            $this->addResult('Login routes', 'warn', 'No login routes configured for brute-force protection', 5);
        } else {
            $this->addResult('Login routes', 'pass', count($routes) . ' route(s) protected');
        }
    }

    protected function checkHoneypotRoutes(): void
    {
        $routes = config('crowdsec-scenarios.honeypot_routes', []);
        if (empty($routes)) {
            $this->addResult('Honeypot routes', 'warn', 'No honeypot traps configured', 3);
        } else {
            $this->addResult('Honeypot routes', 'pass', count($routes) . ' trap(s) active');
        }
    }

    protected function checkBlockedMethods(): void
    {
        $methods = config('crowdsec-scenarios.blocked_methods', []);
        if (empty($methods)) {
            $this->addResult('Blocked methods', 'warn', 'No HTTP methods blocked', 3);
        } else {
            $this->addResult('Blocked methods', 'pass', 'Blocking: ' . implode(', ', $methods));
        }
    }

    // =========================================================================

    protected function addResult(string $check, string $status, string $message, int $penalty = 0): void
    {
        $this->results[] = [
            'check' => $check,
            'status' => $status,
            'message' => $message,
        ];
        $this->score = max(0, $this->score - $penalty);
    }

    protected function outputTable(): void
    {
        $this->newLine();
        $this->line('  🏥 <fg=cyan;options=bold>CrowdSec Doctor — Health Check</>');
        $this->line('  ' . str_repeat('═', 50));
        $this->newLine();

        foreach ($this->results as $result) {
            $icon = match ($result['status']) {
                'pass' => '  <fg=green>✅</>',
                'warn' => '  <fg=yellow>⚠️ </>',
                'fail' => '  <fg=red>❌</>',
                'info' => '  <fg=blue>ℹ️ </>',
            };
            $this->line("{$icon} <options=bold>{$result['check']}:</> {$result['message']}");
        }

        $this->newLine();
        $this->line('  ' . str_repeat('─', 50));

        $scoreColor = match (true) {
            $this->score >= 90 => 'green',
            $this->score >= 70 => 'yellow',
            default => 'red',
        };
        $this->line("  <fg={$scoreColor};options=bold>Security Score: {$this->score}/100</>");

        $recommendations = $this->getRecommendations();
        if (! empty($recommendations)) {
            $this->newLine();
            $this->line('  <fg=cyan>Recommendations:</>');
            foreach ($recommendations as $rec) {
                $this->line("    → {$rec}");
            }
        }

        $this->newLine();
    }

    protected function outputJson(): void
    {
        $this->info(json_encode([
            'score' => $this->score,
            'checks' => $this->results,
            'recommendations' => $this->getRecommendations(),
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
    }

    protected function getRecommendations(): array
    {
        $recs = [];

        foreach ($this->results as $result) {
            if ($result['status'] === 'warn' || $result['status'] === 'fail') {
                $recs[] = $result['message'];
            }
        }

        return $recs;
    }
}

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

    /** @var list<array{check: string, status: string, message: string}> */
    protected array $results = [];

    protected int $score = 100;

    protected bool $hasFailures = false;

    public function handle(): int
    {
        $this->runAllChecks();

        if ($this->option('json')) {
            $this->outputJson();
        } else {
            $this->outputTable();
        }

        return ! $this->hasFailures && $this->score >= 70 ? self::SUCCESS : self::FAILURE;
    }

    public function runAllChecks(): void
    {
        $this->results = [];
        $this->score = 100;
        $this->hasFailures = false;

        $this->checkPackageEnabled();
        $this->checkDatabaseMigrations();
        $this->checkRegexPatterns();
        $this->checkWafConfig();
        $this->checkCacheConnection();
        $this->checkNotifications();
        $this->checkGeoIpProvider();
        $this->checkApiConfig();
        $this->checkMetricsConfig();
        $this->checkDashboardConfig();
        $this->checkWhitelist();
        $this->checkLoginRoutes();
        $this->checkHoneypotRoutes();
        $this->checkBlockedMethods();
    }

    /** @return list<array{check: string, status: string, message: string}> */
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
        $tables = ['blocked_ips', 'ip_behaviors', 'security_events', 'whitelisted_ips'];
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

        $configuredChannels = config('crowdsec-scenarios.notifications.channels', ['mail']);
        $channels = collect(is_array($configuredChannels) ? $configuredChannels : [])
            ->map(fn ($channel) => strtolower(trim((string) $channel)))
            ->filter()
            ->unique()
            ->values();

        if ($channels->isEmpty()) {
            $this->addResult('Notifications', 'fail', 'Enabled but no notification channels configured', 10);
            return;
        }

        $configuredRecipients = config('crowdsec-scenarios.notifications.recipients', []);
        $recipients = collect(is_array($configuredRecipients) ? $configuredRecipients : [])
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

        $provider = strtolower((string) config('crowdsec-scenarios.geoip.provider', 'ipwhois'));

        if (! in_array($provider, ['ipwhois', 'ip-api', 'custom'], true)) {
            $this->addResult('GeoIP lookup', 'fail', "Unsupported provider: {$provider}", 10);
        } elseif ($provider === 'ip-api') {
            $this->addResult('GeoIP lookup', 'warn', 'Legacy ip-api provider uses unencrypted HTTP; migrate to ipwhois', 5);
        } elseif ($provider === 'custom' && ! is_callable(config('crowdsec-scenarios.geoip.custom_callback'))) {
            $this->addResult('GeoIP lookup', 'fail', 'Custom provider requires a callable custom_callback', 10);
        } else {
            $this->addResult('GeoIP lookup', 'pass', "Provider: {$provider}");
        }
    }

    protected function checkWafConfig(): void
    {
        $configuredWaf = config('crowdsec-scenarios.waf', []);
        $waf = is_array($configuredWaf) ? $configuredWaf : [];
        $validModes = \RiloArbabillah\LaravelCrowdSec\Services\WafPolicy::VALID_MODES;
        $invalid = is_array($configuredWaf) ? [] : ['waf must be an array'];

        $defaultMode = strtolower((string) ($waf['default_mode'] ?? 'enforce'));
        if (! in_array($defaultMode, $validModes, true)) {
            $invalid[] = "default_mode={$defaultMode}";
        }

        $scenarioModes = is_array($waf['scenario_modes'] ?? null) ? $waf['scenario_modes'] : [];
        if (isset($waf['scenario_modes']) && ! is_array($waf['scenario_modes'])) {
            $invalid[] = 'scenario_modes must be an array';
        }

        foreach ($scenarioModes as $scenario => $mode) {
            if (! in_array(strtolower((string) $mode), $validModes, true)) {
                $invalid[] = "scenario_modes.{$scenario}={$mode}";
            }
        }

        foreach (config('crowdsec-scenarios', []) as $scenario => $scenarioConfig) {
            if (! is_array($scenarioConfig) || ! array_key_exists('mode', $scenarioConfig)) {
                continue;
            }

            if (! in_array(strtolower((string) $scenarioConfig['mode']), $validModes, true)) {
                $invalid[] = "{$scenario}.mode={$scenarioConfig['mode']}";
            }
        }

        $exclusions = is_array($waf['exclusions'] ?? null) ? $waf['exclusions'] : [];
        if (isset($waf['exclusions']) && ! is_array($waf['exclusions'])) {
            $invalid[] = 'exclusions must be an array';
        }

        foreach ($exclusions as $index => $rule) {
            if (! is_array($rule)) {
                $invalid[] = "exclusions.{$index} must be an array";
                continue;
            }

            foreach (['route_names', 'paths', 'methods', 'skip_scenarios', 'ignore_body_fields'] as $key) {
                if (isset($rule[$key]) && ! is_array($rule[$key])) {
                    $invalid[] = "exclusions.{$index}.{$key} must be an array";
                }
            }

            $hasEffect = (is_array($rule['skip_scenarios'] ?? null) && ! empty($rule['skip_scenarios']))
                || (is_array($rule['ignore_body_fields'] ?? null) && ! empty($rule['ignore_body_fields']));
            if (! $hasEffect) {
                $invalid[] = "exclusions.{$index} has no effect";
            }

            foreach (is_array($rule['methods'] ?? null) ? $rule['methods'] : [] as $method) {
                if (preg_match('/\A[A-Z]+\z/', strtoupper((string) $method)) !== 1) {
                    $invalid[] = "exclusions.{$index} has invalid method";
                    break;
                }
            }
        }

        if ($invalid === []) {
            $this->addResult('WAF policy', 'pass', 'Modes and exclusions are valid');
        } else {
            $this->addResult('WAF policy', 'fail', implode('; ', $invalid), 10);
        }
    }

    protected function checkApiConfig(): void
    {
        $enabled = config('crowdsec-scenarios.api.enabled', false);

        if (! $enabled) {
            $this->addResult('REST API', 'info', 'Disabled');
            return;
        }

        $middleware = $this->normalizedMiddleware(config('crowdsec-scenarios.api.middleware', []));
        $hasAuth = $this->hasAuthMiddleware($middleware);

        if (! $hasAuth) {
            $this->addResult('REST API', 'fail', 'Enabled without auth middleware — add auth:sanctum or another authenticated guard', 15);
        } else {
            $this->addResult('REST API', 'pass', 'Enabled with middleware: ' . implode(', ', $middleware));
        }
    }

    protected function checkMetricsConfig(): void
    {
        $enabled = config('crowdsec-scenarios.metrics.enabled', false);

        if (! $enabled) {
            $this->addResult('Metrics', 'info', 'Disabled');
            return;
        }

        $middleware = $this->normalizedMiddleware(config('crowdsec-scenarios.metrics.middleware', []));
        $hasAuth = $this->hasAuthMiddleware($middleware);
        $hasSigned = collect($middleware)->contains('signed');

        if (! $hasAuth && ! $hasSigned) {
            $this->addResult('Metrics', 'fail', 'Enabled without auth or signed middleware — restrict access before exposing metrics', 15);
        } else {
            $this->addResult('Metrics', 'pass', 'Enabled with middleware: ' . implode(', ', $middleware));
        }
    }

    protected function checkDashboardConfig(): void
    {
        $enabled = config('crowdsec-scenarios.dashboard.enabled', false);

        if (! $enabled) {
            $this->addResult('Dashboard', 'info', 'Disabled');
            return;
        }

        $middleware = $this->normalizedMiddleware(config('crowdsec-scenarios.dashboard.middleware', []));
        $path = config('crowdsec-scenarios.dashboard.path', 'crowdsec');
        $hasAuth = $this->hasAuthMiddleware($middleware);

        if (! $hasAuth) {
            $this->addResult('Dashboard', 'fail', "Enabled at /{$path} without auth middleware", 15);
        } else {
            $this->addResult('Dashboard', 'pass', "Enabled at /{$path} with middleware: " . implode(', ', $middleware));
        }
    }

    protected function checkWhitelist(): void
    {
        $configWhitelist = config('crowdsec-scenarios.whitelist_ips', []);
        $configCount = is_array($configWhitelist) ? count($configWhitelist) : 0;

        $dbCount = 0;
        $anonymousCount = 0;
        if (Schema::hasTable('whitelisted_ips')) {
            $dbCount = (int) DB::table('whitelisted_ips')
                ->where('is_active', true)
                ->where(function ($q) {
                    $q->whereNull('expires_at')->orWhere('expires_at', '>', now());
                })
                ->count();
            $anonymousCount = (int) DB::table('whitelisted_ips')
                ->where('is_active', true)
                ->where(function ($q) {
                    $q->whereNull('label')->orWhere('label', '');
                })
                ->where(function ($q) {
                    $q->whereNull('note')->orWhere('note', '');
                })
                ->count();
        }

        $total = $configCount + $dbCount;

        if ($total === 0) {
            $this->addResult('Whitelist', 'warn', 'Empty — consider adding trusted IPs', 5);
        } else {
            $message = "{$total} active IP(s): {$configCount} from config, {$dbCount} dynamic (DB)";
            $this->addResult('Whitelist', 'pass', $message);
        }

        if ($anonymousCount > 0) {
            $this->addResult(
                'Whitelist labels',
                'warn',
                "{$anonymousCount} dynamic entry(ies) have no label/note — add context for audit clarity",
                3,
            );
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

        if ($status === 'fail') {
            $this->hasFailures = true;
        }

        $this->score = max(0, $this->score - $penalty);
    }

    /**
     * @param array<array-key, mixed> $middleware
     * @return list<string>
     */
    protected function normalizedMiddleware(array $middleware): array
    {
        return collect($middleware)
            ->map(fn ($item) => trim((string) $item))
            ->filter()
            ->values()
            ->all();
    }

    /** @param list<string> $middleware */
    protected function hasAuthMiddleware(array $middleware): bool
    {
        return collect($middleware)->contains(fn ($item) => str_contains($item, 'auth'));
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
                default => '  <fg=blue>ℹ️ </>',
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

    /** @return list<string> */
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

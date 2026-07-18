<?php

namespace RiloArbabillah\LaravelCrowdSec\Tests\Feature;

use Orchestra\Testbench\TestCase;
use RiloArbabillah\LaravelCrowdSec\CrowdSecServiceProvider;

class DoctorCommandTest extends TestCase
{
    protected function getPackageProviders($app): array
    {
        return [CrowdSecServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        $app['config']->set(
            'crowdsec-scenarios',
            require __DIR__ . '/../../config/crowdsec-scenarios.php'
        );

        $app['config']->set('database.default', 'testing');
        $app['config']->set('database.connections.testing', [
            'driver' => 'sqlite',
            'database' => ':memory:',
            'prefix' => '',
        ]);
    }

    protected function setUp(): void
    {
        parent::setUp();
        $this->loadMigrationsFrom(__DIR__ . '/../../src/Database/Migrations');
    }

    public function test_doctor_command_runs_successfully(): void
    {
        $this->artisan('crowdsec:doctor')
            ->assertSuccessful();
    }

    public function test_doctor_command_outputs_health_check_header(): void
    {
        $this->artisan('crowdsec:doctor')
            ->expectsOutputToContain('CrowdSec Doctor')
            ->assertSuccessful();
    }

    public function test_doctor_command_checks_database_migrations(): void
    {
        $this->artisan('crowdsec:doctor')
            ->expectsOutputToContain('3/3 tables found')
            ->assertSuccessful();
    }

    public function test_doctor_command_checks_regex_patterns(): void
    {
        $this->artisan('crowdsec:doctor')
            ->expectsOutputToContain('patterns, 0 errors')
            ->assertSuccessful();
    }

    public function test_doctor_command_checks_whitelist(): void
    {
        $this->artisan('crowdsec:doctor')
            ->expectsOutputToContain('Whitelist')
            ->assertSuccessful();
    }

    public function test_doctor_command_checks_login_routes(): void
    {
        $this->artisan('crowdsec:doctor')
            ->expectsOutputToContain('route(s) protected')
            ->assertSuccessful();
    }

    public function test_doctor_command_checks_honeypot_routes(): void
    {
        $this->artisan('crowdsec:doctor')
            ->expectsOutputToContain('trap(s) active')
            ->assertSuccessful();
    }

    public function test_doctor_command_checks_blocked_methods(): void
    {
        $this->artisan('crowdsec:doctor')
            ->expectsOutputToContain('TRACE, CONNECT')
            ->assertSuccessful();
    }

    public function test_doctor_command_shows_security_score(): void
    {
        $this->artisan('crowdsec:doctor')
            ->expectsOutputToContain('Security Score:')
            ->assertSuccessful();
    }

    public function test_doctor_command_json_flag_runs_successfully(): void
    {
        $this->artisan('crowdsec:doctor', ['--json' => true])
            ->assertSuccessful();
    }

    public function test_doctor_command_results_contain_expected_keys(): void
    {
        $doctor = new \RiloArbabillah\LaravelCrowdSec\Console\Commands\CrowdSecDoctor();
        $doctor->setLaravel($this->app);
        $doctor->runAllChecks();

        $results = $doctor->getResults();
        $this->assertNotEmpty($results);
        $this->assertArrayHasKey('score', ['score' => $doctor->getScore()]);

        // Every check has required fields
        foreach ($results as $check) {
            $this->assertArrayHasKey('check', $check);
            $this->assertArrayHasKey('status', $check);
            $this->assertArrayHasKey('message', $check);
        }
    }

    public function test_doctor_command_detects_disabled_package(): void
    {
        config(['crowdsec-scenarios.enabled' => false]);

        $this->artisan('crowdsec:doctor')
            ->expectsOutputToContain('Disabled')
            ->assertSuccessful();
    }

    public function test_doctor_command_detects_disabled_notifications(): void
    {
        config(['crowdsec-scenarios.notifications.enabled' => false]);

        $this->artisan('crowdsec:doctor')
            ->expectsOutputToContain('Notifications')
            ->assertSuccessful();
    }

    public function test_doctor_command_detects_slack_without_webhook(): void
    {
        config([
            'crowdsec-scenarios.notifications.enabled' => true,
            'crowdsec-scenarios.notifications.channels' => ['slack'],
            'crowdsec-scenarios.notifications.recipients' => [],
            'crowdsec-scenarios.notifications.slack_webhook_url' => '',
        ]);

        $this->artisan('crowdsec:doctor')
            ->expectsOutputToContain('Slack channel enabled but no webhook URL configured')
            ->assertFailed();
    }

    public function test_doctor_command_detects_api_without_auth(): void
    {
        config([
            'crowdsec-scenarios.api.enabled' => true,
            'crowdsec-scenarios.api.middleware' => ['api'],
        ]);

        $this->artisan('crowdsec:doctor')
            ->expectsOutputToContain('without auth middleware')
            ->assertFailed();
    }

    public function test_doctor_command_detects_metrics_without_protection(): void
    {
        config([
            'crowdsec-scenarios.metrics.enabled' => true,
            'crowdsec-scenarios.metrics.middleware' => ['api'],
        ]);

        $this->artisan('crowdsec:doctor')
            ->expectsOutputToContain('without auth or signed middleware')
            ->assertFailed();
    }

    public function test_doctor_command_accepts_signed_metrics_route(): void
    {
        config([
            'crowdsec-scenarios.metrics.enabled' => true,
            'crowdsec-scenarios.metrics.middleware' => ['signed'],
        ]);

        $this->artisan('crowdsec:doctor')
            ->expectsOutputToContain('Metrics')
            ->assertSuccessful();
    }

    public function test_doctor_command_detects_dashboard_without_auth(): void
    {
        config([
            'crowdsec-scenarios.dashboard.enabled' => true,
            'crowdsec-scenarios.dashboard.middleware' => ['web'],
        ]);

        $this->artisan('crowdsec:doctor')
            ->expectsOutputToContain('without auth middleware')
            ->assertFailed();
    }

    public function test_secure_endpoint_defaults_require_authentication(): void
    {
        $this->assertSame(['api', 'auth:sanctum'], config('crowdsec-scenarios.api.middleware'));
        $this->assertSame(['web', 'auth'], config('crowdsec-scenarios.metrics.middleware'));
        $this->assertSame(['web', 'auth'], config('crowdsec-scenarios.dashboard.middleware'));
    }

    public function test_doctor_command_score_is_valid_range(): void
    {
        $doctor = new \RiloArbabillah\LaravelCrowdSec\Console\Commands\CrowdSecDoctor();
        $doctor->setLaravel($this->app);
        $doctor->runAllChecks();

        $score = $doctor->getScore();
        $this->assertGreaterThanOrEqual(0, $score);
        $this->assertLessThanOrEqual(100, $score);
    }

    public function test_doctor_rejects_invalid_waf_mode_and_empty_exclusion(): void
    {
        config([
            'crowdsec-scenarios.waf.default_mode' => 'invalid',
            'crowdsec-scenarios.waf.exclusions' => [['paths' => ['example']]],
            'crowdsec-scenarios.sql_injection.mode' => 'also-invalid',
        ]);

        $this->artisan('crowdsec:doctor')
            ->expectsOutputToContain('WAF policy')
            ->assertFailed();
    }

    public function test_doctor_warns_for_legacy_http_geoip_provider(): void
    {
        config([
            'crowdsec-scenarios.geoip.enabled' => true,
            'crowdsec-scenarios.geoip.provider' => 'ip-api',
        ]);

        $this->artisan('crowdsec:doctor')
            ->expectsOutputToContain('unencrypted HTTP')
            ->assertSuccessful();
    }

    public function test_doctor_rejects_unknown_geoip_provider(): void
    {
        config([
            'crowdsec-scenarios.geoip.enabled' => true,
            'crowdsec-scenarios.geoip.provider' => 'unknown',
        ]);

        $this->artisan('crowdsec:doctor')
            ->expectsOutputToContain('Unsupported provider')
            ->assertFailed();
    }

    public function test_doctor_rejects_non_array_waf_config(): void
    {
        config(['crowdsec-scenarios.waf' => 'invalid']);

        $this->artisan('crowdsec:doctor')
            ->expectsOutputToContain('waf must be an array')
            ->assertFailed();
    }

    public function test_doctor_command_has_minimum_12_checks(): void
    {
        $doctor = new \RiloArbabillah\LaravelCrowdSec\Console\Commands\CrowdSecDoctor();
        $doctor->setLaravel($this->app);
        $doctor->runAllChecks();

        $results = $doctor->getResults();
        $this->assertGreaterThanOrEqual(13, count($results), 'Should run at least 13 health checks');
    }
}

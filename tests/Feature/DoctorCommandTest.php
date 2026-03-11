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

    public function test_doctor_command_json_output(): void
    {
        \Illuminate\Support\Facades\Artisan::call('crowdsec:doctor', ['--json' => true]);
        $raw = \Illuminate\Support\Facades\Artisan::output();

        $json = json_decode($raw, true);
        $this->assertNotNull($json, 'Output should be valid JSON. Raw: ' . substr($raw, 0, 200));
        $this->assertArrayHasKey('score', $json);
        $this->assertArrayHasKey('checks', $json);
        $this->assertArrayHasKey('recommendations', $json);
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

    public function test_doctor_command_detects_api_without_auth(): void
    {
        config([
            'crowdsec-scenarios.api.enabled' => true,
            'crowdsec-scenarios.api.middleware' => ['api'],
        ]);

        $this->artisan('crowdsec:doctor')
            ->expectsOutputToContain('without auth middleware')
            ->assertSuccessful();
    }

    public function test_doctor_command_json_has_valid_structure(): void
    {
        \Illuminate\Support\Facades\Artisan::call('crowdsec:doctor', ['--json' => true]);
        $raw = \Illuminate\Support\Facades\Artisan::output();

        $json = json_decode($raw, true);
        $this->assertNotNull($json);
        $this->assertIsInt($json['score']);
        $this->assertGreaterThanOrEqual(0, $json['score']);
        $this->assertLessThanOrEqual(100, $json['score']);
        $this->assertNotEmpty($json['checks']);

        // Verify each check has required fields
        foreach ($json['checks'] as $check) {
            $this->assertArrayHasKey('check', $check);
            $this->assertArrayHasKey('status', $check);
            $this->assertArrayHasKey('message', $check);
        }
    }
}

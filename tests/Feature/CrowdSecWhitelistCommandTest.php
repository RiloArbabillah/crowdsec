<?php

namespace RiloArbabillah\LaravelCrowdSec\Tests\Feature;

use RiloArbabillah\LaravelCrowdSec\Models\WhitelistedIp;
use RiloArbabillah\LaravelCrowdSec\Services\CrowdSecService;
use RiloArbabillah\LaravelCrowdSec\Tests\PackageTestCase;

class CrowdSecWhitelistCommandTest extends PackageTestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        $this->loadMigrationsFrom(__DIR__ . '/../../src/Database/Migrations');
    }

    public function test_list_command_reports_no_entries_initially(): void
    {
        $this->artisan('crowdsec:whitelist', ['action' => 'list'])
            ->expectsOutputToContain('No dynamic whitelist entries.')
            ->assertSuccessful();
    }

    public function test_add_command_creates_entry(): void
    {
        $this->artisan('crowdsec:whitelist', [
            'action' => 'add',
            'ip' => '10.0.0.0/8',
            '--label' => 'Office VPN',
        ])->expectsOutputToContain('Whitelisted: 10.0.0.0/8 (Office VPN)')
            ->assertSuccessful();

        $this->assertDatabaseHas('whitelisted_ips', [
            'ip' => '10.0.0.0/8',
            'label' => 'Office VPN',
            'is_active' => 1,
        ]);
    }

    public function test_add_command_rejects_invalid_ip(): void
    {
        $this->artisan('crowdsec:whitelist', [
            'action' => 'add',
            'ip' => 'not-an-ip',
        ])->expectsOutputToContain('Invalid IP or CIDR')
            ->assertExitCode(2);

        $this->assertDatabaseCount('whitelisted_ips', 0);
    }

    public function test_add_command_requires_ip_argument(): void
    {
        $this->artisan('crowdsec:whitelist', ['action' => 'add'])
            ->expectsOutputToContain('IP (or CIDR) is required')
            ->assertExitCode(2);
    }

    public function test_add_command_rejects_past_expiration(): void
    {
        $this->artisan('crowdsec:whitelist', [
            'action' => 'add',
            'ip' => '10.0.0.1',
            '--expires' => '2000-01-01',
        ])->expectsOutputToContain('must be in the future')
            ->assertExitCode(2);
    }

    public function test_add_command_accepts_future_expiration(): void
    {
        $this->artisan('crowdsec:whitelist', [
            'action' => 'add',
            'ip' => '10.0.0.1',
            '--expires' => '2099-12-31 23:59:59',
        ])->assertSuccessful();

        $entry = WhitelistedIp::where('ip', '10.0.0.1')->first();
        $this->assertNotNull($entry->expires_at);
        $this->assertTrue($entry->expires_at->isFuture());
    }

    public function test_list_command_renders_table(): void
    {
        $this->app->make(CrowdSecService::class)->whitelistIp('10.0.0.1', 'Alpha');
        $this->app->make(CrowdSecService::class)->whitelistIp('10.0.0.2', 'Beta');

        $this->artisan('crowdsec:whitelist', ['action' => 'list'])
            ->expectsOutputToContain('10.0.0.1')
            ->expectsOutputToContain('10.0.0.2')
            ->assertSuccessful();

        // The label may be HTML-escaped in the rendered table — assert it exists
        // in the database rather than scanning the rendered output for it.
        $this->assertDatabaseHas('whitelisted_ips', ['ip' => '10.0.0.1', 'label' => 'Alpha']);
        $this->assertDatabaseHas('whitelisted_ips', ['ip' => '10.0.0.2', 'label' => 'Beta']);
    }

    public function test_remove_command_deactivates_entry(): void
    {
        $this->app->make(CrowdSecService::class)->whitelistIp('10.0.0.1', 'Test');

        $this->artisan('crowdsec:whitelist', ['action' => 'remove', 'ip' => '10.0.0.1'])
            ->expectsOutputToContain('Removed from whitelist: 10.0.0.1')
            ->assertSuccessful();

        $this->assertDatabaseHas('whitelisted_ips', ['ip' => '10.0.0.1', 'is_active' => 0]);
    }

    public function test_remove_command_warns_when_not_found(): void
    {
        $this->artisan('crowdsec:whitelist', ['action' => 'remove', 'ip' => '10.0.0.99'])
            ->expectsOutputToContain('was not on the dynamic whitelist')
            ->assertSuccessful();
    }

    public function test_remove_command_requires_ip_argument(): void
    {
        $this->artisan('crowdsec:whitelist', ['action' => 'remove'])
            ->expectsOutputToContain('IP (or CIDR) is required')
            ->assertExitCode(2);
    }

    public function test_purge_expired_removes_only_expired_rows(): void
    {
        $service = $this->app->make(CrowdSecService::class);
        $service->whitelistIp('10.0.0.1', 'Fresh');
        $service->whitelistIp('10.0.0.2', 'Expired', null, new \DateTimeImmutable('-1 hour'));
        $service->whitelistIp('10.0.0.3', 'Also expired', null, new \DateTimeImmutable('-2 hours'));

        $this->artisan('crowdsec:whitelist', ['action' => 'purge-expired'])
            ->expectsOutputToContain('Purged 2 expired')
            ->assertSuccessful();

        $this->assertDatabaseCount('whitelisted_ips', 1);
        $this->assertDatabaseHas('whitelisted_ips', ['ip' => '10.0.0.1']);
    }

    public function test_unknown_action_returns_error(): void
    {
        $this->artisan('crowdsec:whitelist', ['action' => 'explode'])
            ->expectsOutputToContain("Unknown action 'explode'")
            ->assertExitCode(2);
    }
}

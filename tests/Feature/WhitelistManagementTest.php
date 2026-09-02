<?php

namespace RiloArbabillah\LaravelCrowdSec\Tests\Feature;

use DateTimeImmutable;
use Illuminate\Http\Request;
use RiloArbabillah\LaravelCrowdSec\Http\Controllers\CrowdSecApiController;
use RiloArbabillah\LaravelCrowdSec\Models\AuditLog;
use RiloArbabillah\LaravelCrowdSec\Models\WhitelistedIp;
use RiloArbabillah\LaravelCrowdSec\Services\CrowdSecService;
use RiloArbabillah\LaravelCrowdSec\Tests\PackageTestCase;

class WhitelistManagementTest extends PackageTestCase
{
    protected CrowdSecService $service;

    protected function setUp(): void
    {
        parent::setUp();
        $this->loadMigrationsFrom(__DIR__ . '/../../src/Database/Migrations');
        $this->service = $this->app->make(CrowdSecService::class);
    }

    protected function controller(): CrowdSecApiController
    {
        return new CrowdSecApiController($this->service);
    }

    public function test_add_whitelist_creates_entry(): void
    {
        $request = Request::create('/api/crowdsec/whitelist', 'POST', [
            'ip' => '10.0.0.0/8',
            'label' => 'Office VPN',
        ]);

        $response = $this->controller()->addWhitelist($request);
        $payload = $response->getData(true);

        $this->assertSame(201, $response->getStatusCode());
        $this->assertSame('IP whitelisted successfully', $payload['message']);
        $this->assertSame('10.0.0.0/8', $payload['data']['ip']);
        $this->assertSame('Office VPN', $payload['data']['label']);
        $this->assertTrue($payload['data']['is_active']);

        $this->assertDatabaseHas('whitelisted_ips', [
            'ip' => '10.0.0.0/8',
            'label' => 'Office VPN',
            'is_active' => 1,
        ]);
    }

    public function test_add_whitelist_rejects_invalid_ip(): void
    {
        $request = Request::create('/api/crowdsec/whitelist', 'POST', [
            'ip' => 'not-an-ip',
        ]);

        $response = $this->controller()->addWhitelist($request);

        $this->assertSame(422, $response->getStatusCode());
        $this->assertSame('Invalid IP or CIDR notation', $response->getData(true)['message']);
    }

    public function test_add_whitelist_rejects_cidr_with_out_of_range_bits(): void
    {
        $request = Request::create('/api/crowdsec/whitelist', 'POST', [
            'ip' => '10.0.0.0/64',
        ]);

        $response = $this->controller()->addWhitelist($request);

        $this->assertSame(422, $response->getStatusCode());
    }

    public function test_add_whitelist_rejects_missing_ip(): void
    {
        $request = Request::create('/api/crowdsec/whitelist', 'POST', []);

        $this->expectException(\Illuminate\Validation\ValidationException::class);
        $this->controller()->addWhitelist($request);
    }

    public function test_add_whitelist_rejects_past_expiration(): void
    {
        $request = Request::create('/api/crowdsec/whitelist', 'POST', [
            'ip' => '10.0.0.0/8',
            'expires_at' => '2000-01-01T00:00:00Z',
        ]);

        $this->expectException(\Illuminate\Validation\ValidationException::class);
        $this->controller()->addWhitelist($request);
    }

    public function test_adding_duplicate_ip_updates_existing_row(): void
    {
        $this->service->whitelistIp('10.0.0.0/8', 'Original', null, null, 1, 'alice');
        $this->service->whitelistIp('10.0.0.0/8', 'Updated', null, null, 2, 'bob');

        $entries = WhitelistedIp::where('ip', '10.0.0.0/8')->get();
        $this->assertCount(1, $entries);
        $this->assertSame('Updated', $entries->first()->label);
        $this->assertSame('bob', $entries->first()->created_by_label);
    }

    public function test_list_whitelist_returns_paginated_results(): void
    {
        $this->service->whitelistIp('10.0.0.1', 'A');
        $this->service->whitelistIp('10.0.0.2', 'B');

        $response = $this->controller()->whitelist(Request::create('/api/crowdsec/whitelist', 'GET'));
        $payload = $response->getData(true);

        $this->assertArrayHasKey('data', $payload);
        $this->assertCount(2, $payload['data']);
    }

    public function test_list_whitelist_filters_by_ip_and_label(): void
    {
        $this->service->whitelistIp('10.0.0.1', 'Office');
        $this->service->whitelistIp('192.168.1.1', 'Home');

        $byIp = $this->controller()->whitelist(Request::create('/api/crowdsec/whitelist', 'GET', ['ip' => '192.168']))->getData(true);
        $this->assertCount(1, $byIp['data']);
        $this->assertSame('192.168.1.1', $byIp['data'][0]['ip']);

        $byLabel = $this->controller()->whitelist(Request::create('/api/crowdsec/whitelist', 'GET', ['label' => 'Office']))->getData(true);
        $this->assertCount(1, $byLabel['data']);
        $this->assertSame('10.0.0.1', $byLabel['data'][0]['ip']);
    }

    public function test_remove_whitelist_marks_inactive(): void
    {
        $this->service->whitelistIp('10.0.0.0/8', 'Test');

        $response = $this->controller()->removeWhitelist('10.0.0.0/8');
        $this->assertTrue($response->getData(true)['removed']);
        $this->assertDatabaseHas('whitelisted_ips', ['ip' => '10.0.0.0/8', 'is_active' => 0]);
    }

    public function test_remove_whitelist_returns_false_when_not_found(): void
    {
        $response = $this->controller()->removeWhitelist('10.0.0.99');
        $this->assertFalse($response->getData(true)['removed']);
    }

    public function test_remove_is_idempotent(): void
    {
        $this->service->whitelistIp('10.0.0.0/8', 'Test');
        $this->controller()->removeWhitelist('10.0.0.0/8');
        $second = $this->controller()->removeWhitelist('10.0.0.0/8');

        $this->assertFalse($second->getData(true)['removed']);
    }

    public function test_whitelisting_an_already_blocked_ip_bypasses_the_active_block(): void
    {
        config()->set('crowdsec-scenarios.cache.enabled', true);
        \Illuminate\Support\Facades\Cache::flush();

        $ip = '198.51.100.42';
        \RiloArbabillah\LaravelCrowdSec\Models\BlockedIp::create([
            'ip' => $ip,
            'reason' => 'Detected threat',
            'is_active' => true,
            'expires_at' => now()->addHour(),
        ]);

        // Prime the blocked-status cache before the whitelist is added.
        $this->assertTrue($this->service->isBlocked($ip));
        $this->service->whitelistIp($ip, 'Trusted host');

        $middleware = new \RiloArbabillah\LaravelCrowdSec\Http\Middleware\CrowdSecProtection($this->service);
        $response = $middleware->handle(
            Request::create('/test', 'GET', [], [], [], ['REMOTE_ADDR' => $ip]),
            fn ($request) => new \Symfony\Component\HttpFoundation\Response('OK', 200),
        );

        $this->assertSame(200, $response->getStatusCode());
        $this->assertTrue($this->service->isWhitelisted($ip));
    }

    public function test_is_whitelisted_returns_true_for_db_entry(): void
    {
        $this->service->whitelistIp('10.0.0.0/8', 'Test');

        $this->assertTrue($this->service->isWhitelisted('10.5.6.7'));
    }

    public function test_is_whitelisted_returns_false_for_inactive_entry(): void
    {
        $this->service->whitelistIp('10.0.0.0/8', 'Test');
        $this->service->unwhitelistIp('10.0.0.0/8');

        $this->assertFalse($this->service->isWhitelisted('10.5.6.7'));
    }

    public function test_is_whitelisted_returns_false_for_expired_entry(): void
    {
        $this->service->whitelistIp('10.0.0.0/8', 'Test', null, new DateTimeImmutable('-1 hour'));

        $this->assertFalse($this->service->isWhitelisted('10.5.6.7'));
    }

    public function test_config_and_db_whitelist_work_independently(): void
    {
        \Illuminate\Support\Facades\Cache::flush();
        \Illuminate\Support\Facades\Config::set('crowdsec-scenarios.whitelist_ips', ['192.168.0.0/16']);
        $this->service->whitelistIp('10.0.0.0/8', 'DB entry');

        $service = new CrowdSecService();
        $this->assertTrue($service->isWhitelisted('192.168.5.5'));
        $this->assertTrue($service->isWhitelisted('10.5.6.7'));
        $this->assertFalse($service->isWhitelisted('172.16.0.1'));
    }

    public function test_audit_log_records_whitelist_changes(): void
    {
        config()->set('crowdsec-scenarios.audit.enabled', true);

        $this->service->whitelistIp('10.0.0.0/8', 'VPN', 'office', null, 7, 'admin-user');
        $this->service->unwhitelistIp('10.0.0.0/8', 7, 'admin-user');

        $logs = AuditLog::orderBy('created_at')->get();
        $this->assertCount(2, $logs);
        $this->assertSame('whitelist_modified', $logs[0]->action);
        $this->assertSame('added', $logs[0]->metadata['action']);
        $this->assertSame('10.0.0.0/8', $logs[0]->target_ip);
        $this->assertSame('removed', $logs[1]->metadata['action']);
    }

    public function test_purge_expired_removes_only_expired_rows(): void
    {
        $this->service->whitelistIp('10.0.0.1', 'Fresh');
        $this->service->whitelistIp('10.0.0.2', 'Expired', null, new DateTimeImmutable('-1 hour'));
        $this->service->whitelistIp('10.0.0.3', 'Also expired', null, new DateTimeImmutable('-2 hours'));

        $deleted = $this->service->purgeExpiredWhitelistEntries();
        $this->assertSame(2, $deleted);
        $this->assertDatabaseMissing('whitelisted_ips', ['ip' => '10.0.0.2']);
        $this->assertDatabaseHas('whitelisted_ips', ['ip' => '10.0.0.1']);
    }

    public function test_is_valid_ip_or_cidr_accepts_supported_formats(): void
    {
        $this->assertTrue($this->service->isValidIpOrCidr('10.0.0.1'));
        $this->assertTrue($this->service->isValidIpOrCidr('10.0.0.0/8'));
        $this->assertTrue($this->service->isValidIpOrCidr('::1'));
        $this->assertTrue($this->service->isValidIpOrCidr('2001:db8::/32'));
        $this->assertFalse($this->service->isValidIpOrCidr('not-an-ip'));
        $this->assertFalse($this->service->isValidIpOrCidr('10.0.0.0/64'));
        $this->assertFalse($this->service->isValidIpOrCidr('10.0.0.0/'));
        $this->assertFalse($this->service->isValidIpOrCidr('999.999.999.999'));
    }

    public function test_delete_whitelist_entry_removes_row(): void
    {
        $this->service->whitelistIp('10.0.0.0/8', 'Test');
        $this->assertTrue($this->service->deleteWhitelistEntry('10.0.0.0/8'));
        $this->assertDatabaseMissing('whitelisted_ips', ['ip' => '10.0.0.0/8']);
    }
}


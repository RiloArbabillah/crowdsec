<?php

namespace RiloArbabillah\LaravelCrowdSec\Tests\Feature;

use Illuminate\Support\Facades\Schema;
use RiloArbabillah\LaravelCrowdSec\Models\AuditLog;
use RiloArbabillah\LaravelCrowdSec\Models\BlockedIp;
use RiloArbabillah\LaravelCrowdSec\Models\IpBehavior;
use RiloArbabillah\LaravelCrowdSec\Services\CrowdSecService;
use RiloArbabillah\LaravelCrowdSec\Tests\PackageTestCase;

class DatabaseCompatibilityTest extends PackageTestCase
{
    private CrowdSecService $service;

    protected function setUp(): void
    {
        parent::setUp();
        $this->loadMigrationsFrom(__DIR__ . '/../../src/Database/Migrations');
        $this->service = $this->app->make(CrowdSecService::class);
    }

    public function test_all_package_tables_and_context_columns_are_created(): void
    {
        foreach (['security_events', 'blocked_ips', 'ip_behaviors', 'crowdsec_audit_logs'] as $table) {
            $this->assertTrue(Schema::hasTable($table), "Missing table: {$table}");
        }

        $this->assertTrue(Schema::hasColumns('security_events', [
            'request_id', 'route_name', 'response_status', 'action_taken', 'country_code', 'asn',
            'authenticated_user_id_hash',
        ]));
        $this->assertTrue(Schema::hasColumns('ip_behaviors', [
            'request_window_started_at', 'error_404_window_started_at', 'login_window_started_at',
        ]));
    }

    public function test_block_escalation_and_unblock_are_consistent(): void
    {
        config()->set('crowdsec-scenarios.audit.enabled', true);

        $first = $this->service->blockIp('203.0.113.10', 'First offense', 30, 'test');
        $second = $this->service->blockIp('203.0.113.10', 'Second offense', 30, 'test');

        $this->assertSame(1, BlockedIp::query()->where('ip', '203.0.113.10')->count());
        $this->assertGreaterThan($first->expires_at, $second->expires_at);
        $this->assertSame(2, IpBehavior::query()->where('ip', '203.0.113.10')->value('block_count'));
        $this->assertSame(2, AuditLog::query()->where('action', 'ip_blocked')->count());

        $this->service->unblockIp('203.0.113.10');

        $this->assertFalse($this->service->isBlocked('203.0.113.10'));
        $this->assertSame(1, AuditLog::query()->where('action', 'ip_unblocked')->count());
    }

    public function test_behavior_mutations_preserve_independent_windows(): void
    {
        $ip = '203.0.113.20';

        $this->service->trackBehavior($ip, '/products');
        $this->service->track404($ip);
        $this->service->trackLoginAttempt($ip);

        $behavior = IpBehavior::query()->where('ip', $ip)->firstOrFail();
        $this->assertSame(1, $behavior->request_count);
        $this->assertSame(1, $behavior->error_404_count);
        $this->assertSame(1, $behavior->login_attempts);
        $this->assertNotNull($behavior->request_window_started_at);
        $this->assertNotNull($behavior->error_404_window_started_at);
        $this->assertNotNull($behavior->login_window_started_at);
    }
}

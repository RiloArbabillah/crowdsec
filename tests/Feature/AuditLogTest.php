<?php

namespace RiloArbabillah\LaravelCrowdSec\Tests\Feature;

use Orchestra\Testbench\TestCase;
use RiloArbabillah\LaravelCrowdSec\CrowdSecServiceProvider;
use RiloArbabillah\LaravelCrowdSec\Models\AuditLog;
use RiloArbabillah\LaravelCrowdSec\Services\CrowdSecService;

class AuditLogTest extends TestCase
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
        $app['config']->set('crowdsec-scenarios.enabled', true);
        $app['config']->set('crowdsec-scenarios.audit.enabled', true);

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

    // =========================================================================
    // MODEL TESTS
    // =========================================================================

    public function test_audit_log_can_be_created(): void
    {
        $log = AuditLog::record('ip_blocked', '1.2.3.4', ['reason' => 'test']);

        $this->assertDatabaseHas('crowdsec_audit_logs', [
            'action' => 'ip_blocked',
            'target_ip' => '1.2.3.4',
            'actor' => 'system',
        ]);
        $this->assertNotNull($log->created_at);
    }

    public function test_audit_log_has_no_updated_at(): void
    {
        $log = AuditLog::record('test_action', '1.1.1.1');

        $this->assertNull($log->updated_at);
    }

    public function test_audit_log_metadata_is_json_cast(): void
    {
        $log = AuditLog::record('ip_blocked', '5.6.7.8', [
            'reason' => 'SQL injection',
            'duration_minutes' => 60,
        ]);

        $log->refresh();
        $this->assertIsArray($log->metadata);
        $this->assertEquals('SQL injection', $log->metadata['reason']);
        $this->assertEquals(60, $log->metadata['duration_minutes']);
    }

    public function test_audit_log_scope_for_ip(): void
    {
        AuditLog::record('ip_blocked', '1.1.1.1');
        AuditLog::record('ip_blocked', '2.2.2.2');
        AuditLog::record('ip_unblocked', '1.1.1.1');

        $logs = AuditLog::forIp('1.1.1.1')->get();

        $this->assertCount(2, $logs);
    }

    public function test_audit_log_scope_action(): void
    {
        AuditLog::record('ip_blocked', '1.1.1.1');
        AuditLog::record('ip_unblocked', '1.1.1.1');
        AuditLog::record('ip_blocked', '2.2.2.2');

        $logs = AuditLog::action('ip_blocked')->get();

        $this->assertCount(2, $logs);
    }

    public function test_audit_log_scope_between(): void
    {
        \Illuminate\Support\Carbon::setTestNow('2026-01-01 12:00:00');
        AuditLog::record('ip_blocked', '1.1.1.1');

        \Illuminate\Support\Carbon::setTestNow('2026-02-01 12:00:00');
        AuditLog::record('ip_blocked', '2.2.2.2');

        \Illuminate\Support\Carbon::setTestNow('2026-03-01 12:00:00');
        AuditLog::record('ip_blocked', '3.3.3.3');

        \Illuminate\Support\Carbon::setTestNow(); // reset

        $logs = AuditLog::between('2026-01-15', '2026-02-15')->get();

        $this->assertCount(1, $logs);
        $this->assertEquals('2.2.2.2', $logs->first()->target_ip);
    }

    public function test_audit_log_custom_actor(): void
    {
        $log = AuditLog::record('ip_blocked', '1.1.1.1', [], 'admin@example.com');

        $this->assertEquals('admin@example.com', $log->actor);
    }

    public function test_audit_log_null_metadata(): void
    {
        $log = AuditLog::record('ip_unblocked', '1.1.1.1');

        $log->refresh();
        $this->assertNull($log->metadata);
    }

    // =========================================================================
    // INTEGRATION TESTS
    // =========================================================================

    public function test_block_ip_creates_audit_log(): void
    {
        $service = app(CrowdSecService::class);
        $service->blockIp('10.0.0.1', 'test reason', 60);

        $this->assertDatabaseHas('crowdsec_audit_logs', [
            'action' => 'ip_blocked',
            'target_ip' => '10.0.0.1',
        ]);

        $log = AuditLog::where('target_ip', '10.0.0.1')->first();
        $this->assertEquals('test reason', $log->metadata['reason']);
        $this->assertEquals(60, $log->metadata['duration_minutes']);
    }

    public function test_unblock_ip_creates_audit_log(): void
    {
        $service = app(CrowdSecService::class);
        $service->blockIp('10.0.0.2', 'test', 60);
        $service->unblockIp('10.0.0.2');

        $logs = AuditLog::forIp('10.0.0.2')->get();
        $this->assertCount(2, $logs);
        $this->assertEquals('ip_blocked', $logs[0]->action);
        $this->assertEquals('ip_unblocked', $logs[1]->action);
    }

    public function test_no_audit_log_when_disabled(): void
    {
        config(['crowdsec-scenarios.audit.enabled' => false]);

        $service = app(CrowdSecService::class);
        $service->blockIp('10.0.0.3', 'test', 60);

        $this->assertDatabaseMissing('crowdsec_audit_logs', [
            'target_ip' => '10.0.0.3',
        ]);
    }
}

<?php

namespace RiloArbabillah\LaravelCrowdSec\Tests\Feature;

use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Support\Facades\Cache;
use RiloArbabillah\LaravelCrowdSec\Http\Controllers\CrowdSecMetricsController;
use RiloArbabillah\LaravelCrowdSec\Models\BlockedIp;
use RiloArbabillah\LaravelCrowdSec\Models\IpBehavior;
use RiloArbabillah\LaravelCrowdSec\Models\SecurityEvent;
use RiloArbabillah\LaravelCrowdSec\Tests\PackageTestCase;

class MaintenanceCommandsTest extends PackageTestCase
{
    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);
        $app['config']->set('crowdsec-scenarios.enabled', true);
    }

    protected function setUp(): void
    {
        parent::setUp();
        $this->loadMigrationsFrom(__DIR__ . '/../../src/Database/Migrations');
    }

    protected function event(string $ip, array $attributes = []): SecurityEvent
    {
        return SecurityEvent::create($attributes + [
            'ip' => $ip,
            'event_type' => 'sql_injection',
            'severity' => 'critical',
            'request_data' => ['uri' => '/x'],
            'matched_patterns' => [],
        ]);
    }

    // =========================================================================
    // Cleanup
    // =========================================================================

    public function test_event_retention_is_configurable(): void
    {
        config(['crowdsec-scenarios.retention.events_days' => 7]);

        $old = $this->event('10.1.0.1');
        $old->forceFill(['created_at' => now()->subDays(8)])->save();
        $recent = $this->event('10.1.0.2');
        $recent->forceFill(['created_at' => now()->subDays(6)])->save();

        $this->artisan('crowdsec:cleanup --old-events')->assertSuccessful();

        $this->assertDatabaseMissing('security_events', ['id' => $old->id]);
        $this->assertDatabaseHas('security_events', ['id' => $recent->id]);
    }

    public function test_events_are_deleted_in_chunks(): void
    {
        $rows = [];
        for ($i = 0; $i < 2500; $i++) {
            $rows[] = [
                'ip' => '10.1.1.1',
                'event_type' => 'xss',
                'severity' => 'high',
                'created_at' => now()->subDays(40),
                'updated_at' => now()->subDays(40),
            ];
        }
        foreach (array_chunk($rows, 500) as $chunk) {
            SecurityEvent::query()->insert($chunk);
        }

        $this->artisan('crowdsec:cleanup --old-events')
            ->expectsOutputToContain('Deleted 2500 old security events')
            ->assertSuccessful();

        $this->assertSame(0, SecurityEvent::count());
    }

    public function test_expired_cleanup_purges_old_inactive_blocks(): void
    {
        BlockedIp::upsertBlock('10.2.0.1', 'old', now()->subDays(40), 'test');
        BlockedIp::where('ip', '10.2.0.1')->update(['is_active' => false, 'updated_at' => now()->subDays(31)]);
        BlockedIp::upsertBlock('10.2.0.2', 'recently unblocked', now()->addHour(), 'test');
        BlockedIp::where('ip', '10.2.0.2')->update(['is_active' => false]);
        BlockedIp::upsertBlock('10.2.0.3', 'active', now()->addHour(), 'test');

        $this->artisan('crowdsec:cleanup --expired')->assertSuccessful();

        $this->assertDatabaseMissing('blocked_ips', ['ip' => '10.2.0.1']);
        $this->assertDatabaseHas('blocked_ips', ['ip' => '10.2.0.2']);
        $this->assertDatabaseHas('blocked_ips', ['ip' => '10.2.0.3', 'is_active' => true]);
    }

    public function test_behavior_cleanup_resets_stale_escalation(): void
    {
        config(['crowdsec-scenarios.retention.block_count_reset_days' => 7]);

        // Active shared IP, last blocked 10 days ago → reset
        IpBehavior::getOrCreate('10.3.0.1')->forceFill(['block_count' => 5])->save();
        BlockedIp::upsertBlock('10.3.0.1', 'old', now()->subDays(9), 'test');
        BlockedIp::where('ip', '10.3.0.1')->update(['updated_at' => now()->subDays(10)]);

        // Blocked 2 days ago → keep
        IpBehavior::getOrCreate('10.3.0.2')->forceFill(['block_count' => 3])->save();
        BlockedIp::upsertBlock('10.3.0.2', 'recent', now()->addDay(), 'test');

        $this->artisan('crowdsec:cleanup --old-behaviors')->assertSuccessful();

        $this->assertSame(0, IpBehavior::where('ip', '10.3.0.1')->value('block_count'));
        $this->assertSame(3, IpBehavior::where('ip', '10.3.0.2')->value('block_count'));
    }

    public function test_dry_run_changes_nothing(): void
    {
        $event = $this->event('10.4.0.1');
        $event->forceFill(['created_at' => now()->subDays(40)])->save();
        IpBehavior::getOrCreate('10.4.0.2')->forceFill(['block_count' => 2])->save();

        $this->artisan('crowdsec:cleanup --dry-run')->assertSuccessful();

        $this->assertDatabaseHas('security_events', ['id' => $event->id]);
        $this->assertSame(2, IpBehavior::where('ip', '10.4.0.2')->value('block_count'));
    }

    public function test_scheduled_tasks_run_on_one_server_without_overlapping(): void
    {
        $events = collect($this->app->make(Schedule::class)->events())
            ->filter(fn ($event) => str_contains((string) $event->command, 'crowdsec:'));

        $this->assertCount(5, $events);
        foreach ($events as $event) {
            $this->assertTrue($event->withoutOverlapping, (string) $event->command);
            $this->assertTrue($event->onOneServer, (string) $event->command);
        }
    }

    // =========================================================================
    // Export
    // =========================================================================

    public function test_export_rejects_unknown_format_and_bad_dates(): void
    {
        $this->artisan('crowdsec:export', ['--format' => 'xml'])->assertFailed();
        $this->artisan('crowdsec:export', ['--from' => 'yesterday-ish'])->assertFailed();
        $this->artisan('crowdsec:export', ['--severity' => 'extreme'])->assertFailed();
    }

    public function test_export_filters_by_ip_and_event_type(): void
    {
        $this->event('10.5.0.1', ['event_type' => 'xss', 'severity' => 'high']);
        $this->event('10.5.0.2', ['event_type' => 'xss', 'severity' => 'high']);
        $this->event('10.5.0.1', ['event_type' => 'ssrf']);

        $path = tempnam(sys_get_temp_dir(), 'crowdsec-export-');
        $this->artisan('crowdsec:export', ['--ip' => '10.5.0.1', '--event-type' => 'xss', '--output' => $path])
            ->expectsOutputToContain('Exported 1 events')
            ->assertSuccessful();

        $rows = json_decode((string) file_get_contents($path), true);
        @unlink($path);

        $this->assertCount(1, $rows);
        $this->assertSame('10.5.0.1', $rows[0]['ip']);
        $this->assertSame('xss', $rows[0]['event_type']);
    }

    public function test_export_streams_valid_json_and_csv_across_batches(): void
    {
        for ($i = 0; $i < 1100; $i++) {
            $this->event('10.6.0.' . ($i % 250));
        }

        $json = tempnam(sys_get_temp_dir(), 'crowdsec-export-');
        $this->artisan('crowdsec:export', ['--output' => $json])->assertSuccessful();
        $rows = json_decode((string) file_get_contents($json), true, flags: JSON_THROW_ON_ERROR);
        @unlink($json);
        $this->assertCount(1100, $rows);
        $this->assertGreaterThanOrEqual($rows[1]['timestamp'], $rows[0]['timestamp'], 'newest first');

        $csv = tempnam(sys_get_temp_dir(), 'crowdsec-export-');
        $this->artisan('crowdsec:export', ['--format' => 'csv', '--output' => $csv])->assertSuccessful();
        $lines = file($csv, FILE_IGNORE_NEW_LINES);
        @unlink($csv);
        $this->assertCount(1101, $lines);
        $this->assertStringStartsWith('timestamp,ip,event_type,severity', $lines[0]);
    }

    public function test_export_fails_when_output_is_not_writable(): void
    {
        $this->event('10.7.0.1');

        $this->artisan('crowdsec:export', ['--output' => '/nonexistent-dir/crowdsec.json'])->assertFailed();
    }

    // =========================================================================
    // Block / unblock commands
    // =========================================================================

    public function test_block_and_unblock_commands(): void
    {
        $this->artisan('crowdsec:block', ['ip' => '10.8.0.1', '--reason' => 'abuse', '--duration' => 30])
            ->expectsOutputToContain('Blocked 10.8.0.1')
            ->assertSuccessful();

        $block = BlockedIp::where('ip', '10.8.0.1')->firstOrFail();
        $this->assertTrue($block->is_active);
        $this->assertSame('abuse', $block->reason);

        $this->artisan('crowdsec:unblock', ['ip' => '10.8.0.1'])
            ->expectsOutputToContain('Unblocked 10.8.0.1')
            ->assertSuccessful();
        $this->assertFalse($block->fresh()->is_active);

        $this->artisan('crowdsec:unblock', ['ip' => '10.8.0.1'])
            ->expectsOutputToContain('was not blocked')
            ->assertSuccessful();
    }

    public function test_block_command_validates_input(): void
    {
        $this->artisan('crowdsec:block', ['ip' => 'not-an-ip'])->assertFailed();
        $this->artisan('crowdsec:block', ['ip' => '10.8.0.2', '--duration' => '0'])->assertFailed();
        $this->assertDatabaseMissing('blocked_ips', ['ip' => '10.8.0.2']);
    }

    // =========================================================================
    // Metrics
    // =========================================================================

    public function test_metrics_output_is_cached(): void
    {
        config(['crowdsec-scenarios.metrics.cache_seconds' => 15]);
        $controller = $this->app->make(CrowdSecMetricsController::class);

        BlockedIp::upsertBlock('10.9.0.1', 'test', now()->addHour(), 'test');
        $this->assertStringContainsString('crowdsec_blocked_ips_active 1', (string) $controller()->getContent());

        BlockedIp::upsertBlock('10.9.0.2', 'test', now()->addHour(), 'test');
        $this->assertStringContainsString('crowdsec_blocked_ips_active 1', (string) $controller()->getContent());

        Cache::forget('crowdsec:metrics:body');
        $this->assertStringContainsString('crowdsec_blocked_ips_active 2', (string) $controller()->getContent());
    }

    public function test_metrics_cache_can_be_disabled(): void
    {
        config(['crowdsec-scenarios.metrics.cache_seconds' => 0]);
        $controller = $this->app->make(CrowdSecMetricsController::class);

        $controller();
        BlockedIp::upsertBlock('10.9.1.1', 'test', now()->addHour(), 'test');

        $this->assertStringContainsString('crowdsec_blocked_ips_active 1', (string) $controller()->getContent());
    }
}

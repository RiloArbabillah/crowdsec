<?php

namespace RiloArbabillah\LaravelCrowdSec\Tests\Feature;

use Illuminate\Auth\GenericUser;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Gate;
use RiloArbabillah\LaravelCrowdSec\Events\CrowdSecMiddlewareFailed;
use RiloArbabillah\LaravelCrowdSec\Http\Middleware\HoneypotTrap;
use RiloArbabillah\LaravelCrowdSec\Models\AuditLog;
use RiloArbabillah\LaravelCrowdSec\Models\BlockedIp;
use RiloArbabillah\LaravelCrowdSec\Models\IpBehavior;
use RiloArbabillah\LaravelCrowdSec\Services\CrowdSecService;
use RiloArbabillah\LaravelCrowdSec\Tests\PackageTestCase;
use Symfony\Component\HttpFoundation\Response;

class SecurityHardeningTest extends PackageTestCase
{
    protected CrowdSecService $service;

    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);

        $app['config']->set('app.key', 'base64:'.base64_encode(str_repeat('k', 32)));
        $app['config']->set('crowdsec-scenarios.enabled', true);
        $app['config']->set('crowdsec-scenarios.api.enabled', true);
        $app['config']->set('crowdsec-scenarios.api.middleware', ['api', 'auth']);
        $app['config']->set('crowdsec-scenarios.dashboard.enabled', true);
    }

    protected function setUp(): void
    {
        parent::setUp();
        $this->loadMigrationsFrom(__DIR__ . '/../../src/Database/Migrations');
        $this->service = $this->app->make(CrowdSecService::class);
    }

    protected function user(): GenericUser
    {
        return new GenericUser(['id' => 1, 'name' => 'Admin']);
    }

    // =========================================================================
    // Authorization gates
    // =========================================================================

    public function test_api_requires_view_gate_outside_local(): void
    {
        $this->actingAs($this->user())
            ->getJson('/api/crowdsec/stats')
            ->assertForbidden();
    }

    public function test_api_read_allowed_when_view_gate_granted(): void
    {
        Gate::define('viewCrowdSec', fn ($user) => true);

        $this->actingAs($this->user())
            ->getJson('/api/crowdsec/stats')
            ->assertOk()
            ->assertJsonStructure(['total_events', 'active_blocks']);
    }

    public function test_api_write_requires_manage_gate(): void
    {
        Gate::define('viewCrowdSec', fn ($user) => true);

        $this->actingAs($this->user())
            ->postJson('/api/crowdsec/block', ['ip' => '10.9.9.9', 'reason' => 'manual'])
            ->assertForbidden();

        $this->assertDatabaseMissing('blocked_ips', ['ip' => '10.9.9.9']);

        Gate::define('manageCrowdSec', fn ($user) => true);

        $this->actingAs($this->user())
            ->postJson('/api/crowdsec/block', ['ip' => '10.9.9.9', 'reason' => 'manual'])
            ->assertCreated();
    }

    public function test_api_requires_authentication(): void
    {
        Gate::define('viewCrowdSec', fn ($user) => true);

        $this->getJson('/api/crowdsec/stats')->assertUnauthorized();
    }

    public function test_dashboard_requires_view_gate(): void
    {
        $this->actingAs($this->user())
            ->get('/crowdsec')
            ->assertForbidden();

        Gate::define('viewCrowdSec', fn ($user) => true);

        $this->actingAs($this->user())
            ->get('/crowdsec')
            ->assertOk()
            ->assertSee(json_encode('/api/crowdsec/whitelist'), false);
    }

    public function test_default_gates_allow_local_environment(): void
    {
        $this->app['env'] = 'local';

        $this->assertTrue(Gate::forUser($this->user())->allows('viewCrowdSec'));
        $this->assertTrue(Gate::forUser($this->user())->allows('manageCrowdSec'));
    }

    public function test_events_endpoint_rejects_invalid_filters(): void
    {
        Gate::define('viewCrowdSec', fn ($user) => true);

        $this->actingAs($this->user())
            ->getJson('/api/crowdsec/events?from=not-a-date&severity=extreme')
            ->assertUnprocessable()
            ->assertJsonValidationErrors(['from', 'severity']);
    }

    public function test_check_endpoint_returns_behavior_summary_only(): void
    {
        Gate::define('viewCrowdSec', fn ($user) => true);
        IpBehavior::getOrCreate('10.1.1.1');

        $behavior = $this->actingAs($this->user())
            ->getJson('/api/crowdsec/check/10.1.1.1')
            ->assertOk()
            ->json('behavior');

        $this->assertArrayHasKey('threat_score', $behavior);
        $this->assertArrayNotHasKey('id', $behavior);
        $this->assertArrayNotHasKey('ip', $behavior);
    }

    // =========================================================================
    // IP matching
    // =========================================================================

    public function test_ipv4_does_not_match_ipv6_cidr(): void
    {
        // 32.1.13.184 has the same leading bytes as 2001:0db8::
        $this->service->whitelistIp('2001:db8::/32');

        $this->assertFalse($this->service->isWhitelisted('32.1.13.184'));
        $this->assertTrue($this->service->isWhitelisted('2001:db8::1'));
    }

    public function test_ipv4_mapped_ipv6_matches_ipv4_entries(): void
    {
        $this->service->whitelistIp('10.0.0.0/8');
        $this->service->whitelistIp('192.168.1.5');

        $this->assertTrue($this->service->isWhitelisted('::ffff:10.2.3.4'));
        $this->assertTrue($this->service->isWhitelisted('::ffff:192.168.1.5'));
    }

    public function test_ipv6_exact_match_ignores_notation(): void
    {
        $this->service->whitelistIp('2001:db8::1');

        $this->assertTrue($this->service->isWhitelisted('2001:0db8:0000:0000:0000:0000:0000:0001'));
    }

    // =========================================================================
    // Blocking
    // =========================================================================

    public function test_shorter_block_does_not_shorten_active_block(): void
    {
        $long = now()->addDays(7);
        BlockedIp::upsertBlock('10.2.2.2', 'Long', $long, 'test');
        $block = BlockedIp::upsertBlock('10.2.2.2', 'Short', now()->addMinutes(15), 'test');

        $this->assertSame('Short', $block->reason);
        $this->assertSame($long->getTimestamp(), $block->expires_at?->getTimestamp());
    }

    public function test_permanent_block_stays_permanent(): void
    {
        BlockedIp::upsertBlock('10.2.2.3', 'Permanent', null, 'test');
        $block = BlockedIp::upsertBlock('10.2.2.3', 'Honeypot', now()->addHours(4), 'honeypot_trap');

        $this->assertNull($block->expires_at);
    }

    public function test_block_after_unblock_uses_new_expiry(): void
    {
        BlockedIp::upsertBlock('10.2.2.4', 'Long', now()->addDays(7), 'test');
        $this->service->unblockIp('10.2.2.4');

        $expires = now()->addMinutes(15);
        $block = BlockedIp::upsertBlock('10.2.2.4', 'Short', $expires, 'test');

        $this->assertSame($expires->getTimestamp(), $block->expires_at?->getTimestamp());
    }

    public function test_block_resets_threat_score_below_threshold(): void
    {
        $behavior = IpBehavior::getOrCreate('10.3.3.3');
        $behavior->update(['threat_score' => 100]);

        $this->service->blockIp('10.3.3.3', 'Suspicious behavior detected', 240, 'behavior_threshold');

        $behavior->refresh();
        $this->assertSame(25.0, (float) $behavior->threat_score);
        $this->assertFalse($this->service->exceedsBehaviorThreshold('10.3.3.3'));
    }

    // =========================================================================
    // Cleanup
    // =========================================================================

    public function test_cleanup_expired_does_not_delete_audit_logs(): void
    {
        config(['crowdsec-scenarios.audit.enabled' => true, 'crowdsec-scenarios.audit.retention_days' => 30]);

        Carbon::setTestNow('2026-01-01 12:00:00');
        AuditLog::record('ip_blocked', '10.4.4.4');
        Carbon::setTestNow('2026-04-05 12:00:00');

        $this->artisan('crowdsec:cleanup --expired')->assertSuccessful();
        $this->assertDatabaseHas('crowdsec_audit_logs', ['target_ip' => '10.4.4.4']);

        $this->artisan('crowdsec:cleanup --audit-logs')->assertSuccessful();
        $this->assertDatabaseMissing('crowdsec_audit_logs', ['target_ip' => '10.4.4.4']);

        Carbon::setTestNow();
    }

    // =========================================================================
    // Honeypot
    // =========================================================================

    public function test_honeypot_skips_whitelisted_ip(): void
    {
        config(['crowdsec-scenarios.honeypot_routes' => ['.env']]);
        $this->service->whitelistIp('10.5.5.5');

        $request = Request::create('/.env', 'GET', [], [], [], ['REMOTE_ADDR' => '10.5.5.5']);
        $response = (new HoneypotTrap($this->service))->handle($request, fn () => new Response('OK', 200));

        $this->assertSame(200, $response->getStatusCode());
        $this->assertFalse($this->service->isBlocked('10.5.5.5'));
    }

    public function test_honeypot_fails_open_on_error(): void
    {
        Event::fake([CrowdSecMiddlewareFailed::class]);
        config(['crowdsec-scenarios.honeypot_routes' => ['.env']]);

        $service = $this->createMock(CrowdSecService::class);
        $service->method('isWhitelisted')->willReturn(false);
        $service->method('blockIp')->willThrowException(new \RuntimeException('db down'));

        $calls = 0;
        $request = Request::create('/.env', 'GET', [], [], [], ['REMOTE_ADDR' => '10.5.5.6']);
        $response = (new HoneypotTrap($service))->handle($request, function () use (&$calls) {
            $calls++;

            return new Response('OK', 200);
        });

        $this->assertSame(200, $response->getStatusCode());
        $this->assertSame(1, $calls);
        Event::assertDispatched(CrowdSecMiddlewareFailed::class);
    }
}

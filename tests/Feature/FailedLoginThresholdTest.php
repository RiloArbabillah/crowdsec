<?php

namespace RiloArbabillah\LaravelCrowdSec\Tests\Feature;

use Illuminate\Auth\Events\Failed;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Config;
use RiloArbabillah\LaravelCrowdSec\Http\Middleware\CrowdSecProtection;
use RiloArbabillah\LaravelCrowdSec\Models\BlockedIp;
use RiloArbabillah\LaravelCrowdSec\Models\IpBehavior;
use RiloArbabillah\LaravelCrowdSec\Tests\PackageTestCase;
use Symfony\Component\HttpFoundation\Response;

/**
 * Failed logins counted through the Failed auth event must not add threat
 * score, otherwise the 4-hour behavior_threshold block pre-empts the 15-minute
 * login_threshold block.
 */
class FailedLoginThresholdTest extends PackageTestCase
{
    private const IP = '203.0.113.60';

    protected function setUp(): void
    {
        parent::setUp();
        $this->loadMigrationsFrom(__DIR__ . '/../../src/Database/Migrations');

        Config::set('crowdsec-scenarios.behavior.login_threshold', 8);
        Config::set('crowdsec-scenarios.behavior.threat_score_threshold', 50);
        $this->app->forgetInstance('crowdsec');
        $this->app->instance('request', $this->livewireRequest());
    }

    private function livewireRequest(): Request
    {
        return Request::create('/livewire/update', 'POST', [], [], [], [
            'REMOTE_ADDR' => self::IP,
            'CONTENT_TYPE' => 'application/json',
            'HTTP_X_LIVEWIRE' => 'true',
            'HTTP_ACCEPT' => 'application/json',
            'HTTP_USER_AGENT' => 'Mozilla/5.0',
        ], '{}');
    }

    private function failLogin(int $times): void
    {
        for ($i = 0; $i < $times; $i++) {
            event(new Failed('web', null, ['email' => 'admin@example.com']));
        }
    }

    public function test_failed_events_below_threshold_count_attempts_without_threat_score(): void
    {
        $this->failLogin(7);

        $behavior = IpBehavior::where('ip', self::IP)->firstOrFail();
        $this->assertSame(7, $behavior->login_attempts);
        $this->assertEquals(0, $behavior->threat_score);
        $this->assertFalse(BlockedIp::isBlocked(self::IP));
    }

    public function test_reaching_login_threshold_blocks_for_fifteen_minutes_as_login_threshold(): void
    {
        $this->failLogin(8);

        $block = BlockedIp::where('ip', self::IP)->firstOrFail();
        $this->assertSame('login_threshold', $block->event_type);
        $this->assertSame('Too many login attempts', $block->reason);
        $this->assertEqualsWithDelta(15, now()->diffInMinutes($block->expires_at, false), 1);
        $this->assertEquals(0, IpBehavior::where('ip', self::IP)->value('threat_score'));
    }

    public function test_failed_events_do_not_trigger_behavior_threshold_before_login_threshold(): void
    {
        // 5 failures used to reach threat_score 50 (5 x 10) and block as behavior_threshold.
        $this->failLogin(5);

        $this->assertSame(0, BlockedIp::count());
        $this->assertEquals(0, IpBehavior::where('ip', self::IP)->value('threat_score'));

        $request = Request::create('/dashboard', 'GET', [], [], [], [
            'REMOTE_ADDR' => self::IP,
            'HTTP_USER_AGENT' => 'Mozilla/5.0',
        ]);
        $this->app->instance('request', $request);
        $response = (new CrowdSecProtection(app('crowdsec')))
            ->handle($request, fn () => new Response('OK', 200));

        $this->assertSame(200, $response->getStatusCode());
        $this->assertSame(0, BlockedIp::count());
    }

    public function test_manual_track_login_attempt_still_adds_threat_score(): void
    {
        app('crowdsec')->trackLoginAttempt(self::IP);

        $behavior = IpBehavior::where('ip', self::IP)->firstOrFail();
        $this->assertSame(1, $behavior->login_attempts);
        $this->assertEquals(10, $behavior->threat_score);
    }
}

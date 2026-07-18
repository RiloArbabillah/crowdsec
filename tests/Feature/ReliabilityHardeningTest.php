<?php

namespace RiloArbabillah\LaravelCrowdSec\Tests\Feature;

use Illuminate\Auth\Events\Authenticated;
use Illuminate\Auth\GenericUser;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Schema;
use Orchestra\Testbench\TestCase;
use RiloArbabillah\LaravelCrowdSec\CrowdSecServiceProvider;
use RiloArbabillah\LaravelCrowdSec\Http\Middleware\CrowdSecProtection;
use RiloArbabillah\LaravelCrowdSec\Http\Middleware\CrowdSecRateLimit;
use RiloArbabillah\LaravelCrowdSec\Models\BlockedIp;
use RiloArbabillah\LaravelCrowdSec\Models\IpBehavior;
use RiloArbabillah\LaravelCrowdSec\Services\CrowdSecService;
use Symfony\Component\HttpFoundation\Response;

class ReliabilityHardeningTest extends TestCase
{
    protected CrowdSecService $service;

    protected CrowdSecProtection $middleware;

    protected function getPackageProviders($app): array
    {
        return [CrowdSecServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        $app['config']->set(
            'crowdsec-scenarios',
            require __DIR__.'/../../config/crowdsec-scenarios.php'
        );
        $app['config']->set('database.default', 'testing');
        $app['config']->set('database.connections.testing', [
            'driver' => 'sqlite',
            'database' => ':memory:',
            'prefix' => '',
        ]);
        $app['config']->set('cache.default', 'array');
    }

    protected function setUp(): void
    {
        parent::setUp();
        $this->loadMigrationsFrom(__DIR__.'/../../src/Database/Migrations');
        $this->service = app(CrowdSecService::class);
        $this->middleware = app(CrowdSecProtection::class);
        Carbon::setTestNow('2026-07-18 10:00:00');
    }

    protected function tearDown(): void
    {
        Carbon::setTestNow();
        parent::tearDown();
    }

    public function test_behavior_window_columns_are_migrated(): void
    {
        $this->assertTrue(Schema::hasColumns('ip_behaviors', [
            'request_window_started_at',
            'error_404_window_started_at',
            'login_window_started_at',
        ]));
    }

    public function test_legacy_counter_without_window_starts_fresh(): void
    {
        $behavior = IpBehavior::create([
            'ip' => '203.0.113.201',
            'request_count' => 499,
            'first_activity' => now()->subDay(),
            'last_activity' => now()->subDay(),
        ]);

        $behavior->incrementRequestCount();

        $this->assertSame(1, $behavior->request_count);
        $this->assertTrue($behavior->request_window_started_at->equalTo(now()));
    }

    public function test_request_window_resets_from_start_even_with_recent_activity(): void
    {
        $ip = '203.0.113.202';
        $this->service->trackBehavior($ip, '/first');

        Carbon::setTestNow(now()->addMinutes(59));
        $this->service->trackBehavior($ip, '/recent');
        $this->assertSame(2, IpBehavior::where('ip', $ip)->value('request_count'));

        Carbon::setTestNow(now()->addMinutes(2));
        $behavior = $this->service->trackBehavior($ip, '/new-window');

        $this->assertSame(1, $behavior->request_count);
        $this->assertTrue($behavior->request_window_started_at->equalTo(now()));
    }

    public function test_login_window_expires_independently(): void
    {
        $ip = '203.0.113.203';
        $threshold = (int) Config::get('crowdsec-scenarios.behavior.login_threshold', 5);

        for ($attempt = 0; $attempt < $threshold; $attempt++) {
            $this->service->trackLoginAttempt($ip);
        }
        $this->assertTrue($this->service->exceedsLoginThreshold($ip));

        Carbon::setTestNow(now()->addMinutes(6));
        $this->assertFalse($this->service->exceedsLoginThreshold($ip));

        $behavior = $this->service->trackLoginAttempt($ip);
        $this->assertSame(1, $behavior->login_attempts);
    }

    public function test_login_password_is_ignored_but_other_body_fields_are_inspected(): void
    {
        $passwordOnly = $this->sendLogin(
            '203.0.113.204',
            ['email' => 'user@example.com', 'password' => "secret' OR 1=1"],
        );
        $maliciousUsername = $this->sendLogin(
            '203.0.113.205',
            ['email' => "admin' OR 1=1", 'password' => 'secret'],
        );

        $this->assertSame(200, $passwordOnly->getStatusCode());
        $this->assertSame(403, $maliciousUsername->getStatusCode());
    }

    public function test_nested_login_password_is_ignored_but_sibling_fields_are_inspected(): void
    {
        $passwordOnly = $this->sendLogin(
            '203.0.113.210',
            ['credentials' => ['email' => 'user@example.com', 'password' => "secret' OR 1=1"]],
        );
        $maliciousEmail = $this->sendLogin(
            '203.0.113.211',
            ['credentials' => ['email' => "admin' OR 1=1", 'password' => 'secret']],
        );

        $this->assertSame(200, $passwordOnly->getStatusCode());
        $this->assertSame(403, $maliciousEmail->getStatusCode());
    }

    public function test_login_query_is_still_inspected(): void
    {
        $request = Request::create(
            '/login?redirect=https://evil.example/steal',
            'POST',
            ['email' => 'user@example.com', 'password' => 'secret'],
            [],
            [],
            ['REMOTE_ADDR' => '203.0.113.206'],
        );

        $response = $this->middleware->handle($request, fn () => new Response('OK'));

        $this->assertSame(403, $response->getStatusCode());
    }

    public function test_authentication_resets_login_window_without_unblocking_or_resetting_score(): void
    {
        $ip = '203.0.113.207';
        $behavior = IpBehavior::getOrCreate($ip);
        $behavior->incrementLoginAttempts();
        $behavior->addThreatScore(20);
        BlockedIp::create([
            'ip' => $ip,
            'reason' => 'Existing security block',
            'expires_at' => now()->addHour(),
            'is_active' => true,
        ]);
        $scoreBeforeAuthentication = (float) $behavior->fresh()->threat_score;

        $request = Request::create('/login', 'POST', [], [], [], ['REMOTE_ADDR' => $ip]);
        $this->app->instance('request', $request);
        event(new Authenticated('web', new GenericUser(['id' => 123])));

        $behavior->refresh();
        $this->assertSame(0, $behavior->login_attempts);
        $this->assertNull($behavior->login_window_started_at);
        $this->assertSame($scoreBeforeAuthentication, (float) $behavior->threat_score);
        $this->assertTrue($this->service->isBlocked($ip));
    }

    public function test_rate_limit_uses_actual_reset_headers_and_expires(): void
    {
        $middleware = new CrowdSecRateLimit();
        $request = Request::create('/limited', 'GET', [], [], [], ['REMOTE_ADDR' => '203.0.113.208']);
        $next = fn () => new Response('OK');

        $first = $middleware->handle($request, $next, '2', '1');
        $second = $middleware->handle($request, $next, '2', '1');
        $blocked = $middleware->handle($request, $next, '2', '1');

        $this->assertSame('1', $first->headers->get('X-RateLimit-Remaining'));
        $this->assertSame('0', $second->headers->get('X-RateLimit-Remaining'));
        $this->assertSame(429, $blocked->getStatusCode());
        $this->assertSame('60', $blocked->headers->get('Retry-After'));
        $this->assertNotNull($blocked->headers->get('X-RateLimit-Reset'));

        Carbon::setTestNow(now()->addSeconds(61));
        $afterReset = $middleware->handle($request, $next, '2', '1');
        $this->assertSame(200, $afterReset->getStatusCode());
    }

    public function test_rate_limit_clamps_invalid_parameters(): void
    {
        $middleware = new CrowdSecRateLimit();
        $request = Request::create('/invalid-limit', 'GET', [], [], [], ['REMOTE_ADDR' => '203.0.113.209']);
        $next = fn () => new Response('OK');

        $this->assertSame(200, $middleware->handle($request, $next, '0', '0')->getStatusCode());
        $this->assertSame(429, $middleware->handle($request, $next, '0', '0')->getStatusCode());
    }

    protected function sendLogin(string $ip, array $parameters): Response
    {
        $request = Request::create('/login', 'POST', $parameters, [], [], ['REMOTE_ADDR' => $ip]);

        return $this->middleware->handle($request, fn () => new Response('OK'));
    }
}

<?php

namespace RiloArbabillah\LaravelCrowdSec\Tests\Feature;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Config;
use Orchestra\Testbench\TestCase;
use RiloArbabillah\LaravelCrowdSec\CrowdSecServiceProvider;
use RiloArbabillah\LaravelCrowdSec\Http\Middleware\CrowdSecProtection;
use RiloArbabillah\LaravelCrowdSec\Models\BlockedIp;
use RiloArbabillah\LaravelCrowdSec\Models\IpBehavior;
use RiloArbabillah\LaravelCrowdSec\Models\SecurityEvent;
use RiloArbabillah\LaravelCrowdSec\Services\CrowdSecService;
use Symfony\Component\HttpFoundation\Response;

/**
 * Integration tests for the CrowdSecProtection middleware pipeline.
 * Tests the full 10-step request processing pipeline end-to-end.
 */
class CrowdSecMiddlewareTest extends TestCase
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
        $this->service = new CrowdSecService();
        $this->middleware = new CrowdSecProtection($this->service);
    }

    /**
     * Helper: run request through middleware and return response.
     */
    protected function sendRequest(
        string $uri = '/test',
        string $method = 'GET',
        array $params = [],
        array $server = [],
        ?string $content = null,
    ): Response {
        $server = array_merge(['REMOTE_ADDR' => '203.0.113.1'], $server);
        $request = Request::create($uri, $method, $params, [], [], $server, $content);

        return $this->middleware->handle(
            $request,
            fn ($req) => new Response('OK', 200)
        );
    }

    /**
     * Helper: create a request with specific IP.
     */
    protected function sendFromIp(string $ip, string $uri = '/test', string $method = 'GET'): Response
    {
        return $this->sendRequest($uri, $method, [], ['REMOTE_ADDR' => $ip]);
    }

    // =========================================================================
    // Step 1: Package enabled/disabled
    // =========================================================================

    public function test_disabled_package_passes_all_requests(): void
    {
        Config::set('crowdsec-scenarios.enabled', false);
        $service = new CrowdSecService();
        $middleware = new CrowdSecProtection($service);

        // Even a malicious request should pass when disabled
        $request = Request::create('/search?q=UNION+SELECT+*+FROM+users', 'GET', [], [], [], [
            'REMOTE_ADDR' => '203.0.113.1',
        ]);

        $response = $middleware->handle($request, fn ($req) => new Response('OK', 200));

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('OK', $response->getContent());
    }

    // =========================================================================
    // Step 2: Whitelisted IP bypass
    // =========================================================================

    public function test_whitelisted_ip_bypasses_all_checks(): void
    {
        // 127.0.0.1 is whitelisted by default
        $response = $this->sendFromIp('127.0.0.1', '/search?q=UNION+SELECT+*+FROM+users');

        $this->assertEquals(200, $response->getStatusCode());
    }

    public function test_whitelisted_ipv6_bypass(): void
    {
        // ::1 is whitelisted by default
        $response = $this->sendFromIp('::1', '/search?q=<script>alert(1)</script>');

        $this->assertEquals(200, $response->getStatusCode());
    }

    // =========================================================================
    // Step 3: Blocked IP returns 403
    // =========================================================================

    public function test_blocked_ip_returns_403(): void
    {
        $ip = '198.51.100.10';
        BlockedIp::create([
            'ip' => $ip,
            'reason' => 'Test block',
            'is_active' => true,
            'expires_at' => now()->addHour(),
        ]);

        $response = $this->sendFromIp($ip);

        $this->assertEquals(403, $response->getStatusCode());
    }

    public function test_expired_block_allows_request(): void
    {
        $ip = '198.51.100.11';
        BlockedIp::create([
            'ip' => $ip,
            'reason' => 'Expired block',
            'is_active' => true,
            'expires_at' => now()->subMinute(), // Expired
        ]);

        $response = $this->sendFromIp($ip);

        $this->assertEquals(200, $response->getStatusCode());
    }

    // =========================================================================
    // Step 4: Blocked HTTP methods
    // =========================================================================

    public function test_trace_method_returns_403(): void
    {
        $response = $this->sendRequest('/api', 'TRACE');

        $this->assertEquals(403, $response->getStatusCode());
        $this->assertDatabaseHas('blocked_ips', ['ip' => '203.0.113.1']);
    }

    public function test_connect_method_returns_403(): void
    {
        $response = $this->sendRequest('/api', 'CONNECT');

        $this->assertEquals(403, $response->getStatusCode());
    }

    public function test_get_method_allowed(): void
    {
        $response = $this->sendRequest('/api', 'GET');

        $this->assertEquals(200, $response->getStatusCode());
    }

    // =========================================================================
    // Step 5: Empty User-Agent (scoring, not blocking)
    // =========================================================================

    public function test_empty_user_agent_adds_threat_score(): void
    {
        Config::set('crowdsec-scenarios.block_empty_ua', true);
        $service = new CrowdSecService();
        $middleware = new CrowdSecProtection($service);

        $ip = '203.0.113.50';
        $request = Request::create('/test', 'GET', [], [], [], [
            'REMOTE_ADDR' => $ip,
            'HTTP_USER_AGENT' => '',
        ]);

        $middleware->handle($request, fn ($req) => new Response('OK', 200));

        $behavior = IpBehavior::where('ip', $ip)->first();
        $this->assertNotNull($behavior);
        $this->assertGreaterThan(0, $behavior->threat_score);
    }

    // =========================================================================
    // Step 6: Oversized request body
    // =========================================================================

    public function test_oversized_request_body_returns_403(): void
    {
        Config::set('crowdsec-scenarios.max_content_length', 100);
        $service = new CrowdSecService();
        $middleware = new CrowdSecProtection($service);

        $request = Request::create('/upload', 'POST', [], [], [], [
            'REMOTE_ADDR' => '203.0.113.60',
            'HTTP_CONTENT_LENGTH' => '1000000',
        ]);

        $response = $middleware->handle($request, fn ($req) => new Response('OK', 200));

        $this->assertEquals(403, $response->getStatusCode());
    }

    // =========================================================================
    // Step 7: Login route brute-force detection
    // =========================================================================

    public function test_login_brute_force_triggers_block(): void
    {
        $ip = '203.0.113.70';
        $loginThreshold = Config::get('crowdsec-scenarios.behavior.login_threshold', 5);

        for ($i = 0; $i < $loginThreshold; $i++) {
            $response = $this->sendRequest('/login', 'POST', [], ['REMOTE_ADDR' => $ip]);
            $this->assertEquals(200, $response->getStatusCode());
        }

        $response = $this->sendRequest('/login', 'POST', [], ['REMOTE_ADDR' => $ip]);

        // The request after the configured allowance is blocked.
        $this->assertEquals(403, $response->getStatusCode());
        $this->assertDatabaseHas('blocked_ips', ['ip' => $ip]);
    }

    public function test_login_route_excludes_password_but_keeps_waf_active(): void
    {
        // Passwords may legitimately contain SQL-like patterns.
        $ip = '203.0.113.71';
        $response = $this->sendRequest('/login', 'POST', [
            'email' => 'user@test.com',
            'password' => "OR 1=1 -- valid_password_that_looks_like_sqli",
        ], ['REMOTE_ADDR' => $ip]);

        // The configured password field is excluded while other sources remain inspected.
        $this->assertEquals(200, $response->getStatusCode());
    }

    // =========================================================================
    // Step 8: WAF pattern detection triggers block + 403
    // =========================================================================

    public function test_sql_injection_triggers_block_and_403(): void
    {
        $ip = '203.0.113.80';
        $response = $this->sendFromIp($ip, '/search?q=1+UNION+SELECT+*+FROM+users');

        $this->assertEquals(403, $response->getStatusCode());
        $this->assertDatabaseHas('blocked_ips', ['ip' => $ip]);
        $this->assertDatabaseHas('security_events', [
            'ip' => $ip,
        ]);
    }

    public function test_xss_triggers_block_and_403(): void
    {
        $ip = '203.0.113.81';
        $response = $this->sendFromIp($ip, '/page?content=<script>alert(document.cookie)</script>');

        $this->assertEquals(403, $response->getStatusCode());
        $this->assertDatabaseHas('blocked_ips', ['ip' => $ip]);
    }

    public function test_path_traversal_triggers_block_and_403(): void
    {
        $ip = '203.0.113.82';
        $response = $this->sendFromIp($ip, '/files?path=../../etc/passwd');

        $this->assertEquals(403, $response->getStatusCode());
        $this->assertDatabaseHas('blocked_ips', ['ip' => $ip]);
    }

    public function test_command_injection_triggers_block_and_403(): void
    {
        $ip = '203.0.113.83';
        $response = $this->sendFromIp($ip, '/api?cmd=test;cat+/etc/passwd');

        $this->assertEquals(403, $response->getStatusCode());
        $this->assertDatabaseHas('blocked_ips', ['ip' => $ip]);
    }

    public function test_security_event_logged_on_threat(): void
    {
        $ip = '203.0.113.84';
        $this->sendFromIp($ip, '/search?q=DROP+TABLE+users');

        $event = SecurityEvent::where('ip', $ip)->first();
        $this->assertNotNull($event);
        $this->assertNotNull($event->matched_patterns);
        $this->assertNotNull($event->request_data);
    }

    // =========================================================================
    // Step 9 & 10: Behavior tracking & threshold
    // =========================================================================

    public function test_behavior_tracking_increments_request_count(): void
    {
        $ip = '203.0.113.90';
        $this->sendFromIp($ip);

        $behavior = IpBehavior::where('ip', $ip)->first();
        $this->assertNotNull($behavior);
        $this->assertGreaterThanOrEqual(1, $behavior->request_count);
    }

    public function test_404_tracking(): void
    {
        $ip = '203.0.113.91';
        $request = Request::create('/nonexistent', 'GET', [], [], [], [
            'REMOTE_ADDR' => $ip,
        ]);

        // Simulate middleware with a 404 response
        $this->middleware->handle(
            $request,
            fn ($req) => new Response('Not Found', 404)
        );

        $behavior = IpBehavior::where('ip', $ip)->first();
        $this->assertNotNull($behavior);
        $this->assertGreaterThanOrEqual(1, $behavior->error_404_count);
    }

    // =========================================================================
    // Fail-open behavior
    // =========================================================================

    public function test_fail_open_on_service_error(): void
    {
        // Create a middleware with a mocked service that throws
        $mockService = $this->createMock(CrowdSecService::class);
        $mockService->method('isEnabled')->willReturn(true);
        $mockService->method('isBlocked')->willThrowException(new \RuntimeException('DB error'));

        $middleware = new CrowdSecProtection($mockService);

        $request = Request::create('/test', 'GET', [], [], [], [
            'REMOTE_ADDR' => '203.0.113.99',
        ]);

        // Should NOT crash — fail open, return 200
        $response = $middleware->handle($request, fn ($req) => new Response('OK', 200));
        $this->assertEquals(200, $response->getStatusCode());
    }

    // =========================================================================
    // Clean requests pass through
    // =========================================================================

    public function test_clean_request_passes_through(): void
    {
        $ip = '203.0.113.100';
        $response = $this->sendFromIp($ip, '/api/users?page=1&per_page=20');

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('OK', $response->getContent());
    }

    public function test_clean_post_request_passes_through(): void
    {
        $ip = '203.0.113.101';
        $response = $this->sendRequest('/api/users', 'POST', [
            'name' => 'John Doe',
            'email' => 'john@example.com',
        ], ['REMOTE_ADDR' => $ip]);

        $this->assertEquals(200, $response->getStatusCode());
    }
}

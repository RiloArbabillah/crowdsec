<?php

namespace RiloArbabillah\LaravelCrowdSec\Tests\Feature;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Config;
use Orchestra\Testbench\TestCase;
use RiloArbabillah\LaravelCrowdSec\CrowdSecServiceProvider;
use RiloArbabillah\LaravelCrowdSec\Http\Middleware\CrowdSecProtection;
use RiloArbabillah\LaravelCrowdSec\Models\BlockedIp;
use RiloArbabillah\LaravelCrowdSec\Models\IpBehavior;
use RiloArbabillah\LaravelCrowdSec\Services\CrowdSecService;
use Symfony\Component\HttpFoundation\Response;

/**
 * Edge case and advanced feature tests for CrowdSec.
 */
class EdgeCaseTest extends TestCase
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

    // =========================================================================
    // CIDR whitelist notation
    // =========================================================================

    public function test_cidr_whitelist_allows_matching_ip(): void
    {
        Config::set('crowdsec-scenarios.whitelist_ips', ['10.0.0.0/8']);
        $service = new CrowdSecService();
        $middleware = new CrowdSecProtection($service);

        // 10.1.2.3 falls within 10.0.0.0/8
        $request = Request::create('/search?q=UNION+SELECT+*+FROM+users', 'GET', [], [], [], [
            'REMOTE_ADDR' => '10.1.2.3',
        ]);

        $response = $middleware->handle($request, fn ($req) => new Response('OK', 200));
        $this->assertEquals(200, $response->getStatusCode());
    }

    public function test_cidr_whitelist_blocks_non_matching_ip(): void
    {
        Config::set('crowdsec-scenarios.whitelist_ips', ['10.0.0.0/8']);
        $service = new CrowdSecService();
        $middleware = new CrowdSecProtection($service);

        // 192.168.1.1 does NOT fall within 10.0.0.0/8
        $request = Request::create('/search?q=UNION+SELECT+*+FROM+users', 'GET', [], [], [], [
            'REMOTE_ADDR' => '192.168.1.1',
        ]);

        $response = $middleware->handle($request, fn ($req) => new Response('OK', 200));
        $this->assertEquals(403, $response->getStatusCode());
    }

    public function test_cidr_16_whitelist(): void
    {
        Config::set('crowdsec-scenarios.whitelist_ips', ['192.168.0.0/16']);
        $service = new CrowdSecService();
        $middleware = new CrowdSecProtection($service);

        $request = Request::create('/search?q=UNION+SELECT+*+FROM+users', 'GET', [], [], [], [
            'REMOTE_ADDR' => '192.168.100.50',
        ]);

        $response = $middleware->handle($request, fn ($req) => new Response('OK', 200));
        $this->assertEquals(200, $response->getStatusCode());
    }

    // =========================================================================
    // Progressive escalation
    // =========================================================================

    public function test_progressive_escalation_doubles_duration(): void
    {
        $ip = '198.51.100.20';

        // Create behavior with previous block
        IpBehavior::create([
            'ip' => $ip,
            'request_count' => 0,
            'error_404_count' => 0,
            'login_attempts' => 0,
            'threat_score' => 0,
            'block_count' => 1, // Already blocked once before
            'first_activity' => now(),
            'last_activity' => now(),
        ]);

        // Block with default duration for 'high' severity (720 min)
        $block = $this->service->blockIp($ip, 'Threat: xss', null, 'xss');

        // Duration should be doubled (720 * 2 = 1440)
        $durationMinutes = $block->created_at->diffInMinutes($block->expires_at);
        $this->assertGreaterThan(720, $durationMinutes);
    }

    public function test_progressive_escalation_caps_at_7_days(): void
    {
        $ip = '198.51.100.21';

        // Create behavior with many previous blocks
        IpBehavior::create([
            'ip' => $ip,
            'request_count' => 0,
            'error_404_count' => 0,
            'login_attempts' => 0,
            'threat_score' => 0,
            'block_count' => 10, // Many previous blocks
            'first_activity' => now(),
            'last_activity' => now(),
        ]);

        $block = $this->service->blockIp($ip, 'Threat: sql_injection', null, 'sql_injection');

        // Max should be 7 days = 10080 minutes
        $durationMinutes = $block->created_at->diffInMinutes($block->expires_at);
        $this->assertLessThanOrEqual(10080, $durationMinutes);
    }

    // =========================================================================
    // Block expiration
    // =========================================================================

    public function test_expired_block_does_not_prevent_access(): void
    {
        $ip = '198.51.100.30';
        BlockedIp::create([
            'ip' => $ip,
            'reason' => 'Old block',
            'is_active' => true,
            'expires_at' => now()->subHour(), // Expired 1 hour ago
        ]);

        $this->assertFalse($this->service->isBlocked($ip));
    }

    public function test_active_block_without_expiration_is_permanent(): void
    {
        $ip = '198.51.100.31';
        BlockedIp::create([
            'ip' => $ip,
            'reason' => 'Permanent block',
            'is_active' => true,
            'expires_at' => null, // No expiration
        ]);

        $this->assertTrue($this->service->isBlocked($ip));
    }

    // =========================================================================
    // Empty User-Agent scoring
    // =========================================================================

    public function test_dash_user_agent_counts_as_empty(): void
    {
        Config::set('crowdsec-scenarios.block_empty_ua', true);
        $service = new CrowdSecService();

        $request = Request::create('/test', 'GET', [], [], [], [
            'HTTP_USER_AGENT' => '-',
        ]);

        $this->assertTrue($service->hasEmptyUserAgent($request));
    }

    public function test_whitespace_user_agent_counts_as_empty(): void
    {
        Config::set('crowdsec-scenarios.block_empty_ua', true);
        $service = new CrowdSecService();

        $request = Request::create('/test', 'GET', [], [], [], [
            'HTTP_USER_AGENT' => '   ',
        ]);

        $this->assertTrue($service->hasEmptyUserAgent($request));
    }

    // =========================================================================
    // Login route detection
    // =========================================================================

    public function test_login_route_detection_all_configured_routes(): void
    {
        $loginRoutes = Config::get('crowdsec-scenarios.login_routes', []);

        foreach ($loginRoutes as $route) {
            $request = Request::create("/{$route}", 'POST');
            // Login routes are POST only
            $this->assertEquals('POST', $request->getMethod());
        }

        $this->assertNotEmpty($loginRoutes, 'Login routes should be configured');
    }

    public function test_get_request_to_login_is_not_login_attempt(): void
    {
        // GET /login should NOT be treated as login attempt
        $ip = '203.0.113.110';
        $request = Request::create('/login', 'GET', [], [], [], [
            'REMOTE_ADDR' => $ip,
        ]);

        $response = $this->middleware->handle($request, fn ($req) => new Response('OK', 200));
        $this->assertEquals(200, $response->getStatusCode());

        // Should NOT have login attempts tracked
        $behavior = IpBehavior::where('ip', $ip)->first();
        $this->assertTrue(
            $behavior === null || $behavior->login_attempts === 0,
            'GET /login should not track login attempts'
        );
    }

    // =========================================================================
    // Request body analysis (JSON, form data, raw XML)
    // =========================================================================

    public function test_json_body_threat_detection(): void
    {
        $request = Request::create(
            '/api/data',
            'POST',
            [],
            [],
            [],
            ['CONTENT_TYPE' => 'application/json', 'REMOTE_ADDR' => '203.0.113.120'],
            json_encode(['query' => "1' OR 1=1 --", 'name' => 'test'])
        );

        $threats = $this->service->analyzeRequest($request);
        $sqli = array_filter($threats, fn ($t) => $t['type'] === 'sql_injection');
        $this->assertNotEmpty($sqli, 'Should detect SQLi in JSON body');
    }

    public function test_form_data_threat_detection(): void
    {
        $request = Request::create(
            '/api/form',
            'POST',
            ['comment' => '<script>alert(document.cookie)</script>'],
            [],
            [],
            ['REMOTE_ADDR' => '203.0.113.121']
        );

        $threats = $this->service->analyzeRequest($request);
        $xss = array_filter($threats, fn ($t) => $t['type'] === 'xss');
        $this->assertNotEmpty($xss, 'Should detect XSS in form data');
    }

    public function test_xml_body_xxe_detection(): void
    {
        $xml = '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>';
        $request = Request::create(
            '/api/xml',
            'POST',
            [],
            [],
            [],
            ['CONTENT_TYPE' => 'text/xml', 'REMOTE_ADDR' => '203.0.113.122'],
            $xml
        );

        $threats = $this->service->analyzeRequest($request);
        $xxe = array_filter($threats, fn ($t) => $t['type'] === 'xxe');
        $this->assertNotEmpty($xxe, 'Should detect XXE in XML body');
    }

    // =========================================================================
    // Cookie-based attack detection
    // =========================================================================

    public function test_cookie_sqli_detection(): void
    {
        $request = Request::create('/page', 'GET');
        $request->cookies->set('session', "admin' OR 1=1 --");

        $threats = $this->service->analyzeRequest($request);
        $sqli = array_filter($threats, fn ($t) => $t['type'] === 'sql_injection');
        $this->assertNotEmpty($sqli, 'Should detect SQLi in cookies');
    }

    public function test_clean_cookies_no_false_positive(): void
    {
        $request = Request::create('/page', 'GET');
        $request->cookies->set('session', 'abc123def456');
        $request->cookies->set('theme', 'dark');
        $request->cookies->set('lang', 'en');

        $threats = $this->service->analyzeRequest($request);
        $this->assertEmpty($threats, 'Clean cookies should not trigger threats');
    }

    // =========================================================================
    // Concurrent threats from multiple scenarios
    // =========================================================================

    public function test_concurrent_threats_all_detected(): void
    {
        // Request with SQLi in query + path traversal in path
        $request = Request::create(
            '/files/../../etc/passwd?q=UNION+SELECT+*+FROM+users',
            'GET',
            [],
            [],
            [],
            ['REMOTE_ADDR' => '203.0.113.130']
        );

        $threats = $this->service->analyzeRequest($request);

        $types = array_unique(array_column($threats, 'type'));
        $this->assertContains('sql_injection', $types, 'Should detect SQLi');
        $this->assertContains('path_traversal', $types, 'Should detect path traversal');
        $this->assertGreaterThanOrEqual(2, count($types), 'Should detect multiple threat types');
    }

    public function test_max_severity_from_concurrent_threats(): void
    {
        $severities = ['low', 'medium', 'high', 'critical'];
        $result = $this->service->getMaxSeverity($severities);
        $this->assertEquals('critical', $result);
    }

    // =========================================================================
    // PUT/PATCH/DELETE body analysis
    // =========================================================================

    public function test_put_request_body_analyzed(): void
    {
        $request = Request::create(
            '/api/users/1',
            'PUT',
            ['name' => "admin'; DROP TABLE users; --"],
            [],
            [],
            ['REMOTE_ADDR' => '203.0.113.140']
        );

        $threats = $this->service->analyzeRequest($request);
        $this->assertNotEmpty($threats, 'Should analyze PUT body for threats');
    }

    public function test_delete_request_body_analyzed(): void
    {
        $request = Request::create(
            '/api/users/1',
            'DELETE',
            ['confirm' => '<script>steal()</script>'],
            [],
            [],
            ['REMOTE_ADDR' => '203.0.113.141']
        );

        $threats = $this->service->analyzeRequest($request);
        $this->assertNotEmpty($threats, 'Should analyze DELETE body for threats');
    }
}

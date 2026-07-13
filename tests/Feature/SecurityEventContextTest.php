<?php

namespace RiloArbabillah\LaravelCrowdSec\Tests\Feature;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use Illuminate\Routing\Route;
use Orchestra\Testbench\TestCase;
use RiloArbabillah\LaravelCrowdSec\CrowdSecServiceProvider;
use RiloArbabillah\LaravelCrowdSec\Http\Controllers\CrowdSecApiController;
use RiloArbabillah\LaravelCrowdSec\Http\Controllers\CrowdSecDashboardController;
use RiloArbabillah\LaravelCrowdSec\Http\Middleware\CrowdSecProtection;
use RiloArbabillah\LaravelCrowdSec\Models\SecurityEvent;
use RiloArbabillah\LaravelCrowdSec\Services\CrowdSecService;
use Symfony\Component\HttpFoundation\Response;

class SecurityEventContextTest extends TestCase
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
        $app['config']->set('app.key', 'base64:test-application-key');
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
        $this->loadMigrationsFrom(__DIR__.'/../../src/Database/Migrations');
        $this->service = $this->app->make(CrowdSecService::class);
        $this->middleware = new CrowdSecProtection($this->service);
    }

    public function test_migration_keeps_new_context_nullable_for_legacy_events(): void
    {
        $event = SecurityEvent::create([
            'ip' => '203.0.113.1',
            'event_type' => 'legacy',
            'severity' => 'medium',
        ]);

        $this->assertNull($event->request_id);
        $this->assertNull($event->action_taken);
        $this->assertNull($event->response_status);
        $this->assertNull($event->authenticated_user_id_hash);
    }

    public function test_blocked_event_records_full_context_and_links_block(): void
    {
        config([
            'crowdsec-scenarios.geoip.enabled' => true,
            'crowdsec-scenarios.geoip.provider' => 'custom',
            'crowdsec-scenarios.geoip.custom_callback' => fn (string $ip) => [
                'country_code' => 'us',
                'asn' => 'AS15169 Google LLC',
                'isp' => 'Google LLC',
            ],
        ]);

        $user = $this->createMock(Authenticatable::class);
        $user->method('getAuthIdentifier')->willReturn(42);

        $request = Request::create('/search?q=UNION+SELECT', 'GET', [], [], [], [
            'REMOTE_ADDR' => '8.8.8.8',
            'HTTP_X_REQUEST_ID' => 'edge-request:123',
            'HTTP_USER_AGENT' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'CONTENT_TYPE' => 'application/json; charset=UTF-8',
            'CONTENT_LENGTH' => '128',
        ]);
        $request->setUserResolver(fn () => $user);
        $route = (new Route(['GET'], 'search', fn () => null))->name('search.index');
        $request->setRouteResolver(fn () => $route);

        $response = $this->middleware->handle($request, fn () => new Response('OK'));
        $event = SecurityEvent::where('ip', '8.8.8.8')->firstOrFail();

        $this->assertSame(403, $response->getStatusCode());
        $this->assertSame('edge-request:123', $response->headers->get('X-Request-ID'));
        $this->assertSame('edge-request:123', $event->request_id);
        $this->assertSame('search.index', $event->route_name);
        $this->assertSame('application/json', $event->content_type);
        $this->assertSame(128, $event->content_length);
        $this->assertSame('blocked', $event->action_taken);
        $this->assertSame(403, $event->response_status);
        $this->assertGreaterThanOrEqual(0, $event->duration_ms);
        $this->assertSame('US', $event->country_code);
        $this->assertSame(15169, $event->asn);
        $this->assertSame('Google LLC', $event->isp);
        $this->assertStringStartsWith('Chrome ', $event->browser);
        $this->assertSame('Windows 10', $event->os);
        $this->assertSame('desktop', $event->device_type);
        $this->assertNotNull($event->blocked_ip_id);
        $this->assertNotNull($event->blockedIp);
        $this->assertSame(
            hash_hmac('sha256', $user::class.'|42', 'base64:test-application-key'),
            $event->authenticated_user_id_hash
        );
        $this->assertNotSame('42', $event->authenticated_user_id_hash);
        $this->assertSame(64, strlen($event->authenticated_user_id_hash));
    }

    public function test_low_severity_event_records_actual_downstream_response(): void
    {
        $this->service->registerScenario('low_probe', [
            'patterns' => ['/LOW_RISK_PROBE/'],
            'severity' => 'low',
            'weight' => 1,
        ]);

        $request = Request::create('/search?q=LOW_RISK_PROBE', 'GET', [], [], [], [
            'REMOTE_ADDR' => '203.0.113.20',
            'HTTP_X_REQUEST_ID' => "invalid\nrequest-id",
        ]);

        $response = $this->middleware->handle($request, fn () => new Response('Accepted', 202));
        $event = SecurityEvent::where('ip', '203.0.113.20')->firstOrFail();

        $this->assertSame(202, $response->getStatusCode());
        $this->assertSame('allowed_scored', $event->action_taken);
        $this->assertSame(202, $event->response_status);
        $this->assertMatchesRegularExpression(
            '/\A[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\z/i',
            $event->request_id
        );
        $this->assertSame($event->request_id, $response->headers->get('X-Request-ID'));
        $this->assertNull($event->blocked_ip_id);
    }

    public function test_query_referer_and_sensitive_threat_sources_are_redacted(): void
    {
        $secret = "UNION SELECT secret-value";
        $request = Request::create(
            '/search?token='.rawurlencode($secret).'&profile[secret]=hidden&safe=value',
            'GET',
            [],
            [],
            [],
            [
                'REMOTE_ADDR' => '203.0.113.21',
                'HTTP_REFERER' => 'https://example.test/callback?access_token=referer-secret&next=home',
            ]
        );

        $event = $this->service->logEvent('203.0.113.21', [
            ['type' => 'sql_injection', 'severity' => 'high', 'weight' => 10, 'source' => 'query', 'matched' => $secret],
            ['type' => 'sql_injection', 'severity' => 'high', 'weight' => 10, 'source' => 'cookie_session', 'matched' => 'cookie-secret'],
            ['type' => 'sql_injection', 'severity' => 'high', 'weight' => 10, 'source' => 'body_api_key', 'matched' => 'body-secret'],
        ], $request);

        $serialized = json_encode([
            $event->request_data,
            $event->matched_patterns,
        ]);

        $this->assertStringContainsString('%5BREDACTED%5D', $event->request_data['query']);
        $this->assertStringContainsString('safe=value', $event->request_data['query']);
        $this->assertStringNotContainsString($secret, $serialized);
        $this->assertStringNotContainsString('referer-secret', $serialized);
        $this->assertStringNotContainsString('cookie-secret', $serialized);
        $this->assertStringNotContainsString('body-secret', $serialized);
        $this->assertSame('[REDACTED]', $event->matched_patterns[1]['matched']);
        $this->assertSame('[REDACTED]', $event->matched_patterns[2]['matched']);
    }

    public function test_existing_response_request_id_is_preserved(): void
    {
        $this->service->registerScenario('low_probe', [
            'patterns' => ['/LOW_RISK_PROBE/'],
            'severity' => 'low',
            'weight' => 1,
        ]);
        $request = Request::create('/?q=LOW_RISK_PROBE', 'GET', [], [], [], [
            'REMOTE_ADDR' => '203.0.113.22',
            'HTTP_X_REQUEST_ID' => 'incoming-id',
        ]);
        $next = function () {
            $response = new Response('OK');
            $response->headers->set('X-Request-ID', 'application-id');

            return $response;
        };

        $response = $this->middleware->handle($request, $next);

        $this->assertSame('application-id', $response->headers->get('X-Request-ID'));
        $this->assertSame('incoming-id', SecurityEvent::firstOrFail()->request_id);
    }

    public function test_security_event_persistence_failure_does_not_bypass_block(): void
    {
        SecurityEvent::creating(function () {
            throw new \RuntimeException('Simulated event persistence failure');
        });
        $request = Request::create('/search?q=UNION+SELECT', 'GET', [], [], [], [
            'REMOTE_ADDR' => '203.0.113.23',
        ]);
        $downstreamCalls = 0;

        $response = $this->middleware->handle($request, function () use (&$downstreamCalls) {
            $downstreamCalls++;

            return new Response('OK');
        });

        $this->assertSame(403, $response->getStatusCode());
        $this->assertSame(0, $downstreamCalls);
    }

    public function test_downstream_exception_is_propagated_without_second_invocation(): void
    {
        $request = Request::create('/clean', 'GET', [], [], [], [
            'REMOTE_ADDR' => '203.0.113.24',
        ]);
        $downstreamCalls = 0;

        try {
            $this->middleware->handle($request, function () use (&$downstreamCalls) {
                $downstreamCalls++;
                throw new \DomainException('Application failed');
            });
            $this->fail('Expected downstream exception was not thrown.');
        } catch (\DomainException $e) {
            $this->assertSame('Application failed', $e->getMessage());
        }

        $this->assertSame(1, $downstreamCalls);
    }

    public function test_events_api_filters_new_context_fields(): void
    {
        SecurityEvent::create([
            'ip' => '203.0.113.30',
            'event_type' => 'sql_injection',
            'severity' => 'high',
            'request_id' => 'blocked-request',
            'action_taken' => 'blocked',
            'country_code' => 'ID',
            'response_status' => 403,
        ]);
        SecurityEvent::create([
            'ip' => '203.0.113.31',
            'event_type' => 'low_probe',
            'severity' => 'low',
            'request_id' => 'allowed-request',
            'action_taken' => 'allowed_scored',
            'country_code' => 'SG',
            'response_status' => 202,
        ]);
        $request = Request::create('/api/crowdsec/events', 'GET', [
            'action_taken' => 'blocked',
            'country_code' => 'ID',
            'response_status' => 403,
        ]);

        $response = (new CrowdSecApiController($this->service))->events($request);
        $payload = $response->getData(true);

        $this->assertSame(1, $payload['total']);
        $this->assertSame('blocked-request', $payload['data'][0]['request_id']);
    }

    public function test_dashboard_renders_enriched_event_aggregates(): void
    {
        SecurityEvent::create([
            'ip' => '203.0.113.40',
            'event_type' => 'sql_injection',
            'severity' => 'high',
            'action_taken' => 'blocked',
            'response_status' => 403,
            'country_code' => 'ID',
            'device_type' => 'desktop',
        ]);

        $html = (new CrowdSecDashboardController())->index()->render();

        $this->assertStringContainsString('Top Source Countries', $html);
        $this->assertStringContainsString('Device Types', $html);
        $this->assertStringContainsString('desktop', $html);
        $this->assertStringContainsString('blocked', $html);
    }
}

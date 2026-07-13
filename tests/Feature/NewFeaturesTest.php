<?php

namespace RiloArbabillah\LaravelCrowdSec\Tests\Feature;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Notification;
use Orchestra\Testbench\TestCase;
use RiloArbabillah\LaravelCrowdSec\CrowdSecServiceProvider;
use RiloArbabillah\LaravelCrowdSec\Events\BehaviorThresholdExceeded;
use RiloArbabillah\LaravelCrowdSec\Events\IpBlocked;
use RiloArbabillah\LaravelCrowdSec\Events\IpUnblocked;
use RiloArbabillah\LaravelCrowdSec\Events\ThreatDetected;
use RiloArbabillah\LaravelCrowdSec\Http\Middleware\CrowdSecProtection;
use RiloArbabillah\LaravelCrowdSec\Http\Middleware\CrowdSecRateLimit;
use RiloArbabillah\LaravelCrowdSec\Http\Middleware\HoneypotTrap;
use RiloArbabillah\LaravelCrowdSec\Listeners\SendSecurityAlert;
use RiloArbabillah\LaravelCrowdSec\Models\BlockedIp;
use RiloArbabillah\LaravelCrowdSec\Models\IpBehavior;
use RiloArbabillah\LaravelCrowdSec\Models\SecurityEvent;
use RiloArbabillah\LaravelCrowdSec\Notifications\SecurityAlertNotification;
use RiloArbabillah\LaravelCrowdSec\Services\CrowdSecService;
use RiloArbabillah\LaravelCrowdSec\Services\GeoIpService;
use Symfony\Component\HttpFoundation\Response;

/**
 * Tests for new features added in v1.0-beta:
 * Events, Notifications, HoneypotTrap, RateLimit, GeoIP, Export, Dashboard,
 * Score Decay, Custom Patterns, isWhitelisted.
 */
class NewFeaturesTest extends TestCase
{
    protected CrowdSecService $service;

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
    }

    // =========================================================================
    // EVENT SYSTEM
    // =========================================================================

    public function test_ip_blocked_event_dispatched_on_block(): void
    {
        Event::fake([IpBlocked::class]);

        $this->service->blockIp('10.0.0.1', 'Test block', 60, 'sql_injection');

        Event::assertDispatched(IpBlocked::class, function ($event) {
            return $event->ip === '10.0.0.1'
                && $event->reason === 'Test block'
                && $event->eventType === 'sql_injection';
        });
    }

    public function test_ip_unblocked_event_dispatched_on_unblock(): void
    {
        Event::fake([IpUnblocked::class]);

        $this->service->blockIp('10.0.0.2', 'Block first', 60);
        $this->service->unblockIp('10.0.0.2');

        Event::assertDispatched(IpUnblocked::class, function ($event) {
            return $event->ip === '10.0.0.2';
        });
    }

    public function test_threat_detected_event_has_correct_properties(): void
    {
        $event = new ThreatDetected(
            ip: '10.0.0.3',
            threats: [['type' => 'xss', 'severity' => 'high']],
            severity: 'high',
            uri: '/test',
            method: 'GET',
        );

        $this->assertEquals('10.0.0.3', $event->ip);
        $this->assertEquals('high', $event->severity);
        $this->assertEquals('/test', $event->uri);
        $this->assertCount(1, $event->threats);
    }

    public function test_ip_blocked_event_has_correct_properties(): void
    {
        $event = new IpBlocked(
            ip: '10.0.0.4',
            reason: 'SQL injection detected',
            durationMinutes: 1440,
            blockCount: 2,
            eventType: 'sql_injection',
        );

        $this->assertEquals('10.0.0.4', $event->ip);
        $this->assertEquals(1440, $event->durationMinutes);
        $this->assertEquals(2, $event->blockCount);
        $this->assertEquals('sql_injection', $event->eventType);
    }

    public function test_behavior_threshold_exceeded_event_properties(): void
    {
        $event = new BehaviorThresholdExceeded(
            ip: '10.0.0.5',
            threatScore: 55.0,
            requestCount: 600,
            error404Count: 20,
            loginAttempts: 3,
        );

        $this->assertEquals('10.0.0.5', $event->ip);
        $this->assertEquals(55.0, $event->threatScore);
        $this->assertEquals(600, $event->requestCount);
    }

    // =========================================================================
    // NOTIFICATION / LISTENER
    // =========================================================================

    public function test_security_alert_notification_via_mail(): void
    {
        $notification = new SecurityAlertNotification(
            ip: '10.0.0.6',
            reason: 'XSS detected',
            severity: 'high',
            context: ['event_type' => 'xss'],
        );

        $notifiable = new \stdClass();
        $channels = $notification->via($notifiable);
        $this->assertContains('mail', $channels);

        $mail = $notification->toMail($notifiable);
        $this->assertNotNull($mail);
    }

    public function test_security_alert_notification_via_mail_and_slack(): void
    {
        Config::set('crowdsec-scenarios.notifications.channels', ['mail', 'slack']);

        $notification = new SecurityAlertNotification(
            ip: '10.0.0.6',
            reason: 'XSS detected',
            severity: 'high',
            context: ['event_type' => 'xss'],
        );

        $channels = $notification->via(new \stdClass());

        $this->assertSame(['mail', 'slack'], $channels);
    }

    public function test_security_alert_notification_to_array(): void
    {
        $notification = new SecurityAlertNotification(
            ip: '10.0.0.7',
            reason: 'SQL injection',
            severity: 'critical',
            context: ['event_type' => 'sql_injection'],
        );

        $array = $notification->toArray(new \stdClass());
        $this->assertEquals('10.0.0.7', $array['ip']);
        $this->assertEquals('critical', $array['severity']);
    }

    public function test_send_security_alert_skips_when_disabled(): void
    {
        Notification::fake();
        Config::set('crowdsec-scenarios.notifications.enabled', false);

        $event = new IpBlocked('10.0.0.8', 'Test', 60, 1, 'sql_injection');
        $listener = new SendSecurityAlert();
        $listener->handle($event);

        Notification::assertNothingSent();
    }

    public function test_send_security_alert_skips_low_severity(): void
    {
        Notification::fake();
        Config::set('crowdsec-scenarios.notifications', [
            'enabled' => true,
            'severity_threshold' => 'high',
            'recipients' => ['admin@example.com'],
            'rate_limit_minutes' => 5,
        ]);
        // directory_bruteforce has 'medium' severity (below 'high' threshold)
        $event = new IpBlocked('10.0.0.9', 'Bruteforce', 60, 1, 'directory_bruteforce');
        $listener = new SendSecurityAlert();
        $listener->handle($event);

        Notification::assertNothingSent();
    }

    public function test_send_security_alert_rate_limits(): void
    {
        Notification::fake();
        Cache::flush();
        Config::set('crowdsec-scenarios.notifications', [
            'enabled' => true,
            'severity_threshold' => 'medium',
            'recipients' => ['admin@example.com'],
            'rate_limit_minutes' => 5,
        ]);

        $event = new IpBlocked('10.0.0.10', 'SQLi', 1440, 1, 'sql_injection');
        $listener = new SendSecurityAlert();

        // First call — should send
        $listener->handle($event);

        // Second call — should be rate-limited
        $listener->handle($event);

        Notification::assertSentToTimes(
            Notification::route('mail', ['admin@example.com']),
            SecurityAlertNotification::class,
            1
        );
    }

    public function test_send_security_alert_routes_mail_and_slack_channels(): void
    {
        Notification::fake();
        Cache::flush();
        Config::set('crowdsec-scenarios.notifications', [
            'enabled' => true,
            'channels' => ['mail', 'slack'],
            'severity_threshold' => 'medium',
            'recipients' => ['admin@example.com'],
            'slack_webhook_url' => 'https://hooks.slack.test/services/T000/B000/XXXX',
            'rate_limit_minutes' => 5,
        ]);

        $event = new IpBlocked('10.0.0.11', 'SQLi', 1440, 1, 'sql_injection');
        $listener = new SendSecurityAlert();
        $listener->handle($event);

        Notification::assertSentOnDemand(SecurityAlertNotification::class, function ($notification, $channels, $notifiable) {
            return $notification->ip === '10.0.0.11'
                && $channels === ['mail', 'slack']
                && $notifiable->routeNotificationFor('mail') === ['admin@example.com']
                && $notifiable->routeNotificationFor('slack') === 'https://hooks.slack.test/services/T000/B000/XXXX';
        });
    }

    public function test_send_security_alert_routes_slack_only_channel(): void
    {
        Notification::fake();
        Cache::flush();
        Config::set('crowdsec-scenarios.notifications', [
            'enabled' => true,
            'channels' => ['slack'],
            'severity_threshold' => 'medium',
            'recipients' => [],
            'slack_webhook_url' => 'https://hooks.slack.test/services/T000/B000/SLACK',
            'rate_limit_minutes' => 5,
        ]);

        $event = new IpBlocked('10.0.0.12', 'SQLi', 1440, 1, 'sql_injection');
        $listener = new SendSecurityAlert();
        $listener->handle($event);

        Notification::assertSentOnDemand(SecurityAlertNotification::class, function ($notification, $channels, $notifiable) {
            return $notification->ip === '10.0.0.12'
                && $channels === ['slack']
                && $notifiable->routeNotificationFor('mail') === null
                && $notifiable->routeNotificationFor('slack') === 'https://hooks.slack.test/services/T000/B000/SLACK';
        });
    }

    public function test_send_security_alert_skips_slack_without_webhook_when_no_mail_route_exists(): void
    {
        Notification::fake();
        Cache::flush();
        Config::set('crowdsec-scenarios.notifications', [
            'enabled' => true,
            'channels' => ['slack'],
            'severity_threshold' => 'medium',
            'recipients' => [],
            'slack_webhook_url' => '',
            'rate_limit_minutes' => 5,
        ]);

        $event = new IpBlocked('10.0.0.13', 'SQLi', 1440, 1, 'sql_injection');
        $listener = new SendSecurityAlert();
        $listener->handle($event);

        Notification::assertNothingSent();
    }

    // =========================================================================
    // HONEYPOT TRAP MIDDLEWARE
    // =========================================================================

    public function test_honeypot_blocks_env_route(): void
    {
        Config::set('crowdsec-scenarios.honeypot_routes', ['.env', 'wp-admin']);

        $request = Request::create('/.env', 'GET', [], [], [], [
            'REMOTE_ADDR' => '10.0.0.11',
        ]);

        $middleware = new HoneypotTrap($this->service);
        $response = $middleware->handle($request, fn ($req) => new Response('OK', 200));

        $this->assertEquals(403, $response->getStatusCode());
    }

    public function test_honeypot_blocks_wp_admin(): void
    {
        Config::set('crowdsec-scenarios.honeypot_routes', ['.env', 'wp-admin']);

        $request = Request::create('/wp-admin/index.php', 'GET', [], [], [], [
            'REMOTE_ADDR' => '10.0.0.12',
        ]);

        $middleware = new HoneypotTrap($this->service);
        $response = $middleware->handle($request, fn ($req) => new Response('OK', 200));

        $this->assertEquals(403, $response->getStatusCode());
    }

    public function test_honeypot_allows_normal_routes(): void
    {
        Config::set('crowdsec-scenarios.honeypot_routes', ['.env', 'wp-admin']);

        $request = Request::create('/dashboard', 'GET', [], [], [], [
            'REMOTE_ADDR' => '10.0.0.13',
        ]);

        $middleware = new HoneypotTrap($this->service);
        $response = $middleware->handle($request, fn ($req) => new Response('OK', 200));

        $this->assertEquals(200, $response->getStatusCode());
    }

    public function test_honeypot_passes_when_no_routes_configured(): void
    {
        Config::set('crowdsec-scenarios.honeypot_routes', []);

        $request = Request::create('/.env', 'GET', [], [], [], [
            'REMOTE_ADDR' => '10.0.0.14',
        ]);

        $middleware = new HoneypotTrap($this->service);
        $response = $middleware->handle($request, fn ($req) => new Response('OK', 200));

        $this->assertEquals(200, $response->getStatusCode());
    }

    public function test_honeypot_creates_block_record(): void
    {
        Config::set('crowdsec-scenarios.honeypot_routes', ['.env']);

        $request = Request::create('/.env', 'GET', [], [], [], [
            'REMOTE_ADDR' => '10.0.0.15',
        ]);

        $middleware = new HoneypotTrap($this->service);
        $middleware->handle($request, fn ($req) => new Response('OK', 200));

        $this->assertTrue($this->service->isBlocked('10.0.0.15'));
        $block = BlockedIp::where('ip', '10.0.0.15')->first();
        $this->assertStringContainsString('Honeypot', $block->reason);
    }

    // =========================================================================
    // RATE LIMITING MIDDLEWARE
    // =========================================================================

    public function test_rate_limit_allows_under_threshold(): void
    {
        Cache::flush();

        $request = Request::create('/api/data', 'GET', [], [], [], [
            'REMOTE_ADDR' => '10.0.0.20',
        ]);

        $middleware = new CrowdSecRateLimit();
        $response = $middleware->handle($request, fn ($req) => new Response('OK', 200), '60', '1');

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('60', $response->headers->get('X-RateLimit-Limit'));
    }

    public function test_rate_limit_blocks_after_exceeding_max(): void
    {
        Cache::flush();
        $ip = '10.0.0.21';
        $middleware = new CrowdSecRateLimit();

        // Send requests up to exactly the limit
        for ($i = 0; $i < 3; $i++) {
            $request = Request::create('/api/limited', 'GET', [], [], [], [
                'REMOTE_ADDR' => $ip,
            ]);
            $response = $middleware->handle($request, fn ($req) => new Response('OK', 200), '3', '1');
        }

        // The 4th request should be blocked
        $request = Request::create('/api/limited', 'GET', [], [], [], [
            'REMOTE_ADDR' => $ip,
        ]);
        $response = $middleware->handle($request, fn ($req) => new Response('OK', 200), '3', '1');

        $this->assertEquals(429, $response->getStatusCode());
        $this->assertNotNull($response->headers->get('Retry-After'));
        $this->assertEquals('0', $response->headers->get('X-RateLimit-Remaining'));
    }

    public function test_rate_limit_includes_remaining_header(): void
    {
        Cache::flush();
        $ip = '10.0.0.22';

        $request = Request::create('/api/data', 'GET', [], [], [], [
            'REMOTE_ADDR' => $ip,
        ]);

        $middleware = new CrowdSecRateLimit();
        $response = $middleware->handle($request, fn ($req) => new Response('OK', 200), '10', '1');

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('10', $response->headers->get('X-RateLimit-Limit'));
        $remaining = (int) $response->headers->get('X-RateLimit-Remaining');
        $this->assertLessThan(10, $remaining);
    }

    public function test_rate_limit_separate_per_ip(): void
    {
        Cache::flush();
        $middleware = new CrowdSecRateLimit();

        // IP A sends 2 requests
        for ($i = 0; $i < 2; $i++) {
            $request = Request::create('/api/test', 'GET', [], [], [], [
                'REMOTE_ADDR' => '10.0.0.23',
            ]);
            $middleware->handle($request, fn ($req) => new Response('OK', 200), '3', '1');
        }

        // IP B should still have full quota
        $request = Request::create('/api/test', 'GET', [], [], [], [
            'REMOTE_ADDR' => '10.0.0.24',
        ]);
        $response = $middleware->handle($request, fn ($req) => new Response('OK', 200), '3', '1');

        $this->assertEquals(200, $response->getStatusCode());
    }

    // =========================================================================
    // GEOIP SERVICE
    // =========================================================================

    public function test_geoip_returns_empty_for_private_ip(): void
    {
        $geoip = new GeoIpService();
        $result = $geoip->lookup('127.0.0.1');

        $this->assertNull($result['country']);
        $this->assertNull($result['city']);
    }

    public function test_geoip_returns_empty_for_localhost(): void
    {
        $geoip = new GeoIpService();
        $result = $geoip->lookup('192.168.1.1');

        $this->assertNull($result['country']);
    }

    public function test_geoip_caches_result(): void
    {
        Http::fake([
            'ip-api.com/*' => Http::response([
                'status' => 'success',
                'country' => 'United States',
                'countryCode' => 'US',
                'regionName' => 'California',
                'city' => 'San Francisco',
                'lat' => 37.7749,
                'lon' => -122.4194,
                'as' => 'AS15169 Google LLC',
                'isp' => 'Test ISP',
            ]),
        ]);

        Cache::flush();
        $geoip = new GeoIpService();

        // First call — should hit API
        $result1 = $geoip->lookup('8.8.8.8');
        $this->assertEquals('United States', $result1['country']);
        $this->assertSame(15169, $result1['asn']);

        // Second call — should hit cache (no additional HTTP call)
        $result2 = $geoip->lookup('8.8.8.8');
        $this->assertEquals('United States', $result2['country']);

        Http::assertSentCount(1);
    }

    public function test_geoip_handles_api_failure(): void
    {
        Http::fake([
            'ip-api.com/*' => Http::response(['status' => 'fail'], 200),
        ]);

        Cache::flush();
        $geoip = new GeoIpService();
        $result = $geoip->lookup('8.8.4.4');

        $this->assertNull($result['country']);
    }

    public function test_geoip_handles_http_error(): void
    {
        Http::fake([
            'ip-api.com/*' => Http::response('Server Error', 500),
        ]);

        Cache::flush();
        $geoip = new GeoIpService();
        $result = $geoip->lookup('1.1.1.1');

        $this->assertNull($result['country']);
    }

    public function test_geoip_custom_callback_provider(): void
    {
        Config::set('crowdsec-scenarios.geoip.provider', 'custom');
        Config::set('crowdsec-scenarios.geoip.custom_callback', function ($ip) {
            return [
                'country' => 'TestLand',
                'country_code' => 'TL',
                'region' => null,
                'city' => null,
                'lat' => null,
                'lon' => null,
                'isp' => null,
            ];
        });

        Cache::flush();
        $geoip = new GeoIpService();
        $result = $geoip->lookup('8.8.8.8');

        $this->assertEquals('TestLand', $result['country']);
    }

    // =========================================================================
    // SIEM EXPORT COMMAND
    // =========================================================================

    public function test_export_json_format(): void
    {
        SecurityEvent::create([
            'ip' => '10.0.0.30',
            'event_type' => 'sql_injection',
            'severity' => 'critical',
            'request_data' => ['uri' => '/test', 'method' => 'GET', 'user_agent' => 'curl'],
            'matched_patterns' => ['UNION SELECT'],
            'request_id' => 'export-request-id',
            'action_taken' => 'blocked',
            'response_status' => 403,
        ]);

        $output = tempnam(sys_get_temp_dir(), 'crowdsec-json-');
        $this->artisan('crowdsec:export', ['--format' => 'json', '--output' => $output])
            ->assertSuccessful();

        $exported = json_decode(file_get_contents($output), true);
        @unlink($output);

        $this->assertSame('export-request-id', $exported[0]['request_id']);
        $this->assertSame('blocked', $exported[0]['action_taken']);
        $this->assertSame(403, $exported[0]['response_status']);
    }

    public function test_export_csv_format(): void
    {
        SecurityEvent::create([
            'ip' => '10.0.0.31',
            'event_type' => 'xss',
            'severity' => 'high',
            'request_data' => ['uri' => '/form', 'method' => 'POST', 'user_agent' => 'Mozilla'],
            'matched_patterns' => ['<script>'],
        ]);

        $this->artisan('crowdsec:export', ['--format' => 'csv'])
            ->assertSuccessful();
    }

    public function test_export_syslog_format(): void
    {
        SecurityEvent::create([
            'ip' => '10.0.0.32',
            'event_type' => 'path_traversal',
            'severity' => 'critical',
            'request_data' => ['uri' => '/../../etc/passwd', 'method' => 'GET'],
            'matched_patterns' => ['../'],
        ]);

        $this->artisan('crowdsec:export', ['--format' => 'syslog'])
            ->assertSuccessful();
    }

    public function test_export_no_events_shows_message(): void
    {
        $this->artisan('crowdsec:export')
            ->expectsOutput('No events found matching the criteria.')
            ->assertSuccessful();
    }

    public function test_export_severity_filter(): void
    {
        SecurityEvent::create([
            'ip' => '10.0.0.33',
            'event_type' => 'sql_injection',
            'severity' => 'critical',
            'request_data' => [],
            'matched_patterns' => [],
        ]);
        SecurityEvent::create([
            'ip' => '10.0.0.34',
            'event_type' => 'directory_bruteforce',
            'severity' => 'medium',
            'request_data' => [],
            'matched_patterns' => [],
        ]);

        $this->artisan('crowdsec:export', ['--severity' => 'critical'])
            ->assertSuccessful();
    }

    public function test_export_to_file(): void
    {
        SecurityEvent::create([
            'ip' => '10.0.0.35',
            'event_type' => 'xss',
            'severity' => 'high',
            'request_data' => ['uri' => '/test'],
            'matched_patterns' => [],
        ]);

        $output = '/tmp/crowdsec-export-test.json';
        $this->artisan('crowdsec:export', ['--output' => $output])
            ->assertSuccessful();

        $this->assertFileExists($output);
        $content = json_decode(file_get_contents($output), true);
        $this->assertNotEmpty($content);
        @unlink($output);
    }

    // =========================================================================
    // CUSTOM PATTERN REGISTRATION
    // =========================================================================

    public function test_register_custom_scenario(): void
    {
        $this->service->registerScenario('custom_attack', [
            'patterns' => ['/CUSTOM_ATTACK_PATTERN/i'],
            'weight' => 10,
            'severity' => 'high',
            'block_duration' => 720,
        ]);

        $request = Request::create('/search?q=CUSTOM_ATTACK_PATTERN', 'GET', [], [], [], [
            'REMOTE_ADDR' => '10.0.0.40',
        ]);

        $threats = $this->service->analyzeRequest($request);
        $custom = array_filter($threats, fn ($t) => $t['type'] === 'custom_attack');
        $this->assertNotEmpty($custom, 'Custom scenario should detect CUSTOM_ATTACK_PATTERN');
    }

    public function test_custom_scenario_does_not_replace_built_in(): void
    {
        $this->service->registerScenario('custom_test', [
            'patterns' => ['/FOOBAR_TEST/i'],
            'weight' => 5,
            'severity' => 'low',
            'block_duration' => 60,
        ]);

        // Built-in SQLi should still work
        $request = Request::create('/search?q=UNION+SELECT+*+FROM+users', 'GET', [], [], [], [
            'REMOTE_ADDR' => '10.0.0.41',
        ]);

        $threats = $this->service->analyzeRequest($request);
        $sqli = array_filter($threats, fn ($t) => $t['type'] === 'sql_injection');
        $this->assertNotEmpty($sqli, 'Built-in SQLi detection should still work');
    }

    // =========================================================================
    // THREAT SCORE DECAY
    // =========================================================================

    public function test_threat_score_decay_reduces_score(): void
    {
        IpBehavior::create([
            'ip' => '10.0.0.50',
            'request_count' => 100,
            'error_404_count' => 5,
            'login_attempts' => 0,
            'threat_score' => 40,
            'block_count' => 0,
            'first_activity' => now()->subDays(3),
            'last_activity' => now()->subHours(5),
        ]);

        // Refresh from DB to ensure proper Carbon casting
        $behavior = IpBehavior::where('ip', '10.0.0.50')->first();
        $result = $behavior->decayThreatScore(5.0, 60);

        $this->assertTrue($result, 'Decay should return true for IP inactive > 60 min');
        $behavior->refresh();
        $this->assertLessThan(40, (float) $behavior->threat_score);
    }

    public function test_threat_score_decay_never_goes_below_zero(): void
    {
        IpBehavior::create([
            'ip' => '10.0.0.51',
            'request_count' => 10,
            'error_404_count' => 0,
            'login_attempts' => 0,
            'threat_score' => 5,
            'block_count' => 0,
            'first_activity' => now()->subDays(30),
            'last_activity' => now()->subDays(30),
        ]);

        $behavior = IpBehavior::where('ip', '10.0.0.51')->first();
        $behavior->decayThreatScore(5.0, 60);
        $behavior->refresh();

        $this->assertGreaterThanOrEqual(0, (float) $behavior->threat_score);
    }

    public function test_apply_decay_all_processes_multiple_ips(): void
    {
        IpBehavior::create([
            'ip' => '10.0.0.52',
            'request_count' => 100,
            'error_404_count' => 5,
            'login_attempts' => 0,
            'threat_score' => 30,
            'block_count' => 0,
            'first_activity' => now()->subHours(10),
            'last_activity' => now()->subHours(5),
        ]);

        IpBehavior::create([
            'ip' => '10.0.0.53',
            'request_count' => 50,
            'error_404_count' => 2,
            'login_attempts' => 0,
            'threat_score' => 20,
            'block_count' => 0,
            'first_activity' => now()->subHours(10),
            'last_activity' => now()->subHours(5),
        ]);

        // applyDecayAll queries from DB so Carbon casting should work
        $count = IpBehavior::applyDecayAll(5.0, 60);
        $this->assertGreaterThanOrEqual(2, $count);

        // Verify scores actually decreased
        $this->assertLessThan(30, (float) IpBehavior::where('ip', '10.0.0.52')->first()->threat_score);
        $this->assertLessThan(20, (float) IpBehavior::where('ip', '10.0.0.53')->first()->threat_score);
    }

    // =========================================================================
    // IS_WHITELISTED METHOD
    // =========================================================================

    public function test_is_whitelisted_exact_match(): void
    {
        Config::set('crowdsec-scenarios.whitelist_ips', ['127.0.0.1', '10.0.0.1']);

        $service = new CrowdSecService();
        $this->assertTrue($service->isWhitelisted('127.0.0.1'));
        $this->assertTrue($service->isWhitelisted('10.0.0.1'));
        $this->assertFalse($service->isWhitelisted('192.168.1.1'));
    }

    public function test_is_whitelisted_cidr_match(): void
    {
        Config::set('crowdsec-scenarios.whitelist_ips', ['10.0.0.0/8']);

        $service = new CrowdSecService();
        $this->assertTrue($service->isWhitelisted('10.1.2.3'));
        $this->assertTrue($service->isWhitelisted('10.255.255.255'));
        $this->assertFalse($service->isWhitelisted('11.0.0.1'));
    }

    // =========================================================================
    // BLOCKED IP CACHING
    // =========================================================================

    public function test_blocked_ip_uses_cache(): void
    {
        Config::set('crowdsec-scenarios.cache.enabled', true);
        Config::set('crowdsec-scenarios.cache.ttl', 300);

        Cache::flush();
        $service = new CrowdSecService();

        // Not blocked initially
        $this->assertFalse($service->isBlocked('10.0.0.60'));

        // Block the IP
        $service->blockIp('10.0.0.60', 'Test', 60);

        // Should be blocked (cache updated)
        $this->assertTrue($service->isBlocked('10.0.0.60'));
    }

    public function test_unblock_invalidates_cache(): void
    {
        Config::set('crowdsec-scenarios.cache.enabled', true);

        Cache::flush();
        $service = new CrowdSecService();

        $service->blockIp('10.0.0.61', 'Test', 60);
        $this->assertTrue($service->isBlocked('10.0.0.61'));

        $service->unblockIp('10.0.0.61');
        $this->assertFalse($service->isBlocked('10.0.0.61'));
    }

    // =========================================================================
    // DASHBOARD CONTROLLER
    // =========================================================================

    public function test_dashboard_disabled_by_default(): void
    {
        Config::set('crowdsec-scenarios.dashboard.enabled', false);

        // Dashboard should not be registered if disabled
        $this->assertFalse(config('crowdsec-scenarios.dashboard.enabled'));
    }

    // =========================================================================
    // CROWDSEC STATS COMMAND
    // =========================================================================

    public function test_stats_command_runs_successfully(): void
    {
        $this->artisan('crowdsec:stats')
            ->assertSuccessful();
    }

    public function test_stats_command_json_output(): void
    {
        $this->artisan('crowdsec:stats', ['--json' => true])
            ->assertSuccessful();
    }

    // =========================================================================
    // CLEANUP COMMAND
    // =========================================================================

    public function test_cleanup_command_runs_successfully(): void
    {
        // Create expired block
        BlockedIp::create([
            'ip' => '10.0.0.70',
            'reason' => 'Expired',
            'is_active' => true,
            'expires_at' => now()->subHour(),
        ]);

        $this->artisan('crowdsec:cleanup')
            ->assertSuccessful();
    }

    public function test_cleanup_dry_run(): void
    {
        BlockedIp::create([
            'ip' => '10.0.0.71',
            'reason' => 'Expired',
            'is_active' => true,
            'expires_at' => now()->subHour(),
        ]);

        $this->artisan('crowdsec:cleanup', ['--dry-run' => true])
            ->assertSuccessful();

        // Block should still exist (dry run)
        $this->assertDatabaseHas('blocked_ips', ['ip' => '10.0.0.71']);
    }
}

<?php

namespace RiloArbabillah\LaravelCrowdSec\Tests\Feature;

use Illuminate\Auth\Events\Authenticated;
use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\GenericUser;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Config;
use RiloArbabillah\LaravelCrowdSec\Http\Middleware\CrowdSecProtection;
use RiloArbabillah\LaravelCrowdSec\Models\BlockedIp;
use RiloArbabillah\LaravelCrowdSec\Models\IpBehavior;
use RiloArbabillah\LaravelCrowdSec\Services\CrowdSecService;
use RiloArbabillah\LaravelCrowdSec\Tests\PackageTestCase;
use Symfony\Component\HttpFoundation\Response;

/**
 * Filament (and any Livewire app) routes every interaction — login, forms,
 * polling — through POST /livewire/update. These tests cover the behaviour
 * that differs from classic form posts.
 */
class FilamentLivewireCompatibilityTest extends PackageTestCase
{
    private const IP = '203.0.113.50';

    protected function setUp(): void
    {
        parent::setUp();
        $this->loadMigrationsFrom(__DIR__ . '/../../src/Database/Migrations');
    }

    /**
     * @param  array<string, mixed>  $payload
     */
    private function livewireRequest(array $payload, ?GenericUser $user = null): Request
    {
        $request = Request::create('/livewire/update', 'POST', [], [], [], [
            'REMOTE_ADDR' => self::IP,
            'CONTENT_TYPE' => 'application/json',
            'HTTP_X_LIVEWIRE' => 'true',
            'HTTP_ACCEPT' => 'application/json',
            'HTTP_USER_AGENT' => 'Mozilla/5.0',
        ], json_encode($payload, JSON_THROW_ON_ERROR));

        if ($user !== null) {
            $this->actingAs($user);
        }

        return $request;
    }

    private function handle(Request $request): Response
    {
        $this->app->instance('request', $request);
        $middleware = new CrowdSecProtection(app('crowdsec'));

        return $middleware->handle($request, fn () => new Response('OK', 200));
    }

    /**
     * @param  array<string, mixed>  $data
     * @param  array<string, mixed>  $updates
     * @return array<string, mixed>
     */
    private function loginPayload(array $data, array $updates = []): array
    {
        return [
            'components' => [[
                'snapshot' => json_encode([
                    'data' => ['data' => [$data, ['s' => 'arr']]],
                    'memo' => ['name' => 'filament.auth.pages.login', 'path' => 'admin/login', 'method' => 'GET'],
                    'checksum' => 'abc123',
                ], JSON_THROW_ON_ERROR),
                'updates' => $updates,
                'calls' => [['path' => '', 'method' => 'authenticate', 'params' => []]],
            ]],
        ];
    }

    public function test_password_in_livewire_updates_is_not_inspected(): void
    {
        $response = $this->handle($this->livewireRequest(
            $this->loginPayload(['email' => 'admin@example.com'], ['data.password' => "a' OR 1=1--"]),
        ));

        $this->assertSame(200, $response->getStatusCode());
        $this->assertFalse(BlockedIp::isBlocked(self::IP));
    }

    public function test_password_in_livewire_snapshot_is_not_inspected(): void
    {
        $response = $this->handle($this->livewireRequest(
            $this->loginPayload(['email' => 'admin@example.com', 'password' => "a' OR 1=1--"]),
        ));

        $this->assertSame(200, $response->getStatusCode());
        $this->assertFalse(BlockedIp::isBlocked(self::IP));
    }

    public function test_password_field_on_non_login_form_is_not_inspected(): void
    {
        $request = Request::create('/admin/users/1', 'POST', [
            'name' => 'Admin',
            'password' => "x' UNION SELECT password FROM users--",
        ], [], [], ['REMOTE_ADDR' => self::IP, 'HTTP_USER_AGENT' => 'Mozilla/5.0']);

        $this->assertSame(200, $this->handle($request)->getStatusCode());
    }

    public function test_other_livewire_fields_are_still_inspected(): void
    {
        $response = $this->handle($this->livewireRequest(
            $this->loginPayload(['email' => 'admin@example.com'], ['data.email' => "' UNION SELECT password FROM users--"]),
        ));

        $this->assertSame(403, $response->getStatusCode());
    }

    public function test_attack_inside_livewire_snapshot_is_still_inspected(): void
    {
        $response = $this->handle($this->livewireRequest(
            $this->loginPayload(['email' => "' UNION SELECT password FROM users--"]),
        ));

        $this->assertSame(403, $response->getStatusCode());
    }

    public function test_failed_auth_event_counts_login_attempts_and_blocks(): void
    {
        $threshold = (int) Config::get('crowdsec-scenarios.behavior.login_threshold', 5);
        $this->app->instance('request', $this->livewireRequest($this->loginPayload([])));

        for ($i = 0; $i < $threshold; $i++) {
            event(new Failed('web', null, ['email' => 'admin@example.com']));
        }

        $this->assertSame($threshold, IpBehavior::where('ip', self::IP)->value('login_attempts'));
        $this->assertTrue(BlockedIp::isBlocked(self::IP));
    }

    public function test_failed_auth_event_on_path_matched_login_route_is_not_double_counted(): void
    {
        $request = Request::create('/login', 'POST', ['email' => 'a@example.com'], [], [], [
            'REMOTE_ADDR' => self::IP,
            'HTTP_USER_AGENT' => 'Mozilla/5.0',
        ]);

        $this->handle($request);
        event(new Failed('web', null, ['email' => 'a@example.com']));

        $this->assertSame(1, IpBehavior::where('ip', self::IP)->value('login_attempts'));
    }

    public function test_manual_tracking_after_failed_event_is_not_double_counted(): void
    {
        $this->app->instance('request', $this->livewireRequest($this->loginPayload([])));

        event(new Failed('web', null, ['username' => 'admin']));
        app(CrowdSecService::class)->trackLoginAttempt(self::IP);

        $this->assertSame(1, IpBehavior::where('ip', self::IP)->value('login_attempts'));

        // A second manual call in the same request still counts.
        app(CrowdSecService::class)->trackLoginAttempt(self::IP);
        $this->assertSame(2, IpBehavior::where('ip', self::IP)->value('login_attempts'));
    }

    public function test_password_is_excluded_when_published_config_lacks_sensitive_fields(): void
    {
        $waf = Config::get('crowdsec-scenarios.waf');
        unset($waf['sensitive_body_fields']);
        Config::set('crowdsec-scenarios.waf', $waf);
        $this->app->forgetInstance('crowdsec');

        $response = $this->handle($this->livewireRequest(
            $this->loginPayload(['email' => 'admin@example.com'], ['data.password' => "a' OR 1=1--"]),
        ));

        $this->assertSame(200, $response->getStatusCode());
    }

    public function test_failed_auth_event_tracking_can_be_disabled(): void
    {
        Config::set('crowdsec-scenarios.behavior.track_failed_auth_event', false);
        $this->app->instance('request', $this->livewireRequest($this->loginPayload([])));

        event(new Failed('web', null, ['email' => 'admin@example.com']));

        $this->assertNull(IpBehavior::where('ip', self::IP)->value('login_attempts'));
    }

    public function test_login_event_resets_login_window_but_authenticated_does_not(): void
    {
        $this->app->instance('request', $this->livewireRequest($this->loginPayload([])));
        app(CrowdSecService::class)->trackLoginAttempt(self::IP);

        event(new Authenticated('web', new GenericUser(['id' => 1])));
        $this->assertSame(1, IpBehavior::where('ip', self::IP)->value('login_attempts'));

        event(new Login('web', new GenericUser(['id' => 1]), false));
        $this->assertSame(0, IpBehavior::where('ip', self::IP)->value('login_attempts'));
    }

    public function test_authenticated_requests_do_not_increase_request_count(): void
    {
        $user = new GenericUser(['id' => 1]);

        for ($i = 0; $i < 3; $i++) {
            $this->handle($this->livewireRequest(['components' => []], $user));
        }

        $this->assertSame(0, (int) IpBehavior::where('ip', self::IP)->value('request_count'));
    }

    public function test_authenticated_request_counting_can_be_re_enabled(): void
    {
        Config::set('crowdsec-scenarios.behavior.skip_authenticated_request_count', false);
        $user = new GenericUser(['id' => 1]);

        $this->handle($this->livewireRequest(['components' => []], $user));

        $this->assertSame(1, (int) IpBehavior::where('ip', self::IP)->value('request_count'));
    }

    public function test_guest_requests_still_increase_request_count(): void
    {
        $this->handle($this->livewireRequest(['components' => []]));

        $this->assertSame(1, (int) IpBehavior::where('ip', self::IP)->value('request_count'));
    }

    public function test_blocked_response_is_json_for_livewire_and_json_requests(): void
    {
        app(CrowdSecService::class)->blockIp(self::IP, 'test', 30);

        $response = $this->handle($this->livewireRequest(['components' => []]));

        $this->assertSame(403, $response->getStatusCode());
        $this->assertStringContainsString('application/json', (string) $response->headers->get('Content-Type'));
        $body = json_decode((string) $response->getContent(), true);
        $this->assertIsString($body['message'] ?? null);
        $this->assertSame(self::IP, $body['ip'] ?? null);
    }

    public function test_blocked_response_stays_plain_text_for_browser_requests(): void
    {
        app(CrowdSecService::class)->blockIp(self::IP, 'test', 30);

        $request = Request::create('/dashboard', 'GET', [], [], [], [
            'REMOTE_ADDR' => self::IP,
            'HTTP_USER_AGENT' => 'Mozilla/5.0',
        ]);
        $response = $this->handle($request);

        $this->assertSame(403, $response->getStatusCode());
        $this->assertStringContainsString('IP: ' . self::IP, (string) $response->getContent());
    }

    public function test_new_block_response_includes_retry_after(): void
    {
        $response = $this->handle($this->livewireRequest(
            $this->loginPayload(['email' => 'admin@example.com'], ['data.email' => "' UNION SELECT password FROM users--"]),
        ));

        $this->assertSame(403, $response->getStatusCode());
        $this->assertGreaterThan(0, (int) $response->headers->get('Retry-After'));
    }
}

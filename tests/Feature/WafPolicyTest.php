<?php

namespace RiloArbabillah\LaravelCrowdSec\Tests\Feature;

use Illuminate\Http\Request;
use Illuminate\Http\UploadedFile;
use Illuminate\Routing\Route;
use Illuminate\Support\Facades\Config;
use Orchestra\Testbench\TestCase;
use RiloArbabillah\LaravelCrowdSec\CrowdSecServiceProvider;
use RiloArbabillah\LaravelCrowdSec\Http\Middleware\CrowdSecProtection;
use RiloArbabillah\LaravelCrowdSec\Models\BlockedIp;
use RiloArbabillah\LaravelCrowdSec\Models\IpBehavior;
use RiloArbabillah\LaravelCrowdSec\Models\SecurityEvent;
use RiloArbabillah\LaravelCrowdSec\Services\CrowdSecService;
use Symfony\Component\HttpFoundation\Response;

class WafPolicyTest extends TestCase
{
    protected function getPackageProviders($app): array
    {
        return [CrowdSecServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        $app['config']->set('crowdsec-scenarios', require __DIR__.'/../../config/crowdsec-scenarios.php');
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
    }

    public function test_monitor_mode_logs_without_scoring_or_blocking(): void
    {
        Config::set('crowdsec-scenarios.waf.scenario_modes.sql_injection', 'monitor');

        $response = $this->send('/search?q=1%20OR%201=1', 'GET', '203.0.113.220');

        $this->assertSame(200, $response->getStatusCode());
        $this->assertFalse(BlockedIp::where('ip', '203.0.113.220')->exists());
        $this->assertSame(0.0, (float) IpBehavior::where('ip', '203.0.113.220')->value('threat_score'));
        $this->assertSame('monitored', SecurityEvent::where('ip', '203.0.113.220')->value('action_taken'));
    }

    public function test_disabled_mode_omits_detection(): void
    {
        Config::set('crowdsec-scenarios.waf.scenario_modes.sql_injection', 'disabled');

        $response = $this->send('/search?q=1%20OR%201=1', 'GET', '203.0.113.221');

        $this->assertSame(200, $response->getStatusCode());
        $this->assertFalse(SecurityEvent::where('ip', '203.0.113.221')->exists());
    }

    public function test_invalid_waf_config_falls_back_to_enforcement(): void
    {
        Config::set('crowdsec-scenarios.waf', 'invalid');

        $response = $this->send('/search?q=1%20OR%201=1', 'GET', '203.0.113.229');

        $this->assertSame(403, $response->getStatusCode());
    }

    public function test_granular_body_exclusion_matches_path_and_method(): void
    {
        Config::set('crowdsec-scenarios.waf.exclusions', [[
            'paths' => ['payments/*'],
            'methods' => ['POST'],
            'ignore_body_fields' => ['payload.note'],
        ]]);

        $ignored = $this->send('/payments/callback', 'POST', '203.0.113.222', [
            'payload' => ['note' => "1' OR 1=1"],
        ]);
        $wrongPath = $this->send('/orders', 'POST', '203.0.113.223', [
            'payload' => ['note' => "1' OR 1=1"],
        ]);

        $this->assertSame(200, $ignored->getStatusCode());
        $this->assertSame(403, $wrongPath->getStatusCode());
    }

    public function test_skip_scenario_does_not_skip_other_scenarios(): void
    {
        Config::set('crowdsec-scenarios.waf.exclusions', [[
            'paths' => ['imports'],
            'skip_scenarios' => ['sql_injection'],
        ]]);

        $sql = $this->send('/imports?q=1%20OR%201=1', 'GET', '203.0.113.224');
        $xss = $this->send('/imports?q=%3Cscript%3E', 'GET', '203.0.113.225');

        $this->assertSame(200, $sql->getStatusCode());
        $this->assertSame(403, $xss->getStatusCode());
    }

    public function test_route_name_selector_applies_exclusion(): void
    {
        Config::set('crowdsec-scenarios.waf.exclusions', [[
            'route_names' => ['webhooks.*'],
            'methods' => ['POST'],
            'ignore_body_fields' => ['payload.signature'],
        ]]);
        $request = Request::create('/callbacks/provider', 'POST', [
            'payload' => ['signature' => "1' OR 1=1"],
        ], [], [], ['REMOTE_ADDR' => '203.0.113.228']);
        $route = (new Route(['POST'], 'callbacks/provider', fn () => null))->name('webhooks.provider');
        $request->setRouteResolver(fn () => $route);

        $response = app(CrowdSecProtection::class)->handle($request, fn () => new Response('OK'));

        $this->assertSame(200, $response->getStatusCode());
    }

    public function test_waf_exclusion_does_not_bypass_active_block(): void
    {
        Config::set('crowdsec-scenarios.waf.exclusions', [[
            'paths' => ['trusted/*'],
            'skip_scenarios' => ['*'],
        ]]);
        BlockedIp::create([
            'ip' => '203.0.113.226',
            'reason' => 'Existing block',
            'expires_at' => now()->addHour(),
            'is_active' => true,
        ]);

        $response = $this->send('/trusted/callback', 'GET', '203.0.113.226');

        $this->assertSame(403, $response->getStatusCode());
    }

    public function test_custom_scenario_mode_is_included_in_threat_result(): void
    {
        $service = app(CrowdSecService::class);
        $service->registerScenario('custom_monitor', [
            'patterns' => ['/custom-danger/i'],
            'severity' => 'critical',
            'mode' => 'monitor',
        ]);

        $threats = $service->analyzeRequest(Request::create('/?q=custom-danger', 'GET'));

        $this->assertSame('monitor', $threats[0]['mode']);
    }

    public function test_deep_upload_threat_respects_monitor_mode(): void
    {
        Config::set('crowdsec-scenarios.waf.scenario_modes.file_upload_threat', 'monitor');
        $request = Request::create('/upload', 'POST', [], [], [
            'document' => UploadedFile::fake()->create('shell.php', 1),
        ], ['REMOTE_ADDR' => '203.0.113.227']);

        $response = app(CrowdSecProtection::class)->handle($request, fn () => new Response('OK'));

        $this->assertSame(200, $response->getStatusCode());
        $this->assertSame('monitored', SecurityEvent::where('ip', '203.0.113.227')->value('action_taken'));
    }

    protected function send(string $uri, string $method, string $ip, array $parameters = []): Response
    {
        $request = Request::create($uri, $method, $parameters, [], [], ['REMOTE_ADDR' => $ip]);

        return app(CrowdSecProtection::class)->handle($request, fn () => new Response('OK'));
    }
}

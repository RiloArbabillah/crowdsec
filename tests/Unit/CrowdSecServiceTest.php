<?php

namespace RiloArbabillah\LaravelCrowdSec\Tests\Unit;

use Illuminate\Http\Request;
use Orchestra\Testbench\TestCase;
use RiloArbabillah\LaravelCrowdSec\CrowdSecServiceProvider;
use RiloArbabillah\LaravelCrowdSec\Services\CrowdSecService;

class CrowdSecServiceTest extends TestCase
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
    }

    protected function setUp(): void
    {
        parent::setUp();
        $this->service = new CrowdSecService();
    }

    // -------------------------------------------------------------------
    // Severity comparison tests
    // -------------------------------------------------------------------

    public function test_max_severity_returns_critical_over_all(): void
    {
        $result = $this->service->getMaxSeverity(['low', 'medium', 'high', 'critical']);
        $this->assertEquals('critical', $result);
    }

    public function test_max_severity_returns_high_when_no_critical(): void
    {
        $result = $this->service->getMaxSeverity(['low', 'medium', 'high']);
        $this->assertEquals('high', $result);
    }

    public function test_max_severity_returns_medium_for_empty(): void
    {
        $result = $this->service->getMaxSeverity([]);
        $this->assertEquals('medium', $result);
    }

    public function test_max_severity_handles_single_value(): void
    {
        $this->assertEquals('critical', $this->service->getMaxSeverity(['critical']));
        $this->assertEquals('low', $this->service->getMaxSeverity(['low']));
    }

    // -------------------------------------------------------------------
    // WAF pattern detection tests
    // -------------------------------------------------------------------

    public function test_detects_sql_injection_union_select(): void
    {
        $request = Request::create('/search?q=1+UNION+SELECT+*+FROM+users', 'GET');
        $threats = $this->service->analyzeRequest($request);

        $this->assertNotEmpty($threats);
        $this->assertEquals('sql_injection', $threats[0]['type']);
    }

    public function test_detects_sql_injection_or_1_equals_1(): void
    {
        $request = Request::create('/search?id=1+OR+1=1', 'GET');
        $threats = $this->service->analyzeRequest($request);

        $this->assertNotEmpty($threats);
        $this->assertEquals('sql_injection', $threats[0]['type']);
    }

    public function test_detects_xss_script_tag(): void
    {
        $request = Request::create('/search?q=<script>alert(1)</script>', 'GET');
        $threats = $this->service->analyzeRequest($request);

        $this->assertNotEmpty($threats);
        $this->assertEquals('xss', $threats[0]['type']);
    }

    public function test_detects_path_traversal(): void
    {
        $request = Request::create('/files?path=../../etc/passwd', 'GET');
        $threats = $this->service->analyzeRequest($request);

        $this->assertNotEmpty($threats);
        $this->assertEquals('path_traversal', $threats[0]['type']);
    }

    public function test_detects_command_injection(): void
    {
        $request = Request::create('/api?cmd=test;cat /etc/passwd', 'GET');
        $threats = $this->service->analyzeRequest($request);

        $this->assertNotEmpty($threats);
        $this->assertEquals('command_injection', $threats[0]['type']);
    }

    // -------------------------------------------------------------------
    // False positive prevention tests
    // -------------------------------------------------------------------

    public function test_no_false_positive_on_normal_text(): void
    {
        $request = Request::create('/search?q=hello+world', 'GET');
        $threats = $this->service->analyzeRequest($request);

        $this->assertEmpty($threats);
    }

    public function test_no_false_positive_on_apostrophe(): void
    {
        $request = Request::create("/search?q=it's+a+beautiful+day", 'GET');
        $threats = $this->service->analyzeRequest($request);

        $this->assertEmpty($threats);
    }

    public function test_no_false_positive_on_normal_url_with_hash(): void
    {
        $request = Request::create('/page?section=overview', 'GET');
        $threats = $this->service->analyzeRequest($request);

        $this->assertEmpty($threats);
    }

    public function test_no_false_positive_on_data_image(): void
    {
        // data:image/png should NOT trigger XSS
        $request = Request::create('/upload?ref=data:image/png;base64,abc', 'GET');
        $threats = $this->service->analyzeRequest($request);

        $xssThreats = array_filter($threats, fn ($t) => $t['type'] === 'xss');
        $this->assertEmpty($xssThreats);
    }

    public function test_no_false_positive_on_html_attribute_like_text(): void
    {
        // "one=1" should NOT match XSS event handler pattern
        $request = Request::create('/search?filter=one&value=1', 'GET');
        $threats = $this->service->analyzeRequest($request);

        $xssThreats = array_filter($threats, fn ($t) => $t['type'] === 'xss');
        $this->assertEmpty($xssThreats);
    }

    // -------------------------------------------------------------------
    // Blocking threats filter test
    // -------------------------------------------------------------------

    public function test_get_blocking_threats_filters_correctly(): void
    {
        $threats = [
            ['type' => 'sql_injection', 'severity' => 'critical'],
            ['type' => 'suspicious_ua', 'severity' => 'low'],
            ['type' => 'xss', 'severity' => 'high'],
        ];

        $blocking = $this->service->getBlockingThreats($threats);

        $this->assertCount(2, $blocking);
    }

    // -------------------------------------------------------------------
    // isEnabled test
    // -------------------------------------------------------------------

    public function test_is_enabled_returns_true_by_default(): void
    {
        $this->assertTrue($this->service->isEnabled());
    }

    public function test_is_enabled_returns_false_when_disabled(): void
    {
        config(['crowdsec-scenarios.enabled' => false]);
        $service = new CrowdSecService();
        $this->assertFalse($service->isEnabled());
    }
}

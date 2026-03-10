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

    // =========================================================================
    // Severity comparison
    // =========================================================================

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
        $this->assertEquals('medium', $this->service->getMaxSeverity([]));
    }

    // =========================================================================
    // Original attack detection
    // =========================================================================

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

    // =========================================================================
    // NEW: SSRF detection
    // =========================================================================

    public function test_detects_ssrf_aws_metadata(): void
    {
        $request = Request::create('/proxy?url=http://169.254.169.254/latest/meta-data/', 'GET');
        $threats = $this->service->analyzeRequest($request);

        $ssrf = array_filter($threats, fn ($t) => $t['type'] === 'ssrf');
        $this->assertNotEmpty($ssrf, 'Should detect AWS metadata SSRF');
    }

    public function test_detects_ssrf_localhost(): void
    {
        $request = Request::create('/proxy?url=http://localhost/admin', 'GET');
        $threats = $this->service->analyzeRequest($request);

        $ssrf = array_filter($threats, fn ($t) => $t['type'] === 'ssrf');
        $this->assertNotEmpty($ssrf, 'Should detect localhost SSRF');
    }

    public function test_detects_ssrf_file_protocol(): void
    {
        $request = Request::create('/proxy?url=file:///etc/passwd', 'GET');
        $threats = $this->service->analyzeRequest($request);

        $this->assertNotEmpty($threats, 'Should detect file:// SSRF');
    }

    // =========================================================================
    // NEW: XXE detection
    // =========================================================================

    public function test_detects_xxe_entity(): void
    {
        $xml = '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>';
        $request = Request::create('/api/xml', 'POST', [], [], [], ['CONTENT_TYPE' => 'text/xml'], $xml);
        $threats = $this->service->analyzeRequest($request);

        $xxe = array_filter($threats, fn ($t) => $t['type'] === 'xxe');
        $this->assertNotEmpty($xxe, 'Should detect XXE entity');
    }

    // =========================================================================
    // NEW: NoSQL injection detection
    // =========================================================================

    public function test_detects_nosql_injection_operators(): void
    {
        $request = Request::create('/api/users?username[$ne]=admin', 'GET');
        $threats = $this->service->analyzeRequest($request);

        $nosql = array_filter($threats, fn ($t) => $t['type'] === 'nosql_injection');
        $this->assertNotEmpty($nosql, 'Should detect $ne NoSQL injection');
    }

    public function test_detects_nosql_injection_gt(): void
    {
        $request = Request::create('/api/users?age[$gt]=0', 'GET');
        $threats = $this->service->analyzeRequest($request);

        $nosql = array_filter($threats, fn ($t) => $t['type'] === 'nosql_injection');
        $this->assertNotEmpty($nosql, 'Should detect $gt NoSQL injection');
    }

    // =========================================================================
    // NEW: SSTI detection
    // =========================================================================

    public function test_detects_ssti_jinja(): void
    {
        $request = Request::create('/template?name={{7*7}}', 'GET');
        $threats = $this->service->analyzeRequest($request);

        $ssti = array_filter($threats, fn ($t) => $t['type'] === 'ssti');
        $this->assertNotEmpty($ssti, 'Should detect {{7*7}} SSTI');
    }

    public function test_detects_ssti_class_chain(): void
    {
        $request = Request::create('/template?x={{"".__class__.__mro__}}', 'GET');
        $threats = $this->service->analyzeRequest($request);

        $ssti = array_filter($threats, fn ($t) => $t['type'] === 'ssti');
        $this->assertNotEmpty($ssti, 'Should detect __class__ SSTI');
    }

    // =========================================================================
    // NEW: Open Redirect detection
    // =========================================================================

    public function test_detects_open_redirect(): void
    {
        $request = Request::create('/login?redirect=https://evil.com/steal', 'GET');
        $threats = $this->service->analyzeRequest($request);

        $redirect = array_filter($threats, fn ($t) => $t['type'] === 'open_redirect');
        $this->assertNotEmpty($redirect, 'Should detect open redirect');
    }

    // =========================================================================
    // NEW: Multi-encoding detection
    // =========================================================================

    public function test_detects_double_encoded_path_traversal(): void
    {
        // %252e%252e%252f = double-encoded ../../
        $request = Request::create('/files?path=%252e%252e%252f%252e%252e%252fetc/passwd', 'GET');
        $threats = $this->service->analyzeRequest($request);

        $traversal = array_filter($threats, fn ($t) => $t['type'] === 'path_traversal');
        $this->assertNotEmpty($traversal, 'Should detect double-encoded path traversal');
    }

    // =========================================================================
    // NEW: HTTP method and request checks
    // =========================================================================

    public function test_blocked_method_trace(): void
    {
        $request = Request::create('/api', 'TRACE');
        $this->assertTrue($this->service->isBlockedMethod($request));
    }

    public function test_allowed_method_get(): void
    {
        $request = Request::create('/api', 'GET');
        $this->assertFalse($this->service->isBlockedMethod($request));
    }

    // =========================================================================
    // False positive prevention
    // =========================================================================

    public function test_no_false_positive_on_normal_text(): void
    {
        $request = Request::create('/search?q=hello+world', 'GET');
        $this->assertEmpty($this->service->analyzeRequest($request));
    }

    public function test_no_false_positive_on_apostrophe(): void
    {
        $request = Request::create("/search?q=it's+a+beautiful+day", 'GET');
        $this->assertEmpty($this->service->analyzeRequest($request));
    }

    public function test_no_false_positive_on_data_image(): void
    {
        $request = Request::create('/upload?ref=data:image/png;base64,abc', 'GET');
        $xss = array_filter($this->service->analyzeRequest($request), fn ($t) => $t['type'] === 'xss');
        $this->assertEmpty($xss);
    }

    public function test_no_false_positive_on_html_attribute_like_text(): void
    {
        $request = Request::create('/search?filter=one&value=1', 'GET');
        $xss = array_filter($this->service->analyzeRequest($request), fn ($t) => $t['type'] === 'xss');
        $this->assertEmpty($xss);
    }

    // =========================================================================
    // Blocking filter
    // =========================================================================

    public function test_get_blocking_threats_filters_correctly(): void
    {
        $threats = [
            ['type' => 'sql_injection', 'severity' => 'critical'],
            ['type' => 'suspicious_ua', 'severity' => 'low'],
            ['type' => 'xss', 'severity' => 'high'],
        ];

        $this->assertCount(2, $this->service->getBlockingThreats($threats));
    }

    // =========================================================================
    // isEnabled
    // =========================================================================

    public function test_is_enabled_returns_true_by_default(): void
    {
        $this->assertTrue($this->service->isEnabled());
    }

    public function test_is_enabled_returns_false_when_disabled(): void
    {
        config(['crowdsec-scenarios.enabled' => false]);
        $this->assertFalse((new CrowdSecService())->isEnabled());
    }
}

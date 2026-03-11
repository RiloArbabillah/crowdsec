<?php

namespace RiloArbabillah\LaravelCrowdSec\Tests\Feature;

use Illuminate\Support\Facades\Config;
use Orchestra\Testbench\TestCase;
use RiloArbabillah\LaravelCrowdSec\CrowdSecServiceProvider;
use RiloArbabillah\LaravelCrowdSec\Services\CrowdSecService;

/**
 * ReDoS (Regular Expression Denial of Service) resistance tests.
 *
 * Verifies that regex patterns complete within acceptable time limits
 * even with adversarial inputs designed to cause catastrophic backtracking.
 */
class ReDoSResistanceTest extends TestCase
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
    // SAFE MATCH METHOD
    // =========================================================================

    public function test_safe_match_returns_true_on_match(): void
    {
        $this->assertTrue($this->service->safeMatch('/hello/i', 'hello world'));
    }

    public function test_safe_match_returns_false_on_no_match(): void
    {
        $this->assertFalse($this->service->safeMatch('/hello/i', 'goodbye world'));
    }

    public function test_safe_match_truncates_long_input(): void
    {
        // Create a 20KB string with a match at position 10KB (should be truncated to 8KB)
        $input = str_repeat('a', 10000) . 'MATCH' . str_repeat('b', 10000);
        $this->assertFalse($this->service->safeMatch('/MATCH/', $input));
    }

    public function test_safe_match_works_within_8kb_limit(): void
    {
        // Match within the 8KB window
        $input = str_repeat('a', 100) . 'MATCH' . str_repeat('b', 100);
        $this->assertTrue($this->service->safeMatch('/MATCH/', $input));
    }

    public function test_safe_match_handles_invalid_pattern(): void
    {
        // Invalid regex should return false, not throw
        $this->assertFalse($this->service->safeMatch('/[invalid/', 'test'));
    }

    // =========================================================================
    // ADVERSARIAL INPUT RESISTANCE (timing-based)
    // All tests should complete in < 100ms even with adversarial inputs
    // =========================================================================

    public function test_redos_resistance_sql_select_from_where(): void
    {
        // Adversarial: long input with repeated SELECT-like patterns
        $input = str_repeat('SELECT x FROM y WHERE z AND ', 100);

        $start = hrtime(true);
        $this->service->safeMatch(
            '/\bSELECT\b[^;]{0,200}\bFROM\b[^;]{0,200}\bWHERE\b/i',
            $input
        );
        $elapsed = (hrtime(true) - $start) / 1e6; // ms

        $this->assertLessThan(100, $elapsed, "SQL pattern should complete in <100ms, took {$elapsed}ms");
    }

    public function test_redos_resistance_xss_event_handler(): void
    {
        // Adversarial: many < characters without closing >
        $input = str_repeat('<div class="test" ', 500);

        $start = hrtime(true);
        $this->service->safeMatch('/\<[^\>]{0,200}\bon\w+\s*=/i', $input);
        $elapsed = (hrtime(true) - $start) / 1e6;

        $this->assertLessThan(100, $elapsed, "XSS pattern should complete in <100ms, took {$elapsed}ms");
    }

    public function test_redos_resistance_ssti_class_chain(): void
    {
        // Adversarial: long {{...}} without closing
        $input = '{{' . str_repeat('x.y.', 500);

        $start = hrtime(true);
        $this->service->safeMatch('/\{\{[^}]{0,200}__class__/i', $input);
        $elapsed = (hrtime(true) - $start) / 1e6;

        $this->assertLessThan(100, $elapsed, "SSTI pattern should complete in <100ms, took {$elapsed}ms");
    }

    public function test_redos_resistance_el_injection(): void
    {
        // Adversarial: long ${...} without closing
        $input = '${' . str_repeat('a.b.', 500);

        $start = hrtime(true);
        $this->service->safeMatch('/\$\{[^}]{0,200}(Runtime|ProcessBuilder|getRuntime)/i', $input);
        $elapsed = (hrtime(true) - $start) / 1e6;

        $this->assertLessThan(100, $elapsed, "EL pattern should complete in <100ms, took {$elapsed}ms");
    }

    public function test_redos_resistance_command_injection_backtick(): void
    {
        // Adversarial: many backticks
        $input = str_repeat('`', 1000);

        $start = hrtime(true);
        $this->service->safeMatch('/`[^`]*`/', $input);
        $elapsed = (hrtime(true) - $start) / 1e6;

        $this->assertLessThan(100, $elapsed, "Backtick pattern should complete in <100ms, took {$elapsed}ms");
    }

    public function test_redos_resistance_command_subst(): void
    {
        // Adversarial: nested $($($(...)
        $input = str_repeat('$(', 500) . str_repeat(')', 500);

        $start = hrtime(true);
        $this->service->safeMatch('/\$\([^)]+\)/', $input);
        $elapsed = (hrtime(true) - $start) / 1e6;

        $this->assertLessThan(100, $elapsed, "Command subst pattern should complete in <100ms, took {$elapsed}ms");
    }

    // =========================================================================
    // LARGE PAYLOAD RESISTANCE
    // =========================================================================

    public function test_analyze_request_completes_fast_with_large_payload(): void
    {
        // 100KB payload with no threats
        $largePayload = str_repeat('normal text content ', 5000);

        $request = \Illuminate\Http\Request::create('/test', 'POST', [], [], [], [
            'REMOTE_ADDR' => '10.0.0.100',
        ], $largePayload);

        $start = hrtime(true);
        $threats = $this->service->analyzeRequest($request);
        $elapsed = (hrtime(true) - $start) / 1e6;

        $this->assertEmpty($threats);
        $this->assertLessThan(500, $elapsed, "Large payload analysis should complete in <500ms, took {$elapsed}ms");
    }

    public function test_analyze_request_detects_threat_in_large_payload(): void
    {
        // Threat embedded in large payload (within first 8KB)
        $payload = 'normal text ' . "UNION SELECT * FROM users" . str_repeat(' padding ', 10000);

        $request = \Illuminate\Http\Request::create('/test?q=' . urlencode($payload), 'GET', [], [], [], [
            'REMOTE_ADDR' => '10.0.0.101',
        ]);

        $threats = $this->service->analyzeRequest($request);
        $sqli = array_filter($threats, fn ($t) => $t['type'] === 'sql_injection');
        $this->assertNotEmpty($sqli, 'Should detect SQLi in large payload');
    }

    // =========================================================================
    // ALL PATTERNS COMPLETE IN TIME
    // =========================================================================

    public function test_all_patterns_complete_fast_with_adversarial_aaa_bang(): void
    {
        // Classic ReDoS payload: "aaa...a!"
        $payload = str_repeat('a', 1000) . '!';
        $scenarios = config('crowdsec-scenarios');
        $nonScenarioKeys = ['enabled', 'log_channel', 'blocked_response_message', 'max_content_length',
            'block_empty_ua', 'blocked_methods', 'behavior', 'defaults', 'whitelist_ips', 'login_routes',
            'cache', 'notifications', 'honeypot_routes', 'geoip', 'api', 'dashboard'];

        $start = hrtime(true);
        foreach ($scenarios as $name => $config) {
            if (in_array($name, $nonScenarioKeys) || !isset($config['patterns'])) {
                continue;
            }
            foreach ($config['patterns'] as $pattern) {
                $this->service->safeMatch($pattern, $payload);
            }
        }
        $elapsed = (hrtime(true) - $start) / 1e6;

        $this->assertLessThan(200, $elapsed, "All patterns against adversarial input should complete in <200ms, took {$elapsed}ms");
    }
}

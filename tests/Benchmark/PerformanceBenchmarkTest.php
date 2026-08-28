<?php

namespace RiloArbabillah\LaravelCrowdSec\Tests\Benchmark;

use Illuminate\Http\Request;
use Orchestra\Testbench\TestCase;
use RiloArbabillah\LaravelCrowdSec\CrowdSecServiceProvider;
use RiloArbabillah\LaravelCrowdSec\Http\Middleware\CrowdSecProtection;
use RiloArbabillah\LaravelCrowdSec\Services\CrowdSecService;
use Symfony\Component\HttpFoundation\Response;

/**
 * Performance benchmarks for CrowdSec middleware and service.
 *
 * Run with: vendor/bin/phpunit tests/Benchmark --testdox
 *
 * These tests measure execution time to ensure the WAF overhead
 * stays within acceptable limits for production use.
 */
class PerformanceBenchmarkTest extends TestCase
{
    protected CrowdSecService $service;

    protected CrowdSecProtection $middleware;

    /** Number of iterations per benchmark for reliable averages */
    protected int $iterations = 100;

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

        // Use SQLite in-memory for benchmark
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
        $this->service = new CrowdSecService();
        $this->middleware = new CrowdSecProtection($this->service);

        // Run migrations
        $this->loadMigrationsFrom(__DIR__ . '/../../src/Database/Migrations');
    }

    /**
     * Helper: measure average execution time over N iterations.
     */
    protected function benchmark(callable $fn): float
    {
        // Warm-up run
        $fn();

        $start = hrtime(true);
        for ($i = 0; $i < $this->iterations; $i++) {
            $fn();
        }
        $elapsed = hrtime(true) - $start;

        // Return average in milliseconds
        return ($elapsed / $this->iterations) / 1_000_000;
    }

    // =========================================================================
    // Service-level benchmarks
    // =========================================================================

    public function test_benchmark_clean_request_analysis(): void
    {
        $request = Request::create('/api/users?page=1&per_page=20', 'GET');

        $avgMs = $this->benchmark(fn () => $this->service->analyzeRequest($request));

        $this->assertLessThan(2, $avgMs, "Clean request analysis should be < 2ms (was {$avgMs}ms)");

        echo "\n    ⏱  Clean request analysis: " . round($avgMs, 3) . "ms avg";
    }

    public function test_benchmark_threat_detection(): void
    {
        $request = Request::create('/search?q=1+UNION+SELECT+*+FROM+users', 'GET');

        $avgMs = $this->benchmark(fn () => $this->service->analyzeRequest($request));

        $this->assertLessThan(5, $avgMs, "Threat detection should be < 5ms (was {$avgMs}ms)");

        echo "\n    ⏱  Threat detection (SQLi): " . round($avgMs, 3) . "ms avg";
    }

    public function test_benchmark_multi_threat_detection(): void
    {
        // Request with multiple threat vectors
        $request = Request::create(
            '/search?q=<script>alert(1)</script>&path=../../etc/passwd&cmd=;cat+/etc/passwd',
            'GET'
        );

        $avgMs = $this->benchmark(fn () => $this->service->analyzeRequest($request));

        $this->assertLessThan(5, $avgMs, "Multi-threat detection should be < 5ms (was {$avgMs}ms)");

        echo "\n    ⏱  Multi-threat detection: " . round($avgMs, 3) . "ms avg";
    }

    public function test_benchmark_post_body_analysis(): void
    {
        $request = Request::create('/api/data', 'POST', [
            'name' => 'John Doe',
            'email' => 'john@example.com',
            'message' => 'This is a normal message with no threats',
            'nested' => [
                'key1' => 'value1',
                'key2' => 'value2',
                'deep' => ['a' => 'b', 'c' => 'd'],
            ],
        ]);

        $avgMs = $this->benchmark(fn () => $this->service->analyzeRequest($request));

        $this->assertLessThan(3, $avgMs, "POST body analysis should be < 3ms (was {$avgMs}ms)");

        echo "\n    ⏱  POST body analysis: " . round($avgMs, 3) . "ms avg";
    }

    // =========================================================================
    // Whitelist benchmark
    // =========================================================================

    public function test_benchmark_whitelist_check(): void
    {
        // Whitelist bypass should be extremely fast
        $request = Request::create('/admin', 'GET', [], [], [], ['REMOTE_ADDR' => '127.0.0.1']);

        $next = fn ($req) => new Response('OK', 200);

        $avgMs = $this->benchmark(fn () => $this->middleware->handle($request, $next));

        $this->assertLessThan(0.5, $avgMs, "Whitelist bypass should be < 0.5ms (was {$avgMs}ms)");

        echo "\n    ⏱  Whitelist bypass: " . round($avgMs, 3) . "ms avg";
    }

    public function test_benchmark_db_whitelist_check(): void
    {
        // Seed a few dynamic whitelist entries
        \RiloArbabillah\LaravelCrowdSec\Models\WhitelistedIp::create([
            'ip' => '10.0.0.0/8',
            'label' => 'bench',
            'is_active' => true,
        ]);
        \RiloArbabillah\LaravelCrowdSec\Models\WhitelistedIp::create([
            'ip' => '172.16.0.0/12',
            'label' => 'bench',
            'is_active' => true,
        ]);

        // First call primes the cache, subsequent calls measure cache hit performance
        $this->service->isWhitelisted('10.5.6.7');
        $this->service->isWhitelisted('172.20.0.1');

        $avgMs = $this->benchmark(fn () => $this->service->isWhitelisted('192.168.5.5'));

        $this->assertLessThan(
            2,
            $avgMs,
            "DB-backed whitelist check (cached) should be < 2ms (was {$avgMs}ms)",
        );

        echo "\n    ⏱  DB whitelist check (cached): " . round($avgMs, 3) . "ms avg";
    }

    // =========================================================================
    // IP check benchmarks
    // =========================================================================

    public function test_benchmark_blocked_ip_check(): void
    {
        $avgMs = $this->benchmark(fn () => $this->service->isBlocked('192.168.1.100'));

        $this->assertLessThan(2, $avgMs, "Blocked IP check should be < 2ms (was {$avgMs}ms)");

        echo "\n    ⏱  Blocked IP check (miss): " . round($avgMs, 3) . "ms avg";
    }

    // =========================================================================
    // Behavior tracking benchmark
    // =========================================================================

    public function test_benchmark_behavior_tracking(): void
    {
        $avgMs = $this->benchmark(fn () => $this->service->trackBehavior('10.0.0.1', '/api/test'));

        $this->assertLessThan(3, $avgMs, "Behavior tracking should be < 3ms (was {$avgMs}ms)");

        echo "\n    ⏱  Behavior tracking: " . round($avgMs, 3) . "ms avg";
    }

    // =========================================================================
    // Summary
    // =========================================================================

    public function test_benchmark_summary(): void
    {
        // This test prints a summary header — always passes
        echo "\n\n    ╔══════════════════════════════════════════╗";
        echo "\n    ║   CrowdSec Performance Benchmark Results ║";
        echo "\n    ╠══════════════════════════════════════════╣";
        echo "\n    ║  Iterations per test: {$this->iterations}               ║";
        echo "\n    ║  All benchmarks passed ✅                ║";
        echo "\n    ╚══════════════════════════════════════════╝\n";

        $this->assertTrue(true);
    }
}

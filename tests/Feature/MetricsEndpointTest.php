<?php

namespace RiloArbabillah\LaravelCrowdSec\Tests\Feature;

use Orchestra\Testbench\TestCase;
use RiloArbabillah\LaravelCrowdSec\CrowdSecServiceProvider;
use RiloArbabillah\LaravelCrowdSec\Models\BlockedIp;
use RiloArbabillah\LaravelCrowdSec\Models\IpBehavior;
use RiloArbabillah\LaravelCrowdSec\Models\SecurityEvent;

class MetricsEndpointTest extends TestCase
{
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
        $app['config']->set('crowdsec-scenarios.metrics.enabled', true);
        $app['config']->set('crowdsec-scenarios.metrics.middleware', []);

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
    }

    public function test_metrics_endpoint_returns_200(): void
    {
        $response = $this->get('/crowdsec/metrics');
        $response->assertStatus(200);
    }

    public function test_metrics_endpoint_returns_openmetrics_content_type(): void
    {
        $response = $this->get('/crowdsec/metrics');
        $response->assertHeader('Content-Type', 'text/plain; version=0.0.4; charset=utf-8');
    }

    public function test_metrics_contains_threats_total(): void
    {
        SecurityEvent::create([
            'ip' => '1.2.3.4',
            'event_type' => 'sql_injection',
            'severity' => 'critical',
            'description' => 'test',
        ]);

        $response = $this->get('/crowdsec/metrics');
        $content = $response->getContent();

        $this->assertStringContainsString('# HELP crowdsec_threats_total', $content);
        $this->assertStringContainsString('# TYPE crowdsec_threats_total counter', $content);
        $this->assertStringContainsString('crowdsec_threats_total{type="sql_injection",severity="critical"} 1', $content);
    }

    public function test_metrics_contains_blocked_ips_active(): void
    {
        BlockedIp::create([
            'ip' => '5.6.7.8',
            'reason' => 'test',
            'blocked_until' => now()->addHour(),
        ]);

        $response = $this->get('/crowdsec/metrics');
        $content = $response->getContent();

        $this->assertStringContainsString('# TYPE crowdsec_blocked_ips_active gauge', $content);
        $this->assertStringContainsString('crowdsec_blocked_ips_active 1', $content);
    }

    public function test_metrics_contains_blocked_ips_total(): void
    {
        $response = $this->get('/crowdsec/metrics');
        $content = $response->getContent();

        $this->assertStringContainsString('# TYPE crowdsec_blocked_ips_total counter', $content);
        $this->assertStringContainsString('crowdsec_blocked_ips_total', $content);
    }

    public function test_metrics_contains_tracked_ips(): void
    {
        IpBehavior::create([
            'ip' => '9.8.7.6',
            'threat_score' => 25,
            'request_count' => 5,
        ]);

        $response = $this->get('/crowdsec/metrics');
        $content = $response->getContent();

        $this->assertStringContainsString('# TYPE crowdsec_tracked_ips gauge', $content);
        $this->assertStringContainsString('crowdsec_tracked_ips 1', $content);
    }

    public function test_metrics_contains_high_threat_ips(): void
    {
        $response = $this->get('/crowdsec/metrics');
        $content = $response->getContent();

        $this->assertStringContainsString('# TYPE crowdsec_high_threat_ips gauge', $content);
        $this->assertStringContainsString('crowdsec_high_threat_ips', $content);
    }

    public function test_metrics_contains_threat_score_average(): void
    {
        $response = $this->get('/crowdsec/metrics');
        $content = $response->getContent();

        $this->assertStringContainsString('# TYPE crowdsec_threat_score_average gauge', $content);
        $this->assertStringContainsString('crowdsec_threat_score_average', $content);
    }

    public function test_metrics_contains_events_today(): void
    {
        $response = $this->get('/crowdsec/metrics');
        $content = $response->getContent();

        $this->assertStringContainsString('# TYPE crowdsec_events_today gauge', $content);
        $this->assertStringContainsString('crowdsec_events_today', $content);
    }

    public function test_metrics_contains_events_this_hour(): void
    {
        $response = $this->get('/crowdsec/metrics');
        $content = $response->getContent();

        $this->assertStringContainsString('# TYPE crowdsec_events_this_hour gauge', $content);
        $this->assertStringContainsString('crowdsec_events_this_hour', $content);
    }

    public function test_metrics_labels_are_sanitized(): void
    {
        SecurityEvent::create([
            'ip' => '1.1.1.1',
            'event_type' => 'xss-attack/reflected',
            'severity' => 'high',
            'description' => 'test',
        ]);

        $response = $this->get('/crowdsec/metrics');
        $content = $response->getContent();

        // Slashes and hyphens should be replaced with underscores
        $this->assertStringContainsString('type="xss_attack_reflected"', $content);
    }

    public function test_metrics_with_empty_database(): void
    {
        $response = $this->get('/crowdsec/metrics');
        $content = $response->getContent();

        $this->assertStringContainsString('crowdsec_blocked_ips_active 0', $content);
        $this->assertStringContainsString('crowdsec_blocked_ips_total 0', $content);
        $this->assertStringContainsString('crowdsec_tracked_ips 0', $content);
        $this->assertStringContainsString('crowdsec_events_today 0', $content);
    }

    public function test_metrics_multiple_threat_types(): void
    {
        SecurityEvent::create([
            'ip' => '1.1.1.1',
            'event_type' => 'sql_injection',
            'severity' => 'critical',
            'description' => 'test',
        ]);
        SecurityEvent::create([
            'ip' => '2.2.2.2',
            'event_type' => 'xss',
            'severity' => 'high',
            'description' => 'test',
        ]);
        SecurityEvent::create([
            'ip' => '3.3.3.3',
            'event_type' => 'sql_injection',
            'severity' => 'critical',
            'description' => 'test',
        ]);

        $response = $this->get('/crowdsec/metrics');
        $content = $response->getContent();

        $this->assertStringContainsString('crowdsec_threats_total{type="sql_injection",severity="critical"} 2', $content);
        $this->assertStringContainsString('crowdsec_threats_total{type="xss",severity="high"} 1', $content);
    }
}

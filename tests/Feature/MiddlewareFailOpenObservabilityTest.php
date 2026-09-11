<?php

namespace RiloArbabillah\LaravelCrowdSec\Tests\Feature;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Event;
use RiloArbabillah\LaravelCrowdSec\Events\CrowdSecMiddlewareFailed;
use RiloArbabillah\LaravelCrowdSec\Http\Middleware\CrowdSecProtection;
use RiloArbabillah\LaravelCrowdSec\Services\CrowdSecService;
use RiloArbabillah\LaravelCrowdSec\Tests\PackageTestCase;
use Symfony\Component\HttpFoundation\Response;

/**
 * The middleware intentionally fails open, but a silent fail-open means
 * protection can be skipped unnoticed. These tests verify that failures are
 * observable via a counter, a structured event, and contextual logging.
 */
class MiddlewareFailOpenObservabilityTest extends PackageTestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        $this->loadMigrationsFrom(__DIR__ . '/../../src/Database/Migrations');
    }

    public function test_fail_open_dispatches_event_and_increments_counter(): void
    {
        $dispatched = [];
        Event::listen(CrowdSecMiddlewareFailed::class, function (CrowdSecMiddlewareFailed $event) use (&$dispatched): void {
            $dispatched[] = $event;
        });

        $service = $this->createMock(CrowdSecService::class);
        $service->method('isEnabled')->willReturn(true);
        $service->method('isWhitelisted')->willReturn(false);
        $service->method('isBlocked')->willThrowException(new \RuntimeException('DB down'));

        $middleware = new CrowdSecProtection($service);

        $request = Request::create('/protected', 'GET', [], [], [], ['REMOTE_ADDR' => '203.0.113.150']);
        $response = $middleware->handle($request, fn () => new Response('OK', 200));

        // Still fails open.
        $this->assertSame(200, $response->getStatusCode());

        // ...but is now observable.
        $this->assertCount(1, $dispatched);
        $this->assertSame('203.0.113.150', $dispatched[0]->ip);
        $this->assertSame('protected', $dispatched[0]->path);
        $this->assertSame('DB down', $dispatched[0]->exception->getMessage());
        $this->assertArrayHasKey('stage', $dispatched[0]->context);

        $this->assertGreaterThanOrEqual(1, (int) Cache::get('crowdsec:middleware_failed', 0));
    }

    public function test_fail_open_counter_is_exposed_by_metrics_endpoint(): void
    {
        Cache::forever('crowdsec:middleware_failed', 0);
        Cache::increment('crowdsec:middleware_failed');
        Cache::increment('crowdsec:middleware_failed');

        $body = app(\RiloArbabillah\LaravelCrowdSec\Http\Controllers\CrowdSecMetricsController::class)
            ->__invoke()
            ->getContent();

        $this->assertStringContainsString('crowdsec_middleware_failed_total 2', $body);
        $this->assertStringContainsString('# TYPE crowdsec_middleware_failed_total counter', $body);
    }

    public function test_application_exceptions_are_not_reported_as_crowdsec_failures(): void
    {
        $dispatched = [];
        Event::listen(CrowdSecMiddlewareFailed::class, function (CrowdSecMiddlewareFailed $event) use (&$dispatched): void {
            $dispatched[] = $event;
        });

        $service = $this->createMock(CrowdSecService::class);
        $service->method('isEnabled')->willReturn(true);
        $service->method('isWhitelisted')->willReturn(false);
        $service->method('isBlocked')->willReturn(false);
        $service->method('isBlockedMethod')->willReturn(false);
        $service->method('hasEmptyUserAgent')->willReturn(false);
        $service->method('isOversizedRequest')->willReturn(false);
        $service->method('analyzeRequest')->willReturn([]);
        $service->method('trackRequest');

        $middleware = new CrowdSecProtection($service);

        $request = Request::create('/boom', 'GET', [], [], [], ['REMOTE_ADDR' => '203.0.113.151']);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('app exploded');

        try {
            $middleware->handle($request, function (): Response {
                throw new \RuntimeException('app exploded');
            });
        } finally {
            $this->assertCount(0, $dispatched);
        }
    }
}

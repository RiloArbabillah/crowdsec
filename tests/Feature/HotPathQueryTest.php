<?php

namespace RiloArbabillah\LaravelCrowdSec\Tests\Feature;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use RiloArbabillah\LaravelCrowdSec\Http\Middleware\CrowdSecProtection;
use RiloArbabillah\LaravelCrowdSec\Models\BlockedIp;
use RiloArbabillah\LaravelCrowdSec\Models\IpBehavior;
use RiloArbabillah\LaravelCrowdSec\Services\CrowdSecService;
use RiloArbabillah\LaravelCrowdSec\Services\SecurityEventContextService;
use RiloArbabillah\LaravelCrowdSec\Tests\PackageTestCase;
use Symfony\Component\HttpFoundation\Response;

class HotPathQueryTest extends PackageTestCase
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
     * @param  array<string, string>  $server
     * @return array{0: Response, 1: list<string>}
     */
    protected function handle(array $server, int $status = 200): array
    {
        $request = Request::create('/products', 'GET', [], [], [], $server + ['REMOTE_ADDR' => '10.8.8.8']);
        $middleware = new CrowdSecProtection($this->service());

        $queries = [];
        DB::listen(function ($query) use (&$queries): void {
            $queries[] = $query->sql;
        });

        $response = $middleware->handle($request, fn () => new Response('OK', $status));

        return [$response, $queries];
    }

    public function test_clean_request_takes_one_behavior_lock(): void
    {
        [$response, $queries] = $this->handle(['HTTP_USER_AGENT' => 'Mozilla/5.0']);

        $this->assertSame(200, $response->getStatusCode());
        $behaviorInserts = array_filter($queries, fn ($sql) => str_contains($sql, 'insert') && str_contains($sql, 'ip_behaviors'));
        $this->assertCount(1, $behaviorInserts, implode("\n", $queries));
        $this->assertLessThanOrEqual(6, count($queries), implode("\n", $queries));
        $this->assertSame(1, IpBehavior::where('ip', '10.8.8.8')->value('request_count'));
    }

    public function test_empty_user_agent_score_is_tracked_in_the_same_lock(): void
    {
        config(['crowdsec-scenarios.block_empty_ua' => true]);

        [, $queries] = $this->handle(['HTTP_USER_AGENT' => '']);

        $behaviorInserts = array_filter($queries, fn ($sql) => str_contains($sql, 'insert') && str_contains($sql, 'ip_behaviors'));
        $this->assertCount(1, $behaviorInserts, implode("\n", $queries));

        $behavior = IpBehavior::where('ip', '10.8.8.8')->firstOrFail();
        $this->assertSame(1, $behavior->request_count);
        $this->assertSame(15.0, (float) $behavior->threat_score);
    }

    public function test_404_is_tracked_with_one_lock(): void
    {
        IpBehavior::getOrCreate('10.8.8.8');

        $queries = [];
        DB::listen(function ($query) use (&$queries): void {
            $queries[] = $query->sql;
        });

        $behavior = $this->service()->track404('10.8.8.8');

        $behaviorInserts = array_filter($queries, fn ($sql) => str_contains($sql, 'insert') && str_contains($sql, 'ip_behaviors'));
        $this->assertCount(1, $behaviorInserts, implode("\n", $queries));
        $this->assertSame(1, $behavior->error_404_count);
        $this->assertSame(5.0, (float) $behavior->threat_score);
    }

    public function test_first_whitelist_change_invalidates_cached_blocks(): void
    {
        config([
            'crowdsec-scenarios.cache.enabled' => true,
            'crowdsec-scenarios.cache.store' => 'array',
        ]);
        $service = $this->service();

        BlockedIp::upsertBlock('10.9.0.1', 'test', now()->addHour(), 'test');
        $this->assertTrue($service->isBlocked('10.9.0.1'));

        // Unblock behind the cache's back, then invalidate everything once.
        BlockedIp::where('ip', '10.9.0.1')->update(['is_active' => false]);
        $service->invalidateAllBlockedCaches();

        $this->assertFalse($service->isBlocked('10.9.0.1'));
        Cache::store('array')->flush();
    }

    public function test_pcre_limits_are_restored_after_waf_pass(): void
    {
        $before = ini_get('pcre.backtrack_limit');

        $this->service()->checkWafPatterns(Request::create('/search?q=' . rawurlencode("1' UNION SELECT 1"), 'GET'));

        $this->assertSame($before, ini_get('pcre.backtrack_limit'));
    }
}

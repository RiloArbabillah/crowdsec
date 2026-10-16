<?php

namespace RiloArbabillah\LaravelCrowdSec\Tests\Feature;

use Illuminate\Http\Request;
use Orchestra\Testbench\TestCase;
use RiloArbabillah\LaravelCrowdSec\CrowdSecServiceProvider;

/**
 * Apps that never publish the config, or published it before a new
 * top-level key existed, still get the package defaults.
 */
class ConfigMergeTest extends TestCase
{
    protected function getPackageProviders($app): array
    {
        return [CrowdSecServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        $app['config']->set('database.default', 'testing');
        $app['config']->set('database.connections.testing', [
            'driver' => 'sqlite',
            'database' => ':memory:',
            'prefix' => '',
        ]);
    }

    public function test_waf_detects_attacks_without_published_config(): void
    {
        $request = Request::create('/search', 'GET', ['q' => "' UNION SELECT password FROM users--"]);

        $threats = app('crowdsec')->analyzeRequest($request);

        $this->assertContains('sql_injection', array_column($threats, 'type'));
    }
}

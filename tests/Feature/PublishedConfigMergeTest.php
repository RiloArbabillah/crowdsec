<?php

namespace RiloArbabillah\LaravelCrowdSec\Tests\Feature;

use Illuminate\Http\Request;
use Orchestra\Testbench\TestCase;
use RiloArbabillah\LaravelCrowdSec\CrowdSecServiceProvider;

/**
 * A config published by an older version keeps its own values and gains
 * top-level keys added later.
 */
class PublishedConfigMergeTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        // In a real app the published file is loaded before providers register.
        $this->app['config']->set('crowdsec-scenarios', ['whitelist_ips' => ['10.0.0.1']]);
        (new CrowdSecServiceProvider($this->app))->register();
    }

    public function test_app_values_win_and_missing_top_level_keys_are_filled(): void
    {
        $this->assertSame(['10.0.0.1'], config('crowdsec-scenarios.whitelist_ips'));
        $this->assertNotEmpty(config('crowdsec-scenarios.sql_injection.patterns'));
        $this->assertNotNull(config('crowdsec-scenarios.behavior.request_threshold'));

        $request = Request::create('/search', 'GET', ['q' => "' UNION SELECT password FROM users--"]);
        $this->assertContains('sql_injection', array_column(app('crowdsec')->analyzeRequest($request), 'type'));
    }
}

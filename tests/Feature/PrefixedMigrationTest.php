<?php

namespace RiloArbabillah\LaravelCrowdSec\Tests\Feature;

use Illuminate\Support\Facades\Schema;
use RiloArbabillah\LaravelCrowdSec\Tests\PackageTestCase;

class PrefixedMigrationTest extends PackageTestCase
{
    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);
        $app['config']->set('database.connections.testing.prefix', 'app_');
        $app['config']->set('database.connections.testing.prefix_indexes', true);
    }

    public function test_migrations_run_and_roll_back_with_a_table_prefix(): void
    {
        $this->loadMigrationsFrom(__DIR__ . '/../../src/Database/Migrations');

        $this->assertTrue(Schema::hasTable('security_events'));
        $this->assertTrue(Schema::hasTable('blocked_ips'));
    }
}

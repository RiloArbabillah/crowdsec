<?php

namespace RiloArbabillah\LaravelCrowdSec\Tests;

use Orchestra\Testbench\TestCase;
use RiloArbabillah\LaravelCrowdSec\CrowdSecServiceProvider;

abstract class PackageTestCase extends TestCase
{
    protected function getPackageProviders($app): array
    {
        return [CrowdSecServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        $app['config']->set(
            'crowdsec-scenarios',
            require __DIR__ . '/../config/crowdsec-scenarios.php'
        );

        $connection = getenv('TEST_DB_CONNECTION') ?: 'sqlite';
        $app['config']->set('database.default', 'testing');
        $app['config']->set('database.connections.testing', $this->databaseConfig($connection));
    }

    /**
     * @return array<string, mixed>
     */
    private function databaseConfig(string $connection): array
    {
        if ($connection === 'mysql') {
            return [
                'driver' => 'mysql',
                'host' => getenv('TEST_DB_HOST') ?: '127.0.0.1',
                'port' => getenv('TEST_DB_PORT') ?: '3306',
                'database' => getenv('TEST_DB_DATABASE') ?: 'crowdsec_testing',
                'username' => getenv('TEST_DB_USERNAME') ?: 'root',
                'password' => getenv('TEST_DB_PASSWORD') ?: '',
                'charset' => 'utf8mb4',
                'collation' => 'utf8mb4_unicode_ci',
                'prefix' => '',
            ];
        }

        if ($connection === 'pgsql') {
            return [
                'driver' => 'pgsql',
                'host' => getenv('TEST_DB_HOST') ?: '127.0.0.1',
                'port' => getenv('TEST_DB_PORT') ?: '5432',
                'database' => getenv('TEST_DB_DATABASE') ?: 'crowdsec_testing',
                'username' => getenv('TEST_DB_USERNAME') ?: 'postgres',
                'password' => getenv('TEST_DB_PASSWORD') ?: 'postgres',
                'charset' => 'utf8',
                'prefix' => '',
                'search_path' => 'public',
            ];
        }

        return [
            'driver' => 'sqlite',
            'database' => ':memory:',
            'prefix' => '',
        ];
    }
}

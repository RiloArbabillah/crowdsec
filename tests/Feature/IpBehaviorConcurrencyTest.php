<?php

namespace RiloArbabillah\LaravelCrowdSec\Tests\Feature;

use Illuminate\Support\Facades\DB;
use RiloArbabillah\LaravelCrowdSec\Models\IpBehavior;
use RiloArbabillah\LaravelCrowdSec\Tests\PackageTestCase;
use Throwable;

/**
 * Real concurrency regression coverage for the ip_behaviors locking strategy.
 *
 * SQLite serializes writers and has no SELECT ... FOR UPDATE, so it cannot
 * reproduce the interleaving that caused MySQL 1213. This test therefore runs
 * only against the shared MySQL/PostgreSQL connections used by the
 * `database` CI job (TEST_DB_CONNECTION), spawning parallel worker processes
 * that mutate the same IP row.
 */
class IpBehaviorConcurrencyTest extends PackageTestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        if (getenv('TEST_DB_CONNECTION') === false) {
            $this->markTestSkipped('Concurrency test requires a shared database connection (TEST_DB_CONNECTION).');
        }

        if (! function_exists('proc_open')) {
            $this->markTestSkipped('proc_open is required for the concurrency test.');
        }

        $this->loadMigrationsFrom(__DIR__ . '/../../src/Database/Migrations');
        DB::table('ip_behaviors')->delete();
    }

    public function test_parallel_track_request_never_deadlocks_and_keeps_counters_consistent(): void
    {
        $ip = '198.51.100.200';
        $workers = 6;
        $iterations = 25;

        $script = $this->workerScript($ip, $iterations);
        $scriptPath = tempnam(sys_get_temp_dir(), 'crowdsec-lock-worker-') . '.php';
        file_put_contents($scriptPath, $script);

        $processes = [];
        $pipes = [];

        for ($i = 0; $i < $workers; $i++) {
            $descriptors = [1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
            $process = proc_open(
                [PHP_BINARY, $scriptPath],
                $descriptors,
                $processPipes,
                dirname(__DIR__, 2),
            );

            $this->assertIsResource($process, 'Unable to spawn a concurrency worker');
            $processes[$i] = $process;
            $pipes[$i] = $processPipes;
        }

        $outputs = [];
        $errors = [];

        foreach ($processes as $i => $process) {
            $outputs[$i] = stream_get_contents($pipes[$i][1]);
            $errors[$i] = stream_get_contents($pipes[$i][2]);
            fclose($pipes[$i][1]);
            fclose($pipes[$i][2]);
            $exitCode = proc_close($process);

            $this->assertSame(0, $exitCode, "Worker {$i} failed:\n{$errors[$i]}\n{$outputs[$i]}");
            $this->assertStringNotContainsString('Deadlock', $errors[$i], "Worker {$i} hit a deadlock:\n{$errors[$i]}");
        }

        @unlink($scriptPath);

        $behavior = IpBehavior::where('ip', $ip)->firstOrFail();

        // Every worker performed $iterations request counts. The counter must be
        // exactly the total — proving no increments were lost to a deadlock.
        $this->assertSame($workers * $iterations, $behavior->request_count, 'Request counter lost increments under concurrency');
        $this->assertSame(1, IpBehavior::where('ip', $ip)->count(), 'Row must not be duplicated');
    }

    protected function workerScript(string $ip, int $iterations): string
    {
        $connection = getenv('TEST_DB_CONNECTION');
        $host = getenv('TEST_DB_HOST') ?: '127.0.0.1';
        $database = getenv('TEST_DB_DATABASE') ?: 'crowdsec_testing';
        $username = getenv('TEST_DB_USERNAME') ?: 'root';
        $password = getenv('TEST_DB_PASSWORD') ?: '';
        $driver = $connection === 'pgsql' ? 'pgsql' : 'mysql';
        $port = getenv('TEST_DB_PORT') ?: ($driver === 'pgsql' ? 5432 : 3306);

        $bootstrap = <<<'PHP'
<?php

require AUTOLOAD_PATH;

$container = new Illuminate\Container\Container();
Illuminate\Container\Container::setInstance($container);
$container->instance('app', $container);
Illuminate\Support\Facades\Facade::setFacadeApplication($container);

$config = new Illuminate\Config\Repository();
$config->set('database.default', 'default');
$container->instance('config', $config);

$capsule = new Illuminate\Database\Capsule\Manager($container);
$capsule->addConnection(CONNECTION_CONFIG, 'default');
$capsule->setAsGlobal();
$capsule->bootEloquent();

$container->instance('db', $capsule->getDatabaseManager());

$ip = IP_VALUE;
$iterations = ITERATIONS_VALUE;

try {
    for ($i = 0; $i < $iterations; $i++) {
        RiloArbabillah\LaravelCrowdSec\Models\IpBehavior::withLock($ip, function ($behavior): void {
            $behavior->setAttribute('request_count', (int) $behavior->request_count + 1);
            $behavior->setAttribute('last_activity', now());
            $behavior->save();
        });
    }
} catch (Throwable $e) {
    fwrite(STDERR, 'ERROR: ' . $e->getMessage() . PHP_EOL);
    exit(1);
}

echo "done\n";
PHP;

        $config = var_export([
            'driver' => $driver,
            'host' => $host,
            'port' => (int) $port,
            'database' => $database,
            'username' => $username,
            'password' => $password,
        ], true);

        return str_replace(
            ['AUTOLOAD_PATH', 'CONNECTION_CONFIG', 'IP_VALUE', 'ITERATIONS_VALUE'],
            [
                var_export(dirname(__DIR__, 2) . '/vendor/autoload.php', true),
                $config,
                var_export($ip, true),
                (string) $iterations,
            ],
            $bootstrap,
        );
    }
}

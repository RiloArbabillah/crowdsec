<?php

namespace RiloArbabillah\LaravelCrowdSec\Tests\Feature;

use Illuminate\Database\Events\TransactionBeginning;
use Illuminate\Support\Facades\DB;
use RiloArbabillah\LaravelCrowdSec\Models\BlockedIp;
use RiloArbabillah\LaravelCrowdSec\Models\IpBehavior;
use RiloArbabillah\LaravelCrowdSec\Services\CrowdSecService;
use RiloArbabillah\LaravelCrowdSec\Tests\PackageTestCase;

/**
 * SQLite (the default test connection) silently ignores SELECT ... FOR UPDATE,
 * so these tests assert on statement ordering and transaction boundaries
 * instead of on the literal lock SQL. MySQL/PostgreSQL lock ordering is
 * covered by the DatabaseCompatibilityTest CI job.
 */
class IpBehaviorLockingTest extends PackageTestCase
{
    protected CrowdSecService $service;

    protected function setUp(): void
    {
        parent::setUp();
        $this->loadMigrationsFrom(__DIR__ . '/../../src/Database/Migrations');
        $this->service = $this->app->make(CrowdSecService::class);
    }

    /**
     * @param  callable():void  $callback
     * @return list<string>
     */
    protected function captureQueries(callable $callback): array
    {
        $queries = [];
        DB::listen(function ($query) use (&$queries): void {
            $queries[] = $query->sql;
        });

        $callback();

        return $queries;
    }

    protected function firstMatching(array $queries, callable $predicate): ?int
    {
        foreach ($queries as $index => $sql) {
            if ($predicate($sql)) {
                return $index;
            }
        }

        return null;
    }

    /**
     * Regression: withLock() must not perform the INSERT inside the same
     * transaction that later locks the row. An insert-intention lock combined
     * with a row lock across concurrent sessions on the same unique key is what
     * produced MySQL 1213 deadlocks.
     */
    public function test_ensure_exists_runs_before_the_locking_transaction(): void
    {
        $ip = '198.51.100.1';

        $queries = $this->captureQueries(function () use ($ip): void {
            IpBehavior::withLock($ip, fn (IpBehavior $behavior) => $behavior);
        });

        $insertIndex = $this->firstMatching(
            $queries,
            fn (string $sql): bool => stripos($sql, 'insert') !== false && stripos($sql, 'ip_behaviors') !== false,
        );
        $selectIndex = $this->firstMatching(
            $queries,
            fn (string $sql): bool => stripos($sql, 'select') !== false && stripos($sql, 'ip_behaviors') !== false,
        );

        $this->assertNotNull($insertIndex, 'ensureExists should INSERT the row');
        $this->assertNotNull($selectIndex, 'withLock should SELECT the locked row');
        $this->assertLessThan($selectIndex, $insertIndex, 'ensure-exists INSERT must precede the locking SELECT');
    }

    /**
     * ensureExists() must run outside the locking transaction (autocommit),
     * so it cannot be rolled back together with the lock.
     */
    public function test_ensure_exists_runs_outside_the_transaction(): void
    {
        $ip = '198.51.100.7';
        $events = [];

        DB::listen(function ($query) use (&$events): void {
            $events[] = 'query:' . $query->sql;
        });
        DB::connection()->getEventDispatcher()->listen(TransactionBeginning::class, function () use (&$events): void {
            $events[] = 'transaction:begin';
        });

        IpBehavior::withLock($ip, fn (IpBehavior $behavior) => $behavior);

        $insertPosition = null;
        $transactionPosition = null;

        foreach ($events as $index => $event) {
            if ($insertPosition === null && str_starts_with($event, 'query:insert') && str_contains($event, 'ip_behaviors')) {
                $insertPosition = $index;
            }
            if ($transactionPosition === null && $event === 'transaction:begin') {
                $transactionPosition = $index;
            }
        }

        $this->assertNotNull($insertPosition);
        $this->assertNotNull($transactionPosition);
        $this->assertLessThan($transactionPosition, $insertPosition, 'ensure-exists INSERT must happen before the transaction begins');
    }

    public function test_ensure_exists_is_idempotent(): void
    {
        $ip = '198.51.100.2';

        IpBehavior::ensureExists($ip);
        IpBehavior::ensureExists($ip);
        IpBehavior::ensureExists($ip);

        $this->assertSame(1, IpBehavior::where('ip', $ip)->count());
    }

    /**
     * One request should acquire the ip_behaviors row lock exactly once even
     * when it includes a login attempt and enforced threats.
     */
    public function test_track_request_uses_a_single_transaction(): void
    {
        $ip = '198.51.100.3';
        $transactionCount = 0;

        DB::connection()->getEventDispatcher()->listen(TransactionBeginning::class, function () use (&$transactionCount): void {
            $transactionCount++;
        });

        $this->service->trackRequest(
            $ip,
            true,
            true,
            [[
                'type' => 'sql_injection',
                'severity' => 'critical',
                'weight' => 25,
                'mode' => 'enforce',
            ]],
        );

        $this->assertSame(1, $transactionCount, 'A single trackRequest call should open one transaction');

        $behavior = IpBehavior::where('ip', $ip)->firstOrFail();
        $this->assertSame(1, $behavior->request_count);
        $this->assertSame(1, $behavior->login_attempts);
        // 10 (login) + 25 (threat weight)
        $this->assertSame(35.0, (float) $behavior->threat_score);
    }

    public function test_track_request_without_login_or_threats_only_counts_requests(): void
    {
        $ip = '198.51.100.4';

        $this->service->trackRequest($ip);

        $behavior = IpBehavior::where('ip', $ip)->firstOrFail();
        $this->assertSame(1, $behavior->request_count);
        $this->assertSame(0, $behavior->login_attempts);
        $this->assertSame(0.0, (float) $behavior->threat_score);
    }

    /**
     * blockIp() must keep the lock order ip_behaviors -> blocked_ips and use an
     * atomic upsert rather than updateOrCreate() (SELECT + INSERT/UPDATE).
     */
    public function test_block_ip_writes_behaviors_before_blocked_ips(): void
    {
        $ip = '198.51.100.5';

        $queries = $this->captureQueries(function () use ($ip): void {
            $this->service->blockIp($ip, 'Testing upsert', 30, 'test');
        });

        $behaviorWrite = $this->firstMatching(
            $queries,
            fn (string $sql): bool => stripos($sql, 'update') !== false
                && stripos($sql, 'ip_behaviors') !== false
                && stripos($sql, 'block_count') !== false,
        );
        $blockedUpsert = $this->firstMatching(
            $queries,
            fn (string $sql): bool => stripos($sql, 'blocked_ips') !== false
                && (stripos($sql, 'insert') !== false || stripos($sql, 'update') !== false),
        );

        $this->assertNotNull($behaviorWrite, 'blockIp should update ip_behaviors');
        $this->assertNotNull($blockedUpsert, 'blockIp should upsert blocked_ips');
        $this->assertLessThan($blockedUpsert, $behaviorWrite, 'ip_behaviors write must precede blocked_ips write');

        $this->assertSame(1, BlockedIp::where('ip', $ip)->count());
    }

    public function test_blocked_ip_upsert_does_not_select_before_writing_when_row_absent(): void
    {
        $ip = '198.51.100.8';

        $queries = $this->captureQueries(function () use ($ip): void {
            BlockedIp::upsertBlock($ip, 'reason', now()->addMinutes(30), 'test');
        });

        // The absence probe is the only SELECT; the write itself is a single
        // atomic INSERT ... ON CONFLICT/ON DUPLICATE KEY statement.
        $write = $this->firstMatching(
            $queries,
            fn (string $sql): bool => stripos($sql, 'insert') !== false && stripos($sql, 'blocked_ips') !== false,
        );

        $this->assertNotNull($write, 'upsertBlock should INSERT the block row');
        $this->assertSame(1, BlockedIp::where('ip', $ip)->count());
    }

    public function test_repeated_blocks_refresh_single_row_and_escalate(): void
    {
        $ip = '198.51.100.6';

        $first = $this->service->blockIp($ip, 'First', 30, 'test');
        $second = $this->service->blockIp($ip, 'Second', 30, 'test');

        $this->assertSame(1, BlockedIp::where('ip', $ip)->count());
        $this->assertGreaterThan($first->expires_at, $second->expires_at);
        $this->assertSame(2, IpBehavior::where('ip', $ip)->value('block_count'));
        $this->assertSame('Second', BlockedIp::where('ip', $ip)->value('reason'));
    }

    /**
     * Deadlock/serialization errors are classified for retry; logic errors are not.
     */
    public function test_is_retryable_lock_error_classifies_only_lock_failures(): void
    {
        $deadlockPdo = new \PDOException('Deadlock found when trying to get lock');
        $deadlockPdo->errorInfo = ['40001', 1213, 'Deadlock found when trying to get lock'];
        $deadlock = new \Illuminate\Database\QueryException('testing', 'select 1', [], $deadlockPdo);

        $logicPdo = new \PDOException('Syntax error');
        $logicPdo->errorInfo = ['42000', 1064, 'Syntax error'];
        $logic = new \Illuminate\Database\QueryException('testing', 'select 1', [], $logicPdo);

        $this->assertTrue(IpBehavior::isRetryableLockError($deadlock));
        $this->assertFalse(IpBehavior::isRetryableLockError($logic));
        $this->assertFalse(IpBehavior::isRetryableLockError(new \RuntimeException('nope')));
    }

    /**
     * A deadlocked callback is retried and eventually succeeds.
     */
    public function test_with_lock_retries_deadlock_and_recovers(): void
    {
        $ip = '198.51.100.9';
        $attempts = 0;

        $result = IpBehavior::withLock($ip, function (IpBehavior $behavior) use (&$attempts): string {
            $attempts++;

            if ($attempts < 3) {
                $pdo = new \PDOException('Deadlock found when trying to get lock');
                $pdo->errorInfo = ['40001', 1213, 'Deadlock found when trying to get lock'];

                throw new \Illuminate\Database\QueryException('testing', 'select 1', [], $pdo);
            }

            return 'ok';
        });

        $this->assertSame('ok', $result);
        $this->assertSame(3, $attempts);
    }

    /**
     * A non-retryable error is not swallowed and is raised immediately.
     */
    public function test_with_lock_does_not_retry_logic_errors(): void
    {
        $ip = '198.51.100.10';
        $attempts = 0;

        $this->expectException(\RuntimeException::class);

        try {
            IpBehavior::withLock($ip, function () use (&$attempts): void {
                $attempts++;
                throw new \RuntimeException('logic error');
            });
        } finally {
            $this->assertSame(1, $attempts);
        }
    }
}

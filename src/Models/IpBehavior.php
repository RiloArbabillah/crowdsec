<?php

namespace RiloArbabillah\LaravelCrowdSec\Models;

use Closure;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Log;
use PDOException;
use Throwable;

/**
 * @property string $ip
 * @property int $request_count
 * @property \Illuminate\Support\Carbon|null $request_window_started_at
 * @property int $error_404_count
 * @property \Illuminate\Support\Carbon|null $error_404_window_started_at
 * @property int $login_attempts
 * @property \Illuminate\Support\Carbon|null $login_window_started_at
 * @property float|string $threat_score
 * @property int $block_count
 * @property \Illuminate\Support\Carbon|null $first_activity
 * @property \Illuminate\Support\Carbon|null $last_activity
 */
class IpBehavior extends Model
{
    protected $table = 'ip_behaviors';

    /**
     * Number of attempts used when a deadlock/lock-wait is retried.
     * Kept at one attempt for a mutation callback so firstOrCreate-style
     * callbacks that perform inserts are not executed twice.
     */
    protected const DEADLOCK_RETRY_ATTEMPTS = 5;

    protected $fillable = [
        'ip',
        'request_count',
        'request_window_started_at',
        'error_404_count',
        'error_404_window_started_at',
        'login_attempts',
        'login_window_started_at',
        'threat_score',
        'block_count',
        'first_activity',
        'last_activity',
    ];

    protected $casts = [
        'request_count' => 'integer',
        'request_window_started_at' => 'datetime',
        'error_404_count' => 'integer',
        'error_404_window_started_at' => 'datetime',
        'login_attempts' => 'integer',
        'login_window_started_at' => 'datetime',
        'threat_score' => 'decimal:2',
        'block_count' => 'integer',
        'first_activity' => 'datetime',
        'last_activity' => 'datetime',
        'created_at' => 'datetime',
        'updated_at' => 'datetime',
    ];


    /**
     * @param Builder<IpBehavior> $query
     * @return Builder<IpBehavior>
     */
    public function scopeHighThreat(Builder $query, float $score = 50): Builder
    {
        return $query->where('threat_score', '>=', $score);
    }

    /**
     * @param Builder<IpBehavior> $query
     * @return Builder<IpBehavior>
     */
    public function scopeActiveRecently(Builder $query, int $minutes = 60): Builder
    {
        return $query->where('last_activity', '>=', now()->subMinutes($minutes));
    }

    /**
     * Read-only accessor: guarantees the row exists without holding a row lock.
     * Used by the per-instance mutators so they never take an INSERT
     * insert-intention lock inside the locking transaction.
     */
    public static function getOrCreate(string $ip): self
    {
        static::ensureExists($ip);

        /** @var self|null $behavior */
        $behavior = static::query()->where('ip', $ip)->first();

        if ($behavior === null) {
            // Defensive fallback: a concurrent cleanup may have removed the row.
            static::ensureExists($ip);
            $behavior = static::query()->where('ip', $ip)->first();
        }

        if ($behavior === null) {
            throw new \RuntimeException("Unable to create ip_behaviors row for {$ip}");
        }

        return $behavior;
    }

    /**
     * Make sure an ip_behaviors row exists for the given IP.
     *
     * This deliberately runs *outside* any locking transaction (autocommit) so
     * the INSERT insert-intention lock is released before the row is locked
     * with SELECT ... FOR UPDATE. Holding an insert-intention lock for a
     * unique key while other sessions already hold row locks is what produced
     * the 1213 deadlock cycle between concurrent requests for the same IP.
     *
     * Idempotent: uses INSERT IGNORE-equivalent semantics via `insertOrIgnore`.
     */
    public static function ensureExists(string $ip): void
    {
        $now = now();
        $table = static::query()->getModel()->getTable();

        \Illuminate\Support\Facades\DB::table($table)->insertOrIgnore([
            'ip' => $ip,
            'request_count' => 0,
            'error_404_count' => 0,
            'login_attempts' => 0,
            'threat_score' => 0,
            'block_count' => 0,
            'first_activity' => $now,
            'last_activity' => $now,
            'created_at' => $now,
            'updated_at' => $now,
        ]);
    }

    /**
     * Serialize all state mutations for one IP across concurrent requests.
     *
     * The row is ensured *before* the locking transaction begins, so the
     * transaction only ever takes a single row lock. Deadlocks (SQLSTATE
     * 40001 / MySQL 1213) are retried with bounded backoff. A callback is
     * finalized at most once per attempt, so mutation callbacks must be
     * idempotent (they only read and persist a single row and are re-run
     * against a freshly locked row).
     *
     * @template TResult
     * @param  Closure(self): TResult  $callback
     * @return TResult
     */
    public static function withLock(string $ip, Closure $callback, bool $retryOnDeadlock = true): mixed
    {
        static::ensureExists($ip);

        $attempts = $retryOnDeadlock ? self::DEADLOCK_RETRY_ATTEMPTS : 1;

        $run = function () use ($ip, $callback) {
            return \Illuminate\Support\Facades\DB::transaction(function () use ($ip, $callback) {
                /** @var self $behavior */
                $behavior = static::query()->where('ip', $ip)->lockForUpdate()->firstOrFail();

                return $callback($behavior);
            });
        };

        for ($attempt = 1; $attempt <= $attempts; $attempt++) {
            try {
                return $run();
            } catch (Throwable $e) {
                if ($attempt >= $attempts || ! self::isRetryableLockError($e)) {
                    throw $e;
                }

                $delay = self::deadlockBackoffMicroseconds($attempt);
                Log::warning('CrowdSec: ip_behaviors lock contention, retrying', [
                    'ip' => $ip,
                    'attempt' => $attempt,
                    'max_attempts' => $attempts,
                    'backoff_ms' => round($delay / 1000, 2),
                    'error' => $e->getMessage(),
                ]);
                usleep($delay);
            }
        }

        throw new \RuntimeException('ip_behaviors lock retry exhausted unexpectedly');
    }

    /**
     * Mutate an IP row inside a single lock acquisition and return the locked,
     * mutated model. Prefer this over chaining multiple increment/add helpers so one request = one lock acquisition.
     *
     * @template TResult
     * @param  Closure(self): TResult  $callback
     * @return array{0: self, 1: TResult}
     */
    public static function mutateLocked(string $ip, Closure $callback): array
    {
        /** @var array{0: self, 1: mixed} $result */
        $result = static::withLock($ip, function (self $behavior) use ($callback): array {
            $value = $callback($behavior);

            return [$behavior, $value];
        });

        return $result;
    }

    public function incrementRequestCount(): void
    {
        $this->syncFromLockedMutation(function (self $behavior): void {
            $behavior->incrementWindowCounter(
                'request_count',
                'request_window_started_at',
                (int) config('crowdsec-scenarios.behavior.request_window_minutes', 60),
            );
        });
    }

    public function incrementError404Count(): void
    {
        $this->syncFromLockedMutation(function (self $behavior): void {
            $behavior->incrementWindowCounter(
                'error_404_count',
                'error_404_window_started_at',
                (int) config('crowdsec-scenarios.behavior.404_window_minutes', 60),
            );
            $behavior->setAttribute('threat_score', min(100, (float) $behavior->threat_score + 5));
            $behavior->save();
        });
    }

    public function incrementLoginAttempts(bool $addThreatScore = true): void
    {
        $this->syncFromLockedMutation(function (self $behavior) use ($addThreatScore): void {
            $behavior->incrementWindowCounter(
                'login_attempts',
                'login_window_started_at',
                (int) config('crowdsec-scenarios.behavior.login_window_minutes', 5),
            );

            if ($addThreatScore) {
                $behavior->setAttribute('threat_score', min(100, (float) $behavior->threat_score + 10));
                $behavior->save();
            }
        });
    }

    public function addThreatScore(float $score): void
    {
        $this->syncFromLockedMutation(function (self $behavior) use ($score): void {
            $behavior->setAttribute('threat_score', min(100, (float) $behavior->threat_score + $score));
            $behavior->setAttribute('last_activity', now());
            $behavior->save();
        });
    }

    public function resetThreatScore(): void
    {
        $this->syncFromLockedMutation(function (self $behavior): void {
            $behavior->setAttribute('threat_score', 0);
            $behavior->save();
        });
    }

    public function resetAuthenticationState(bool $resetThreatScore = false): void
    {
        $this->syncFromLockedMutation(function (self $behavior) use ($resetThreatScore): void {
            $behavior->setAttribute('login_attempts', 0);
            $behavior->setAttribute('login_window_started_at', null);
            if ($resetThreatScore) {
                $behavior->setAttribute('threat_score', 0);
            }
            $behavior->save();
        });
    }

    public function isWindowActive(string $windowAttribute, int $windowMinutes): bool
    {
        $startedAt = $this->getAttribute($windowAttribute);

        return $startedAt !== null
            && $startedAt->gt(now()->subMinutes(max(1, $windowMinutes)));
    }

    /**
     * Clean up old behavior records (older than specified days)
     */
    public static function cleanup(int $days = 30): int
    {
        return static::where('last_activity', '<', now()->subDays($days))
            ->delete();
    }

    /**
     * Reset request counts older than the specified minutes (hourly cleanup)
     */
    public static function resetOldRequestCounts(int $minutes = 60): int
    {
        return static::where('last_activity', '<', now()->subMinutes($minutes))
            ->update([
                'request_count' => 0,
                'request_window_started_at' => null,
                'error_404_count' => 0,
                'error_404_window_started_at' => null,
                'login_attempts' => 0,
                'login_window_started_at' => null,
            ]);
    }

    /**
     * Apply threat score decay based on inactivity time.
     * Reduces score gradually for IPs that have stopped suspicious activity.
     *
     * @param  float  $decayRate  Points to subtract per decay interval
     * @param  int  $decayIntervalMinutes  Minutes of inactivity before decay applies
     * @return bool Whether the score was actually decayed
     */
    public function decayThreatScore(float $decayRate = 5.0, int $decayIntervalMinutes = 60): bool
    {
        if ($this->threat_score <= 0) {
            return false;
        }

        $minutesSinceLastActivity = $this->last_activity
            ? (int) now()->diffInMinutes($this->last_activity, absolute: true)
            : 0;

        if ($minutesSinceLastActivity < $decayIntervalMinutes) {
            return false;
        }

        // Calculate number of decay intervals passed
        $intervals = (int) floor($minutesSinceLastActivity / $decayIntervalMinutes);
        $totalDecay = $decayRate * $intervals;

        $newScore = max(0, $this->threat_score - $totalDecay);
        $this->update(['threat_score' => $newScore]);

        return true;
    }

    /**
     * Apply decay to all behaviors that have been inactive.
     *
     * @return int Number of records decayed
     */
    public static function applyDecayAll(float $decayRate = 5.0, int $decayIntervalMinutes = 60): int
    {
        $decayed = 0;
        $candidates = static::where('threat_score', '>', 0)
            ->where('last_activity', '<', now()->subMinutes($decayIntervalMinutes))
            ->get();

        foreach ($candidates as $behavior) {
            if ($behavior->decayThreatScore($decayRate, $decayIntervalMinutes)) {
                $decayed++;
            }
        }

        return $decayed;
    }

    /**
     * Determine whether an exception is a deadlock / serialization failure
     * that is safe to retry (MySQL 1213, PostgreSQL 40P01 / SQLSTATE 40001).
     */
    public static function isRetryableLockError(Throwable $e): bool
    {
        $sqlState = null;
        $driverCode = null;

        $current = $e;

        while ($current !== null) {
            if ($current instanceof \Illuminate\Database\QueryException) {
                $sqlState = $current->getCode();
            }

            if ($current instanceof PDOException && isset($current->errorInfo[1])) {
                $driverCode = (int) $current->errorInfo[1];
                $sqlState ??= (string) ($current->errorInfo[0] ?? '');
            }

            $current = $current->getPrevious();
        }

        if ($driverCode !== null && in_array($driverCode, [1213, 1205], true)) {
            return true;
        }

        return in_array((string) $sqlState, ['40001', '40P01'], true);
    }

    /**
     * Exponential backoff with jitter, in microseconds.
     */
    protected static function deadlockBackoffMicroseconds(int $attempt): int
    {
        $baseMs = min(200, 5 * (2 ** max(0, $attempt - 1)));
        $jitterMs = random_int(0, 5);

        return (int) (($baseMs + $jitterMs) * 1000);
    }

    public function incrementWindowCounter(string $counter, string $windowAttribute, int $windowMinutes): void
    {
        $now = now();
        $windowMinutes = max(1, $windowMinutes);

        if (! $this->isWindowActive($windowAttribute, $windowMinutes)) {
            $this->setAttribute($counter, 0);
            $this->setAttribute($windowAttribute, $now);
        }

        $this->setAttribute($counter, (int) $this->getAttribute($counter) + 1);
        $this->setAttribute('last_activity', $now);
        $this->save();
    }

    protected function syncFromLockedMutation(Closure $callback): void
    {
        $fresh = static::withLock($this->ip, function (self $behavior) use ($callback): self {
            $callback($behavior);

            return $behavior;
        });

        $this->setRawAttributes($fresh->getAttributes(), true);
    }

}

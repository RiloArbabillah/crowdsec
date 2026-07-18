<?php

namespace RiloArbabillah\LaravelCrowdSec\Models;

use Closure;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\DB;

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
    use HasFactory;

    protected $table = 'ip_behaviors';

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


    public function scopeHighThreat($query, float $score = 50)
    {
        return $query->where('threat_score', '>=', $score);
    }

    public function scopeActiveRecently($query, int $minutes = 60)
    {
        return $query->where('last_activity', '>=', now()->subMinutes($minutes));
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

    public static function getOrCreate(string $ip): self
    {
        return static::withLock($ip, fn (self $behavior): self => $behavior);
    }

    /**
     * Serialize all state mutations for one IP across concurrent requests.
     *
     * @template TResult
     * @param  Closure(self): TResult  $callback
     * @return TResult
     */
    public static function withLock(string $ip, Closure $callback): mixed
    {
        return DB::transaction(function () use ($ip, $callback) {
            $now = now();

            $table = static::query()->getModel()->getTable();
            DB::table($table)->insertOrIgnore([
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

            /** @var self $behavior */
            $behavior = static::query()->where('ip', $ip)->lockForUpdate()->firstOrFail();

            return $callback($behavior);
        }, 3);
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

    protected function incrementWindowCounter(string $counter, string $windowAttribute, int $windowMinutes): void
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

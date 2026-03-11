<?php

namespace RiloArbabillah\LaravelCrowdSec\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class IpBehavior extends Model
{
    use HasFactory;

    protected $table = 'ip_behaviors';

    protected $fillable = [
        'ip',
        'request_count',
        'error_404_count',
        'login_attempts',
        'threat_score',
        'block_count',
        'first_activity',
        'last_activity',
    ];

    protected $casts = [
        'request_count' => 'integer',
        'error_404_count' => 'integer',
        'login_attempts' => 'integer',
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
        $this->increment('request_count');
        $this->update(['last_activity' => now()]);
    }

    public function incrementError404Count(): void
    {
        $this->increment('error_404_count');
        $this->addThreatScore(5);
        $this->update(['last_activity' => now()]);
    }

    public function incrementLoginAttempts(): void
    {
        $this->increment('login_attempts', 1, ['last_activity' => now()]);
        $this->addThreatScore(10);
    }

    public function addThreatScore(float $score): void
    {
        $newScore = min(100, $this->threat_score + $score);
        $this->update(['threat_score' => $newScore]);
    }

    public function resetThreatScore(): void
    {
        $this->update(['threat_score' => 0]);
    }


    public static function getOrCreate(string $ip): self
    {
        return static::firstOrCreate(
            ['ip' => $ip],
            [
                'request_count' => 0,
                'error_404_count' => 0,
                'login_attempts' => 0,
                'threat_score' => 0,
                'block_count' => 0,
                'first_activity' => now(),
                'last_activity' => now(),
            ]
        );
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
                'error_404_count' => 0,
                'login_attempts' => 0,
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
}

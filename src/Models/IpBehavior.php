<?php

namespace Simenawan\LaravelCrowdSec\Models;

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
        'first_activity',
        'last_activity',
    ];

    protected $casts = [
        'request_count' => 'integer',
        'error_404_count' => 'integer',
        'login_attempts' => 'integer',
        'threat_score' => 'decimal:2',
        'first_activity' => 'datetime',
        'last_activity' => 'datetime',
        'created_at' => 'datetime',
        'updated_at' => 'datetime',
    ];

    public const THRESHOLD_REQUEST_COUNT = 1000; // per hour
    public const THRESHOLD_ERROR_404_COUNT = 20; // per hour
    public const THRESHOLD_LOGIN_ATTEMPTS = 10; // per 5 minutes
    public const THRESHOLD_THREAT_SCORE = 50;

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

    public function exceedsThresholds(): bool
    {
        return $this->request_count >= self::THRESHOLD_REQUEST_COUNT
            || $this->error_404_count >= self::THRESHOLD_ERROR_404_COUNT
            || $this->threat_score >= self::THRESHOLD_THREAT_SCORE;
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
}

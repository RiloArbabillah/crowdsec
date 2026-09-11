<?php

namespace RiloArbabillah\LaravelCrowdSec\Models;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;
use RiloArbabillah\LaravelCrowdSec\Models\SecurityEvent;

/**
 * @property string $ip
 * @property string|null $reason
 * @property bool $is_active
 * @property \Illuminate\Support\Carbon|null $expires_at
 * @property \Illuminate\Support\Carbon|null $created_at
 */
class BlockedIp extends Model
{
    protected $table = 'blocked_ips';

    protected $fillable = [
        'ip',
        'reason',
        'event_type',
        'expires_at',
        'is_active',
        'created_by',
    ];

    protected $casts = [
        'expires_at' => 'datetime',
        'is_active' => 'boolean',
        'created_at' => 'datetime',
        'updated_at' => 'datetime',
    ];

    /** @return HasMany<SecurityEvent, $this> */
    public function securityEvents(): HasMany
    {
        return $this->hasMany(SecurityEvent::class);
    }

    /**
     * @param Builder<BlockedIp> $query
     * @return Builder<BlockedIp>
     */
    public function scopeActive(Builder $query): Builder
    {
        return $query->where('is_active', true);
    }

    /**
     * @param Builder<BlockedIp> $query
     * @return Builder<BlockedIp>
     */
    public function scopeExpired(Builder $query): Builder
    {
        return $query->where('is_active', true)
            ->whereNotNull('expires_at')
            ->where('expires_at', '<', now());
    }

    /**
     * @param Builder<BlockedIp> $query
     * @return Builder<BlockedIp>
     */
    public function scopeNotExpired(Builder $query): Builder
    {
        return $query->where(function ($q) {
            $q->whereNull('expires_at')
                ->orWhere('expires_at', '>', now());
        });
    }

    /**
     * @param Builder<BlockedIp> $query
     * @return Builder<BlockedIp>
     */
    public function scopeExpiringSoon(Builder $query, int $hours = 24): Builder
    {
        return $query->where('is_active', true)
            ->whereNotNull('expires_at')
            ->where('expires_at', '<=', now()->addHours($hours));
    }

    public function getIsExpiredAttribute(): bool
    {
        if (! $this->expires_at) {
            return false;
        }

        return $this->expires_at->isPast();
    }

    public function getRemainingTimeAttribute(): ?string
    {
        if (! $this->expires_at) {
            return null;
        }

        if ($this->isExpired) {
            return 'Expired';
        }

        return $this->expires_at->diffForHumans();
    }

    public function getDurationMinutesAttribute(): ?int
    {
        if (! $this->expires_at || ! $this->created_at) {
            return null;
        }

        return (int) round($this->created_at->diffInMinutes($this->expires_at));
    }

    /**
     * Atomically create or refresh a block for the given IP.
     *
     * Replaces updateOrCreate() (SELECT + INSERT/UPDATE) so the write takes a
     * single row lock and never holds a gap lock. Callers are expected to run
     * this *after* any ip_behaviors lock is taken, keeping the lock order
     * consistent: ip_behaviors -> blocked_ips.
     *
     * @return self The freshly persisted block row.
     */
    public static function upsertBlock(
        string $ip,
        ?string $reason,
        ?\DateTimeInterface $expiresAt,
        ?string $eventType = null,
    ): self {
        $now = now();

        /** @var self|null $existing */
        $existing = static::query()->where('ip', $ip)->first();

        static::query()->upsert(
            [
                [
                    'ip' => $ip,
                    'reason' => $reason,
                    'event_type' => $eventType,
                    'expires_at' => $expiresAt,
                    'is_active' => true,
                    'created_at' => $existing?->created_at?->format('Y-m-d H:i:s') ?? $now,
                    'updated_at' => $now,
                ],
            ],
            ['ip'],
            ['reason', 'event_type', 'expires_at', 'is_active', 'updated_at'],
        );

        /** @var self $blocked */
        $blocked = static::query()->where('ip', $ip)->firstOrFail();

        return $blocked;
    }

    public static function isBlocked(string $ip): bool
    {
        return static::where('ip', $ip)
            ->where('is_active', true)
            ->where(function ($query) {
                $query->whereNull('expires_at')
                    ->orWhere('expires_at', '>', now());
            })
            ->exists();
    }
}

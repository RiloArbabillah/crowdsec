<?php

namespace RiloArbabillah\LaravelCrowdSec\Models;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;

/**
 * @property int $id
 * @property string $ip
 * @property string|null $label
 * @property string|null $note
 * @property bool $is_active
 * @property \Illuminate\Support\Carbon|null $expires_at
 * @property int|null $created_by
 * @property string|null $created_by_label
 * @property \Illuminate\Support\Carbon|null $created_at
 * @property \Illuminate\Support\Carbon|null $updated_at
 */
class WhitelistedIp extends Model
{
    protected $table = 'whitelisted_ips';

    protected $fillable = [
        'ip',
        'label',
        'note',
        'is_active',
        'expires_at',
        'created_by',
        'created_by_label',
    ];

    protected $casts = [
        'expires_at' => 'datetime',
        'is_active' => 'boolean',
        'created_at' => 'datetime',
        'updated_at' => 'datetime',
    ];

    /**
     * @param Builder<WhitelistedIp> $query
     * @return Builder<WhitelistedIp>
     */
    public function scopeActive(Builder $query): Builder
    {
        return $query->where('is_active', true);
    }

    /**
     * @param Builder<WhitelistedIp> $query
     * @return Builder<WhitelistedIp>
     */
    public function scopeNotExpired(Builder $query): Builder
    {
        return $query->where(function ($q) {
            $q->whereNull('expires_at')
                ->orWhere('expires_at', '>', now());
        });
    }

    /**
     * @param Builder<WhitelistedIp> $query
     * @return Builder<WhitelistedIp>
     */
    public function scopeExpired(Builder $query): Builder
    {
        return $query->whereNotNull('expires_at')
            ->where('expires_at', '<=', now());
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
}

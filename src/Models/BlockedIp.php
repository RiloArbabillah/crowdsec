<?php

namespace Simenawan\LaravelCrowdSec\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Simenawan\LaravelCrowdSec\Models\SecurityEvent;

class BlockedIp extends Model
{
    use HasFactory;

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

    public function securityEvents()
    {
        return $this->hasMany(SecurityEvent::class);
    }

    public function scopeActive($query)
    {
        return $query->where('is_active', true);
    }

    public function scopeExpired($query)
    {
        return $query->where('is_active', true)
            ->whereNotNull('expires_at')
            ->where('expires_at', '<', now());
    }

    public function scopeNotExpired($query)
    {
        return $query->where(function ($q) {
            $q->whereNull('expires_at')
                ->orWhere('expires_at', '>', now());
        });
    }

    public function scopeExpiringSoon($query, int $hours = 24)
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

        return $this->created_at->diffInMinutes($this->expires_at);
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

<?php

namespace RiloArbabillah\LaravelCrowdSec\Models;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;

class AuditLog extends Model
{
    /**
     * The table associated with the model.
     */
    protected $table = 'crowdsec_audit_logs';

    /**
     * Disable updated_at — audit logs are immutable.
     */
    const UPDATED_AT = null;

    /**
     * The attributes that are mass assignable.
     */
    protected $fillable = [
        'action',
        'actor',
        'target_ip',
        'metadata',
    ];

    /**
     * The attributes that should be cast.
     */
    protected $casts = [
        'metadata' => 'array',
        'created_at' => 'datetime',
    ];

    // =========================================================================
    // SCOPES
    // =========================================================================

    /**
     * @param Builder<AuditLog> $query
     * @return Builder<AuditLog>
     */
    public function scopeForIp(Builder $query, string $ip): Builder
    {
        return $query->where('target_ip', $ip);
    }

    /**
     * @param Builder<AuditLog> $query
     * @return Builder<AuditLog>
     */
    public function scopeAction(Builder $query, string $action): Builder
    {
        return $query->where('action', $action);
    }

    /**
     * @param Builder<AuditLog> $query
     * @return Builder<AuditLog>
     */
    public function scopeBetween(Builder $query, string $from, string $to): Builder
    {
        return $query->whereBetween('created_at', [$from, $to]);
    }

    // =========================================================================
    // HELPERS
    // =========================================================================

    /**
     * Record an audit log entry.
     */
    /** @param array<string, mixed> $metadata */
    public static function record(string $action, ?string $targetIp = null, array $metadata = [], string $actor = 'system'): self
    {
        return static::create([
            'action' => $action,
            'actor' => $actor,
            'target_ip' => $targetIp,
            'metadata' => ! empty($metadata) ? $metadata : null,
        ]);
    }
}

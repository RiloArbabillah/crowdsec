<?php

namespace RiloArbabillah\LaravelCrowdSec\Models;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

/**
 * @property string $ip
 * @property string $event_type
 * @property string $severity
 * @property array<string, mixed> $request_data
 * @property list<array<string, mixed>>|null $matched_patterns
 * @property string|null $request_id
 * @property string|null $route_name
 * @property string|null $content_type
 * @property int|null $content_length
 * @property int|null $response_status
 * @property int|null $duration_ms
 * @property string|null $action_taken
 * @property string|null $country_code
 * @property int|null $asn
 * @property string|null $isp
 * @property string|null $authenticated_user_id_hash
 * @property string|null $browser
 * @property string|null $os
 * @property string|null $device_type
 * @property \Illuminate\Support\Carbon $created_at
 */
class SecurityEvent extends Model
{
    protected $table = 'security_events';

    protected $fillable = [
        'ip',
        'event_type',
        'severity',
        'request_data',
        'user_agent',
        'request_path',
        'matched_patterns',
        'blocked_ip_id',
        'request_id',
        'route_name',
        'content_type',
        'content_length',
        'response_status',
        'duration_ms',
        'action_taken',
        'country_code',
        'asn',
        'isp',
        'authenticated_user_id_hash',
        'browser',
        'os',
        'device_type',
    ];

    protected $casts = [
        'request_data' => 'array',
        'matched_patterns' => 'array',
        'content_length' => 'integer',
        'response_status' => 'integer',
        'duration_ms' => 'integer',
        'asn' => 'integer',
        'created_at' => 'datetime',
        'updated_at' => 'datetime',
    ];

    public const SEVERITY_LOW = 'low';

    public const SEVERITY_MEDIUM = 'medium';

    public const SEVERITY_HIGH = 'high';

    public const SEVERITY_CRITICAL = 'critical';

    public const EVENT_SQL_INJECTION = 'sql_injection';

    public const EVENT_XSS = 'xss';

    public const EVENT_PATH_TRAVERSAL = 'path_traversal';

    public const EVENT_BRUTE_FORCE = 'brute_force';

    public const EVENT_DIRECTORY_BRUTEFORCE = 'directory_bruteforce';

    public const EVENT_API_ABUSE = 'api_abuse';

    public const EVENT_SUSPICIOUS_USER_AGENT = 'suspicious_user_agent';

    public const EVENT_HEADER_INJECTION = 'header_injection';

    public const EVENT_BEHAVIOR_THRESHOLD = 'behavior_threshold';

    /** @return BelongsTo<BlockedIp, $this> */
    public function blockedIp(): BelongsTo
    {
        return $this->belongsTo(BlockedIp::class);
    }

    /**
     * @param Builder<SecurityEvent> $query
     * @return Builder<SecurityEvent>
     */
    public function scopeRecent(Builder $query, int $days = 7): Builder
    {
        return $query->where('created_at', '>=', now()->subDays($days));
    }

    /**
     * @param Builder<SecurityEvent> $query
     * @return Builder<SecurityEvent>
     */
    public function scopeByType(Builder $query, string $type): Builder
    {
        return $query->where('event_type', $type);
    }

    /**
     * @param Builder<SecurityEvent> $query
     * @return Builder<SecurityEvent>
     */
    public function scopeBySeverity(Builder $query, string $severity): Builder
    {
        return $query->where('severity', $severity);
    }

    /**
     * @param Builder<SecurityEvent> $query
     * @return Builder<SecurityEvent>
     */
    public function scopeByIp(Builder $query, string $ip): Builder
    {
        return $query->where('ip', $ip);
    }

    public function getIsHighSeverityAttribute(): bool
    {
        return in_array($this->severity, [self::SEVERITY_HIGH, self::SEVERITY_CRITICAL]);
    }
}

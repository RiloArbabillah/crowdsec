<?php

namespace Simenawan\LaravelCrowdSec\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class SecurityEvent extends Model
{
    use HasFactory;

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
    ];

    protected $casts = [
        'request_data' => 'array',
        'matched_patterns' => 'array',
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

    public function blockedIp()
    {
        return $this->belongsTo(BlockedIp::class);
    }

    public function scopeRecent($query, int $days = 7)
    {
        return $query->where('created_at', '>=', now()->subDays($days));
    }

    public function scopeByType($query, string $type)
    {
        return $query->where('event_type', $type);
    }

    public function scopeBySeverity($query, string $severity)
    {
        return $query->where('severity', $severity);
    }

    public function scopeByIp($query, string $ip)
    {
        return $query->where('ip', $ip);
    }

    public function getIsHighSeverityAttribute(): bool
    {
        return in_array($this->severity, [self::SEVERITY_HIGH, self::SEVERITY_CRITICAL]);
    }
}

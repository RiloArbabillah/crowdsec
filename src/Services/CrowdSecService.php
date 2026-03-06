<?php

namespace RiloArbabillah\LaravelCrowdSec\Services;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use RiloArbabillah\LaravelCrowdSec\Models\BlockedIp;
use RiloArbabillah\LaravelCrowdSec\Models\IpBehavior;
use RiloArbabillah\LaravelCrowdSec\Models\SecurityEvent;

class CrowdSecService
{
    protected array $scenarios;

    /**
     * Severity weight map for proper comparison.
     * Higher value = more severe.
     */
    protected const SEVERITY_WEIGHTS = [
        'low' => 1,
        'medium' => 2,
        'high' => 3,
        'critical' => 4,
    ];

    public function __construct()
    {
        $this->scenarios = config('crowdsec-scenarios', []);
    }

    /**
     * Check if the package is enabled
     */
    public function isEnabled(): bool
    {
        return (bool) ($this->scenarios['enabled'] ?? true);
    }

    /**
     * Check if an IP is currently blocked
     */
    public function isBlocked(string $ip): bool
    {
        return BlockedIp::isBlocked($ip);
    }

    /**
     * Analyze a request for security threats.
     * Returns detected threats without logging or blocking — caller is responsible for those.
     */
    public function analyzeRequest(Request $request): array
    {
        return $this->checkWafPatterns($request);
    }

    /**
     * Check request against WAF patterns
     */
    public function checkWafPatterns(Request $request): array
    {
        $threats = [];
        $inputsToCheck = [];

        // Collect all inputs to check (URL decode to detect encoded attacks)
        $inputsToCheck['query'] = urldecode($request->getQueryString() ?? '');
        $inputsToCheck['path'] = $request->path();

        // Check POST data (skip for login requests — handled separately)
        if ($request->isMethod('POST')) {
            $postData = $this->extractPostData($request);
            foreach ($postData as $key => $value) {
                $inputsToCheck[$key] = is_string($value) ? urldecode($value) : $value;
            }
        }

        // Check headers (only specific headers, not body)
        $inputsToCheck['user_agent'] = $request->userAgent() ?? '';
        $inputsToCheck['referer'] = urldecode($request->header('Referer') ?? '');

        foreach ($inputsToCheck as $source => $input) {
            if (! is_string($input) || $input === '') {
                continue;
            }

            foreach ($this->scenarios as $scenarioName => $config) {
                // Skip non-pattern scenarios
                if (in_array($scenarioName, ['behavior', 'defaults', 'whitelist_ips', 'login_routes', 'enabled', 'blocked_response_message', 'log_channel'])) {
                    continue;
                }

                if (! isset($config['patterns']) || ! is_array($config['patterns'])) {
                    continue;
                }

                // Only check 'user_agent' source against suspicious_user_agent scenario
                if ($scenarioName === 'suspicious_user_agent' && $source !== 'user_agent') {
                    continue;
                }

                // Skip suspicious_user_agent for non-user-agent sources
                if ($scenarioName !== 'suspicious_user_agent' && $source === 'user_agent') {
                    continue;
                }

                foreach ($config['patterns'] as $pattern) {
                    if (@preg_match($pattern, $input) === 1) {
                        $threats[] = [
                            'type' => $scenarioName,
                            'source' => $source,
                            'matched' => Str::limit($input, 100),
                            'severity' => $config['severity'] ?? 'medium',
                            'weight' => $config['weight'] ?? 5,
                        ];

                        // Break after first match per scenario/source to avoid duplicates
                        break;
                    }
                }
            }
        }

        return $threats;
    }

    /**
     * Extract and flatten POST data for checking (including JSON/Livewire payloads)
     */
    protected function extractPostData(Request $request): array
    {
        $flatData = [];

        // Try to get data from standard POST
        $data = $request->all();

        // If empty, try to decode JSON body (Livewire uses JSON)
        if (empty($data)) {
            $content = $request->getContent();
            if (! empty($content)) {
                $jsonData = json_decode($content, true);
                if (is_array($jsonData)) {
                    $data = $jsonData;
                }
            }
        }

        // Flatten the data for pattern matching
        $this->flattenData($data, '', $flatData);

        return $flatData;
    }

    /**
     * Recursively flatten data array for pattern matching
     */
    protected function flattenData(array $data, string $prefix, array &$flatData, int $depth = 0): void
    {
        // Prevent infinite recursion on deeply nested data
        if ($depth > 10) {
            return;
        }

        foreach ($data as $key => $value) {
            $fullKey = $prefix ? "{$prefix}[{$key}]" : $key;

            if (is_array($value)) {
                // For nested structures (like Livewire components), encode to JSON
                $flatData[$fullKey] = urldecode(json_encode($value));
                // Also check individual nested values
                $this->flattenData($value, $fullKey, $flatData, $depth + 1);
            } else {
                $flatData[$fullKey] = is_string($value) ? urldecode($value) : (string) $value;
            }
        }
    }

    /**
     * Track behavior for an IP
     */
    public function trackBehavior(string $ip, string $path): IpBehavior
    {
        $behavior = IpBehavior::getOrCreate($ip);
        $behavior->incrementRequestCount();

        return $behavior;
    }

    /**
     * Track 404 response for an IP
     */
    public function track404(string $ip): IpBehavior
    {
        $behavior = IpBehavior::getOrCreate($ip);
        $behavior->incrementError404Count();

        return $behavior;
    }

    /**
     * Track login attempt for an IP
     */
    public function trackLoginAttempt(string $ip): IpBehavior
    {
        $behavior = IpBehavior::getOrCreate($ip);
        $behavior->incrementLoginAttempts();

        return $behavior;
    }

    /**
     * Check if IP exceeds behavior thresholds
     */
    public function exceedsBehaviorThreshold(string $ip): bool
    {
        $behavior = IpBehavior::where('ip', $ip)
            ->where('last_activity', '>=', now()->subHour())
            ->first();

        if (! $behavior) {
            return false;
        }

        $behaviorConfig = $this->scenarios['behavior'] ?? [];

        return $behavior->request_count >= ($behaviorConfig['request_threshold'] ?? 500)
            || $behavior->error_404_count >= ($behaviorConfig['404_threshold'] ?? 15)
            || $behavior->threat_score >= ($behaviorConfig['threat_score_threshold'] ?? 50);
    }

    /**
     * Check login brute force threshold
     */
    public function exceedsLoginThreshold(string $ip): bool
    {
        $behavior = IpBehavior::where('ip', $ip)
            ->where('last_activity', '>=', now()->subMinutes(5))
            ->first();

        if (! $behavior) {
            return false;
        }

        $behaviorConfig = $this->scenarios['behavior'] ?? [];

        return $behavior->login_attempts >= ($behaviorConfig['login_threshold'] ?? 5);
    }

    /**
     * Block an IP address
     */
    public function blockIp(
        string $ip,
        string $reason,
        ?int $durationMinutes = null,
        ?string $eventType = null
    ): BlockedIp {
        // Determine block duration based on severity if not provided
        if ($durationMinutes === null) {
            $severity = $this->getSeverityFromReason($reason);
            $durationMinutes = $this->scenarios['defaults'][$severity] ?? 240;
        }

        // Use updateOrCreate to handle the unique constraint on 'ip'
        $blockedIp = BlockedIp::updateOrCreate(
            ['ip' => $ip],
            [
                'reason' => $reason,
                'event_type' => $eventType,
                'expires_at' => now()->addMinutes($durationMinutes),
                'is_active' => true,
            ]
        );

        $this->log('warning', 'IP blocked', [
            'ip' => $ip,
            'reason' => $reason,
            'duration_minutes' => $durationMinutes,
        ]);

        return $blockedIp;
    }

    /**
     * Unblock an IP address
     */
    public function unblockIp(string $ip): bool
    {
        $count = BlockedIp::where('ip', $ip)
            ->where('is_active', true)
            ->update(['is_active' => false]);

        if ($count > 0) {
            $this->log('info', 'IP unblocked', ['ip' => $ip]);

            return true;
        }

        return false;
    }

    /**
     * Log a security event
     */
    public function logEvent(string $ip, array $threats, Request $request): SecurityEvent
    {
        $eventTypes = array_unique(array_column($threats, 'type'));
        $severities = array_column($threats, 'severity');
        $maxSeverity = $this->getMaxSeverity($severities);

        $event = SecurityEvent::create([
            'ip' => $ip,
            'event_type' => implode(', ', $eventTypes),
            'severity' => $maxSeverity,
            'request_data' => [
                'method' => $request->method(),
                'path' => $request->path(),
                'query' => $request->getQueryString(),
                'user_agent' => $request->userAgent(),
                'referer' => $request->header('Referer'),
            ],
            'user_agent' => $request->userAgent(),
            'request_path' => $request->path(),
            'matched_patterns' => $threats,
        ]);

        return $event;
    }

    /**
     * Clean up expired IP bans
     */
    public function cleanupExpiredBans(): int
    {
        $count = BlockedIp::expired()->update(['is_active' => false]);

        if ($count > 0) {
            $this->log('info', "Cleaned up {$count} expired bans");
        }

        return $count;
    }

    /**
     * Get statistics
     */
    public function getStats(): array
    {
        return [
            'blocked_ips_active' => BlockedIp::active()->count(),
            'blocked_ips_expired' => BlockedIp::expired()->count(),
            'events_today' => SecurityEvent::whereDate('created_at', today())->count(),
            'events_week' => SecurityEvent::where('created_at', '>=', now()->subWeek())->count(),
            'top_attackers' => SecurityEvent::selectRaw('ip, COUNT(*) as count')
                ->where('created_at', '>=', now()->subDay())
                ->groupBy('ip')
                ->orderByDesc('count')
                ->limit(10)
                ->get(),
        ];
    }

    /**
     * Get threats that should be blocked (critical + high + medium severity)
     */
    public function getBlockingThreats(array $threats): array
    {
        return array_filter($threats, fn ($t) => in_array(($t['severity'] ?? 'medium'), ['critical', 'high', 'medium']));
    }

    /**
     * Compare severity levels and return the highest.
     * Uses numeric weights to avoid alphabetical string comparison bug.
     */
    public function getMaxSeverity(array $severities): string
    {
        if (empty($severities)) {
            return 'medium';
        }

        $maxWeight = 0;
        $maxSeverity = 'medium';

        foreach ($severities as $severity) {
            $weight = self::SEVERITY_WEIGHTS[$severity] ?? 0;
            if ($weight > $maxWeight) {
                $maxWeight = $weight;
                $maxSeverity = $severity;
            }
        }

        return $maxSeverity;
    }

    /**
     * Determine severity from reason string
     */
    protected function getSeverityFromReason(string $reason): string
    {
        $reasonLower = strtolower($reason);

        if (Str::contains($reasonLower, ['sql', 'command', 'injection', 'serialization'])) {
            return 'critical';
        }
        if (Str::contains($reasonLower, ['xss', 'traversal', 'inclusion'])) {
            return 'high';
        }
        if (Str::contains($reasonLower, ['behavior', 'threshold', 'brute'])) {
            return 'high';
        }

        return 'medium';
    }

    /**
     * Internal logging helper — uses configured log channel if set
     */
    protected function log(string $level, string $message, array $context = []): void
    {
        $channel = $this->scenarios['log_channel'] ?? null;
        $logger = $channel ? Log::channel($channel) : Log::getFacadeRoot();

        $logger->{$level}("CrowdSec: {$message}", $context);
    }
}

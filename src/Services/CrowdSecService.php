<?php

namespace RiloArbabillah\LaravelCrowdSec\Services;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use RiloArbabillah\LaravelCrowdSec\Events\IpBlocked;
use RiloArbabillah\LaravelCrowdSec\Events\IpUnblocked;
use RiloArbabillah\LaravelCrowdSec\Events\ThreatDetected;
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

    /**
     * Config keys that are NOT pattern-based scenarios.
     */
    public const NON_SCENARIO_KEYS = [
        'behavior', 'defaults', 'whitelist_ips', 'login_routes',
        'enabled', 'blocked_response_message', 'log_channel',
        'max_content_length', 'block_empty_ua', 'blocked_methods',
        'cache',
        'notifications',
        'honeypot_routes',
        'geoip',
        'api',
        'metrics',
        'dashboard',
    ];

    public function __construct()
    {
        $this->scenarios = config('crowdsec-scenarios', []);
    }

    /**
     * Register a custom detection scenario at runtime.
     * Custom scenarios are merged with built-in config scenarios.
     *
     * Usage from service provider:
     *   app('crowdsec')->registerScenario('api_abuse', [
     *       'patterns' => ['/excessive-api-call-pattern/i'],
     *       'severity' => 'high',
     *       'weight' => 30,
     *       'block_duration' => 720,
     *   ]);
     */
    public function registerScenario(string $name, array $config): self
    {
        $this->scenarios[$name] = array_merge([
            'patterns' => [],
            'severity' => 'medium',
            'weight' => 20,
            'block_duration' => 240,
        ], $config);

        return $this;
    }

    /**
     * Get all registered scenarios (built-in + custom).
     */
    public function getScenarios(): array
    {
        return array_diff_key($this->scenarios, array_flip(self::NON_SCENARIO_KEYS));
    }

    /**
     * Check if the package is enabled
     */
    public function isEnabled(): bool
    {
        return (bool) ($this->scenarios['enabled'] ?? true);
    }

    /**
     * Check if an IP is currently blocked (with caching)
     */
    public function isBlocked(string $ip): bool
    {
        if (! $this->isCacheEnabled()) {
            return BlockedIp::isBlocked($ip);
        }

        $cacheKey = $this->getBlockedCacheKey($ip);
        $cacheTtl = $this->scenarios['cache']['ttl'] ?? 60; // seconds

        return $this->cacheStore()->remember($cacheKey, $cacheTtl, function () use ($ip) {
            return BlockedIp::isBlocked($ip);
        });
    }

    /**
     * Check if an IP is whitelisted (supports exact match and CIDR notation)
     */
    public function isWhitelisted(string $ip): bool
    {
        $whitelist = $this->scenarios['whitelist_ips'] ?? [];

        foreach ($whitelist as $entry) {
            if ($ip === $entry) {
                return true;
            }
            if (str_contains($entry, '/') && $this->ipInCidr($ip, $entry)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if an IP address falls within a CIDR range
     */
    protected function ipInCidr(string $ip, string $cidr): bool
    {
        [$subnet, $bits] = explode('/', $cidr, 2);
        $bits = (int) $bits;

        $ipBin = inet_pton($ip);
        $subnetBin = inet_pton($subnet);

        if ($ipBin === false || $subnetBin === false) {
            return false;
        }

        $mask = str_repeat('f', (int) ($bits / 4));
        if ($bits % 4) {
            $mask .= dechex(0xF << (4 - ($bits % 4)) & 0xF);
        }
        $mask = str_pad($mask, strlen(bin2hex($ipBin)), '0');
        $mask = pack('H*', $mask);

        return ($ipBin & $mask) === ($subnetBin & $mask);
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
     * Check request against WAF patterns with multi-layer decoding
     */
    public function checkWafPatterns(Request $request): array
    {
        $threats = [];
        $inputsToCheck = [];

        // Collect all inputs to check
        $inputsToCheck['query'] = $request->getQueryString() ?? '';
        $inputsToCheck['path'] = $request->path();

        // Check body data for all mutating methods (not just POST)
        if (in_array($request->method(), ['POST', 'PUT', 'PATCH', 'DELETE'])) {
            $bodyData = $this->extractBodyData($request);
            foreach ($bodyData as $key => $value) {
                $inputsToCheck["body_{$key}"] = is_string($value) ? $value : '';
            }
        }

        // Check headers
        $inputsToCheck['user_agent'] = $request->userAgent() ?? '';
        $inputsToCheck['referer'] = $request->header('Referer') ?? '';

        // Check cookies
        foreach ($request->cookies->all() as $cookieName => $cookieValue) {
            if (is_string($cookieValue) && $cookieValue !== '') {
                $inputsToCheck["cookie_{$cookieName}"] = $cookieValue;
            }
        }

        foreach ($inputsToCheck as $source => $input) {
            if (! is_string($input) || $input === '') {
                continue;
            }

            // Generate multiple decoded versions for multi-encoding detection
            $decodedVersions = $this->multiDecode($input);

            foreach ($this->scenarios as $scenarioName => $config) {
                // Skip non-pattern scenarios
                if (in_array($scenarioName, self::NON_SCENARIO_KEYS, true)) {
                    continue;
                }

                if (! isset($config['patterns']) || ! is_array($config['patterns'])) {
                    continue;
                }

                // Route patterns to correct sources
                if (! $this->shouldCheckScenario($scenarioName, $source)) {
                    continue;
                }

                $matched = false;

                foreach ($config['patterns'] as $pattern) {
                    // Check each decoded version against the pattern
                    foreach ($decodedVersions as $decoded) {
                        if ($this->safeMatch($pattern, $decoded)) {
                            $threats[] = [
                                'type' => $scenarioName,
                                'source' => $source,
                                'matched' => Str::limit($input, 100),
                                'severity' => $config['severity'] ?? 'medium',
                                'weight' => $config['weight'] ?? 5,
                            ];
                            $matched = true;
                            break; // Stop checking decoded versions
                        }
                    }

                    if ($matched) {
                        break; // Stop checking patterns for this scenario/source
                    }
                }
            }
        }

        return $threats;
    }

    /**
     * Determine if a scenario should be checked against a given source.
     */
    protected function shouldCheckScenario(string $scenarioName, string $source): bool
    {
        $isUserAgent = $source === 'user_agent';

        // suspicious_user_agent only checks UA
        if ($scenarioName === 'suspicious_user_agent') {
            return $isUserAgent;
        }

        // All other scenarios skip UA
        if ($isUserAgent) {
            return false;
        }

        // header_injection only checks headers
        if ($scenarioName === 'header_injection') {
            return in_array($source, ['referer', 'user_agent']) || str_starts_with($source, 'header_');
        }

        // open_redirect only checks query and path
        if ($scenarioName === 'open_redirect') {
            return in_array($source, ['query', 'path']);
        }

        return true;
    }

    /**
     * Produce multiple decoded versions of input for multi-layer attack detection.
     * Catches double-URL-encoding, hex encoding, and unicode escapes.
     */
    protected function multiDecode(string $input): array
    {
        $versions = [];

        // Original input
        $versions[] = $input;

        // Single URL decode
        $decoded1 = urldecode($input);
        if ($decoded1 !== $input) {
            $versions[] = $decoded1;

            // Double URL decode (catches double-encoded attacks like %2527 → %27 → ')
            $decoded2 = urldecode($decoded1);
            if ($decoded2 !== $decoded1) {
                $versions[] = $decoded2;
            }
        }

        // HTML entity decode
        $htmlDecoded = html_entity_decode($input, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        if ($htmlDecoded !== $input && ! in_array($htmlDecoded, $versions, true)) {
            $versions[] = $htmlDecoded;
        }

        return array_unique($versions);
    }

    /**
     * Extract and flatten body data for checking (supports JSON, form data, XML)
     */
    protected function extractBodyData(Request $request): array
    {
        $flatData = [];

        // Standard form / JSON data
        $data = $request->all();

        // If empty, try to decode JSON body
        if (empty($data)) {
            $content = $request->getContent();
            if (! empty($content)) {
                $jsonData = json_decode($content, true);
                if (is_array($jsonData)) {
                    $data = $jsonData;
                } else {
                    // Raw body (could be XML or other payloads) — check as-is
                    $flatData['raw_body'] = $content;
                }
            }
        }

        // Flatten the data for pattern matching
        if (! empty($data)) {
            $this->flattenData($data, '', $flatData);
        }

        return $flatData;
    }

    /**
     * Recursively flatten data array for pattern matching
     */
    protected function flattenData(array $data, string $prefix, array &$flatData, int $depth = 0): void
    {
        if ($depth > 10) {
            return;
        }

        foreach ($data as $key => $value) {
            $fullKey = $prefix ? "{$prefix}[{$key}]" : $key;

            if (is_array($value)) {
                $flatData[$fullKey] = json_encode($value);
                $this->flattenData($value, $fullKey, $flatData, $depth + 1);
            } else {
                $flatData[$fullKey] = is_string($value) ? $value : (string) $value;
            }
        }
    }

    /**
     * Check for content-length anomaly
     */
    public function isOversizedRequest(Request $request): bool
    {
        $maxLength = $this->scenarios['max_content_length'] ?? 0;

        if ($maxLength <= 0) {
            return false;
        }

        $contentLength = $request->header('Content-Length', 0);

        return (int) $contentLength > $maxLength;
    }

    /**
     * Check for empty / missing user agent
     */
    public function hasEmptyUserAgent(Request $request): bool
    {
        if (! ($this->scenarios['block_empty_ua'] ?? false)) {
            return false;
        }

        $ua = $request->userAgent();

        return empty($ua) || trim($ua) === '' || $ua === '-';
    }

    /**
     * Check if HTTP method is blocked
     */
    public function isBlockedMethod(Request $request): bool
    {
        $blockedMethods = $this->scenarios['blocked_methods'] ?? [];

        return in_array(strtoupper($request->method()), $blockedMethods, true);
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
     * Add threat score based on detected threats
     */
    public function addThreatScoreFromThreats(string $ip, array $threats): void
    {
        if (empty($threats)) {
            return;
        }

        $totalWeight = array_sum(array_column($threats, 'weight'));
        $behavior = IpBehavior::getOrCreate($ip);
        $behavior->addThreatScore($totalWeight);
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
     * Block an IP address with progressive escalation.
     * Each re-offense doubles the previous block duration.
     */
    public function blockIp(
        string $ip,
        string $reason,
        ?int $durationMinutes = null,
        ?string $eventType = null
    ): BlockedIp {
        // Determine base block duration
        if ($durationMinutes === null) {
            $severity = $this->getSeverityFromReason($reason);
            $durationMinutes = $this->scenarios['defaults'][$severity] ?? 240;
        }

        // Progressive escalation: check past blocks to escalate duration
        $behavior = IpBehavior::where('ip', $ip)->first();
        if ($behavior) {
            $blockCount = $behavior->block_count ?? 0;
            if ($blockCount > 0) {
                // Double duration for each previous block, capped at 7 days
                $escalatedDuration = $durationMinutes * pow(2, min($blockCount, 5));
                $durationMinutes = min($escalatedDuration, 10080); // max 7 days
            }
            $behavior->increment('block_count');
        }

        // Use updateOrCreate to handle re-blocking
        $blockedIp = BlockedIp::updateOrCreate(
            ['ip' => $ip],
            [
                'reason' => $reason,
                'event_type' => $eventType,
                'expires_at' => now()->addMinutes($durationMinutes),
                'is_active' => true,
            ]
        );

        // Invalidate cache so blocked status is reflected immediately
        $this->invalidateBlockedCache($ip);

        $this->log('warning', 'IP blocked', [
            'ip' => $ip,
            'reason' => $reason,
            'duration_minutes' => $durationMinutes,
            'block_count' => ($behavior->block_count ?? 1),
        ]);

        // Dispatch IpBlocked event
        IpBlocked::dispatch($ip, $reason, $durationMinutes, $behavior->block_count ?? 1, $eventType);

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
            // Invalidate cache so unblocked status is reflected immediately
            $this->invalidateBlockedCache($ip);

            $this->log('info', 'IP unblocked', ['ip' => $ip]);

            // Dispatch IpUnblocked event
            IpUnblocked::dispatch($ip);

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

        if (Str::contains($reasonLower, ['sql', 'command', 'injection', 'serialization', 'ssrf', 'xxe', 'ssti', 'nosql'])) {
            return 'critical';
        }
        if (Str::contains($reasonLower, ['xss', 'traversal', 'inclusion', 'ldap'])) {
            return 'high';
        }
        if (Str::contains($reasonLower, ['behavior', 'threshold', 'brute'])) {
            return 'high';
        }

        return 'medium';
    }

    /**
     * Internal logging helper
     */
    protected function log(string $level, string $message, array $context = []): void
    {
        $channel = $this->scenarios['log_channel'] ?? null;
        $logger = $channel ? Log::channel($channel) : Log::getFacadeRoot();

        $logger->{$level}("CrowdSec: {$message}", $context);
    }

    // =========================================================================
    // Cache helpers
    // =========================================================================

    /**
     * Check if caching is enabled
     */
    protected function isCacheEnabled(): bool
    {
        return (bool) ($this->scenarios['cache']['enabled'] ?? false);
    }

    /**
     * Get the cache store instance
     */
    protected function cacheStore(): \Illuminate\Contracts\Cache\Repository
    {
        $store = $this->scenarios['cache']['store'] ?? null;

        return $store ? Cache::store($store) : Cache::store();
    }

    /**
     * Get cache key for blocked IP check
     */
    protected function getBlockedCacheKey(string $ip): string
    {
        $prefix = $this->scenarios['cache']['prefix'] ?? 'crowdsec';

        return "{$prefix}:blocked:{$ip}";
    }

    /**
     * Invalidate cached blocked status for an IP
     */
    public function invalidateBlockedCache(string $ip): void
    {
        if ($this->isCacheEnabled()) {
            $this->cacheStore()->forget($this->getBlockedCacheKey($ip));
        }
    }

    /**
     * Safe regex match with backtracking limits to prevent ReDoS.
     *
     * Reduces pcre.backtrack_limit and pcre.recursion_limit during match,
     * then restores original values. Returns false on catastrophic backtracking
     * (fail-open design — a regex timeout should never block a legitimate user).
     *
     * @param  string  $pattern  Regex pattern
     * @param  string  $subject  Input to match against (truncated to 8KB)
     * @return bool Whether the pattern matched
     */
    public function safeMatch(string $pattern, string $subject): bool
    {
        // Truncate input to 8KB to limit regex processing time
        $maxInputLength = 8192;
        if (strlen($subject) > $maxInputLength) {
            $subject = substr($subject, 0, $maxInputLength);
        }

        // Save current limits
        $originalBacktrack = ini_get('pcre.backtrack_limit');
        $originalRecursion = ini_get('pcre.recursion_limit');

        // Reduce limits to prevent catastrophic backtracking
        ini_set('pcre.backtrack_limit', '10000');
        ini_set('pcre.recursion_limit', '1000');

        $result = @preg_match($pattern, $subject);
        $error = preg_last_error();

        // Restore original limits
        ini_set('pcre.backtrack_limit', $originalBacktrack);
        ini_set('pcre.recursion_limit', $originalRecursion);

        // Handle PCRE errors (backtrack limit exceeded, recursion limit, etc.)
        if ($error !== PREG_NO_ERROR) {
            Log::warning("CrowdSec: Regex error (code: {$error}) for pattern: {$pattern}");

            return false; // Fail-open: don't block user on regex error
        }

        return $result === 1;
    }
}

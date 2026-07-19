<?php

namespace RiloArbabillah\LaravelCrowdSec\Services;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use Symfony\Component\HttpFoundation\Response;
use RiloArbabillah\LaravelCrowdSec\Events\IpBlocked;
use RiloArbabillah\LaravelCrowdSec\Events\IpUnblocked;
use RiloArbabillah\LaravelCrowdSec\Events\ThreatDetected;
use RiloArbabillah\LaravelCrowdSec\Models\AuditLog;
use RiloArbabillah\LaravelCrowdSec\Models\BlockedIp;
use RiloArbabillah\LaravelCrowdSec\Models\IpBehavior;
use RiloArbabillah\LaravelCrowdSec\Models\SecurityEvent;

class CrowdSecService
{
    /** @var array<string, mixed> */
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
        'audit',
        'dashboard',
        'event_context',
        'waf',
    ];

    protected SecurityEventContextService $eventContext;

    public function __construct(?SecurityEventContextService $eventContext = null)
    {
        $this->scenarios = config('crowdsec-scenarios', []);
        $this->eventContext = $eventContext ?? app(SecurityEventContextService::class);
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
    /** @param array<string, mixed> $config */
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
    /** @return array<string, array<string, mixed>> */
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
     *
     * @param list<string> $excludedBodyFields
     * @return list<array<string, mixed>>
     */
    public function analyzeRequest(Request $request, array $excludedBodyFields = []): array
    {
        return $this->checkWafPatterns($request, $excludedBodyFields);
    }

    /**
     * Check request against WAF patterns with multi-layer decoding
     *
     * @param list<string> $excludedBodyFields
     * @return list<array<string, mixed>>
     */
    public function checkWafPatterns(Request $request, array $excludedBodyFields = []): array
    {
        $threats = [];
        $inputsToCheck = [];
        $wafConfig = is_array($this->scenarios['waf'] ?? null) ? $this->scenarios['waf'] : [];
        $policy = new WafPolicy($wafConfig);
        $exclusions = $policy->exclusionsFor($request);
        $excludedBodyFields = array_values(array_unique(array_merge(
            $excludedBodyFields,
            $exclusions['ignored_body_fields'],
        )));
        $skippedScenarios = $exclusions['skipped_scenarios'];

        // Collect all inputs to check
        $inputsToCheck['query'] = $request->getQueryString() ?? '';
        $inputsToCheck['path'] = $request->path();

        // Check body data for all mutating methods (not just POST)
        if (in_array($request->method(), ['POST', 'PUT', 'PATCH', 'DELETE'])) {
            $bodyData = $this->extractBodyData($request, $excludedBodyFields);
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

                $mode = $policy->modeFor($scenarioName, $config);
                if ($mode === WafPolicy::MODE_DISABLED || $policy->skipsScenario($scenarioName, $skippedScenarios)) {
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
                                'mode' => $mode,
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

        // Deep inspection: file uploads
        $threats = array_merge($threats, $this->inspectFileUploads($request));

        // Deep inspection: JWT payloads
        $threats = array_merge($threats, $this->inspectJwtPayloads($request));

        return array_values(array_filter(array_map(
            function (array $threat) use ($policy, $skippedScenarios): ?array {
                $type = (string) ($threat['type'] ?? 'unknown');
                $mode = $threat['mode'] ?? $policy->modeFor($type);

                if ($mode === WafPolicy::MODE_DISABLED || $policy->skipsScenario($type, $skippedScenarios)) {
                    return null;
                }

                $threat['mode'] = $mode;

                return $threat;
            },
            $threats,
        )));
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
     *
     * @return list<string>
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

        // Base64 decode — detect encoded payloads
        $b64Decoded = $this->tryBase64Decode($input);
        if ($b64Decoded !== null && ! in_array($b64Decoded, $versions, true)) {
            $versions[] = $b64Decoded;

            // Recursive: base64 inside base64 (up to 1 more level)
            $b64Inner = $this->tryBase64Decode($b64Decoded);
            if ($b64Inner !== null && ! in_array($b64Inner, $versions, true)) {
                $versions[] = $b64Inner;
            }
        }

        return array_unique($versions);
    }

    /**
     * Try to decode a Base64-encoded string. Returns decoded content if valid, null otherwise.
     */
    protected function tryBase64Decode(string $input): ?string
    {
        // Only attempt if it looks like Base64 (min 8 chars, valid charset)
        if (strlen($input) < 8 || ! preg_match('/^[A-Za-z0-9+\/=]{8,}$/', trim($input))) {
            return null;
        }

        $decoded = base64_decode(trim($input), true);
        if ($decoded === false || $decoded === '') {
            return null;
        }

        // Only accept if decoded content is printable text (not binary noise)
        if (! mb_check_encoding($decoded, 'UTF-8') || preg_match('/[\x00-\x08\x0E-\x1F]/', $decoded)) {
            return null;
        }

        return $decoded;
    }

    /**
     * Inspect uploaded files for dangerous content.
     *
     * @return list<array<string, mixed>>
     */
    protected function inspectFileUploads(Request $request): array
    {
        $threats = [];
        $dangerousExtensions = ['php', 'php3', 'php4', 'php5', 'php7', 'phtml', 'phar', 'shtml', 'asp', 'aspx', 'jsp', 'cgi'];

        foreach ($request->allFiles() as $field => $files) {
            $fileList = is_array($files) ? $files : [$files];

            foreach ($fileList as $file) {
                if (! $file instanceof \Illuminate\Http\UploadedFile) {
                    continue;
                }

                $name = $file->getClientOriginalName();
                $ext = strtolower(pathinfo($name, PATHINFO_EXTENSION));

                // Check dangerous extensions
                if (in_array($ext, $dangerousExtensions, true)) {
                    $threats[] = [
                        'type' => 'file_upload_threat',
                        'source' => "upload_{$field}",
                        'matched' => $name,
                        'severity' => 'critical',
                        'weight' => 15,
                    ];
                }

                // Check double-extension attacks (e.g. image.jpg.php)
                if (preg_match('/\.\w+\.(php\d?|phtml|phar|shtml)$/i', $name)) {
                    $threats[] = [
                        'type' => 'file_upload_double_ext',
                        'source' => "upload_{$field}",
                        'matched' => $name,
                        'severity' => 'critical',
                        'weight' => 15,
                    ];
                }

                // Check path traversal in filename
                if (str_contains($name, '..') || str_contains($name, '/') || str_contains($name, '\\')) {
                    $threats[] = [
                        'type' => 'file_upload_path_traversal',
                        'source' => "upload_{$field}",
                        'matched' => $name,
                        'severity' => 'critical',
                        'weight' => 15,
                    ];
                }
            }
        }

        return $threats;
    }

    /**
     * Inspect JWT tokens for injected claims.
     *
     * @return list<array<string, mixed>>
     */
    protected function inspectJwtPayloads(Request $request): array
    {
        $threats = [];
        $tokens = [];

        // Extract from Authorization header
        $authHeader = $request->header('Authorization', '');
        if (preg_match('/^Bearer\s+(.+)$/i', $authHeader, $m)) {
            $tokens['authorization_header'] = $m[1];
        }

        // Extract from body (common field names)
        foreach (['token', 'jwt', 'access_token', 'id_token'] as $field) {
            $val = $request->input($field);
            if (is_string($val) && $val !== '') {
                $tokens["body_{$field}"] = $val;
            }
        }

        foreach ($tokens as $source => $token) {
            $parts = explode('.', $token);
            if (count($parts) !== 3) {
                continue; // Not a JWT format
            }

            $payload = json_decode(base64_decode(strtr($parts[1], '-_', '+/')), true);
            if (! is_array($payload)) {
                continue;
            }

            // Check for privilege escalation attempts
            foreach (['role', 'roles', 'is_admin', 'admin', 'scope', 'scopes'] as $claimKey) {
                if (! isset($payload[$claimKey])) {
                    continue;
                }

                $val = is_array($payload[$claimKey])
                    ? implode(',', $payload[$claimKey])
                    : (string) $payload[$claimKey];

                if ($this->safeMatch('/\b(admin|root|superuser|super_admin)\b/i', $val)) {
                    $threats[] = [
                        'type' => 'jwt_privilege_escalation',
                        'source' => $source,
                        'matched' => "{$claimKey}={$val}",
                        'severity' => 'critical',
                        'weight' => 20,
                    ];
                }
            }

            // Scan all JWT payload values against WAF patterns
            foreach ($payload as $key => $value) {
                if (! is_string($value)) {
                    continue;
                }

                $decodedVersions = $this->multiDecode($value);

                foreach ($this->scenarios as $scenarioName => $config) {
                    if (in_array($scenarioName, self::NON_SCENARIO_KEYS, true)) {
                        continue;
                    }
                    if (! isset($config['patterns']) || ! is_array($config['patterns'])) {
                        continue;
                    }

                    foreach ($config['patterns'] as $pattern) {
                        foreach ($decodedVersions as $decoded) {
                            if ($this->safeMatch($pattern, $decoded)) {
                                $threats[] = [
                                    'type' => "jwt_payload_{$scenarioName}",
                                    'source' => $source,
                                    'matched' => Str::limit("{$key}={$value}", 100),
                                    'severity' => $config['severity'] ?? 'high',
                                    'weight' => ($config['weight'] ?? 5) + 5,
                                ];
                                break 2;
                            }
                        }
                    }
                }
            }
        }

        return $threats;
    }

    /**
     * Extract and flatten body data for checking (supports JSON, form data, XML)
     *
     * @param list<string> $excludedBodyFields
     * @return array<string, string>
     */
    protected function extractBodyData(Request $request, array $excludedBodyFields = []): array
    {
        $flatData = [];

        // Read the body only. Query parameters are inspected separately above.
        $data = $request->isJson()
            ? $request->json()->all()
            : $request->request->all();

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
            $flatData = $this->flattenData($data, '', $flatData, 0, $excludedBodyFields);
        }

        return $flatData;
    }

    /**
     * Recursively flatten data array for pattern matching
     *
     * @param array<array-key, mixed> $data
     * @param array<string, string> $flatData
     * @param list<string> $excludedFields
     * @return array<string, string>
     */
    protected function flattenData(
        array $data,
        string $prefix,
        array $flatData,
        int $depth = 0,
        array $excludedFields = [],
    ): array {
        if ($depth > 10) {
            return $flatData;
        }

        foreach ($data as $key => $value) {
            $normalizedKey = strtolower((string) $key);
            $normalizedPath = strtolower(str_replace(['][', '[', ']'], ['.', '.', ''], (string) ($prefix ? "{$prefix}[{$key}]" : $key)));
            $isExcluded = collect($excludedFields)->contains(function ($pattern) use ($normalizedKey, $normalizedPath): bool {
                $pattern = strtolower(trim((string) $pattern));

                return $pattern !== '' && (str_contains($pattern, '.') || str_contains($pattern, '*')
                    ? Str::is($pattern, $normalizedPath)
                    : $pattern === $normalizedKey);
            });

            if ($isExcluded) {
                continue;
            }

            $fullKey = $prefix ? "{$prefix}[{$key}]" : $key;

            if (is_array($value)) {
                $flatData = $this->flattenData($value, $fullKey, $flatData, $depth + 1, $excludedFields);
            } else {
                $flatData[$fullKey] = is_string($value) ? $value : (string) $value;
            }
        }

        return $flatData;
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

        $contentLength = $request->header('Content-Length') ?? 0;

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
    public function trackLoginAttempt(string $ip, bool $addThreatScore = true): IpBehavior
    {
        $behavior = IpBehavior::getOrCreate($ip);
        $behavior->incrementLoginAttempts($addThreatScore);

        return $behavior;
    }

    /**
     * Add threat score based on detected threats
     *
     * @param array<int, array<string, mixed>> $threats
     */
    public function addThreatScoreFromThreats(string $ip, array $threats): void
    {
        $enforcedThreats = array_filter(
            $threats,
            fn ($threat) => ($threat['mode'] ?? WafPolicy::MODE_ENFORCE) === WafPolicy::MODE_ENFORCE,
        );

        if (empty($enforcedThreats)) {
            return;
        }

        $totalWeight = array_sum(array_column($enforcedThreats, 'weight'));
        IpBehavior::withLock($ip, function (IpBehavior $behavior) use ($totalWeight): void {
            $behavior->setAttribute('threat_score', min(100, (float) $behavior->threat_score + $totalWeight));
            $behavior->setAttribute('last_activity', now());
            $behavior->save();
        });
    }

    /**
     * Check if IP exceeds behavior thresholds
     */
    public function exceedsBehaviorThreshold(string $ip): bool
    {
        $behavior = IpBehavior::where('ip', $ip)->first();

        if (! $behavior) {
            return false;
        }

        $behaviorConfig = $this->scenarios['behavior'] ?? [];

        $requestWindowActive = $behavior->isWindowActive(
            'request_window_started_at',
            (int) ($behaviorConfig['request_window_minutes'] ?? 60),
        );
        $errorWindowActive = $behavior->isWindowActive(
            'error_404_window_started_at',
            (int) ($behaviorConfig['404_window_minutes'] ?? 60),
        );

        return ($requestWindowActive && $behavior->request_count >= ($behaviorConfig['request_threshold'] ?? 500))
            || ($errorWindowActive && $behavior->error_404_count >= ($behaviorConfig['404_threshold'] ?? 15))
            || $behavior->threat_score >= ($behaviorConfig['threat_score_threshold'] ?? 50);
    }

    /**
     * Check login brute force threshold
     */
    public function exceedsLoginThreshold(string $ip): bool
    {
        $behavior = IpBehavior::where('ip', $ip)->first();

        if (! $behavior) {
            return false;
        }

        $behaviorConfig = $this->scenarios['behavior'] ?? [];

        return $behavior->isWindowActive(
            'login_window_started_at',
            (int) ($behaviorConfig['login_window_minutes'] ?? 5),
        ) && $behavior->login_attempts >= ($behaviorConfig['login_threshold'] ?? 5);
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

        [$blockedIp, $durationMinutes, $blockCount] = IpBehavior::withLock(
            $ip,
            function (IpBehavior $behavior) use ($ip, $reason, $durationMinutes, $eventType): array {
                $previousBlockCount = (int) $behavior->block_count;
                $effectiveDuration = $durationMinutes;

                // Progressive escalation: double each re-offense, capped at 7 days.
                if ($previousBlockCount > 0) {
                    $escalatedDuration = $effectiveDuration * pow(2, min($previousBlockCount, 5));
                    $effectiveDuration = (int) min($escalatedDuration, 10080);
                }

                $behavior->setAttribute('block_count', $previousBlockCount + 1);
                $behavior->setAttribute('last_activity', now());
                $behavior->save();

                $blockedIp = BlockedIp::updateOrCreate(
                    ['ip' => $ip],
                    [
                        'reason' => $reason,
                        'event_type' => $eventType,
                        'expires_at' => now()->addMinutes($effectiveDuration),
                        'is_active' => true,
                    ]
                );

                return [$blockedIp, $effectiveDuration, $previousBlockCount + 1];
            }
        );

        // Invalidate cache so blocked status is reflected immediately
        $this->invalidateBlockedCache($ip);

        $this->log('warning', 'IP blocked', [
            'ip' => $ip,
            'reason' => $reason,
            'duration_minutes' => $durationMinutes,
            'block_count' => $blockCount,
        ]);

        // Dispatch IpBlocked event
        IpBlocked::dispatch($ip, $reason, $durationMinutes, $blockCount, $eventType);

        // Record audit log
        if (config('crowdsec-scenarios.audit.enabled', false)) {
            AuditLog::record('ip_blocked', $ip, [
                'reason' => $reason,
                'duration_minutes' => $durationMinutes,
                'block_count' => $blockCount,
                'event_type' => $eventType,
            ]);
        }

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

            // Record audit log
            if (config('crowdsec-scenarios.audit.enabled', false)) {
                AuditLog::record('ip_unblocked', $ip);
            }

            return true;
        }

        return false;
    }

    /**
     * Log a security event
     *
     * @param array<int, array<string, mixed>> $threats
     */
    public function logEvent(
        string $ip,
        array $threats,
        Request $request,
        ?string $actionTaken = null
    ): SecurityEvent
    {
        $eventTypes = array_unique(array_column($threats, 'type'));
        $severities = array_column($threats, 'severity');
        $maxSeverity = $this->getMaxSeverity($severities);
        $context = $this->eventContext->collect($request);

        $event = SecurityEvent::create([
            'ip' => $ip,
            'event_type' => implode(', ', $eventTypes),
            'severity' => $maxSeverity,
            'request_data' => [
                'method' => $request->method(),
                'path' => $request->path(),
                'query' => $this->eventContext->redactQuery($request),
                'user_agent' => $request->userAgent(),
                'referer' => $this->eventContext->redactReferer($request->header('Referer')),
            ],
            'user_agent' => $request->userAgent(),
            'request_path' => $request->path(),
            'matched_patterns' => $this->eventContext->sanitizeThreats($threats, $request),
            'action_taken' => $actionTaken,
            ...$context,
        ]);

        return $event;
    }

    public function finalizeEvent(
        SecurityEvent $event,
        Response $response,
        int $startedAtNanoseconds,
        string $actionTaken,
        ?BlockedIp $blockedIp = null
    ): void
    {
        $event->update([
            'response_status' => $response->getStatusCode(),
            'duration_ms' => max(0, (int) round((hrtime(true) - $startedAtNanoseconds) / 1_000_000)),
            'action_taken' => $actionTaken,
            'blocked_ip_id' => $blockedIp?->getKey(),
        ]);

        $requestId = $event->getAttribute('request_id');
        $this->eventContext->addRequestIdHeader($response, is_string($requestId) ? $requestId : null);
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
     *
     * @return array<string, mixed>
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
     *
     * @param array<int, array<string, mixed>> $threats
     * @return array<int, array<string, mixed>>
     */
    public function getBlockingThreats(array $threats): array
    {
        return array_filter($threats, fn ($t) => ($t['mode'] ?? WafPolicy::MODE_ENFORCE) === WafPolicy::MODE_ENFORCE
            && in_array(($t['severity'] ?? 'medium'), ['critical', 'high', 'medium'], true));
    }

    /**
     * Compare severity levels and return the highest.
     *
     * @param list<string> $severities
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
     *
     * @param array<string, mixed> $context
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

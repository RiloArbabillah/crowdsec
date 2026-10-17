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
use RiloArbabillah\LaravelCrowdSec\Models\WhitelistedIp;

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
    /** Request attribute holding the IP whose failed login the Failed listener already counted. */
    public const FAILED_LOGIN_TRACKED_ATTRIBUTE = 'crowdsec.failed_login_tracked';

    /** Used when a published config predates `waf.sensitive_body_fields`. */
    protected const DEFAULT_SENSITIVE_BODY_FIELDS = ['password', 'password_confirmation', 'current_password'];

    /** Maximum body nesting flattened field-by-field before the rest is inspected as JSON. */
    protected const MAX_BODY_DEPTH = 32;

    /**
     * Headers not inspected as generic header_* sources: inspected elsewhere
     * (UA, Referer, cookies, Authorization JWTs) or never attacker-meaningful.
     */
    protected const UNINSPECTED_HEADERS = [
        'user-agent', 'referer', 'cookie', 'authorization', 'content-length',
        'content-type', 'accept', 'accept-encoding', 'accept-language',
        'x-csrf-token', 'x-xsrf-token',
    ];

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
        'retention',
        'waf',
    ];

    protected SecurityEventContextService $eventContext;

    /** True while withPcreLimits() has the reduced PCRE limits in place. */
    protected bool $pcreLimitsApplied = false;

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
     * Check if an IP is whitelisted. Checks the static config array first
     * (preserves backward compatibility) and then the database-backed
     * `whitelisted_ips` table. The DB lookup is short-cached (30s).
     */
    public function isWhitelisted(string $ip): bool
    {
        foreach ($this->scenarios['whitelist_ips'] ?? [] as $entry) {
            if ($this->matchesWhitelistEntry($ip, (string) $entry)) {
                return true;
            }
        }

        return $this->isWhitelistedInDatabase($ip);
    }

    /**
     * Match an IP against a single whitelist entry (exact or CIDR).
     */
    protected function matchesWhitelistEntry(string $ip, string $entry): bool
    {
        if ($ip === $entry || $this->normalizeIp($ip) === $this->normalizeIp($entry)) {
            return true;
        }
        if (str_contains($entry, '/') && $this->ipInCidr($ip, $entry)) {
            return true;
        }
        return false;
    }

    /**
     * Look up the IP in the dynamic (DB-backed) whitelist.
     */
    protected function isWhitelistedInDatabase(string $ip): bool
    {
        if (! $this->isCacheEnabled()) {
            return $this->matchesAnyEntry(
                $ip,
                WhitelistedIp::active()->notExpired()->pluck('ip')->all(),
            );
        }

        $entries = $this->cacheStore()->remember(
            $this->getWhitelistCacheKey(),
            30,
            fn () => WhitelistedIp::active()->notExpired()->pluck('ip')->all()
        );

        return $this->matchesAnyEntry($ip, $entries);
    }

    /**
     * @param list<string> $entries
     */
    protected function matchesAnyEntry(string $ip, array $entries): bool
    {
        foreach ($entries as $entry) {
            if ($this->matchesWhitelistEntry($ip, (string) $entry)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Validate a string is a single IP or a CIDR range.
     */
    public function isValidIpOrCidr(string $value): bool
    {
        if (str_contains($value, '/')) {
            [$subnet, $bitsRaw] = explode('/', $value, 2);
            if ($bitsRaw === '' || ! ctype_digit($bitsRaw)) {
                return false;
            }
            if (! filter_var($subnet, FILTER_VALIDATE_IP)) {
                return false;
            }
            $bits = (int) $bitsRaw;
            $max = filter_var($subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) ? 32 : 128;
            return $bits >= 0 && $bits <= $max;
        }

        return (bool) filter_var($value, FILTER_VALIDATE_IP);
    }

    /**
     * Add (or update) a dynamic whitelist entry.
     */
    public function whitelistIp(
        string $ip,
        ?string $label = null,
        ?string $note = null,
        ?\DateTimeInterface $expiresAt = null,
        ?int $createdBy = null,
        ?string $createdByLabel = null,
    ): WhitelistedIp {
        $entry = WhitelistedIp::updateOrCreate(
            ['ip' => $ip],
            [
                'label' => $label,
                'note' => $note,
                'expires_at' => $expiresAt,
                'is_active' => true,
                'created_by' => $createdBy,
                'created_by_label' => $createdByLabel,
            ],
        );

        $this->invalidateWhitelistCache();
        // A whitelist entry must take effect immediately, even when this IP
        // already has a cached active block. The middleware checks the
        // whitelist first, but stale blocked-cache state must not leak into
        // other consumers of isBlocked(). For CIDR entries, clear every
        // cached blocked IP cannot be derived safely, so use a cache version
        // to invalidate the whole blocked namespace.
        $this->invalidateAllBlockedCaches();

        $this->log('info', 'IP whitelisted', [
            'ip' => $ip,
            'label' => $label,
            'expires_at' => $expiresAt?->format(DATE_ATOM),
        ]);

        if (config('crowdsec-scenarios.audit.enabled', false)) {
            AuditLog::record('whitelist_modified', $ip, [
                'action' => 'added',
                'label' => $label,
                'note' => $note,
                'expires_at' => $expiresAt?->format(DATE_ATOM),
                'actor_id' => $createdBy,
                'actor_label' => $createdByLabel,
            ]);
        }

        return $entry;
    }

    /**
     * Deactivate a dynamic whitelist entry. Returns true only when an active
     * entry was actually transitioned to inactive (idempotent: re-running on
     * an already-inactive or unknown entry returns false).
     */
    public function unwhitelistIp(
        string $ip,
        ?int $actorId = null,
        ?string $actorLabel = null,
    ): bool {
        $entry = WhitelistedIp::where('ip', $ip)->where('is_active', true)->first();
        if (! $entry) {
            return false;
        }

        $entry->update(['is_active' => false]);
        $this->invalidateWhitelistCache();

        $this->log('info', 'IP removed from whitelist', ['ip' => $ip]);

        if (config('crowdsec-scenarios.audit.enabled', false)) {
            AuditLog::record('whitelist_modified', $ip, [
                'action' => 'removed',
                'actor_id' => $actorId,
                'actor_label' => $actorLabel,
            ]);
        }

        return true;
    }

    /**
     * Hard-delete a dynamic whitelist entry. Returns true if a row was removed.
     */
    public function deleteWhitelistEntry(string $ip): bool
    {
        $deleted = (bool) WhitelistedIp::where('ip', $ip)->delete();
        if ($deleted) {
            $this->invalidateWhitelistCache();
        }
        return $deleted;
    }

    /**
     * Permanently delete all expired dynamic whitelist entries.
     */
    public function purgeExpiredWhitelistEntries(): int
    {
        $deleted = WhitelistedIp::expired()->delete();
        if ($deleted > 0) {
            $this->invalidateWhitelistCache();
        }
        return $deleted;
    }

    public function invalidateWhitelistCache(): void
    {
        $this->cacheStore()->forget($this->getWhitelistCacheKey());
    }

    protected function getWhitelistCacheKey(): string
    {
        $prefix = $this->scenarios['cache']['prefix'] ?? 'crowdsec';

        return "{$prefix}:whitelist:merged";
    }

    /**
     * Canonical form of an IP: compressed IPv6, IPv4-mapped IPv6 as IPv4.
     * Returns the input unchanged when it is not a valid IP.
     */
    protected function normalizeIp(string $ip): string
    {
        $bin = @inet_pton($ip);
        if ($bin === false) {
            return $ip;
        }

        if (strlen($bin) === 16 && str_starts_with($bin, str_repeat("\0", 10) . "\xff\xff")) {
            $bin = substr($bin, 12);
        }

        return (string) inet_ntop($bin);
    }

    /**
     * Check if an IP address falls within a CIDR range
     */
    protected function ipInCidr(string $ip, string $cidr): bool
    {
        [$subnet, $bits] = explode('/', $cidr, 2);
        $bits = (int) $bits;

        $ipBin = @inet_pton($this->normalizeIp($ip));
        $subnetBin = @inet_pton($subnet);

        // Different address families never match: PHP's `&` truncates to the
        // shorter string, so an IPv4 address would otherwise match an IPv6 range.
        if ($ipBin === false || $subnetBin === false || strlen($ipBin) !== strlen($subnetBin)) {
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
        return $this->withPcreLimits(fn (): array => $this->runWafChecks($request, $excludedBodyFields));
    }

    /**
     * @param list<string> $excludedBodyFields
     * @return list<array<string, mixed>>
     */
    protected function runWafChecks(Request $request, array $excludedBodyFields): array
    {
        $threats = [];
        $inputsToCheck = [];
        $wafConfig = is_array($this->scenarios['waf'] ?? null) ? $this->scenarios['waf'] : [];
        $policy = new WafPolicy($wafConfig);
        $exclusions = $policy->exclusionsFor($request);
        $excludedBodyFields = array_values(array_unique(array_merge(
            $excludedBodyFields,
            $exclusions['ignored_body_fields'],
            array_map('strval', (array) ($wafConfig['sensitive_body_fields'] ?? self::DEFAULT_SENSITIVE_BODY_FIELDS)),
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

        // Other headers (header_injection / jndi_injection only, see shouldCheckScenario)
        foreach ($request->headers->all() as $headerName => $headerValues) {
            if (in_array($headerName, self::UNINSPECTED_HEADERS, true)) {
                continue;
            }
            $headerValue = implode(', ', array_filter($headerValues, 'is_string'));
            if ($headerValue !== '') {
                $inputsToCheck["header_{$headerName}"] = $headerValue;
            }
        }

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
                // jwt_payload_<scenario> follows its base scenario's mode and exclusions
                $baseType = str_starts_with($type, 'jwt_payload_') ? substr($type, strlen('jwt_payload_')) : $type;
                $mode = $threat['mode'] ?? $policy->modeFor($type, match (true) {
                    $baseType !== $type => ['mode' => $policy->modeFor($baseType, $this->scenarios[$baseType] ?? [])],
                    // Legitimate admin tokens carry role=admin; enforce only on opt-in.
                    $type === 'jwt_privilege_escalation' => ['mode' => WafPolicy::MODE_MONITOR],
                    default => [],
                });

                if ($mode === WafPolicy::MODE_DISABLED
                    || $policy->skipsScenario($type, $skippedScenarios)
                    || $policy->skipsScenario($baseType, $skippedScenarios)) {
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

        // All other scenarios skip UA (except Log4Shell, often sent in the UA)
        if ($isUserAgent && $scenarioName !== 'jndi_injection') {
            return false;
        }

        // header_injection only checks headers
        if ($scenarioName === 'header_injection') {
            return in_array($source, ['referer', 'user_agent']) || str_starts_with($source, 'header_');
        }

        // jndi_injection (Log4Shell) checks every source
        if ($scenarioName === 'jndi_injection') {
            return true;
        }

        // Generic headers are noisy (Origin, Host, Accept…); only the
        // header-specific scenarios above inspect them.
        if (str_starts_with($source, 'header_')) {
            return false;
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
        $versions = [$input];

        // URL decode until stable (up to 3 layers, e.g. %252527 → %2527 → %27 → ')
        $current = $input;
        for ($pass = 0; $pass < 3; $pass++) {
            $next = urldecode($this->decodePercentU($current));
            if ($next === $current) {
                break;
            }
            $versions[] = $current = $next;
        }

        // HTML entity decode, on the raw and on the URL-decoded input
        foreach (array_unique([$input, $current]) as $candidate) {
            $versions[] = html_entity_decode($candidate, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        }

        // Base64 decode — detect encoded payloads
        $b64Decoded = $this->tryBase64Decode($input);
        if ($b64Decoded !== null) {
            $versions[] = $b64Decoded;

            // Recursive: base64 inside base64 (up to 1 more level)
            $b64Inner = $this->tryBase64Decode($b64Decoded);
            if ($b64Inner !== null) {
                $versions[] = $b64Inner;
            }
        }

        // Evasion normalization on every version: NUL bytes, SQL inline
        // comments (UNION/**/SELECT), and fullwidth/compatibility characters.
        foreach ($versions as $version) {
            $versions[] = $this->normalizeEvasions($version);
        }

        return array_values(array_unique($versions));
    }

    /**
     * Decode IIS-style %uXXXX escapes.
     */
    protected function decodePercentU(string $input): string
    {
        if (stripos($input, '%u') === false) {
            return $input;
        }

        return (string) preg_replace_callback(
            '/%u([0-9a-f]{4})/i',
            fn (array $m): string => mb_chr((int) hexdec($m[1]), 'UTF-8') ?: '',
            $input,
        );
    }

    /**
     * Strip common WAF evasions so patterns see the effective payload.
     */
    protected function normalizeEvasions(string $input): string
    {
        $normalized = str_replace("\0", '', $input);

        if (str_contains($normalized, '/*')) {
            $normalized = (string) preg_replace('#/\*.*?\*/#s', ' ', $normalized);
        }

        if (class_exists(\Normalizer::class) && preg_match('/[^\x00-\x7F]/', $normalized)) {
            $normalized = \Normalizer::normalize($normalized, \Normalizer::FORM_KC) ?: $normalized;
        }

        return $normalized;
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

        // Livewire sends component state as a JSON string; decode it so field
        // exclusions apply to its keys too.
        if ($request->hasHeader('X-Livewire') && is_array($data['components'] ?? null)) {
            foreach ($data['components'] as $index => $component) {
                $snapshot = is_array($component) ? ($component['snapshot'] ?? null) : null;
                $decoded = is_string($snapshot) ? json_decode($snapshot, true) : null;
                if (is_array($decoded)) {
                    $data['components'][$index]['snapshot'] = $decoded;
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
        // Past the depth limit, inspect the remaining subtree as one JSON
        // string instead of dropping it (deep nesting was a WAF bypass).
        if ($depth > self::MAX_BODY_DEPTH) {
            $flatData[$prefix ?: 'nested'] = (string) json_encode(
                $this->withoutExcludedKeys($data, $excludedFields),
                JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PARTIAL_OUTPUT_ON_ERROR,
            );

            return $flatData;
        }

        foreach ($data as $key => $value) {
            $normalizedKey = strtolower((string) $key);
            $normalizedPath = strtolower(str_replace(['][', '[', ']'], ['.', '.', ''], (string) ($prefix ? "{$prefix}[{$key}]" : $key)));
            $isExcluded = collect($excludedFields)->contains(function ($pattern) use ($normalizedKey, $normalizedPath): bool {
                $pattern = strtolower(trim((string) $pattern));

                return $pattern !== '' && (str_contains($pattern, '.') || str_contains($pattern, '*')
                    ? Str::is($pattern, $normalizedPath)
                    : $pattern === $normalizedKey || $pattern === Str::afterLast($normalizedKey, '.'));
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
     * Recursively drop keys named in $excludedFields (plain key names, and
     * the last segment of dotted patterns) from a subtree.
     *
     * @param array<array-key, mixed> $data
     * @param list<string> $excludedFields
     * @return array<array-key, mixed>
     */
    protected function withoutExcludedKeys(array $data, array $excludedFields): array
    {
        $names = array_map(
            fn ($pattern): string => strtolower(Str::afterLast(trim((string) $pattern), '.')),
            $excludedFields,
        );

        foreach ($data as $key => $value) {
            if (in_array(strtolower((string) $key), $names, true)) {
                unset($data[$key]);
            } elseif (is_array($value)) {
                $data[$key] = $this->withoutExcludedKeys($value, $excludedFields);
            }
        }

        return $data;
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

        $contentLength = $request->header('Content-Length');

        // Chunked requests carry no Content-Length; measure the body instead.
        if ($contentLength === null || $contentLength === '') {
            return strlen((string) $request->getContent()) > $maxLength;
        }

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
        return $this->trackRequest($ip);
    }

    /**
     * Track 404 response for an IP
     */
    public function track404(string $ip): IpBehavior
    {
        [$behavior] = IpBehavior::mutateLocked($ip, function (IpBehavior $behavior): void {
            $behavior->incrementWindowCounter(
                'error_404_count',
                'error_404_window_started_at',
                (int) ($this->scenarios['behavior']['404_window_minutes'] ?? 60),
            );
            $behavior->setAttribute('threat_score', min(100, (float) $behavior->threat_score + 5));
            $behavior->save();
        });

        return $behavior;
    }

    /**
     * Whether the request is a POST to one of the configured login routes.
     */
    public function isLoginRequest(Request $request): bool
    {
        if ($request->method() !== 'POST') {
            return false;
        }

        $path = $request->path();

        foreach (config('crowdsec-scenarios.login_routes', ['login']) as $route) {
            if ($path === $route || fnmatch($route, $path)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Track login attempt for an IP
     */
    public function trackLoginAttempt(string $ip, bool $addThreatScore = true): IpBehavior
    {
        // Apps that call this manually after a failed Auth::attempt() would
        // otherwise count the failure twice (once by the Failed listener).
        $request = app()->bound('request') ? request() : null;
        if ($request !== null && $request->attributes->get(self::FAILED_LOGIN_TRACKED_ATTRIBUTE) === $ip) {
            $request->attributes->remove(self::FAILED_LOGIN_TRACKED_ATTRIBUTE);

            return IpBehavior::getOrCreate($ip);
        }

        $behavior = IpBehavior::getOrCreate($ip);
        $behavior->incrementLoginAttempts($addThreatScore);

        return $behavior;
    }

    /**
     * Consolidate the mutations produced by a single request into ONE lock
     * acquisition on ip_behaviors. Previously a single request performed two
     * to three separate withLock() calls (login attempt, threat score, request
     * count), which multiplied lock contention and helped trigger 1213
     * deadlocks under concurrency.
     *
     * @param  array<int, array<string, mixed>>  $threats
     * @param  array<string, mixed>  $extraCounters  Reserved for future counters
     *                                               (e.g. error_404_count) keyed by column name.
     * @param  float  $additionalThreatScore  Score from non-WAF heuristics (e.g. empty User-Agent)
     */
    public function trackRequest(
        string $ip,
        bool $loginAttempt = false,
        bool $loginAddsThreatScore = true,
        array $threats = [],
        array $extraCounters = [],
        bool $countRequest = true,
        float $additionalThreatScore = 0.0,
    ): IpBehavior {
        $totalWeight = $this->totalEnforcedThreatWeight($threats) + max(0.0, $additionalThreatScore);

        /** @var IpBehavior $behavior */
        [$behavior] = IpBehavior::mutateLocked($ip, function (IpBehavior $behavior) use (
            $loginAttempt,
            $loginAddsThreatScore,
            $totalWeight,
            $extraCounters,
            $countRequest
        ): void {
            $now = now();
            $behavior->setAttribute('last_activity', $now);

            if ($countRequest) {
                $behavior->incrementWindowCounter(
                    'request_count',
                    'request_window_started_at',
                    (int) ($this->scenarios['behavior']['request_window_minutes'] ?? 60),
                );
            }

            if ($loginAttempt) {
                $behavior->incrementWindowCounter(
                    'login_attempts',
                    'login_window_started_at',
                    (int) ($this->scenarios['behavior']['login_window_minutes'] ?? 5),
                );
            }

            foreach ($extraCounters as $counter => $increment) {
                $increment = max(0, (int) $increment);
                if ($increment === 0) {
                    continue;
                }

                $column = (string) $counter;
                $behavior->setAttribute($column, (int) $behavior->getAttribute($column) + $increment);
            }

            $scoreDelta = $totalWeight;
            if ($loginAttempt && $loginAddsThreatScore) {
                $scoreDelta += 10;
            }

            if ($scoreDelta > 0) {
                $behavior->setAttribute(
                    'threat_score',
                    min(100, (float) $behavior->threat_score + $scoreDelta),
                );
            }

            $behavior->save();
        });

        return $behavior;
    }

    /**
     * Track the request count for an IP in one lock acquisition.
     */
    public function trackRequestCount(string $ip): IpBehavior
    {
        return $this->trackRequest($ip);
    }

    /**
     * Add threat score based on detected threats
     *
     * @param array<int, array<string, mixed>> $threats
     */
    public function addThreatScoreFromThreats(string $ip, array $threats): void
    {
        $totalWeight = $this->totalEnforcedThreatWeight($threats);

        if ($totalWeight <= 0) {
            return;
        }

        IpBehavior::withLock($ip, function (IpBehavior $behavior) use ($totalWeight): void {
            $behavior->setAttribute('threat_score', min(100, (float) $behavior->threat_score + $totalWeight));
            $behavior->setAttribute('last_activity', now());
            $behavior->save();
        });
    }

    /**
     * Sum the weight of threats that are being enforced (scored).
     *
     * @param  array<int, array<string, mixed>>  $threats
     */
    protected function totalEnforcedThreatWeight(array $threats): float
    {
        $enforcedThreats = array_filter(
            $threats,
            fn ($threat) => ($threat['mode'] ?? WafPolicy::MODE_ENFORCE) === WafPolicy::MODE_ENFORCE,
        );

        if (empty($enforcedThreats)) {
            return 0.0;
        }

        return (float) array_sum(array_column($enforcedThreats, 'weight'));
    }

    /**
     * Check if IP exceeds behavior thresholds. Pass a freshly tracked
     * $behavior to skip the lookup query.
     */
    public function exceedsBehaviorThreshold(string $ip, ?IpBehavior $behavior = null): bool
    {
        $behavior ??= IpBehavior::where('ip', $ip)->first();

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

                // The block is the penalty; block_count carries the escalation.
                // Without this the score is still over the threshold when the
                // block expires, and the first request re-blocks at double length.
                $scoreThreshold = (float) ($this->scenarios['behavior']['threat_score_threshold'] ?? 50);
                if ((float) $behavior->threat_score >= $scoreThreshold) {
                    $behavior->setAttribute('threat_score', $scoreThreshold / 2);
                }

                $behavior->save();

                // Atomic upsert (INSERT ... ON DUPLICATE KEY UPDATE) instead of
                // updateOrCreate() (SELECT + INSERT/UPDATE). This acquires a
                // single row lock without holding a gap lock, and runs strictly
                // after the ip_behaviors lock to keep lock ordering consistent:
                // ip_behaviors -> blocked_ips.
                $blockedIp = BlockedIp::upsertBlock(
                    $ip,
                    $reason,
                    now()->addMinutes($effectiveDuration),
                    $eventType,
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
     * Longest `block_duration` configured for the threats' scenarios, or null
     * to fall back to the severity defaults.
     *
     * @param array<array-key, array<string, mixed>> $threats
     */
    public function blockDurationForThreats(array $threats): ?int
    {
        $durations = [];
        foreach ($threats as $threat) {
            $type = (string) ($threat['type'] ?? '');
            $type = str_starts_with($type, 'jwt_payload_') ? substr($type, strlen('jwt_payload_')) : $type;
            $duration = $this->scenarios[$type]['block_duration'] ?? null;
            if (is_numeric($duration) && (int) $duration > 0) {
                $durations[] = (int) $duration;
            }
        }

        return $durations === [] ? null : max($durations);
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

        return "{$prefix}:blocked:" . $this->getBlockedCacheVersion() . ":{$ip}";
    }

    protected function getBlockedCacheVersion(): int
    {
        return (int) $this->cacheStore()->get($this->getBlockedCacheVersionKey(), 1);
    }

    protected function getBlockedCacheVersionKey(): string
    {
        $prefix = $this->scenarios['cache']['prefix'] ?? 'crowdsec';

        return "{$prefix}:blocked:version";
    }

    /**
     * Invalidate all cached blocked statuses. Used when a whitelist changes,
     * because a CIDR whitelist can cover multiple already-cached IPs.
     */
    public function invalidateAllBlockedCaches(): void
    {
        if ($this->isCacheEnabled()) {
            // Seed the implicit version 1 first: increment() on a missing key
            // yields 1, which would leave every cached key valid.
            $this->cacheStore()->add($this->getBlockedCacheVersionKey(), 1);
            $this->cacheStore()->increment($this->getBlockedCacheVersionKey());
        }
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
     * Inputs over 8KB are matched in overlapping 8KB chunks (up to 64KB), so
     * padding a payload past the first 8KB no longer hides it.
     *
     * @param  string  $pattern  Regex pattern
     * @param  string  $subject  Input to match against
     * @return bool Whether the pattern matched
     */
    /**
     * Run $callback with reduced PCRE limits (against catastrophic
     * backtracking), set once for a whole WAF pass rather than per match.
     *
     * @template TResult
     * @param  \Closure(): TResult  $callback
     * @return TResult
     */
    protected function withPcreLimits(\Closure $callback): mixed
    {
        if ($this->pcreLimitsApplied) {
            return $callback();
        }

        $originalBacktrack = (string) ini_get('pcre.backtrack_limit');
        $originalRecursion = (string) ini_get('pcre.recursion_limit');
        ini_set('pcre.backtrack_limit', '10000');
        ini_set('pcre.recursion_limit', '1000');
        $this->pcreLimitsApplied = true;

        try {
            return $callback();
        } finally {
            ini_set('pcre.backtrack_limit', $originalBacktrack);
            ini_set('pcre.recursion_limit', $originalRecursion);
            $this->pcreLimitsApplied = false;
        }
    }

    public function safeMatch(string $pattern, string $subject): bool
    {
        $chunkLength = 8192;
        if (strlen($subject) <= $chunkLength) {
            return $this->safeMatchChunk($pattern, $subject);
        }

        $overlap = 512;
        $limit = min(strlen($subject), 65536);
        for ($offset = 0; $offset < $limit; $offset += $chunkLength - $overlap) {
            $isLast = $offset + $chunkLength >= $limit;
            // A \x01 sentinel at interior chunk edges keeps ^ and $ from
            // matching there; they should only match the real start and end.
            $chunk = ($offset > 0 ? "\x01" : '')
                . substr($subject, $offset, $isLast ? $limit - $offset : $chunkLength)
                . ($isLast ? '' : "\x01");

            if ($this->safeMatchChunk($pattern, $chunk)) {
                return true;
            }
            if ($isLast) {
                break;
            }
        }

        return false;
    }

    protected function safeMatchChunk(string $pattern, string $subject): bool
    {
        [$result, $error] = $this->withPcreLimits(fn (): array => [@preg_match($pattern, $subject), preg_last_error()]);

        // Handle PCRE errors (backtrack limit exceeded, recursion limit, etc.)
        if ($error !== PREG_NO_ERROR) {
            Log::warning("CrowdSec: Regex error (code: {$error}) for pattern: {$pattern}");

            return false; // Fail-open: don't block user on regex error
        }

        return $result === 1;
    }
}

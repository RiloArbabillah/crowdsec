<?php

namespace RiloArbabillah\LaravelCrowdSec\Services;

use DeviceDetector\DeviceDetector;
use Illuminate\Http\Request;
use Illuminate\Support\Str;
use Symfony\Component\HttpFoundation\Response;

class SecurityEventContextService
{
    protected const DEFAULT_SENSITIVE_KEYS = [
        'password',
        'password_confirmation',
        'token',
        'access_token',
        'refresh_token',
        'api_key',
        'secret',
        'authorization',
        'signature',
    ];

    public function __construct(
        protected GeoIpService $geoIp,
    ) {}

    /**
     * Collect safe, normalized context for a detected security event.
     */
    public function collect(Request $request): array
    {
        $requestId = $this->resolveRequestId($request);
        $request->attributes->set('crowdsec.request_id', $requestId);

        return array_merge([
            'request_id' => $requestId,
            'route_name' => $this->routeName($request),
            'content_type' => $this->contentType($request),
            'content_length' => $this->contentLength($request),
            'authenticated_user_id_hash' => $this->authenticatedUserHash($request),
        ], $this->geoContext($request), $this->clientContext($request));
    }

    public function redactQuery(Request $request): ?string
    {
        $query = $request->query->all();

        if ($query === []) {
            return null;
        }

        return http_build_query(
            $this->redactArray($query),
            '',
            '&',
            PHP_QUERY_RFC3986
        );
    }

    public function redactReferer(?string $referer): ?string
    {
        if ($referer === null || $referer === '') {
            return $referer;
        }

        $parts = parse_url($referer);
        if ($parts === false || ! isset($parts['query'])) {
            return Str::limit($referer, 2048, '');
        }

        parse_str($parts['query'], $query);
        $redactedQuery = http_build_query($this->redactArray($query), '', '&', PHP_QUERY_RFC3986);
        $base = strstr($referer, '?', true);

        return Str::limit(($base === false ? $referer : $base).'?'.$redactedQuery, 2048, '');
    }

    public function sanitizeThreats(array $threats, Request $request): array
    {
        $redactedQuery = $this->redactQuery($request);

        return array_map(function (array $threat) use ($redactedQuery): array {
            $source = strtolower((string) ($threat['source'] ?? ''));

            if ($source === 'query') {
                $threat['matched'] = Str::limit($redactedQuery ?? '', 100, '');
            } elseif ($this->isSensitiveSource($source)) {
                $threat['matched'] = '[REDACTED]';
            }

            return $threat;
        }, $threats);
    }

    public function addRequestIdHeader(Response $response, ?string $requestId): void
    {
        if ($requestId === null || $requestId === '') {
            return;
        }

        $header = (string) config('crowdsec-scenarios.event_context.request_id_header', 'X-Request-ID');
        if ($header !== '' && ! $response->headers->has($header)) {
            $response->headers->set($header, $requestId);
        }
    }

    protected function resolveRequestId(Request $request): string
    {
        $header = (string) config('crowdsec-scenarios.event_context.request_id_header', 'X-Request-ID');
        $candidate = $header !== '' ? trim((string) $request->header($header, '')) : '';

        if ($candidate !== '' && preg_match('/\A[A-Za-z0-9._:-]{1,128}\z/D', $candidate) === 1) {
            return $candidate;
        }

        return (string) Str::uuid();
    }

    protected function routeName(Request $request): ?string
    {
        $route = $request->route();

        if (is_object($route) && method_exists($route, 'getName')) {
            $name = $route->getName();

            return is_string($name) && $name !== '' ? Str::limit($name, 255, '') : null;
        }

        return null;
    }

    protected function contentType(Request $request): ?string
    {
        $contentType = $request->headers->get('Content-Type');
        if (! is_string($contentType) || trim($contentType) === '') {
            return null;
        }

        return Str::limit(strtolower(trim(explode(';', $contentType, 2)[0])), 255, '');
    }

    protected function contentLength(Request $request): ?int
    {
        $value = $request->headers->get('Content-Length');

        if (! is_string($value)) {
            return null;
        }

        $value = trim((string) $value);

        return preg_match('/\A\d+\z/D', $value) === 1 ? (int) $value : null;
    }

    protected function authenticatedUserHash(Request $request): ?string
    {
        if (! config('crowdsec-scenarios.event_context.hash_authenticated_user', true)) {
            return null;
        }

        try {
            $user = $request->user();
            if (! is_object($user) || ! method_exists($user, 'getAuthIdentifier')) {
                return null;
            }

            $identifier = $user->getAuthIdentifier();
            if ($identifier === null || $identifier === '') {
                return null;
            }

            $key = config('crowdsec-scenarios.event_context.user_hash_key') ?: config('app.key');
            if (! is_string($key) || $key === '') {
                return null;
            }

            return hash_hmac('sha256', $user::class.'|'.(string) $identifier, $key);
        } catch (\Throwable) {
            return null;
        }
    }

    protected function geoContext(Request $request): array
    {
        $empty = ['country_code' => null, 'asn' => null, 'isp' => null];

        if (! config('crowdsec-scenarios.geoip.enabled', false)) {
            return $empty;
        }

        try {
            $geo = $this->geoIp->lookup($request->ip() ?? '');
            $countryCode = strtoupper((string) ($geo['country_code'] ?? ''));

            return [
                'country_code' => preg_match('/\A[A-Z]{2}\z/D', $countryCode) === 1 ? $countryCode : null,
                'asn' => $this->normalizeAsn($geo['asn'] ?? null),
                'isp' => $this->nullableString($geo['isp'] ?? null),
            ];
        } catch (\Throwable) {
            return $empty;
        }
    }

    protected function clientContext(Request $request): array
    {
        $empty = ['browser' => null, 'os' => null, 'device_type' => null];

        if (! config('crowdsec-scenarios.event_context.parse_user_agent', true)) {
            return $empty;
        }

        $userAgent = trim((string) $request->userAgent());
        if ($userAgent === '') {
            return $empty;
        }

        try {
            $detector = new DeviceDetector($userAgent);
            $detector->parse();

            if ($detector->isBot()) {
                $bot = $detector->getBot();

                return [
                    'browser' => $this->formatNameVersion($bot['name'] ?? 'Bot', null),
                    'os' => null,
                    'device_type' => 'bot',
                ];
            }

            $client = $detector->getClient();
            $os = $detector->getOs();

            return [
                'browser' => is_array($client)
                    ? $this->formatNameVersion($client['name'] ?? null, $client['version'] ?? null)
                    : null,
                'os' => is_array($os)
                    ? $this->formatNameVersion($os['name'] ?? null, $os['version'] ?? null)
                    : null,
                'device_type' => $this->nullableString($detector->getDeviceName(), 64),
            ];
        } catch (\Throwable) {
            return $empty;
        }
    }

    protected function formatNameVersion(mixed $name, mixed $version): ?string
    {
        $name = trim((string) $name);
        $version = trim((string) $version);

        return $this->nullableString(trim($name.' '.$version));
    }

    protected function nullableString(mixed $value, int $limit = 255): ?string
    {
        if (! is_scalar($value)) {
            return null;
        }

        $value = trim((string) $value);

        return $value !== '' ? Str::limit($value, $limit, '') : null;
    }

    protected function normalizeAsn(mixed $asn): ?int
    {
        if (is_int($asn) && $asn >= 0) {
            return $asn;
        }

        if (is_string($asn) && preg_match('/(?:\A|\b)AS?(\d+)\b/i', trim($asn), $matches) === 1) {
            return (int) $matches[1];
        }

        return is_numeric($asn) && (int) $asn >= 0 ? (int) $asn : null;
    }

    protected function redactArray(array $data): array
    {
        foreach ($data as $key => $value) {
            if ($this->isSensitiveKey((string) $key)) {
                $data[$key] = '[REDACTED]';
            } elseif (is_array($value)) {
                $data[$key] = $this->redactArray($value);
            }
        }

        return $data;
    }

    protected function isSensitiveSource(string $source): bool
    {
        if (str_starts_with($source, 'cookie_') || str_contains($source, 'authorization')) {
            return true;
        }

        foreach ($this->sensitiveKeys() as $key) {
            if (preg_match('/(?:\A|_)'.preg_quote($key, '/').'(?:\z|_)/', $source) === 1) {
                return true;
            }
        }

        return false;
    }

    protected function isSensitiveKey(string $key): bool
    {
        $key = strtolower(str_replace(['-', '.'], '_', trim($key)));

        return in_array($key, $this->sensitiveKeys(), true);
    }

    protected function sensitiveKeys(): array
    {
        return array_values(array_unique(array_map(
            fn ($key) => strtolower(str_replace(['-', '.'], '_', trim((string) $key))),
            config('crowdsec-scenarios.event_context.redact_query_parameters', self::DEFAULT_SENSITIVE_KEYS)
        )));
    }
}

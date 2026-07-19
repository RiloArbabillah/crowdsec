<?php

namespace RiloArbabillah\LaravelCrowdSec\Services;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;

class GeoIpService
{
    /**
     * Lookup geo information for an IP address.
     * Uses ip-api.com (free, no key required) as default provider.
     *
     * @return array{country: ?string, country_code: ?string, region: ?string, city: ?string, lat: ?float, lon: ?float, asn: ?int, isp: ?string}
     */
    public function lookup(string $ip): array
    {
        // Skip private/reserved IPs
        if ($this->isPrivateIp($ip)) {
            return $this->emptyResult();
        }

        $cacheTtl = config('crowdsec-scenarios.geoip.cache_ttl', 86400); // 24 hours
        $provider = strtolower((string) config('crowdsec-scenarios.geoip.provider', 'ipwhois'));
        $providerKey = preg_replace('/[^a-z0-9_-]/', '_', $provider) ?: 'unknown';
        $cacheKey = "crowdsec:geoip:{$providerKey}:{$ip}";

        return Cache::remember($cacheKey, $cacheTtl, function () use ($ip) {
            return $this->fetchFromProvider($ip);
        });
    }

    /**
     * Fetch GeoIP data from configured provider.
     *
     * @return array{country: ?string, country_code: ?string, region: ?string, city: ?string, lat: ?float, lon: ?float, asn: ?int, isp: ?string}
     */
    protected function fetchFromProvider(string $ip): array
    {
        $provider = strtolower((string) config('crowdsec-scenarios.geoip.provider', 'ipwhois'));

        try {
            return match ($provider) {
                'ipwhois' => $this->fetchFromIpWhoIs($ip),
                'ip-api' => $this->fetchFromIpApi($ip),
                'custom' => $this->fetchFromCustom($ip),
                default => throw new \InvalidArgumentException("Unsupported GeoIP provider: {$provider}"),
            };
        } catch (\Throwable $e) {
            Log::warning("CrowdSec GeoIP lookup failed for {$ip}: {$e->getMessage()}");

            return $this->emptyResult();
        }
    }

    /**
     * Fetch GeoIP data over HTTPS from ipwho.is.
     *
     * @return array{country: ?string, country_code: ?string, region: ?string, city: ?string, lat: ?float, lon: ?float, asn: ?int, isp: ?string}
     */
    protected function fetchFromIpWhoIs(string $ip): array
    {
        $response = Http::timeout((int) config('crowdsec-scenarios.geoip.timeout', 2))
            ->get("https://ipwho.is/{$ip}");

        if ($response->failed() || $response->json('success') === false) {
            return $this->emptyResult();
        }

        $data = $response->json();

        return $this->normalizeResult([
            'country' => $data['country'] ?? null,
            'country_code' => $data['country_code'] ?? null,
            'region' => $data['region'] ?? null,
            'city' => $data['city'] ?? null,
            'lat' => $data['latitude'] ?? null,
            'lon' => $data['longitude'] ?? null,
            'asn' => $data['connection']['asn'] ?? null,
            'isp' => $data['connection']['isp'] ?? null,
        ]);
    }

    /**
     * ip-api.com provider (free, 45 req/min).
     *
     * @return array{country: ?string, country_code: ?string, region: ?string, city: ?string, lat: ?float, lon: ?float, asn: ?int, isp: ?string}
     */
    protected function fetchFromIpApi(string $ip): array
    {
        $response = Http::timeout((int) config('crowdsec-scenarios.geoip.timeout', 2))
            ->get("http://ip-api.com/json/{$ip}", [
                'fields' => 'status,country,countryCode,regionName,city,lat,lon,as,isp',
            ]);

        if ($response->failed() || $response->json('status') !== 'success') {
            return $this->emptyResult();
        }

        $data = $response->json();

        return $this->normalizeResult([
            'country' => $data['country'] ?? null,
            'country_code' => $data['countryCode'] ?? null,
            'region' => $data['regionName'] ?? null,
            'city' => $data['city'] ?? null,
            'lat' => $data['lat'] ?? null,
            'lon' => $data['lon'] ?? null,
            'asn' => $this->parseAsn($data['as'] ?? null),
            'isp' => $data['isp'] ?? null,
        ]);
    }

    /**
     * Custom callback provider.
     * Configure with: config('crowdsec-scenarios.geoip.custom_callback')
     *
     * @return array{country: ?string, country_code: ?string, region: ?string, city: ?string, lat: ?float, lon: ?float, asn: ?int, isp: ?string}
     */
    protected function fetchFromCustom(string $ip): array
    {
        $callback = config('crowdsec-scenarios.geoip.custom_callback');

        if (is_callable($callback)) {
            $result = $callback($ip);

            return is_array($result) ? $this->normalizeResult($result) : $this->emptyResult();
        }

        return $this->emptyResult();
    }

    protected function isPrivateIp(string $ip): bool
    {
        return ! filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE);
    }

    /** @return array{country: null, country_code: null, region: null, city: null, lat: null, lon: null, asn: null, isp: null} */
    protected function emptyResult(): array
    {
        return [
            'country' => null,
            'country_code' => null,
            'region' => null,
            'city' => null,
            'lat' => null,
            'lon' => null,
            'asn' => null,
            'isp' => null,
        ];
    }

    protected function parseAsn(mixed $value): ?int
    {
        if (is_int($value) && $value >= 0) {
            return $value;
        }

        if (is_string($value) && preg_match('/\AAS(\d+)\b/i', trim($value), $matches) === 1) {
            return (int) $matches[1];
        }

        return is_numeric($value) && (int) $value >= 0 ? (int) $value : null;
    }

    /**
     * @param array<string, mixed> $result
     * @return array{country: ?string, country_code: ?string, region: ?string, city: ?string, lat: ?float, lon: ?float, asn: ?int, isp: ?string}
     */
    protected function normalizeResult(array $result): array
    {
        return [
            'country' => isset($result['country']) ? (string) $result['country'] : null,
            'country_code' => isset($result['country_code']) ? (string) $result['country_code'] : null,
            'region' => isset($result['region']) ? (string) $result['region'] : null,
            'city' => isset($result['city']) ? (string) $result['city'] : null,
            'lat' => is_numeric($result['lat'] ?? null) ? (float) $result['lat'] : null,
            'lon' => is_numeric($result['lon'] ?? null) ? (float) $result['lon'] : null,
            'asn' => $this->parseAsn($result['asn'] ?? null),
            'isp' => isset($result['isp']) ? (string) $result['isp'] : null,
        ];
    }
}

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
     * @return array{country: ?string, country_code: ?string, region: ?string, city: ?string, lat: ?float, lon: ?float, isp: ?string}
     */
    public function lookup(string $ip): array
    {
        // Skip private/reserved IPs
        if ($this->isPrivateIp($ip)) {
            return $this->emptyResult();
        }

        $cacheTtl = config('crowdsec-scenarios.geoip.cache_ttl', 86400); // 24 hours
        $cacheKey = "crowdsec:geoip:{$ip}";

        return Cache::remember($cacheKey, $cacheTtl, function () use ($ip) {
            return $this->fetchFromProvider($ip);
        });
    }

    /**
     * Fetch GeoIP data from configured provider.
     */
    protected function fetchFromProvider(string $ip): array
    {
        $provider = config('crowdsec-scenarios.geoip.provider', 'ip-api');

        try {
            return match ($provider) {
                'ip-api' => $this->fetchFromIpApi($ip),
                'custom' => $this->fetchFromCustom($ip),
                default => $this->fetchFromIpApi($ip),
            };
        } catch (\Throwable $e) {
            Log::warning("CrowdSec GeoIP lookup failed for {$ip}: {$e->getMessage()}");

            return $this->emptyResult();
        }
    }

    /**
     * ip-api.com provider (free, 45 req/min).
     */
    protected function fetchFromIpApi(string $ip): array
    {
        $response = Http::timeout(5)
            ->get("http://ip-api.com/json/{$ip}", [
                'fields' => 'status,country,countryCode,regionName,city,lat,lon,isp',
            ]);

        if ($response->failed() || $response->json('status') !== 'success') {
            return $this->emptyResult();
        }

        $data = $response->json();

        return [
            'country' => $data['country'] ?? null,
            'country_code' => $data['countryCode'] ?? null,
            'region' => $data['regionName'] ?? null,
            'city' => $data['city'] ?? null,
            'lat' => $data['lat'] ?? null,
            'lon' => $data['lon'] ?? null,
            'isp' => $data['isp'] ?? null,
        ];
    }

    /**
     * Custom callback provider.
     * Configure with: config('crowdsec-scenarios.geoip.custom_callback')
     */
    protected function fetchFromCustom(string $ip): array
    {
        $callback = config('crowdsec-scenarios.geoip.custom_callback');

        if (is_callable($callback)) {
            return $callback($ip);
        }

        return $this->emptyResult();
    }

    protected function isPrivateIp(string $ip): bool
    {
        return ! filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE);
    }

    protected function emptyResult(): array
    {
        return [
            'country' => null,
            'country_code' => null,
            'region' => null,
            'city' => null,
            'lat' => null,
            'lon' => null,
            'isp' => null,
        ];
    }
}

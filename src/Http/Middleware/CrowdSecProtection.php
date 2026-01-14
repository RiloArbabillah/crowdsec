<?php

namespace RiloArbabillah\LaravelCrowdSec\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Symfony\Component\HttpFoundation\Response;
use RiloArbabillah\LaravelCrowdSec\Services\CrowdSecService;

class CrowdSecProtection
{
    protected CrowdSecService $service;

    public function __construct(CrowdSecService $service)
    {
        $this->service = $service;
    }

    /**
     * Handle an incoming request.
     */
    public function handle(Request $request, Closure $next): Response
    {
        $ip = $request->ip() ?? 'unknown';

        // 1. Skip for whitelisted IPs first (performance)
        if ($this->isWhitelisted($ip)) {
            return $next($request);
        }

        // 2. Check if IP is already blocked
        if ($this->service->isBlocked($ip)) {
            return $this->blockedResponse($ip, 'IP is blocked');
        }

        // 3. Run WAF pattern detection
        $threats = $this->service->analyzeRequest($request);

        if (! empty($threats)) {
            // Separate blocking threats (critical + high + medium) from low
            $blockingThreats = $this->service->getBlockingThreats($threats);
            $nonBlockingThreats = array_filter($threats, fn ($t) => ! in_array(($t['severity'] ?? 'medium'), ['critical', 'high', 'medium']));

            // Log all threats
            $this->service->logEvent($ip, $threats, $request);

            // Block if critical or high severity threats exist
            if (! empty($blockingThreats)) {
                $reason = collect($blockingThreats)->pluck('type')->implode(', ');
                $this->service->blockIp($ip, "Threat: {$reason}", null, $blockingThreats[0]['type'] ?? 'security_threat');

                return $this->blockedResponse($ip, 'Malicious pattern detected');
            }

            // For low: log warning
            if (! empty($nonBlockingThreats)) {
                Log::warning('CrowdSec: Low severity threat detected', [
                    'ip' => $ip,
                    'threats' => $nonBlockingThreats,
                ]);
            }

            // Continue processing
            return $next($request);
        }

        // 4. Track behavior
        $this->service->trackBehavior($ip, $request->path());

        // 5. Check behavior thresholds
        if ($this->service->exceedsBehaviorThreshold($ip)) {
            $this->service->blockIp($ip, 'Suspicious behavior detected', 240, 'behavior_threshold');

            return $this->blockedResponse($ip, 'Rate limit exceeded');
        }

        return $next($request);
    }

    /**
     * Check if IP is whitelisted
     */
    protected function isWhitelisted(string $ip): bool
    {
        $whitelist = config('crowdsec-scenarios.whitelist_ips', []);

        if (empty($whitelist)) {
            return false;
        }

        return in_array($ip, $whitelist);
    }

    /**
     * Generate blocked response
     */
    protected function blockedResponse(string $ip, string $reason): Response
    {
        // Log the blocked attempt
        Log::warning('CrowdSec: Blocked request', [
            'ip' => $ip,
            'reason' => $reason,
            'user_agent' => request()->userAgent(),
            'path' => request()->path(),
        ]);

        // Return 403 Forbidden
        return response('Forbidden - Your IP has been blocked due to suspicious activity', 403);
    }
}

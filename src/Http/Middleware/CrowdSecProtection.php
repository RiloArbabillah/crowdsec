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
        // Check if package is enabled
        if (! $this->service->isEnabled()) {
            return $next($request);
        }

        // Wrap everything in try-catch so WAF errors never crash the application
        try {
            return $this->processRequest($request, $next);
        } catch (\Throwable $e) {
            Log::error('CrowdSec: Middleware error — request allowed through', [
                'error' => $e->getMessage(),
                'ip' => $request->ip(),
                'path' => $request->path(),
            ]);

            // Fail open: allow request through if WAF encounters an error
            return $next($request);
        }
    }

    /**
     * Process the request through all security checks.
     */
    protected function processRequest(Request $request, Closure $next): Response
    {
        $ip = $request->ip() ?? 'unknown';

        // 1. Skip for whitelisted IPs first (performance)
        if ($this->isWhitelisted($ip)) {
            return $next($request);
        }

        // 2. Check if IP is already blocked
        if ($this->service->isBlocked($ip)) {
            return $this->blockedResponse($request, 'IP is blocked');
        }

        // 3. Check if this is a login request
        if ($this->isLoginRequest($request)) {
            // For login requests: track attempt and check login threshold
            $this->service->trackLoginAttempt($ip);

            if ($this->service->exceedsLoginThreshold($ip)) {
                $this->service->blockIp($ip, 'Too many login attempts', 15, 'login_threshold');

                return $this->blockedResponse($request, 'Too many login attempts');
            }

            // Allow login request through (skip WAF patterns for passwords)
            return $next($request);
        }

        // 4. For non-login requests: run WAF pattern detection
        $threats = $this->service->analyzeRequest($request);

        if (! empty($threats)) {
            // Log the event (single place — no more duplicate logging)
            $this->service->logEvent($ip, $threats, $request);

            // Separate blocking threats (critical + high + medium) from low
            $blockingThreats = $this->service->getBlockingThreats($threats);

            // Block if blocking-level threats exist
            if (! empty($blockingThreats)) {
                $reason = collect($blockingThreats)->pluck('type')->unique()->implode(', ');
                $firstType = $blockingThreats[array_key_first($blockingThreats)]['type'] ?? 'security_threat';
                $this->service->blockIp($ip, "Threat: {$reason}", null, $firstType);

                return $this->blockedResponse($request, 'Malicious pattern detected');
            }

            // For low severity: already logged above, continue processing
        }

        // 5. Track behavior
        $this->service->trackBehavior($ip, $request->path());

        // 6. Check behavior thresholds
        if ($this->service->exceedsBehaviorThreshold($ip)) {
            $this->service->blockIp($ip, 'Suspicious behavior detected', 240, 'behavior_threshold');

            return $this->blockedResponse($request, 'Rate limit exceeded');
        }

        // 7. Process the request and track 404 responses
        $response = $next($request);

        if ($response->getStatusCode() === 404) {
            $this->service->track404($ip);
        }

        return $response;
    }

    /**
     * Check if IP is whitelisted (supports exact match and CIDR notation)
     */
    protected function isWhitelisted(string $ip): bool
    {
        $whitelist = config('crowdsec-scenarios.whitelist_ips', []);

        if (empty($whitelist)) {
            return false;
        }

        foreach ($whitelist as $entry) {
            // Exact match
            if ($ip === $entry) {
                return true;
            }

            // CIDR match (e.g., 10.0.0.0/8, 192.168.0.0/16)
            if (str_contains($entry, '/') && $this->ipInCidr($ip, $entry)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if an IP address falls within a CIDR range.
     * Supports both IPv4 and IPv6.
     */
    protected function ipInCidr(string $ip, string $cidr): bool
    {
        [$subnet, $bits] = explode('/', $cidr, 2);
        $bits = (int) $bits;

        $ipBin = @inet_pton($ip);
        $subnetBin = @inet_pton($subnet);

        if ($ipBin === false || $subnetBin === false) {
            return false;
        }

        // Both must be same IP version (same byte length)
        if (strlen($ipBin) !== strlen($subnetBin)) {
            return false;
        }

        // Create mask and compare
        $mask = str_repeat("\xff", (int) ($bits / 8));
        if ($bits % 8 > 0) {
            $mask .= chr(256 - (1 << (8 - ($bits % 8))));
        }
        $mask = str_pad($mask, strlen($ipBin), "\x00");

        return ($ipBin & $mask) === ($subnetBin & $mask);
    }

    /**
     * Check if the request is a login attempt
     */
    protected function isLoginRequest(Request $request): bool
    {
        if ($request->method() !== 'POST') {
            return false;
        }

        $loginRoutes = config('crowdsec-scenarios.login_routes', ['login']);
        $path = $request->path();

        foreach ($loginRoutes as $route) {
            if ($path === $route || fnmatch($route, $path)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Generate blocked response
     */
    protected function blockedResponse(Request $request, string $reason): Response
    {
        $ip = $request->ip() ?? 'unknown';

        $message = config(
            'crowdsec-scenarios.blocked_response_message',
            'Forbidden - Your IP has been blocked due to suspicious activity'
        );

        // Return 403 Forbidden
        return response($message, 403);
    }
}

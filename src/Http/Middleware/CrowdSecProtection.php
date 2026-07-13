<?php

namespace RiloArbabillah\LaravelCrowdSec\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Symfony\Component\HttpFoundation\Response;
use RiloArbabillah\LaravelCrowdSec\Events\BehaviorThresholdExceeded;
use RiloArbabillah\LaravelCrowdSec\Events\ThreatDetected;
use RiloArbabillah\LaravelCrowdSec\Models\BlockedIp;
use RiloArbabillah\LaravelCrowdSec\Models\SecurityEvent;
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

        $startedAtNanoseconds = hrtime(true);
        $downstreamInvoked = false;
        $downstreamResponse = null;
        $guardedNext = function (Request $request) use ($next, &$downstreamInvoked, &$downstreamResponse): Response {
            $downstreamInvoked = true;
            $downstreamResponse = $next($request);

            return $downstreamResponse;
        };

        // Wrap WAF operations so package errors fail open without invoking the app twice.
        try {
            return $this->processRequest($request, $guardedNext, $startedAtNanoseconds);
        } catch (\Throwable $e) {
            if ($downstreamInvoked && ! $downstreamResponse instanceof Response) {
                // Exceptions from the application are not CrowdSec failures.
                throw $e;
            }

            Log::error('CrowdSec: Middleware error — request allowed through', [
                'error' => $e->getMessage(),
                'ip' => $request->ip(),
                'path' => $request->path(),
            ]);

            if ($downstreamInvoked) {
                if ($downstreamResponse instanceof Response) {
                    return $downstreamResponse;
                }
            }

            // Fail open only when CrowdSec failed before invoking the application.
            return $next($request);
        }
    }

    /**
     * Process the request through all security checks.
     */
    protected function processRequest(Request $request, Closure $next, int $startedAtNanoseconds): Response
    {
        $ip = $request->ip() ?? 'unknown';
        $securityEvent = null;

        // 1. Skip for whitelisted IPs (performance)
        if ($this->isWhitelisted($ip)) {
            return $next($request);
        }

        // 2. Check if IP is already blocked
        if ($this->service->isBlocked($ip)) {
            return $this->blockedResponse($request, 'IP is blocked');
        }

        // 3. Block suspicious HTTP methods (TRACE, CONNECT, etc.)
        if ($this->service->isBlockedMethod($request)) {
            $this->service->blockIp($ip, 'Blocked HTTP method: ' . $request->method(), 720, 'blocked_method');

            return $this->blockedResponse($request, 'HTTP method not allowed');
        }

        // 4. Check for empty User-Agent (bot indicator)
        if ($this->service->hasEmptyUserAgent($request)) {
            $behavior = \RiloArbabillah\LaravelCrowdSec\Models\IpBehavior::getOrCreate($ip);
            $behavior->addThreatScore(15);

            // Don't block immediately, just score — repeated offenses will trigger threshold
        }

        // 5. Check for oversized request body
        if ($this->service->isOversizedRequest($request)) {
            return $this->blockedResponse($request, 'Request body too large');
        }

        // 6. Check if this is a login request
        if ($this->isLoginRequest($request)) {
            $this->service->trackLoginAttempt($ip);

            if ($this->service->exceedsLoginThreshold($ip)) {
                $this->service->blockIp($ip, 'Too many login attempts', 15, 'login_threshold');

                return $this->blockedResponse($request, 'Too many login attempts');
            }

            // Allow login request through (skip WAF patterns for passwords)
            return $next($request);
        }

        // 7. Run WAF pattern detection
        $threats = $this->service->analyzeRequest($request);

        if (! empty($threats)) {
            // Persist detection first. Response and final decision are filled in later.
            $securityEvent = $this->logEventSafely($ip, $threats, $request);

            // Dispatch ThreatDetected event
            $severity = $this->service->getMaxSeverity(array_column($threats, 'severity'));
            ThreatDetected::dispatch($ip, $threats, $severity, $request->path(), $request->method(), $request);

            // Add cumulative threat score from detected patterns
            $this->service->addThreatScoreFromThreats($ip, $threats);

            // Separate blocking threats from low severity
            $blockingThreats = $this->service->getBlockingThreats($threats);

            // Block if blocking-level threats exist
            if (! empty($blockingThreats)) {
                $reason = collect($blockingThreats)->pluck('type')->unique()->implode(', ');
                $firstType = $blockingThreats[array_key_first($blockingThreats)]['type'] ?? 'security_threat';
                $blockedIp = $this->service->blockIp($ip, "Threat: {$reason}", null, $firstType);
                $response = $this->blockedResponse($request, 'Malicious pattern detected');
                $this->finalizeEventSafely(
                    $securityEvent,
                    $response,
                    $startedAtNanoseconds,
                    'blocked',
                    $blockedIp
                );

                return $response;
            }

            // Low severity: logged + scored above, continue processing
        }

        // 8. Track behavior
        $this->service->trackBehavior($ip, $request->path());

        // 9. Check behavior thresholds (including cumulative threat score)
        if ($this->service->exceedsBehaviorThreshold($ip)) {
            // Dispatch BehaviorThresholdExceeded event
            $behavior = \RiloArbabillah\LaravelCrowdSec\Models\IpBehavior::where('ip', $ip)->first();
            if ($behavior) {
                BehaviorThresholdExceeded::dispatch(
                    $ip,
                    (float) $behavior->threat_score,
                    $behavior->request_count,
                    $behavior->error_404_count,
                    $behavior->login_attempts
                );
            }

            $blockedIp = $this->service->blockIp($ip, 'Suspicious behavior detected', 240, 'behavior_threshold');
            $response = $this->blockedResponse($request, 'Rate limit exceeded');
            $this->finalizeEventSafely(
                $securityEvent,
                $response,
                $startedAtNanoseconds,
                'blocked',
                $blockedIp
            );

            return $response;
        }

        // 10. Process the request and track 404 responses
        $response = $next($request);

        $this->finalizeEventSafely(
            $securityEvent,
            $response,
            $startedAtNanoseconds,
            'allowed_scored'
        );

        if ($response->getStatusCode() === 404) {
            $this->service->track404($ip);
        }

        return $response;
    }

    protected function logEventSafely(string $ip, array $threats, Request $request): ?SecurityEvent
    {
        try {
            return $this->service->logEvent($ip, $threats, $request);
        } catch (\Throwable $e) {
            Log::error('CrowdSec: Failed to persist security event', [
                'error' => $e->getMessage(),
                'ip' => $ip,
                'path' => $request->path(),
            ]);

            return null;
        }
    }

    protected function finalizeEventSafely(
        ?SecurityEvent $event,
        Response $response,
        int $startedAtNanoseconds,
        string $actionTaken,
        ?BlockedIp $blockedIp = null
    ): void
    {
        if ($event === null) {
            return;
        }

        try {
            $this->service->finalizeEvent(
                $event,
                $response,
                $startedAtNanoseconds,
                $actionTaken,
                $blockedIp
            );
        } catch (\Throwable $e) {
            Log::error('CrowdSec: Failed to finalize security event context', [
                'error' => $e->getMessage(),
                'event_id' => $event->getKey(),
            ]);
        }
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
     * Check if an IP address falls within a CIDR range (IPv4/IPv6)
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

        if (strlen($ipBin) !== strlen($subnetBin)) {
            return false;
        }

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
        $message = config(
            'crowdsec-scenarios.blocked_response_message',
            'Forbidden - Your IP has been blocked due to suspicious activity'
        );

        return response($message, 403);
    }
}

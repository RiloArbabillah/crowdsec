<?php

namespace RiloArbabillah\LaravelCrowdSec\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;
use Symfony\Component\HttpFoundation\Response;
use RiloArbabillah\LaravelCrowdSec\Events\BehaviorThresholdExceeded;
use RiloArbabillah\LaravelCrowdSec\Events\CrowdSecMiddlewareFailed;
use RiloArbabillah\LaravelCrowdSec\Events\ThreatDetected;
use RiloArbabillah\LaravelCrowdSec\Models\BlockedIp;
use RiloArbabillah\LaravelCrowdSec\Models\SecurityEvent;
use RiloArbabillah\LaravelCrowdSec\Services\CrowdSecService;
use RiloArbabillah\LaravelCrowdSec\Services\WafPolicy;

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

            $this->reportFailOpen($request, $e, [
                'stage' => $downstreamInvoked ? 'post_downstream' : 'pre_downstream',
                'downstream_invoked' => $downstreamInvoked,
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
        if ($this->service->isWhitelisted($ip)) {
            return $next($request);
        }

        // 2. Check if IP is already blocked
        if ($this->service->isBlocked($ip)) {
            return $this->blockedResponse($request, 'IP is blocked');
        }

        // 3. Block suspicious HTTP methods (TRACE, CONNECT, etc.)
        if ($this->service->isBlockedMethod($request)) {
            $blockedIp = $this->service->blockIp($ip, 'Blocked HTTP method: ' . $request->method(), 720, 'blocked_method');

            return $this->blockedResponse($request, 'HTTP method not allowed', $blockedIp);
        }

        // 4. Check for empty User-Agent (bot indicator). Don't block, just
        //    score (in step 8's lock) — repeated offenses trigger the threshold.
        $emptyUserAgentScore = $this->service->hasEmptyUserAgent($request) ? 15.0 : 0.0;

        // 5. Check for oversized request body
        if ($this->service->isOversizedRequest($request)) {
            return $this->blockedResponse($request, 'Request body too large');
        }

        // 6. Detect login attempts. The counter itself is written later, in the
        //    same single lock acquisition as the request/threat-score updates.
        $isLoginRequest = $this->isLoginRequest($request);
        if ($isLoginRequest) {
            if ($this->service->exceedsLoginThreshold($ip)) {
                $blockedIp = $this->service->blockIp($ip, 'Too many login attempts', 15, 'login_threshold');

                return $this->blockedResponse($request, 'Too many login attempts', $blockedIp);
            }
        }

        // 7. Run WAF pattern detection
        $excludedBodyFields = $isLoginRequest
            ? array_map(
                fn ($field) => strtolower((string) $field),
                config('crowdsec-scenarios.behavior.login_ignored_fields', [
                    'password',
                    'password_confirmation',
                    'current_password',
                ]),
            )
            : [];
        $threats = $this->service->analyzeRequest($request, $excludedBodyFields);

        if (! empty($threats)) {
            // Persist detection first. Response and final decision are filled in later.
            $securityEvent = $this->logEventSafely($ip, $threats, $request);

            // Dispatch ThreatDetected event
            $severity = $this->service->getMaxSeverity(array_column($threats, 'severity'));
            ThreatDetected::dispatch($ip, $threats, $severity, $request->path(), $request->method(), $request);

            $hasEnforcedThreats = collect($threats)->contains(
                fn ($threat) => ($threat['mode'] ?? WafPolicy::MODE_ENFORCE) === WafPolicy::MODE_ENFORCE,
            );

            // Separate blocking threats from low severity
            $blockingThreats = $this->service->getBlockingThreats($threats);

            // Block if blocking-level threats exist
            if (! empty($blockingThreats)) {
                $reason = collect($blockingThreats)->pluck('type')->unique()->implode(', ');
                $firstType = $blockingThreats[array_key_first($blockingThreats)]['type'] ?? 'security_threat';
                $blockedIp = $this->service->blockIp(
                    $ip,
                    "Threat: {$reason}",
                    $this->service->blockDurationForThreats($blockingThreats),
                    $firstType,
                );
                $response = $this->blockedResponse($request, 'Malicious pattern detected', $blockedIp);
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

        // 8. Track behavior in a single lock acquisition: request count, the
        //    login attempt counter for login routes, and the cumulative threat
        //    score are all persisted together. `$loginAddsThreatScore=false`
        //    preserves the provisional-login semantics: the login counter is
        //    reset by Laravel's Login event, and only manually tracked
        //    failed logins add score. Authenticated users can be excluded from
        //    the request count (Filament/Livewire polling).
        $countRequest = ! (
            config('crowdsec-scenarios.behavior.skip_authenticated_request_count', true)
            && $this->isAuthenticated($request)
        );
        $behavior = null;
        if ($countRequest || $isLoginRequest || ! empty($threats) || $emptyUserAgentScore > 0) {
            $behavior = $this->service->trackRequest(
                $ip,
                $isLoginRequest,
                false,
                $threats,
                [],
                $countRequest,
                $emptyUserAgentScore,
            );
        }

        // 9. Check behavior thresholds (including cumulative threat score)
        if ($this->service->exceedsBehaviorThreshold($ip, $behavior)) {
            // Dispatch BehaviorThresholdExceeded event
            $behavior ??= \RiloArbabillah\LaravelCrowdSec\Models\IpBehavior::where('ip', $ip)->first();
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
            $response = $this->blockedResponse($request, 'Rate limit exceeded', $blockedIp);
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
            isset($hasEnforcedThreats) && ! $hasEnforcedThreats ? 'monitored' : 'allowed_scored'
        );

        if ($response->getStatusCode() === 404) {
            $this->service->track404($ip);
        }

        return $response;
    }

    /**
     * Record a fail-open occurrence: a counter metric (so it is visible in
     * monitoring, not just logs), a structured log entry, and a
     * CrowdSecMiddlewareFailed event so applications can hook alerting.
     *
     * @param  array<string, mixed>  $context
     */
    protected function reportFailOpen(Request $request, \Throwable $e, array $context = []): void
    {
        $ip = $request->ip() ?? 'unknown';
        $path = $request->path();

        try {
            Cache::increment('crowdsec:middleware_failed');
        } catch (\Throwable) {
            // Metrics must never make fail-open worse.
        }

        $context = array_merge([
            'error' => $e->getMessage(),
            'error_class' => $e::class,
            'ip' => $ip,
            'path' => $path,
        ], $context);

        Log::error('CrowdSec: Middleware error — request allowed through (fail-open)', $context);

        try {
            CrowdSecMiddlewareFailed::dispatch($ip, $path, $e, $context);
        } catch (\Throwable) {
            // Listener failures must not interfere with fail-open handling.
        }
    }

    /** @param list<array<string, mixed>> $threats */
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
     * Check if the request is a login attempt
     */
    protected function isLoginRequest(Request $request): bool
    {
        return $this->service->isLoginRequest($request);
    }

    /**
     * Resolve the user defensively: a misconfigured guard must not turn every
     * request into a fail-open.
     */
    protected function isAuthenticated(Request $request): bool
    {
        try {
            return $request->user() !== null;
        } catch (\Throwable) {
            return false;
        }
    }

    /**
     * Generate blocked response
     */
    protected function blockedResponse(Request $request, string $reason, ?BlockedIp $blockedIp = null): Response
    {
        $message = config(
            'crowdsec-scenarios.blocked_response_message',
            'Forbidden - Your IP has been blocked due to suspicious activity'
        );
        $ip = $request->ip() ?? 'unknown';

        $headers = [];
        if ($blockedIp?->expires_at !== null) {
            $headers['Retry-After'] = (string) max(1, $blockedIp->expires_at->getTimestamp() - now()->getTimestamp());
        }

        // Livewire (Filament) and API clients get JSON.
        if ($request->expectsJson() || $request->hasHeader('X-Livewire')) {
            return response()->json(['message' => $message, 'ip' => $ip], 403, $headers);
        }

        // Include the resolved client IP so the block response identifies the
        // exact address that was denied.
        return response($message . ' IP: ' . $ip, 403, $headers);
    }
}

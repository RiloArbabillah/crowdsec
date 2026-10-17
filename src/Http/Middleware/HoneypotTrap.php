<?php

namespace RiloArbabillah\LaravelCrowdSec\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;
use Symfony\Component\HttpFoundation\Response;
use RiloArbabillah\LaravelCrowdSec\Events\CrowdSecMiddlewareFailed;
use RiloArbabillah\LaravelCrowdSec\Services\CrowdSecService;

class HoneypotTrap
{
    public function __construct(
        protected CrowdSecService $service,
    ) {}

    /**
     * Handle an incoming request.
     * Block any request that hits a honeypot route.
     */
    public function handle(Request $request, Closure $next): Response
    {
        $honeypotRoutes = config('crowdsec-scenarios.honeypot_routes', []);

        if (empty($honeypotRoutes)) {
            return $next($request);
        }

        $path = ltrim($request->path(), '/');

        foreach ($honeypotRoutes as $route) {
            $route = ltrim($route, '/');

            if ($path === $route || str_starts_with($path, $route . '/')) {
                $ip = $request->ip() ?? 'unknown';

                try {
                    $whitelisted = $this->service->isWhitelisted($ip);
                } catch (\Throwable $e) {
                    $this->reportFailOpen($ip, $path, $e);

                    return $next($request);
                }

                if ($whitelisted) {
                    return $next($request);
                }

                try {
                    // Block immediately — honeypot access is always malicious
                    $this->service->blockIp($ip, 'Honeypot trap triggered', null, 'honeypot_trap');

                    // Log the event
                    $this->service->logEvent($ip, [
                        [
                            'type' => 'honeypot_trap',
                            'severity' => 'critical',
                            'pattern' => $route,
                            'matched' => $path,
                        ],
                    ], $request);
                } catch (\Throwable $e) {
                    $this->reportFailOpen($ip, $path, $e);

                    return $next($request);
                }

                return new Response(
                    config('crowdsec-scenarios.blocked_response_message', 'Access denied'),
                    403
                );
            }
        }

        return $next($request);
    }

    /**
     * Same fail-open reporting as CrowdSecProtection: counter, log, event.
     */
    protected function reportFailOpen(string $ip, string $path, \Throwable $e): void
    {
        try {
            Cache::increment('crowdsec:middleware_failed');
        } catch (\Throwable) {
            // Metrics must never make fail-open worse.
        }

        $context = [
            'error' => $e->getMessage(),
            'error_class' => $e::class,
            'ip' => $ip,
            'path' => $path,
            'middleware' => 'honeypot',
        ];

        Log::error('CrowdSec: Honeypot error — request allowed through (fail-open)', $context);

        try {
            CrowdSecMiddlewareFailed::dispatch($ip, $path, $e, $context);
        } catch (\Throwable) {
            // Listener failures must not interfere with fail-open handling.
        }
    }
}

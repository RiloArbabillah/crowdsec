<?php

namespace RiloArbabillah\LaravelCrowdSec\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;
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

                return new Response(
                    config('crowdsec-scenarios.blocked_response_message', 'Access denied'),
                    403
                );
            }
        }

        return $next($request);
    }
}

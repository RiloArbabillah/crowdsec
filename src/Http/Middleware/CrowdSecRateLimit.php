<?php

namespace RiloArbabillah\LaravelCrowdSec\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Symfony\Component\HttpFoundation\Response;

class CrowdSecRateLimit
{
    /**
     * Handle an incoming request.
     *
     * Usage in routes:
     *   Route::middleware('crowdsec.rate:60,1')->group(...)
     *   // 60 requests per minute
     *
     * @param  string  $maxAttempts  Max requests allowed in the decay window
     * @param  string  $decayMinutes  Window in minutes (default: 1)
     */
    public function handle(Request $request, Closure $next, string $maxAttempts = '60', string $decayMinutes = '1'): Response
    {
        $max = (int) $maxAttempts;
        $decay = (int) $decayMinutes;
        $ip = $request->ip() ?? 'unknown';
        $routeKey = $this->resolveRouteKey($request);

        $cacheKey = "crowdsec:ratelimit:{$routeKey}:{$ip}";

        $hits = (int) Cache::get($cacheKey, 0);

        if ($hits >= $max) {
            $retryAfter = $decay * 60;

            return new Response(
                json_encode([
                    'message' => 'Too many requests',
                    'retry_after' => $retryAfter,
                ]),
                429,
                [
                    'Content-Type' => 'application/json',
                    'Retry-After' => $retryAfter,
                    'X-RateLimit-Limit' => $max,
                    'X-RateLimit-Remaining' => 0,
                ]
            );
        }

        Cache::put($cacheKey, $hits + 1, now()->addMinutes($decay));

        $response = $next($request);

        $response->headers->set('X-RateLimit-Limit', (string) $max);
        $response->headers->set('X-RateLimit-Remaining', (string) max(0, $max - $hits - 1));

        return $response;
    }

    /**
     * Resolve a unique key for the current route.
     */
    protected function resolveRouteKey(Request $request): string
    {
        $route = $request->route();

        if ($route && method_exists($route, 'getName') && $route->getName()) {
            return $route->getName();
        }

        return md5($request->method() . ':' . $request->path());
    }
}

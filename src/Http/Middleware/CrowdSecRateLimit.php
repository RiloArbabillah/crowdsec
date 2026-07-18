<?php

namespace RiloArbabillah\LaravelCrowdSec\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\RateLimiter;
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
        $max = max(1, (int) $maxAttempts);
        $decay = max(1, (int) $decayMinutes);
        $ip = $request->ip() ?? 'unknown';
        $routeKey = $this->resolveRouteKey($request);

        $cacheKey = "crowdsec:ratelimit:{$routeKey}:{$ip}";

        if (RateLimiter::tooManyAttempts($cacheKey, $max)) {
            $retryAfter = max(1, RateLimiter::availableIn($cacheKey));

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
                    'X-RateLimit-Reset' => now()->timestamp + $retryAfter,
                ]
            );
        }

        RateLimiter::hit($cacheKey, $decay * 60);
        $remaining = RateLimiter::remaining($cacheKey, $max);
        $resetAt = now()->timestamp + max(1, RateLimiter::availableIn($cacheKey));

        $response = $next($request);

        $response->headers->set('X-RateLimit-Limit', (string) $max);
        $response->headers->set('X-RateLimit-Remaining', (string) $remaining);
        $response->headers->set('X-RateLimit-Reset', (string) $resetAt);

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

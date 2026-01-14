<?php

namespace Simenawan\LaravelCrowdSec\Facades;

use Illuminate\Support\Facades\Facade;

/**
 * @method static bool isBlocked(string $ip)
 * @method static array analyzeRequest(\Illuminate\Http\Request $request)
 * @method static array checkWafPatterns(\Illuminate\Http\Request $request)
 * @method static \Simenawan\LaravelCrowdSec\Models\IpBehavior trackBehavior(string $ip, string $path)
 * @method static \Simenawan\LaravelCrowdSec\Models\IpBehavior trackLoginAttempt(string $ip)
 * @method static bool exceedsBehaviorThreshold(string $ip)
 * @method static bool exceedsLoginThreshold(string $ip)
 * @method static \Simenawan\LaravelCrowdSec\Models\BlockedIp blockIp(string $ip, string $reason, ?int $durationMinutes = null, ?string $eventType = null)
 * @method static bool unblockIp(string $ip)
 * @method static \Simenawan\LaravelCrowdSec\Models\SecurityEvent logEvent(string $ip, array $threats, \Illuminate\Http\Request $request)
 * @method static int cleanupExpiredBans()
 * @method static array getStats()
 * @method static array getBlockingThreats(array $threats)
 */
class CrowdSec extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return 'crowdsec';
    }
}

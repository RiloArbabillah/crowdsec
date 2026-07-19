<?php

namespace RiloArbabillah\LaravelCrowdSec\Facades;

use Illuminate\Support\Facades\Facade;

/**
 * @method static bool isEnabled()
 * @method static bool isBlocked(string $ip)
 * @method static list<array<string, mixed>> analyzeRequest(\Illuminate\Http\Request $request)
 * @method static list<array<string, mixed>> checkWafPatterns(\Illuminate\Http\Request $request)
 * @method static \RiloArbabillah\LaravelCrowdSec\Models\IpBehavior trackBehavior(string $ip, string $path)
 * @method static \RiloArbabillah\LaravelCrowdSec\Models\IpBehavior track404(string $ip)
 * @method static \RiloArbabillah\LaravelCrowdSec\Models\IpBehavior trackLoginAttempt(string $ip)
 * @method static void addThreatScoreFromThreats(string $ip, list<array<string, mixed>> $threats)
 * @method static bool exceedsBehaviorThreshold(string $ip)
 * @method static bool exceedsLoginThreshold(string $ip)
 * @method static bool isBlockedMethod(\Illuminate\Http\Request $request)
 * @method static bool hasEmptyUserAgent(\Illuminate\Http\Request $request)
 * @method static bool isOversizedRequest(\Illuminate\Http\Request $request)
 * @method static \RiloArbabillah\LaravelCrowdSec\Models\BlockedIp blockIp(string $ip, string $reason, ?int $durationMinutes = null, ?string $eventType = null)
 * @method static bool unblockIp(string $ip)
 * @method static \RiloArbabillah\LaravelCrowdSec\Models\SecurityEvent logEvent(string $ip, list<array<string, mixed>> $threats, \Illuminate\Http\Request $request, ?string $actionTaken = null)
 * @method static void finalizeEvent(\RiloArbabillah\LaravelCrowdSec\Models\SecurityEvent $event, \Symfony\Component\HttpFoundation\Response $response, int $startedAtNanoseconds, string $actionTaken, ?\RiloArbabillah\LaravelCrowdSec\Models\BlockedIp $blockedIp = null)
 * @method static int cleanupExpiredBans()
 * @method static array<string, mixed> getStats()
 * @method static list<array<string, mixed>> getBlockingThreats(list<array<string, mixed>> $threats)
 * @method static string getMaxSeverity(list<string> $severities)
 */
class CrowdSec extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return 'crowdsec';
    }
}

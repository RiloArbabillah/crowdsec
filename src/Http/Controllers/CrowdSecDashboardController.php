<?php

namespace RiloArbabillah\LaravelCrowdSec\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use RiloArbabillah\LaravelCrowdSec\Models\BlockedIp;
use RiloArbabillah\LaravelCrowdSec\Models\IpBehavior;
use RiloArbabillah\LaravelCrowdSec\Models\SecurityEvent;

class CrowdSecDashboardController extends Controller
{
    /**
     * Display the security dashboard.
     */
    public function index()
    {
        $stats = [
            'total_events' => SecurityEvent::count(),
            'events_today' => SecurityEvent::where('created_at', '>=', now()->startOfDay())->count(),
            'events_this_week' => SecurityEvent::where('created_at', '>=', now()->startOfWeek())->count(),
            'active_blocks' => BlockedIp::active()->count(),
            'total_ips_tracked' => IpBehavior::count(),
            'high_threat_ips' => IpBehavior::highThreat()->count(),
        ];

        $recentEvents = SecurityEvent::orderBy('created_at', 'desc')
            ->limit(20)
            ->get();

        $blockedIps = BlockedIp::active()
            ->orderBy('created_at', 'desc')
            ->limit(20)
            ->get();

        $topAttackers = SecurityEvent::selectRaw('ip, COUNT(*) as count')
            ->where('created_at', '>=', now()->subDay())
            ->groupBy('ip')
            ->orderByDesc('count')
            ->limit(10)
            ->get();

        $threatBreakdown = SecurityEvent::selectRaw('severity, COUNT(*) as count')
            ->where('created_at', '>=', now()->subWeek())
            ->groupBy('severity')
            ->get()
            ->pluck('count', 'severity')
            ->toArray();

        $topCountries = SecurityEvent::selectRaw('country_code, COUNT(*) as count')
            ->whereNotNull('country_code')
            ->where('created_at', '>=', now()->subWeek())
            ->groupBy('country_code')
            ->orderByDesc('count')
            ->limit(10)
            ->get();

        $deviceBreakdown = SecurityEvent::selectRaw('device_type, COUNT(*) as count')
            ->whereNotNull('device_type')
            ->where('created_at', '>=', now()->subWeek())
            ->groupBy('device_type')
            ->orderByDesc('count')
            ->get();

        return view()->make('crowdsec::dashboard', compact(
            'stats',
            'recentEvents',
            'blockedIps',
            'topAttackers',
            'threatBreakdown',
            'topCountries',
            'deviceBreakdown'
        ));
    }
}

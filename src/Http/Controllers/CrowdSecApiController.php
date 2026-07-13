<?php

namespace RiloArbabillah\LaravelCrowdSec\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use RiloArbabillah\LaravelCrowdSec\Models\BlockedIp;
use RiloArbabillah\LaravelCrowdSec\Models\IpBehavior;
use RiloArbabillah\LaravelCrowdSec\Models\SecurityEvent;
use RiloArbabillah\LaravelCrowdSec\Services\CrowdSecService;

class CrowdSecApiController extends Controller
{
    public function __construct(
        protected CrowdSecService $service,
    ) {}

    /**
     * GET /api/crowdsec/stats — Overview statistics
     */
    public function stats(): JsonResponse
    {
        return response()->json([
            'total_events' => SecurityEvent::count(),
            'events_today' => SecurityEvent::where('created_at', '>=', now()->startOfDay())->count(),
            'events_this_week' => SecurityEvent::where('created_at', '>=', now()->startOfWeek())->count(),
            'active_blocks' => BlockedIp::active()->count(),
            'total_ips_tracked' => IpBehavior::count(),
            'high_threat_ips' => IpBehavior::highThreat()->count(),
        ]);
    }

    /**
     * GET /api/crowdsec/events — List security events
     */
    public function events(Request $request): JsonResponse
    {
        $query = SecurityEvent::query()->orderBy('created_at', 'desc');

        if ($severity = $request->query('severity')) {
            $query->where('severity', $severity);
        }
        if ($ip = $request->query('ip')) {
            $query->where('ip', $ip);
        }
        if ($from = $request->query('from')) {
            $query->where('created_at', '>=', $from);
        }

        foreach ([
            'request_id',
            'route_name',
            'action_taken',
            'country_code',
            'asn',
            'authenticated_user_id_hash',
            'response_status',
        ] as $filter) {
            if ($request->filled($filter)) {
                $query->where($filter, $request->query($filter));
            }
        }

        $events = $query->paginate($this->perPage($request));

        return response()->json($events);
    }

    /**
     * GET /api/crowdsec/blocked — List blocked IPs
     */
    public function blocked(Request $request): JsonResponse
    {
        $query = BlockedIp::active()->orderBy('created_at', 'desc');

        if ($ip = $request->query('ip')) {
            $query->where('ip', $ip);
        }

        $blocked = $query->paginate($this->perPage($request));

        return response()->json($blocked);
    }

    /**
     * POST /api/crowdsec/block — Block an IP
     */
    public function block(Request $request): JsonResponse
    {
        $request->validate([
            'ip' => 'required|ip',
            'reason' => 'required|string|max:255',
            'duration' => 'nullable|integer|min:1',
        ]);

        $blocked = $this->service->blockIp(
            $request->input('ip'),
            $request->input('reason'),
            $request->input('duration'),
        );

        return response()->json([
            'message' => 'IP blocked successfully',
            'data' => $blocked,
        ], 201);
    }

    /**
     * DELETE /api/crowdsec/block/{ip} — Unblock an IP
     */
    public function unblock(string $ip): JsonResponse
    {
        $result = $this->service->unblockIp($ip);

        return response()->json([
            'message' => $result ? 'IP unblocked successfully' : 'IP was not blocked',
            'unblocked' => $result,
        ]);
    }

    /**
     * GET /api/crowdsec/check/{ip} — Check if IP is blocked/tracked
     */
    public function check(string $ip): JsonResponse
    {
        return response()->json([
            'ip' => $ip,
            'is_blocked' => $this->service->isBlocked($ip),
            'is_whitelisted' => $this->service->isWhitelisted($ip),
            'behavior' => IpBehavior::where('ip', $ip)->first(),
        ]);
    }

    protected function perPage(Request $request): int
    {
        $value = $request->query('per_page');
        $perPage = is_scalar($value) ? (int) $value : 20;

        return max(1, min(100, $perPage));
    }
}

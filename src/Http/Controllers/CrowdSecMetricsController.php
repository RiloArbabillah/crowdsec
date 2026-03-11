<?php

namespace RiloArbabillah\LaravelCrowdSec\Http\Controllers;

use Illuminate\Http\Response;
use Illuminate\Routing\Controller;
use RiloArbabillah\LaravelCrowdSec\Models\BlockedIp;
use RiloArbabillah\LaravelCrowdSec\Models\IpBehavior;
use RiloArbabillah\LaravelCrowdSec\Models\SecurityEvent;

class CrowdSecMetricsController extends Controller
{
    /**
     * GET /crowdsec/metrics — Prometheus/OpenMetrics endpoint
     */
    public function __invoke(): Response
    {
        $lines = [];

        // -- threats_total (counter) --
        $lines[] = '# HELP crowdsec_threats_total Total number of threats detected';
        $lines[] = '# TYPE crowdsec_threats_total counter';

        $threatsByType = SecurityEvent::query()
            ->selectRaw("event_type, severity, count(*) as total")
            ->groupBy('event_type', 'severity')
            ->get();

        foreach ($threatsByType as $row) {
            $type = $this->sanitizeLabel($row->event_type);
            $severity = $this->sanitizeLabel($row->severity);
            $lines[] = "crowdsec_threats_total{type=\"{$type}\",severity=\"{$severity}\"} {$row->total}";
        }

        // -- blocked_ips_active (gauge) --
        $lines[] = '';
        $lines[] = '# HELP crowdsec_blocked_ips_active Number of currently active blocked IPs';
        $lines[] = '# TYPE crowdsec_blocked_ips_active gauge';
        $lines[] = 'crowdsec_blocked_ips_active ' . BlockedIp::active()->count();

        // -- blocked_ips_total (counter) --
        $lines[] = '';
        $lines[] = '# HELP crowdsec_blocked_ips_total Total number of IPs ever blocked';
        $lines[] = '# TYPE crowdsec_blocked_ips_total counter';
        $lines[] = 'crowdsec_blocked_ips_total ' . BlockedIp::count();

        // -- tracked_ips (gauge) --
        $lines[] = '';
        $lines[] = '# HELP crowdsec_tracked_ips Number of IPs being tracked';
        $lines[] = '# TYPE crowdsec_tracked_ips gauge';
        $lines[] = 'crowdsec_tracked_ips ' . IpBehavior::count();

        // -- high_threat_ips (gauge) --
        $lines[] = '';
        $lines[] = '# HELP crowdsec_high_threat_ips IPs with threat score above threshold';
        $lines[] = '# TYPE crowdsec_high_threat_ips gauge';
        $lines[] = 'crowdsec_high_threat_ips ' . IpBehavior::highThreat()->count();

        // -- threat_score_average (gauge) --
        $lines[] = '';
        $lines[] = '# HELP crowdsec_threat_score_average Average threat score across all tracked IPs';
        $lines[] = '# TYPE crowdsec_threat_score_average gauge';
        $avg = IpBehavior::avg('threat_score') ?? 0;
        $lines[] = 'crowdsec_threat_score_average ' . round((float) $avg, 2);

        // -- events_today (gauge) --
        $lines[] = '';
        $lines[] = '# HELP crowdsec_events_today Number of security events today';
        $lines[] = '# TYPE crowdsec_events_today gauge';
        $lines[] = 'crowdsec_events_today ' . SecurityEvent::where('created_at', '>=', now()->startOfDay())->count();

        // -- events_this_hour (gauge) --
        $lines[] = '';
        $lines[] = '# HELP crowdsec_events_this_hour Number of security events in the last hour';
        $lines[] = '# TYPE crowdsec_events_this_hour gauge';
        $lines[] = 'crowdsec_events_this_hour ' . SecurityEvent::where('created_at', '>=', now()->subHour())->count();

        $lines[] = '';

        return response(
            implode("\n", $lines),
            200,
            ['Content-Type' => 'text/plain; version=0.0.4; charset=utf-8']
        );
    }

    protected function sanitizeLabel(string $value): string
    {
        return preg_replace('/[^a-zA-Z0-9_]/', '_', $value);
    }
}

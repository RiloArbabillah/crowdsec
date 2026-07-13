<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CrowdSec Security Dashboard</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #e2e8f0; }
        .container { max-width: 1200px; margin: 0 auto; padding: 24px; }
        h1 { font-size: 24px; margin-bottom: 24px; display: flex; align-items: center; gap: 8px; }
        h1 span { font-size: 28px; }
        .grid { display: grid; gap: 16px; margin-bottom: 24px; }
        .grid-4 { grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); }
        .grid-2 { grid-template-columns: repeat(auto-fit, minmax(min(400px, 100%), 1fr)); }
        .card { background: #1e293b; border-radius: 12px; padding: 20px; border: 1px solid #334155; }
        .card h2 { font-size: 14px; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 8px; }
        .card .value { font-size: 32px; font-weight: 700; }
        .card .label { font-size: 12px; color: #64748b; margin-top: 4px; }
        .section-title { font-size: 16px; margin-bottom: 12px; color: #cbd5e1; }
        table { width: 100%; border-collapse: collapse; }
        th { text-align: left; padding: 10px 12px; font-size: 12px; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.5px; border-bottom: 1px solid #334155; }
        td { padding: 10px 12px; font-size: 14px; border-bottom: 1px solid #1e293b; }
        tr:hover { background: #334155; }
        .badge { padding: 2px 8px; border-radius: 9999px; font-size: 11px; font-weight: 600; }
        .badge-critical { background: #991b1b; color: #fca5a5; }
        .badge-high { background: #92400e; color: #fcd34d; }
        .badge-medium { background: #1e3a5f; color: #93c5fd; }
        .badge-low { background: #064e3b; color: #6ee7b7; }
        .text-green { color: #4ade80; }
        .text-red { color: #f87171; }
        .text-yellow { color: #fbbf24; }
        .text-blue { color: #60a5fa; }
        .footer { text-align: center; padding: 24px; color: #475569; font-size: 12px; }
        .table-wrap { overflow-x: auto; }
    </style>
</head>
<body>
    <div class="container">
        <h1><span>🛡️</span> CrowdSec Security Dashboard</h1>

        {{-- Stats Cards --}}
        <div class="grid grid-4">
            <div class="card">
                <h2>Events Today</h2>
                <div class="value text-blue">{{ $stats['events_today'] }}</div>
                <div class="label">Total: {{ $stats['total_events'] }}</div>
            </div>
            <div class="card">
                <h2>This Week</h2>
                <div class="value text-yellow">{{ $stats['events_this_week'] }}</div>
                <div class="label">Security events</div>
            </div>
            <div class="card">
                <h2>Active Blocks</h2>
                <div class="value text-red">{{ $stats['active_blocks'] }}</div>
                <div class="label">Currently blocked IPs</div>
            </div>
            <div class="card">
                <h2>High Threat</h2>
                <div class="value text-green">{{ $stats['high_threat_ips'] }}</div>
                <div class="label">of {{ $stats['total_ips_tracked'] }} tracked</div>
            </div>
        </div>

        {{-- Threat Breakdown --}}
        @if(!empty($threatBreakdown))
        <div class="card" style="margin-bottom: 24px;">
            <h2>Threat Breakdown (Last 7 Days)</h2>
            <div style="display: flex; gap: 16px; margin-top: 12px; flex-wrap: wrap;">
                @foreach($threatBreakdown as $severity => $count)
                <div style="text-align: center;">
                    <span class="badge badge-{{ $severity ?? 'medium' }}">{{ strtoupper($severity ?? 'unknown') }}</span>
                    <div style="font-size: 20px; font-weight: 600; margin-top: 4px;">{{ $count }}</div>
                </div>
                @endforeach
            </div>
        </div>
        @endif

        {{-- Tables --}}
        <div class="grid grid-2">
            {{-- Recent Events --}}
            <div class="card">
                <h2>Recent Events</h2>
                <div class="table-wrap"><table>
                    <thead>
                        <tr><th>IP</th><th>Type</th><th>Action</th><th>Status</th><th>Country</th><th>Client</th><th>Time</th></tr>
                    </thead>
                    <tbody>
                        @forelse($recentEvents as $event)
                        <tr>
                            <td>{{ $event->ip }}</td>
                            <td>{{ $event->event_type ?? '-' }}</td>
                            <td><span class="badge badge-{{ $event->severity ?? 'medium' }}">{{ $event->action_taken ?? '-' }}</span></td>
                            <td>{{ $event->response_status ?? '-' }}</td>
                            <td>{{ $event->country_code ?? '-' }}</td>
                            <td>{{ $event->device_type ?? $event->browser ?? '-' }}</td>
                            <td>{{ $event->created_at->diffForHumans() }}</td>
                        </tr>
                        @empty
                        <tr><td colspan="7" style="text-align:center; color:#64748b;">No events recorded</td></tr>
                        @endforelse
                    </tbody>
                </table></div>
            </div>

            {{-- Blocked IPs --}}
            <div class="card">
                <h2>Blocked IPs</h2>
                <table>
                    <thead>
                        <tr><th>IP</th><th>Reason</th><th>Expires</th></tr>
                    </thead>
                    <tbody>
                        @forelse($blockedIps as $blocked)
                        <tr>
                            <td>{{ $blocked->ip }}</td>
                            <td>{{ Str::limit($blocked->reason, 30) }}</td>
                            <td>{{ $blocked->expires_at ? $blocked->expires_at->diffForHumans() : 'Never' }}</td>
                        </tr>
                        @empty
                        <tr><td colspan="3" style="text-align:center; color:#64748b;">No blocked IPs</td></tr>
                        @endforelse
                    </tbody>
                </table>
            </div>
        </div>

        @if($topCountries->isNotEmpty() || $deviceBreakdown->isNotEmpty())
        <div class="grid grid-2">
            <div class="card">
                <h2>Top Source Countries (Last 7 Days)</h2>
                <div class="table-wrap"><table>
                    <thead><tr><th>Country</th><th>Events</th></tr></thead>
                    <tbody>
                        @forelse($topCountries as $country)
                        <tr><td>{{ $country->country_code }}</td><td>{{ $country->count }}</td></tr>
                        @empty
                        <tr><td colspan="2" style="text-align:center; color:#64748b;">No country data</td></tr>
                        @endforelse
                    </tbody>
                </table></div>
            </div>
            <div class="card">
                <h2>Device Types (Last 7 Days)</h2>
                <div class="table-wrap"><table>
                    <thead><tr><th>Device</th><th>Events</th></tr></thead>
                    <tbody>
                        @forelse($deviceBreakdown as $device)
                        <tr><td>{{ $device->device_type }}</td><td>{{ $device->count }}</td></tr>
                        @empty
                        <tr><td colspan="2" style="text-align:center; color:#64748b;">No device data</td></tr>
                        @endforelse
                    </tbody>
                </table></div>
            </div>
        </div>
        @endif

        {{-- Top Attackers --}}
        @if($topAttackers->isNotEmpty())
        <div class="card" style="margin-top: 24px;">
            <h2>Top Attackers (Last 24h)</h2>
            <table>
                <thead>
                    <tr><th>#</th><th>IP Address</th><th>Events</th></tr>
                </thead>
                <tbody>
                    @foreach($topAttackers as $index => $attacker)
                    <tr>
                        <td>{{ $index + 1 }}</td>
                        <td>{{ $attacker->ip }}</td>
                        <td>{{ $attacker->count }}</td>
                    </tr>
                    @endforeach
                </tbody>
            </table>
        </div>
        @endif

        <div class="footer">
            CrowdSec for Laravel — Powered by rilo-arbabillah/laravel-crowdsec
        </div>
    </div>
</body>
</html>

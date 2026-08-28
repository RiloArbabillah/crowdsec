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

        {{-- Whitelist --}}
        @if(config('crowdsec-scenarios.api.enabled', false))
        <div class="card" style="margin-top: 24px;">
            <h2>Dynamic IP Whitelist</h2>
            <p style="color: #94a3b8; font-size: 12px; margin: 8px 0 16px 0;">
                Add or remove trusted IPs at runtime. Static defaults from
                <code style="color:#cbd5e1;">config('crowdsec-scenarios.whitelist_ips')</code>
                are also active and shown below.
            </p>

            <form id="whitelist-add-form" style="display:flex; gap:8px; flex-wrap:wrap; margin-bottom:16px;" onsubmit="return crowdsecWhitelistSubmit(event)">
                <input id="wl-ip" type="text" placeholder="10.0.0.0/8" required
                    style="flex:1; min-width:160px; padding:8px 10px; background:#0f172a; color:#e2e8f0; border:1px solid #334155; border-radius:6px; font-size:13px;">
                <input id="wl-label" type="text" placeholder="Label (e.g. Office VPN)"
                    style="flex:1; min-width:160px; padding:8px 10px; background:#0f172a; color:#e2e8f0; border:1px solid #334155; border-radius:6px; font-size:13px;">
                <input id="wl-note" type="text" placeholder="Note (optional)"
                    style="flex:1; min-width:160px; padding:8px 10px; background:#0f172a; color:#e2e8f0; border:1px solid #334155; border-radius:6px; font-size:13px;">
                <input id="wl-expires" type="datetime-local"
                    style="flex:1; min-width:200px; padding:8px 10px; background:#0f172a; color:#e2e8f0; border:1px solid #334155; border-radius:6px; font-size:13px;">
                <button type="submit"
                    style="padding:8px 16px; background:#1e40af; color:#fff; border:0; border-radius:6px; font-size:13px; cursor:pointer;">
                    Add to whitelist
                </button>
            </form>
            <div id="whitelist-message" style="font-size:12px; margin-bottom:12px;"></div>

            <div class="table-wrap"><table>
                <thead>
                    <tr><th>IP / CIDR</th><th>Label</th><th>Note</th><th>Expires</th><th>Added by</th><th>Action</th></tr>
                </thead>
                <tbody id="whitelist-rows">
                    <tr><td colspan="6" style="text-align:center; color:#64748b;">Loading…</td></tr>
                </tbody>
            </table></div>

            @php
                $staticWhitelist = (array) config('crowdsec-scenarios.whitelist_ips', []);
            @endphp
            @if(!empty($staticWhitelist))
            <div style="margin-top:16px; font-size:12px; color:#94a3b8;">
                <strong>Config-level (static):</strong>
                <span style="color:#cbd5e1;">{{ implode(', ', $staticWhitelist) }}</span>
            </div>
            @endif
        </div>

        <script>
        (function () {
            const apiBase = @json(route('crowdsec.dashboard', [], false) ? '/api/crowdsec' : '/api/crowdsec');
            const csrf = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || '';

            async function loadWhitelist() {
                const rows = document.getElementById('whitelist-rows');
                const msg = document.getElementById('whitelist-message');
                msg.textContent = '';
                try {
                    const res = await fetch(apiBase + '/whitelist', { headers: { 'Accept': 'application/json', 'X-Requested-With': 'XMLHttpRequest' }, credentials: 'same-origin' });
                    if (!res.ok) throw new Error('HTTP ' + res.status);
                    const json = await res.json();
                    const data = json.data || json;
                    if (!data || data.length === 0) {
                        rows.innerHTML = '<tr><td colspan="6" style="text-align:center; color:#64748b;">No dynamic entries yet.</td></tr>';
                        return;
                    }
                    rows.innerHTML = data.map(function (e) {
                        const expires = e.expires_at ? new Date(e.expires_at).toLocaleString() : '—';
                        return '<tr>'
                            + '<td><code style="color:#cbd5e1;">' + escape(e.ip) + '</code></td>'
                            + '<td>' + escape(e.label || '—') + '</td>'
                            + '<td>' + escape(e.note || '—') + '</td>'
                            + '<td>' + expires + '</td>'
                            + '<td>' + escape(e.created_by_label || (e.created_by ? ('#' + e.created_by) : '—')) + '</td>'
                            + '<td><button data-ip="' + escape(e.ip) + '" class="wl-remove" style="background:#7f1d1d; color:#fecaca; border:0; padding:4px 10px; border-radius:4px; font-size:12px; cursor:pointer;">Remove</button></td>'
                            + '</tr>';
                    }).join('');
                } catch (err) {
                    rows.innerHTML = '<tr><td colspan="6" style="text-align:center; color:#f87171;">Failed to load: ' + escape(String(err)) + '</td></tr>';
                }
            }

            function escape(s) {
                return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
                    return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
                });
            }

            window.crowdsecWhitelistSubmit = async function (ev) {
                ev.preventDefault();
                const msg = document.getElementById('whitelist-message');
                const body = {
                    ip: document.getElementById('wl-ip').value.trim(),
                    label: document.getElementById('wl-label').value.trim() || null,
                    note: document.getElementById('wl-note').value.trim() || null,
                    expires_at: document.getElementById('wl-expires').value || null,
                };
                if (!body.ip) { msg.textContent = 'IP is required.'; msg.style.color = '#f87171'; return false; }
                msg.textContent = 'Adding…'; msg.style.color = '#94a3b8';
                try {
                    const res = await fetch(apiBase + '/whitelist', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json', 'Accept': 'application/json', 'X-Requested-With': 'XMLHttpRequest', 'X-CSRF-TOKEN': csrf },
                        credentials: 'same-origin',
                        body: JSON.stringify(body),
                    });
                    if (!res.ok) {
                        const err = await res.json().catch(() => ({}));
                        throw new Error(err.message || ('HTTP ' + res.status));
                    }
                    document.getElementById('whitelist-add-form').reset();
                    msg.textContent = 'Added.'; msg.style.color = '#4ade80';
                    loadWhitelist();
                } catch (err) {
                    msg.textContent = 'Failed: ' + err.message; msg.style.color = '#f87171';
                }
                return false;
            };

            document.addEventListener('click', async function (ev) {
                const btn = ev.target.closest && ev.target.closest('.wl-remove');
                if (!btn) return;
                const ip = btn.getAttribute('data-ip');
                if (!ip) return;
                if (!window.confirm('Remove ' + ip + ' from the dynamic whitelist?')) return;
                try {
                    const res = await fetch(apiBase + '/whitelist/' + encodeURIComponent(ip), {
                        method: 'DELETE',
                        headers: { 'Accept': 'application/json', 'X-Requested-With': 'XMLHttpRequest', 'X-CSRF-TOKEN': csrf },
                        credentials: 'same-origin',
                    });
                    if (!res.ok) throw new Error('HTTP ' + res.status);
                    loadWhitelist();
                } catch (err) {
                    alert('Remove failed: ' + err.message);
                }
            });

            loadWhitelist();
        })();
        </script>
        @endif

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

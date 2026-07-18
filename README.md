# Laravel CrowdSec

[![Tests](https://github.com/RiloArbabillah/crowdsec/actions/workflows/tests.yml/badge.svg)](https://github.com/RiloArbabillah/crowdsec/actions/workflows/tests.yml)
[![PHP Version](https://img.shields.io/packagist/php-v/rilo-arbabillah/laravel-crowdsec.svg)](https://packagist.org/packages/rilo-arbabillah/laravel-crowdsec)
[![License](https://img.shields.io/packagist/l/rilo-arbabillah/laravel-crowdsec.svg)](LICENSE)

Laravel CrowdSec is a lightweight, application-layer Web Application Firewall (WAF) for Laravel. It detects common web attacks, tracks suspicious behavior, blocks abusive IP addresses, and records security events without requiring a separate proxy or security agent.

It is designed as an additional layer of protection for Laravel applications. It does not replace infrastructure controls such as a reverse-proxy WAF, DDoS protection, network filtering, or secure application code.

Installing with a coding agent? Use the [AI-Assisted Installation Guide](README_AI.md) for a repository-aware, verified setup workflow.

## Contents

- [Features](#features)
- [Requirements](#requirements)
- [Quick Start](#quick-start)
- [AI-Assisted Installation](README_AI.md)
- [Protecting Routes](#protecting-routes)
- [Programmatic Usage](#programmatic-usage)
- [Configuration](#configuration)
- [Optional Features](#optional-features)
- [Artisan Commands](#artisan-commands)
- [Scheduled Maintenance](#scheduled-maintenance)
- [Detection Coverage](#detection-coverage)
- [Database Tables](#database-tables)
- [Production Checklist](#production-checklist)
- [Development](#development)
- [Security](#security)
- [License](#license)

## Features

- Detection for 15 attack categories, including SQL injection, XSS, path traversal, command injection, SSRF, and XXE
- Multi-layer URL and HTML entity decoding to detect encoded payloads
- Temporary IP blocking with expiration and progressive escalation
- Request-rate, 404, login-attempt, and threat-score behavior tracking
- Exact-IP and CIDR allowlisting
- Cached blocked-IP lookups for high-traffic applications
- Security events with request correlation, route and response context, GeoIP/ASN data, pseudonymous user hashes, and parsed client information
- Automatic redaction of sensitive query, cookie, authorization, and matched-source values
- Email and Slack notifications with severity filtering and rate limiting
- Honeypot and per-route rate-limiting middleware
- REST management API, admin dashboard, and Prometheus-compatible metrics endpoint
- Immutable audit records for manual block and unblock actions
- JSON, CSV, and RFC 5424 Syslog exports
- Health checks through `crowdsec:doctor`

## Requirements

- PHP `^8.1`
- Laravel `^10.0`, `^11.0`, or `^12.0`
- A Laravel-supported database, such as MySQL, PostgreSQL, or SQLite

The latest stable package release is `v1.2.0`.

## Quick Start

### 1. Install the package

```bash
composer require rilo-arbabillah/laravel-crowdsec
```

Laravel auto-discovers the service provider, facade, and middleware aliases.

### 2. Run the migrations

```bash
php artisan migrate
```

The package migrations create the security tables automatically. No migration publishing step is required.

### 3. Publish the configuration

Publishing is optional, but recommended before changing thresholds or enabling integrations:

```bash
php artisan vendor:publish --tag=crowdsec-config
```

This creates `config/crowdsec-scenarios.php` in the host application.

### 4. Protect a route

```php
use Illuminate\Support\Facades\Route;

Route::middleware('crowdsec')->group(function () {
    Route::get('/admin', AdminController::class);
    Route::post('/login', [AuthController::class, 'login']);
});
```

### 5. Verify the installation

```bash
php artisan crowdsec:doctor
```

The doctor checks the package state, database tables, detection patterns, cache, notifications, GeoIP, optional endpoints, allowlists, and route configuration.

## Protecting Routes

The package registers three middleware aliases:

| Alias | Purpose | Example |
| --- | --- | --- |
| `crowdsec` | Full WAF and behavior protection | `Route::middleware('crowdsec')` |
| `crowdsec.honeypot` | Immediately block clients that access a trap route | `Route::middleware('crowdsec.honeypot')` |
| `crowdsec.rate` | Apply an IP-based route limit | `Route::middleware('crowdsec.rate:60,1')` |

### Route groups

```php
Route::middleware(['api', 'crowdsec'])->group(function () {
    Route::get('/account', AccountController::class);
    Route::post('/orders', [OrderController::class, 'store']);
});
```

Use `withoutMiddleware()` for endpoints that must remain outside the protected group:

```php
Route::get('/health', HealthController::class)
    ->withoutMiddleware('crowdsec');
```

### Global middleware

Route-level protection is usually easier to tune. To protect every request in Laravel 11 or 12, append the middleware in `bootstrap/app.php`:

```php
use Illuminate\Foundation\Configuration\Middleware;
use RiloArbabillah\LaravelCrowdSec\Http\Middleware\CrowdSecProtection;

->withMiddleware(function (Middleware $middleware): void {
    $middleware->append(CrowdSecProtection::class);
})
```

For Laravel 10, add the class to the global `$middleware` array in `app/Http/Kernel.php`:

```php
protected $middleware = [
    // ...
    \RiloArbabillah\LaravelCrowdSec\Http\Middleware\CrowdSecProtection::class,
];
```

## Programmatic Usage

The `CrowdSec` facade provides access to the protection service.

### Check, block, and unblock an IP

```php
use RiloArbabillah\LaravelCrowdSec\Facades\CrowdSec;

$ip = request()->ip();

if (CrowdSec::isBlocked($ip)) {
    abort(403, 'Your IP has been blocked.');
}

CrowdSec::blockIp($ip, 'Manual block for abusive traffic', 60);
CrowdSec::unblockIp($ip);
```

Block duration is expressed in minutes. Repeated blocks are progressively extended, up to seven days.

### Track a failed login

```php
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use RiloArbabillah\LaravelCrowdSec\Facades\CrowdSec;

public function login(Request $request)
{
    if (! Auth::attempt($request->only('email', 'password'))) {
        CrowdSec::trackLoginAttempt($request->ip());

        return back()->withErrors(['email' => 'Invalid credentials.']);
    }

    return redirect('/dashboard');
}
```

Use manual `trackLoginAttempt()` calls only when the route is not already listed in `login_routes`; combining both mechanisms counts the same failed request twice. Automatic middleware tracking records a provisional attempt without threat score, allows the configured number of requests, and blocks the following request when the counter was not reset by successful authentication.

Successful Laravel authentication resets only the IP's login-attempt counter and login window. Existing threat scores and active blocks are preserved by default. Automatic threat-score reset and unblocking are explicit configuration opt-ins.

### Analyze a request

```php
use RiloArbabillah\LaravelCrowdSec\Facades\CrowdSec;

$threats = CrowdSec::analyzeRequest($request);

foreach ($threats as $threat) {
    logger()->warning('Security threat detected', [
        'type' => $threat['type'],
        'severity' => $threat['severity'],
        'matched' => $threat['matched'],
    ]);
}
```

### Register a custom scenario

Register runtime scenarios from an application service provider:

```php
use RiloArbabillah\LaravelCrowdSec\Facades\CrowdSec;

CrowdSec::registerScenario('api_abuse', [
    'patterns' => ['/custom-api-abuse-signature/i'],
    'severity' => 'high',
    'weight' => 30,
    'block_duration' => 720,
    'mode' => 'monitor',
]);
```

Custom scenarios are merged with the built-in scenarios.

## Configuration

After publishing the configuration, edit `config/crowdsec-scenarios.php`. The most commonly adjusted settings are:

```php
return [
    'enabled' => env('CROWDSEC_ENABLED', true),

    'waf' => [
        'default_mode' => 'enforce',
        'scenario_modes' => [
            // 'sql_injection' => 'monitor',
        ],
        'exclusions' => [
            [
                'route_names' => ['webhooks.provider'],
                'paths' => ['webhooks/provider'],
                'methods' => ['POST'],
                'skip_scenarios' => ['sql_injection'],
                'ignore_body_fields' => ['payload.signature'],
            ],
        ],
    ],

    'whitelist_ips' => [
        '127.0.0.1',
        '::1',
        // '10.0.0.0/8',
    ],

    'behavior' => [
        'request_threshold' => 500,
        'request_window_minutes' => 60,
        '404_threshold' => 15,
        '404_window_minutes' => 60,
        'login_threshold' => 5,
        'login_window_minutes' => 5,
        'login_ignored_fields' => [
            'password',
            'password_confirmation',
            'current_password',
        ],
        'unblock_on_authentication' => false,
        'reset_threat_score_on_authentication' => false,
        'threat_score_threshold' => 50,
        'block_duration' => 240,
        'severity' => 'high',
    ],
];
```

Scenario mode `enforce` preserves normal scoring and blocking. `monitor` records and dispatches the detection with action `monitored` but does not score or block, while `disabled` omits the scenario entirely. An exclusion rule matches only when every non-empty selector group matches; entries within a group support wildcards and use OR semantics. Exclusions skip only the listed scenarios or dotted body fields. Existing IP blocks and behavior thresholds remain enforced.

Request, 404, and login counters use independent fixed windows. Login requests are still inspected by the WAF, but configured secret fields are excluded from body inspection. Query parameters, paths, headers, cookies, uploads, JWT data, and non-secret body fields remain protected.

The `crowdsec.rate` middleware uses Laravel's atomic rate limiter and returns `Retry-After`, `X-RateLimit-Limit`, `X-RateLimit-Remaining`, and `X-RateLimit-Reset` headers based on the actual limiter state.

### Environment variables

| Variable | Default | Purpose |
| --- | --- | --- |
| `CROWDSEC_ENABLED` | `true` | Enable or disable all package protection |
| `CROWDSEC_LOG_CHANNEL` | Laravel default | Select the Laravel log channel |
| `CROWDSEC_MAX_CONTENT_LENGTH` | `10485760` | Maximum inspected request size in bytes; `0` disables the limit |
| `CROWDSEC_BLOCK_EMPTY_UA` | `false` | Block requests without a User-Agent header |
| `CROWDSEC_CACHE_ENABLED` | `false` | Cache blocked-IP lookups |
| `CROWDSEC_CACHE_STORE` | Laravel default | Select the cache store |
| `CROWDSEC_CACHE_TTL` | `60` | Blocked-IP cache lifetime in seconds |
| `CROWDSEC_NOTIFY_ENABLED` | `false` | Enable security notifications |
| `CROWDSEC_NOTIFY_CHANNELS` | `mail` | Comma-separated `mail` and/or `slack` channels |
| `CROWDSEC_NOTIFY_RECIPIENTS` | Empty | Comma-separated mail recipients |
| `CROWDSEC_NOTIFY_SLACK_WEBHOOK_URL` | Empty | Slack incoming webhook URL |
| `CROWDSEC_GEOIP_ENABLED` | `false` | Enable GeoIP enrichment |
| `CROWDSEC_GEOIP_PROVIDER` | `ipwhois` | Use HTTPS `ipwhois`, legacy `ip-api`, or a configured custom provider |
| `CROWDSEC_GEOIP_TIMEOUT` | `2` | GeoIP request timeout in seconds |
| `CROWDSEC_REQUEST_ID_HEADER` | `X-Request-ID` | Header used for request correlation |
| `CROWDSEC_PARSE_USER_AGENT` | `true` | Parse browser, OS, and device type |
| `CROWDSEC_HASH_AUTHENTICATED_USER` | `true` | Store a pseudonymous authenticated-user hash |
| `CROWDSEC_USER_HASH_KEY` | `APP_KEY` | Dedicated HMAC key for stable user hashes |
| `CROWDSEC_API_ENABLED` | `false` | Enable the REST management API |
| `CROWDSEC_METRICS_ENABLED` | `false` | Enable the metrics endpoint |
| `CROWDSEC_AUDIT_ENABLED` | `false` | Record manual block and unblock audit events |
| `CROWDSEC_AUDIT_RETENTION_DAYS` | `365` | Audit record retention period |
| `CROWDSEC_DASHBOARD_ENABLED` | `false` | Enable the admin dashboard |

Configuration values that do not have an environment variable, including middleware stacks, endpoint paths, severity thresholds, allowlists, redaction fields, and detection patterns, are configured directly in `crowdsec-scenarios.php`.

### Notifications

```env
CROWDSEC_NOTIFY_ENABLED=true
CROWDSEC_NOTIFY_CHANNELS=mail,slack
CROWDSEC_NOTIFY_RECIPIENTS=security@example.com,ops@example.com
CROWDSEC_NOTIFY_SLACK_WEBHOOK_URL=https://hooks.slack.com/services/your/webhook/path
```

Notifications default to high-severity and critical blocks, with one notification per IP every five minutes. Laravel mail must be configured for the `mail` channel. The `slack` channel requires a valid incoming webhook URL.

### Security event context and privacy

Only detected security events are stored; the package is not a general access logger. Events can include request and route metadata, response status, enforcement action, duration, country, ASN/ISP, pseudonymous user identity, browser, OS, and device type.

Sensitive query parameters, cookies, authorization values, referers, and matched sources are redacted before persistence. Authenticated user IDs are stored as HMAC-SHA256 hashes rather than raw identifiers. Set `CROWDSEC_USER_HASH_KEY` if hashes must remain stable when `APP_KEY` is rotated.

Client IPs, User-Agent strings, GeoIP results, and client-provided request IDs are correlation signals, not trusted identity. Configure Laravel's trusted proxies correctly before relying on the recorded client IP.

## Optional Features

The REST API, metrics endpoint, audit log, dashboard, notifications, GeoIP lookup, and blocked-IP cache are disabled by default.

### REST API

Enable it with `CROWDSEC_API_ENABLED=true`. The default middleware is `['api', 'auth:sanctum']`.

| Method | Endpoint | Purpose |
| --- | --- | --- |
| `GET` | `/api/crowdsec/stats` | Protection statistics |
| `GET` | `/api/crowdsec/events` | Filterable security events |
| `GET` | `/api/crowdsec/blocked` | Blocked IP addresses |
| `POST` | `/api/crowdsec/block` | Manually block an IP |
| `DELETE` | `/api/crowdsec/block/{ip}` | Unblock an IP |
| `GET` | `/api/crowdsec/check/{ip}` | Check an IP's block status |

If the application does not use Sanctum, replace the middleware with an equivalent authenticated API guard. Do not expose management routes without authentication.

### Prometheus metrics

Enable metrics with `CROWDSEC_METRICS_ENABLED=true`. The default path is `/crowdsec/metrics`, protected by `['web', 'auth']`.

For monitoring systems that cannot authenticate through a Laravel session, configure a signed URL or a dedicated allowlist middleware. The doctor command rejects an enabled metrics endpoint that has neither `auth` nor `signed` protection.

### Admin dashboard

Enable the dashboard with `CROWDSEC_DASHBOARD_ENABLED=true`. The default path is `/crowdsec`, protected by `['web', 'auth']`.

The bundled Blade dashboard shows recent events, active blocks, top attackers, severity breakdowns, source countries, and device types. Publish its views only when customization is needed:

```bash
php artisan vendor:publish --tag=crowdsec-views
```

### GeoIP enrichment

Enable the default HTTPS `ipwho.is` provider with:

```env
CROWDSEC_GEOIP_ENABLED=true
CROWDSEC_GEOIP_PROVIDER=ipwhois
CROWDSEC_GEOIP_TIMEOUT=2
```

Results are cached for 24 hours with provider-specific keys. Private addresses are not sent to the provider. The legacy `ip-api` provider remains available for existing installations but uses unencrypted HTTP and produces a doctor warning. Review the selected provider's availability, privacy, and usage terms before enabling it in production.

### Audit logging

Enable immutable audit records for manual IP block and unblock actions:

```env
CROWDSEC_AUDIT_ENABLED=true
CROWDSEC_AUDIT_RETENTION_DAYS=365
```

Audit retention is enforced by `crowdsec:cleanup` when audit logging is enabled.

## Artisan Commands

| Command | Purpose |
| --- | --- |
| `php artisan crowdsec:doctor` | Validate configuration, migrations, patterns, and integrations |
| `php artisan crowdsec:stats` | Show blocks, event totals, threat counts, and top attackers |
| `php artisan crowdsec:cleanup` | Expire bans and remove old event, behavior, and audit records |
| `php artisan crowdsec:export` | Export events as JSON, CSV, or RFC 5424 Syslog |

### Health checks and statistics

```bash
php artisan crowdsec:doctor
php artisan crowdsec:doctor --json

php artisan crowdsec:stats
php artisan crowdsec:stats --json
```

JSON output is suitable for automated checks and monitoring integrations.

### Cleanup

Running cleanup without a selector processes all supported record types:

```bash
php artisan crowdsec:cleanup
```

Use selectors or preview the result:

```bash
php artisan crowdsec:cleanup --dry-run
php artisan crowdsec:cleanup --expired
php artisan crowdsec:cleanup --old-events
php artisan crowdsec:cleanup --old-behaviors
```

Security events and inactive behavior records are removed after 30 days. Audit records use `CROWDSEC_AUDIT_RETENTION_DAYS`. The `--dry-run` option does not modify data.

### SIEM export

```bash
php artisan crowdsec:export --format=json
php artisan crowdsec:export --format=csv --from=2026-07-01 --to=2026-07-31
php artisan crowdsec:export --format=syslog --severity=critical
php artisan crowdsec:export --format=json --output=storage/app/crowdsec-events.json
```

Supported options are `--format`, `--from`, `--to`, `--severity`, and `--output`. Without `--output`, the export is written to standard output.

## Scheduled Maintenance

The package registers these tasks automatically through Laravel's scheduler:

- Expired bans: daily
- Security events older than 30 days: weekly
- Inactive behavior records older than 30 days: weekly

The application must still run Laravel's scheduler in production, for example through a cron entry that invokes `php artisan schedule:run` every minute.

For Laravel 10 applications where package schedule discovery is unavailable, add the equivalent commands to `app/Console/Kernel.php`:

```php
use Illuminate\Console\Scheduling\Schedule;

protected function schedule(Schedule $schedule): void
{
    $schedule->command('crowdsec:cleanup --expired')->daily();
    $schedule->command('crowdsec:cleanup --old-events')->weekly();
    $schedule->command('crowdsec:cleanup --old-behaviors')->weekly();
}
```

Do not register these fallback schedules when the package tasks already appear in `php artisan schedule:list`.

## Detection Coverage

| Threat category | Default severity | Examples |
| --- | --- | --- |
| SQL injection | Critical | Boolean, union, stacked, time-based, and file-based SQL payloads |
| Cross-site scripting (XSS) | High | Script tags, event handlers, dangerous URI schemes, and DOM access |
| Path traversal | Critical | Plain, encoded, Windows-style, and null-byte traversal |
| Command injection | Critical | Shell separators, substitutions, shell paths, and reverse shells |
| File inclusion | High | PHP, data, expect, ZIP, PHAR, and related wrappers |
| PHP serialization | Critical | Serialized objects and magic-method payloads |
| Directory brute force | Medium | Sensitive files, CMS paths, debug endpoints, and backups |
| Header injection | High | CRLF and injected location headers |
| Suspicious User-Agent | Medium | Common vulnerability scanners and exploitation tools |
| SSRF | Critical | Cloud metadata, private hosts, and dangerous protocols |
| XXE | Critical | External entities, system identifiers, and XInclude |
| NoSQL injection | Critical | MongoDB operators, aggregation stages, and JavaScript payloads |
| LDAP injection | High | LDAP filter and distinguished-name manipulation |
| Server-side template injection | Critical | Common expression and template-control syntax |
| Open redirect | Medium | External URLs supplied through redirect parameters |

Detection runs after URL decoding, double URL decoding, and HTML entity decoding. Default patterns and severities can be reviewed and adjusted in the published configuration.

Because application traffic varies, test configuration changes against representative legitimate requests before deploying stricter patterns or thresholds.

## Database Tables

| Table | Purpose |
| --- | --- |
| `blocked_ips` | Active and historical IP blocks, reasons, and expiration |
| `ip_behaviors` | Per-IP request, 404, login, threat-score, and block counters |
| `security_events` | Detected threats and enriched request/response context |
| `crowdsec_audit_logs` | Optional immutable records of manual block and unblock actions |

All tables are managed by the package migrations loaded by the service provider.

## Production Checklist

1. Run `php artisan crowdsec:doctor` after deployment and configuration changes.
2. Protect sensitive routes first, then expand coverage after reviewing legitimate traffic.
3. Configure trusted proxies so Laravel resolves the actual client IP.
4. Add internal services and trusted networks to `whitelist_ips`, using CIDR entries where appropriate.
5. Keep the REST API, metrics, and dashboard disabled unless needed; retain authentication or signed middleware when enabling them.
6. Configure Laravel mail or Slack before enabling notifications.
7. Confirm `php artisan schedule:list` includes cleanup tasks and that the scheduler runs in production.
8. Monitor `crowdsec:stats`, application logs, security events, and optional metrics.
9. Enable a shared cache store for high-traffic or multi-instance deployments.
10. Treat detection as defense in depth and continue using validation, authorization, secure coding, and infrastructure controls.

Performance depends on traffic, request size, database, cache, enabled enrichment, and deployment hardware. Run the included benchmark suite in an environment representative of production:

```bash
vendor/bin/phpunit tests/Benchmark --testdox
```

## Development

Clone the repository and install development dependencies:

```bash
composer install
```

Run the automated checks before submitting a pull request:

```bash
composer test
composer analyse
composer validate --strict
```

The test suite uses PHPUnit and Orchestra Testbench. GitHub Actions maps Laravel 10, 11, and 12 explicitly to compatible Testbench releases, covers PHP 8.1 through 8.4 where supported, runs a Composer security audit, and enforces Larastan/PHPStan level 5 across all package source and route files.

Stable releases use the manual `Release` workflow. It requires matching README and CHANGELOG metadata, a successful `Tests` run on the current `master` commit, and passing release quality gates before it creates an annotated tag and GitHub Release.

Laravel 10 remains package-compatible, but it is end-of-life. Compatibility does not imply active framework security support; production applications should use a Laravel version that still receives security updates.

Contributions should be submitted through a focused branch and pull request with tests for behavioral changes.

## Security

Do not open a public issue for an undisclosed vulnerability. Contact the maintainer privately with reproduction steps, affected versions, impact, and any suggested mitigation.

## License

Laravel CrowdSec is open-source software licensed under the [MIT License](LICENSE).

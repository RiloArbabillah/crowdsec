# AI-Assisted Installation Guide

This guide is an installation contract for coding agents adding Laravel CrowdSec to an existing Laravel application. It is designed for repository-aware agents such as Codex, Claude Code, and similar tools that can inspect files, run commands, and report results.

For package features and the complete human-readable reference, see the [main README](README.md).

## Start Here

Give your coding agent this prompt from the root of the Laravel application you want to protect:

```text
Read README_AI.md from the Laravel CrowdSec package documentation. Inspect this
Laravel application, then install and configure Laravel CrowdSec by following that
guide. Use route-level protection by default, preserve unrelated changes, do not
enable optional endpoints unless I request them, and report every change and
verification result.
```

If this file is not already available in the target repository, provide its URL or contents to the agent before asking it to begin.

## Agent Contract

The agent must follow these rules throughout the installation:

- Inspect the target application before changing files or installing dependencies.
- Preserve unrelated work in a dirty Git working tree.
- Explain compatibility problems before attempting workarounds.
- Never print, commit, or replace application secrets.
- Never weaken Composer security checks to force dependency resolution.
- Keep the REST API, metrics endpoint, dashboard, audit logging, notifications, GeoIP, and cache disabled unless the user requests them.
- Keep authentication or signed middleware on every enabled administrative or observability endpoint.
- Prefer route-level WAF protection. Add global middleware only when explicitly requested.
- Ask before running migrations against a production database or when the environment cannot be identified safely.
- Stop and report the exact failure when dependency installation, configuration, migration, or verification fails.
- Do not commit or push changes unless the user explicitly requests it.

## Compatibility

The target application must provide:

- PHP `^8.1`
- Laravel `^10.0`, `^11.0`, or `^12.0`
- Composer
- A configured Laravel-supported database such as MySQL, PostgreSQL, or SQLite

The package name is `rilo-arbabillah/laravel-crowdsec`. Laravel auto-discovers its service provider, facade, commands, migrations, views, and middleware aliases.

Laravel 10 remains package-compatible but is end-of-life. Do not describe compatibility as active framework security support; recommend a Laravel release that still receives security updates for production deployments.

## Installation Workflow

### 1. Inspect the target application

Before making changes, inspect and report:

- The PHP version and the Laravel version declared in `composer.json`
- Whether Composer can resolve the current dependency set
- The current Git branch and working-tree state
- The configured application environment, without displaying secrets
- Whether a database connection is configured and whether migrations can be run safely
- The route files and route groups that contain sensitive application surfaces
- The Laravel authentication system and any API guard such as Sanctum
- Existing global and route middleware registration
- Existing trusted-proxy configuration
- Existing tests and the commands used to run them

Do not treat a dirty working tree as permission to discard or overwrite changes. If an existing change overlaps a required edit, integrate with it or report the conflict.

### 2. Present the installation scope

Before running a mutating command, state the intended changes. The default scope is:

- Install the Composer package
- Run the package migrations
- Apply the `crowdsec` middleware to selected sensitive routes
- Run health checks and the target application's relevant tests

Publishing the configuration is optional. Do it only when the application needs non-default thresholds, allowlists, endpoint settings, integrations, or environment-variable documentation.

### 3. Install the package

Run from the target Laravel application root:

```bash
composer require rilo-arbabillah/laravel-crowdsec
```

If dependency resolution fails:

1. Preserve the Composer error output without exposing credentials.
2. Compare the target PHP and Laravel versions with the supported versions above.
3. Identify the conflicting package and constraint.
4. Stop and report the conflict with a safe remediation recommendation.

Do not use `--ignore-platform-reqs`, disable security blocking, or remove unrelated dependencies to force installation.

### 4. Publish configuration when needed

To customize the package, run:

```bash
php artisan vendor:publish --tag=crowdsec-config
```

This creates `config/crowdsec-scenarios.php`. Preserve existing published configuration if the file already exists; inspect and update only the required keys.

Do not place secrets directly in the PHP configuration file. Reference environment variables and add placeholder names to `.env.example` when the target project tracks one. Never copy real values from `.env` into documentation or version-controlled files.

### 5. Run migrations

Inspect pending migrations first:

```bash
php artisan migrate:status
```

In a confirmed local, test, or development environment, run:

```bash
php artisan migrate
```

In production or an unidentified environment, obtain explicit user approval before running the migration. The package manages these tables:

| Table | Purpose |
| --- | --- |
| `blocked_ips` | Active and historical IP blocks |
| `ip_behaviors` | Per-IP behavior and threat scores |
| `security_events` | Detected threats and request context |
| `crowdsec_audit_logs` | Optional block and unblock audit records |

Do not manually recreate package migrations or edit migration history to hide a failure.

Confirm that `ip_behaviors` includes `request_window_started_at`, `error_404_window_started_at`, and `login_window_started_at`. These fields provide independent fixed windows for request, 404, and login counters.

### 6. Protect selected routes

The default installation must protect selected sensitive routes with the registered alias:

```php
use Illuminate\Support\Facades\Route;

Route::middleware('crowdsec')->group(function () {
    Route::get('/admin', AdminController::class);
    Route::post('/login', [AuthController::class, 'login']);
});
```

Choose real routes from the target application. Prioritize authentication, administration, account, write-heavy API, upload, search, and other abuse-sensitive surfaces. Do not invent controllers or replace the application's existing route structure.

The package registers these aliases:

| Alias | Purpose |
| --- | --- |
| `crowdsec` | WAF detection, blocking, event logging, and behavior tracking |
| `crowdsec.honeypot` | Immediately block access to an intentional trap route |
| `crowdsec.rate:max,minutes` | Apply an IP-based route rate limit, for example `crowdsec.rate:60,1` |

Do not add honeypot routes or new rate limits without confirming that they match the application's routing and traffic expectations.

The route rate limiter returns an actual reset time through `X-RateLimit-Reset` and a matching `Retry-After` value when blocked. Preserve these headers if the target application wraps middleware responses.

### 7. Add global protection only when requested

For Laravel 11 or 12, global middleware belongs in `bootstrap/app.php`:

```php
use Illuminate\Foundation\Configuration\Middleware;
use RiloArbabillah\LaravelCrowdSec\Http\Middleware\CrowdSecProtection;

->withMiddleware(function (Middleware $middleware): void {
    $middleware->append(CrowdSecProtection::class);
})
```

For Laravel 10, add the middleware class to the global `$middleware` array in `app/Http/Kernel.php`:

```php
protected $middleware = [
    // Existing middleware...
    \RiloArbabillah\LaravelCrowdSec\Http\Middleware\CrowdSecProtection::class,
];
```

Before enabling global protection, identify health checks, inbound webhooks, trusted internal callbacks, large uploads, and other routes that may need exclusion or tuning.

Successful authentication resets only the login-attempt counter and its fixed window by default. It must not remove an active block or reset the threat score unless the user explicitly requests that policy and enables `behavior.unblock_on_authentication` or `behavior.reset_threat_score_on_authentication`.

Login POST requests remain subject to WAF inspection. Password fields are excluded by default, while query parameters, paths, headers, cookies, uploads, JWT data, and non-secret body fields remain inspected. Preserve or extend `behavior.login_ignored_fields` when an application uses additional credential field names.

Do not add a manual `trackLoginAttempt()` call to a route already configured in `login_routes`; doing both counts one failed request twice. The middleware allows the configured number of provisional login requests and blocks the following request unless successful authentication resets the window.

When legitimate input triggers a scenario, prefer a narrow `waf.exclusions` rule tied to route name or path, method, scenario, and dotted body field. Use `monitor` mode to validate a scenario against production-like traffic before enforcement. Never disable the complete package to resolve one false positive, and verify that active blocks and behavior thresholds still apply.

## Optional Features

Enable optional features only when requested and only after validating their prerequisites.

| Feature | Enablement | Required checks |
| --- | --- | --- |
| Blocked-IP cache | `CROWDSEC_CACHE_ENABLED=true` | Confirm a working cache store; use a shared store for multiple instances |
| Notifications | `CROWDSEC_NOTIFY_ENABLED=true` | Confirm Laravel mail and/or a Slack webhook; never expose the webhook |
| GeoIP | `CROWDSEC_GEOIP_ENABLED=true` | Review provider privacy and usage terms; confirm outbound access |
| Audit logging | `CROWDSEC_AUDIT_ENABLED=true` | Confirm retention requirements and scheduled cleanup |
| REST API | `CROWDSEC_API_ENABLED=true` | Keep `api` plus an authenticated guard; default is `auth:sanctum` |
| Metrics | `CROWDSEC_METRICS_ENABLED=true` | Keep `auth` or `signed` middleware; confirm monitoring access |
| Dashboard | `CROWDSEC_DASHBOARD_ENABLED=true` | Keep `web` and authenticated middleware |

Run `php artisan crowdsec:doctor` after enabling any optional feature. Do not remove an authentication warning merely to make the doctor command pass.

New configurations use the HTTPS `ipwhois` GeoIP provider. Preserve an application's explicit legacy `ip-api` selection during an unrelated installation, but report the doctor's unencrypted-transport warning and recommend a planned migration to `ipwhois`.

### Notifications

Use placeholders in `.env.example`:

```dotenv
CROWDSEC_NOTIFY_ENABLED=false
CROWDSEC_NOTIFY_CHANNELS=mail
CROWDSEC_NOTIFY_RECIPIENTS=
CROWDSEC_NOTIFY_SLACK_WEBHOOK_URL=
```

### Administrative and observability endpoints

Secure defaults are:

```php
'api' => [
    'enabled' => env('CROWDSEC_API_ENABLED', false),
    'middleware' => ['api', 'auth:sanctum'],
],

'metrics' => [
    'enabled' => env('CROWDSEC_METRICS_ENABLED', false),
    'middleware' => ['web', 'auth'],
],

'dashboard' => [
    'enabled' => env('CROWDSEC_DASHBOARD_ENABLED', false),
    'middleware' => ['web', 'auth'],
],
```

If Sanctum is unavailable, select an authentication guard already used by the target application. Never replace it with an empty middleware list.

## Verification

The installation is incomplete until every applicable check below has been run and reported.

### Package health

```bash
php artisan crowdsec:doctor
```

For machine-readable CI output:

```bash
php artisan crowdsec:doctor --json
```

Treat a non-zero exit code or a failed doctor check as an incomplete installation. Warnings for intentionally disabled optional features may be reported as accepted defaults.

### Database and routes

```bash
php artisan migrate:status
php artisan route:list
```

Confirm that package migrations are complete, protected application routes still exist, and no optional package endpoint is exposed unexpectedly.

### Application tests

Discover and run the target repository's existing test and static-analysis commands. Common Laravel examples are:

```bash
php artisan test
composer test
composer analyse
```

Run only commands supported by the target project. Do not claim success for a command that was unavailable or not executed.

### Manual acceptance checks

When a local environment is available, verify that:

- A normal request to a protected route is not blocked.
- Authentication and other protected workflows still function.
- An enabled dashboard, API, or metrics endpoint requires the configured protection.
- Logs and persisted events do not expose raw secrets or authenticated user IDs.

Do not send destructive attack payloads to a shared, staging, or production environment without explicit authorization.

## Scheduled Maintenance

Confirm that Laravel's scheduler runs in the deployment environment and inspect:

```bash
php artisan schedule:list
```

The package registers expired-ban cleanup daily and old security-event and behavior cleanup weekly. For Laravel 10 installations where package schedules do not appear, add the documented fallback schedules from the [main README](README.md#scheduled-maintenance). Do not register duplicates.

## Failure And Rollback

On failure:

1. Stop at the failed step and preserve diagnostic output.
2. State whether Composer files, configuration, routes, or the database changed before the failure.
3. Do not delete migrations, database tables, user configuration, or unrelated dependencies automatically.
4. Propose the smallest reversible recovery action.
5. Obtain confirmation before rolling back a production migration or removing the package.

If installation must be removed, account for route middleware changes, published configuration, Composer dependencies, and database data separately. `composer remove` does not automatically restore routes or delete package tables.

## Required Handoff

Finish by reporting:

- Detected PHP and Laravel versions
- Compatibility result
- Package version installed
- Commands executed and their exit status
- Files changed, with a short explanation for each
- Routes protected and middleware applied
- Migrations applied or left pending
- Optional features enabled and their protection middleware
- `crowdsec:doctor` result
- Tests and static analysis executed, including failures or skipped checks
- Remaining user actions, operational warnings, and rollback considerations

Do not summarize an installation as successful when a required migration, health check, or relevant application test failed.

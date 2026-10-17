# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **JNDI / Log4Shell detection** — new `jndi_injection` scenario (critical) checks every input, including request headers and the User-Agent, for `${jndi:…}` and obfuscated lookups. It is a new top-level config key, so published configs pick it up automatically
- **Header inspection** — request headers other than the User-Agent, Referer, cookies, Authorization, and standard content headers are inspected by the `header_injection` and `jndi_injection` scenarios
- **Migration `2026_10_17_000000_optimize_crowdsec_indexes.php`** — adds `security_events (event_type, severity)` for the metrics endpoint's grouping and drops two redundant indexes (`security_events.event_type`, covered by the new composite, and `blocked_ips.ip`, covered by the unique index)

### Security

- **Dashboard and API were open to every logged-in user** — any authenticated user could block, unblock, or whitelist IPs and read raw security events. The dashboard and read endpoints now require the `viewCrowdSec` gate and write endpoints `manageCrowdSec`. The package defines both to allow access only in the `local` environment; applications grant access by defining them
- **REST API had no rate limit** — the default `api.middleware` now includes `throttle:60,1`
- **IPv4 addresses matched IPv6 whitelist ranges** — `2001:db8::/32` matched `32.1.13.184` because the CIDR check compared addresses of different lengths. Different address families never match now; IPv4-mapped IPv6 addresses (`::ffff:10.0.0.1`) match IPv4 entries, and IPv6 exact matches ignore notation

### Fixed

- **`crowdsec:cleanup --expired` deleted audit logs** — any selector also ran the audit-log cleanup, so the daily `--expired` schedule pruned audit records. Audit cleanup now runs without selectors or with the new `--audit-logs` option, which has its own daily schedule
- **A new block could shorten a longer one** — `BlockedIp::upsertBlock()` overwrote `expires_at`, so a honeypot hit could cut a 7-day or permanent block to 4 hours. An active block that ends later (or never) keeps its expiry
- **Blocked IPs were re-blocked on the first request after expiry** — the threat score stayed above `threat_score_threshold` through the block, so the next request blocked again at double the duration. Blocking now lowers a score at or above the threshold to half the threshold; `block_count` still drives escalation
- **`HoneypotTrap` blocked whitelisted IPs and could break requests** — it now skips whitelisted IPs and fails open (counter, log, `CrowdSecMiddlewareFailed` event) when blocking fails
- **Dashboard whitelist panel used a hardcoded API path** — it now uses the named `crowdsec.api.whitelist` route
- **Invalid API filters caused server errors** — `events` validates `severity`, `ip`, and `from`; `blocked` validates `ip`; `{ip}` route parameters are constrained
- **WAF evasions** — payloads now also match after `%uXXXX` decoding, a third URL-decoding layer, HTML entity decoding of URL-decoded input, NUL-byte removal, SQL inline-comment removal (`UNION/**/SELECT`), and NFKC normalization of fullwidth characters (with `intl`)
- **Padding past 8 KB hid payloads** — `safeMatch()` truncated input to 8 KB; it now scans overlapping 8 KB chunks up to 64 KB
- **Deeply nested bodies were not inspected** — fields nested deeper than 10 levels were dropped. Flattening now goes 32 levels deep and inspects anything deeper as one JSON string
- **Chunked requests skipped the size check** — `isOversizedRequest()` measures the body when there is no `Content-Length` header
- **Scenario `block_duration` was ignored** — WAF blocks used a duration guessed from the reason text. They now use the longest `block_duration` among the blocking threats' scenarios (new `CrowdSecService::blockDurationForThreats()`), falling back to the severity defaults
- **Admin JWTs were blocked** — `jwt_privilege_escalation` (any token with `role=admin` and similar) defaulted to `enforce`, blocking legitimate admins using bearer tokens. It now defaults to `monitor`; `jwt_payload_*` threats follow their base scenario's mode and exclusions
- **The first blocked-cache invalidation did nothing** — `invalidateAllBlockedCaches()` incremented a missing version key to `1`, the implicit current version, so cached blocks survived the first whitelist change. The key is seeded before it is incremented

### Changed

- API routes are named `crowdsec.api.*`
- `GET /api/crowdsec/check/{ip}` returns only behavior counters (`request_count`, `error_404_count`, `login_attempts`, `threat_score`, `block_count`, `last_activity`) instead of the full row
- **Fewer queries per request** — a clean request takes one `ip_behaviors` lock (5 queries instead of 7 on SQLite); the empty User-Agent score is written in the same lock as the request count instead of two extra locks, and `track404()` takes one lock instead of two. `trackRequest()` accepts an `$additionalThreatScore` argument
- **PCRE limits are set once per WAF pass** — `checkWafPatterns()` lowers `pcre.backtrack_limit`/`pcre.recursion_limit` once and restores them afterwards, instead of four `ini_set()` calls per pattern match

### Upgrade Notes

- **Define the gates before upgrading production.** Outside `local`, the dashboard and API return `403` until the application defines `viewCrowdSec` and `manageCrowdSec`, for example in `AppServiceProvider::boot()`: `Gate::define('viewCrowdSec', fn ($user) => $user->is_admin);`
- Published configs keep their `api.middleware`; add `throttle:60,1` (or your own limiter) manually
- Laravel 10 apps that schedule cleanup in `app/Console/Kernel.php` should add `$schedule->command('crowdsec:cleanup --audit-logs')->daily();` to keep audit retention enforced
- Some WAF block durations change to the scenario's configured value (for example `directory_bruteforce` blocks last 6 hours instead of 4)
- To keep blocking admin-role JWT claims, set `waf.scenario_modes.jwt_privilege_escalation` to `enforce`
- If a header legitimately carries `${…}` lookups, add `jndi_injection` to an exclusion's `skip_scenarios` for that route
- Run `php artisan migrate` for the new index migration

## [1.6.0] - 2026-10-16

### Added

- **Label-driven releases** — the new `Auto Release` workflow releases a merged pull request labelled `release:patch`, `release:minor`, or `release:major` once `Tests` pass on its merge commit: it bumps the version, dates the CHANGELOG section, updates the README, runs the quality gates, and publishes the tag and GitHub Release. `tools/prepare-release.php` does the metadata step locally. The manual `Release` workflow is unchanged

### Fixed

- **WAF detected nothing without a published config** — the service provider never merged the package config, so apps that skipped `vendor:publish` ran with no scenarios or patterns. The provider now calls `mergeConfigFrom()`; published configs also gain top-level keys added in later releases (shallow merge)
- **Filament/Livewire login brute force was not detected** — Livewire logins post to `livewire/update`, which never matched `login_routes`. Failed attempts are now counted from Laravel's `Failed` auth event (`behavior.track_failed_auth_event`, default `true`) and the IP is blocked at `login_threshold`. Path-matched login routes are not double counted, and a manual `trackLoginAttempt()` call for the same IP later in the same request is skipped
- **Passwords triggered WAF blocks** — password fields were only excluded on login routes, so a password such as `a' OR 1=1--` on a Livewire login or a "change password" form blocked the user's IP and was stored in the security event. Fields in the new `waf.sensitive_body_fields` (falling back to the password fields when a published config lacks the key) are excluded on every route, matched by key name including the last segment of dotted keys (`data.password`). Livewire component snapshots are JSON-decoded so the exclusion applies inside them
- **Active admins could hit `request_threshold`** — Filament polling and live fields count toward 500 requests/hour. Authenticated requests are no longer counted (`behavior.skip_authenticated_request_count`, default `true`); WAF and threat scoring still apply
- **Login window reset ran on every authenticated request** — the reset listener now uses Laravel's `Login` event instead of `Authenticated`, removing an `ip_behaviors` query from every request with a session user

### Changed

- Livewire (`X-Livewire`) and JSON requests receive a JSON `403` body (`message`, `ip`). New blocks include a `Retry-After` header
- The middleware reuses the behavior row returned by `trackRequest()` for the threshold check, saving one query per request. `exceedsBehaviorThreshold()` accepts an optional `IpBehavior`
- `CrowdSecService::isLoginRequest()` is now public; `trackRequest()` accepts a `$countRequest` flag

### Upgrade Notes

- Manual `CrowdSec::trackLoginAttempt()` calls after a failed `Auth::attempt()` keep working and are no longer needed; they can be removed
- Code that listened for the package resetting login attempts on `Authenticated` now gets the reset on `Login` only
- For Filament, register the middleware with `appendToGroup('web', ...)` so authenticated users are resolved (see README, "Filament and Livewire")

## [1.5.0] - 2026-09-11

### Fixed

- **`ip_behaviors` deadlocks (MySQL 1213)** — `IpBehavior::withLock()` no longer runs its `INSERT IGNORE` inside the same transaction that takes `SELECT ... FOR UPDATE` on the row. The row is ensured *before* the locking transaction begins, so the insert-intention lock on the unique `ip` key is never held alongside a row lock. This removes the lock cycle that caused concurrent requests for the same IP to deadlock, which previously made the middleware fail open and silently skip protection
- **Consistent lock ordering** — block writes now always lock `ip_behaviors` before `blocked_ips`, and `blocked_ips` is written with an atomic upsert (`INSERT ... ON DUPLICATE KEY UPDATE` / `ON CONFLICT`) instead of `updateOrCreate()`'s `SELECT + INSERT/UPDATE`, eliminating the gap lock that contributed to the deadlock

### Added

- **Single-acquisition request tracking** — `CrowdSecService::trackRequest()` and `IpBehavior::mutateLocked()` consolidate a request's request count, login attempt, and cumulative threat score into one `ip_behaviors` lock acquisition (previously two to three). The middleware now uses this on the request path
- **Deadlock-aware retries** — `IpBehavior::isRetryableLockError()` classifies serialization failures (`SQLSTATE 40001`, MySQL `1213`/`1205`, PostgreSQL `40P01`); retries run up to five times with exponential backoff and jitter and never retry logic errors
- **Fail-open observability** — every fail-open now increments the `crowdsec_middleware_failed` counter (surfaced as `crowdsec_middleware_failed_total` on the metrics endpoint), logs structured error/transaction context, and dispatches a new `CrowdSecMiddlewareFailed` event for alerting
- **Migration `2026_09_11_000000_add_unique_index_to_blocked_ips_ip.php`** — adds a unique index on `blocked_ips.ip`, which the atomic block upsert requires. Existing deployments must run `php artisan migrate`
- **Concurrency and regression tests** — real parallel-process concurrency coverage against MySQL/PostgreSQL, a regression test asserting the ensure-exists insert runs outside the locking transaction, single-lock tracking assertions, and fail-open observability tests

### Upgrade Notes

- Run `php artisan migrate` to apply the new `2026_09_11_000000_add_unique_index_to_blocked_ips_ip.php` migration, which adds the unique index on `blocked_ips.ip` required by the atomic block upsert. If a deployment already contains duplicate `blocked_ips` rows for the same IP, they must be reconciled before the unique index can be created
- Public APIs are preserved (`trackBehavior`, `trackLoginAttempt`, `addThreatScoreFromThreats`, `withLock`). Existing counters and blocks continue to work; the change is transparent to callers
- Add a monitoring alert on a rising `crowdsec_middleware_failed_total`. A non-zero value means the middleware failed open and protection was skipped at least once

## [1.4.0] - 2026-08-29

### Added

- **Dynamic IP Whitelist** — new `whitelisted_ips` table plus `crowdsec:whitelist` Artisan command, `GET/POST/DELETE /api/crowdsec/whitelist` REST endpoints, and a dashboard tab let trusted IPs be added or removed at runtime without editing `config/crowdsec-scenarios.php`
- **Hybrid Whitelist Lookup** — `isWhitelisted()` now checks both the static `whitelist_ips` config and the DB layer, so existing deployments keep their defaults while gaining dynamic control
- **Whitelist Expiration** — DB entries support `expires_at` for time-boxed access (e.g. contractor), with a daily `crowdsec:whitelist purge-expired` scheduled task
- **Whitelist Audit Trail** — every add/remove is recorded in `crowdsec_audit_logs` with `action='whitelist_modified'` when audit logging is enabled
- **Whitelist Health Check** — `crowdsec:doctor` now reports combined config + DB counts and warns on dynamic entries with no label or note

### Changed

- **Whitelist Performance** — DB lookups follow the same opt-in caching pattern as blocked IPs (30s TTL when `cache.enabled=true`, immediate otherwise)
- **README** — new "Dynamic IP Whitelist" section with CLI, API, and programmatic examples

### Upgrade Notes

- A new migration (`2026_08_28_000000_create_whitelisted_ips_table.php`) must be applied; existing deployments should run `php artisan migrate`
- The dynamic whitelist layer is additive: existing static `whitelist_ips` entries continue to apply, and no behavior changes for previously whitelisted IPs
- Audit logging of whitelist changes is gated by `audit.enabled`; no new audit records are written when audit logging is disabled

## [1.3.0] - 2026-07-19

### Added

- **Accuracy Corpus** — a versioned WAF corpus verifies all 15 attack categories and representative legitimate Laravel requests
- **Database Compatibility CI** — dedicated MySQL 8.4 and PostgreSQL 16 jobs validate migrations, block escalation, audit records, and independent behavior windows
- **Coverage Gate** — PCOV and a repository-owned Clover validator enforce at least 85% source line coverage in CI

### Changed

- **Static Analysis** — Larastan/PHPStan now runs at level 6 with typed model scopes, service arrays, GeoIP results, event context, notifications, and facade contracts
- **Test Workflow** — performance benchmarks move out of the default test suite into the explicit `composer benchmark` command and a dedicated CI job
- **Database Test Harness** — package tests can select SQLite, MySQL, or PostgreSQL through isolated `TEST_DB_*` environment variables

### Fixed

- **Root Git Probe Detection** — `/.git/config` is now detected by the directory-bruteforce scenario in addition to nested `.git` paths

### Upgrade Notes

- No database migration or application configuration change is required
- Existing public facade, middleware, event, route, and model behavior remains compatible
- Contributors should use `composer test`, `composer analyse`, and `composer benchmark` as separate quality checks

## [1.2.0] - 2026-07-19

### Added

- **WAF Policy Controls** — scenarios support `enforce`, `monitor`, and `disabled` modes plus route, path, method, scenario, and dotted body-field exclusions
- **HTTPS GeoIP Provider** — new `ipwhois` provider is the default for newly published configuration while legacy `ip-api` and custom callbacks remain supported
- **Release Automation** — a guarded manual workflow validates metadata and CI before creating an annotated tag and GitHub Release from the changelog

### Changed

- **PHP 8.4 Validation** — CI now covers PHP 8.4 across Laravel 10, 11, and 12
- **Threat Contract** — detected threat arrays include an additive `mode` field, and monitored events use the `monitored` action without scoring or blocking
- **GeoIP Cache Isolation** — cached lookups are separated by provider and all provider responses are normalized to the existing result shape

### Fixed

- **Login Threshold Semantics** — the configured allowance is processed before the following request is blocked, and provisional middleware tracking no longer raises threat score for a potentially valid login
- **Notification Deduplication** — alert cooldown acquisition is atomic and is only consumed when a usable notification route exists
- **Release Metadata** — stable-version documentation is synchronized and guarded against future README/CHANGELOG mismatches

### Security

- **Narrow False-Positive Tuning** — exclusions affect only selected WAF scenarios or body fields and never bypass active blocks or behavior protection
- **GeoIP Transport Privacy** — the default provider now uses HTTPS; the doctor command warns when the legacy HTTP provider is enabled

### Upgrade Notes

- No database migration is required for this release
- Existing published configuration remains compatible; `ipwhois` becomes the default only when publishing a new configuration
- Existing `ip-api` installations continue to work but receive a doctor warning because that legacy provider uses unencrypted HTTP
- Threat arrays include a new additive `mode` field; consumers that ignore unknown keys require no changes
- Applications that both protect a configured `login_routes` path and call `trackLoginAttempt()` manually should keep only one tracking mechanism to avoid double counting

## [1.1.1] - 2026-07-18

### Added

- **Independent Behavior Windows** — request, 404, and login counters now use dedicated fixed-window timestamps with configurable 60/60/5 minute defaults
- **AI Installation Contract** — a separate repository-aware installation guide documents secure defaults, migration checks, and verification requirements for coding agents

### Changed

- **Authentication Defaults** — successful authentication resets only the login counter and window; automatic unblocking and threat-score resets are explicit opt-ins
- **Login Inspection** — login requests remain subject to WAF analysis while configured password fields, including nested fields, are excluded from body inspection
- **Route Rate Limiting** — `crowdsec.rate` uses Laravel's atomic rate limiter and reports actual `Retry-After` and `X-RateLimit-Reset` values
- **Quality Gates** — Larastan/PHPStan level 5 covers all source and route files, and CI explicitly maps Laravel 10/11/12 to compatible Testbench versions

### Fixed

- **Concurrent Behavior Updates** — per-IP counters, threat scores, and progressive block escalation are serialized to prevent lost updates under concurrent requests
- **Window Expiration** — behavior thresholds are evaluated against their own fixed-window start instead of unrelated recent activity
- **Block Duration Accessor** — block duration remains an integer under Carbon 3

### Security

- **Secret-Aware Login WAF** — query parameters, paths, headers, cookies, uploads, JWT data, and non-secret login fields remain inspected without scanning configured credentials
- **Secure Reauthentication** — an existing security block or threat score is no longer cleared merely because authentication succeeds

## [1.1.0] - 2026-07-14

### Added

- **Security Event Context** — detected threats now record request IDs, routes, content metadata, response status, duration, enforcement action, country/ASN/ISP, HMAC user identity, and parsed browser/OS/device type
- **Event Filters and Dashboard Insights** — enriched event fields are filterable through the REST API and visible in SIEM exports, recent events, top countries, and device breakdowns

### Changed

- **GeoIP Contract** — ip-api and custom providers now support normalized ASN data and a configurable lookup timeout
- **SIEM Export** — JSON, CSV, and Syslog include enrichment fields while preserving the existing CSV column order prefix

### Security

- **Sensitive Data Redaction** — configured query secrets plus cookie and authorization match values are redacted before database persistence or export
- **Pseudonymous User Correlation** — authenticated user identifiers are stored only as HMAC-SHA256 hashes
- **Telemetry Isolation** — event persistence/enrichment failures no longer weaken blocking decisions, and downstream requests are never invoked twice

## [1.0.2] - 2026-04-06

### Fixed

- **Packagist README** — align the published README copy with the current stable release metadata and Laravel 10/11/12 support

## [1.0.1] - 2026-04-05

### Added

- **Laravel 12 Compatibility** — package constraints and CI matrix now cover Laravel 10.x/11.x/12.x
- **Audit Log Compliance Trail** — immutable audit log records for block and unblock actions
- **Doctor Command** — `crowdsec:doctor` health check for configuration and production readiness
- **Metrics Endpoint** — Prometheus/OpenMetrics export for operational monitoring
- **Static Analysis Gate** — `composer analyse` plus a dedicated GitHub Actions quality job

### Changed

- **Optional Endpoint Defaults** — API, metrics, and dashboard now default to authenticated middleware
- **Release Docs** — README, PRD, and progress notes now distinguish the published Packagist tag from the active maintenance branch
- **Cleanup Behavior** — `crowdsec:cleanup` now prunes audit logs based on `audit.retention_days`

### Fixed

- **Slack Notifications** — on-demand alerts now route correctly through configured mail and Slack channels
- **Metrics Tests** — fixtures now match the current schema and model contracts
- **Audit Retention** — configured audit retention is now enforced instead of remaining a docs-only setting

## [1.0.0] - 2026-03-11

### Added

- **WAF Pattern Detection** — 15 attack types with 100+ regex patterns
  - SQL Injection, XSS, Path Traversal, Command Injection
  - SSRF, XXE, NoSQL Injection, LDAP Injection, SSTI
  - Open Redirect, File Inclusion, PHP Serialization
  - Directory Bruteforce, Header Injection, Suspicious User Agent
- **IP Blocking** — temporary blocks with automatic expiration
- **Progressive Escalation** — block duration doubles per re-offense (max 7 days)
- **Behavior Tracking** — request rate, 404 errors, login attempts, threat score
- **Multi-Layer Decoding** — URL decode (single/double) + HTML entity decode
- **IP Whitelist** — exact match + CIDR notation support
- **Login Route Detection** — brute-force protection for configured login routes
- **Caching Layer** — cached blocked IP lookups via Laravel Cache (PR #22)
- **Event System** — 4 Laravel events: ThreatDetected, IpBlocked, IpUnblocked, BehaviorThresholdExceeded (PR #25)
- **Notification Support** — email/Slack alerts with severity filtering and rate limiting (PR #26)
- **IP Threat Score Decay** — gradual score reduction for inactive IPs (PR #24)
- **Scheduled Cleanup** — auto-registration of cleanup commands (PR #23)
- **Custom Pattern Plugin** — `registerScenario()` for runtime pattern registration (PR #27)
- **Honeypot Route Trap** — `crowdsec.honeypot` middleware for scanner detection (PR #28)
- **Per-Route Rate Limiting** — `crowdsec.rate:60,1` middleware (PR #29)
- **SIEM Export** — `crowdsec:export` command with JSON, CSV, Syslog (RFC 5424) formats (PR #30)
- **GeoIP Lookup** — ip-api.com provider with 24h caching (PR #31)
- **REST API** — 6 endpoints for programmatic management (PR #32)
- **Admin Dashboard** — standalone Blade dashboard with dark theme (PR #33)
- **CLI Commands** — `crowdsec:stats`, `crowdsec:cleanup`, `crowdsec:export`
- **Facade API** — `CrowdSec::blockIp()`, `isBlocked()`, `unblockIp()`, `analyzeRequest()`
- **Auto-Migration** — 3 database tables created automatically
- **GitHub Actions CI** — PHP 8.1/8.2/8.3 × Laravel 10.x/11.x matrix (PR #18)

### Security

- **ReDoS Protection** — `safeMatch()` wrapper with pcre.backtrack_limit=10,000 and 8KB input truncation (PR #43)
- **Tightened Patterns** — replaced risky `.*` quantifiers with bounded `[^x]{0,200}` alternatives
- **Fail-Open Design** — WAF errors never crash the application

### Testing

- 136 tests with 202 assertions
- 27 unit tests, 22 integration tests, 20 edge case tests
- 8 performance benchmarks (all <1ms)
- 45 new feature tests (PR #42)
- 14 ReDoS resistance tests (PR #43)

## [1.0.0-alpha] - 2026-03-08

### Added

- Initial release with core WAF detection (12 attack types)
- IP blocking with expiration
- Behavior tracking
- CLI commands (stats, cleanup)
- Facade API
- 27 unit tests

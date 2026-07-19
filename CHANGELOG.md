# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

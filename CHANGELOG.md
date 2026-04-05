# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Static Analysis Gate** — `composer analyse` plus a dedicated GitHub Actions quality job

### Changed

- **Laravel Compatibility** — current `master` branch now tests against Laravel 10.x/11.x/12.x
- **Optional Endpoint Defaults** — API, metrics, and dashboard now default to authenticated middleware
- **Release Docs** — README, PRD, and progress notes now distinguish the published `1.0.0` tag from the current `1.0.x` maintenance branch

### Fixed

- **Slack Notifications** — on-demand alerts now route correctly through configured mail and Slack channels
- **Metrics Tests** — fixtures now match the current schema and model contracts

> Note: The latest Packagist stable tag is still `1.0.0`. Laravel 12 compatibility and the changes listed in `Unreleased` are currently available on `master` and will ship in the next `1.0.x` tag.

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

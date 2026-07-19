# 📊 Project Progress — Laravel CrowdSec

> Last updated: 19 Jul 2026
> **Test suite:** 267 passed (525 assertions), plus 8 dedicated performance benchmarks
> **Next focus:** validate `v1.3.0` quality gates on GitHub Actions and monitor the accuracy corpus

---

## ✅ Completed

### Core Engine

- [x] `CrowdSecService` — main detection engine with multi-layer decoding
- [x] `CrowdSecProtection` middleware — 10-step request processing pipeline
- [x] Fail-open error handling (WAF error tidak crash aplikasi)
- [x] Enable/disable via `CROWDSEC_ENABLED` env variable
- [x] `isWhitelisted()` method on service (exact + CIDR matching)

### Pattern Detection (15 Attack Types)

- [x] SQL Injection (UNION, OR 1=1, stacked queries, SLEEP, BENCHMARK)
- [x] XSS (script tag, javascript:, event handlers, SVG, base hijack)
- [x] Path Traversal (../, encoded variants, null byte)
- [x] Command Injection (shell separators, backtick, $(), reverse shell)
- [x] File Inclusion (PHP wrappers: php://, phar://, data://)
- [x] PHP Serialization Attack (object injection, magic methods)
- [x] Directory Bruteforce (.git, .env, wp-admin, phpinfo, etc.)
- [x] Header Injection (CRLF, Location header)
- [x] Suspicious User Agent (sqlmap, nikto, nmap, burpsuite, etc.)
- [x] SSRF (AWS metadata, localhost, file://, gopher://)
- [x] XXE (<!ENTITY, <!DOCTYPE SYSTEM, XInclude)
- [x] NoSQL Injection (MongoDB operators: $ne, $gt, $where)
- [x] LDAP Injection (filter injection, DN injection)
- [x] SSTI (Jinja2 {{7*7}}, **class**, {%import%})
- [x] Open Redirect (redirect params with external URL)

### Multi-Layer Decoding

- [x] Single URL decode
- [x] Double URL decode (bypass %2527 → %27 → ')
- [x] HTML entity decode

### IP Management

- [x] IP blocking dengan expiration time
- [x] Progressive escalation (2x durasi per re-offense, max 7 hari)
- [x] IP unblocking (manual via Facade)
- [x] IP whitelist (exact match + CIDR notation)
- [x] Block count tracking per IP
- [x] **Caching layer** — cached blocked IP lookups (configurable TTL, store)

### Behavior Analysis

- [x] Request rate tracking per IP (threshold: 500/jam)
- [x] 404 error tracking (threshold: 15/jam)
- [x] Login attempt tracking (threshold: 5/5 menit)
- [x] Cumulative threat score (threshold: 50, max: 100)
- [x] Login route auto-detection (configurable routes)
- [x] **Threat score decay** — auto-decay berdasarkan inactivity (`decayThreatScore`, `applyDecayAll`)
- [x] Independent fixed windows — request 60 menit, 404 60 menit, dan login 5 menit
- [x] Atomic per-IP counter dan threat-score updates dengan transaction locking
- [x] Login WAF tetap memeriksa query dan field body non-secret
- [x] Autentikasi sukses hanya mereset login window secara default; unblock dan threat reset opt-in
- [x] Login threshold mengizinkan configured allowance dan memblokir request berikutnya
- [x] Provisional middleware login tracking tidak menambah threat score

### Data Layer

- [x] `blocked_ips` table — IP blocks with expiration
- [x] `ip_behaviors` table — per-IP behavior metrics
- [x] `security_events` table — security event logs
- [x] Security event context — request/route/content, response/action/duration, GeoIP/ASN, HMAC user, browser/OS/device
- [x] Sensitive query, referer, cookie, authorization, dan matched-source redaction
- [x] Auto-migration (no manual setup)
- [x] Database indexes for performance

### Eloquent Models

- [x] `BlockedIp` — scopes: active, expired, notExpired, expiringSoon
- [x] `IpBehavior` — scopes: highThreat, activeRecently + cleanup + decay methods
- [x] `SecurityEvent` — scopes: recent, byType, bySeverity, byIp

### CLI Commands

- [x] `crowdsec:stats` — active blocks, events, top attackers (table + JSON)
- [x] `crowdsec:cleanup` — expired bans, old events, old behaviors, dry-run
- [x] **`crowdsec:export`** — SIEM-compatible export (JSON, CSV, Syslog RFC 5424)

### Event System

- [x] `ThreatDetected` — fired saat threat terdeteksi (IP, threats, severity, request)
- [x] `IpBlocked` — fired saat IP di-block (IP, reason, duration, block count)
- [x] `IpUnblocked` — fired saat IP di-unblock
- [x] `BehaviorThresholdExceeded` — fired saat behavior threshold tercapai
- [x] Events dispatched dari `CrowdSecService` dan `CrowdSecProtection`

### Notification Support

- [x] `SecurityAlertNotification` — mail, Slack, array channels (ShouldQueue)
- [x] `SendSecurityAlert` listener — severity filtering + rate limiting
- [x] Konfigurasi: channels, severity threshold, rate limit, recipients
- [x] Atomic notification cooldown dengan `Cache::add()` setelah route tervalidasi

### Honeypot Routes

- [x] `HoneypotTrap` middleware — block semua request ke trap routes
- [x] Default routes: `.env`, `wp-admin`, `wp-login.php`, `phpmyadmin`, `.git/config`, dll.
- [x] Middleware alias: `crowdsec.honeypot`

### Rate Limiting

- [x] `CrowdSecRateLimit` middleware — per-route rate limiting
- [x] Configurable max attempts dan decay window via middleware params
- [x] Returns 429 with `Retry-After` dan `X-RateLimit-*` headers
- [x] Middleware alias: `crowdsec.rate:60,1` (60 req per 1 min)
- [x] Laravel atomic `RateLimiter` dengan `Retry-After` dan `X-RateLimit-Reset` aktual

### Custom Patterns

- [x] `registerScenario()` — register custom detection scenario at runtime
- [x] `getScenarios()` — list all registered scenarios (built-in + custom)
- [x] WAF mode per scenario: `enforce`, `monitor`, dan `disabled`
- [x] Granular exclusions berdasarkan route name, path, method, scenario, dan dotted body field
- [x] Monitor events dicatat tanpa threat score atau blocking

### GeoIP Integration

- [x] `GeoIpService` — IP geolocation lookup
- [x] `ip-api.com` provider (free, no API key required)
- [x] HTTPS `ipwho.is` provider sebagai default konfigurasi baru
- [x] Legacy `ip-api` warning dan provider-specific cache keys
- [x] Result caching (24h default)
- [x] Custom callback provider support
- [x] Private IP detection (skip lookup)
- [x] ASN/ISP enrichment + configurable provider timeout

### REST API Endpoints

- [x] `GET /api/crowdsec/stats` — overview statistics
- [x] `GET /api/crowdsec/events` — list events (filter: severity, ip, from, request ID, route, action, status, country, ASN, user hash)
- [x] `GET /api/crowdsec/blocked` — list blocked IPs
- [x] `POST /api/crowdsec/block` — block an IP
- [x] `DELETE /api/crowdsec/block/{ip}` — unblock an IP
- [x] `GET /api/crowdsec/check/{ip}` — check IP status
- [x] Configurable middleware (default: `api`, `auth:sanctum`)
- [x] Disabled by default (enable via `CROWDSEC_API_ENABLED`)

### Admin Dashboard

- [x] `/crowdsec` — standalone dark theme dashboard (Blade, no external CSS)
- [x] Stats cards (events today, this week, active blocks, high threat IPs)
- [x] Recent events table (IP, type, action, status, country, client, time)
- [x] Blocked IPs table (IP, reason, expires)
- [x] Top attackers table (last 24h)
- [x] Threat breakdown by severity (last 7 days)
- [x] Top source countries + device type breakdown (last 7 days)
- [x] Disabled by default (enable via `CROWDSEC_DASHBOARD_ENABLED`)
- [x] Publishable views via `crowdsec-views` tag

### Scheduled Cleanup

- [x] Auto-registered via `callAfterResolving(Schedule::class)` (Laravel 11+)
- [x] Expired bans cleanup: daily
- [x] Old events/behaviors cleanup: weekly
- [x] Laravel 10 fallback documented in PHPDoc

### Developer API

- [x] `CrowdSec` Facade (auto-discovered)
- [x] `CrowdSecServiceProvider` (auto-registered)
- [x] Publishable config: `vendor:publish --tag=crowdsec-config`
- [x] Publishable views: `vendor:publish --tag=crowdsec-views`

### Configuration

- [x] Per-scenario config (patterns, weight, severity, block_duration)
- [x] Behavior thresholds (request, 404, login, threat score)
- [x] Block duration defaults per severity level
- [x] Whitelist IPs (array, supports CIDR)
- [x] Login routes (configurable list)
- [x] Blocked HTTP methods (TRACE, CONNECT)
- [x] Max content length
- [x] Block empty User-Agent toggle
- [x] Custom blocked response message
- [x] Custom log channel
- [x] Cache config (enabled, store, TTL, prefix)
- [x] Notifications config (enabled, channels, severity threshold, rate limit, recipients)
- [x] Honeypot routes config
- [x] GeoIP config (enabled, provider, cache TTL, custom callback)
- [x] Event context config (request ID, UA parsing, HMAC user, sensitive parameter redaction)
- [x] API config (enabled, middleware)
- [x] Dashboard config (enabled, path, middleware)
- [x] WAF policy config (default mode, scenario overrides, granular exclusions)

### CI/CD

- [x] GitHub Actions CI pipeline (`.github/workflows/tests.yml`)
- [x] Matrix eksplisit Laravel 10/Testbench 8, Laravel 11/Testbench 9, Laravel 12/Testbench 10
- [x] PHP 8.4 matrix untuk Laravel 10/11/12
- [x] Composer dependency caching
- [x] SQLite for the Laravel/PHP compatibility matrix
- [x] Dedicated MySQL 8.4 and PostgreSQL 16 database compatibility jobs
- [x] Minimum 85% source line coverage gate dengan PCOV dan Clover
- [x] Dedicated quality gate untuk Composer audit dan Larastan/PHPStan level 6 seluruh source
- [x] Guarded manual release workflow (metadata, CI, tag, dan GitHub Release)

### Testing

- [x] 31 unit test cases (PHPUnit + release metadata validator)
- [x] 22 integration test cases (`CrowdSecMiddlewareTest` — full 10-step pipeline)
- [x] 20 edge case tests (`EdgeCaseTest` — CIDR, escalation, body analysis, etc.)
- [x] 8 dedicated performance benchmarks via `composer benchmark` (all < 1ms target)
- [x] Versioned WAF accuracy corpus: 15 malicious + 20 benign samples
- [x] Expanded feature, doctor, metrics, and notification coverage for v1 hardening
- [x] Security event context coverage (enforcement, privacy, API, export, GeoIP, UA, HMAC)
- [x] 10 reliability hardening tests (fixed windows, nested login inspection, auth defaults, rate limiting)
- [x] WAF policy, GeoIP HTTPS, release validator, login semantics, dan atomic notification coverage
- [x] Total functional suite: **267 tests, 525 assertions**

### Documentation

- [x] README.md lengkap (installation, usage, config, benchmarks, CI badge)
- [x] PRD.md — Product Requirements Document
- [x] PROGRESS.md — Project progress tracking
- [x] README_AI.md — kontrak instalasi package untuk coding agent

---

## ⬜ To Do

### Next Steps

- [x] **Validate the full CI matrix** — Laravel 10/11/12 compatibility passed on GitHub Actions
- [x] **Tag `v1.1.1`** — publish reliability hardening after CI succeeds
- [x] **Validate `v1.2.0` on GitHub Actions** — PHP 8.4 and all Laravel compatibility jobs passed
- [x] **Prepare `v1.2.0` release metadata** — stable README, CHANGELOG, PRD, and progress metadata synchronized
- [x] **Prepare `v1.3.0` production hardening** — coverage, accuracy corpus, database matrix, PHPStan level 6, and benchmark isolation

### Future Enhancements (v1.1+)

- [ ] **Distributed blocklist** — share blocklist antar instance
- [ ] **Bot detection (CAPTCHA)** — CAPTCHA challenge untuk suspicious IPs
- [ ] **CrowdSec API integration** — integrate dengan real CrowdSec ecosystem

---

## 📈 Stats

| Metric                 | Value      |
| ---------------------- | ---------- |
| Total source files     | 30         |
| Total lines of code    | ~4,500     |
| Attack types detected  | 15         |
| Regex patterns         | 100+       |
| Unit tests             | 31         |
| Integration tests      | 22         |
| Edge case tests        | 20         |
| Performance benchmarks | 8          |
| **Functional tests**   | **267**    |
| Test assertions        | 525        |
| Laravel compatibility  | 10.x, 11.x, 12.x |
| PHP minimum            | 8.1        |
| Package status         | v1.3.0 stable release |
| CI quality gates       | PHPUnit + 85% coverage + MySQL/PostgreSQL + PHPStan level 6 + Composer audit |

---

## 📝 Git History

```
451daeb  feat: harden production quality gates
6cd511d  ci: upgrade checkout action to v7
563296c  docs: prepare v1.2.0 release
abb00b9  feat: add configurable WAF policy controls
b4f2401  docs: prepare v1.1.1 release
37bd253  fix: harden behavior tracking reliability
1271b68  docs: add AI installation guide
0430a1a  docs: fix Packagist license badge
7e6b336  docs: modernize project readme
b441a22  chore: remove release notes temp file
c0b5f0c  docs: prepare v1.1.0 release
f2461d7  feat: enrich security events with client context
793c222  chore: remove release notes temp file
d6d81e0  docs: sync Packagist README for 1.0.2
3f32562  chore: remove release notes temp file
2773058  docs: prepare 1.0.1 release notes
e76d4e4  fix: enforce audit retention cleanup (#55) (#66)
cb07b44  chore: align release docs for v1 (#56) (#65)
d517a26  chore: add static analysis quality gate (#60) (#64)
6ef3079  fix: harden optional endpoint defaults (#57) (#63)
e903852  fix: wire Slack notifications end-to-end (#58) (#62)
0e78512  fix: align metrics test fixtures (#59) (#61)
f7c24a6  feat: add request body deep inspection (#46) (#54)
481d5d2  feat: add immutable audit log for compliance (#49) (#53)
d84aea6  feat: add Prometheus/OpenMetrics metrics endpoint (#48) (#52)
a39ae19  feat: add crowdsec:doctor health check command (#50) (#51)
cf4ec0b  chore: add LICENSE, .gitattributes, update composer.json for Packagist
91ed2b0  feat: add Laravel 12 compatibility support (#35) (#45)
22bfaa3  chore: prepare v1.0.0 stable release (#38) (#44)
b5ab47c  security: audit regex patterns for ReDoS vulnerability (#37) (#43)
```

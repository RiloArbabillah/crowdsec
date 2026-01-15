# Laravel CrowdSec

[![PHP Version](https://img.shields.io/packagist/php-v/rilo-arbabillah/laravel-crowdsec.svg)](https://packagist.org/packages/rilo-arbabillah/laravel-crowdsec)
[![Laravel Version](https://img.shields.io/packagist/dependency-v/rilo-arbabillah/laravel-crowdsec/laravel.svg)](https://laravel.com)
[![License](https://img.shields.io/packagist/license/rilo-arbabillah/laravel-crowdsec.svg)](LICENSE)

A lightweight, CrowdSec-like Web Application Firewall (WAF) protection package for Laravel applications. This package provides real-time threat detection and IP blocking based on WAF patterns and behavior analysis.

## Features

- **WAF Pattern Detection**: Detects SQL injection, XSS, path traversal, command injection, and more
- **IP Blocking**: Temporary IP blocks with automatic expiration
- **Behavior-based Protection**: Rate limiting and brute-force detection
- **Security Logging**: Records all security events for analysis
- **CLI Commands**: Statistics and cleanup utilities
- **Facade API**: Easy programmatic access to all features
- **Auto-migrations**: Database tables created automatically

## Requirements

- PHP ^8.1
- Laravel ^10.0 or ^11.0
- MySQL/PostgreSQL/SQLite (any Laravel-supported database)

## Installation

Install the package via Composer:

```bash
composer require rilo-arbabillah/laravel-crowdsec
```

The package will automatically register its service provider and facade.

## Configuration

Publish the configuration file to customize detection scenarios and thresholds:

```bash
php artisan vendor:publish --tag=crowdsec-config
```

This will create `config/crowdsec-scenarios.php` where you can:

- Enable or disable the package
- Configure detection patterns for each attack type
- Adjust behavior thresholds (request limits, 404 limits, login attempts)
- Set block durations per severity
- Whitelist IPs that should never be blocked

### Enabling/Disabling the Package

You can toggle the package on or off via configuration:

```php
// config/crowdsec-scenarios.php

return [
    // Enable or disable the entire package
    'enabled' => true,  // Set to false to disable all protection

    // ... rest of configuration
];
```

When disabled, the middleware will pass all requests through without any filtering or blocking. This is useful for:

- Development environments where you need to test without WAF interference
- Debugging specific issues without protection blocking legitimate traffic
- Temporary maintenance windows

### Default Configuration

```php
// config/crowdsec-scenarios.php

return [
    // Enable/disable the package
    'enabled' => true,

    // Whitelist IPs (won't be blocked)
    'whitelist_ips' => [
        '127.0.0.1',
        '::1',
    ],

    // Behavior thresholds
    'behavior' => [
        'request_threshold' => 500,      // requests per minute
        '404_threshold' => 15,           // 404s per minute
        'login_threshold' => 5,          // login attempts per minute
        'threat_score_threshold' => 50,
        'block_duration' => 240,         // 4 hours
        'severity' => 'high',
    ],

    // Block duration defaults (in minutes)
    'defaults' => [
        'low' => 60,
        'medium' => 240,
        'high' => 720,
        'critical' => 1440,
    ],

    // ... detection patterns
];
```

## Basic Usage

### Applying Middleware to Routes

Apply the middleware to individual routes:

```php
use Illuminate\Support\Facades\Route;

Route::middleware(['crowdsec'])->group(function () {
    Route::get('/admin', function () {
        // Protected route
    });

    Route::post('/login', [AuthController::class, 'login']);
});
```

### Applying Middleware Globally

Add the middleware to your HTTP kernel for global protection:

```php
// app/Http/Kernel.php

protected $middlewareAliases = [
    // ...
    'crowdsec' => \RiloArbabillah\LaravelCrowdSec\Http\Middleware\CrowdSecProtection::class,
];
```

Then apply to routes or route groups:

```php
// Protect all web routes
Route::middleware(['crowdsec'])->group(base_path('routes/web.php'));

// Protect API routes
Route::middleware(['api', 'crowdsec'])->group(base_path('routes/api.php'));
```

### Skipping Middleware for Certain Routes

```php
// Disable for health check endpoints
Route::middleware(['crowdsec'])->group(function () {
    Route::get('/admin', function () {
        // Protected
    });
});

Route::get('/health', function () {
    // Not protected
})->withoutMiddleware(['crowdsec']);
```

## Programmatic Usage

Use the `CrowdSec` facade for programmatic control:

### Check if IP is Blocked

```php
use RiloArbabillah\LaravelCrowdSec\Facades\CrowdSec;

$ip = request()->ip();

if (CrowdSec::isBlocked($ip)) {
    abort(403, 'Your IP has been blocked');
}
```

### Manually Block an IP

```php
use RiloArbabillah\LaravelCrowdSec\Facades\CrowdSec;

// Block for 60 minutes
CrowdSec::blockIp($request->ip(), 'Manual ban - spam', 60);

// Block for 24 hours (default for critical threats)
CrowdSec::blockIp($request->ip(), 'Suspicious activity', 1440);
```

### Unblock an IP

```php
use RiloArbabillah\LaravelCrowdSec\Facades\CrowdSec;

CrowdSec::unblockIp($ip);
```

### Track Login Attempts

Call this after failed login attempts for brute-force protection:

```php
use RiloArbabillah\LaravelCrowdSec\Facades\CrowdSec;

public function login(Request $request)
{
    if (! Auth::attempt($credentials)) {
        // Track failed attempt
        CrowdSec::trackLoginAttempt($request->ip());

        return back()->withErrors(['email' => 'Invalid credentials']);
    }

    // Reset login attempts on successful login
    // (optional - you could implement this)

    return redirect('/dashboard');
}
```

### Analyze Request for Threats

```php
use RiloArbabillah\LaravelCrowdSec\Facades\CrowdSec;

$threats = CrowdSec::analyzeRequest($request);

if (! empty($threats)) {
    foreach ($threats as $threat) {
        \Log::warning('Security threat detected', [
            'type' => $threat['type'],
            'severity' => $threat['severity'],
            'matched' => $threat['matched'],
        ]);
    }
}
```

## CLI Commands

### View Protection Statistics

```bash
php artisan crowdsec:stats
```

Output includes:
- Active blocked IPs
- Expired blocked IPs
- Events today
- Events this week
- Top attackers (IP addresses)

For JSON output (useful for monitoring):

```bash
php artisan crowdsec:stats --json
```

### Clean Up Expired Bans

Remove expired IP blocks and old security events:

```bash
php artisan crowdsec:cleanup
```

#### Cleanup Options

```bash
# Preview what would be deleted (no changes)
php artisan crowdsec:cleanup --dry-run

# Clean only expired bans
php artisan crowdsec:cleanup --expired

# Clean only old events (older than 30 days)
php artisan crowdsec:cleanup --old-events

# Clean only old behaviors (older than 7 days)
php artisan crowdsec:cleanup --old-behaviors
```

#### Automated Cleanup in Production

Add to your `routes/console.php` or set up a scheduled command:

```php
// In routes/console.php
Artisan::command('crowdsec:daily-cleanup', function () {
    $this->call('crowdsec:cleanup', ['--expired' => true]);
})->purpose('Clean up expired bans daily');
```

Or use Laravel's scheduler:

```php
// In app/Console/Kernel.php
protected function schedule(Schedule $schedule)
{
    $schedule->command('crowdsec:cleanup --expired')->daily();
}
```

## Database

The package creates three tables automatically via migrations:

| Table | Description |
|-------|-------------|
| `blocked_ips` | Tracks blocked IPs with expiration and reason |
| `ip_behaviors` | Tracks per-IP metrics (request count, 404s, login attempts, threat score) |
| `security_events` | Logs all detected security threats |

Tables are created when you run:

```bash
php artisan migrate
```

## Detected Threats

The package detects the following attack types:

| Threat Type | Severity | Examples |
|-------------|----------|----------|
| SQL Injection | Critical | `UNION SELECT`, `OR 1=1`, `xp_cmdshell` |
| XSS | High | `<script>`, `javascript:`, `onclick=` |
| Path Traversal | Critical | `../`, `%2e%2e%2f` |
| Command Injection | Critical | `;cat`, `\|whoami`, `` `id` `` |
| File Inclusion | High | `php://input`, `data:text/html` |
| PHP Serialization | Critical | `O:16:"MaliciousClass"` |
| Directory Bruteforce | Medium | `.git/config`, `.env`, `wp-admin` |
| Header Injection | High | CRLF injection, `Location:` |
| Suspicious User Agent | Medium | `sqlmap`, `nmap`, `python-requests` |
| Behavior Threshold | High | Rate limiting, brute-force |

## Production Guidelines

### 1. Monitor Regularly

Run stats command periodically or set up monitoring:

```bash
# Check for active threats
php artisan crowdsec:stats

# Export to monitoring system
php artisan crowdsec:stats --json | jq '.events_today'
```

### 2. Tune Thresholds for Production

Adjust `config/crowdsec-scenarios.php` based on your traffic:

```php
'behavior' => [
    'request_threshold' => 1000,    // Increase for high-traffic sites
    '404_threshold' => 20,          // Adjust based on your 404 rate
    'login_threshold' => 3,         // Stricter for login pages
    'threat_score_threshold' => 50,
    'block_duration' => 240,
],
```

### 3. Whitelist Internal Services

```php
'whitelist_ips' => [
    '127.0.0.1',
    '::1',
    '10.0.0.0/8',      // Internal network
    '192.168.0.0/16',  // Internal network
    'your-load-balancer-ip',
],
```

### 4. Set Up Log Monitoring

Monitor Laravel logs for CrowdSec warnings:

```php
// Log channel configuration
'log' => [
    'driver' => 'daily',
    'path' => storage_path('logs/laravel.log'),
    'level' => 'warning',
],
```

### 5. Schedule Regular Cleanup

```php
// In app/Console/Kernel.php
protected function schedule(Schedule $schedule)
{
    // Clean expired bans daily at 3 AM
    $schedule->command('crowdsec:cleanup --expired --old-events --old-behaviors')
             ->daily()
             ->at('03:00');
}
```

### 6. Performance Considerations

- The middleware runs on every request - keep patterns optimized
- IP whitelist is checked first for performance
- Behavior tracking uses efficient increment operations
- Consider caching blocked IPs for very high-traffic sites

## Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-new-feature`
3. Make your changes
4. Run tests: `composer test`
5. Commit your changes: `git commit -am 'Add some feature'`
6. Push to the branch: `git push origin feature/my-new-feature`
7. Submit a Pull Request

### Running Tests

```bash
composer test
```

## Security

If you discover any security-related issues, please email the maintainer instead of opening an issue.

## License

This package is open-sourced software licensed under the [MIT license](LICENSE).

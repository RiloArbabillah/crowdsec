<?php

/**
 * CrowdSec-like Protection Scenarios Configuration
 *
 * This file defines detection patterns for various attack types.
 * Each scenario has:
 * - patterns: Regex patterns to match (for input-based detection)
 * - weight: Severity weight (1-10)
 * - block_duration: How long to block (in minutes)
 * - severity: low, medium, high, critical
 * - description: Human-readable description
 */

return [
    // Enable/disable the package (use .env to toggle)
    'enabled' => env('CROWDSEC_ENABLED', true),

    // Log channel (null = default channel)
    'log_channel' => env('CROWDSEC_LOG_CHANNEL', null),

    // Custom response message when IP is blocked
    'blocked_response_message' => 'Forbidden - Your IP has been blocked due to suspicious activity',

    // Maximum allowed content length in bytes (0 = disabled)
    'max_content_length' => env('CROWDSEC_MAX_CONTENT_LENGTH', 10 * 1024 * 1024), // 10MB

    // Block empty User-Agent requests
    'block_empty_ua' => env('CROWDSEC_BLOCK_EMPTY_UA', false),

    // Blocked HTTP methods (these are never legitimate in web apps)
    'blocked_methods' => ['TRACE', 'CONNECT'],

    // =========================================================================
    // PATTERN-BASED SCENARIOS
    // =========================================================================

    // SQL Injection patterns
    'sql_injection' => [
        'patterns' => [
            // Boolean-based injection (OR 1=1, AND 1=1)
            '/\bOR\b\s+\d+\s*=\s*\d+/i',
            '/\bAND\b\s+\d+\s*=\s*\d+/i',
            // Union-based injection
            '/\bUNION\b\s+\bALL\b\s+\bSELECT\b/i',
            '/\bUNION\b\s+\bSELECT\b/i',
            // Common SQL keywords (multi-word to reduce false positives)
            '/\bSELECT\b.*\bFROM\b.*\bWHERE\b/i',
            '/\bINSERT\b\s+\bINTO\b/i',
            '/\bDELETE\b\s+\bFROM\b/i',
            '/\bUPDATE\b\s+\w+\s+\bSET\b/i',
            '/\bDROP\b\s+\bTABLE\b/i',
            '/\bALTER\b\s+\bTABLE\b/i',
            '/\bEXEC\b(\s|\()/i',
            '/\bEXECUTE\b(\s|\()/i',
            '/\bxp_cmdshell\b/i',
            // Hex-encoded injection
            '/0x[0-9a-f]{8,}/i',
            // SLEEP/BENCHMARK (time-based blind injection)
            '/\bSLEEP\s*\(\s*\d+\s*\)/i',
            '/\bBENCHMARK\s*\(/i',
            // LOAD_FILE / INTO OUTFILE
            '/\bLOAD_FILE\s*\(/i',
            '/\bINTO\b\s+\bOUTFILE\b/i',
            // Stacked queries
            '/;\s*\bSELECT\b/i',
            '/;\s*\bDROP\b/i',
            '/;\s*\bINSERT\b/i',
            // Information schema enumeration
            '/\bINFORMATION_SCHEMA\b/i',
            '/\bSYS\.\w+/i',
        ],
        'weight' => 10,
        'block_duration' => 1440, // 24 hours
        'severity' => 'critical',
        'description' => 'SQL Injection attempt detected',
    ],

    // XSS patterns (tightened to reduce false positives)
    'xss' => [
        'patterns' => [
            '/<script[^>]*>/i',
            '/javascript\s*:/i',
            // Event handlers in HTML context (require < before them)
            '/<[^>]+\bon\w+\s*=/i',
            '/<iframe[^>]*>/i',
            '/<object[^>]*>/i',
            '/<embed[^>]*>/i',
            '/expression\s*\(/i',
            '/vbscript\s*:/i',
            // Only dangerous data: URIs
            '/data\s*:\s*text\/html/i',
            // SVG-based XSS
            '/<svg[^>]*\bon\w+/i',
            // Base tag hijack
            '/<base[^>]+href/i',
            // DOM manipulation in input
            '/document\s*\.\s*(cookie|location|write)/i',
            '/window\s*\.\s*location/i',
        ],
        'weight' => 8,
        'block_duration' => 720, // 12 hours
        'severity' => 'high',
        'description' => 'Cross-site scripting (XSS) attempt detected',
    ],

    // Path traversal patterns
    'path_traversal' => [
        'patterns' => [
            '/\.\.\//',
            '/\.\.\\\\/',
            '/%2e%2e(%2f|%5c)/i',
            '/\.\.(%2f|%5c)/i',
            '/%2e%2e\//i',
            '/%2e%2e\\\\/i',
            // Null byte injection (path truncation)
            '/%00/i',
            '/\x00/',
        ],
        'weight' => 10,
        'block_duration' => 1440, // 24 hours
        'severity' => 'critical',
        'description' => 'Path traversal attempt detected',
    ],

    // Directory bruteforce patterns (anchored to reduce false positives)
    'directory_bruteforce' => [
        'patterns' => [
            '/\/\.git\//i',
            '/\/\.env$/i',
            '/\/\.env\./i',
            '/\/wp-admin/i',
            '/\/wp-login/i',
            '/\/phpmyadmin/i',
            '/\.bak$/i',
            '/\.sql$/i',
            '/\/\.htaccess$/i',
            '/\/\.htpasswd$/i',
            '/\/server-status$/i',
            '/\/server-info$/i',
            '/\/adminer/i',
            // Config files
            '/\/web\.config$/i',
            '/\/wp-config\.php/i',
            '/\/config\.php\.bak/i',
            // Debug endpoints
            '/\/debug\//i',
            '/\/phpinfo/i',
            '/\/_profiler/i',
            '/\/telescope/i',
        ],
        'weight' => 5,
        'block_duration' => 360, // 6 hours
        'severity' => 'medium',
        'description' => 'Directory/file access attempt detected',
    ],

    // Header injection patterns
    'header_injection' => [
        'patterns' => [
            '/%0d%0a/i',
            '/\r\n.*?:/i',
            '/Location\s*:\s*https?:/i',
        ],
        'weight' => 7,
        'block_duration' => 480, // 8 hours
        'severity' => 'high',
        'description' => 'HTTP header injection attempt detected',
    ],

    // Suspicious user agent patterns (checked against User-Agent header only)
    'suspicious_user_agent' => [
        'patterns' => [
            '/sqlmap/i',
            '/nikto/i',
            '/havij/i',
            '/nmap/i',
            '/masscan/i',
            '/nessus/i',
            '/acunetix/i',
            '/dirbuster/i',
            '/gobuster/i',
            '/wpscan/i',
            '/burpsuite/i',
            '/zaproxy|owasp\s*zap/i',
            '/metasploit/i',
            '/w3af/i',
            '/skipfish/i',
            '/commix/i',
        ],
        'weight' => 4,
        'block_duration' => 60, // 1 hour
        'severity' => 'medium',
        'description' => 'Suspicious user agent detected',
    ],

    // Command injection patterns
    'command_injection' => [
        'patterns' => [
            // Shell command separators with dangerous commands
            '/;\s*(cat|ls|whoami|pwd|id|uname|hostname)\b/i',
            '/\|\s*(cat|whoami|id|uname)\b/i',
            '/&&\s*(cat|whoami|id|uname)\b/i',
            // Backtick execution
            '/`[^`]*`/',
            // $() command substitution
            '/\$\([^)]+\)/',
            // Shell paths
            '/\/bin\/(sh|bash|zsh|dash)\b/i',
            '/\/etc\/passwd/i',
            '/\/etc\/shadow/i',
            // Dangerous commands
            '/\brm\b\s+-rf\b/i',
            '/\bchmod\b\s+[0-7]{3,4}\b/i',
            '/\bnc\b\s+-[elp]/i',
            '/\bbash\b\s+-i\b/i',
            // Reverse shell patterns
            '/\bexec\b\s+\d+<>/i',
            '/\/dev\/(tcp|udp)\//i',
            // PowerShell
            '/powershell\s*(-\w+\s+)*-?(enc|encodedcommand|e)\b/i',
            '/\bInvoke-(WebRequest|Expression|RestMethod)\b/i',
        ],
        'weight' => 10,
        'block_duration' => 1440, // 24 hours
        'severity' => 'critical',
        'description' => 'Command injection attempt detected',
    ],

    // File inclusion / PHP wrappers
    'file_inclusion' => [
        'patterns' => [
            '/php:\/\/(input|filter|data)/i',
            '/data:text\/html/i',
            '/expect:\/\//i',
            '/zip:\/\//i',
            '/phar:\/\//i',
            '/glob:\/\//i',
            '/ogg:\/\//i',
            '/rar:\/\//i',
        ],
        'weight' => 9,
        'block_duration' => 720, // 12 hours
        'severity' => 'high',
        'description' => 'File inclusion attempt detected',
    ],

    // PHP object injection / serialization attack
    'php_serialization' => [
        'patterns' => [
            '/O:\d+:"[a-zA-Z_]/',  // PHP serialized object
            '/C:\d+:"[a-zA-Z_]/',  // PHP serialized class
            '/__wakeup|__destruct|__toString/',  // PHP magic methods in input
        ],
        'weight' => 10,
        'block_duration' => 1440, // 24 hours
        'severity' => 'critical',
        'description' => 'PHP object injection attempt detected',
    ],

    // =========================================================================
    // NEW SCENARIOS
    // =========================================================================

    // SSRF — Server-Side Request Forgery
    'ssrf' => [
        'patterns' => [
            // AWS/Azure/GCP metadata endpoints
            '/169\.254\.169\.254/i',
            '/metadata\.google\.internal/i',
            '/169\.254\.170\.2/i',       // AWS ECS metadata
            // Internal IPs in URL params
            '/[?&=](https?:\/\/|\/\/)(127\.\d+\.\d+\.\d+|10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)/i',
            '/[?&=](https?:\/\/|\/\/)localhost/i',
            '/[?&=](https?:\/\/|\/\/)0\.0\.0\.0/i',
            // File protocol
            '/file:\/\//i',
            // Gopher protocol (SSRF vector)
            '/gopher:\/\//i',
            // Dict protocol
            '/dict:\/\//i',
            // Internal cloud URLs
            '/2852039166/',  // Decimal IP for 169.254.169.254
            '/0xa9fea9fe/i', // Hex IP for 169.254.169.254
        ],
        'weight' => 10,
        'block_duration' => 1440, // 24 hours
        'severity' => 'critical',
        'description' => 'Server-Side Request Forgery (SSRF) attempt detected',
    ],

    // XXE — XML External Entity Injection
    'xxe' => [
        'patterns' => [
            '/<!ENTITY\s/i',
            '/<!DOCTYPE[^>]+SYSTEM/i',
            '/<!DOCTYPE[^>]+PUBLIC/i',
            '/SYSTEM\s*"(https?|file|php|expect|data):/i',
            '/<!ENTITY\s+\w+\s+SYSTEM/i',
            '/<!ENTITY\s+%/i',  // Parameter entity
            '/xmlns:xi="http:\/\/www\.w3\.org\/2001\/XInclude"/i',
        ],
        'weight' => 10,
        'block_duration' => 1440, // 24 hours
        'severity' => 'critical',
        'description' => 'XML External Entity (XXE) injection attempt detected',
    ],

    // NoSQL Injection (MongoDB, CouchDB, etc.)
    'nosql_injection' => [
        'patterns' => [
            // MongoDB operators in JSON input
            '/\$(?:gt|gte|lt|lte|ne|eq|in|nin|and|or|not|nor|exists|type|regex|where|all|elemMatch|size)\b/i',
            // MongoDB functions
            '/\$(?:group|project|match|limit|skip|sort|unwind|lookup)\b/i',
            // JavaScript injection in NoSQL
            '/\bfunction\s*\(/i',
            // this.constructor
            '/this\s*\.\s*constructor/i',
            // MongoDB shell commands
            '/db\.\w+\.(find|insert|update|delete|drop|remove)\s*\(/i',
        ],
        'weight' => 10,
        'block_duration' => 1440, // 24 hours
        'severity' => 'critical',
        'description' => 'NoSQL injection attempt detected',
    ],

    // LDAP Injection
    'ldap_injection' => [
        'patterns' => [
            // LDAP filter injection
            '/\)\s*\(\s*[&|!]/',        // )(& or )(| or )(!
            '/\*\)\s*\(/',               // *)(
            '/\)\s*\(\s*\w+\s*=\s*\*/', // )(attr=*
            // Null byte in LDAP context
            '/\x00/',
            '/%00/',
            // DN injection
            '/[;,]\s*(cn|ou|dc|uid)\s*=/i',
        ],
        'weight' => 8,
        'block_duration' => 720, // 12 hours
        'severity' => 'high',
        'description' => 'LDAP injection attempt detected',
    ],

    // SSTI — Server-Side Template Injection
    'ssti' => [
        'patterns' => [
            // Jinja2/Twig/Django/Blade
            '/\{\{\s*\d+\s*\*\s*\d+\s*\}\}/',       // {{7*7}}
            '/\{\{\s*[\w.]+\s*\(/',                   // {{func(
            '/\{\{.*?__class__/i',                    // {{x.__class__
            '/\{\{.*?__mro__/i',                      // MRO chain
            '/\{\{.*?__subclasses__/i',               // Subclass access
            '/\{%\s*(import|include|extends)\b/i',    // {%import / {%include
            // Smarty / PHP templates
            '/\{php\}/i',
            '/\{\$smarty/i',
            // EL / Java
            '/\$\{.*?(Runtime|ProcessBuilder|getRuntime)/i',
            '/#\{.*?(Runtime|processBuilder)/i',
            // Expression Language
            '/\$\{T\s*\(/i',                          // ${T(
        ],
        'weight' => 10,
        'block_duration' => 1440, // 24 hours
        'severity' => 'critical',
        'description' => 'Server-Side Template Injection (SSTI) attempt detected',
    ],

    // Open Redirect
    'open_redirect' => [
        'patterns' => [
            // Protocol-relative URL in redirect params (match start of string or after & / ?)
            '/(?:^|[?&])(redirect|return|next|url|goto|target|dest|destination|rurl|redir)\s*=\s*(https?:)?\/\/[^\/]/i',
            // Backslash trick
            '/(?:^|[?&])(redirect|return|next|url|goto|target|dest)\s*=\s*\\\\\\\\[^\/]/i',
            // Encoded redirect
            '/(?:^|[?&])(redirect|return|next|url|goto|target|dest)\s*=\s*%2f%2f/i',
            // Data URI redirect
            '/(?:^|[?&])(redirect|return|next|url|goto|target|dest)\s*=\s*data:/i',
            // JavaScript redirect
            '/(?:^|[?&])(redirect|return|next|url|goto|target|dest)\s*=\s*javascript:/i',
        ],
        'weight' => 5,
        'block_duration' => 240, // 4 hours
        'severity' => 'medium',
        'description' => 'Open redirect attempt detected',
    ],

    // =========================================================================
    // BEHAVIOR THRESHOLDS
    // =========================================================================

    // Behavior thresholds (not pattern-based)
    'behavior' => [
        'request_threshold' => 500, // requests per hour
        '404_threshold' => 15, // 404s per hour
        'login_threshold' => 5, // login attempts per 5 minutes
        'threat_score_threshold' => 50,
        'block_duration' => 240, // 4 hours
        'severity' => 'high',
        'description' => 'Suspicious behavior detected',
    ],

    // Block duration defaults (in minutes)
    'defaults' => [
        'low' => 60,      // 1 hour
        'medium' => 240,  // 4 hours
        'high' => 720,    // 12 hours
        'critical' => 1440, // 24 hours
    ],

    // Whitelist IPs (won't be blocked) — supports CIDR notation
    'whitelist_ips' => [
        '127.0.0.1',
        '::1',
    ],

    // Login routes — these routes use login_threshold instead of WAF patterns
    'login_routes' => [
        'login',
        'auth/login',
        'admin/login',
        'filament/auth/login',
        'filament/login',
    ],

    // =========================================================================
    // CACHING
    // =========================================================================

    // Cache blocked IP lookups for performance (recommended for high-traffic sites)
    'cache' => [
        'enabled' => env('CROWDSEC_CACHE_ENABLED', false),
        'store' => env('CROWDSEC_CACHE_STORE', null), // null = default cache store
        'ttl' => env('CROWDSEC_CACHE_TTL', 60), // seconds
        'prefix' => 'crowdsec',
    ],

    // =========================================================================
    // NOTIFICATIONS
    // =========================================================================

    'notifications' => [
        'enabled' => env('CROWDSEC_NOTIFY_ENABLED', false),
        'channels' => ['mail'], // Supported: 'mail', 'slack'
        'severity_threshold' => 'high', // Only notify for this severity and above
        'rate_limit_minutes' => 5, // Max 1 notification per IP per N minutes
        'recipients' => explode(',', env('CROWDSEC_NOTIFY_RECIPIENTS', '')),
    ],

    // =========================================================================
    // HONEYPOT ROUTES
    // =========================================================================

    // Routes that serve as traps for malicious scanners.
    // Any request to these routes will immediately block the IP.
    'honeypot_routes' => [
        '.env',
        'wp-admin',
        'wp-login.php',
        'wp-includes',
        'xmlrpc.php',
        'phpmyadmin',
        'administrator',
        '.git/config',
        '.well-known/security.txt',
    ],

    // =========================================================================
    // GEOIP
    // =========================================================================

    'geoip' => [
        'enabled' => env('CROWDSEC_GEOIP_ENABLED', false),
        'provider' => env('CROWDSEC_GEOIP_PROVIDER', 'ip-api'), // 'ip-api', 'custom'
        'cache_ttl' => 86400, // Cache GeoIP results for 24 hours
        'custom_callback' => null, // callable for custom provider
    ],

    // =========================================================================
    // REST API
    // =========================================================================

    'api' => [
        'enabled' => env('CROWDSEC_API_ENABLED', false),
        'middleware' => ['api'], // Add 'auth:sanctum' for production
    ],
];

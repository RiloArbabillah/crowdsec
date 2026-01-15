<?php

/**
 * CrowdSec-like Protection Scenarios Configuration
 *
 * This file defines detection patterns for various attack types.
 * Each scenario has:
 * - pattern: Regex pattern to match (for input-based detection)
 * - weight: Severity weight (1-10)
 * - block_duration: How long to block (in minutes)
 * - severity: low, medium, high, critical
 * - description: Human-readable description
 */

return [
    // Enable/disable the package
    'enabled' => true,

    // SQL Injection patterns
    'sql_injection' => [
        'patterns' => [
            // Basic injection chars
            '/(\%27)|(\')|(\-\-)|(\%23)|(#)/i',
            // Boolean-based injection (OR 1=1, AND 1=1)
            '/\bOR\b\s+\d+\s*=\s*\d+/i',
            '/\bAND\b\s+\d+\s*=\s*\d+/i',
            // Union-based injection
            '/\bUNION\b\s+\bALL\b\s+\bSELECT\b/i',
            '/\bUNION\b\s+\bSELECT\b/i',
            // Common SQL keywords with optional spaces
            '/\bSELECT\b.*\bFROM\b/i',
            '/\bINSERT\b\s+\bINTO\b/i',
            '/\bDELETE\b\s+\bFROM\b/i',
            '/\bUPDATE\b.*\bSET\b/i',
            '/\bDROP\b\s+\bTABLE\b/i',
            '/\bALTER\b\s+\bTABLE\b/i',
            '/\bEXEC\b(\s|\()/i',
            '/\bEXECUTE\b(\s|\()/i',
            '/\bxp_cmdshell\b/i',
            // Comment-based injection
            '/\-\-\s*$/m',
            '/#\s*\d+/',
        ],
        'weight' => 10,
        'block_duration' => 1440, // 24 hours
        'severity' => 'critical',
        'description' => 'SQL Injection attempt detected',
    ],

    // XSS patterns
    'xss' => [
        'patterns' => [
            '/<script[^>]*>/i',
            '/javascript:/i',
            '/on\w+\s*=/i',
            '/<iframe[^>]*>/i',
            '/<object[^>]*>/i',
            '/<embed[^>]*>/i',
            '/expression\s*\(/i',
            '/data:/i',
            '/vbscript:/i',
            '/alert\s*\(/i',
            '/prompt\s*\(/i',
            '/confirm\s*\(/i',
        ],
        'weight' => 8,
        'block_duration' => 720, // 12 hours
        'severity' => 'high',
        'description' => 'Cross-site scripting (XSS) attempt detected',
    ],

    // Path traversal patterns
    'path_traversal' => [
        'patterns' => [
            '/\.\.\/|\.\.\\\/i',
            '/%2e%2e%2f/i',
            '/%2e%2e%5c/i',
            '/\.\.%2f/i',
            '/\.\.%5c/i',
            '/\.\.\//i',
            '/\.\.\\/i',
        ],
        'weight' => 10,
        'block_duration' => 1440, // 24 hours
        'severity' => 'critical',
        'description' => 'Path traversal attempt detected',
    ],

    // Directory bruteforce patterns
    'directory_bruteforce' => [
        'patterns' => [
            '/\.git\/config/i',
            '/\.env/i',
            '/wp-admin/i',
            '/wp-login/i',
            '/administrator/i',
            '/phpmyadmin/i',
            '/.bak/i',
            '/.sql/i',
            '/.log/i',
            '/~admin/i',
            '/~user/i',
        ],
        'weight' => 5,
        'block_duration' => 360, // 6 hours
        'severity' => 'medium',
        'description' => 'Directory/file access attempt detected',
    ],

    // Header injection patterns
    'header_injection' => [
        'patterns' => [
            '/\r\n|\n\r|\n|\r/',
            '/%0d%0a/i',
            '/Location:\s*http/i',
        ],
        'weight' => 7,
        'block_duration' => 480, // 8 hours
        'severity' => 'high',
        'description' => 'HTTP header injection attempt detected',
    ],

    // Suspicious user agent patterns
    'suspicious_user_agent' => [
        'patterns' => [
            '/python-requests/i',
            '/curl/i',
            '/wget/i',
            '/sqlmap/i',
            '/nikto/i',
            '/havij/i',
            '/nmap/i',
            '/masscan/i',
        ],
        'weight' => 4,
        'block_duration' => 60, // 1 hour
        'severity' => 'medium',
        'description' => 'Suspicious user agent detected',
    ],

    // Command injection patterns
    'command_injection' => [
        'patterns' => [
            // Shell command separators
            '/;\s*cat\b/i',
            '/;\s*ls\b/i',
            '/;\s*whoami\b/i',
            '/;\s*pwd\b/i',
            '/;\s*id\b/i',
            '/\|\s*whoami\b/i',
            '/\|\s*cat\b/i',
            '/&&\s*cat\b/i',
            '/`.*`/',
            '/\$\(.*\)/',
            // Shell paths
            '/\/bin\/sh\b/i',
            '/\/bin\/bash\b/i',
            // Dangerous commands
            '/\brm\b\s+-rf\b/i',
            '/\bchmod\b\s+777\b/i',
            '/\bwget\b\s+http/i',
            '/\bcurl\b\s+http/i',
            '/\bnc\b\s+-e\b/i',
            '/\bbash\b\s+-i\b/i',
        ],
        'weight' => 10,
        'block_duration' => 1440, // 24 hours
        'severity' => 'critical',
        'description' => 'Command injection attempt detected',
    ],

    // File inclusion / PHP deserialization patterns
    'file_inclusion' => [
        'patterns' => [
            '/\.\.\/.*\./i',
            '/php:\/\/input/i',
            '/data:text\/html/i',
            '/expect:\/\//i',
            '/input=file:/i',
        ],
        'weight' => 9,
        'block_duration' => 720, // 12 hours
        'severity' => 'high',
        'description' => 'File inclusion attempt detected',
    ],

    // PHP object injection / serialization attack
    'php_serialization' => [
        'patterns' => [
            '/^O:\d+:"[a-zA-Z_]/',  // PHP serialized object
            '/^C:\d+:"[a-zA-Z_]/',  // PHP serialized class
            '/a:\d+:\{/',           // PHP serialized array
            '/s:\d+:"/',            // PHP serialized string
            '/__wakeup|__destruct|__toString/',  // PHP magic methods
        ],
        'weight' => 10,
        'block_duration' => 1440, // 24 hours
        'severity' => 'critical',
        'description' => 'PHP object injection attempt detected',
    ],

    // Behavior thresholds (not pattern-based)
    'behavior' => [
        'request_threshold' => 500, // requests per minute
        '404_threshold' => 15, // 404s per minute
        'login_threshold' => 5, // login attempts per minute
        'threat_score_threshold' => 50,
        'block_duration' => 240, // 4 hours
        'severity' => 'high',
        'description' => 'Suspicious behavior detected',
    ],

    // Block duration defaults
    'defaults' => [
        'low' => 60,      // 1 hour
        'medium' => 240,  // 4 hours
        'high' => 720,    // 12 hours
        'critical' => 1440, // 24 hours
    ],

    // Whitelist IPs (won't be blocked)
    'whitelist_ips' => [
        '127.0.0.1',
        '::1',
    ],

    // Login routes - these routes will use login_threshold instead of WAF patterns
    'login_routes' => [
        'login',
        'auth/login',
        'admin/login',
        'filament/auth/login',
        'filament/login',
    ],
];

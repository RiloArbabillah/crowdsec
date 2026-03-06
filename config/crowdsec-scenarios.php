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
        ],
        'weight' => 5,
        'block_duration' => 360, // 6 hours
        'severity' => 'medium',
        'description' => 'Directory/file access attempt detected',
    ],

    // Header injection patterns (only checked against header values)
    'header_injection' => [
        'patterns' => [
            '/%0d%0a/i',
            '/\r\n.*?:/i',   // CRLF followed by header name
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
];

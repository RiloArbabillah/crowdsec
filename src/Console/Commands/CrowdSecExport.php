<?php

namespace RiloArbabillah\LaravelCrowdSec\Console\Commands;

use Illuminate\Console\Command;
use RiloArbabillah\LaravelCrowdSec\Models\SecurityEvent;

class CrowdSecExport extends Command
{
    protected $signature = 'crowdsec:export
                           {--format=json : Export format (json, csv, syslog)}
                           {--from= : Start date (Y-m-d)}
                           {--to= : End date (Y-m-d)}
                           {--severity= : Filter by severity (low, medium, high, critical)}
                           {--output= : Output file path (default: stdout)}';

    protected $description = 'Export security events in SIEM-compatible format (JSON, CSV, Syslog)';

    public function handle(): int
    {
        $format = $this->option('format');
        $query = SecurityEvent::query()->orderBy('created_at', 'desc');

        // Apply filters
        if ($from = $this->option('from')) {
            $query->where('created_at', '>=', $from);
        }
        if ($to = $this->option('to')) {
            $query->where('created_at', '<=', "{$to} 23:59:59");
        }
        if ($severity = $this->option('severity')) {
            $query->where('severity', $severity);
        }

        $events = $query->get();

        if ($events->isEmpty()) {
            $this->info('No events found matching the criteria.');

            return Command::SUCCESS;
        }

        $output = match ($format) {
            'csv' => $this->formatCsv($events),
            'syslog' => $this->formatSyslog($events),
            default => $this->formatJson($events),
        };

        if ($outputPath = $this->option('output')) {
            file_put_contents($outputPath, $output);
            $this->info("Exported {$events->count()} events to {$outputPath}");
        } else {
            $this->line($output);
        }

        return Command::SUCCESS;
    }

    protected function formatJson($events): string
    {
        return $events->map(fn ($event) => [
            'timestamp' => $event->created_at->toISOString(),
            'ip' => $event->ip,
            'event_type' => $event->event_type,
            'severity' => $event->severity,
            'matched_patterns' => $event->matched_patterns,
            'request_uri' => $event->request_data['path'] ?? $event->request_data['uri'] ?? null,
            'request_method' => $event->request_data['method'] ?? null,
            'user_agent' => $event->request_data['user_agent'] ?? null,
            'request_id' => $event->request_id,
            'route_name' => $event->route_name,
            'content_type' => $event->content_type,
            'content_length' => $event->content_length,
            'response_status' => $event->response_status,
            'duration_ms' => $event->duration_ms,
            'action_taken' => $event->action_taken,
            'country_code' => $event->country_code,
            'asn' => $event->asn,
            'isp' => $event->isp,
            'authenticated_user_id_hash' => $event->authenticated_user_id_hash,
            'browser' => $event->browser,
            'os' => $event->os,
            'device_type' => $event->device_type,
        ])->toJson(JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    }

    protected function formatCsv($events): string
    {
        $lines = [implode(',', [
            'timestamp', 'ip', 'event_type', 'severity', 'request_uri', 'request_method', 'user_agent',
            'request_id', 'route_name', 'content_type', 'content_length', 'response_status', 'duration_ms',
            'action_taken', 'country_code', 'asn', 'isp', 'authenticated_user_id_hash', 'browser', 'os',
            'device_type',
        ])];

        foreach ($events as $event) {
            $lines[] = implode(',', array_map([$this, 'csvField'], [
                $event->created_at->toISOString(),
                $event->ip,
                $event->event_type ?? '',
                $event->severity ?? '',
                $event->request_data['path'] ?? $event->request_data['uri'] ?? '',
                $event->request_data['method'] ?? '',
                $event->request_data['user_agent'] ?? '',
                $event->request_id,
                $event->route_name,
                $event->content_type,
                $event->content_length,
                $event->response_status,
                $event->duration_ms,
                $event->action_taken,
                $event->country_code,
                $event->asn,
                $event->isp,
                $event->authenticated_user_id_hash,
                $event->browser,
                $event->os,
                $event->device_type,
            ]));
        }

        return implode("\n", $lines) . "\n";
    }

    protected function csvField(mixed $value): string
    {
        return '"'.str_replace('"', '""', (string) ($value ?? '')).'"';
    }

    protected function formatSyslog($events): string
    {
        $lines = [];

        foreach ($events as $event) {
            // RFC 5424 format
            $priority = match ($event->severity) {
                'critical' => 2,
                'high' => 3,
                'medium' => 4,
                'low' => 6,
                default => 5,
            };

            $lines[] = sprintf(
                '<%d>1 %s %s CrowdSec - - - ip=%s event_type=%s severity=%s uri=%s request_id=%s action=%s status=%s duration_ms=%s country=%s asn=%s device=%s',
                $priority,
                $event->created_at->toISOString(),
                gethostname(),
                $event->ip,
                $event->event_type ?? 'unknown',
                $event->severity ?? 'unknown',
                $event->request_data['path'] ?? $event->request_data['uri'] ?? '-',
                $event->request_id ?? '-',
                $event->action_taken ?? '-',
                $event->response_status ?? '-',
                $event->duration_ms ?? '-',
                $event->country_code ?? '-',
                $event->asn ?? '-',
                $event->device_type ?? '-',
            );
        }

        return implode("\n", $lines) . "\n";
    }
}

<?php

namespace RiloArbabillah\LaravelCrowdSec\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Support\Carbon;
use RiloArbabillah\LaravelCrowdSec\Models\SecurityEvent;

class CrowdSecExport extends Command
{
    protected $signature = 'crowdsec:export
                           {--format=json : Export format (json, csv, syslog)}
                           {--from= : Start date (Y-m-d)}
                           {--to= : End date (Y-m-d)}
                           {--severity= : Filter by severity (low, medium, high, critical)}
                           {--ip= : Filter by IP address}
                           {--event-type= : Filter by event type}
                           {--output= : Output file path (default: stdout)}';

    protected $description = 'Export security events in SIEM-compatible format (JSON, CSV, Syslog)';

    protected const FORMATS = ['json', 'csv', 'syslog'];

    protected const SEVERITIES = ['low', 'medium', 'high', 'critical'];

    protected const CSV_COLUMNS = [
        'timestamp', 'ip', 'event_type', 'severity', 'request_uri', 'request_method', 'user_agent',
        'request_id', 'route_name', 'content_type', 'content_length', 'response_status', 'duration_ms',
        'action_taken', 'country_code', 'asn', 'isp', 'authenticated_user_id_hash', 'browser', 'os',
        'device_type',
    ];

    public function handle(): int
    {
        $format = (string) $this->option('format');
        if (! in_array($format, self::FORMATS, true)) {
            $this->error("Unsupported format \"{$format}\". Use one of: " . implode(', ', self::FORMATS));

            return Command::FAILURE;
        }

        $severity = $this->option('severity');
        if ($severity !== null && ! in_array($severity, self::SEVERITIES, true)) {
            $this->error("Unsupported severity \"{$severity}\". Use one of: " . implode(', ', self::SEVERITIES));

            return Command::FAILURE;
        }

        $query = SecurityEvent::query();

        foreach (['from' => '>=', 'to' => '<='] as $option => $operator) {
            $value = $this->option($option);
            if ($value === null) {
                continue;
            }

            try {
                $date = Carbon::parse((string) $value);
            } catch (\Throwable) {
                $this->error("Invalid --{$option} date \"{$value}\". Use Y-m-d.");

                return Command::FAILURE;
            }

            // A plain date covers the whole day; a date-time is used as given.
            if (preg_match('/^\d{4}-\d{2}-\d{2}$/', (string) $value) === 1) {
                $date = $option === 'from' ? $date->startOfDay() : $date->endOfDay();
            }

            $query->where('created_at', $operator, $date);
        }

        if ($severity !== null) {
            $query->where('severity', $severity);
        }
        if ($ip = $this->option('ip')) {
            $query->where('ip', $ip);
        }
        if ($eventType = $this->option('event-type')) {
            $query->where('event_type', $eventType);
        }

        if (! (clone $query)->exists()) {
            $this->info('No events found matching the criteria.');

            return Command::SUCCESS;
        }

        $outputPath = $this->option('output');
        $handle = $outputPath ? @fopen((string) $outputPath, 'w') : null;
        if ($handle === false) {
            $this->error("Cannot write to {$outputPath}");

            return Command::FAILURE;
        }

        $write = $handle
            ? function (string $chunk) use ($handle, $outputPath): void {
                if (fwrite($handle, $chunk) === false) {
                    throw new \RuntimeException("Failed writing to {$outputPath}");
                }
            }
            : fn (string $chunk) => $this->output->write($chunk);

        try {
            $count = $this->stream($query, $format, $write);
        } catch (\RuntimeException $e) {
            $this->error($e->getMessage());

            return Command::FAILURE;
        } finally {
            if ($handle) {
                fclose($handle);
            }
        }

        if ($outputPath) {
            $this->info("Exported {$count} events to {$outputPath}");
        }

        return Command::SUCCESS;
    }

    /**
     * Write events newest first in batches, so memory stays flat on large tables.
     *
     * @param  Builder<SecurityEvent>  $query
     * @param  \Closure(string): void  $write
     */
    protected function stream(Builder $query, string $format, \Closure $write): int
    {
        $count = 0;

        if ($format === 'json') {
            $write("[\n");
        } elseif ($format === 'csv') {
            $write(implode(',', self::CSV_COLUMNS) . "\n");
        }

        foreach ($query->lazyByIdDesc(500) as $event) {
            $write(match ($format) {
                'csv' => $this->csvLine($event),
                'syslog' => $this->syslogLine($event),
                default => ($count > 0 ? ",\n" : '') . (string) json_encode($this->eventRecord($event), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES),
            });
            $count++;
        }

        if ($format === 'json') {
            $write("\n]\n");
        }

        return $count;
    }

    /**
     * @return array<string, mixed>
     */
    protected function eventRecord(SecurityEvent $event): array
    {
        return [
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
        ];
    }

    protected function csvLine(SecurityEvent $event): string
    {
        $record = $this->eventRecord($event);
        unset($record['matched_patterns']);

        return implode(',', array_map([$this, 'csvField'], array_values($record))) . "\n";
    }

    protected function csvField(mixed $value): string
    {
        return '"'.str_replace('"', '""', (string) ($value ?? '')).'"';
    }

    protected function syslogLine(SecurityEvent $event): string
    {
        // RFC 5424 format
        $priority = match ($event->severity) {
            'critical' => 2,
            'high' => 3,
            'medium' => 4,
            'low' => 6,
            default => 5,
        };

        return sprintf(
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
        ) . "\n";
    }
}

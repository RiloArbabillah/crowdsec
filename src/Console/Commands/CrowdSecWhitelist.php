<?php

namespace RiloArbabillah\LaravelCrowdSec\Console\Commands;

use DateTimeImmutable;
use Illuminate\Console\Command;
use RiloArbabillah\LaravelCrowdSec\Models\WhitelistedIp;
use RiloArbabillah\LaravelCrowdSec\Services\CrowdSecService;

class CrowdSecWhitelist extends Command
{
    protected $signature = 'crowdsec:whitelist
                            {action : list|add|remove|purge-expired}
                            {ip? : IP address or CIDR range (required for add/remove)}
                            {--label= : Human-readable label (e.g. "Office VPN")}
                            {--note= : Free-form note}
                            {--expires= : Optional expiration date (e.g. 2026-12-31 or 2026-12-31 23:59:59)}';

    protected $description = 'Manage the dynamic CrowdSec IP whitelist';

    public function handle(): int
    {
        $action = (string) $this->argument('action');

        return match ($action) {
            'list' => $this->listEntries(),
            'add' => $this->addEntry(),
            'remove' => $this->removeEntry(),
            'purge-expired' => $this->purgeExpired(),
            default => $this->unknownAction($action),
        };
    }

    protected function listEntries(): int
    {
        $entries = WhitelistedIp::query()->orderBy('created_at', 'desc')->get();

        if ($entries->isEmpty()) {
            $this->info('No dynamic whitelist entries.');
            return self::SUCCESS;
        }

        $this->table(
            ['ID', 'IP / CIDR', 'Label', 'Active', 'Expires', 'Created by', 'Created at'],
            $entries->map(fn (WhitelistedIp $e) => [
                $e->id,
                $e->ip,
                $e->label ?? '-',
                $e->is_active ? 'yes' : 'no',
                $e->expires_at ? $e->expires_at->toDateTimeString() . ' (' . $e->remaining_time . ')' : 'never',
                $e->created_by_label ?? ($e->created_by ? '#' . $e->created_by : '-'),
                $e->created_at?->toDateTimeString() ?? '-',
            ])->all(),
        );

        return self::SUCCESS;
    }

    protected function addEntry(): int
    {
        $ip = (string) ($this->argument('ip') ?? '');
        if ($ip === '') {
            $this->error('IP (or CIDR) is required for add.');
            return self::INVALID;
        }

        $service = app(CrowdSecService::class);

        if (! $service->isValidIpOrCidr($ip)) {
            $this->error("Invalid IP or CIDR: {$ip}");
            return self::INVALID;
        }

        $label = $this->option('label');
        $note = $this->option('note');
        $expiresRaw = $this->option('expires');

        $expiresAt = null;
        if ($expiresRaw !== null && $expiresRaw !== '') {
            try {
                $expiresAt = new DateTimeImmutable((string) $expiresRaw);
            } catch (\Exception $e) {
                $this->error("Could not parse --expires value '{$expiresRaw}'. Use a parseable date, e.g. '2026-12-31' or '2026-12-31 23:59:59'.");
                return self::INVALID;
            }
            if ($expiresAt <= new DateTimeImmutable()) {
                $this->error('--expires must be in the future.');
                return self::INVALID;
            }
        }

        $entry = $service->whitelistIp(
            $ip,
            $label !== null ? (string) $label : null,
            $note !== null ? (string) $note : null,
            $expiresAt,
            null,
            'cli',
        );

        $this->info("Whitelisted: {$entry->ip}" . ($entry->label ? " ({$entry->label})" : ''));

        return self::SUCCESS;
    }

    protected function removeEntry(): int
    {
        $ip = (string) ($this->argument('ip') ?? '');
        if ($ip === '') {
            $this->error('IP (or CIDR) is required for remove.');
            return self::INVALID;
        }

        $removed = app(CrowdSecService::class)->unwhitelistIp($ip, null, 'cli');

        if ($removed) {
            $this->info("Removed from whitelist: {$ip}");
            return self::SUCCESS;
        }

        $this->warn("{$ip} was not on the dynamic whitelist.");
        return self::SUCCESS;
    }

    protected function purgeExpired(): int
    {
        $deleted = app(CrowdSecService::class)->purgeExpiredWhitelistEntries();
        $this->info("Purged {$deleted} expired whitelist entries.");
        return self::SUCCESS;
    }

    protected function unknownAction(string $action): int
    {
        $this->error("Unknown action '{$action}'. Use: list, add, remove, purge-expired.");
        return self::INVALID;
    }
}

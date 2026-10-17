<?php

namespace RiloArbabillah\LaravelCrowdSec\Console\Commands;

use Illuminate\Console\Command;
use RiloArbabillah\LaravelCrowdSec\Services\CrowdSecService;

class CrowdSecBlock extends Command
{
    protected $signature = 'crowdsec:block
                            {ip : IP address to block}
                            {--reason=Manual block : Reason stored with the block}
                            {--duration= : Block duration in minutes (default: severity default)}';

    protected $description = 'Block an IP address';

    public function handle(CrowdSecService $service): int
    {
        $ip = (string) $this->argument('ip');
        if (! filter_var($ip, FILTER_VALIDATE_IP)) {
            $this->error("Invalid IP address: {$ip}");

            return self::FAILURE;
        }

        $duration = $this->option('duration');
        if ($duration !== null && (! ctype_digit((string) $duration) || (int) $duration < 1)) {
            $this->error('--duration must be a positive number of minutes');

            return self::FAILURE;
        }

        if ($service->isWhitelisted($ip)) {
            $this->warn("{$ip} is whitelisted; the block is stored but not enforced while the whitelist entry exists.");
        }

        $block = $service->blockIp($ip, (string) $this->option('reason'), $duration !== null ? (int) $duration : null, 'manual');

        $this->info("Blocked {$ip} until " . ($block->expires_at?->toDateTimeString() ?? 'further notice'));

        return self::SUCCESS;
    }
}

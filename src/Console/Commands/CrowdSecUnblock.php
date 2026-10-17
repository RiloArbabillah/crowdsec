<?php

namespace RiloArbabillah\LaravelCrowdSec\Console\Commands;

use Illuminate\Console\Command;
use RiloArbabillah\LaravelCrowdSec\Services\CrowdSecService;

class CrowdSecUnblock extends Command
{
    protected $signature = 'crowdsec:unblock {ip : IP address to unblock}';

    protected $description = 'Unblock an IP address';

    public function handle(CrowdSecService $service): int
    {
        $ip = (string) $this->argument('ip');

        if (! $service->unblockIp($ip)) {
            $this->warn("{$ip} was not blocked.");

            return self::SUCCESS;
        }

        $this->info("Unblocked {$ip}");

        return self::SUCCESS;
    }
}

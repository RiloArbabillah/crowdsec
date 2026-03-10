<?php

namespace RiloArbabillah\LaravelCrowdSec\Events;

use Illuminate\Broadcasting\InteractsWithSockets;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;

class IpBlocked
{
    use Dispatchable, InteractsWithSockets, SerializesModels;

    public function __construct(
        public string $ip,
        public string $reason,
        public int $durationMinutes,
        public int $blockCount,
        public ?string $eventType = null,
    ) {}
}

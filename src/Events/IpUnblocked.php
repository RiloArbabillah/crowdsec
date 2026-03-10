<?php

namespace RiloArbabillah\LaravelCrowdSec\Events;

use Illuminate\Broadcasting\InteractsWithSockets;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;

class IpUnblocked
{
    use Dispatchable, InteractsWithSockets, SerializesModels;

    public function __construct(
        public string $ip,
    ) {}
}

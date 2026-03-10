<?php

namespace RiloArbabillah\LaravelCrowdSec\Events;

use Illuminate\Broadcasting\InteractsWithSockets;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;

class BehaviorThresholdExceeded
{
    use Dispatchable, InteractsWithSockets, SerializesModels;

    public function __construct(
        public string $ip,
        public float $threatScore,
        public int $requestCount,
        public int $error404Count,
        public int $loginAttempts,
    ) {}
}

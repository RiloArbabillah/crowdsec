<?php

namespace RiloArbabillah\LaravelCrowdSec\Events;

use Illuminate\Broadcasting\InteractsWithSockets;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Http\Request;
use Illuminate\Queue\SerializesModels;

class ThreatDetected
{
    use Dispatchable, InteractsWithSockets, SerializesModels;

    /** @param list<array<string, mixed>> $threats */
    public function __construct(
        public string $ip,
        public array $threats,
        public string $severity,
        public string $uri,
        public string $method,
        public ?Request $request = null,
    ) {}
}

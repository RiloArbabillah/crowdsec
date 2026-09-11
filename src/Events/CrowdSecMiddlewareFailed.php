<?php

namespace RiloArbabillah\LaravelCrowdSec\Events;

use Illuminate\Broadcasting\InteractsWithSockets;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;
use Throwable;

/**
 * Dispatched when the CrowdSec middleware fails and falls back to fail-open.
 *
 * The middleware intentionally fails open so a package or database error never
 * locks legitimate users out, but a silent fail-open also means protection can
 * be skipped without anyone noticing. This event makes those occurrences
 * observable (monitoring, alerting, metrics) instead of log-only.
 */
class CrowdSecMiddlewareFailed
{
    use Dispatchable, InteractsWithSockets, SerializesModels;

    /**
     * @param  array<string, mixed>  $context
     */
    public function __construct(
        public string $ip,
        public string $path,
        public Throwable $exception,
        public array $context = [],
    ) {}
}

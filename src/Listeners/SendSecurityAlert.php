<?php

namespace RiloArbabillah\LaravelCrowdSec\Listeners;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Notification;
use RiloArbabillah\LaravelCrowdSec\Events\IpBlocked;
use RiloArbabillah\LaravelCrowdSec\Notifications\SecurityAlertNotification;

class SendSecurityAlert
{
    /**
     * Handle the IpBlocked event.
     */
    public function handle(IpBlocked $event): void
    {
        $config = config('crowdsec-scenarios.notifications', []);

        if (! ($config['enabled'] ?? false)) {
            return;
        }

        // Only notify for configured severity levels
        $severityThreshold = $config['severity_threshold'] ?? 'high';
        $severityWeights = ['low' => 1, 'medium' => 2, 'high' => 3, 'critical' => 4];

        // Derive severity from event type
        $scenarios = config('crowdsec-scenarios', []);
        $severity = 'medium';
        if ($event->eventType && isset($scenarios[$event->eventType]['severity'])) {
            $severity = $scenarios[$event->eventType]['severity'];
        }

        if (($severityWeights[$severity] ?? 0) < ($severityWeights[$severityThreshold] ?? 3)) {
            return;
        }

        // Rate limiting: max 1 notification per IP per 5 minutes
        $rateLimitMinutes = $config['rate_limit_minutes'] ?? 5;
        $cacheKey = "crowdsec:notify:{$event->ip}";

        if (Cache::has($cacheKey)) {
            return;
        }

        Cache::put($cacheKey, true, now()->addMinutes($rateLimitMinutes));

        // Send notification
        $recipients = $config['recipients'] ?? [];
        if (empty($recipients)) {
            return;
        }

        $notification = new SecurityAlertNotification(
            ip: $event->ip,
            reason: $event->reason,
            severity: $severity,
            context: [
                'duration_minutes' => $event->durationMinutes,
                'block_count' => $event->blockCount,
                'event_type' => $event->eventType,
            ]
        );

        Notification::route('mail', $recipients)
            ->notify($notification);
    }
}

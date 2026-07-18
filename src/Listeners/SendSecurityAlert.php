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

        $routes = $this->notificationRoutes($config);

        if (empty($routes)) {
            return;
        }

        // Cache::add is atomic on supported shared cache stores.
        $rateLimitMinutes = max(1, (int) ($config['rate_limit_minutes'] ?? 5));
        $cacheKey = "crowdsec:notify:{$event->ip}";
        if (! Cache::add($cacheKey, true, now()->addMinutes($rateLimitMinutes))) {
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

        Notification::routes($routes)->notify($notification);
    }

    protected function notificationRoutes(array $config): array
    {
        $channels = collect($config['channels'] ?? ['mail'])
            ->map(fn ($channel) => strtolower(trim((string) $channel)))
            ->filter()
            ->unique()
            ->values();

        $routes = [];

        if ($channels->contains('mail')) {
            $recipients = collect($config['recipients'] ?? [])
                ->map(fn ($recipient) => trim((string) $recipient))
                ->filter()
                ->values()
                ->all();

            if (! empty($recipients)) {
                $routes['mail'] = $recipients;
            }
        }

        if ($channels->contains('slack')) {
            $webhookUrl = trim((string) ($config['slack_webhook_url'] ?? ''));

            if ($webhookUrl !== '') {
                $routes['slack'] = $webhookUrl;
            }
        }

        return $routes;
    }
}

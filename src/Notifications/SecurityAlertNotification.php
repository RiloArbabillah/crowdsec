<?php

namespace RiloArbabillah\LaravelCrowdSec\Notifications;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Messages\SlackMessage;
use Illuminate\Notifications\Notification;

class SecurityAlertNotification extends Notification implements ShouldQueue
{
    use Queueable;

    public function __construct(
        public string $ip,
        public string $reason,
        public string $severity,
        public array $context = [],
    ) {}

    /**
     * Get the notification's delivery channels.
     */
    public function via(object $notifiable): array
    {
        return config('crowdsec-scenarios.notifications.channels', ['mail']);
    }

    /**
     * Get the mail representation.
     */
    public function toMail(object $notifiable): MailMessage
    {
        return (new MailMessage)
            ->subject("[CrowdSec] {$this->severity} security alert: {$this->reason}")
            ->greeting('🛡️ CrowdSec Security Alert')
            ->line("**Severity:** {$this->severity}")
            ->line("**IP Address:** {$this->ip}")
            ->line("**Reason:** {$this->reason}")
            ->line('**Time:** ' . now()->toDateTimeString())
            ->when(! empty($this->context), function ($message) {
                $message->line('**Context:** ' . json_encode($this->context, JSON_PRETTY_PRINT));
            })
            ->action('View Dashboard', url('/'))
            ->line('This is an automated security notification.');
    }

    /**
     * Get the Slack representation.
     */
    public function toSlack(object $notifiable): SlackMessage
    {
        return (new SlackMessage)
            ->error()
            ->content("🛡️ CrowdSec: {$this->severity} alert — {$this->reason}")
            ->attachment(function ($attachment) {
                $attachment
                    ->title('Security Alert')
                    ->fields([
                        'IP' => $this->ip,
                        'Severity' => $this->severity,
                        'Reason' => $this->reason,
                        'Time' => now()->toDateTimeString(),
                    ]);
            });
    }

    /**
     * Get the array representation (for database/broadcast).
     */
    public function toArray(object $notifiable): array
    {
        return [
            'ip' => $this->ip,
            'reason' => $this->reason,
            'severity' => $this->severity,
            'context' => $this->context,
            'timestamp' => now()->toISOString(),
        ];
    }
}

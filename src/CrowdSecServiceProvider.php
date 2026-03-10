<?php

namespace RiloArbabillah\LaravelCrowdSec;

use Illuminate\Auth\Events\Authenticated;
use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\ServiceProvider;
use RiloArbabillah\LaravelCrowdSec\Console\Commands\CrowdSecCleanup;
use RiloArbabillah\LaravelCrowdSec\Console\Commands\CrowdSecStats;
use RiloArbabillah\LaravelCrowdSec\Http\Middleware\CrowdSecProtection;
use RiloArbabillah\LaravelCrowdSec\Models\IpBehavior;
use RiloArbabillah\LaravelCrowdSec\Services\CrowdSecService;

class CrowdSecServiceProvider extends ServiceProvider
{
    /**
     * Register services.
     */
    public function register(): void
    {
        // Register the main service
        $this->app->singleton('crowdsec', function ($app) {
            return new CrowdSecService();
        });

        // Register the facade
        $this->app->alias('crowdsec', CrowdSecService::class);
    }

    /**
     * Bootstrap services.
     */
    public function boot(): void
    {
        // Load migrations
        $this->loadMigrationsFrom(__DIR__.'/Database/Migrations');

        // Publish config
        $this->publishes([
            __DIR__.'/../config/crowdsec-scenarios.php' => config_path('crowdsec-scenarios.php'),
        ], 'crowdsec-config');

        // Register commands
        if ($this->app->runningInConsole()) {
            $this->commands([
                CrowdSecCleanup::class,
                CrowdSecStats::class,
                \RiloArbabillah\LaravelCrowdSec\Console\Commands\CrowdSecExport::class,
            ]);
        }

        // Register middleware
        $router = $this->app['router'];
        $router->aliasMiddleware('crowdsec', CrowdSecProtection::class);
        $router->aliasMiddleware('crowdsec.honeypot', \RiloArbabillah\LaravelCrowdSec\Http\Middleware\HoneypotTrap::class);
        $router->aliasMiddleware('crowdsec.rate', \RiloArbabillah\LaravelCrowdSec\Http\Middleware\CrowdSecRateLimit::class);

        // Listen for successful authentication to unblock IP and reset login attempts
        Event::listen(Authenticated::class, function (Authenticated $event) {
            $ip = request()->ip() ?? 'unknown';
            $service = app('crowdsec');

            // Unblock the IP if it was blocked
            $service->unblockIp($ip);

            // Reset login attempts and threat score for this IP
            $behavior = IpBehavior::where('ip', $ip)->first();
            if ($behavior) {
                $behavior->update([
                    'login_attempts' => 0,
                    'threat_score' => 0,
                ]);
            }
        });

        // Register scheduled cleanup tasks (Laravel 11+ style)
        $this->registerScheduledCleanup();

        // Register event listeners for notifications
        Event::listen(
            \RiloArbabillah\LaravelCrowdSec\Events\IpBlocked::class,
            \RiloArbabillah\LaravelCrowdSec\Listeners\SendSecurityAlert::class
        );
    }

    /**
     * Register scheduled cleanup tasks.
     * Uses callAfterResolving for Laravel 11+ auto-registration.
     * For Laravel 10, users should add to app/Console/Kernel.php:
     *   $schedule->command('crowdsec:cleanup --expired')->daily();
     *   $schedule->command('crowdsec:cleanup --old-events')->weekly();
     *   $schedule->command('crowdsec:cleanup --old-behaviors')->weekly();
     */
    protected function registerScheduledCleanup(): void
    {
        $this->callAfterResolving(Schedule::class, function (Schedule $schedule) {
            // Clean up expired bans daily
            $schedule->command('crowdsec:cleanup --expired')
                ->daily()
                ->description('CrowdSec: cleanup expired bans');

            // Clean up old events weekly
            $schedule->command('crowdsec:cleanup --old-events')
                ->weekly()
                ->description('CrowdSec: cleanup old security events');

            // Clean up old behavior records weekly
            $schedule->command('crowdsec:cleanup --old-behaviors')
                ->weekly()
                ->description('CrowdSec: cleanup old behavior records');
        });
    }
}

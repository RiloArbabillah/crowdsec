<?php

namespace RiloArbabillah\LaravelCrowdSec;

use Illuminate\Auth\Events\Authenticated;
use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\ServiceProvider;
use RiloArbabillah\LaravelCrowdSec\Console\Commands\CrowdSecCleanup;
use RiloArbabillah\LaravelCrowdSec\Console\Commands\CrowdSecStats;
use RiloArbabillah\LaravelCrowdSec\Console\Commands\CrowdSecWhitelist;
use RiloArbabillah\LaravelCrowdSec\Http\Middleware\CrowdSecProtection;
use RiloArbabillah\LaravelCrowdSec\Models\IpBehavior;
use RiloArbabillah\LaravelCrowdSec\Services\CrowdSecService;
use RiloArbabillah\LaravelCrowdSec\Services\SecurityEventContextService;

class CrowdSecServiceProvider extends ServiceProvider
{
    /**
     * Register services.
     */
    public function register(): void
    {
        // Register the main service
        $this->app->singleton('crowdsec', function ($app) {
            return new CrowdSecService($app->make(SecurityEventContextService::class));
        });

        // Register the facade
        $this->app->alias('crowdsec', CrowdSecService::class);

        // Register GeoIP service
        $this->app->singleton(\RiloArbabillah\LaravelCrowdSec\Services\GeoIpService::class);
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

        // Load API routes (if enabled)
        if (config('crowdsec-scenarios.api.enabled', false)) {
            $this->loadRoutesFrom(__DIR__.'/../routes/api.php');
        }

        // Load metrics route (if enabled)
        if (config('crowdsec-scenarios.metrics.enabled', false)) {
            $this->loadRoutesFrom(__DIR__.'/../routes/metrics.php');
        }

        // Load dashboard routes (if enabled)
        if (config('crowdsec-scenarios.dashboard.enabled', false)) {
            $this->loadRoutesFrom(__DIR__.'/../routes/web.php');
        }

        // Register views
        $this->loadViewsFrom(__DIR__.'/../resources/views', 'crowdsec');

        // Publish views
        $this->publishes([
            __DIR__.'/../resources/views' => resource_path('views/vendor/crowdsec'),
        ], 'crowdsec-views');

        // Register commands
        if ($this->app->runningInConsole()) {
            $this->commands([
                CrowdSecCleanup::class,
                CrowdSecStats::class,
                CrowdSecWhitelist::class,
                \RiloArbabillah\LaravelCrowdSec\Console\Commands\CrowdSecExport::class,
                \RiloArbabillah\LaravelCrowdSec\Console\Commands\CrowdSecDoctor::class,
            ]);
        }

        // Register middleware
        $router = $this->app['router'];
        $router->aliasMiddleware('crowdsec', CrowdSecProtection::class);
        $router->aliasMiddleware('crowdsec.honeypot', \RiloArbabillah\LaravelCrowdSec\Http\Middleware\HoneypotTrap::class);
        $router->aliasMiddleware('crowdsec.rate', \RiloArbabillah\LaravelCrowdSec\Http\Middleware\CrowdSecRateLimit::class);

        // Reset the login window after successful authentication. Unblocking and
        // threat-score resets are secure opt-ins for backward compatibility.
        Event::listen(Authenticated::class, function (Authenticated $event) {
            $ip = request()->ip() ?? 'unknown';
            $service = app('crowdsec');

            if (config('crowdsec-scenarios.behavior.unblock_on_authentication', false)) {
                $service->unblockIp($ip);
            }

            $behavior = IpBehavior::where('ip', $ip)->first();
            if ($behavior) {
                $behavior->resetAuthenticationState(
                    (bool) config('crowdsec-scenarios.behavior.reset_threat_score_on_authentication', false),
                );
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

            // Purge expired whitelist entries daily
            $schedule->command('crowdsec:whitelist purge-expired')
                ->daily()
                ->description('CrowdSec: purge expired whitelist entries');
        });
    }
}

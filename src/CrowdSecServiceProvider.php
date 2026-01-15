<?php

namespace RiloArbabillah\LaravelCrowdSec;

use Illuminate\Auth\Events\Authenticated;
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

        // Load translations
        $this->loadTranslationsFrom(__DIR__.'/lang', 'crowdsec');

        // Publish config
        $this->publishes([
            __DIR__.'/../config/crowdsec-scenarios.php' => config_path('crowdsec-scenarios.php'),
        ], 'crowdsec-config');

        // Register commands
        if ($this->app->runningInConsole()) {
            $this->commands([
                CrowdSecCleanup::class,
                CrowdSecStats::class,
            ]);
        }

        // Register middleware
        $router = $this->app['router'];
        $router->aliasMiddleware('crowdsec', CrowdSecProtection::class);

        // Listen for successful authentication to unblock IP and reset login attempts
        Event::listen(Authenticated::class, function (Authenticated $event) {
            $ip = request()->ip() ?? 'unknown';
            $service = app(CrowdSecService::class);

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
    }
}

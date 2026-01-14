<?php

namespace RiloArbabillah\LaravelCrowdSec;

use Illuminate\Support\ServiceProvider;
use RiloArbabillah\LaravelCrowdSec\Console\Commands\CrowdSecCleanup;
use RiloArbabillah\LaravelCrowdSec\Console\Commands\CrowdSecStats;
use RiloArbabillah\LaravelCrowdSec\Http\Middleware\CrowdSecProtection;
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
    }
}

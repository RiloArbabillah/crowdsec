<?php

use Illuminate\Auth\Middleware\Authorize;
use Illuminate\Support\Facades\Route;
use RiloArbabillah\LaravelCrowdSec\Http\Controllers\CrowdSecDashboardController;

Route::prefix(config('crowdsec-scenarios.dashboard.path', 'crowdsec'))
    ->middleware(config('crowdsec-scenarios.dashboard.middleware', ['web', 'auth']))
    ->group(function () {
        Route::get('/', [CrowdSecDashboardController::class, 'index'])
            ->middleware(Authorize::class.':viewCrowdSec')
            ->name('crowdsec.dashboard');
    });

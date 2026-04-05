<?php

use Illuminate\Support\Facades\Route;
use RiloArbabillah\LaravelCrowdSec\Http\Controllers\CrowdSecDashboardController;

Route::prefix(config('crowdsec-scenarios.dashboard.path', 'crowdsec'))
    ->middleware(config('crowdsec-scenarios.dashboard.middleware', ['web', 'auth']))
    ->group(function () {
        Route::get('/', [CrowdSecDashboardController::class, 'index'])->name('crowdsec.dashboard');
    });

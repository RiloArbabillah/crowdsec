<?php

use Illuminate\Support\Facades\Route;
use RiloArbabillah\LaravelCrowdSec\Http\Controllers\CrowdSecApiController;

Route::prefix('api/crowdsec')
    ->middleware(config('crowdsec-scenarios.api.middleware', ['api', 'auth:sanctum']))
    ->group(function () {
        Route::get('/stats', [CrowdSecApiController::class, 'stats']);
        Route::get('/events', [CrowdSecApiController::class, 'events']);
        Route::get('/blocked', [CrowdSecApiController::class, 'blocked']);
        Route::post('/block', [CrowdSecApiController::class, 'block']);
        Route::delete('/block/{ip}', [CrowdSecApiController::class, 'unblock']);
        Route::get('/check/{ip}', [CrowdSecApiController::class, 'check']);
    });

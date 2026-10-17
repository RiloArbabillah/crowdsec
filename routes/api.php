<?php

use Illuminate\Auth\Middleware\Authorize;
use Illuminate\Support\Facades\Route;
use RiloArbabillah\LaravelCrowdSec\Http\Controllers\CrowdSecApiController;

$ipPattern = '[0-9A-Fa-f:.]+';

Route::prefix('api/crowdsec')
    ->name('crowdsec.api.')
    ->middleware(config('crowdsec-scenarios.api.middleware', ['api', 'auth:sanctum', 'throttle:60,1']))
    ->group(function () use ($ipPattern) {
        Route::middleware(Authorize::class.':viewCrowdSec')->group(function () use ($ipPattern) {
            Route::get('/stats', [CrowdSecApiController::class, 'stats'])->name('stats');
            Route::get('/events', [CrowdSecApiController::class, 'events'])->name('events');
            Route::get('/blocked', [CrowdSecApiController::class, 'blocked'])->name('blocked');
            Route::get('/check/{ip}', [CrowdSecApiController::class, 'check'])->name('check')->where('ip', $ipPattern);
            Route::get('/whitelist', [CrowdSecApiController::class, 'whitelist'])->name('whitelist');
        });

        Route::middleware(Authorize::class.':manageCrowdSec')->group(function () use ($ipPattern) {
            Route::post('/block', [CrowdSecApiController::class, 'block'])->name('block');
            Route::delete('/block/{ip}', [CrowdSecApiController::class, 'unblock'])->name('unblock')->where('ip', $ipPattern);
            Route::post('/whitelist', [CrowdSecApiController::class, 'addWhitelist'])->name('whitelist.store');
            Route::delete('/whitelist/{ip}', [CrowdSecApiController::class, 'removeWhitelist'])->name('whitelist.destroy')->where('ip', '[0-9A-Fa-f:.]+(/[0-9]{1,3})?');
        });
    });

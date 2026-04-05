<?php

use Illuminate\Support\Facades\Route;
use RiloArbabillah\LaravelCrowdSec\Http\Controllers\CrowdSecMetricsController;

Route::get(
    config('crowdsec-scenarios.metrics.path', 'crowdsec/metrics'),
    CrowdSecMetricsController::class
)->middleware(config('crowdsec-scenarios.metrics.middleware', ['web', 'auth']));

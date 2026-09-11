<?php

/**
 * PHPStan bootstrap (runs after Larastan boots the analysis application).
 *
 * Larastan validates `view-string` arguments by calling `view()->exists($name)`
 * against the booted application. The package's Blade namespace (`crowdsec::`)
 * is registered at runtime by CrowdSecServiceProvider; when Larastan resolves a
 * bare testbench application for this package, that namespace is not present, so
 * the dashboard view looks "missing" and `view('crowdsec::dashboard')` is
 * reported as an invalid view-string.
 *
 * Registering the same namespace here keeps static analysis in sync with runtime
 * without changing application behavior.
 */

use Illuminate\View\Factory;

if (! function_exists('app')) {
    return;
}

$app = function_exists('app') ? app() : null;

if ($app === null || ! $app->bound('view')) {
    return;
}

/** @var Factory $view */
$view = $app->make('view');
$view->addNamespace('crowdsec', dirname(__DIR__).'/resources/views');

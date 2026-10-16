<?php

// Usage: php tools/prepare-release.php <patch|minor|major> <latest-tag> [YYYY-MM-DD]
// Rewrites README.md and CHANGELOG.md for the next release and prints its version.

use RiloArbabillah\LaravelCrowdSec\Tools\ReleasePreparer;

require __DIR__.'/ReleasePreparer.php';

$bump = $argv[1] ?? '';
$latestTag = $argv[2] ?? '';
$date = $argv[3] ?? gmdate('Y-m-d');
$root = dirname(__DIR__);
$readme = file_get_contents($root.'/README.md');
$changelog = file_get_contents($root.'/CHANGELOG.md');

if ($readme === false || $changelog === false) {
    fwrite(STDERR, "Unable to read README.md or CHANGELOG.md.\n");
    exit(1);
}

try {
    $preparer = new ReleasePreparer();
    $version = $preparer->nextVersion($latestTag, $bump);
    [$readme, $changelog] = $preparer->prepare($version, $date, $readme, $changelog);
} catch (\Throwable $e) {
    fwrite(STDERR, $e->getMessage()."\n");
    exit(1);
}

if (file_put_contents($root.'/README.md', $readme) === false
    || file_put_contents($root.'/CHANGELOG.md', $changelog) === false) {
    fwrite(STDERR, "Unable to write README.md or CHANGELOG.md.\n");
    exit(1);
}

fwrite(STDOUT, $version."\n");

<?php

use RiloArbabillah\LaravelCrowdSec\Tools\ReleaseMetadataValidator;

require __DIR__.'/ReleaseMetadataValidator.php';

$version = $argv[1] ?? '';
$notesOutput = $argv[2] ?? null;
$root = dirname(__DIR__);
$readme = file_get_contents($root.'/README.md');
$changelog = file_get_contents($root.'/CHANGELOG.md');

if ($readme === false || $changelog === false) {
    fwrite(STDERR, "Unable to read README.md or CHANGELOG.md.\n");
    exit(1);
}

$validator = new ReleaseMetadataValidator();
$errors = $validator->validate($version, $readme, $changelog);

if ($errors !== []) {
    foreach ($errors as $error) {
        fwrite(STDERR, "- {$error}\n");
    }
    exit(1);
}

if ($notesOutput !== null) {
    $notes = $validator->releaseNotes($version, $changelog);
    if ($notes === null || file_put_contents($notesOutput, $notes."\n") === false) {
        fwrite(STDERR, "Unable to write release notes.\n");
        exit(1);
    }
}

fwrite(STDOUT, "Release metadata for {$version} is valid.\n");

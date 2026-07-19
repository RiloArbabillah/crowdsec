<?php

declare(strict_types=1);

$path = $argv[1] ?? '';
$minimum = isset($argv[2]) ? (float) $argv[2] : 85.0;

if ($path === '' || ! is_file($path)) {
    fwrite(STDERR, "Coverage report not found: {$path}\n");
    exit(1);
}

$report = simplexml_load_file($path);
if ($report === false) {
    fwrite(STDERR, "Coverage report is not valid XML: {$path}\n");
    exit(1);
}

$metrics = $report->project->metrics;
$statements = (int) ($metrics['statements'] ?? 0);
$covered = (int) ($metrics['coveredstatements'] ?? 0);

if ($statements === 0) {
    fwrite(STDERR, "Coverage report contains no executable statements.\n");
    exit(1);
}

$percentage = ($covered / $statements) * 100;
printf("Line coverage: %.2f%% (%d/%d), required: %.2f%%\n", $percentage, $covered, $statements, $minimum);

exit($percentage >= $minimum ? 0 : 1);

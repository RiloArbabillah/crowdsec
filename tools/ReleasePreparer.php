<?php

namespace RiloArbabillah\LaravelCrowdSec\Tools;

class ReleasePreparer
{
    public function nextVersion(string $latestTag, string $bump): string
    {
        if (preg_match('/\Av(\d+)\.(\d+)\.(\d+)\z/', $latestTag, $matches) !== 1) {
            throw new \InvalidArgumentException("Latest tag {$latestTag} is not a stable vX.Y.Z version.");
        }

        [$major, $minor, $patch] = [(int) $matches[1], (int) $matches[2], (int) $matches[3]];

        return match ($bump) {
            'major' => 'v'.($major + 1).'.0.0',
            'minor' => "v{$major}.".($minor + 1).'.0',
            'patch' => "v{$major}.{$minor}.".($patch + 1),
            default => throw new \InvalidArgumentException("Unknown bump {$bump}; use patch, minor, or major."),
        };
    }

    /**
     * Turn the [Unreleased] changelog section into a dated release and point
     * the README at the new version.
     *
     * @return array{0: string, 1: string} [readme, changelog]
     */
    public function prepare(string $version, string $date, string $readme, string $changelog): array
    {
        $readmePattern = '/The latest stable package release is `v\d+\.\d+\.\d+`\./';
        if (preg_match($readmePattern, $readme) !== 1) {
            throw new \RuntimeException('README has no "The latest stable package release is `vX.Y.Z`." line.');
        }

        if (preg_match('/^## \[Unreleased\]\R(.*?)(?=^## \[|\z)/ms', $changelog, $matches) !== 1 || trim($matches[1]) === '') {
            throw new \RuntimeException('CHANGELOG [Unreleased] section is missing or empty.');
        }

        $plainVersion = substr($version, 1);
        $changelog = (string) preg_replace(
            '/^## \[Unreleased\]\R\R?/m',
            "## [Unreleased]\n\n## [{$plainVersion}] - {$date}\n\n",
            $changelog,
            1,
        );
        $readme = (string) preg_replace($readmePattern, "The latest stable package release is `{$version}`.", $readme, 1);

        return [$readme, $changelog];
    }
}

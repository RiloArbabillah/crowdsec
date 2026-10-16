<?php

namespace RiloArbabillah\LaravelCrowdSec\Tests\Unit;

use PHPUnit\Framework\TestCase;
use RiloArbabillah\LaravelCrowdSec\Tools\ReleaseMetadataValidator;
use RiloArbabillah\LaravelCrowdSec\Tools\ReleasePreparer;

require_once __DIR__.'/../../tools/ReleaseMetadataValidator.php';
require_once __DIR__.'/../../tools/ReleasePreparer.php';

class ReleasePreparerTest extends TestCase
{
    protected ReleasePreparer $preparer;

    protected function setUp(): void
    {
        $this->preparer = new ReleasePreparer();
    }

    public function test_bumps_versions(): void
    {
        $this->assertSame('v1.5.1', $this->preparer->nextVersion('v1.5.0', 'patch'));
        $this->assertSame('v1.6.0', $this->preparer->nextVersion('v1.5.3', 'minor'));
        $this->assertSame('v2.0.0', $this->preparer->nextVersion('v1.5.3', 'major'));
    }

    public function test_rejects_unknown_bump_and_non_stable_tag(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->preparer->nextVersion('v1.5.0', 'huge');
    }

    public function test_rejects_non_stable_latest_tag(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->preparer->nextVersion('v1.0.0-alpha', 'patch');
    }

    public function test_prepares_metadata_that_passes_release_validation(): void
    {
        $readme = "Intro\n\nThe latest stable package release is `v1.5.0`.\n";
        $changelog = "# Changelog\n\n## [Unreleased]\n\n### Fixed\n\n- New fix\n\n## [1.5.0] - 2026-09-11\n\n- Old\n";

        [$newReadme, $newChangelog] = $this->preparer->prepare('v1.6.0', '2026-10-17', $readme, $changelog);

        $this->assertStringContainsString('The latest stable package release is `v1.6.0`.', $newReadme);
        $this->assertStringContainsString("## [Unreleased]\n\n## [1.6.0] - 2026-10-17\n\n### Fixed\n\n- New fix\n\n## [1.5.0]", $newChangelog);

        $validator = new ReleaseMetadataValidator();
        $this->assertSame([], $validator->validate('v1.6.0', $newReadme, $newChangelog));
        $this->assertSame("### Fixed\n\n- New fix", $validator->releaseNotes('v1.6.0', $newChangelog));
    }

    public function test_rejects_empty_unreleased_section(): void
    {
        $this->expectExceptionMessage('Unreleased');
        $this->preparer->prepare(
            'v1.6.0',
            '2026-10-17',
            'The latest stable package release is `v1.5.0`.',
            "## [Unreleased]\n\n## [1.5.0] - 2026-09-11\n\n- Old\n",
        );
    }

    public function test_rejects_readme_without_latest_stable_line(): void
    {
        $this->expectExceptionMessage('README');
        $this->preparer->prepare('v1.6.0', '2026-10-17', 'No version here', "## [Unreleased]\n\n- Fix\n");
    }
}

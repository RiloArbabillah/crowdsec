<?php

namespace RiloArbabillah\LaravelCrowdSec\Tests\Unit;

use PHPUnit\Framework\TestCase;
use RiloArbabillah\LaravelCrowdSec\Tools\ReleaseMetadataValidator;

require_once __DIR__.'/../../tools/ReleaseMetadataValidator.php';

class ReleaseMetadataValidatorTest extends TestCase
{
    protected ReleaseMetadataValidator $validator;

    protected function setUp(): void
    {
        $this->validator = new ReleaseMetadataValidator();
    }

    public function test_accepts_matching_stable_release_metadata(): void
    {
        $errors = $this->validator->validate(
            'v1.2.3',
            'The latest stable package release is `v1.2.3`.',
            "## [Unreleased]\n\n## [1.2.3] - 2026-07-19\n\n### Fixed\n\n- Example\n",
        );

        $this->assertSame([], $errors);
    }

    public function test_rejects_non_stable_semver(): void
    {
        $errors = $this->validator->validate('1.2', '', '');

        $this->assertStringContainsString('vX.Y.Z', $errors[0]);
    }

    public function test_reports_readme_and_changelog_mismatches(): void
    {
        $errors = $this->validator->validate('v1.2.3', 'v1.2.2', '## [Unreleased]');

        $this->assertCount(2, $errors);
    }

    public function test_extracts_only_requested_release_notes(): void
    {
        $changelog = "## [1.2.3] - 2026-07-19\n\n### Fixed\n\n- Current\n\n## [1.2.2] - 2026-07-18\n\n- Old\n";

        $this->assertSame("### Fixed\n\n- Current", $this->validator->releaseNotes('v1.2.3', $changelog));
    }
}

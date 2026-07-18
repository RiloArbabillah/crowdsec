<?php

namespace RiloArbabillah\LaravelCrowdSec\Tools;

class ReleaseMetadataValidator
{
    /**
     * @return array<int, string>
     */
    public function validate(string $version, string $readme, string $changelog): array
    {
        $errors = [];

        if (preg_match('/\Av\d+\.\d+\.\d+\z/', $version) !== 1) {
            $errors[] = 'Version must use stable SemVer format vX.Y.Z.';

            return $errors;
        }

        if (! str_contains($readme, "The latest stable package release is `{$version}`.")) {
            $errors[] = "README latest stable version does not match {$version}.";
        }

        if ($this->releaseNotes($version, $changelog) === null) {
            $errors[] = "CHANGELOG does not contain a dated [{$this->withoutPrefix($version)}] section.";
        }

        return $errors;
    }

    public function releaseNotes(string $version, string $changelog): ?string
    {
        $plainVersion = preg_quote($this->withoutPrefix($version), '/');
        $pattern = "/^## \[{$plainVersion}\] - \d{4}-\d{2}-\d{2}\R(.*?)(?=^## \[|\z)/ms";

        if (preg_match($pattern, $changelog, $matches) !== 1) {
            return null;
        }

        return trim($matches[1]);
    }

    protected function withoutPrefix(string $version): string
    {
        return str_starts_with($version, 'v') ? substr($version, 1) : $version;
    }
}

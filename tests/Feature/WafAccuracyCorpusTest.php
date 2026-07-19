<?php

namespace RiloArbabillah\LaravelCrowdSec\Tests\Feature;

use Illuminate\Http\Request;
use PHPUnit\Framework\Attributes\DataProvider;
use RiloArbabillah\LaravelCrowdSec\Services\CrowdSecService;
use RiloArbabillah\LaravelCrowdSec\Tests\PackageTestCase;

class WafAccuracyCorpusTest extends PackageTestCase
{
    private CrowdSecService $service;

    protected function setUp(): void
    {
        parent::setUp();
        $this->service = $this->app->make(CrowdSecService::class);
    }

    /**
     * @param array<string, mixed> $sample
     */
    #[DataProvider('maliciousSamples')]
    public function test_malicious_sample_matches_expected_scenario(string $scenario, array $sample): void
    {
        $types = array_column($this->service->analyzeRequest($this->requestFrom($sample)), 'type');

        $this->assertContains($scenario, $types, "Expected {$scenario} for {$sample['path']}");
    }

    /**
     * @param array<string, mixed> $sample
     */
    #[DataProvider('benignSamples')]
    public function test_benign_sample_has_no_detection(array $sample): void
    {
        $this->assertSame([], $this->service->analyzeRequest($this->requestFrom($sample)));
    }

    /**
     * @return iterable<string, array{string, array<string, mixed>}>
     */
    public static function maliciousSamples(): iterable
    {
        foreach (self::corpus()['malicious'] as $index => $sample) {
            $scenario = (string) $sample['scenario'];
            unset($sample['scenario']);
            yield "{$scenario}-{$index}" => [$scenario, $sample];
        }
    }

    /**
     * @return iterable<string, array{array<string, mixed>}>
     */
    public static function benignSamples(): iterable
    {
        foreach (self::corpus()['benign'] as $index => $sample) {
            yield "benign-{$index}" => [$sample];
        }
    }

    /**
     * @param array<string, mixed> $sample
     */
    private function requestFrom(array $sample): Request
    {
        $server = [];
        foreach (($sample['headers'] ?? []) as $name => $value) {
            $server['HTTP_' . strtoupper(str_replace('-', '_', (string) $name))] = $value;
        }
        if (isset($sample['content_type'])) {
            $server['CONTENT_TYPE'] = $sample['content_type'];
        }

        return Request::create(
            (string) $sample['path'],
            (string) ($sample['method'] ?? 'GET'),
            (array) ($sample['body'] ?? []),
            [],
            [],
            $server,
            (string) ($sample['content'] ?? ''),
        );
    }

    /**
     * @return array{version: int, malicious: list<array<string, mixed>>, benign: list<array<string, mixed>>}
     */
    private static function corpus(): array
    {
        $contents = file_get_contents(__DIR__ . '/../Fixtures/waf-accuracy-v1.json');
        self::assertNotFalse($contents);
        $corpus = json_decode($contents, true, flags: JSON_THROW_ON_ERROR);
        self::assertSame(1, $corpus['version']);

        return $corpus;
    }
}

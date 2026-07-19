<?php

namespace RiloArbabillah\LaravelCrowdSec\Services;

use Illuminate\Http\Request;
use Illuminate\Support\Str;

class WafPolicy
{
    public const MODE_ENFORCE = 'enforce';

    public const MODE_MONITOR = 'monitor';

    public const MODE_DISABLED = 'disabled';

    public const VALID_MODES = [
        self::MODE_ENFORCE,
        self::MODE_MONITOR,
        self::MODE_DISABLED,
    ];

    /** @param array<string, mixed> $config */
    public function __construct(protected array $config = []) {}

    /**
     * @return array{ignored_body_fields: array<int, string>, skipped_scenarios: array<int, string>}
     */
    public function exclusionsFor(Request $request): array
    {
        $ignoredBodyFields = [];
        $skippedScenarios = [];

        $rules = is_array($this->config['exclusions'] ?? null) ? $this->config['exclusions'] : [];

        foreach ($rules as $rule) {
            if (! is_array($rule) || ! $this->matchesRequest($request, $rule)) {
                continue;
            }

            $ignoredBodyFields = array_merge(
                $ignoredBodyFields,
                $this->stringList($rule['ignore_body_fields'] ?? []),
            );
            $skippedScenarios = array_merge(
                $skippedScenarios,
                $this->stringList($rule['skip_scenarios'] ?? []),
            );
        }

        return [
            'ignored_body_fields' => array_values(array_unique($ignoredBodyFields)),
            'skipped_scenarios' => array_values(array_unique($skippedScenarios)),
        ];
    }

    /** @param array<string, mixed> $scenario */
    public function modeFor(string $type, array $scenario = []): string
    {
        $scenarioModes = is_array($this->config['scenario_modes'] ?? null)
            ? $this->config['scenario_modes']
            : [];
        $configuredMode = $scenarioModes[$type]
            ?? $scenario['mode']
            ?? $this->config['default_mode']
            ?? self::MODE_ENFORCE;

        $mode = is_string($configuredMode) ? strtolower($configuredMode) : self::MODE_ENFORCE;

        return in_array($mode, self::VALID_MODES, true) ? $mode : self::MODE_ENFORCE;
    }

    /** @param list<string> $patterns */
    public function skipsScenario(string $type, array $patterns): bool
    {
        foreach ($patterns as $pattern) {
            if (Str::is($pattern, $type)) {
                return true;
            }
        }

        return false;
    }

    /** @param array<string, mixed> $rule */
    protected function matchesRequest(Request $request, array $rule): bool
    {
        $routeNames = $this->stringList($rule['route_names'] ?? []);
        $paths = $this->stringList($rule['paths'] ?? []);
        $methods = array_map('strtoupper', $this->stringList($rule['methods'] ?? []));

        $route = $request->route();
        $routeName = is_object($route) && method_exists($route, 'getName')
            ? $route->getName()
            : null;

        return ($routeNames === [] || ($routeName !== null && $this->matchesAny($routeName, $routeNames)))
            && ($paths === [] || $this->matchesAny($request->path(), $paths))
            && ($methods === [] || in_array(strtoupper($request->method()), $methods, true));
    }

    /** @param list<string> $patterns */
    protected function matchesAny(string $value, array $patterns): bool
    {
        foreach ($patterns as $pattern) {
            if (Str::is($pattern, $value)) {
                return true;
            }
        }

        return false;
    }

    /** @return list<string> */
    protected function stringList(mixed $items): array
    {
        if (! is_array($items)) {
            return [];
        }

        return array_values(array_filter(array_map(
            fn ($item) => trim((string) $item),
            $items,
        ), fn ($item) => $item !== ''));
    }
}

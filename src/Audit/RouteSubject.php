<?php

declare(strict_types=1);

namespace Usamamuneerchaudhary\GatekeeperAudit\Audit;

final readonly class RouteSubject
{
    /**
     * @param  list<string>  $methods
     * @param  list<string>  $middleware
     * @param  list<array{name: string, model: class-string|string|null, variable: string|null}>  $objectParameters
     * @param  list<string>  $binderScopedParameters
     */
    public function __construct(
        public array $methods,
        public string $uri,
        public ?string $name,
        public string $action,
        public ?string $controllerClass,
        public ?string $method,
        public ?string $file,
        public ?int $line,
        public bool $isClosure,
        public array $middleware,
        public array $objectParameters,
        public bool $scopedBindings,
        public array $binderScopedParameters = [],
        public ?string $skipReason = null,
    ) {}

    /**
     * Whether this route names a single object through a URI parameter.
     */
    public function isObjectRoute(): bool
    {
        return $this->objectParameters !== [];
    }

    /**
     * Whether any verb mutates state.
     */
    public function isWrite(): bool
    {
        return array_intersect($this->methods, ['POST', 'PUT', 'PATCH', 'DELETE']) !== [];
    }

    /**
     * Route parameter names that carry an object or identifier.
     *
     * @return list<string>
     */
    public function objectParameterNames(): array
    {
        return array_values(array_map(static fn (array $parameter): string => $parameter['name'], $this->objectParameters));
    }

    /**
     * Model classes bound to route parameters, when known.
     *
     * @return list<string>
     */
    public function boundModelClasses(): array
    {
        $models = [];

        foreach ($this->objectParameters as $parameter) {
            if (is_string($parameter['model']) && $parameter['model'] !== '') {
                $models[] = $parameter['model'];
            }
        }

        return array_values(array_unique($models));
    }
}

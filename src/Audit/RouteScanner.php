<?php

declare(strict_types=1);

namespace Usamamuneerchaudhary\GatekeeperAudit\Audit;

use Illuminate\Routing\Route;
use Illuminate\Routing\Router;

final readonly class RouteScanner
{
    /**
     * Read audit options that decide which routes are in scope.
     *
     * @param  array<string, mixed>  $config
     */
    public function __construct(
        private Router $router,
        private array $config,
    ) {}

    /**
     * Build subjects for every registered route.
     *
     * Vendor and public routes are marked skipped instead of dropped, so the
     * verbose report can explain why they were not audited.
     *
     * @return list<RouteSubject>
     */
    public function scan(bool $includeVendor = false, bool $includePublic = false, ?string $only = null): array
    {
        $subjects = [];

        foreach ($this->router->getRoutes() as $route) {
            if (! $route instanceof Route) {
                continue;
            }

            $subject = $this->subjectFor($route, $includeVendor, $includePublic);

            if ($subject === null) {
                continue;
            }

            if ($only !== null && $only !== '' && ! str_starts_with($subject->uri, ltrim($only, '/'))) {
                continue;
            }

            $subjects[] = $subject;
        }

        return $subjects;
    }

    /**
     * Build one subject, or null for verbs Laravel adds implicitly.
     */
    private function subjectFor(Route $route, bool $includeVendor, bool $includePublic): ?RouteSubject
    {
        $methods = array_values(array_filter($route->methods(), static fn (string $method): bool => $method !== 'HEAD'));

        if ($methods === []) {
            return null;
        }

        sort($methods);

        $uri = $route->uri();
        $action = $route->getAction();
        $uses = $action['uses'] ?? null;
        $middleware = array_values(array_map('strval', $route->gatherMiddleware()));

        $controllerClass = null;
        $method = null;
        $file = null;
        $line = null;
        $isClosure = false;
        $actionLabel = 'unknown';
        $parameters = [];

        if ($uses instanceof \Closure) {
            $isClosure = true;
            $reflection = new \ReflectionFunction($uses);
            $file = $reflection->getFileName() ?: null;
            $line = $reflection->getStartLine() ?: null;
            $actionLabel = 'Closure in '.($file !== null ? basename($file) : 'unknown').($line !== null ? ':'.$line : '');
            $parameters = $this->closureParameters($reflection);
        } elseif (is_string($uses) && str_contains($uses, '@')) {
            [$controllerClass, $method] = explode('@', $uses, 2);
            $controllerClass = ltrim($controllerClass, '\\');
            $actionLabel = $controllerClass.'@'.$method;
            [$file, $line, $parameters] = $this->controllerDetails($controllerClass, $method);
        } elseif (is_array($uses) && isset($uses[0], $uses[1]) && is_string($uses[0])) {
            $controllerClass = ltrim($uses[0], '\\');
            $method = (string) $uses[1];
            $actionLabel = $controllerClass.'@'.$method;
            [$file, $line, $parameters] = $this->controllerDetails($controllerClass, $method);
        } elseif (is_string($uses) && class_exists($uses)) {
            $controllerClass = ltrim($uses, '\\');
            $method = '__invoke';
            $actionLabel = $controllerClass;
            [$file, $line, $parameters] = $this->controllerDetails($controllerClass, '__invoke');
        } else {
            $actionLabel = is_string($route->getActionName()) ? $route->getActionName() : 'unknown';
        }

        $objectParameters = $this->objectParameters($route, $parameters);
        $scopedBindings = false;

        if (method_exists($route, 'enforcesScopedBindings')) {
            $scopedBindings = $route->enforcesScopedBindings();
        }

        if (! $scopedBindings && isset($action['scope_bindings'])) {
            $scopedBindings = (bool) $action['scope_bindings'];
        }

        $skipReason = $this->skipReason($route, $uri, $middleware, $controllerClass, $file, $includeVendor, $includePublic);

        return new RouteSubject(
            methods: $methods,
            uri: $uri,
            name: $route->getName(),
            action: $actionLabel,
            controllerClass: $controllerClass,
            method: $method,
            file: is_string($file) ? $file : null,
            line: is_int($line) ? $line : null,
            isClosure: $isClosure,
            middleware: $middleware,
            objectParameters: $objectParameters,
            scopedBindings: $scopedBindings,
            binderScopedParameters: $this->binderScopedParameters($route),
            skipReason: $skipReason,
        );
    }

    /**
     * Reflection details for a controller action.
     *
     * @return array{string|null, int|null, list<array{name: string, type: string|null}>}
     */
    private function controllerDetails(string $class, string $method): array
    {
        if (! class_exists($class) || ! method_exists($class, $method)) {
            return [null, null, []];
        }

        try {
            $reflection = new \ReflectionMethod($class, $method);
        } catch (\Throwable) {
            return [null, null, []];
        }

        $parameters = [];

        foreach ($reflection->getParameters() as $parameter) {
            $type = $parameter->getType();
            $typeName = null;

            if ($type instanceof \ReflectionNamedType && ! $type->isBuiltin()) {
                $typeName = ltrim($type->getName(), '\\');
            }

            $parameters[] = ['name' => $parameter->getName(), 'type' => $typeName];
        }

        $file = $reflection->getFileName();

        return [is_string($file) ? $file : null, $reflection->getStartLine() ?: null, $parameters];
    }

    /**
     * Reflection parameters for a route closure.
     *
     * @return list<array{name: string, type: string|null}>
     */
    private function closureParameters(\ReflectionFunction $reflection): array
    {
        $parameters = [];

        foreach ($reflection->getParameters() as $parameter) {
            $type = $parameter->getType();
            $typeName = null;

            if ($type instanceof \ReflectionNamedType && ! $type->isBuiltin()) {
                $typeName = ltrim($type->getName(), '\\');
            }

            $parameters[] = ['name' => $parameter->getName(), 'type' => $typeName];
        }

        return $parameters;
    }

    /**
     * URI parameters that carry an object or identifier, with their model types.
     *
     * @param  list<array{name: string, type: string|null}>  $parameters
     * @return list<array{name: string, model: string|null, variable: string|null}>
     */
    private function objectParameters(Route $route, array $parameters): array
    {
        $byName = [];

        foreach ($parameters as $parameter) {
            $byName[$parameter['name']] = $parameter;
        }

        $objects = [];

        foreach ($route->parameterNames() as $name) {
            $parameter = $byName[$name] ?? null;
            $model = null;

            if ($parameter !== null && $parameter['type'] !== null && class_exists($parameter['type'])
                && is_subclass_of($parameter['type'], 'Illuminate\\Database\\Eloquent\\Model')) {
                $model = $parameter['type'];
            }

            $objects[] = ['name' => $name, 'model' => $model, 'variable' => $parameter['name'] ?? $name];
        }

        return $objects;
    }

    /**
     * Route parameters with an explicit binder whose closure reads the authenticated user.
     *
     * @return list<string>
     */
    private function binderScopedParameters(Route $route): array
    {
        try {
            $property = new \ReflectionProperty($this->router, 'binders');
            $binders = $property->getValue($this->router);
        } catch (\Throwable) {
            return [];
        }

        if (! is_array($binders)) {
            return [];
        }

        $scoped = [];

        foreach ($route->parameterNames() as $name) {
            $binder = $binders[$name] ?? null;

            if (! $binder instanceof \Closure) {
                continue;
            }

            try {
                $reflection = new \ReflectionFunction($binder);
                $file = $reflection->getFileName();
                $start = $reflection->getStartLine();
                $end = $reflection->getEndLine();

                if (! is_string($file) || ! is_file($file)) {
                    continue;
                }

                $lines = file($file);

                if ($lines === false || $start === false || $end === false) {
                    continue;
                }

                $source = implode('', array_slice($lines, max(0, $start - 1), $end - $start + 1));

                if (str_contains($source, 'auth') || str_contains($source, '->user()') || str_contains($source, 'request()->user')) {
                    $scoped[] = $name;
                }
            } catch (\Throwable) {
                continue;
            }
        }

        return $scoped;
    }

    /**
     * Why a route is out of scope, or null when it should be audited.
     *
     * @param  list<string>  $middleware
     */
    private function skipReason(Route $route, string $uri, array $middleware, ?string $controllerClass, ?string $file, bool $includeVendor, bool $includePublic): ?string
    {
        if ($uri === 'up') {
            return 'health check route';
        }

        if ($controllerClass !== null && (str_starts_with($controllerClass, 'Livewire\\') || str_starts_with($controllerClass, 'Filament\\'))) {
            return 'Livewire and Filament actions are not scanned in this version';
        }

        if (str_starts_with($uri, '_livewire') || str_starts_with($uri, 'livewire')) {
            return 'Livewire endpoint';
        }

        $isVendor = ($file !== null && str_contains(str_replace('\\', '/', $file), '/vendor/'))
            || ($controllerClass !== null && (str_starts_with($controllerClass, 'Illuminate\\') || str_starts_with($controllerClass, 'Livewire\\') || str_starts_with($controllerClass, 'Filament\\')));

        if ($isVendor && ! $includeVendor) {
            return 'vendor route';
        }

        foreach ($this->stringList($this->config['ignore_routes'] ?? []) as $prefix) {
            if (str_starts_with($uri, ltrim($prefix, '/'))) {
                return 'ignored by gatekeeper.ignore_routes';
            }
        }

        if ($controllerClass !== null && in_array($controllerClass, $this->stringList($this->config['ignore_controllers'] ?? []), true)) {
            return 'ignored by gatekeeper.ignore_controllers';
        }

        if (! $includePublic && ! $this->isAuthenticated($middleware)) {
            return 'public route without auth middleware';
        }

        return null;
    }

    /**
     * Whether resolved middleware proves a user is signed in.
     *
     * @param  list<string>  $middleware
     */
    private function isAuthenticated(array $middleware): bool
    {
        $prefixes = $this->stringList($this->config['auth_middleware'] ?? ['auth']);

        foreach ($middleware as $entry) {
            foreach ($prefixes as $prefix) {
                if ($entry === $prefix || str_starts_with($entry, $prefix.':') || str_starts_with($entry, $prefix.',')) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Normalise a config value to a list of strings.
     *
     * @return list<string>
     */
    private function stringList(mixed $value): array
    {
        if (! is_array($value)) {
            return [];
        }

        return array_values(array_map('strval', $value));
    }
}

<?php

declare(strict_types=1);

namespace Usamamuneerchaudhary\GatekeeperAudit\Audit;

use PhpParser\Node;
use PhpParser\Node\Expr\Array_;
use PhpParser\Node\Expr\ClassConstFetch;
use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Expr\StaticCall;
use PhpParser\Node\Identifier;
use PhpParser\Node\Name;
use PhpParser\Node\Scalar\String_;
use PhpParser\NodeFinder;
use PhpParser\NodeTraverser;
use PhpParser\NodeVisitor\NameResolver;
use PhpParser\Parser;
use PhpParser\ParserFactory;
use Throwable;

final class RouteFileMap
{
    private const array VERBS = ['get', 'post', 'put', 'patch', 'delete', 'options', 'any', 'view', 'redirect', 'permanentredirect'];

    private const array RESOURCE = ['index', 'create', 'store', 'show', 'edit', 'update', 'destroy'];

    private const array API_RESOURCE = ['index', 'show', 'store', 'update', 'destroy'];

    private const array SINGLETON = ['show', 'edit', 'update'];

    private const array API_SINGLETON = ['store', 'show', 'update', 'destroy'];

    private Parser $parser;

    /** @var array<string, list<array{file: string, uri: string|null}>>|null */
    private ?array $actions = null;

    /**
     * Create the parser used to read route files.
     */
    public function __construct()
    {
        $this->parser = (new ParserFactory)->createForNewestSupportedVersion();
    }

    /**
     * Route file that registered an action, relative to the application when it lives there.
     *
     * Returns `vendor` for framework files and `unknown` when the defining file cannot be resolved.
     * A matching URI wins over a resource registration of the same action.
     */
    public function find(string $action, string $uri, ?string $closureFile): string
    {
        if ($closureFile !== null && $closureFile !== '') {
            return $this->display($closureFile);
        }

        $this->actions ??= $this->build();
        $action = ltrim($action, '\\');
        $candidates = $this->actions[$action] ?? [];

        if ($candidates === [] && str_ends_with($action, '@__invoke')) {
            $candidates = $this->actions[substr($action, 0, -strlen('@__invoke'))] ?? [];
        }

        return $this->choose($candidates, $uri) ?? 'unknown';
    }

    /**
     * Index controller actions declared in loaded PHP and in routes/*.php.
     *
     * Returns an empty map when no route registration can be read.
     *
     * @return array<string, list<array{file: string, uri: string|null}>>
     */
    private function build(): array
    {
        $actions = [];

        foreach ($this->files() as $file) {
            foreach ($this->registrations($file) as $registration) {
                $actions[$registration['action']][] = [
                    'file' => $registration['file'],
                    'uri' => $registration['uri'],
                ];
            }
        }

        return $actions;
    }

    /**
     * PHP files that may have registered routes.
     *
     * Vendor files are left out. Route files under the application are included even when a cache already loaded them.
     *
     * @return list<string>
     */
    private function files(): array
    {
        $paths = get_included_files();
        $routes = base_path('routes');

        if (is_dir($routes)) {
            $iterator = new \RecursiveIteratorIterator(
                new \RecursiveDirectoryIterator($routes, \FilesystemIterator::SKIP_DOTS),
            );

            foreach ($iterator as $file) {
                if ($file->isFile() && $file->getExtension() === 'php') {
                    $paths[] = $file->getPathname();
                }
            }
        }

        $unique = [];

        foreach ($paths as $path) {
            $real = realpath($path);

            if ($real === false || $this->isVendorPath($real)) {
                continue;
            }

            $unique[$real] = $real;
        }

        return array_values($unique);
    }

    /**
     * Controller actions registered from one file.
     *
     * Returns an empty list when the file cannot be parsed or contains no route registration.
     *
     * @return list<array{action: string, file: string, uri: string|null}>
     */
    private function registrations(string $file): array
    {
        $code = file_get_contents($file);

        if ($code === false || ! $this->mightRegisterRoutes($code)) {
            return [];
        }

        try {
            $statements = $this->parser->parse($code);
        } catch (Throwable) {
            return [];
        }

        if ($statements === null) {
            return [];
        }

        $traverser = new NodeTraverser;
        $traverser->addVisitor(new NameResolver(null, ['replaceNodes' => true, 'preserveOriginalNames' => true]));
        $statements = $traverser->traverse($statements);
        $finder = new NodeFinder;
        $calls = $finder->find($statements, static fn (Node $node): bool => $node instanceof StaticCall || $node instanceof MethodCall);
        $display = $this->display($file);
        $registrations = [];

        foreach ($calls as $call) {
            if (! $call instanceof StaticCall && ! $call instanceof MethodCall) {
                continue;
            }

            if ($call instanceof StaticCall && ! $this->isRouteCall($call)) {
                continue;
            }

            $name = $this->callName($call);

            if ($name === null) {
                continue;
            }

            foreach ($this->actionsFor($call, $name, $calls) as $action) {
                $registrations[] = [
                    'action' => $action['action'],
                    'file' => $display,
                    'uri' => $action['uri'],
                ];
            }
        }

        return $registrations;
    }

    /**
     * Whether the source is worth parsing.
     */
    private function mightRegisterRoutes(string $code): bool
    {
        return str_contains($code, 'Route::')
            || str_contains($code, '->get(')
            || str_contains($code, '->post(')
            || str_contains($code, '->put(')
            || str_contains($code, '->patch(')
            || str_contains($code, '->delete(')
            || str_contains($code, '->resource(')
            || str_contains($code, '->apiResource(')
            || str_contains($code, '->match(');
    }

    /**
     * Whether a static call is on the Route facade, including an unqualified alias.
     */
    private function isRouteCall(StaticCall $call): bool
    {
        if (! $call->class instanceof Name) {
            return false;
        }

        $name = ltrim($call->class->toString(), '\\');

        return $name === 'Route' || str_ends_with($name, '\\Route');
    }

    /**
     * Lowercase call name, or null when the name is dynamic.
     */
    private function callName(StaticCall|MethodCall $call): ?string
    {
        if (! $call->name instanceof Identifier) {
            return null;
        }

        return strtolower($call->name->toString());
    }

    /**
     * Actions created by one route call.
     *
     * Returns an empty list when the call is not a route registration.
     *
     * @param  list<Node>  $calls
     * @return list<array{action: string, uri: string|null}>
     */
    private function actionsFor(StaticCall|MethodCall $call, string $name, array $calls): array
    {
        if (in_array($name, self::VERBS, true)) {
            $action = $this->actionExpression($this->argument($call, 1));
            $uri = $this->stringValue($this->argument($call, 0));

            return $action === null ? [] : [['action' => $action, 'uri' => $uri]];
        }

        if ($name === 'match') {
            $action = $this->actionExpression($this->argument($call, 2));
            $uri = $this->stringValue($this->argument($call, 1));

            return $action === null ? [] : [['action' => $action, 'uri' => $uri]];
        }

        $methods = match ($name) {
            'resource', 'resources' => self::RESOURCE,
            'apiresource', 'apiresources' => self::API_RESOURCE,
            'singleton', 'singletons' => self::SINGLETON,
            'apisingleton', 'apisingletons' => self::API_SINGLETON,
            default => null,
        };

        if ($methods === null) {
            return [];
        }

        $methods = $this->limitedMethods($call, $methods, $calls);

        if (in_array($name, ['resources', 'apiresources', 'singletons', 'apisingletons'], true)) {
            return $this->resourceMap($this->argument($call, 0), $methods);
        }

        $controller = $this->className($this->argument($call, 1));

        if ($controller === null) {
            return [];
        }

        return $this->methodActions($controller, $methods);
    }

    /**
     * Apply only and except from a chained call or the options array.
     *
     * @param  list<string>  $methods
     * @param  list<Node>  $calls
     * @return list<string>
     */
    private function limitedMethods(StaticCall|MethodCall $call, array $methods, array $calls): array
    {
        $options = $this->options($this->argument($call, 2));

        if (isset($options['only'])) {
            $methods = array_values(array_intersect($methods, $options['only']));
        }

        if (isset($options['except'])) {
            $methods = array_values(array_diff($methods, $options['except']));
        }

        foreach ($calls as $limiter) {
            if (! $limiter instanceof MethodCall || $limiter->var !== $call) {
                continue;
            }

            $limiterName = $this->callName($limiter);
            $listed = $this->stringItems($this->argument($limiter, 0));

            if ($limiterName === 'only') {
                $methods = array_values(array_intersect($methods, $listed));
            }

            if ($limiterName === 'except') {
                $methods = array_values(array_diff($methods, $listed));
            }
        }

        return $methods;
    }

    /**
     * Actions for a map of resource name to controller.
     *
     * @param  list<string>  $methods
     * @return list<array{action: string, uri: string|null}>
     */
    private function resourceMap(?Node $node, array $methods): array
    {
        if (! $node instanceof Array_) {
            return [];
        }

        $actions = [];

        foreach ($node->items as $item) {
            if ($item === null) {
                continue;
            }

            $controller = $this->className($item->value);

            if ($controller === null) {
                continue;
            }

            $actions = [...$actions, ...$this->methodActions($controller, $methods)];
        }

        return $actions;
    }

    /**
     * One entry per resource method. The URI is left empty because the framework expands it.
     *
     * @param  list<string>  $methods
     * @return list<array{action: string, uri: string|null}>
     */
    private function methodActions(string $controller, array $methods): array
    {
        $actions = [];

        foreach ($methods as $method) {
            $actions[] = ['action' => $controller.'@'.$method, 'uri' => null];
        }

        return $actions;
    }

    /**
     * Positional argument node, or null when it is absent.
     */
    private function argument(StaticCall|MethodCall $call, int $index): ?Node
    {
        $argument = $call->args[$index] ?? null;

        return $argument instanceof Node\Arg ? $argument->value : null;
    }

    /**
     * Controller action from a class pair, an invokable class, or a Class@method string.
     *
     * Returns null when the argument is not a controller reference.
     */
    private function actionExpression(?Node $node): ?string
    {
        if ($node instanceof Array_) {
            $class = $this->className($node->items[0]->value ?? null);
            $method = $this->stringValue($node->items[1]->value ?? null);

            if ($class !== null && $method !== null && $method !== '') {
                return $class.'@'.$method;
            }

            return null;
        }

        if ($node instanceof String_ && str_contains($node->value, '@')) {
            return ltrim($node->value, '\\');
        }

        $class = $this->className($node);

        return $class === null ? null : $class.'@__invoke';
    }

    /**
     * Fully qualified class from a ::class constant.
     *
     * Returns null when the node is not a class constant.
     */
    private function className(?Node $node): ?string
    {
        if (! $node instanceof ClassConstFetch || ! $node->class instanceof Name) {
            return null;
        }

        if (! $node->name instanceof Identifier || strtolower($node->name->toString()) !== 'class') {
            return null;
        }

        return ltrim($node->class->toString(), '\\');
    }

    /**
     * String value of a literal, or null for any other node.
     */
    private function stringValue(?Node $node): ?string
    {
        return $node instanceof String_ ? $node->value : null;
    }

    /**
     * String items in an array literal.
     *
     * @return list<string>
     */
    private function stringItems(?Node $node): array
    {
        if (! $node instanceof Array_) {
            return [];
        }

        $values = [];

        foreach ($node->items as $item) {
            if ($item !== null && $item->value instanceof String_) {
                $values[] = $item->value->value;
            }
        }

        return $values;
    }

    /**
     * only and except lists from a resource options array.
     *
     * @return array{only?: list<string>, except?: list<string>}
     */
    private function options(?Node $node): array
    {
        if (! $node instanceof Array_) {
            return [];
        }

        $options = [];

        foreach ($node->items as $item) {
            if ($item === null || ! $item->key instanceof String_) {
                continue;
            }

            $key = $item->key->value;

            if ($key === 'only' || $key === 'except') {
                $options[$key] = $this->stringItems($item->value);
            }
        }

        return $options;
    }

    /**
     * Pick the file whose declared URI matches, otherwise the only resource file.
     *
     * Returns null when several files remain possible.
     *
     * @param  list<array{file: string, uri: string|null}>  $candidates
     */
    private function choose(array $candidates, string $uri): ?string
    {
        if ($candidates === []) {
            return null;
        }

        $uri = trim($uri, '/');
        $matched = [];

        foreach ($candidates as $candidate) {
            if ($candidate['uri'] === null) {
                continue;
            }

            $defined = trim($candidate['uri'], '/');

            if ($defined !== '' && ($uri === $defined || str_ends_with($uri, '/'.$defined))) {
                $matched[$candidate['file']] = true;
            }
        }

        if (count($matched) === 1) {
            return array_key_first($matched);
        }

        if ($matched !== []) {
            return null;
        }

        $unspecified = [];

        foreach ($candidates as $candidate) {
            if ($candidate['uri'] === null) {
                $unspecified[$candidate['file']] = true;
            }
        }

        if (count($unspecified) === 1) {
            return array_key_first($unspecified);
        }

        return null;
    }

    /**
     * Whether a file belongs to a vendor directory rather than the application.
     *
     * A path under the application stays, even when that application itself lives inside another vendor directory.
     */
    private function isVendorPath(string $path): bool
    {
        $normalized = str_replace('\\', '/', $path);
        $base = realpath(base_path());
        $base = $base === false ? '' : rtrim(str_replace('\\', '/', $base), '/');

        if ($base !== '' && str_starts_with($normalized, $base.'/')) {
            return str_starts_with($normalized, $base.'/vendor/');
        }

        return str_contains($normalized, '/vendor/');
    }

    /**
     * Application-relative path. Framework files collapse to vendor.
     */
    private function display(string $path): string
    {
        $real = realpath($path);
        $normalized = str_replace('\\', '/', $real === false ? $path : $real);

        if ($this->isVendorPath($normalized)) {
            return 'vendor';
        }

        return PhpFileIndex::relativePath($path);
    }
}

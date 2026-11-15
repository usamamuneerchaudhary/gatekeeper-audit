<?php

declare(strict_types=1);

namespace Usamamuneerchaudhary\GatekeeperAudit\Audit;

use PhpParser\Node;
use PhpParser\Node\Expr\Closure;
use PhpParser\Node\Expr\FuncCall;
use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Expr\New_;
use PhpParser\Node\Expr\StaticCall;
use PhpParser\Node\Expr\Variable;
use PhpParser\Node\Name;
use PhpParser\Node\Scalar\String_;
use PhpParser\Node\Stmt\Class_;
use PhpParser\Node\Stmt\ClassMethod;
use PhpParser\Node\Stmt\Return_;
use PhpParser\PrettyPrinter\Standard;

final class ActionInspector
{
    private const array GATE_METHODS = ['authorize', 'allows', 'denies', 'inspect', 'check', 'can', 'cannot', 'authorizeorfail'];

    private const array SINGLE_FINDERS = ['find', 'findorfail', 'findornew', 'firstorfail', 'firstorcreate', 'sole'];

    private const array CHAIN_TERMINALS = ['get', 'first', 'firstorfail', 'find', 'findorfail', 'paginate', 'simplepaginate', 'cursorpaginate', 'sole'];

    /**
     * Read configuration shared with the model inspector.
     *
     * @param  array<string, mixed>  $config
     */
    public function __construct(
        private readonly PhpFileIndex $files,
        private readonly ModelInspector $models,
        private readonly array $config,
    ) {}

    /**
     * Inspect one routed action. An unparsable file returns early as unparsed.
     */
    public function inspect(RouteSubject $subject): ActionAnalysis
    {
        if ($subject->file === null) {
            return ActionAnalysis::unparsed();
        }

        $statements = $this->files->parse($subject->file, $subject->isClosure ? 'closure' : 'controller');

        if ($statements === null) {
            return ActionAnalysis::unparsed();
        }

        $context = $this->actionContext($subject, $statements);

        if ($context === null) {
            return ActionAnalysis::unparsed();
        }

        [$actionMethod, $classNode, $parameters] = $context;

        $nodes = $this->collectedNodes($actionMethod, $classNode);
        $objectVariables = $this->objectVariables($subject, $parameters);

        $hasObjectCheck = false;
        $objectEvidence = null;
        $hasAnyAuthorization = false;
        $roleEvidence = [];
        $abilities = [];

        foreach ($this->middlewareObjectChecks($subject) as $check) {
            $hasObjectCheck = true;
            $hasAnyAuthorization = true;
            $objectEvidence ??= $check['evidence'];
            $abilities[] = $check['ability'];
        }

        foreach ($this->middlewareRoleEvidence($subject) as $evidence) {
            $roleEvidence[] = $evidence;
            $hasAnyAuthorization = true;
        }

        $resource = $this->authorizeResource($classNode, $subject);

        if ($resource !== null) {
            $hasAnyAuthorization = true;
            $abilities[] = $resource['ability'];

            if ($subject->isObjectRoute()) {
                $hasObjectCheck = true;
                $objectEvidence ??= $resource['evidence'];
            }
        }

        foreach ($this->staticMiddleware($classNode, $subject) as $entry) {
            $parsed = $this->parseCanMiddleware($entry, $subject);

            if ($parsed !== null) {
                $hasObjectCheck = true;
                $hasAnyAuthorization = true;
                $objectEvidence ??= 'HasMiddleware can:'.$entry;
                $abilities[] = $parsed;
            } elseif (str_starts_with($entry, 'can:') || str_starts_with($entry, 'role:') || str_starts_with($entry, 'permission:')) {
                $hasAnyAuthorization = true;
                $roleEvidence[] = 'HasMiddleware '.$entry;
            }
        }

        $formRequestTrivial = false;
        $formRequestClass = null;

        foreach ($parameters as $parameter) {
            $type = $parameter['type'];

            if ($type === null || ! $this->isFormRequest($type)) {
                continue;
            }

            $formRequestClass = $type;
            $result = $this->inspectFormRequest($type, $subject);

            if ($result['referencesRouteModel']) {
                $hasObjectCheck = true;
                $hasAnyAuthorization = true;
                $objectEvidence ??= $type.'::authorize() references the route model';
            }

            if ($result['trivial']) {
                $formRequestTrivial = true;
            }

            if ($result['hasAuthorization']) {
                $hasAnyAuthorization = true;

                if (! $result['referencesRouteModel']) {
                    $roleEvidence[] = $type.'::authorize() checks a permission without the route model';
                }
            }
        }

        foreach ($this->authorizationCalls($nodes, $objectVariables) as $call) {
            $hasAnyAuthorization = true;

            if ($call['ability'] !== null) {
                $abilities[] = $call['ability'];
            }

            if ($call['object']) {
                $hasObjectCheck = true;
                $objectEvidence ??= $call['evidence'];
            } else {
                $roleEvidence[] = $call['evidence'];
            }
        }

        [$policyTrivial, $policyEvidence] = $this->inspectPolicies($subject, array_values(array_unique($abilities)));

        return new ActionAnalysis(
            unparsed: false,
            hasObjectCheck: $hasObjectCheck,
            objectCheckEvidence: $objectEvidence,
            hasAnyAuthorization: $hasAnyAuthorization,
            roleEvidence: array_values(array_unique($roleEvidence)),
            formRequestTrivial: $formRequestTrivial,
            formRequestClass: $formRequestClass,
            policyTrivial: $policyTrivial,
            policyEvidence: $policyEvidence,
            lookups: $this->findLookups($nodes, $subject),
        );
    }

    /**
     * Locate the action method or closure and its parameters.
     *
     * @param  list<Node>  $statements
     * @return array{ClassMethod|Closure, Class_|null, list<array{name: string, type: string|null}>}|null
     */
    private function actionContext(RouteSubject $subject, array $statements): ?array
    {
        if ($subject->isClosure) {
            $closures = $this->files->finder()->findInstanceOf($statements, Closure::class);
            $closure = null;

            foreach ($closures as $candidate) {
                if ($candidate->getStartLine() === $subject->line) {
                    $closure = $candidate;
                    break;
                }
            }

            $closure ??= $closures[0] ?? null;

            if ($closure === null) {
                return null;
            }

            return [$closure, null, $this->parametersOf($closure)];
        }

        if ($subject->controllerClass === null || $subject->method === null) {
            return null;
        }

        $declaring = $subject->controllerClass;

        try {
            $reflection = new \ReflectionMethod($subject->controllerClass, $subject->method);
            $declaringClass = $reflection->getDeclaringClass()->getName();

            if (is_string($declaringClass) && $declaringClass !== '') {
                $declaring = $declaringClass;
            }
        } catch (\Throwable) {
        }

        $classNode = $this->files->findClassLike($declaring, 'controller') ?? $this->files->findClassLike($subject->controllerClass ?? '', 'controller');

        if (! $classNode instanceof Class_) {
            return null;
        }

        $methods = $this->allMethods($classNode);
        $method = $methods[strtolower($subject->method)] ?? null;

        if ($method === null) {
            return null;
        }

        return [$method, $classNode, $this->parametersOf($method)];
    }

    /**
     * Action statements plus one level of same-class and app-trait helper calls.
     *
     * @return list<Node>
     */
    private function collectedNodes(ClassMethod|Closure $action, ?Class_ $classNode): array
    {
        $body = $action instanceof Closure ? $action->stmts : ($action->stmts ?? []);

        if ($body === null) {
            return [];
        }

        $nodes = array_values($body);

        if ($classNode === null) {
            return $nodes;
        }

        $methods = $this->allMethods($classNode);
        $called = [];

        foreach ($this->files->finder()->findInstanceOf($nodes, MethodCall::class) as $call) {
            if ($call->var instanceof Variable && $call->var->name === 'this' && $call->name instanceof Node\Identifier) {
                $called[strtolower($call->name->toString())] = true;
            }
        }

        foreach (array_keys($called) as $name) {
            if (isset($methods[$name]) && $methods[$name] !== $action && $methods[$name]->stmts !== null) {
                $nodes = [...$nodes, ...$methods[$name]->stmts];
            }
        }

        return $nodes;
    }

    /**
     * Methods declared on the class and its non-vendor traits, keyed by lowercase name.
     *
     * @return array<string, ClassMethod>
     */
    private function allMethods(Class_ $classNode): array
    {
        $methods = $this->files->methodsOf($classNode);

        foreach ($this->files->traitsOf($classNode) as $trait) {
            $file = $this->files->fileFor($trait);

            if ($file !== null && str_contains(str_replace('\\', '/', $file), '/vendor/')) {
                continue;
            }

            $traitNode = $this->files->findClassLike($trait, 'trait');

            if ($traitNode === null) {
                continue;
            }

            foreach ($this->files->methodsOf($traitNode) as $name => $method) {
                $methods[$name] ??= $method;
            }
        }

        $parent = $classNode->extends?->toCodeString();

        if (is_string($parent) && $parent !== '') {
            $parentNode = $this->files->findClassLike(ltrim($parent, '\\'), 'controller');

            if ($parentNode instanceof Class_) {
                foreach ($this->files->methodsOf($parentNode) as $name => $method) {
                    $methods[$name] ??= $method;
                }
            }
        }

        return $methods;
    }

    /**
     * Parameters with resolved class types for a method or closure.
     *
     * @return list<array{name: string, type: string|null}>
     */
    private function parametersOf(ClassMethod|Closure $node): array
    {
        $parameters = [];

        foreach ($node->params as $param) {
            $type = null;

            if ($param->type instanceof Name) {
                $type = ltrim($param->type->toCodeString(), '\\');
            } elseif ($param->type instanceof Node\NullableType && $param->type->type instanceof Name) {
                $type = ltrim($param->type->type->toCodeString(), '\\');
            }

            if ($param->var instanceof Variable && is_string($param->var->name)) {
                $parameters[] = ['name' => $param->var->name, 'type' => $type];
            }
        }

        return $parameters;
    }

    /**
     * Variable names that carry the routed object.
     *
     * @param  list<array{name: string, type: string|null}>  $parameters
     * @return list<string>
     */
    private function objectVariables(RouteSubject $subject, array $parameters): array
    {
        $variables = $subject->objectParameterNames();

        foreach ($parameters as $parameter) {
            if (in_array($parameter['name'], $subject->objectParameterNames(), true)) {
                $variables[] = $parameter['name'];
            }
        }

        return array_values(array_unique($variables));
    }

    /**
     * Object-level can middleware entries for this route.
     *
     * @return list<array{ability: string, evidence: string}>
     */
    private function middlewareObjectChecks(RouteSubject $subject): array
    {
        $checks = [];

        foreach ($subject->middleware as $entry) {
            $ability = $this->parseCanMiddleware($entry, $subject);

            if ($ability !== null) {
                $checks[] = ['ability' => $ability, 'evidence' => 'middleware can:'.$entry];
            }
        }

        return $checks;
    }

    /**
     * Parse a can entry. Returns the ability only when its target is a route parameter.
     */
    private function parseCanMiddleware(string $entry, RouteSubject $subject): ?string
    {
        if (! str_starts_with($entry, 'can:')) {
            return null;
        }

        $parts = array_map('trim', explode(',', substr($entry, 4)));
        $ability = $parts[0] ?? '';
        $target = $parts[1] ?? null;

        if ($ability === '' || $target === null) {
            return null;
        }

        return in_array($target, $subject->objectParameterNames(), true) ? $ability : null;
    }

    /**
     * Role-level middleware evidence that never clears an object route.
     *
     * @return list<string>
     */
    private function middlewareRoleEvidence(RouteSubject $subject): array
    {
        $roleNames = is_array($this->config['role_middleware'] ?? null)
            ? $this->config['role_middleware']
            : ['role', 'permission', 'role_or_permission', 'can'];

        $evidence = [];

        foreach ($subject->middleware as $entry) {
            $name = explode(':', $entry, 2)[0];

            if (! in_array($name, $roleNames, true)) {
                continue;
            }

            if ($name === 'can' && $this->parseCanMiddleware($entry, $subject) !== null) {
                continue;
            }

            $evidence[] = 'middleware '.$entry.' is role or class level, not object level';
        }

        return $evidence;
    }

    /**
     * Detect authorizeResource in the constructor and map its conventional ability.
     *
     * @return array{ability: string, evidence: string}|null
     */
    private function authorizeResource(?Class_ $classNode, RouteSubject $subject): ?array
    {
        if ($classNode === null || $subject->method === null) {
            return null;
        }

        $methods = $this->allMethods($classNode);
        $constructor = $methods['__construct'] ?? null;

        if ($constructor === null || $constructor->stmts === null) {
            return null;
        }

        foreach ($this->files->finder()->findInstanceOf($constructor->stmts, MethodCall::class) as $call) {
            if (! $call->name instanceof Node\Identifier || strtolower($call->name->toString()) !== 'authorizeresource') {
                continue;
            }

            $model = isset($call->args[0]) && $call->args[0] instanceof Node\Arg ? $this->classFromClassConstant($call->args[0]->value) : null;
            $ability = $this->conventionalAbility($subject->method);

            if ($ability === null) {
                return null;
            }

            return ['ability' => $ability, 'evidence' => 'authorizeResource('.($model ?? 'model').") maps {$subject->method} to {$ability}"];
        }

        return null;
    }

    /**
     * Middleware strings declared through the HasMiddleware contract.
     *
     * @return list<string>
     */
    private function staticMiddleware(?Class_ $classNode, RouteSubject $subject): array
    {
        if ($classNode === null) {
            return [];
        }

        $methods = $this->allMethods($classNode);
        $middleware = $methods['middleware'] ?? null;

        if ($middleware === null || $middleware->stmts === null) {
            return [];
        }

        $entries = [];

        foreach ($this->files->finder()->findInstanceOf($middleware->stmts, New_::class) as $new) {
            if (! $new->class instanceof Name || class_basename(ltrim($new->class->toCodeString(), '\\')) !== 'Middleware') {
                continue;
            }

            $first = $new->args[0] ?? null;

            if (! $first instanceof Node\Arg || ! $first->value instanceof String_) {
                continue;
            }

            $only = null;
            $except = null;

            foreach ($new->args as $arg) {
                if (! $arg instanceof Node\Arg || $arg->name === null) {
                    continue;
                }

                $values = [];

                if ($arg->value instanceof Node\Expr\Array_) {
                    foreach ($arg->value->items as $item) {
                        if ($item instanceof Node\ArrayItem && $item->value instanceof String_) {
                            $values[] = $item->value->value;
                        }
                    }
                }

                if ($arg->name->toString() === 'only') {
                    $only = $values;
                }

                if ($arg->name->toString() === 'except') {
                    $except = $values;
                }
            }

            if ($subject->method !== null && $only !== null && ! in_array($subject->method, $only, true)) {
                continue;
            }

            if ($subject->method !== null && $except !== null && in_array($subject->method, $except, true)) {
                continue;
            }

            $entries[] = $first->value->value;
        }

        foreach ($this->files->finder()->findInstanceOf($middleware->stmts, String_::class) as $string) {
            if (str_contains($string->value, ':')) {
                $entries[] = $string->value;
            }
        }

        return array_values(array_unique($entries));
    }

    /**
     * Conventional policy ability for a resource action.
     */
    private function conventionalAbility(string $action): ?string
    {
        return match (strtolower($action)) {
            'index' => 'viewAny',
            'create', 'store' => 'create',
            'show' => 'view',
            'edit', 'update' => 'update',
            'destroy' => 'delete',
            'restore' => 'restore',
            'forcedelete' => 'forceDelete',
            default => null,
        };
    }

    /**
     * Whether a type is a FormRequest through reflection or its declared parent.
     */
    private function isFormRequest(string $class): bool
    {
        if (class_exists($class) && is_subclass_of($class, 'Illuminate\\Foundation\\Http\\FormRequest')) {
            $this->files->assignRole($class, 'request');

            return true;
        }

        if (class_exists($class) && is_subclass_of($class, 'Illuminate\\Database\\Eloquent\\Model')) {
            $this->files->assignRole($class, 'model');
        }

        $node = $this->files->findClassLike($class);
        $isRequest = $node instanceof Class_
            && $node->extends !== null
            && str_ends_with(ltrim($node->extends->toCodeString(), '\\'), 'FormRequest');

        if ($isRequest) {
            $this->files->assignRole($class, 'request');
        }

        return $isRequest;
    }

    /**
     * Inspect a FormRequest authorize method, following application parents.
     *
     * @return array{trivial: bool, referencesRouteModel: bool, hasAuthorization: bool}
     */
    private function inspectFormRequest(string $class, RouteSubject $subject): array
    {
        $current = $class;

        for ($depth = 0; $depth < 5; $depth++) {
            if (str_starts_with($current, 'Illuminate\\')) {
                break;
            }

            $node = $this->files->findClassLike($current, 'request');

            if (! $node instanceof Class_) {
                break;
            }

            $methods = $this->files->methodsOf($node);
            $authorize = $methods['authorize'] ?? null;

            if ($authorize !== null && $authorize->stmts !== null) {
                $references = $this->referencesRouteModel($authorize->stmts, $subject);
                $hasAuthorization = $this->containsAuthorizationCall($authorize->stmts);

                return [
                    'trivial' => ! $references && $this->isTrivialAuthorize($authorize->stmts),
                    'referencesRouteModel' => $references,
                    'hasAuthorization' => $hasAuthorization || $references,
                ];
            }

            $parent = $node->extends?->toCodeString();

            if (! is_string($parent) || $parent === '') {
                break;
            }

            $current = ltrim($parent, '\\');
        }

        return ['trivial' => true, 'referencesRouteModel' => false, 'hasAuthorization' => false];
    }

    /**
     * Whether authorize only proves a user is signed in, or always returns true.
     *
     * @param  list<Node>  $statements
     */
    private function isTrivialAuthorize(array $statements): bool
    {
        $meaningful = array_values(array_filter($statements, static fn (Node $node): bool => $node instanceof Return_));

        if ($meaningful === []) {
            return true;
        }

        if (count($statements) !== 1 || ! $statements[0] instanceof Return_) {
            return false;
        }

        $expression = $statements[0]->expr;

        if ($expression === null) {
            return true;
        }

        if ($expression instanceof Node\Expr\ConstFetch) {
            return strtolower($expression->name->toCodeString()) === 'true';
        }

        $text = $this->expressionText($expression);

        return str_contains($text, 'check()')
            || str_contains($text, '!== null')
            || str_contains($text, '!= null');
    }

    /**
     * Whether the nodes ask the gate about the routed object.
     *
     * @param  list<Node>  $statements
     */
    private function referencesRouteModel(array $statements, RouteSubject $subject): bool
    {
        foreach ($this->files->finder()->findInstanceOf($statements, MethodCall::class) as $call) {
            if (! $call->name instanceof Node\Identifier || strtolower($call->name->toString()) !== 'route') {
                continue;
            }

            foreach ($call->args as $arg) {
                if ($arg instanceof Node\Arg && $arg->value instanceof String_ && in_array($arg->value->value, $subject->objectParameterNames(), true)) {
                    return true;
                }
            }

            if ($call->args === [] && $subject->isObjectRoute()) {
                return true;
            }
        }

        foreach ($this->files->finder()->findInstanceOf($statements, FuncCall::class) as $call) {
            if ($call->name instanceof Name && strtolower($call->name->toCodeString()) === 'route') {
                foreach ($call->args as $arg) {
                    if ($arg instanceof Node\Arg && $arg->value instanceof String_ && in_array($arg->value->value, $subject->objectParameterNames(), true)) {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    /**
     * Whether the nodes contain any can, authorize, or gate call.
     *
     * @param  list<Node>  $statements
     */
    private function containsAuthorizationCall(array $statements): bool
    {
        foreach ($this->files->finder()->findInstanceOf($statements, MethodCall::class) as $call) {
            if ($call->name instanceof Node\Identifier && in_array(strtolower($call->name->toString()), ['can', 'cannot', 'authorize', 'check'], true)) {
                return true;
            }
        }

        foreach ($this->files->finder()->findInstanceOf($statements, StaticCall::class) as $call) {
            if ($call->name instanceof Node\Identifier && in_array(strtolower($call->name->toString()), self::GATE_METHODS, true)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Authorization calls in the collected action nodes.
     *
     * @param  list<Node>  $nodes
     * @param  list<string>  $objectVariables
     * @return list<array{object: bool, ability: string|null, evidence: string}>
     */
    private function authorizationCalls(array $nodes, array $objectVariables): array
    {
        $calls = [];

        foreach ($this->files->finder()->findInstanceOf($nodes, MethodCall::class) as $call) {
            if (! $call->name instanceof Node\Identifier) {
                continue;
            }

            $name = strtolower($call->name->toString());

            if (! in_array($name, ['authorize', 'authorizeorfail', 'can', 'cannot', 'check', 'allows', 'denies'], true)) {
                continue;
            }

            if ($name === 'check' && ! $this->looksLikeGateCheck($call)) {
                continue;
            }

            $ability = $this->stringArgument($call, 0);
            $object = $this->argumentsReferenceObject($call->args, $objectVariables)
                || ($name === 'authorize' && $this->argumentsReferenceObject($call->args, $objectVariables));

            $calls[] = [
                'object' => $object,
                'ability' => $ability,
                'evidence' => $this->expressionText($call).' at line '.$call->getStartLine(),
            ];
        }

        foreach ($this->files->finder()->findInstanceOf($nodes, StaticCall::class) as $call) {
            if (! $call->name instanceof Node\Identifier || ! $call->class instanceof Name) {
                continue;
            }

            $class = class_basename(ltrim($call->class->toCodeString(), '\\'));
            $name = strtolower($call->name->toString());

            if (! in_array($class, ['Gate', 'Auth'], true) || ! in_array($name, self::GATE_METHODS, true)) {
                continue;
            }

            $calls[] = [
                'object' => $this->argumentsReferenceObject($call->args, $objectVariables),
                'ability' => $this->stringArgument($call, 0),
                'evidence' => $class.'::'.$call->name->toString().' at line '.$call->getStartLine(),
            ];
        }

        return $calls;
    }

    /**
     * Avoid treating unrelated check() calls as gate checks.
     */
    private function looksLikeGateCheck(MethodCall $call): bool
    {
        $text = $this->expressionText($call->var);

        return str_contains($text, 'auth') || str_contains($text, 'Gate') || str_contains($text, 'user()');
    }

    /**
     * Whether any argument mentions an object variable.
     *
     * @param  array<int, Node\Arg|Node\VariadicPlaceholder>  $args
     * @param  list<string>  $objectVariables
     */
    private function argumentsReferenceObject(array $args, array $objectVariables): bool
    {
        if ($objectVariables === []) {
            return false;
        }

        foreach ($args as $arg) {
            if (! $arg instanceof Node\Arg) {
                continue;
            }

            foreach ($this->files->finder()->findInstanceOf([$arg->value], Variable::class) as $variable) {
                if (is_string($variable->name) && in_array($variable->name, $objectVariables, true)) {
                    return true;
                }
            }

            if ($arg->value instanceof MethodCall && $this->isRouteModelCall($arg->value)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Whether a call reads a model from the current route.
     */
    private function isRouteModelCall(MethodCall $call): bool
    {
        return $call->name instanceof Node\Identifier && strtolower($call->name->toString()) === 'route';
    }

    /**
     * First string argument of a call, when literal.
     */
    private function stringArgument(MethodCall|StaticCall $call, int $index): ?string
    {
        $arg = $call->args[$index] ?? null;

        return $arg instanceof Node\Arg && $arg->value instanceof String_ ? $arg->value->value : null;
    }

    /**
     * Resolve policies for used abilities and detect return-true bodies.
     *
     * @param  list<string>  $abilities
     * @return array{bool, string|null}
     */
    private function inspectPolicies(RouteSubject $subject, array $abilities): array
    {
        foreach ($subject->boundModelClasses() as $model) {
            $policy = $this->policyFor($model);

            if ($policy === null) {
                continue;
            }

            $node = $this->files->findClassLike($policy, 'policy');

            if (! $node instanceof Class_) {
                continue;
            }

            $methods = $this->files->methodsOf($node);

            if (isset($methods['before']) && $this->returnsOnlyTrue($methods['before'])) {
                return [true, $policy.'::before() returns true'];
            }

            foreach ($abilities as $ability) {
                $method = $methods[strtolower($ability)] ?? null;

                if ($method !== null && $this->returnsOnlyTrue($method)) {
                    return [true, $policy.'::'.$ability.'() returns true'];
                }
            }
        }

        return [false, null];
    }

    /**
     * Whether a method body is a single return true.
     */
    private function returnsOnlyTrue(ClassMethod $method): bool
    {
        if ($method->stmts === null || count($method->stmts) !== 1 || ! $method->stmts[0] instanceof Return_) {
            return false;
        }

        $expression = $method->stmts[0]->expr;

        return $expression instanceof Node\Expr\ConstFetch
            && strtolower($expression->name->toCodeString()) === 'true';
    }

    /**
     * Resolve a policy through the gate when possible, else by convention.
     */
    private function policyFor(string $model): ?string
    {
        try {
            if (function_exists('app')) {
                $gate = app('Illuminate\\Contracts\\Auth\\Access\\Gate');

                if (is_object($gate) && method_exists($gate, 'getPolicyFor')) {
                    $policy = $gate->getPolicyFor($model);

                    if (is_object($policy)) {
                        return $policy::class;
                    }
                }
            }
        } catch (\Throwable) {
        }

        $candidates = [];
        $candidates[] = str_replace('\\Models\\', '\\Policies\\', $model).'Policy';
        $candidates[] = preg_replace('/\\\\[^\\\\]+$/', '\\\\Policies\\\\', $model).class_basename($model).'Policy';

        foreach (array_unique($candidates) as $candidate) {
            if (is_string($candidate) && class_exists($candidate)) {
                return $candidate;
            }
        }

        return null;
    }

    /**
     * Find unscoped static, chained, and DB table lookups in the action nodes.
     *
     * @param  list<Node>  $nodes
     * @return list<array{rule: string, model: string|null, table: string|null, line: int, expression: string}>
     */
    private function findLookups(array $nodes, RouteSubject $subject): array
    {
        $lookups = [];
        $ownershipColumns = is_array($this->config['ownership']['columns'] ?? null)
            ? $this->config['ownership']['columns']
            : ['user_id', 'owner_id', 'tenant_id', 'team_id', 'account_id'];

        foreach ($this->files->finder()->findInstanceOf($nodes, StaticCall::class) as $call) {
            if (! $call->class instanceof Name || ! $call->name instanceof Node\Identifier) {
                continue;
            }

            $class = ltrim($call->class->toCodeString(), '\\');
            $name = strtolower($call->name->toString());

            if (class_basename($class) === 'DB' && $name === 'table') {
                continue;
            }

            if (! $this->isModelClass($class, $subject)) {
                continue;
            }

            if (in_array($name, self::SINGLE_FINDERS, true)) {
                $lookups[] = $this->lookup('unscoped_lookup', $class, null, $call);
            } elseif ($name === 'all') {
                $lookups[] = $this->lookup('unscoped_collection', $class, null, $call);
            }
        }

        foreach ($this->files->finder()->findInstanceOf($nodes, MethodCall::class) as $call) {
            if (! $call->name instanceof Node\Identifier) {
                continue;
            }

            $terminal = strtolower($call->name->toString());

            if (! in_array($terminal, self::CHAIN_TERMINALS, true)) {
                continue;
            }

            if ($this->isUserRooted($call)) {
                continue;
            }

            $model = $this->chainModel($call, $subject);
            $table = null;

            if ($model === null) {
                $table = $this->chainTable($call);
            }

            if ($model === null && $table === null) {
                continue;
            }

            if ($model !== null && $this->chainIsScoped($call, $ownershipColumns)) {
                continue;
            }

            $collection = in_array($terminal, ['get', 'paginate', 'simplepaginate', 'cursorpaginate'], true);

            $lookups[] = $this->lookup($collection ? 'unscoped_collection' : 'unscoped_lookup', $model, $table, $call);
        }

        $unique = [];

        foreach ($lookups as $lookup) {
            $key = $lookup['rule'].'|'.($lookup['model'] ?? $lookup['table'] ?? '').'|'.$lookup['line'];

            $unique[$key] = $lookup;
        }

        return array_values($unique);
    }

    /**
     * Build one lookup record.
     *
     * @return array{rule: string, model: string|null, table: string|null, line: int, expression: string}
     */
    private function lookup(string $rule, ?string $model, ?string $table, Node $node): array
    {
        return [
            'rule' => $rule,
            'model' => $model,
            'table' => $table,
            'line' => $node->getStartLine(),
            'expression' => $this->expressionText($node),
        ];
    }

    /**
     * Model class at the root of a method chain, when the root is a static model call.
     */
    private function chainModel(MethodCall $call, RouteSubject $subject): ?string
    {
        $root = $call;

        while ($root instanceof MethodCall) {
            $root = $root->var;
        }

        if (! $root instanceof StaticCall || ! $root->class instanceof Name) {
            return null;
        }

        $class = ltrim($root->class->toCodeString(), '\\');

        return $this->isModelClass($class, $subject) ? $class : null;
    }

    /**
     * Table at the root of a DB::table chain, when present.
     */
    private function chainTable(MethodCall $call): ?string
    {
        $root = $call;

        while ($root instanceof MethodCall) {
            $root = $root->var;
        }

        if (! $root instanceof StaticCall || ! $root->class instanceof Name || ! $root->name instanceof Node\Identifier) {
            return null;
        }

        if (class_basename(ltrim($root->class->toCodeString(), '\\')) !== 'DB' || strtolower($root->name->toString()) !== 'table') {
            return null;
        }

        $arg = $root->args[0] ?? null;

        return $arg instanceof Node\Arg && $arg->value instanceof String_ ? $arg->value->value : null;
    }

    /**
     * Whether a chain is scoped through the authenticated user or an ownership column.
     *
     * @param  list<string>  $ownershipColumns
     */
    private function chainIsScoped(MethodCall $call, array $ownershipColumns): bool
    {
        if ($this->isUserRooted($call)) {
            return true;
        }

        $current = $call;

        while ($current instanceof MethodCall) {
            if ($current->name instanceof Node\Identifier && in_array(strtolower($current->name->toString()), ['where', 'wherein', 'wherehas'], true)) {
                $first = $current->args[0] ?? null;

                if ($first instanceof Node\Arg && $first->value instanceof String_ && in_array($first->value->value, $ownershipColumns, true)) {
                    $text = $this->expressionText($current);

                    if (str_contains($text, 'auth') || str_contains($text, 'user()') || str_contains($text, '->id')) {
                        return true;
                    }
                }
            }

            $current = $current->var;
        }

        return false;
    }

    /**
     * Whether an expression is rooted at the authenticated user.
     */
    private function isUserRooted(Node $node): bool
    {
        foreach ($this->files->finder()->findInstanceOf([$node], MethodCall::class) as $call) {
            if ($call->name instanceof Node\Identifier && strtolower($call->name->toString()) === 'user') {
                return true;
            }
        }

        foreach ($this->files->finder()->findInstanceOf([$node], FuncCall::class) as $call) {
            if ($call->name instanceof Name && strtolower($call->name->toCodeString()) === 'auth') {
                return true;
            }
        }

        return false;
    }

    /**
     * Whether a class is an Eloquent model or one of the bound route models.
     */
    private function isModelClass(string $class, RouteSubject $subject): bool
    {
        if (in_array($class, $subject->boundModelClasses(), true)) {
            return true;
        }

        if (! class_exists($class)) {
            return false;
        }

        return is_subclass_of($class, 'Illuminate\\Database\\Eloquent\\Model');
    }

    /**
     * Class name from a ::class constant expression.
     */
    private function classFromClassConstant(Node $node): ?string
    {
        if ($node instanceof Node\Expr\ClassConstFetch && $node->class instanceof Name) {
            return ltrim($node->class->toCodeString(), '\\');
        }

        return null;
    }

    /**
     * Compact source text for evidence messages.
     */
    private function expressionText(Node $node): string
    {
        try {
            $printer = new Standard;
            $text = $printer->print($node);
        } catch (\Throwable) {
            $text = $node::class;
        }

        $text = preg_replace('/\s+/', ' ', $text) ?? $text;

        return strlen($text) > 140 ? substr($text, 0, 137).'...' : $text;
    }
}

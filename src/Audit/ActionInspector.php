<?php

declare(strict_types=1);

namespace Usamamuneerchaudhary\GatekeeperAudit\Audit;

use PhpParser\Node;
use PhpParser\Node\Expr\ArrowFunction;
use PhpParser\Node\Expr\Closure;
use PhpParser\Node\Expr\FuncCall;
use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Expr\NullsafeMethodCall;
use PhpParser\Node\Expr\StaticCall;
use PhpParser\Node\Expr\Variable;
use PhpParser\Node\Name;
use PhpParser\Node\Scalar\String_;
use PhpParser\Node\Stmt\Class_;
use PhpParser\Node\Stmt\ClassMethod;
use PhpParser\Node\Stmt\Return_;
use PhpParser\NodeTraverser;
use PhpParser\NodeVisitor\CloningVisitor;
use PhpParser\NodeVisitorAbstract;
use PhpParser\PrettyPrinter\Standard;

final class ActionInspector
{
    private const array GATE_METHODS = ['authorize', 'allows', 'denies', 'inspect', 'check', 'any', 'none'];

    /** Method calls that ask the gate about an ability. `check` is accepted only on a gate instance. */
    private const array ABILITY_METHODS = ['authorize', 'authorizeorfail', 'can', 'cannot', 'cant', 'check', 'allows', 'denies', 'any', 'none', 'inspect'];

    /** Calls that throw on failure, so they enforce the check wherever they appear. */
    private const array THROWING_METHODS = ['authorize', 'authorizeorfail'];

    private const array STATIC_SINGLE = ['find', 'findorfail', 'findornew', 'findor', 'firstorfail', 'firstorcreate', 'firstornew', 'firstwhere', 'updateorcreate', 'sole', 'destroy'];

    private const array STATIC_COLLECTION = ['all', 'findmany'];

    private const array CHAIN_SINGLE = ['first', 'firstorfail', 'firstor', 'firstwhere', 'firstorcreate', 'firstornew', 'find', 'findorfail', 'findor', 'findornew', 'updateorcreate', 'updateorinsert', 'sole', 'value', 'update', 'delete', 'forcedelete', 'restore', 'increment', 'decrement'];

    private const array CHAIN_COLLECTION = ['get', 'paginate', 'simplepaginate', 'cursorpaginate', 'pluck', 'findmany', 'lazy', 'lazybyid', 'cursor', 'chunk', 'chunkbyid', 'each'];

    /** Query methods whose arguments can constrain the query to an owner. */
    private const array SCOPING_METHODS = ['where', 'wherein', 'firstwhere', 'wherebelongsto', 'firstorcreate', 'firstornew', 'updateorcreate', 'updateorinsert'];

    /**
     * Read the ownership and middleware configuration.
     *
     * @param  array<string, mixed>  $config
     */
    public function __construct(
        private readonly PhpFileIndex $files,
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

        foreach ($this->authorizationCalls($nodes, $objectVariables, $actionMethod) as $call) {
            if (! $call['enforced']) {
                $roleEvidence[] = $call['evidence'].' result is not used to allow or deny the request';

                continue;
            }

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
            lookups: $this->findLookups($nodes, $subject, $this->userVariables($nodes, $actionMethod)),
        );
    }

    /**
     * Locate the action method or closure and its parameters.
     *
     * @param  list<Node>  $statements
     * @return array{ClassMethod|Closure|ArrowFunction, Class_|null, list<array{name: string, type: string|null}>}|null
     */
    private function actionContext(RouteSubject $subject, array $statements): ?array
    {
        if ($subject->isClosure) {
            $closure = null;

            foreach ($this->files->finder()->find($statements, static fn (Node $node): bool => $node instanceof Closure || $node instanceof ArrowFunction) as $candidate) {
                if ($candidate->getStartLine() === $subject->line) {
                    $closure = $candidate;
                    break;
                }
            }

            // Never fall back to another closure: the first closure in a route file is
            // usually the group wrapper, and its body contains every sibling route.
            if (! $closure instanceof Closure && ! $closure instanceof ArrowFunction) {
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
            $declaring = $reflection->getDeclaringClass()->getName();
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
    private function collectedNodes(ClassMethod|Closure|ArrowFunction $action, ?Class_ $classNode): array
    {
        if ($action instanceof ArrowFunction) {
            return [$action->expr];
        }

        $nodes = array_values($action instanceof Closure ? $action->stmts : ($action->stmts ?? []));

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
    private function parametersOf(ClassMethod|Closure|ArrowFunction $node): array
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
     * Whether authorize() only returns true or only proves that a user is signed in.
     *
     * Guard clauses such as `if (! auth()->check()) { return false; }` are allowed before the final return.
     * A body with no return denies every request, so it is not trivial.
     *
     * @param  list<Node>  $statements
     */
    private function isTrivialAuthorize(array $statements): bool
    {
        $allowsSomeone = false;

        foreach ($statements as $statement) {
            if ($statement instanceof Node\Stmt\Nop) {
                continue;
            }

            if ($statement instanceof Return_) {
                $verdict = $this->trivialReturn($statement->expr);

                if ($verdict === null) {
                    return false;
                }

                $allowsSomeone = $allowsSomeone || $verdict;

                continue;
            }

            if ($statement instanceof Node\Stmt\If_
                && $statement->elseifs === []
                && AuthExpressions::isAuthenticationOnly($statement->cond)
                && $this->onlyConstantReturns($statement->stmts)
                && ($statement->else === null || $this->onlyConstantReturns($statement->else->stmts))) {
                continue;
            }

            return false;
        }

        return $allowsSomeone;
    }

    /**
     * True when a return allows any signed-in user, false when it denies, null when it does real work.
     */
    private function trivialReturn(?Node\Expr $expression): ?bool
    {
        if ($expression === null) {
            return false;
        }

        if ($expression instanceof Node\Expr\ConstFetch) {
            return match (strtolower($expression->name->toString())) {
                'true' => true,
                'false', 'null' => false,
                default => null,
            };
        }

        return AuthExpressions::isAuthenticationOnly($expression) ? true : null;
    }

    /**
     * Whether a block only returns true or false.
     *
     * @param  array<Node>  $statements
     */
    private function onlyConstantReturns(array $statements): bool
    {
        foreach ($statements as $statement) {
            if (! $statement instanceof Return_ || $this->trivialReturn($statement->expr) === null) {
                return false;
            }

            if ($statement->expr !== null && ! $statement->expr instanceof Node\Expr\ConstFetch) {
                return false;
            }
        }

        return true;
    }

    /**
     * Whether authorize() checks the routed object.
     *
     * The route model must reach an ability call (`can`, `Gate::allows`, ...) or be compared with the
     * signed-in user. Reading it alone, for example `$this->route('invoice') !== null`, does not count.
     * The model may be read as `$this->route('invoice')`, `$this->route()->parameter('invoice')`, or `$this->invoice`.
     *
     * @param  list<Node>  $statements
     */
    private function referencesRouteModel(array $statements, RouteSubject $subject): bool
    {
        $names = $subject->objectParameterNames();

        if ($names === []) {
            return false;
        }

        $references = $this->files->finder()->find($statements, fn (Node $node): bool => $this->isRouteObjectRead($node, $names));

        foreach ($references as $reference) {
            if ($this->reachesObjectCheck($reference)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Whether a node reads a routed object inside a FormRequest.
     *
     * @param  list<string>  $names
     */
    private function isRouteObjectRead(Node $node, array $names): bool
    {
        if ($node instanceof MethodCall || $node instanceof NullsafeMethodCall) {
            if (! $node->name instanceof Node\Identifier) {
                return false;
            }

            $method = strtolower($node->name->toString());
            $first = $node->args[0] ?? null;
            $literal = $first instanceof Node\Arg && $first->value instanceof String_ ? $first->value->value : null;

            if ($method === 'route') {
                return $literal !== null && in_array($literal, $names, true);
            }

            if ($method === 'parameter' && ($node->var instanceof MethodCall || $node->var instanceof NullsafeMethodCall)
                && $node->var->name instanceof Node\Identifier && strtolower($node->var->name->toString()) === 'route') {
                return $literal !== null && in_array($literal, $names, true);
            }

            return false;
        }

        if ($node instanceof Node\Expr\PropertyFetch || $node instanceof Node\Expr\NullsafePropertyFetch) {
            return $node->var instanceof Variable
                && $node->var->name === 'this'
                && $node->name instanceof Node\Identifier
                && in_array($node->name->toString(), $names, true);
        }

        return false;
    }

    /**
     * Whether a routed-object read flows into an ability call or a comparison with the signed-in user.
     */
    private function reachesObjectCheck(Node $reference): bool
    {
        $child = $reference;
        $parent = $reference->getAttribute('parent');

        while ($parent instanceof Node && ! $parent instanceof Node\Stmt) {
            if ($this->isAbilityCall($parent) && $this->isArgumentOf($child, $parent)) {
                return true;
            }

            $isComparison = $parent instanceof Node\Expr\BinaryOp\Identical || $parent instanceof Node\Expr\BinaryOp\Equal
                || $parent instanceof Node\Expr\BinaryOp\NotIdentical || $parent instanceof Node\Expr\BinaryOp\NotEqual;
            $isCall = $parent instanceof MethodCall || $parent instanceof NullsafeMethodCall
                || $parent instanceof StaticCall || $parent instanceof FuncCall;

            if (($isComparison || $isCall) && $this->containsUser($parent, $child)) {
                return true;
            }

            $child = $parent;
            $parent = $parent->getAttribute('parent');
        }

        return false;
    }

    /**
     * Whether a node is a gate or ability call by name.
     */
    private function isAbilityCall(Node $node): bool
    {
        if (($node instanceof MethodCall || $node instanceof NullsafeMethodCall) && $node->name instanceof Node\Identifier) {
            $name = strtolower($node->name->toString());

            return in_array($name, self::ABILITY_METHODS, true) && ($name !== 'check' || $this->looksLikeGateCheck($node));
        }

        return $node instanceof StaticCall
            && $node->class instanceof Name
            && class_basename(ltrim($node->class->toString(), '\\')) === 'Gate'
            && $node->name instanceof Node\Identifier
            && in_array(strtolower($node->name->toString()), self::GATE_METHODS, true);
    }

    /**
     * Whether a child node is one of the call's arguments rather than its receiver.
     */
    private function isArgumentOf(Node $child, Node $call): bool
    {
        return $child instanceof Node\Arg && $child->getAttribute('parent') === $call;
    }

    /**
     * Whether a node contains a signed-in user expression outside the given subtree.
     */
    private function containsUser(Node $node, Node $exclude): bool
    {
        $found = $this->files->finder()->findFirst([$node], static function (Node $candidate) use ($exclude): bool {
            if (! AuthExpressions::isUserDerived($candidate)) {
                return false;
            }

            for ($current = $candidate; $current instanceof Node; $current = $current->getAttribute('parent')) {
                if ($current === $exclude) {
                    return false;
                }
            }

            return true;
        });

        return $found !== null;
    }

    /**
     * Whether the nodes contain any gate or ability call. Signing in is not authorization.
     *
     * @param  list<Node>  $statements
     */
    private function containsAuthorizationCall(array $statements): bool
    {
        return $this->files->finder()->findFirst($statements, fn (Node $node): bool => $this->isAbilityCall($node)) !== null;
    }

    /**
     * Authorization calls in the collected action nodes, with whether each one guards the request.
     *
     * @param  list<Node>  $nodes
     * @param  list<string>  $objectVariables
     * @return list<array{object: bool, ability: string|null, evidence: string, enforced: bool}>
     */
    private function authorizationCalls(array $nodes, array $objectVariables, ClassMethod|Closure|ArrowFunction $action): array
    {
        $calls = [];

        foreach ($this->files->finder()->find($nodes, fn (Node $node): bool => $this->isAbilityCall($node)) as $call) {
            if (! $call instanceof MethodCall && ! $call instanceof NullsafeMethodCall && ! $call instanceof StaticCall) {
                continue;
            }

            if (! $call->name instanceof Node\Identifier) {
                continue;
            }

            $name = strtolower($call->name->toString());
            $arguments = $call->args;

            // Gate::inspect(...)->authorize() carries the object on the inspect call.
            if ($name === 'authorize' && $arguments === [] && ! $call instanceof StaticCall
                && ($call->var instanceof StaticCall || $call->var instanceof MethodCall)) {
                $arguments = $call->var->args;
            }

            $throws = in_array($name, self::THROWING_METHODS, true);

            $calls[] = [
                'object' => $this->argumentsReferenceObject($arguments, $objectVariables),
                'ability' => $this->stringArgument($call, 0),
                'evidence' => $this->expressionText($call).' at line '.$call->getStartLine(),
                'enforced' => $throws || $this->isEnforced($call, $action),
            ];
        }

        return $calls;
    }

    /**
     * Whether a boolean ability result decides what the request may do.
     *
     * It counts when it is an if, while, ternary, or match condition, the first argument of
     * abort_if/abort_unless/throw_if/throw_unless, or the return value of a helper the action calls.
     * Assigning it, passing it to a view, or discarding it does not count.
     */
    private function isEnforced(Node $call, ClassMethod|Closure|ArrowFunction $action): bool
    {
        $current = $call;
        $parent = $call->getAttribute('parent');

        while ($parent instanceof Node) {
            if ($parent instanceof Node\Expr\BooleanNot || $parent instanceof Node\Expr\Cast\Bool_
                || $parent instanceof Node\Expr\BinaryOp\BooleanAnd || $parent instanceof Node\Expr\BinaryOp\BooleanOr
                || $parent instanceof Node\Expr\BinaryOp\LogicalAnd || $parent instanceof Node\Expr\BinaryOp\LogicalOr
                || $parent instanceof Node\Expr\BinaryOp\Identical || $parent instanceof Node\Expr\BinaryOp\NotIdentical
                || $parent instanceof Node\Expr\BinaryOp\Equal || $parent instanceof Node\Expr\BinaryOp\NotEqual) {
                $current = $parent;
                $parent = $parent->getAttribute('parent');

                continue;
            }

            // A Response from inspect() is enforced by ->authorize(), or tested through ->allowed() and ->denied().
            if (($parent instanceof MethodCall || $parent instanceof NullsafeMethodCall) && $parent->var === $current
                && $parent->name instanceof Node\Identifier) {
                $method = strtolower($parent->name->toString());

                if ($method === 'authorize') {
                    return true;
                }

                if (in_array($method, ['allowed', 'denied'], true)) {
                    $current = $parent;
                    $parent = $parent->getAttribute('parent');

                    continue;
                }

                return false;
            }

            if (($parent instanceof Node\Stmt\If_ || $parent instanceof Node\Stmt\ElseIf_ || $parent instanceof Node\Stmt\While_
                || $parent instanceof Node\Stmt\Do_ || $parent instanceof Node\Expr\Ternary || $parent instanceof Node\Expr\Match_)
                && $parent->cond === $current) {
                return true;
            }

            if ($parent instanceof Node\MatchArm && in_array($current, $parent->conds ?? [], true)) {
                return true;
            }

            if ($parent instanceof Return_) {
                return $this->enclosingFunction($parent) !== $action;
            }

            if ($parent instanceof Node\Arg) {
                $function = $parent->getAttribute('parent');

                return $function instanceof FuncCall
                    && $function->name instanceof Name
                    && in_array(strtolower($function->name->toString()), ['abort_if', 'abort_unless', 'throw_if', 'throw_unless'], true)
                    && ($function->args[0] ?? null) === $parent;
            }

            return false;
        }

        return false;
    }

    /**
     * The closest function, method, or closure around a node.
     */
    private function enclosingFunction(Node $node): ?Node
    {
        for ($current = $node->getAttribute('parent'); $current instanceof Node; $current = $current->getAttribute('parent')) {
            if ($current instanceof Node\FunctionLike) {
                return $current;
            }
        }

        return null;
    }

    /**
     * Avoid treating unrelated check() calls, such as auth()->check(), as gate checks.
     */
    private function looksLikeGateCheck(MethodCall|NullsafeMethodCall $call): bool
    {
        $text = $this->expressionText($call->var);

        return str_contains($text, 'Gate') || str_contains($text, 'gate');
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
     * Find unscoped static, chained, and DB table lookups and writes in the action nodes.
     *
     * @param  list<Node>  $nodes
     * @param  list<string>  $userVariables
     * @return list<array{rule: string, model: string|null, table: string|null, line: int, expression: string}>
     */
    private function findLookups(array $nodes, RouteSubject $subject, array $userVariables): array
    {
        $lookups = [];
        $ownershipColumns = $this->ownershipColumns();
        $modelVariables = [...$this->modelVariables($subject), ...$userVariables];

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

            if ($this->isScopingCall($call, $ownershipColumns, $modelVariables)) {
                continue;
            }

            if (in_array($name, self::STATIC_SINGLE, true)) {
                $lookups[] = $this->lookup('unscoped_lookup', $class, null, $call);
            } elseif (in_array($name, self::STATIC_COLLECTION, true)) {
                $lookups[] = $this->lookup('unscoped_collection', $class, null, $call);
            }
        }

        $chainCalls = $this->files->finder()->find($nodes, static fn (Node $node): bool => $node instanceof MethodCall || $node instanceof NullsafeMethodCall);

        foreach ($chainCalls as $call) {
            if ((! $call instanceof MethodCall && ! $call instanceof NullsafeMethodCall) || ! $call->name instanceof Node\Identifier) {
                continue;
            }

            $terminal = strtolower($call->name->toString());
            $collection = in_array($terminal, self::CHAIN_COLLECTION, true);

            if (! $collection && ! in_array($terminal, self::CHAIN_SINGLE, true)) {
                continue;
            }

            if (AuthExpressions::chainIsUserRooted($call)) {
                continue;
            }

            $model = $this->chainModel($call, $subject);
            $table = $model === null ? $this->chainTable($call) : null;

            if ($model === null && $table === null) {
                continue;
            }

            if ($this->chainIsScoped($call, $ownershipColumns, $modelVariables)) {
                continue;
            }

            $lookups[] = $this->lookup($collection ? 'unscoped_collection' : 'unscoped_lookup', $model, $table, $call);
        }

        $unique = [];

        foreach ($lookups as $lookup) {
            $key = $lookup['rule'].'|'.($lookup['model'] ?? $lookup['table'] ?? '').'|'.$lookup['line'];

            $unique[$key] ??= $lookup;
        }

        return array_values($unique);
    }

    /**
     * Variables that hold the signed-in user or a value read from it.
     *
     * Covers `$user = $request->user();`, `$userId = Auth::id();`, and action parameters marked
     * with Laravel's #[CurrentUser] or #[Authenticated] attributes.
     *
     * @param  list<Node>  $nodes
     * @return list<string>
     */
    private function userVariables(array $nodes, ClassMethod|Closure|ArrowFunction $action): array
    {
        $variables = [];

        foreach ($action->params as $param) {
            foreach ($param->attrGroups as $group) {
                foreach ($group->attrs as $attribute) {
                    if (in_array(class_basename($attribute->name->toString()), ['CurrentUser', 'Authenticated'], true)
                        && $param->var instanceof Variable && is_string($param->var->name)) {
                        $variables[] = $param->var->name;
                    }
                }
            }
        }

        // Two passes so `$user = $request->user(); $teamId = $user->current_team_id;` is followed.
        for ($pass = 0; $pass < 2; $pass++) {
            foreach ($this->files->finder()->findInstanceOf($nodes, Node\Expr\Assign::class) as $assign) {
                if ($assign->var instanceof Variable && is_string($assign->var->name)
                    && AuthExpressions::isUserValue($assign->expr, $variables)) {
                    $variables[] = $assign->var->name;
                }
            }
        }

        return array_values(array_unique($variables));
    }

    /**
     * Configured ownership columns.
     *
     * @return list<string>
     */
    private function ownershipColumns(): array
    {
        $columns = $this->config['ownership']['columns'] ?? null;

        return is_array($columns)
            ? array_values(array_map('strval', $columns))
            : ['user_id', 'owner_id', 'tenant_id', 'team_id', 'account_id'];
    }

    /**
     * Action variables that hold a route-bound model, such as `$team` for `{team}`.
     *
     * A query constrained by one of these is scoped to that parent. Whether the user may reach the
     * parent is checked by the object_authorization rule. Plain ids such as `{id}` never qualify.
     *
     * @return list<string>
     */
    private function modelVariables(RouteSubject $subject): array
    {
        $variables = [];

        foreach ($subject->objectParameters as $parameter) {
            if (is_string($parameter['model']) && $parameter['model'] !== '' && is_string($parameter['variable'])) {
                $variables[] = $parameter['variable'];
            }
        }

        return $variables;
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
    private function chainModel(MethodCall|NullsafeMethodCall $call, RouteSubject $subject): ?string
    {
        $root = $call;

        while ($root instanceof MethodCall || $root instanceof NullsafeMethodCall) {
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
    private function chainTable(MethodCall|NullsafeMethodCall $call): ?string
    {
        $root = $call;

        while ($root instanceof MethodCall || $root instanceof NullsafeMethodCall) {
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
     * Whether a chain is scoped through the authenticated user, an ownership column, or a bound parent model.
     *
     * Only the call spine is read. A user() call inside an unrelated argument does not scope the query.
     *
     * @param  list<string>  $ownershipColumns
     * @param  list<string>  $modelVariables
     */
    private function chainIsScoped(MethodCall|NullsafeMethodCall $call, array $ownershipColumns, array $modelVariables): bool
    {
        if (AuthExpressions::chainIsUserRooted($call)) {
            return true;
        }

        $current = $call;

        while ($current instanceof MethodCall || $current instanceof NullsafeMethodCall || $current instanceof StaticCall) {
            if ($this->isScopingCall($current, $ownershipColumns, $modelVariables)) {
                return true;
            }

            if ($current instanceof StaticCall) {
                break;
            }

            $current = $current->var;
        }

        return false;
    }

    /**
     * Whether one query call constrains an ownership column to the signed-in user or a bound parent.
     *
     * Recognises `where('user_id', Auth::id())`, `where('user_id', '=', $request->user()->id)`,
     * `where(['team_id' => $team->id])`, `whereBelongsTo($request->user())`, and the same
     * attribute arrays passed to firstOrCreate and updateOrCreate.
     *
     * @param  list<string>  $ownershipColumns
     * @param  list<string>  $modelVariables
     */
    private function isScopingCall(MethodCall|NullsafeMethodCall|StaticCall $call, array $ownershipColumns, array $modelVariables): bool
    {
        if (! $call->name instanceof Node\Identifier) {
            return false;
        }

        $name = strtolower($call->name->toString());

        if (! in_array($name, self::SCOPING_METHODS, true)) {
            return false;
        }

        $arguments = array_values(array_filter($call->args, static fn ($arg): bool => $arg instanceof Node\Arg));
        $first = $arguments[0]->value ?? null;

        if ($first === null) {
            return false;
        }

        if ($name === 'wherebelongsto') {
            return $this->isOwnerValue($first, $modelVariables);
        }

        if ($first instanceof String_) {
            if (! in_array($first->value, $ownershipColumns, true)) {
                return false;
            }

            $value = count($arguments) >= 3 ? $arguments[2]->value : ($arguments[1]->value ?? null);

            return $value !== null && $this->isOwnerValue($value, $modelVariables);
        }

        if ($first instanceof Node\Expr\Array_) {
            foreach ($first->items as $item) {
                if ($item instanceof Node\ArrayItem && $item->key instanceof String_
                    && in_array($item->key->value, $ownershipColumns, true)
                    && $this->isOwnerValue($item->value, $modelVariables)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Whether a value comes from the signed-in user, the current tenant, a route-bound model, or a variable holding one.
     *
     * @param  list<string>  $modelVariables
     */
    private function isOwnerValue(Node $value, array $modelVariables): bool
    {
        return AuthExpressions::isUserValue($value, $modelVariables);
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
     * Compact source text for evidence messages, printed with the names as written in the source.
     */
    private function expressionText(Node $node): string
    {
        try {
            $traverser = new NodeTraverser(new CloningVisitor, new class extends NodeVisitorAbstract
            {
                public function leaveNode(Node $node): ?Node
                {
                    $original = $node->getAttribute('originalName');

                    return $node instanceof Name && $original instanceof Name ? $original : null;
                }
            });

            $copy = $traverser->traverse([$node])[0];
            $printer = new Standard;
            $text = $copy instanceof Node\Expr ? $printer->prettyPrintExpr($copy) : $printer->prettyPrint([$copy]);
        } catch (\Throwable) {
            $text = $node::class;
        }

        $text = preg_replace('/\s+/', ' ', $text) ?? $text;

        return strlen($text) > 140 ? substr($text, 0, 137).'...' : $text;
    }
}

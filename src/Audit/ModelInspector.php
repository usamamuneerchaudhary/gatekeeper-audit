<?php

declare(strict_types=1);

namespace Usamamuneerchaudhary\GatekeeperAudit\Audit;

use Illuminate\Support\Str;
use PhpParser\Node;
use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Expr\StaticCall;
use PhpParser\Node\Stmt\Class_;
use Throwable;

final class ModelInspector
{
    /** @var array<string, ModelInfo> */
    private array $cache = [];

    /**
     * Read ownership configuration used by the scoping rules.
     *
     * @param  array<string, mixed>  $config
     */
    public function __construct(
        private readonly PhpFileIndex $files,
        private readonly array $config,
    ) {}

    /**
     * Inspect a model class once and cache the result for this run.
     */
    public function inspect(string $class): ModelInfo
    {
        $class = ltrim($class, '\\');

        return $this->cache[$class] ??= $this->build($class);
    }

    /**
     * Build ownership facts from config and the model source.
     */
    private function build(string $class): ModelInfo
    {
        $ownership = is_array($this->config['ownership'] ?? null) ? $this->config['ownership'] : [];
        $listed = array_map(static fn (mixed $value): string => ltrim((string) $value, '\\'), is_array($ownership['models'] ?? null) ? $ownership['models'] : []);
        $ignored = array_map(static fn (mixed $value): string => ltrim((string) $value, '\\'), is_array($ownership['ignore_models'] ?? null) ? $ownership['ignore_models'] : []);
        $relations = is_array($ownership['relations'] ?? null) ? $ownership['relations'] : ['user', 'owner', 'tenant', 'team', 'account'];
        $scopeTraits = array_map(static fn (mixed $value): string => ltrim((string) $value, '\\'), is_array($ownership['global_scope_traits'] ?? null) ? $ownership['global_scope_traits'] : []);

        if (in_array($class, $ignored, true)) {
            return new ModelInfo($class, false, false, $this->tableFor($class));
        }

        $owned = in_array($class, $listed, true);
        $hasGlobalScope = false;

        $node = $this->files->findClassLike($class, 'model');

        if ($node instanceof Class_) {
            $methods = $this->files->methodsOf($node);

            foreach ($methods as $name => $method) {
                if ($method->stmts === null) {
                    continue;
                }

                $calls = $this->files->finder()->findInstanceOf($method->stmts, MethodCall::class);

                foreach ($calls as $call) {
                    if (! $call->name instanceof Node\Identifier) {
                        continue;
                    }

                    $called = strtolower($call->name->toString());

                    if ($called === 'belongsto') {
                        $owned = true;
                    }
                }

                if ($this->callsAddGlobalScope($method->stmts)) {
                    $hasGlobalScope = true;
                }

                if (in_array($name, array_map('strtolower', $relations), true)) {
                    $owned = true;
                }
            }

            foreach ($this->files->traitsOf($node) as $trait) {
                if (in_array($trait, $scopeTraits, true)) {
                    $hasGlobalScope = true;
                }

                // Framework traits such as SoftDeletes register scopes that never constrain by owner.
                if (str_starts_with($trait, 'Illuminate\\')) {
                    continue;
                }

                $traitNode = $this->files->findClassLike($trait, 'trait');

                if ($traitNode === null) {
                    continue;
                }

                foreach ($this->files->methodsOf($traitNode) as $method) {
                    if ($method->stmts === null) {
                        continue;
                    }

                    if ($this->callsAddGlobalScope($method->stmts)) {
                        $hasGlobalScope = true;
                    }
                }
            }
        }

        return new ModelInfo($class, $owned, $hasGlobalScope, $this->tableFor($class));
    }

    /**
     * Whether the statements register a global scope by method or static call.
     *
     * @param  list<Node>  $statements
     */
    private function callsAddGlobalScope(array $statements): bool
    {
        $calls = $this->files->finder()->find($statements, static fn (Node $node): bool => $node instanceof StaticCall || $node instanceof MethodCall);

        foreach ($calls as $call) {
            if (! $call instanceof StaticCall && ! $call instanceof MethodCall) {
                continue;
            }

            if (! $call->name instanceof Node\Identifier || strtolower($call->name->toString()) !== 'addglobalscope') {
                continue;
            }

            if (! $this->isFrameworkScope($call->args[0] ?? null)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Whether a scope argument is a framework scope such as SoftDeletingScope.
     */
    private function isFrameworkScope(mixed $argument): bool
    {
        if (! $argument instanceof Node\Arg) {
            return false;
        }

        $value = $argument->value;

        if ($value instanceof Node\Expr\New_ && $value->class instanceof Node\Name) {
            return str_starts_with(ltrim($value->class->toString(), '\\'), 'Illuminate\\');
        }

        return false;
    }

    /**
     * Owned-model facts for a table, used when a DB::table() query names no model.
     *
     * Candidates are the configured ownership models and the conventional application model
     * for the table name, for example App\Models\Invoice for invoices. Returns null when no
     * candidate uses this table.
     */
    public function forTable(string $table): ?ModelInfo
    {
        $ownership = is_array($this->config['ownership'] ?? null) ? $this->config['ownership'] : [];
        $candidates = array_map(static fn (mixed $value): string => ltrim((string) $value, '\\'), is_array($ownership['models'] ?? null) ? $ownership['models'] : []);

        try {
            $namespace = function_exists('app') ? app()->getNamespace() : 'App\\';
        } catch (Throwable) {
            $namespace = 'App\\';
        }

        $candidates[] = $namespace.'Models\\'.Str::studly(Str::singular($table));
        $candidates[] = $namespace.Str::studly(Str::singular($table));

        foreach (array_unique($candidates) as $candidate) {
            if (! class_exists($candidate) || ! is_subclass_of($candidate, 'Illuminate\\Database\\Eloquent\\Model')) {
                continue;
            }

            $info = $this->inspect($candidate);

            if ($info->table === $table) {
                return $info;
            }
        }

        return null;
    }

    /**
     * Resolve a model table through Eloquent when the class can be built, else by convention.
     */
    private function tableFor(string $class): ?string
    {
        if (! class_exists($class)) {
            return null;
        }

        try {
            $reflection = new \ReflectionClass($class);

            if (! $reflection->isInstantiable()) {
                return null;
            }

            $instance = $reflection->newInstanceWithoutConstructor();

            if (method_exists($instance, 'getTable')) {
                $table = $instance->getTable();

                return is_string($table) && $table !== '' ? $table : null;
            }
        } catch (Throwable $e) {
            return null;
        }

        return null;
    }
}

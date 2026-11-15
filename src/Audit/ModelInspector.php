<?php

declare(strict_types=1);

namespace Usamamuneerchaudhary\GatekeeperAudit\Audit;

use PhpParser\Node;
use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Expr\StaticCall;
use PhpParser\Node\Stmt\Class_;

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

        $node = $this->files->findClassLike($class);

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

                    if ($called === 'addglobalscope') {
                        $hasGlobalScope = true;
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

                $traitNode = $this->files->findClassLike($trait);

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
        foreach ($this->files->finder()->findInstanceOf($statements, StaticCall::class) as $call) {
            if ($call->name instanceof Node\Identifier && strtolower($call->name->toString()) === 'addglobalscope') {
                return true;
            }
        }

        foreach ($this->files->finder()->findInstanceOf($statements, MethodCall::class) as $call) {
            if ($call->name instanceof Node\Identifier && strtolower($call->name->toString()) === 'addglobalscope') {
                return true;
            }
        }

        return false;
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
        } catch (\Throwable) {
            return null;
        }

        return null;
    }
}

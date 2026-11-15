<?php

declare(strict_types=1);

namespace Usamamuneerchaudhary\GatekeeperAudit\Audit;

use PhpParser\Node;
use PhpParser\Node\Stmt\Class_;
use PhpParser\Node\Stmt\ClassLike;
use PhpParser\Node\Stmt\Trait_;
use PhpParser\NodeFinder;
use PhpParser\NodeTraverser;
use PhpParser\NodeVisitor\NameResolver;
use PhpParser\Parser;
use PhpParser\ParserFactory;
use ReflectionClass;
use Throwable;

final class PhpFileIndex
{
    private Parser $parser;

    private NodeFinder $finder;

    /** @var array<string, list<Node>|null> */
    private array $cache = [];

    /** @var array<string, true> */
    private array $failed = [];

    /**
     * Create the parser and node finder used for every file in a run.
     */
    public function __construct()
    {
        $this->parser = (new ParserFactory)->createForNewestSupportedVersion();
        $this->finder = new NodeFinder;
    }

    /**
     * Parse a file once per realpath. Returns null when the file is missing or unparsable.
     *
     * @return list<Node>|null
     */
    public function parse(string $file): ?array
    {
        $real = realpath($file);

        if ($real === false) {
            return null;
        }

        if (array_key_exists($real, $this->cache)) {
            return $this->cache[$real];
        }

        try {
            $code = file_get_contents($real);

            if ($code === false) {
                throw new \RuntimeException('Unreadable file.');
            }

            $statements = $this->parser->parse($code);

            if ($statements === null) {
                throw new \RuntimeException('Parser returned no statements.');
            }

            $traverser = new NodeTraverser;
            $traverser->addVisitor(new NameResolver(null, ['replaceNodes' => true, 'preserveOriginalNames' => true]));
            $statements = $traverser->traverse($statements);

            return $this->cache[$real] = array_values($statements);
        } catch (Throwable $e) {
            $this->failed[$real] = true;

            return $this->cache[$real] = null;
        }
    }

    /**
     * Whether the last parse attempt for a file failed.
     */
    public function failed(string $file): bool
    {
        $real = realpath($file);

        return $real !== false && isset($this->failed[$real]);
    }

    /**
     * Find a class, trait, or interface declaration for a fully qualified name.
     */
    public function findClassLike(string $class): ?ClassLike
    {
        $file = $this->fileFor($class);

        if ($file === null) {
            return null;
        }

        $statements = $this->parse($file);

        if ($statements === null) {
            return null;
        }

        $found = $this->finder->findFirst($statements, static function (Node $node) use ($class): bool {
            return $node instanceof ClassLike
                && $node->namespacedName !== null
                && strcasecmp(ltrim($node->namespacedName->toCodeString(), '\\'), ltrim($class, '\\')) === 0;
        });

        return $found instanceof ClassLike ? $found : null;
    }

    /**
     * Source file for a class through reflection, or null when unavailable.
     */
    public function fileFor(string $class): ?string
    {
        $class = ltrim($class, '\\');

        if (! class_exists($class) && ! trait_exists($class) && ! interface_exists($class)) {
            return null;
        }

        try {
            $reflection = new ReflectionClass($class);
        } catch (Throwable) {
            return null;
        }

        $file = $reflection->getFileName();

        return is_string($file) && $file !== '' ? $file : null;
    }

    /**
     * All methods declared directly on a class-like node, keyed by lowercase name.
     *
     * @return array<string, Node\Stmt\ClassMethod>
     */
    public function methodsOf(ClassLike $class): array
    {
        $methods = [];

        foreach ($class->getMethods() as $method) {
            $methods[strtolower($method->name->toString())] = $method;
        }

        return $methods;
    }

    /**
     * Trait names used directly by a class-like node, fully qualified when resolvable.
     *
     * @return list<string>
     */
    public function traitsOf(ClassLike $class): array
    {
        if (! $class instanceof Class_ && ! $class instanceof Trait_) {
            return [];
        }

        $traits = [];

        foreach ($class->getTraitUses() as $use) {
            foreach ($use->traits as $trait) {
                $traits[] = ltrim($trait->toCodeString(), '\\');
            }
        }

        return $traits;
    }

    /**
     * Expose the shared node finder for inspectors.
     */
    public function finder(): NodeFinder
    {
        return $this->finder;
    }
}

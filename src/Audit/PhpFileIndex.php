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
use PhpParser\NodeVisitor\ParentConnectingVisitor;
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

    /** @var array<string, array{roles: array<string, true>, parsed: bool}> */
    private array $covered = [];

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
     * A role is recorded when the caller knows why the file was opened.
     *
     * @return list<Node>|null
     */
    public function parse(string $file, ?string $role = null): ?array
    {
        $real = realpath($file);

        if ($real === false) {
            return null;
        }

        if (array_key_exists($real, $this->cache)) {
            $this->remember($real, $role, $this->cache[$real] !== null);

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
            $traverser->addVisitor(new ParentConnectingVisitor);
            $statements = array_values($traverser->traverse($statements));
            $this->cache[$real] = $statements;
            $this->remember($real, $role, true);

            return $statements;
        } catch (Throwable $e) {
            $this->failed[$real] = true;
            $this->cache[$real] = null;
            $this->remember($real, $role, false);

            return null;
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
     *
     * Returns null when the class has no file or the file cannot be parsed.
     */
    public function findClassLike(string $class, ?string $role = null): ?ClassLike
    {
        $file = $this->fileFor($class);

        if ($file === null) {
            return null;
        }

        $statements = $this->parse($file, $role);

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

        $file = (new ReflectionClass($class))->getFileName();

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

    /**
     * Remember why a class file was opened.
     *
     * Returns without recording when the class has no source file.
     */
    public function assignRole(string $class, string $role): void
    {
        $file = $this->fileFor($class);

        if ($file === null) {
            return;
        }

        $real = realpath($file);

        if ($real === false) {
            return;
        }

        $this->covered[$real] ??= ['roles' => [], 'parsed' => false];
        $this->covered[$real]['roles'][$role] = true;
    }

    /**
     * Files opened during this run.
     *
     * Vendor paths are omitted unless the audit was asked to include them.
     * Paths are relative to the application base path when they live under it.
     *
     * @return list<array{path: string, roles: list<string>, parsed: bool}>
     */
    public function coveredFiles(bool $includeVendor = false): array
    {
        $files = [];

        foreach ($this->covered as $path => $entry) {
            $normalized = str_replace('\\', '/', $path);

            if (! $includeVendor && str_contains($normalized, '/vendor/')) {
                continue;
            }

            $roles = array_keys($entry['roles']);
            sort($roles);

            if ($roles === []) {
                $roles = ['php'];
            }

            $files[] = [
                'path' => self::relativePath($path),
                'roles' => $roles,
                'parsed' => $entry['parsed'],
            ];
        }

        usort($files, static fn (array $left, array $right): int => strcmp($left['path'], $right['path']));

        return $files;
    }

    /**
     * Path relative to the application, or the original path when it lives elsewhere.
     */
    public static function relativePath(string $path): string
    {
        $real = realpath($path);
        $normalized = str_replace('\\', '/', $real === false ? $path : $real);
        $base = realpath(base_path());
        $prefix = rtrim(str_replace('\\', '/', $base === false ? base_path() : $base), '/').'/';

        if (str_starts_with($normalized, $prefix)) {
            return substr($normalized, strlen($prefix));
        }

        return $normalized;
    }

    /**
     * Record a parsed file and an optional role. A later success marks the file parsed.
     */
    private function remember(string $real, ?string $role, bool $parsed): void
    {
        $entry = $this->covered[$real] ?? ['roles' => [], 'parsed' => false];

        if ($role !== null && $role !== '') {
            $entry['roles'][$role] = true;
        }

        if ($parsed) {
            $entry['parsed'] = true;
        }

        $this->covered[$real] = $entry;
    }
}

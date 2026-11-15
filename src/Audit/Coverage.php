<?php

declare(strict_types=1);

namespace Usamamuneerchaudhary\GatekeeperAudit\Audit;

final readonly class Coverage
{
    /**
     * @param  array<string, array{audited: int, skipped: int}>  $routes
     * @param  list<array{path: string, roles: list<string>, parsed: bool}>  $files
     * @param  list<array{reason: string, count: int}>  $skipped
     * @param  list<array{name: string, file: string}>  $console
     */
    public function __construct(
        public array $routes,
        public array $files,
        public array $skipped,
        public array $console,
    ) {}

    /**
     * Coverage payload stored on the versioned JSON report.
     *
     * @return array{routes: array<string, array{audited: int, skipped: int}>, files: list<array{path: string, roles: list<string>, parsed: bool}>, skipped: list<array{reason: string, count: int}>, console: list<array{name: string, file: string}>}
     */
    public function toArray(): array
    {
        return [
            'routes' => $this->routes,
            'files' => $this->files,
            'skipped' => $this->skipped,
            'console' => $this->console,
        ];
    }
}

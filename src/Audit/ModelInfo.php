<?php

declare(strict_types=1);

namespace Usamamuneerchaudhary\GatekeeperAudit\Audit;

final readonly class ModelInfo
{
    /**
     * Ownership and scoping facts read from a model class.
     */
    public function __construct(
        public string $class,
        public bool $owned,
        public bool $hasGlobalScope,
        public ?string $table,
    ) {}
}

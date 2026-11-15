<?php

declare(strict_types=1);

namespace Usamamuneerchaudhary\GatekeeperAudit\Audit;

final readonly class ActionAnalysis
{
    /**
     * @param  list<string>  $roleEvidence
     * @param  list<array{rule: string, model: string|null, table: string|null, line: int, expression: string}>  $lookups
     */
    public function __construct(
        public bool $unparsed,
        public bool $hasObjectCheck,
        public ?string $objectCheckEvidence,
        public bool $hasAnyAuthorization,
        public array $roleEvidence,
        public bool $formRequestTrivial,
        public ?string $formRequestClass,
        public bool $policyTrivial,
        public ?string $policyEvidence,
        public array $lookups,
    ) {}

    /**
     * Analysis used when an action file cannot be parsed.
     */
    public static function unparsed(): self
    {
        return new self(true, false, null, false, [], false, null, false, null, []);
    }
}

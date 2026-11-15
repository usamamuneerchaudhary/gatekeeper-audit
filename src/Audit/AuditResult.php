<?php

declare(strict_types=1);

namespace Usamamuneerchaudhary\GatekeeperAudit\Audit;

final readonly class AuditResult
{
    /**
     * @param  list<Finding>  $findings
     * @param  list<array{subject: RouteSubject, reason: string}>  $skipped
     * @param  list<RouteSubject>  $passed
     * @param  list<array{finding: Finding, reason: string}>  $suppressed
     */
    public function __construct(
        public array $findings,
        public array $skipped,
        public array $passed,
        public array $suppressed,
        public int $audited,
        public Coverage $coverage,
    ) {}

    /**
     * Findings grouped by severity value for the summary line.
     *
     * @return array{high: int, medium: int, low: int}
     */
    public function counts(): array
    {
        $counts = ['high' => 0, 'medium' => 0, 'low' => 0];

        foreach ($this->findings as $finding) {
            $counts[$finding->severity->value]++;
        }

        return $counts;
    }
}

<?php

declare(strict_types=1);

namespace Usamamuneerchaudhary\GatekeeperAudit\Audit;

use Usamamuneerchaudhary\GatekeeperAudit\Enums\SuggestionMode;

final readonly class Suggestion
{
    /**
     * @param  list<string>  $steps
     */
    public function __construct(
        public SuggestionMode $mode,
        public string $summary,
        public array $steps,
        public ?string $diff = null,
    ) {}

    /**
     * Serialise the suggestion for JSON and other machine reports.
     *
     * @return array{mode: string, summary: string, steps: list<string>, diff: string|null}
     */
    public function toArray(): array
    {
        return [
            'mode' => $this->mode->value,
            'summary' => $this->summary,
            'steps' => $this->steps,
            'diff' => $this->diff,
        ];
    }
}

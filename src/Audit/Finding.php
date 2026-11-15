<?php

declare(strict_types=1);

namespace Usamamuneerchaudhary\GatekeeperAudit\Audit;

use Usamamuneerchaudhary\GatekeeperAudit\Enums\Severity;

final readonly class Finding
{
    /**
     * @param  list<string>  $methods
     * @param  list<string>  $evidence
     * @param  list<int>  $lines
     */
    public function __construct(
        public string $rule,
        public Severity $severity,
        public array $methods,
        public string $uri,
        public string $action,
        public ?string $file,
        public array $lines,
        public string $message,
        public array $evidence = [],
    ) {}

    /**
     * Build a finding with its stable baseline id.
     *
     * The id deliberately excludes line numbers so a baseline entry survives
     * unrelated edits around the flagged line.
     */
    public function id(): string
    {
        return $this->rule.':'.implode('|', $this->methods).':'.$this->uri.':'.$this->action;
    }

    /**
     * The first known line, or null when the action could not be located.
     */
    public function line(): ?int
    {
        return $this->lines[0] ?? null;
    }

    /**
     * Serialise for the versioned JSON report.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'id' => $this->id(),
            'rule' => $this->rule,
            'severity' => $this->severity->value,
            'methods' => $this->methods,
            'uri' => $this->uri,
            'action' => $this->action,
            'file' => $this->file,
            'lines' => $this->lines,
            'message' => $this->message,
            'evidence' => $this->evidence,
        ];
    }
}

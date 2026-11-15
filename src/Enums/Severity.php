<?php

declare(strict_types=1);

namespace Usamamuneerchaudhary\GatekeeperAudit\Enums;

enum Severity: string
{
    case Low = 'low';
    case Medium = 'medium';
    case High = 'high';

    /**
     * Numeric rank used for --fail-on thresholds and report ordering.
     */
    public function rank(): int
    {
        return match ($this) {
            self::Low => 1,
            self::Medium => 2,
            self::High => 3,
        };
    }

    /**
     * Whether this severity meets or exceeds the given threshold.
     */
    public function atLeast(self $threshold): bool
    {
        return $this->rank() >= $threshold->rank();
    }
}

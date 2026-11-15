<?php

declare(strict_types=1);

namespace Usamamuneerchaudhary\GatekeeperAudit\Report;

use Usamamuneerchaudhary\GatekeeperAudit\Audit\AuditResult;
use Usamamuneerchaudhary\GatekeeperAudit\Enums\Severity;

final class GithubReporter
{
    /**
     * Render GitHub workflow commands, one per finding.
     */
    public function render(AuditResult $result): string
    {
        $lines = [];

        foreach ($result->findings as $finding) {
            $level = $finding->severity === Severity::Low ? 'notice' : 'error';
            $properties = [];

            if ($finding->file !== null) {
                $properties[] = 'file='.$this->escape($finding->file);
            }

            if ($finding->line() !== null) {
                $properties[] = 'line='.$finding->line();
            }

            $properties[] = 'title='.$this->escape('Gatekeeper '.$finding->rule);
            $message = $this->escape(implode('|', $finding->methods).' '.$finding->uri.': '.$finding->message.' ['.$finding->id().']');
            $lines[] = '::'.$level.' '.implode(',', $properties).'::'.$message;
        }

        $counts = $result->counts();
        $lines[] = sprintf('Gatekeeper audit: %d high, %d medium, %d low.', $counts['high'], $counts['medium'], $counts['low']);

        return implode(PHP_EOL, $lines).PHP_EOL;
    }

    /**
     * Escape a workflow command value.
     */
    private function escape(string $value): string
    {
        return strtr($value, ['%' => '%25', "\r" => '%0D', "\n" => '%0A', ':' => '%3A', ',' => '%2C']);
    }
}

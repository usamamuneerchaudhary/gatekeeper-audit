<?php

declare(strict_types=1);

namespace Usamamuneerchaudhary\GatekeeperAudit\Report;

use Symfony\Component\Console\Formatter\OutputFormatter;
use Usamamuneerchaudhary\GatekeeperAudit\Audit\AuditResult;
use Usamamuneerchaudhary\GatekeeperAudit\Audit\Finding;
use Usamamuneerchaudhary\GatekeeperAudit\Enums\Severity;
use Usamamuneerchaudhary\GatekeeperAudit\Enums\SuggestionMode;

final class ConsoleReporter
{
    /**
     * Render the grouped human report with severity colors and a diff for each suggestion.
     */
    public function render(AuditResult $result, bool $verbose = false): string
    {
        $lines = ['<options=bold>Gatekeeper audit</>', ''];

        if ($result->findings === []) {
            $lines[] = '<fg=green>No findings.</>';
        }

        foreach ($result->findings as $index => $finding) {
            if ($index > 0) {
                $lines[] = '';
            }

            $lines = [...$lines, ...$this->findingLines($finding)];
        }

        if ($verbose) {
            $lines[] = '';
            $lines[] = '<options=bold>Passed</>';

            foreach ($result->passed as $subject) {
                $lines[] = '  <fg=green>[pass]</> '.implode('|', $subject->methods).' '.$this->escape($subject->uri).' '.$this->escape($subject->action);
            }

            $lines[] = '<options=bold>Skipped</>';

            foreach ($result->skipped as $entry) {
                $lines[] = '  <fg=gray>[skip]</> '.implode('|', $entry['subject']->methods).' '.$this->escape($entry['subject']->uri).': '.$this->escape($entry['reason']);
            }

            $lines[] = '<options=bold>Suppressed</>';

            foreach ($result->suppressed as $entry) {
                $lines[] = '  <fg=gray>[suppressed]</> '.$this->escape($entry['finding']->id()).': '.$this->escape($entry['reason']);
            }
        }

        $counts = $result->counts();
        $lines[] = '';
        $lines[] = sprintf(
            '<options=bold>Summary:</> %d high, %d medium, %d low, %d passed, %d skipped, %d suppressed, %d audited.',
            $counts['high'],
            $counts['medium'],
            $counts['low'],
            count($result->passed),
            count($result->skipped),
            count($result->suppressed),
            $result->audited,
        );

        return implode(PHP_EOL, $lines).PHP_EOL;
    }

    /**
     * One finding card: where it is, why, and the colored suggestion.
     *
     * @return list<string>
     */
    private function findingLines(Finding $finding): array
    {
        $location = $finding->action;

        if ($finding->file !== null) {
            $location .= ' ('.$finding->file.($finding->line() !== null ? ':'.$finding->line() : '').')';
        }

        $lines = [
            sprintf(
                '%s %s %s <fg=gray>%s</>',
                $this->severity($finding->severity),
                implode('|', $finding->methods),
                $this->escape($finding->uri),
                $this->escape($finding->rule),
            ),
            '  <fg=gray>'.$this->escape($location).'</>',
            '  '.$this->escape($finding->message),
        ];

        foreach ($finding->evidence as $evidence) {
            $lines[] = '  <fg=gray>-</> '.$this->escape($evidence);
        }

        $suggestion = $finding->suggestion;

        if ($suggestion === null) {
            return $lines;
        }

        $lines[] = '';
        $lines[] = '  <options=bold>Suggested fix</>';
        $lines[] = '  '.$this->escape($suggestion->summary);

        if ($suggestion->diff !== null) {
            foreach (explode("\n", $suggestion->diff) as $diffLine) {
                $lines[] = '  '.$this->diffLine($diffLine);
            }

            $lines[] = $suggestion->mode === SuggestionMode::Patch
                ? '  <fg=green>Apply this diff as written.</>'
                : '  <fg=yellow>Hint only. Adapt it before applying.</>';
        } else {
            foreach ($suggestion->steps as $step) {
                $lines[] = '  <fg=gray>-</> '.$this->escape($step);
            }
        }

        return $lines;
    }

    /**
     * Color a severity token. The bracketed word stays so plain output is greppable.
     */
    private function severity(Severity $severity): string
    {
        $label = '['.strtoupper($severity->value).']';

        $color = match ($severity) {
            Severity::High => 'red',
            Severity::Medium => 'yellow',
            Severity::Low => 'gray',
        };

        return "<fg={$color};options=bold>{$label}</>";
    }

    /**
     * Color one diff line. Added lines are green and removed lines are red.
     */
    private function diffLine(string $line): string
    {
        $escaped = $this->escape($line);

        if (str_starts_with($line, '+')) {
            return '<fg=green>'.$escaped.'</>';
        }

        if (str_starts_with($line, '-')) {
            return '<fg=red>'.$escaped.'</>';
        }

        return '<fg=gray>'.$escaped.'</>';
    }

    /**
     * Escape text so source code is not parsed as console color tags.
     */
    private function escape(string $text): string
    {
        return OutputFormatter::escape($text);
    }
}

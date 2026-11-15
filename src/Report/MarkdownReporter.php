<?php

declare(strict_types=1);

namespace Usamamuneerchaudhary\GatekeeperAudit\Report;

use Usamamuneerchaudhary\GatekeeperAudit\Audit\AuditResult;
use Usamamuneerchaudhary\GatekeeperAudit\Audit\Finding;
use Usamamuneerchaudhary\GatekeeperAudit\Enums\SuggestionMode;

final class MarkdownReporter
{
    /**
     * Render one markdown fix list an agent can apply finding by finding.
     */
    public function render(AuditResult $result): string
    {
        $counts = $result->counts();
        $lines = [
            '# Gatekeeper audit',
            '',
            'Fix the findings below one at a time. `patch` means apply the diff as written. `hint` means the diff is an example shape: adapt the ability, owner column, or relation before saving. Do not edit a baseline file to hide a finding. Do not replace an object check with a role check. Leave the application source unchanged when a finding has no diff.',
            '',
            '## Summary',
            '',
            '- High: '.$counts['high'],
            '- Medium: '.$counts['medium'],
            '- Low: '.$counts['low'],
            '- Passed: '.count($result->passed),
            '- Skipped: '.count($result->skipped),
            '- Suppressed: '.count($result->suppressed),
            '- Audited: '.$result->audited,
            '',
        ];

        $lines = [...$lines, ...$this->coverageLines($result)];

        if ($result->findings === []) {
            $lines[] = 'No findings.';
            $lines[] = '';
        }

        foreach ($result->findings as $index => $finding) {
            $lines = [...$lines, ...$this->findingLines($index + 1, $finding)];
        }

        return implode(PHP_EOL, $lines);
    }

    /**
     * Route files that registered the audited routes, files opened, and console commands left out.
     *
     * @return list<string>
     */
    private function coverageLines(AuditResult $result): array
    {
        $lines = [
            '## Coverage',
            '',
        ];

        if ($result->coverage->routes === []) {
            $lines[] = '- HTTP routes: none';
        }

        foreach ($result->coverage->routes as $file => $counts) {
            $lines[] = '- `'.$file.'`: '.$counts['audited'].' audited, '.$counts['skipped'].' skipped';
        }

        $lines[] = '- Files opened: '.count($result->coverage->files);
        $lines[] = '- Console commands not audited: '.count($result->coverage->console);
        $lines[] = '';
        $lines[] = '### Files';
        $lines[] = '';

        if ($result->coverage->files === []) {
            $lines[] = 'None.';
            $lines[] = '';
        }

        foreach ($result->coverage->files as $file) {
            $state = $file['parsed'] ? 'parsed' : 'unparsed';
            $lines[] = '- `'.$file['path'].'` ('.implode(', ', $file['roles']).', '.$state.')';
        }

        if ($result->coverage->files !== []) {
            $lines[] = '';
        }

        if ($result->coverage->console !== []) {
            $lines[] = '### Console';
            $lines[] = '';
            $lines[] = 'Console commands are outside the HTTP route audit.';
            $lines[] = '';

            foreach ($result->coverage->console as $command) {
                $lines[] = '- `'.$command['name'].'` (`'.$command['file'].'`)';
            }

            $lines[] = '';
        }

        if ($result->coverage->skipped !== []) {
            $lines[] = '### Skipped';
            $lines[] = '';

            foreach ($result->coverage->skipped as $row) {
                $lines[] = '- '.$row['count'].' '.$row['reason'];
            }

            $lines[] = '';
        }

        return $lines;
    }

    /**
     * One finding section with the file, the reason, and the suggested change.
     *
     * @return list<string>
     */
    private function findingLines(int $number, Finding $finding): array
    {
        $mode = $finding->suggestion?->mode->value ?? 'hint';
        $location = $finding->file ?? 'unknown';

        if ($finding->line() !== null) {
            $location .= ':'.$finding->line();
        }

        $lines = [
            '## '.$number.'. '.$finding->rule,
            '',
            '- Severity: '.$finding->severity->value,
            '- Mode: '.$mode,
            '- Route: `'.implode('|', $finding->methods).' '.$finding->uri.'`',
            '- Action: `'.$finding->action.'`',
            '- File: `'.$location.'`',
            '',
            '### Why',
            '',
            $finding->message,
            '',
        ];

        if ($finding->evidence !== []) {
            $lines[] = '### Evidence';
            $lines[] = '';

            foreach ($finding->evidence as $evidence) {
                $lines[] = '- '.$evidence;
            }

            $lines[] = '';
        }

        $suggestion = $finding->suggestion;

        if ($suggestion === null) {
            return $lines;
        }

        $lines[] = '### Suggested fix';
        $lines[] = '';
        $lines[] = $suggestion->summary;
        $lines[] = '';
        $lines[] = '### Steps';
        $lines[] = '';

        foreach ($suggestion->steps as $step) {
            $lines[] = '- '.$step;
        }

        $lines[] = '';

        if ($suggestion->diff !== null) {
            $lines[] = '### Diff';
            $lines[] = '';
            $lines[] = '```diff';
            $lines[] = $suggestion->diff;
            $lines[] = '```';
            $lines[] = '';
            $lines[] = $suggestion->mode === SuggestionMode::Patch
                ? 'Apply this diff as written.'
                : 'Hint only. Adapt it before applying.';
            $lines[] = '';
        }

        return $lines;
    }
}

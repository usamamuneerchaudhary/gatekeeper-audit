<?php

declare(strict_types=1);

namespace Usamamuneerchaudhary\GatekeeperAudit\Report;

use Usamamuneerchaudhary\GatekeeperAudit\Audit\AuditResult;

final class ConsoleReporter
{
    /**
     * Render the grouped human report.
     */
    public function render(AuditResult $result, bool $verbose = false): string
    {
        $lines = ['Gatekeeper audit', ''];

        if ($result->findings === []) {
            $lines[] = 'No findings.';
        }

        foreach ($result->findings as $finding) {
            $lines[] = sprintf('[%s] %s %s %s', strtoupper($finding->severity->value), implode('|', $finding->methods), $finding->uri, $finding->rule);
            $lines[] = '  '.$finding->action.($finding->file !== null ? ' ('.$finding->file.($finding->line() !== null ? ':'.$finding->line() : '').')' : '');
            $lines[] = '  '.$finding->message;

            foreach ($finding->evidence as $evidence) {
                $lines[] = '  - '.$evidence;
            }
        }

        if ($verbose) {
            $lines[] = '';
            $lines[] = 'Passed:';

            foreach ($result->passed as $subject) {
                $lines[] = '  [pass] '.implode('|', $subject->methods).' '.$subject->uri.' '.$subject->action;
            }

            $lines[] = 'Skipped:';

            foreach ($result->skipped as $entry) {
                $lines[] = '  [skip] '.implode('|', $entry['subject']->methods).' '.$entry['subject']->uri.': '.$entry['reason'];
            }

            $lines[] = 'Suppressed:';

            foreach ($result->suppressed as $entry) {
                $lines[] = '  [suppressed] '.$entry['finding']->id().': '.$entry['reason'];
            }
        }

        $counts = $result->counts();
        $lines[] = '';
        $lines[] = sprintf(
            'Summary: %d high, %d medium, %d low, %d passed, %d skipped, %d suppressed, %d audited.',
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
}

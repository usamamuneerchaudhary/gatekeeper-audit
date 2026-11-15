<?php

declare(strict_types=1);

namespace Usamamuneerchaudhary\GatekeeperAudit\Report;

use Usamamuneerchaudhary\GatekeeperAudit\Audit\AuditResult;

final class JsonReporter
{
    /**
     * Render the versioned JSON report.
     */
    public function render(AuditResult $result): string
    {
        $payload = [
            'version' => 'gatekeeper.report.v1',
            'summary' => [
                ...$result->counts(),
                'passed' => count($result->passed),
                'skipped' => count($result->skipped),
                'suppressed' => count($result->suppressed),
                'audited' => $result->audited,
            ],
            'findings' => array_map(static fn ($finding): array => $finding->toArray(), $result->findings),
            'skipped' => array_map(static fn (array $entry): array => [
                'methods' => $entry['subject']->methods,
                'uri' => $entry['subject']->uri,
                'action' => $entry['subject']->action,
                'reason' => $entry['reason'],
            ], $result->skipped),
            'suppressed' => array_map(static fn (array $entry): array => [
                'id' => $entry['finding']->id(),
                'reason' => $entry['reason'],
            ], $result->suppressed),
        ];

        $json = json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);

        return ($json === false ? '{}' : $json).PHP_EOL;
    }
}

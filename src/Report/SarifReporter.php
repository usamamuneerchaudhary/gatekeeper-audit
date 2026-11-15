<?php

declare(strict_types=1);

namespace Usamamuneerchaudhary\GatekeeperAudit\Report;

use Usamamuneerchaudhary\GatekeeperAudit\Audit\AuditResult;
use Usamamuneerchaudhary\GatekeeperAudit\Enums\Severity;

final class SarifReporter
{
    /**
     * Render a SARIF 2.1.0 log for code scanning.
     */
    public function render(AuditResult $result): string
    {
        $rules = [];
        $results = [];

        foreach ($result->findings as $finding) {
            $rules[$finding->rule] ??= [
                'id' => $finding->rule,
                'name' => $finding->rule,
                'shortDescription' => ['text' => $finding->message],
                'fullDescription' => ['text' => $finding->message],
                'defaultConfiguration' => ['level' => $this->level($finding->severity)],
            ];

            $location = ['physicalLocation' => ['artifactLocation' => ['uri' => $finding->file ?? $finding->uri]]];

            if ($finding->line() !== null && $finding->file !== null) {
                $location['physicalLocation']['region'] = ['startLine' => $finding->line()];
            }

            $results[] = [
                'ruleId' => $finding->rule,
                'level' => $this->level($finding->severity),
                'message' => ['text' => implode('|', $finding->methods).' '.$finding->uri.': '.$finding->message],
                'locations' => [$location],
                'partialFingerprints' => ['gatekeeperId' => $finding->id()],
            ];
        }

        $payload = [
            '$schema' => 'https://json.schemastore.org/sarif-2.1.0.json',
            'version' => '2.1.0',
            'runs' => [[
                'tool' => ['driver' => [
                    'name' => 'gatekeeper-audit',
                    'informationUri' => 'https://github.com/usamamuneerchaudhary/gatekeeper-audit',
                    'rules' => array_values($rules),
                ]],
                'results' => $results,
            ]],
        ];

        $json = json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);

        return ($json === false ? '{}' : $json).PHP_EOL;
    }

    /**
     * Map a severity to a SARIF level.
     */
    private function level(Severity $severity): string
    {
        return match ($severity) {
            Severity::High, Severity::Medium => 'error',
            Severity::Low => 'note',
        };
    }
}

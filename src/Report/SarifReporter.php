<?php

declare(strict_types=1);

namespace Usamamuneerchaudhary\GatekeeperAudit\Report;

use Usamamuneerchaudhary\GatekeeperAudit\Audit\AuditResult;
use Usamamuneerchaudhary\GatekeeperAudit\Audit\Finding;
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

            $location = ['physicalLocation' => ['artifactLocation' => $this->artifactLocation($finding)]];

            if ($finding->line() !== null && $finding->file !== null) {
                $location['physicalLocation']['region'] = ['startLine' => $finding->line()];
            }

            $results[] = [
                'ruleId' => $finding->rule,
                'level' => $this->level($finding->severity),
                'message' => ['text' => $this->message($finding)],
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
     * Result text, including the one-line suggestion when one exists.
     */
    private function message(Finding $finding): string
    {
        $text = implode('|', $finding->methods).' '.$finding->uri.': '.$finding->message;

        if ($finding->suggestion !== null) {
            $text .= ' Suggestion: '.$finding->suggestion->summary;
        }

        return $text;
    }

    /**
     * Artifact location relative to the repository root, so code scanning can attach it to a file.
     *
     * Findings carry paths relative to the application. Paths outside it become file URIs.
     *
     * @return array<string, string>
     */
    private function artifactLocation(Finding $finding): array
    {
        $file = $finding->file;

        if ($file === null || $file === '') {
            return ['uri' => $finding->uri];
        }

        $file = str_replace('\\', '/', $file);

        if (str_starts_with($file, '/') || preg_match('/^[A-Za-z]:\//', $file) === 1) {
            return ['uri' => 'file://'.(str_starts_with($file, '/') ? '' : '/').implode('/', array_map('rawurlencode', explode('/', $file)))];
        }

        return ['uri' => implode('/', array_map('rawurlencode', explode('/', $file))), 'uriBaseId' => '%SRCROOT%'];
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

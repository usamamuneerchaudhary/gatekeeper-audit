<?php

declare(strict_types=1);

namespace Usamamuneerchaudhary\GatekeeperAudit\Console;

use Illuminate\Console\Command;
use Symfony\Component\Console\Formatter\OutputFormatter;
use Usamamuneerchaudhary\GatekeeperAudit\Audit\Auditor;
use Usamamuneerchaudhary\GatekeeperAudit\Audit\AuditResult;
use Usamamuneerchaudhary\GatekeeperAudit\Audit\Baseline;
use Usamamuneerchaudhary\GatekeeperAudit\Audit\Finding;
use Usamamuneerchaudhary\GatekeeperAudit\Enums\Severity;
use Usamamuneerchaudhary\GatekeeperAudit\Report\ConsoleReporter;
use Usamamuneerchaudhary\GatekeeperAudit\Report\GithubReporter;
use Usamamuneerchaudhary\GatekeeperAudit\Report\JsonReporter;
use Usamamuneerchaudhary\GatekeeperAudit\Report\MarkdownReporter;
use Usamamuneerchaudhary\GatekeeperAudit\Report\SarifReporter;

class AuditCommand extends Command
{
    protected $signature = 'gatekeeper:audit
        {--format=console : Output format: console, markdown, json, github, or sarif}
        {--output= : Also write the report to this file. Markdown and JSON are the formats to hand to an agent}
        {--fail-on=high : Minimum severity that fails the run: high, medium, or low}
        {--fail-on-unauthorized : Fail on high and medium authorization and scoping findings}
        {--no-fail : Always exit 0 after a successful run}
        {--baseline= : Baseline file whose finding ids are suppressed}
        {--prune-baseline : Rewrite the baseline to the current finding set}
        {--only= : Only audit URIs starting with this prefix}
        {--include-vendor : Also audit vendor routes}
        {--include-public : Also audit routes without auth middleware}';

    protected $description = 'Audit authenticated routes for missing object-level authorization and unscoped lookups.';

    private const array UNAUTHORIZED_RULES = ['object_authorization', 'trivial_form_request', 'trivial_policy', 'missing_authorization', 'unscoped_lookup', 'unscoped_collection'];

    /**
     * Run the audit, print the selected report, and return the CI exit code.
     *
     * Returns 2 when the audit itself cannot run, instead of guessing.
     */
    public function handle(Auditor $auditor): int
    {
        $format = strtolower((string) $this->option('format'));

        if (! in_array($format, ['console', 'markdown', 'json', 'github', 'sarif'], true)) {
            $this->error("Unknown format [{$format}]. Use console, markdown, json, github, or sarif.");

            return 2;
        }

        $threshold = Severity::tryFrom(strtolower((string) $this->option('fail-on')));

        if ($threshold === null && ! $this->option('fail-on-unauthorized')) {
            $this->error('Unknown --fail-on value. Use high, medium, or low.');

            return 2;
        }

        try {
            $baselinePath = $this->baselinePath();
            $explicitBaseline = $this->option('baseline') !== null;

            if ($explicitBaseline && ! is_file($baselinePath)) {
                $this->error("Baseline file not found: {$baselinePath}");

                return 2;
            }

            $baselineIds = is_file($baselinePath) ? Baseline::read($baselinePath) : [];
            $result = $auditor->audit(
                includeVendor: (bool) $this->option('include-vendor'),
                includePublic: (bool) $this->option('include-public'),
                only: $this->option('only') !== null ? (string) $this->option('only') : null,
                baselineIds: $baselineIds,
            );

            $baselined = $this->baselinedFindings($result);
            $matchedIds = array_map(static fn (Finding $finding): string => $finding->id(), $baselined);
            $staleIds = array_values(array_diff($baselineIds, $matchedIds));

            // Pruning only removes ids that no longer match. New findings are never added here,
            // because that would hide them; record them on purpose with gatekeeper:baseline.
            if ($this->option('prune-baseline')) {
                if ($this->option('only') !== null) {
                    $this->error('--prune-baseline audits every route, so it cannot be combined with --only.');

                    return 2;
                }

                if (! is_file($baselinePath)) {
                    $this->error("No baseline to prune at {$baselinePath}. Create one with gatekeeper:baseline.");

                    return 2;
                }

                Baseline::write($baselinePath, $baselined);
            }
        } catch (\Throwable $exception) {
            $this->error('Gatekeeper audit could not run: '.$exception->getMessage());

            return 2;
        }

        $rendered = match ($format) {
            'json' => (new JsonReporter)->render($result),
            'markdown' => (new MarkdownReporter)->render($result),
            'github' => (new GithubReporter)->render($result),
            'sarif' => (new SarifReporter)->render($result),
            default => (new ConsoleReporter)->render($result, $this->output->isVerbose()),
        };

        $written = $this->writeOutput($rendered);

        if ($written !== null) {
            return $written;
        }

        $this->output->write($rendered);

        if ($staleIds !== [] && $format === 'console' && $this->option('only') === null) {
            $this->warn($this->option('prune-baseline') ? 'Pruned stale baseline ids:' : 'Stale baseline ids (no longer reported):');

            foreach ($staleIds as $id) {
                $this->line('  - '.$id);
            }
        }

        if ($this->option('no-fail')) {
            return self::SUCCESS;
        }

        return $this->shouldFail($result, $threshold) ? self::FAILURE : self::SUCCESS;
    }

    /**
     * Write a plain-text copy of the report when --output is set.
     *
     * Returns 2 when the file cannot be written, and null after a successful write or when no path was given.
     * Color tags are stripped so a saved console report stays readable. The command still prints the colored report.
     */
    private function writeOutput(string $rendered): ?int
    {
        $option = $this->option('output');

        if (! is_string($option) || $option === '') {
            return null;
        }

        $path = str_starts_with($option, '/') ? $option : base_path($option);
        $directory = dirname($path);

        if (! is_dir($directory)) {
            $this->error("Output directory not found: {$directory}");

            return 2;
        }

        $plain = (new OutputFormatter(false))->format($rendered);

        if (file_put_contents($path, $plain) === false) {
            $this->error("Could not write the report to {$path}.");

            return 2;
        }

        return null;
    }

    /**
     * Resolve the baseline path from the option or published config.
     */
    private function baselinePath(): string
    {
        $option = $this->option('baseline');
        $path = is_string($option) && $option !== '' ? $option : (string) config('gatekeeper.baseline', 'gatekeeper-baseline.json');

        if (str_starts_with($path, '/')) {
            return $path;
        }

        return base_path($path);
    }

    /**
     * Findings the baseline suppressed in this run.
     *
     * @return list<Finding>
     */
    private function baselinedFindings(AuditResult $result): array
    {
        $findings = [];

        foreach ($result->suppressed as $entry) {
            if ($entry['reason'] === 'baseline') {
                $findings[] = $entry['finding'];
            }
        }

        return $findings;
    }

    /**
     * Whether the findings cross the configured failure threshold.
     */
    private function shouldFail(AuditResult $result, ?Severity $threshold): bool
    {
        foreach ($result->findings as $finding) {
            if ($this->option('fail-on-unauthorized')) {
                if (in_array($finding->rule, self::UNAUTHORIZED_RULES, true) && $finding->severity->atLeast(Severity::Medium)) {
                    return true;
                }

                continue;
            }

            if ($threshold !== null && $finding->severity->atLeast($threshold)) {
                return true;
            }
        }

        return false;
    }
}

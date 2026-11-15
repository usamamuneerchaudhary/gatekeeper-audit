<?php

declare(strict_types=1);

namespace Usamamuneerchaudhary\GatekeeperAudit\Console;

use Illuminate\Console\Command;
use Usamamuneerchaudhary\GatekeeperAudit\Audit\Auditor;
use Usamamuneerchaudhary\GatekeeperAudit\Audit\AuditResult;
use Usamamuneerchaudhary\GatekeeperAudit\Audit\Baseline;
use Usamamuneerchaudhary\GatekeeperAudit\Enums\Severity;
use Usamamuneerchaudhary\GatekeeperAudit\Report\ConsoleReporter;
use Usamamuneerchaudhary\GatekeeperAudit\Report\GithubReporter;
use Usamamuneerchaudhary\GatekeeperAudit\Report\JsonReporter;
use Usamamuneerchaudhary\GatekeeperAudit\Report\SarifReporter;

class AuditCommand extends Command
{
    protected $signature = 'gatekeeper:audit
        {--format=console : Output format: console, json, github, or sarif}
        {--fail-on=high : Minimum severity that fails the run: high, medium, or low}
        {--fail-on-unauthorized : Fail on high and medium authorization and scoping findings}
        {--no-fail : Always exit 0 after a successful run}
        {--baseline= : Baseline file whose finding ids are suppressed}
        {--prune-baseline : Rewrite the baseline to the current finding set}
        {--only= : Only audit URIs starting with this prefix}
        {--include-vendor : Also audit vendor routes}
        {--include-public : Also audit routes without auth middleware}';

    protected $description = 'Audit authenticated routes for missing object-level authorization and unscoped lookups.';

    private const array UNAUTHORIZED_RULES = ['object_authorization', 'trivial_form_request', 'trivial_policy', 'unscoped_lookup', 'unscoped_collection'];

    /**
     * Run the audit, print the selected report, and return the CI exit code.
     *
     * Returns 2 when the audit itself cannot run, instead of guessing.
     */
    public function handle(Auditor $auditor): int
    {
        $format = strtolower((string) $this->option('format'));

        if (! in_array($format, ['console', 'json', 'github', 'sarif'], true)) {
            $this->error("Unknown format [{$format}]. Use console, json, github, or sarif.");

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
            $preBaseline = $auditor->audit(
                includeVendor: (bool) $this->option('include-vendor'),
                includePublic: (bool) $this->option('include-public'),
                only: $this->option('only') !== null ? (string) $this->option('only') : null,
            );

            if ($this->option('prune-baseline')) {
                Baseline::write($baselinePath, $preBaseline->findings);
                $baselineIds = array_map(static fn ($finding): string => $finding->id(), $preBaseline->findings);
            }

            $currentIds = array_map(static fn ($finding): string => $finding->id(), $preBaseline->findings);
            $staleIds = array_values(array_diff($baselineIds, $currentIds));
            $result = $this->applyBaseline($preBaseline, $baselineIds);
        } catch (\Throwable $exception) {
            $this->error('Gatekeeper audit could not run: '.$exception->getMessage());

            return 2;
        }

        $this->output->write(match ($format) {
            'json' => (new JsonReporter)->render($result),
            'github' => (new GithubReporter)->render($result),
            'sarif' => (new SarifReporter)->render($result),
            default => (new ConsoleReporter)->render($result, $this->output->isVerbose()),
        });

        if ($staleIds !== [] && $format === 'console') {
            $this->warn('Stale baseline ids (no longer reported):');

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
     * Remove baselined findings from a completed audit.
     *
     * @param  list<string>  $baselineIds
     */
    private function applyBaseline(AuditResult $result, array $baselineIds): AuditResult
    {
        if ($baselineIds === []) {
            return $result;
        }

        $findings = [];
        $suppressed = $result->suppressed;
        $passedSubjects = [];

        foreach ($result->findings as $finding) {
            if (in_array($finding->id(), $baselineIds, true)) {
                $suppressed[] = ['finding' => $finding, 'reason' => 'baseline'];

                continue;
            }

            $findings[] = $finding;
        }

        $passed = $result->passed;

        if (count($findings) !== count($result->findings) && $findings === []) {
            $passedSubjects = $passed;
        }

        return new AuditResult($findings, $result->skipped, $passedSubjects !== [] ? $passedSubjects : $passed, $suppressed, $result->audited);
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

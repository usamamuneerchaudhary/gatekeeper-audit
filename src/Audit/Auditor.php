<?php

declare(strict_types=1);

namespace Usamamuneerchaudhary\GatekeeperAudit\Audit;

use Usamamuneerchaudhary\GatekeeperAudit\Enums\Severity;

final readonly class Auditor
{
    /**
     * Wire the scanner, inspector, model facts, and suggestion builder.
     *
     * @param  array<string, mixed>  $config
     */
    public function __construct(
        private RouteScanner $scanner,
        private ActionInspector $inspector,
        private ModelInspector $models,
        private array $config,
        private Suggester $suggester,
        private PhpFileIndex $files,
        private ConsoleInventory $console,
    ) {}

    /**
     * Audit the registered routes and apply the baseline when given.
     *
     * @param  list<string>  $baselineIds
     */
    public function audit(bool $includeVendor = false, bool $includePublic = false, ?string $only = null, array $baselineIds = []): AuditResult
    {
        $findings = [];
        $skipped = [];
        $passed = [];
        $suppressed = [];
        $audited = 0;
        $routes = [];

        $flagGlobalScopes = (bool) ($this->config['ownership']['flag_global_scopes'] ?? false);

        foreach ($this->scanner->scan($includeVendor, $includePublic, $only) as $subject) {
            $routeFile = $subject->routeFile !== '' ? $subject->routeFile : 'unknown';
            $routes[$routeFile] ??= ['audited' => 0, 'skipped' => 0];

            if ($subject->skipReason !== null) {
                $skipped[] = ['subject' => $subject, 'reason' => $subject->skipReason];
                $routes[$routeFile]['skipped']++;

                continue;
            }

            $audited++;
            $routes[$routeFile]['audited']++;
            $subjectFindings = $this->auditSubject($subject, $flagGlobalScopes, $suppressed);
            $kept = [];

            foreach ($subjectFindings as $finding) {
                if (in_array($finding->id(), $baselineIds, true)) {
                    $suppressed[] = ['finding' => $finding, 'reason' => 'baseline'];

                    continue;
                }

                $kept[] = $finding;
            }

            if ($kept === []) {
                $passed[] = $subject;
            }

            $findings = [...$findings, ...$kept];
        }

        $this->sortFindings($findings);
        $console = $this->consoleCommands();

        return new AuditResult(
            $findings,
            $skipped,
            $passed,
            $suppressed,
            $audited,
            new Coverage(
                routes: $this->sortedRoutes($routes),
                files: $this->files->coveredFiles($includeVendor),
                skipped: $this->skippedReasons($skipped, $console),
                console: $console,
            ),
        );
    }

    /**
     * Application console commands, with paths relative to the application.
     *
     * @return list<array{name: string, file: string}>
     */
    private function consoleCommands(): array
    {
        return array_map(static fn (array $command): array => [
            'name' => $command['name'],
            'file' => PhpFileIndex::relativePath($command['file']),
        ], $this->console->applicationCommands());
    }

    /**
     * Route-file counts in path order so the report is stable.
     *
     * @param  array<string, array{audited: int, skipped: int}>  $routes
     * @return array<string, array{audited: int, skipped: int}>
     */
    private function sortedRoutes(array $routes): array
    {
        ksort($routes);

        return $routes;
    }

    /**
     * Collapse per-route skip reasons, then add console commands as their own reason.
     *
     * @param  list<array{subject: RouteSubject, reason: string}>  $skipped
     * @param  list<array{name: string, file: string}>  $console
     * @return list<array{reason: string, count: int}>
     */
    private function skippedReasons(array $skipped, array $console): array
    {
        $counts = [];

        foreach ($skipped as $entry) {
            $counts[$entry['reason']] = ($counts[$entry['reason']] ?? 0) + 1;
        }

        if ($console !== []) {
            $counts['console commands are not audited'] = count($console);
        }

        $rows = [];

        foreach ($counts as $reason => $count) {
            $rows[] = ['reason' => $reason, 'count' => $count];
        }

        usort($rows, static function (array $left, array $right): int {
            $byCount = $right['count'] <=> $left['count'];

            return $byCount !== 0 ? $byCount : strcmp($left['reason'], $right['reason']);
        });

        return $rows;
    }

    /**
     * Apply every rule to one route.
     *
     * @param  list<array{finding: Finding, reason: string}>  $suppressed
     * @return list<Finding>
     */
    private function auditSubject(RouteSubject $subject, bool $flagGlobalScopes, array &$suppressed): array
    {
        $analysis = $this->inspector->inspect($subject);

        if ($analysis->unparsed) {
            return [$this->report('unparsed_action', Severity::Low, $subject, $analysis, 'The action source could not be parsed, so no authorization signal could be confirmed.', [], $subject->line !== null ? [$subject->line] : [])];
        }

        $findings = [];

        if ($analysis->policyTrivial) {
            $findings[] = $this->report('trivial_policy', Severity::High, $subject, $analysis, 'A policy check runs, but the policy always returns true.', [$analysis->policyEvidence ?? 'policy returns true'], $subject->line !== null ? [$subject->line] : []);
        }

        if ($subject->isObjectRoute()) {
            if (! $analysis->hasObjectCheck && $analysis->formRequestTrivial && $analysis->formRequestClass !== null) {
                $findings[] = $this->report('trivial_form_request', Severity::High, $subject, $analysis, 'The FormRequest authorize() method does not check the routed object.', [$analysis->formRequestClass.'::authorize() is trivial or missing'], $subject->line !== null ? [$subject->line] : []);
            } elseif (! $analysis->hasObjectCheck) {
                $evidence = $analysis->roleEvidence;
                $evidence[] = 'no object-level authorize, Gate, can middleware, or FormRequest check was found';

                $findings[] = $this->report('object_authorization', Severity::High, $subject, $analysis, 'Authenticated route accepts an object but shows no object-level authorization check.', $evidence, $subject->line !== null ? [$subject->line] : []);
            }
        } elseif ($subject->isWrite()) {
            if ($analysis->formRequestTrivial && ! $analysis->hasAnyAuthorization && $analysis->formRequestClass !== null) {
                $findings[] = $this->report('trivial_form_request', Severity::Medium, $subject, $analysis, 'The FormRequest authorize() method does not check anything.', [$analysis->formRequestClass.'::authorize() is trivial or missing'], $subject->line !== null ? [$subject->line] : []);
            } elseif (! $analysis->hasAnyAuthorization) {
                $findings[] = $this->report('missing_authorization', Severity::Medium, $subject, $analysis, 'State-changing route shows no authorization check of any kind.', ['no authorize, Gate, can middleware, or FormRequest check was found'], $subject->line !== null ? [$subject->line] : []);
            }
        }

        foreach ($this->groupLookups($analysis->lookups) as $group) {
            $model = $group['model'];
            $owned = false;
            $globalScope = false;
            $label = $model ?? ('table '.($group['table'] ?? 'unknown'));

            if ($model !== null) {
                $info = $this->models->inspect($model);
                $owned = $info->owned;
                $globalScope = $info->hasGlobalScope;
            } elseif ($group['table'] !== null) {
                $matched = null;

                foreach ($subject->boundModelClasses() as $bound) {
                    $info = $this->models->inspect($bound);

                    if ($info->table === $group['table']) {
                        $matched = $info;
                        break;
                    }
                }

                $matched ??= $this->models->forTable($group['table']);

                if ($matched !== null) {
                    $owned = $matched->owned;
                    $globalScope = $matched->hasGlobalScope;
                    $label = $matched->class.' (table '.$group['table'].')';
                }
            }

            if (! $owned) {
                continue;
            }

            if ($globalScope && ! $flagGlobalScopes) {
                $probe = $this->report($group['rule'], Severity::Low, $subject, $analysis, 'Suppressed lookup on a globally scoped model.', [], $group['lines']);

                $suppressed[] = ['finding' => $probe, 'reason' => 'global scope on '.$label];

                continue;
            }

            $severity = $group['rule'] === 'unscoped_collection'
                ? Severity::Medium
                : ($analysis->hasObjectCheck ? Severity::Low : Severity::Medium);

            $message = $group['rule'] === 'unscoped_collection'
                ? 'Collection query on an owned model shows no owner or tenant constraint.'
                : 'Lookup on an owned model is not scoped through the authenticated user.';

            $evidence = array_map(static fn (array $lookup): string => $lookup['expression'].' at line '.$lookup['line'], $group['items']);
            $evidence[] = 'model '.$label;

            if ($subject->scopedBindings) {
                $evidence[] = 'scoped bindings cover the injected parameter only, not this query';
            }

            $findings[] = $this->report($group['rule'], $severity, $subject, $analysis, $message, $evidence, $group['lines']);
        }

        return $findings;
    }

    /**
     * Group lookups by rule and target so one route reports each problem once.
     *
     * @param  list<array{rule: string, model: string|null, table: string|null, line: int, expression: string}>  $lookups
     * @return list<array{rule: string, model: string|null, table: string|null, lines: list<int>, items: list<array{rule: string, model: string|null, table: string|null, line: int, expression: string}>}>
     */
    private function groupLookups(array $lookups): array
    {
        $groups = [];

        foreach ($lookups as $lookup) {
            $key = $lookup['rule'].'|'.($lookup['model'] ?? $lookup['table'] ?? '');

            $groups[$key] ??= ['rule' => $lookup['rule'], 'model' => $lookup['model'], 'table' => $lookup['table'], 'lines' => [], 'items' => []];
            $groups[$key]['lines'][] = $lookup['line'];
            $groups[$key]['items'][] = $lookup;
        }

        return array_values($groups);
    }

    /**
     * Build a finding and the suggestion that belongs with it.
     *
     * @param  list<string>  $evidence
     * @param  list<int>  $lines
     */
    private function report(string $rule, Severity $severity, RouteSubject $subject, ActionAnalysis $analysis, string $message, array $evidence, array $lines): Finding
    {
        return new Finding(
            rule: $rule,
            severity: $severity,
            methods: $subject->methods,
            uri: $subject->uri,
            action: $subject->action,
            file: $subject->file !== null ? PhpFileIndex::relativePath($subject->file) : null,
            lines: $lines,
            message: $message,
            evidence: $evidence,
            suggestion: $this->suggester->make($rule, $subject, $analysis),
        );
    }

    /**
     * Sort writes first, then by severity, so the human report leads with destructive routes.
     *
     * @param  list<Finding>  $findings
     */
    private function sortFindings(array &$findings): void
    {
        $verbRank = static fn (array $methods): int => array_intersect($methods, ['DELETE', 'PUT', 'PATCH', 'POST']) !== [] ? 0 : 1;

        usort($findings, static function (Finding $left, Finding $right) use ($verbRank): int {
            $byVerb = $verbRank($left->methods) <=> $verbRank($right->methods);

            if ($byVerb !== 0) {
                return $byVerb;
            }

            $bySeverity = $right->severity->rank() <=> $left->severity->rank();

            return $bySeverity !== 0 ? $bySeverity : strcmp($left->uri, $right->uri);
        });
    }
}

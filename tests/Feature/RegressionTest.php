<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Artisan;
use Usamamuneerchaudhary\GatekeeperAudit\Tests\Fixtures\Models\Invoice;

/**
 * Regression tests for the false negatives, false positives, and CLI bugs fixed in 1.0.3.
 *
 * Every route lives under regressions/ in TestCase::defineRoutes().
 */

/**
 * Decoded JSON report for routes under one URI prefix.
 *
 * @return array<string, mixed>
 */
function regressionReport(string $only): array
{
    Artisan::call('gatekeeper:audit', ['--only' => $only, '--format' => 'json', '--no-fail' => true]);

    $report = json_decode(Artisan::output(), true);

    expect($report)->toBeArray();

    return $report;
}

/**
 * Rules reported for routes under one URI prefix.
 *
 * @return list<string>
 */
function regressionRules(string $only): array
{
    return array_values(array_map(static fn (array $finding): string => $finding['rule'], regressionReport($only)['findings']));
}

describe('FormRequest authorize()', function () {
    it('flags authorize() that only checks auth()->check()', function () {
        expect(regressionRules('regressions/signed-in'))->toContain('trivial_form_request');
    });

    it('flags authorize() that only checks the user is not null', function () {
        expect(regressionRules('regressions/not-null-user'))->toContain('trivial_form_request');
    });

    it('flags a signed-in guard clause followed by return true', function () {
        expect(regressionRules('regressions/guard-clause'))->toContain('trivial_form_request');
    });

    it('does not accept reading the route model without checking it', function () {
        expect(regressionRules('regressions/route-not-null'))->toContain('object_authorization');
    });

    it('does not accept route() with no argument as a route model check', function () {
        expect(regressionRules('regressions/route-name'))->toContain('object_authorization');
    });

    it('accepts the routed model read as $this->invoice', function () {
        expect(regressionRules('regressions/magic-property'))->toBe([]);
    });

    it('accepts comparing the route model owner with the signed-in user', function () {
        expect(regressionRules('regressions/owner-comparison'))->toBe([]);
    });
});

describe('ability results', function () {
    it('does not clear a route when the can() result is only passed to the response', function () {
        $report = regressionReport('regressions/unenforced-can');
        $finding = $report['findings'][0] ?? null;

        expect($finding['rule'] ?? null)->toBe('object_authorization')
            ->and(implode("\n", $finding['evidence']))->toContain('result is not used to allow or deny the request');
    });

    it('does not clear a route when the Gate::allows() result is discarded', function () {
        expect(regressionRules('regressions/discarded-gate'))->toContain('object_authorization');
    });

    it('accepts can() used as an if condition', function () {
        expect(regressionRules('regressions/enforced-if'))->toBe([]);
    });

    it('accepts can() passed to abort_unless', function () {
        expect(regressionRules('regressions/enforced-abort'))->toBe([]);
    });

    it('accepts Gate::inspect()->authorize()', function () {
        expect(regressionRules('regressions/inspect-authorize'))->toBe([]);
    });

    it('accepts a helper that returns the gate verdict', function () {
        expect(regressionRules('regressions/helper-verdict'))->toBe([]);
    });

    it('does not treat Auth::check() as authorization on a write route', function () {
        expect(regressionRules('regressions/auth-check-only'))->toContain('missing_authorization');
    });
});

describe('middleware and closures', function () {
    it('applies HasMiddleware only: to the listed methods', function () {
        $report = regressionReport('regressions/only-middleware');
        $methods = array_map(static fn (array $finding): string => implode('|', $finding['methods']), $report['findings']);

        expect($methods)->toBe(['DELETE']);
    });

    it('analyses an arrow function route instead of the enclosing group closure', function () {
        expect(regressionRules('closure-invoices'))->toContain('object_authorization')
            ->and(regressionRules('regressions/gated-closure'))->toBe([]);
    });
});

describe('lookups and writes', function () {
    it('flags Model::destroy() with a raw id', function () {
        expect(regressionRules('regressions/destroy-by-id'))->toContain('unscoped_lookup');
    });

    it('flags where(id)->update()', function () {
        expect(regressionRules('regressions/update-by-id'))->toContain('unscoped_lookup');
    });

    it('flags firstWhere() with a raw id', function () {
        expect(regressionRules('regressions/first-where-id'))->toContain('unscoped_lookup');
    });

    it('does not suppress lookups on a model because it uses SoftDeletes', function () {
        expect(regressionRules('regressions/soft-deleted'))->toContain('unscoped_lookup');
    });

    it('accepts where(user_id, Auth::id()) as scoped', function () {
        expect(regressionRules('regressions/auth-id-scoped'))->not->toContain('unscoped_lookup');
    });

    it('accepts an owner column compared with a variable that holds the signed-in user', function () {
        expect(regressionRules('regressions/local-user-scoped'))->not->toContain('unscoped_lookup');
    });

    it('accepts an owner column compared with a #[CurrentUser] parameter', function () {
        expect(regressionRules('regressions/current-user-scoped'))->not->toContain('unscoped_lookup');
    });

    it('does not accept a user() call in an unrelated constraint as scoping', function () {
        expect(regressionRules('regressions/user-in-other-column'))->toContain('unscoped_lookup');
    });

    it('does not accept an owner column compared with request input as scoping', function () {
        expect(regressionRules('regressions/owner-from-input'))->toContain('unscoped_lookup');
    });

    it('flags a DB::table() delete on an owned table with no route model', function () {
        config()->set('gatekeeper.ownership.models', [Invoice::class]);

        expect(regressionRules('regressions/table-delete'))->toContain('unscoped_lookup');
    });

    it('accepts a DB::table() query scoped through Auth::id()', function () {
        config()->set('gatekeeper.ownership.models', [Invoice::class]);

        expect(regressionRules('regressions/table-scoped-delete'))->not->toContain('unscoped_lookup');
    });
});

describe('reports', function () {
    it('prints evidence as source code', function () {
        $findings = array_values(array_filter(
            regressionReport('regressions/update-by-id')['findings'],
            static fn (array $finding): bool => $finding['rule'] === 'unscoped_lookup',
        ));
        $finding = $findings[0];

        expect($finding['evidence'][0])->toStartWith("Invoice::where('id', \$request->input('id'))->update(")
            ->and(json_encode($finding))->not->toContain('PhpParser');
    });

    it('reports files relative to the application base path', function () {
        app()->setBasePath((string) realpath(__DIR__.'/../..'));

        $finding = regressionReport('regressions/update-by-id')['findings'][0];

        expect($finding['file'])->toBe('support/Fixtures/Controllers/RegressionInvoiceController.php');
    });

    it('anchors SARIF results to the source root', function () {
        app()->setBasePath((string) realpath(__DIR__.'/../..'));

        Artisan::call('gatekeeper:audit', ['--only' => 'regressions/update-by-id', '--format' => 'sarif', '--no-fail' => true]);
        $location = json_decode(Artisan::output(), true)['runs'][0]['results'][0]['locations'][0]['physicalLocation']['artifactLocation'];

        expect($location)->toBe([
            'uri' => 'support/Fixtures/Controllers/RegressionInvoiceController.php',
            'uriBaseId' => '%SRCROOT%',
        ]);
    });

    it('does not percent-encode colons in GitHub annotation messages', function () {
        Artisan::call('gatekeeper:audit', ['--only' => 'regressions/update-by-id', '--format' => 'github', '--no-fail' => true]);
        $line = explode("\n", Artisan::output())[0];
        $message = substr($line, (int) strpos($line, '::', 2) + 2);

        expect($message)->toContain('POST regressions/update-by-id: ')
            ->and($message)->not->toContain('%3A');
    });
});

describe('command options', function () {
    it('fails on missing_authorization with --fail-on-unauthorized', function () {
        $exitCode = Artisan::call('gatekeeper:audit', ['--only' => 'regressions/auth-check-only', '--fail-on-unauthorized' => true]);

        expect($exitCode)->toBe(1);
    });

    it('refuses to prune the baseline when --only limits the audit', function () {
        $baseline = tempnam(sys_get_temp_dir(), 'gatekeeper-baseline-').'.json';
        file_put_contents($baseline, json_encode(['findings' => []]));

        try {
            $exitCode = Artisan::call('gatekeeper:audit', ['--only' => 'regressions', '--baseline' => $baseline, '--prune-baseline' => true]);

            expect($exitCode)->toBe(2);
        } finally {
            unlink($baseline);
        }
    });

    it('keeps baselined findings that still occur when pruning', function () {
        $baseline = tempnam(sys_get_temp_dir(), 'gatekeeper-baseline-').'.json';

        try {
            Artisan::call('gatekeeper:baseline', ['--path' => $baseline, '--only' => 'regressions/destroy-by-id']);
            $recorded = json_decode((string) file_get_contents($baseline), true)['findings'];

            $exitCode = Artisan::call('gatekeeper:audit', ['--baseline' => $baseline, '--prune-baseline' => true, '--no-fail' => true]);
            $pruned = json_decode((string) file_get_contents($baseline), true)['findings'];

            expect($exitCode)->toBe(0)
                ->and($recorded)->not->toBe([])
                ->and($pruned)->toBe($recorded);
        } finally {
            unlink($baseline);
        }
    });
});

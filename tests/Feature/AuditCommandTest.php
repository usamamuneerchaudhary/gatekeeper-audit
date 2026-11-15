<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Artisan;
use Symfony\Component\Console\Output\BufferedOutput;
use Symfony\Component\Console\Output\OutputInterface;
use Usamamuneerchaudhary\GatekeeperAudit\Tests\Fixtures\Models\Invoice;

/**
 * Run the audit command and return its exit code and output.
 *
 * @param  array<string, mixed>  $parameters
 * @return array{int, string}
 */
function runGatekeeperAudit(array $parameters = []): array
{
    $exitCode = Artisan::call('gatekeeper:audit', $parameters);

    return [$exitCode, Artisan::output()];
}

it('passes a route with an object-level authorize call', function () {
    [$exitCode, $output] = runGatekeeperAudit(['--only' => 'secure-invoices', '--fail-on' => 'high']);

    expect($exitCode)->toBe(0)
        ->and($output)->not->toContain('object_authorization');
});

it('flags an ungated object route and fails on high', function () {
    [$exitCode, $output] = runGatekeeperAudit(['--only' => 'ungated-invoices']);

    expect($exitCode)->toBe(1)
        ->and($output)->toContain('object_authorization')
        ->and($output)->toContain('ungated-invoices/{invoice}');
});

it('passes when can middleware targets the route parameter', function () {
    [$exitCode, $output] = runGatekeeperAudit(['--only' => 'can-invoices']);

    expect($exitCode)->toBe(0)
        ->and($output)->not->toContain('object_authorization');
});

it('does not pass a route gated only by a role', function () {
    [$exitCode, $output] = runGatekeeperAudit(['--only' => 'role-invoices']);

    expect($exitCode)->toBe(1)
        ->and($output)->toContain('object_authorization')
        ->and($output)->toContain('role:admin');
});

it('does not pass a route gated by a class-level can check', function () {
    [$exitCode, $output] = runGatekeeperAudit(['--only' => 'class-can-invoices']);

    expect($exitCode)->toBe(1)
        ->and($output)->toContain('object_authorization');
});

it('passes a route covered by authorizeResource', function () {
    [$exitCode, $output] = runGatekeeperAudit(['--only' => 'resource-invoices']);

    expect($exitCode)->toBe(0)
        ->and($output)->not->toContain('object_authorization');
});

it('flags a return true FormRequest authorize', function () {
    [$exitCode, $output] = runGatekeeperAudit(['--only' => 'form-invoices']);

    expect($exitCode)->toBe(1)
        ->and($output)->toContain('trivial_form_request');
});

it('passes a FormRequest that checks the routed model', function () {
    [$exitCode, $output] = runGatekeeperAudit(['--only' => 'secure-form-invoices']);

    expect($exitCode)->toBe(0)
        ->and($output)->not->toContain('trivial_form_request')
        ->and($output)->not->toContain('object_authorization');
});

it('flags an inherited return true FormRequest authorize', function () {
    [$exitCode, $output] = runGatekeeperAudit(['--only' => 'inherited-form-invoices']);

    expect($exitCode)->toBe(1)
        ->and($output)->toContain('trivial_form_request');
});

it('flags a policy that only returns true', function () {
    [$exitCode, $output] = runGatekeeperAudit(['--only' => 'policy-invoices']);

    expect($exitCode)->toBe(1)
        ->and($output)->toContain('trivial_policy');
});

it('does not flag a lookup scoped through the user relation', function () {
    [, $output] = runGatekeeperAudit(['--only' => 'scoped-invoices', '--no-fail' => true]);

    expect($output)->not->toContain('unscoped_lookup');
});

it('flags a raw findOrFail on an owned model as low when an object check exists', function () {
    [$exitCode, $output] = runGatekeeperAudit(['--only' => 'secure-invoices', '--fail-on' => 'low']);

    expect($exitCode)->toBe(1)
        ->and($output)->toContain('unscoped_lookup')
        ->and($output)->toContain('[LOW]');
});

it('suppresses raw lookups on a globally scoped model', function () {
    [, $output] = runGatekeeperAudit(['--only' => 'global-invoices', '--no-fail' => true]);

    expect($output)->not->toContain('unscoped_lookup')
        ->and($output)->toContain('1 suppressed');
});

it('flags a second raw lookup even with scoped bindings', function () {
    [, $output] = runGatekeeperAudit(['--only' => 'bound-invoices', '--no-fail' => true]);

    expect($output)->toContain('unscoped_lookup')
        ->and($output)->toContain('scoped bindings cover the injected parameter only');
});

it('flags an unscoped collection query on an owned model', function () {
    [$exitCode, $output] = runGatekeeperAudit(['--only' => 'invoice-collection', '--fail-on' => 'medium']);

    expect($exitCode)->toBe(1)
        ->and($output)->toContain('unscoped_collection');
});

it('flags a state-changing route with no authorization at all', function () {
    [$exitCode, $output] = runGatekeeperAudit(['--only' => 'stores', '--fail-on' => 'medium']);

    expect($exitCode)->toBe(1)
        ->and($output)->toContain('missing_authorization');
});

it('still flags an unowned object route for authorization but not for scoping', function () {
    [, $output] = runGatekeeperAudit(['--only' => 'product', '--no-fail' => true]);

    expect($output)->toContain('object_authorization')
        ->and($output)->not->toContain('unscoped_lookup');
});

it('stays silent on scoping for models on the ownership ignore list', function () {
    config(['gatekeeper.ownership.ignore_models' => [Invoice::class]]);

    [, $output] = runGatekeeperAudit(['--only' => 'secure-invoices', '--no-fail' => true]);

    expect($output)->not->toContain('unscoped_lookup');
});

it('audits closure routes', function () {
    [$exitCode, $output] = runGatekeeperAudit(['--only' => 'closure-invoices']);

    expect($exitCode)->toBe(1)
        ->and($output)->toContain('object_authorization')
        ->and($output)->toContain('Closure');
});

it('skips public routes by default and audits them on request', function () {
    [, $output] = runGatekeeperAudit(['--only' => 'public-invoices', '--no-fail' => true]);

    expect($output)->not->toContain('object_authorization')
        ->and($output)->toContain('1 skipped');

    [$exitCode, $included] = runGatekeeperAudit(['--only' => 'public-invoices', '--include-public' => true]);

    expect($exitCode)->toBe(1)
        ->and($included)->toContain('object_authorization');
});

it('flags a DB table lookup on an owned model table', function () {
    [, $output] = runGatekeeperAudit(['--only' => 'db-invoices', '--no-fail' => true]);

    expect($output)->toContain('unscoped_lookup')
        ->and($output)->toContain('table invoices');
});

it('explains passes and skips in verbose mode', function () {
    $output = new BufferedOutput(OutputInterface::VERBOSITY_VERBOSE);

    Artisan::call('gatekeeper:audit', ['--only' => 'can-invoices', '--no-fail' => true], $output);

    expect($output->fetch())->toContain('[pass]')
        ->toContain('can-invoices/{invoice}');
});

it('emits the versioned JSON report', function () {
    [$exitCode, $output] = runGatekeeperAudit(['--only' => 'ungated-invoices', '--format' => 'json']);

    $report = json_decode($output, true);

    expect($exitCode)->toBe(1)
        ->and($report['version'])->toBe('gatekeeper.report.v1')
        ->and($report['findings'][0]['rule'])->toBe('object_authorization')
        ->and($report['findings'][0]['id'])->toContain('object_authorization:')
        ->and($report['summary']['audited'])->toBe(2);
});

it('emits github workflow commands and sarif', function () {
    [, $github] = runGatekeeperAudit(['--only' => 'ungated-invoices', '--format' => 'github', '--no-fail' => true]);

    expect($github)->toContain('::error');

    [, $sarifOutput] = runGatekeeperAudit(['--only' => 'ungated-invoices', '--format' => 'sarif', '--no-fail' => true]);
    $sarif = json_decode($sarifOutput, true);

    expect($sarif['version'])->toBe('2.1.0')
        ->and($sarif['runs'][0]['results'][0]['ruleId'])->toBe('object_authorization');
});

it('returns exit code 2 for an unknown format', function () {
    [$exitCode] = runGatekeeperAudit(['--format' => 'yaml']);

    expect($exitCode)->toBe(2);
});

it('fails on medium scoping findings with the unauthorized alias', function () {
    [$exitCode] = runGatekeeperAudit(['--only' => 'invoice-collection', '--fail-on-unauthorized' => true]);

    expect($exitCode)->toBe(1);
});

it('suppresses baselined findings and still fails on new ones', function () {
    $baseline = tempnam(sys_get_temp_dir(), 'gatekeeper-baseline-').'.json';

    try {
        $writeExit = Artisan::call('gatekeeper:baseline', ['--path' => $baseline, '--only' => 'ungated-invoices']);

        expect($writeExit)->toBe(0)
            ->and(is_file($baseline))->toBeTrue();

        [$exitCode, $output] = runGatekeeperAudit(['--only' => 'ungated-invoices', '--baseline' => $baseline]);

        expect($exitCode)->toBe(0)
            ->and($output)->toContain('suppressed');

        [$newExit] = runGatekeeperAudit(['--only' => 'role-invoices', '--baseline' => $baseline]);

        expect($newExit)->toBe(1);
    } finally {
        if (is_file($baseline)) {
            unlink($baseline);
        }
    }
});

it('prunes stale baseline ids', function () {
    $baseline = tempnam(sys_get_temp_dir(), 'gatekeeper-baseline-').'.json';
    file_put_contents($baseline, json_encode(['findings' => [['id' => 'object_authorization:GET:gone/{id}:Gone@show']]]));

    try {
        [$exitCode] = runGatekeeperAudit(['--only' => 'can-invoices', '--baseline' => $baseline, '--prune-baseline' => true, '--no-fail' => true]);

        $written = json_decode((string) file_get_contents($baseline), true);

        expect($exitCode)->toBe(0)
            ->and($written['version'])->toBe('gatekeeper.baseline.v1')
            ->and($written['findings'])->toBe([]);
    } finally {
        if (is_file($baseline)) {
            unlink($baseline);
        }
    }
});

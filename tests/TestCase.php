<?php

declare(strict_types=1);

namespace Usamamuneerchaudhary\GatekeeperAudit\Tests;

use Illuminate\Routing\Router;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Facades\Route;
use Orchestra\Testbench\TestCase as Orchestra;
use Usamamuneerchaudhary\GatekeeperAudit\GatekeeperServiceProvider;
use Usamamuneerchaudhary\GatekeeperAudit\Tests\Fixtures\Controllers\FormInvoiceController;
use Usamamuneerchaudhary\GatekeeperAudit\Tests\Fixtures\Controllers\OneLineInvoiceController;
use Usamamuneerchaudhary\GatekeeperAudit\Tests\Fixtures\Controllers\OnlyMiddlewareInvoiceController;
use Usamamuneerchaudhary\GatekeeperAudit\Tests\Fixtures\Controllers\PolicyInvoiceController;
use Usamamuneerchaudhary\GatekeeperAudit\Tests\Fixtures\Controllers\RegressionInvoiceController;
use Usamamuneerchaudhary\GatekeeperAudit\Tests\Fixtures\Controllers\ResourceInvoiceController;
use Usamamuneerchaudhary\GatekeeperAudit\Tests\Fixtures\Controllers\ScopedInvoiceController;
use Usamamuneerchaudhary\GatekeeperAudit\Tests\Fixtures\Controllers\SecureInvoiceController;
use Usamamuneerchaudhary\GatekeeperAudit\Tests\Fixtures\Controllers\StoreInvoiceController;
use Usamamuneerchaudhary\GatekeeperAudit\Tests\Fixtures\Controllers\UngatedInvoiceController;
use Usamamuneerchaudhary\GatekeeperAudit\Tests\Fixtures\Models\Invoice;

class TestCase extends Orchestra
{
    /**
     * Register the package provider for every test.
     *
     * @param  mixed  $app
     * @return list<class-string>
     */
    protected function getPackageProviders($app): array
    {
        return [GatekeeperServiceProvider::class];
    }

    /**
     * Register the fixture routes that exercise each rule.
     */
    protected function defineRoutes($router): void
    {
        $router->middleware('auth')->group(function (Router $router): void {
            $router->get('secure-invoices/{invoice}', [SecureInvoiceController::class, 'show']);
            $router->put('secure-invoices/{invoice}', [SecureInvoiceController::class, 'update']);
            $router->get('ungated-invoices/{invoice}', [UngatedInvoiceController::class, 'show']);
            $router->delete('ungated-invoices/{invoice}', [UngatedInvoiceController::class, 'destroy']);
            $router->get('can-invoices/{invoice}', [UngatedInvoiceController::class, 'show'])->middleware('can:view,invoice');
            $router->get('role-invoices/{invoice}', [UngatedInvoiceController::class, 'show'])->middleware('role:admin');
            $router->get('class-can-invoices/{invoice}', [UngatedInvoiceController::class, 'show'])->middleware('can:view,'.Invoice::class);
            $router->get('resource-invoices/{invoice}', [ResourceInvoiceController::class, 'show']);
            $router->put('form-invoices/{invoice}', [FormInvoiceController::class, 'update']);
            $router->put('secure-form-invoices/{invoice}', [FormInvoiceController::class, 'secure']);
            $router->put('inherited-form-invoices/{invoice}', [FormInvoiceController::class, 'inherited']);
            $router->get('scoped-invoices/{invoice}', [ScopedInvoiceController::class, 'show']);
            $router->get('global-invoices/{invoice}', [ScopedInvoiceController::class, 'global']);
            $router->get('bound-invoices/{invoice}', [ScopedInvoiceController::class, 'bound'])->scopeBindings();
            $router->get('invoice-collection', [ScopedInvoiceController::class, 'index']);
            $router->get('assigned-invoices/{invoice}', [ScopedInvoiceController::class, 'assigned']);
            $router->get('wrapped-invoices/{invoice}', [ScopedInvoiceController::class, 'wrapped']);
            $router->get('db-invoices/{invoice}', [ScopedInvoiceController::class, 'dbLookup']);
            $router->put('policy-invoices/{policyInvoice}', [PolicyInvoiceController::class, 'update']);
            $router->get('line-invoices/{invoice}', [OneLineInvoiceController::class, 'touch']);
            $router->post('stores', [StoreInvoiceController::class, 'store']);
            $router->get('products/{product}', [StoreInvoiceController::class, 'product']);
            $router->get('product-lookups/{product}', [StoreInvoiceController::class, 'productLookup']);
            $router->get('closure-invoices/{invoice}', static fn (Invoice $invoice): Invoice => $invoice);
            $router->get('block-invoices/{invoice}', function (Invoice $invoice) {
                return $invoice;
            });

            // 1.0.3 regressions. A sibling closure with a gate call must not clear the arrow function above.
            $router->get('regressions/gated-closure/{invoice}', function (Invoice $invoice) {
                Gate::authorize('view', $invoice);

                return $invoice;
            });

            $regressions = [
                ['put', 'regressions/signed-in/{invoice}', 'signedIn'],
                ['put', 'regressions/not-null-user/{invoice}', 'notNullUser'],
                ['put', 'regressions/guard-clause/{invoice}', 'guardClause'],
                ['put', 'regressions/route-not-null/{invoice}', 'routeNotNull'],
                ['put', 'regressions/route-name/{invoice}', 'routeName'],
                ['put', 'regressions/magic-property/{invoice}', 'magicProperty'],
                ['put', 'regressions/owner-comparison/{invoice}', 'ownerComparison'],
                ['get', 'regressions/unenforced-can/{invoice}', 'unenforcedCan'],
                ['put', 'regressions/discarded-gate/{invoice}', 'discardedGate'],
                ['put', 'regressions/enforced-if/{invoice}', 'enforcedIf'],
                ['get', 'regressions/enforced-abort/{invoice}', 'enforcedAbort'],
                ['get', 'regressions/inspect-authorize/{invoice}', 'inspectAuthorize'],
                ['get', 'regressions/helper-verdict/{invoice}', 'helperVerdict'],
                ['post', 'regressions/auth-check-only', 'authCheckOnly'],
                ['post', 'regressions/destroy-by-id', 'destroyById'],
                ['post', 'regressions/update-by-id', 'updateById'],
                ['get', 'regressions/first-where-id', 'firstWhereId'],
                ['get', 'regressions/soft-deleted', 'softDeleted'],
                ['get', 'regressions/auth-id-scoped', 'authIdScoped'],
                ['get', 'regressions/user-in-other-column', 'userInOtherColumn'],
                ['get', 'regressions/owner-from-input', 'ownerFromInput'],
                ['post', 'regressions/table-delete', 'tableDelete'],
                ['post', 'regressions/table-scoped-delete', 'tableScopedDelete'],
                ['get', 'regressions/local-user-scoped', 'localUserScoped'],
                ['get', 'regressions/current-user-scoped', 'currentUserScoped'],
            ];

            foreach ($regressions as [$verb, $uri, $action]) {
                $router->{$verb}($uri, [RegressionInvoiceController::class, $action]);
            }

            $router->put('regressions/only-middleware/{invoice}', [OnlyMiddlewareInvoiceController::class, 'update']);
            $router->delete('regressions/only-middleware/{invoice}', [OnlyMiddlewareInvoiceController::class, 'destroy']);
        });

        Route::get('public-invoices/{invoice}', [UngatedInvoiceController::class, 'show']);
    }
}

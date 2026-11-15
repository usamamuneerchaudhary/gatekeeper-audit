<?php

declare(strict_types=1);

namespace Usamamuneerchaudhary\GatekeeperAudit\Tests;

use Illuminate\Routing\Router;
use Illuminate\Support\Facades\Route;
use Orchestra\Testbench\TestCase as Orchestra;
use Usamamuneerchaudhary\GatekeeperAudit\GatekeeperServiceProvider;
use Usamamuneerchaudhary\GatekeeperAudit\Tests\Support\Fixtures\Controllers\FormInvoiceController;
use Usamamuneerchaudhary\GatekeeperAudit\Tests\Support\Fixtures\Controllers\PolicyInvoiceController;
use Usamamuneerchaudhary\GatekeeperAudit\Tests\Support\Fixtures\Controllers\ResourceInvoiceController;
use Usamamuneerchaudhary\GatekeeperAudit\Tests\Support\Fixtures\Controllers\ScopedInvoiceController;
use Usamamuneerchaudhary\GatekeeperAudit\Tests\Support\Fixtures\Controllers\SecureInvoiceController;
use Usamamuneerchaudhary\GatekeeperAudit\Tests\Support\Fixtures\Controllers\StoreInvoiceController;
use Usamamuneerchaudhary\GatekeeperAudit\Tests\Support\Fixtures\Controllers\UngatedInvoiceController;
use Usamamuneerchaudhary\GatekeeperAudit\Tests\Support\Fixtures\Models\Invoice;

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
            $router->get('db-invoices/{invoice}', [ScopedInvoiceController::class, 'dbLookup']);
            $router->put('policy-invoices/{policyInvoice}', [PolicyInvoiceController::class, 'update']);
            $router->post('stores', [StoreInvoiceController::class, 'store']);
            $router->get('products/{product}', [StoreInvoiceController::class, 'product']);
            $router->get('product-lookups/{product}', [StoreInvoiceController::class, 'productLookup']);
            $router->get('closure-invoices/{invoice}', static fn (Invoice $invoice): Invoice => $invoice);
        });

        Route::get('public-invoices/{invoice}', [UngatedInvoiceController::class, 'show']);
    }
}

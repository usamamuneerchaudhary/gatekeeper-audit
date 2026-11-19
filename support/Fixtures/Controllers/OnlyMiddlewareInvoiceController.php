<?php

declare(strict_types=1);

namespace Usamamuneerchaudhary\GatekeeperAudit\Tests\Fixtures\Controllers;

use Illuminate\Routing\Controllers\HasMiddleware;
use Illuminate\Routing\Controllers\Middleware;
use Usamamuneerchaudhary\GatekeeperAudit\Tests\Fixtures\Models\Invoice;

class OnlyMiddlewareInvoiceController implements HasMiddleware
{
    /**
     * Object-level middleware that applies to update only.
     *
     * @return list<Middleware>
     */
    public static function middleware(): array
    {
        return [new Middleware('can:update,invoice', only: ['update'])];
    }

    /**
     * Covered by the can middleware.
     */
    public function update(Invoice $invoice): Invoice
    {
        return $invoice;
    }

    /**
     * Not covered: the middleware is limited to update.
     */
    public function destroy(Invoice $invoice): Invoice
    {
        return $invoice;
    }
}

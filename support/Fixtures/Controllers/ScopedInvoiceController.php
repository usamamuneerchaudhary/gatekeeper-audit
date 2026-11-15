<?php

declare(strict_types=1);

namespace Usamamuneerchaudhary\GatekeeperAudit\Tests\Fixtures\Controllers;

use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\DB;
use Usamamuneerchaudhary\GatekeeperAudit\Tests\Fixtures\Models\GlobalInvoice;
use Usamamuneerchaudhary\GatekeeperAudit\Tests\Fixtures\Models\Invoice;

class ScopedInvoiceController extends Controller
{
    /**
     * Load an invoice through the authenticated user relation.
     */
    public function show(Request $request, int $invoice): mixed
    {
        return $request->user()->invoices()->findOrFail($invoice);
    }

    /**
     * Load a globally scoped invoice by raw id.
     */
    public function global(GlobalInvoice $invoice): ?GlobalInvoice
    {
        return GlobalInvoice::findOrFail($invoice->id);
    }

    /**
     * Ignore the scoped injected invoice and reload by raw id.
     */
    public function bound(Invoice $invoice): ?Invoice
    {
        return Invoice::findOrFail($invoice->id);
    }

    /**
     * Load an invoice row through the query builder by raw id.
     */
    public function dbLookup(Invoice $invoice): mixed
    {
        return DB::table('invoices')->find($invoice->id);
    }

    /**
     * List every invoice without an owner constraint.
     */
    public function index(): mixed
    {
        return Invoice::query()->get();
    }

    /**
     * Assign a raw lookup before returning it.
     */
    public function assigned(Invoice $invoice): ?Invoice
    {
        $found = Invoice::findOrFail($invoice->id);

        return $found;
    }

    /**
     * Load an invoice through a query that spans more than one line.
     */
    public function wrapped(Invoice $invoice): ?Invoice
    {
        return Invoice::query()
            ->findOrFail($invoice->id);
    }
}

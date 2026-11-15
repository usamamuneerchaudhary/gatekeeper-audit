<?php

declare(strict_types=1);

namespace Usamamuneerchaudhary\GatekeeperAudit\Tests\Fixtures\Controllers;

use Illuminate\Routing\Controller;
use Usamamuneerchaudhary\GatekeeperAudit\Tests\Fixtures\Models\Invoice;

class UngatedInvoiceController extends Controller
{
    /**
     * Show any invoice without a check.
     */
    public function show(Invoice $invoice): Invoice
    {
        return $invoice;
    }

    /**
     * Delete any invoice without a check.
     */
    public function destroy(Invoice $invoice): ?Invoice
    {
        return Invoice::findOrFail($invoice->id);
    }
}

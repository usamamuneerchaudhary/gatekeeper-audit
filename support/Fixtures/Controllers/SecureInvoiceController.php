<?php

declare(strict_types=1);

namespace Usamamuneerchaudhary\GatekeeperAudit\Tests\Fixtures\Controllers;

use Illuminate\Foundation\Auth\Access\AuthorizesRequests;
use Illuminate\Routing\Controller;
use Usamamuneerchaudhary\GatekeeperAudit\Tests\Fixtures\Models\Invoice;

class SecureInvoiceController extends Controller
{
    use AuthorizesRequests;

    /**
     * Show an invoice after an object-level check.
     */
    public function show(Invoice $invoice): Invoice
    {
        $this->authorize('view', $invoice);

        return $invoice;
    }

    /**
     * Update an invoice after an object-level check, then reload it unscoped.
     */
    public function update(Invoice $invoice): ?Invoice
    {
        $this->authorize('update', $invoice);

        return Invoice::findOrFail($invoice->id);
    }
}

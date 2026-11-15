<?php

declare(strict_types=1);

namespace Usamamuneerchaudhary\GatekeeperAudit\Tests\Support\Fixtures\Controllers;

use Illuminate\Routing\Controller;
use Usamamuneerchaudhary\GatekeeperAudit\Tests\Fixtures\Models\Invoice;
use Usamamuneerchaudhary\GatekeeperAudit\Tests\Fixtures\Requests\InheritedUpdateInvoiceRequest;
use Usamamuneerchaudhary\GatekeeperAudit\Tests\Fixtures\Requests\SecureUpdateInvoiceRequest;
use Usamamuneerchaudhary\GatekeeperAudit\Tests\Fixtures\Requests\UpdateInvoiceRequest;

class FormInvoiceController extends Controller
{
    /**
     * Update relying on a trivial FormRequest.
     */
    public function update(UpdateInvoiceRequest $request, Invoice $invoice): Invoice
    {
        return $invoice;
    }

    /**
     * Update relying on a FormRequest that checks the routed invoice.
     */
    public function secure(SecureUpdateInvoiceRequest $request, Invoice $invoice): Invoice
    {
        return $invoice;
    }

    /**
     * Update relying on an inherited trivial FormRequest.
     */
    public function inherited(InheritedUpdateInvoiceRequest $request, Invoice $invoice): Invoice
    {
        return $invoice;
    }
}

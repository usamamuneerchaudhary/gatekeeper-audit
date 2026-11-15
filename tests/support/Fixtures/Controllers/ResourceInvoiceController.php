<?php

declare(strict_types=1);

namespace Usamamuneerchaudhary\GatekeeperAudit\Tests\Support\Fixtures\Controllers;

use Illuminate\Foundation\Auth\Access\AuthorizesRequests;
use Illuminate\Routing\Controller;
use Usamamuneerchaudhary\GatekeeperAudit\Tests\Fixtures\Models\Invoice;

class ResourceInvoiceController extends Controller
{
    use AuthorizesRequests;

    /**
     * Register conventional resource authorization.
     */
    public function __construct()
    {
        $this->authorizeResource(Invoice::class, 'invoice');
    }

    /**
     * Show an invoice covered by authorizeResource.
     */
    public function show(Invoice $invoice): Invoice
    {
        return $invoice;
    }
}

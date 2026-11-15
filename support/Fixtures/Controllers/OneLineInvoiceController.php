<?php

declare(strict_types=1);

namespace Usamamuneerchaudhary\GatekeeperAudit\Tests\Fixtures\Controllers;

use Illuminate\Routing\Controller;
use Usamamuneerchaudhary\GatekeeperAudit\Tests\Fixtures\Models\Invoice;

class OneLineInvoiceController extends Controller
{
    /**
     * Touch an invoice in a single line so the suggestion must stay inside the method.
     */
    public function touch(Invoice $invoice): Invoice { return $invoice; }
}

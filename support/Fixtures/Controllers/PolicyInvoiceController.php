<?php

declare(strict_types=1);

namespace Usamamuneerchaudhary\GatekeeperAudit\Tests\Fixtures\Controllers;

use Illuminate\Foundation\Auth\Access\AuthorizesRequests;
use Illuminate\Routing\Controller;
use Usamamuneerchaudhary\GatekeeperAudit\Tests\Fixtures\Models\PolicyInvoice;

class PolicyInvoiceController extends Controller
{
    use AuthorizesRequests;

    /**
     * Update through a policy that always returns true.
     */
    public function update(PolicyInvoice $policyInvoice): PolicyInvoice
    {
        $this->authorize('update', $policyInvoice);

        return $policyInvoice;
    }
}

<?php

declare(strict_types=1);

namespace Usamamuneerchaudhary\GatekeeperAudit\Tests\Support\Fixtures\Policies;

use Usamamuneerchaudhary\GatekeeperAudit\Tests\Support\Fixtures\Models\PolicyInvoice;
use Usamamuneerchaudhary\GatekeeperAudit\Tests\Support\Fixtures\Models\User;

class PolicyInvoicePolicy
{
    /**
     * Broken policy that allows everyone.
     */
    public function update(User $user, PolicyInvoice $invoice): bool
    {
        return true;
    }
}

<?php

declare(strict_types=1);

namespace Usamamuneerchaudhary\GatekeeperAudit\Tests\Fixtures\Policies;

use Usamamuneerchaudhary\GatekeeperAudit\Tests\Fixtures\Models\PolicyInvoice;
use Usamamuneerchaudhary\GatekeeperAudit\Tests\Fixtures\Models\User;

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

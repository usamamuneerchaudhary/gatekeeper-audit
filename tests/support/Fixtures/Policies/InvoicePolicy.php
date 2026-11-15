<?php

declare(strict_types=1);

namespace Usamamuneerchaudhary\GatekeeperAudit\Tests\Support\Fixtures\Policies;

use Usamamuneerchaudhary\GatekeeperAudit\Tests\Fixtures\Models\Invoice;
use Usamamuneerchaudhary\GatekeeperAudit\Tests\Fixtures\Models\User;

class InvoicePolicy
{
    /**
     * Only the owner may update an invoice.
     */
    public function update(User $user, Invoice $invoice): bool
    {
        return $user->id === $invoice->user_id;
    }

    /**
     * Only the owner may view an invoice.
     */
    public function view(User $user, Invoice $invoice): bool
    {
        return $user->id === $invoice->user_id;
    }
}

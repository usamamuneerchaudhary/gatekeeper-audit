<?php

declare(strict_types=1);

namespace Usamamuneerchaudhary\GatekeeperAudit\Tests\Support\Fixtures\Requests;

use Illuminate\Foundation\Http\FormRequest;

class SecureUpdateInvoiceRequest extends FormRequest
{
    /**
     * Check the routed invoice against the current user.
     */
    public function authorize(): bool
    {
        return $this->user()?->can('update', $this->route('invoice')) ?? false;
    }
}

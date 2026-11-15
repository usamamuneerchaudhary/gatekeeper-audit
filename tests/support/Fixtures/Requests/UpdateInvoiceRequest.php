<?php

declare(strict_types=1);

namespace Usamamuneerchaudhary\GatekeeperAudit\Tests\Support\Fixtures\Requests;

use Illuminate\Foundation\Http\FormRequest;

class UpdateInvoiceRequest extends FormRequest
{
    /**
     * Trivial authorization that checks nothing.
     */
    public function authorize(): bool
    {
        return true;
    }
}

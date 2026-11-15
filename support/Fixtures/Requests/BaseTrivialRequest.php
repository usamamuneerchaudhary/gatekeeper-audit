<?php

declare(strict_types=1);

namespace Usamamuneerchaudhary\GatekeeperAudit\Tests\Fixtures\Requests;

use Illuminate\Foundation\Http\FormRequest;

class BaseTrivialRequest extends FormRequest
{
    /**
     * Inherited trivial authorization.
     */
    public function authorize(): bool
    {
        return true;
    }
}

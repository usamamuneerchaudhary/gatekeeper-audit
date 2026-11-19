<?php

declare(strict_types=1);

namespace Usamamuneerchaudhary\GatekeeperAudit\Tests\Fixtures\Requests;

use Illuminate\Foundation\Http\FormRequest;

class OwnerComparisonRequest extends FormRequest
{
    /**
     * Regression fixture for 1.0.3.
     */
    public function authorize(): bool
    {
        return $this->route('invoice')?->user_id === $this->user()?->id;
    }
}

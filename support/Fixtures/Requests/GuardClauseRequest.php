<?php

declare(strict_types=1);

namespace Usamamuneerchaudhary\GatekeeperAudit\Tests\Fixtures\Requests;

use Illuminate\Foundation\Http\FormRequest;

class GuardClauseRequest extends FormRequest
{
    /**
     * Regression fixture for 1.0.3.
     */
    public function authorize(): bool
    {
        if (! $this->user()) {
            return false;
        }

        return true;
    }
}

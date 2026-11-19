<?php

declare(strict_types=1);

namespace Usamamuneerchaudhary\GatekeeperAudit\Tests\Fixtures\Requests;

use Illuminate\Foundation\Http\FormRequest;

class RouteNotNullRequest extends FormRequest
{
    /**
     * Regression fixture for 1.0.3.
     */
    public function authorize(): bool
    {
        return $this->route('invoice') !== null;
    }
}

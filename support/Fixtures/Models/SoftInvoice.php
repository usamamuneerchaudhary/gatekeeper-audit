<?php

declare(strict_types=1);

namespace Usamamuneerchaudhary\GatekeeperAudit\Tests\Fixtures\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\SoftDeletes;

class SoftInvoice extends Model
{
    use SoftDeletes;

    protected $table = 'soft_invoices';

    /**
     * Owner of this invoice.
     */
    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }
}

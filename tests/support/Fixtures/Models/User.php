<?php

declare(strict_types=1);

namespace Usamamuneerchaudhary\GatekeeperAudit\Tests\Support\Fixtures\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;

class User extends Model
{
    protected $table = 'users';

    /**
     * Invoices owned by this user.
     */
    public function invoices(): HasMany
    {
        return $this->hasMany(Invoice::class);
    }
}

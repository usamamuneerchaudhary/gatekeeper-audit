<?php

declare(strict_types=1);

namespace Usamamuneerchaudhary\GatekeeperAudit\Tests\Fixtures\Controllers;

use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Usamamuneerchaudhary\GatekeeperAudit\Tests\Fixtures\Models\Product;

class StoreInvoiceController extends Controller
{
    /**
     * Create a record with no authorization at all.
     */
    public function store(Request $request): array
    {
        return ['created' => true];
    }

    /**
     * Show an unowned product without a check.
     */
    public function product(Product $product): Product
    {
        return $product;
    }

    /**
     * Reload an unowned product by raw id.
     */
    public function productLookup(Product $product): ?Product
    {
        return Product::findOrFail($product->id);
    }
}

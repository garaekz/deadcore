<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;

class Order extends Model
{
    /**
     * Get the products that belong to this order.
     */
    public function products(): BelongsToMany
    {
        return $this->belongsToMany(Product::class)
            ->withPivot('quantity', 'unit_price', 'discount_amount', 'tax_amount')
            ->withTimestamps()
            ->as('order_item');
    }

    /**
     * Get promotional codes applied to this order.
     */
    public function promoCodes(): BelongsToMany
    {
        return $this->belongsToMany(PromoCode::class, 'order_promo_code')
            ->withPivot('discount_applied', 'applied_at')
            ->as('promotion');
    }

    /**
     * Get shipping methods available for this order.
     */
    public function shippingMethods(): BelongsToMany
    {
        $relation = $this->belongsToMany(ShippingMethod::class);
        
        return $relation
            ->withPivot('cost', 'estimated_days', 'tracking_number')
            ->withTimestamps();
    }

    /**
     * Get payment methods used for this order.
     */
    public function paymentMethods(): BelongsToMany
    {
        return $this->belongsToMany(PaymentMethod::class)
            ->withPivot(['amount', 'transaction_id', 'processed_at'])
            ->as('payment')
            ->withTimestamps();
    }
}
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Casts\Attribute;

/**
 * Test fixture for Laravel model attribute casting
 * Demonstrates various cast types and their usage patterns.
 */
class Order extends Model
{
    protected $fillable = [
        'user_id', 'total', 'status', 'items', 'metadata', 
        'shipped_at', 'is_paid', 'discount_percentage'
    ];

    /**
     * Basic type casting for automatic conversion.
     * Laravel automatically handles these transformations.
     */
    protected $casts = [
        // Date/time casting
        'shipped_at' => 'datetime',
        'created_at' => 'datetime',
        'updated_at' => 'datetime',
        
        // Boolean casting
        'is_paid' => 'boolean',
        'is_shipped' => 'boolean',
        'is_cancelled' => 'boolean',
        
        // Numeric casting
        'total' => 'decimal:2',
        'discount_percentage' => 'float',
        'tax_rate' => 'double',
        
        // JSON casting for complex data
        'items' => 'array',
        'metadata' => 'json',
        'shipping_address' => 'object',
        
        // Collection casting
        'tags' => 'collection',
        
        // Encrypted casting for sensitive data
        'notes' => 'encrypted',
        'internal_comments' => 'encrypted:array',
        
        // Custom casting
        'status' => OrderStatus::class,
        'priority' => PriorityLevel::class,
    ];

    /**
     * Example of combining casts with modern attributes.
     * Shows how casting and attribute accessors can work together.
     */
    public function formattedTotal(): Attribute
    {
        return Attribute::make(
            get: fn ($value, $attributes) => '$' . number_format($attributes['total'], 2)
        );
    }

    /**
     * Date attribute combining cast with accessor logic.
     * Leverages automatic datetime casting with additional formatting.
     */
    public function shippedAtFormatted(): Attribute
    {
        return Attribute::make(
            get: fn ($value, $attributes) => $attributes['shipped_at']?->format('M j, Y g:i A')
        );
    }

    /**
     * Complex JSON attribute with validation.
     * Uses array casting with additional business logic.
     */
    public function validatedItems(): Attribute
    {
        return Attribute::make(
            get: function ($value, $attributes) {
                $items = $attributes['items'] ?? [];
                return array_filter($items, fn ($item) => isset($item['id'], $item['quantity']));
            }
        );
    }

    /**
     * Boolean attribute with custom logic.
     * Combines boolean casting with business rules.
     */
    public function canBeCancelled(): Attribute
    {
        return Attribute::make(
            get: fn ($value, $attributes) => 
                !$attributes['is_shipped'] && 
                !$attributes['is_cancelled'] &&
                $attributes['created_at']->diffInHours() < 24
        );
    }
}

/**
 * Example custom cast class for order status.
 * Demonstrates how custom casts integrate with attribute detection.
 */
enum OrderStatus: string
{
    case PENDING = 'pending';
    case PROCESSING = 'processing';
    case SHIPPED = 'shipped';
    case DELIVERED = 'delivered';
    case CANCELLED = 'cancelled';
    
    public function label(): string
    {
        return match($this) {
            self::PENDING => 'Pending Payment',
            self::PROCESSING => 'Processing Order',
            self::SHIPPED => 'Shipped',
            self::DELIVERED => 'Delivered',
            self::CANCELLED => 'Cancelled',
        };
    }
}

/**
 * Example priority level enum for custom casting.
 */
enum PriorityLevel: int
{
    case LOW = 1;
    case MEDIUM = 2;
    case HIGH = 3;
    case URGENT = 4;
}
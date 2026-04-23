<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Casts\Attribute;

/**
 * Test fixture for edge cases and complex attribute patterns.
 * Tests matcher behavior with unusual but valid Laravel code.
 */
class EdgeCaseModel extends Model
{
    // ========================================
    // Minimal Attribute Patterns
    // ========================================

    /**
     * Minimal modern attribute with just getter.
     */
    public function simple(): Attribute
    {
        return Attribute::make(get: fn ($value) => $value);
    }

    /**
     * Minimal modern attribute with just setter.
     */
    public function setter(): Attribute
    {
        return Attribute::make(set: fn ($value) => $value);
    }

    /**
     * Empty legacy accessor.
     */
    public function getEmptyAttribute($value)
    {
        return $value;
    }

    /**
     * Empty legacy mutator.
     */
    public function setEmptyAttribute($value)
    {
        $this->attributes['empty'] = $value;
    }

    // ========================================
    // Complex Method Names
    // ========================================

    /**
     * Attribute with numbers in name.
     */
    public function address2(): Attribute
    {
        return Attribute::make(get: fn ($value) => $value);
    }

    /**
     * Attribute with underscores (non-standard but possible).
     */
    public function user_id(): Attribute
    {
        return Attribute::make(get: fn ($value) => (int) $value);
    }

    /**
     * Legacy accessor with complex name pattern.
     */
    public function getHTML5ContentAttribute($value)
    {
        return htmlspecialchars($value);
    }

    /**
     * Legacy mutator with acronym.
     */
    public function setURLPathAttribute($value)
    {
        $this->attributes['url_path'] = ltrim($value, '/');
    }

    // ========================================
    // Conditional and Dynamic Attributes
    // ========================================

    /**
     * Attribute with complex conditional logic.
     */
    public function conditionalValue(): Attribute
    {
        return Attribute::make(
            get: function ($value, $attributes) {
                switch ($attributes['type'] ?? 'default') {
                    case 'premium':
                        return $value * 1.5;
                    case 'discount':
                        return $value * 0.8;
                    default:
                        return $value;
                }
            },
            set: function ($value) {
                return is_numeric($value) ? floatval($value) : 0;
            }
        );
    }

    /**
     * Legacy accessor with dynamic method calls.
     */
    public function getDynamicValueAttribute()
    {
        $method = 'get' . ucfirst($this->type ?? 'default') . 'Value';
        return method_exists($this, $method) ? $this->$method() : null;
    }

    // ========================================
    // Multiline and Complex Expressions
    // ========================================

    /**
     * Modern attribute with multiline closure.
     */
    public function complexCalculation(): Attribute
    {
        return Attribute::make(
            get: function ($value, $attributes) {
                $base = floatval($attributes['base_value'] ?? 0);
                $multiplier = floatval($attributes['multiplier'] ?? 1);
                $tax = floatval($attributes['tax_rate'] ?? 0.1);
                
                return ($base * $multiplier) * (1 + $tax);
            }
        );
    }

    /**
     * Legacy accessor with complex processing.
     */
    public function getProcessedDataAttribute()
    {
        $data = json_decode($this->raw_data ?? '{}', true);
        
        if (!is_array($data)) {
            return [];
        }
        
        $processed = array_map(function ($item) {
            if (is_array($item) && isset($item['value'])) {
                $item['processed'] = true;
                $item['timestamp'] = time();
            }
            return $item;
        }, $data);
        
        return $processed;
    }

    // ========================================
    // Invalid or Malformed Patterns
    // ========================================

    /**
     * Method that looks like attribute but isn't.
     */
    public function getAttribute($key)
    {
        return parent::getAttribute($key);
    }

    /**
     * Method that doesn't follow attribute pattern.
     */
    public function getConfiguration()
    {
        return config('app.name');
    }

    /**
     * Non-attribute method with Attribute return type.
     */
    public function buildAttribute(): Attribute
    {
        return Attribute::make(get: fn ($value) => $value);
    }

    // ========================================
    // Cast Edge Cases
    // ========================================

    /**
     * Casts with custom classes and parameters.
     */
    protected $casts = [
        // Standard casts
        'simple_bool' => 'boolean',
        'simple_int' => 'integer',
        
        // Casts with parameters
        'price' => 'decimal:4',
        'coordinates' => 'float',
        
        // Custom cast classes
        'status' => CustomStatus::class,
        'priority' => 'App\\Casts\\Priority',
        
        // Complex cast specifications
        'metadata' => 'encrypted:json',
        'settings' => 'encrypted:array',
        'cache_data' => 'compressed:json',
        
        // Edge case cast names
        'data_2' => 'json',
        'html_5_content' => 'string',
        'api_v1_response' => 'array',
    ];

    // ========================================
    // Commented and Documented Patterns
    // ========================================

    /**
     * Well-documented modern attribute with detailed explanation.
     * 
     * This attribute demonstrates proper documentation practices
     * and shows how complex business logic can be encapsulated
     * within an attribute accessor.
     * 
     * @return \Illuminate\Database\Eloquent\Casts\Attribute
     */
    public function documentedAttribute(): Attribute
    {
        return Attribute::make(
            // Getter with detailed inline documentation
            get: function ($value, array $attributes): string {
                // Step 1: Validate input data
                if (empty($attributes['source_data'])) {
                    return 'No data available';
                }
                
                // Step 2: Process the data
                $processed = json_decode($attributes['source_data'], true);
                
                // Step 3: Apply business rules
                if (is_array($processed) && count($processed) > 0) {
                    return implode(', ', array_keys($processed));
                }
                
                return 'Invalid data format';
            },
            
            // Setter with validation and sanitization
            set: function (mixed $value): array {
                if (is_string($value)) {
                    return ['source_data' => json_encode(['input' => $value])];
                }
                
                if (is_array($value)) {
                    return ['source_data' => json_encode($value)];
                }
                
                return ['source_data' => json_encode([])];
            }
        );
    }
}

/**
 * Example custom cast class for testing.
 */
class CustomStatus
{
    // Custom cast implementation would go here
}
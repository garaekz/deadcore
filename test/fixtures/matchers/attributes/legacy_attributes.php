<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Hash;
use Carbon\Carbon;

/**
 * Test fixture for legacy Laravel attribute accessors and mutators
 * Using the traditional get{Name}Attribute and set{Name}Attribute patterns
 * that were the standard before Laravel 9's Attribute class.
 */
class Product extends Model
{
    protected $fillable = ['name', 'price', 'description', 'created_at'];

    /**
     * Get the product name in title case.
     * Legacy accessor pattern for string transformation.
     */
    public function getNameAttribute($value)
    {
        return ucwords(strtolower($value));
    }

    /**
     * Set the product name with proper sanitization.
     * Legacy mutator pattern for input cleaning.
     */
    public function setNameAttribute($value)
    {
        $this->attributes['name'] = trim(strip_tags($value));
    }

    /**
     * Get the formatted price with currency symbol.
     * Legacy accessor for display formatting.
     */
    public function getPriceFormattedAttribute()
    {
        return '$' . number_format($this->price / 100, 2);
    }

    /**
     * Set the price converting dollars to cents.
     * Legacy mutator for storage format conversion.
     */
    public function setPriceAttribute($value)
    {
        $this->attributes['price'] = round($value * 100);
    }

    /**
     * Get a shortened description for listing views.
     * Legacy accessor with text truncation logic.
     */
    public function getShortDescriptionAttribute()
    {
        return strlen($this->description) > 100
            ? substr($this->description, 0, 100) . '...'
            : $this->description;
    }

    /**
     * Set the description with HTML stripping.
     * Legacy mutator for content sanitization.
     */
    public function setDescriptionAttribute($value)
    {
        $this->attributes['description'] = strip_tags($value, '<p><br><strong><em>');
    }

    /**
     * Get the creation date in a friendly format.
     * Legacy accessor for date formatting.
     */
    public function getCreatedAtFormattedAttribute()
    {
        return Carbon::parse($this->created_at)->format('M j, Y');
    }

    /**
     * Get the time since creation in human readable format.
     * Legacy accessor with relative time calculation.
     */
    public function getTimeAgoAttribute()
    {
        return Carbon::parse($this->created_at)->diffForHumans();
    }

    /**
     * Get boolean indication of whether product is new.
     * Legacy accessor with business logic.
     */
    public function getIsNewAttribute()
    {
        return Carbon::parse($this->created_at)->diffInDays() <= 30;
    }

    /**
     * Get the SEO-friendly slug from the product name.
     * Legacy accessor for URL generation.
     */
    public function getSlugAttribute()
    {
        return strtolower(preg_replace('/[^A-Za-z0-9-]+/', '-', $this->name));
    }

    /**
     * Get the product category from external service.
     * Legacy accessor with complex lookup logic.
     */
    public function getCategoryNameAttribute()
    {
        // Simulated external lookup
        $categoryMap = [
            'electronics' => 'Electronics & Technology',
            'clothing' => 'Fashion & Apparel',
            'books' => 'Books & Media',
            'home' => 'Home & Garden'
        ];

        $category = strtolower($this->attributes['category'] ?? 'general');
        return $categoryMap[$category] ?? 'General';
    }
}
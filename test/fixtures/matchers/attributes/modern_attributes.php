<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Casts\Attribute;
use Illuminate\Database\Eloquent\Model;

/**
 * Test fixture for modern Laravel attribute accessors using Attribute::make()
 * Introduced in Laravel 9, these provide a more concise syntax for defining
 * attribute accessors and mutators.
 */
class User extends Model
{
    protected $fillable = ['first_name', 'last_name', 'email', 'birth_date'];

    /**
     * Get the user's full name attribute.
     * Combines first and last name into a single computed attribute.
     */
    public function fullName(): Attribute
    {
        return Attribute::make(
            get: fn ($value, $attributes) => $attributes['first_name'] . ' ' . $attributes['last_name']
        );
    }

    /**
     * Get/set the first name attribute with proper casing.
     * Modern attribute with both getter and setter logic.
     */
    public function firstName(): Attribute
    {
        return Attribute::make(
            get: fn ($value) => ucfirst(strtolower($value)),
            set: fn ($value) => strtolower(trim($value))
        );
    }

    /**
     * Get the user's age based on birth date.
     * Read-only computed attribute using Carbon for date calculation.
     */
    public function age(): Attribute
    {
        return Attribute::make(
            get: fn ($value, $attributes) => now()->diffInYears($attributes['birth_date'])
        );
    }

    /**
     * Get the email domain from the email address.
     * Extracts domain portion for display or filtering purposes.
     */
    public function emailDomain(): Attribute
    {
        return Attribute::make(
            get: fn ($value, $attributes) => substr(
                strrchr($attributes['email'], '@'), 1
            )
        );
    }

    /**
     * Boolean attribute for email verification status.
     * Casts database values to proper boolean type.
     */
    public function isVerified(): Attribute
    {
        return Attribute::make(
            get: fn ($value) => (bool) $value,
            set: fn ($value) => $value ? 1 : 0
        );
    }

    /**
     * Complex attribute with multiple transformations.
     * Demonstrates chained operations and validation.
     */
    public function displayName(): Attribute
    {
        return Attribute::make(
            get: fn ($value, $attributes) => !empty($attributes['nickname'])
                ? $attributes['nickname']
                : $attributes['first_name'],
            set: fn ($value) => is_string($value) ? trim($value) : ''
        );
    }
}
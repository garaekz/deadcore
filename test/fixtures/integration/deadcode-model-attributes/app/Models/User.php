<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Casts\Attribute;
use Illuminate\Database\Eloquent\Model;

class User extends Model
{
    public function getDisplayNameAttribute($value)
    {
        return trim($value);
    }

    public function setDisplayNameAttribute($value)
    {
        $this->attributes['display_name'] = trim($value);
    }

    protected function secretName(): Attribute
    {
        return Attribute::make(
            get: fn ($value) => strtoupper($value),
            set: fn ($value) => strtolower($value),
        );
    }
}

<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Invoice extends Model
{
    public function customer()
    {
        return $this->belongsTo(Customer::class);
    }

    public function legacyNotes()
    {
        return $this->hasMany(Note::class);
    }
}

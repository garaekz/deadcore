<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Invoice extends Model
{
    public function summary(): string
    {
        return 'invoice-summary';
    }

    public function debugLabel(): string
    {
        return 'invoice-debug-label';
    }
}

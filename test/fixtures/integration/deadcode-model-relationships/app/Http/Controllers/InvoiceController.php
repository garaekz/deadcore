<?php

namespace App\Http\Controllers;

use App\Models\Invoice;

final class InvoiceController
{
    public function index(): array
    {
        return Invoice::query()->with('customer')->get()->all();
    }
}

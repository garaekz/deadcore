<?php

namespace App\Http\Controllers;

use App\Models\Invoice;

final class InvoiceController
{
    public function index(): array
    {
        $invoice = Invoice::query()->with('customer')->firstOrFail();

        $invoice->customer?->name;

        return [$invoice];
    }
}

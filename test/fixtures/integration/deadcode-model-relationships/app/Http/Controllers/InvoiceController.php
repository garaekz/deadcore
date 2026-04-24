<?php

namespace App\Http\Controllers;

use App\Models\Invoice;

final class InvoiceController
{
    public function index(): array
    {
        $invoice = Invoice::query()->with(['customer'])->firstOrFail();
        $customer = $invoice->customer()->first();

        $customer?->name;

        return [$invoice, $customer];
    }
}

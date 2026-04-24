<?php

namespace App\Http\Controllers;

use App\Models\Invoice;

final class InvoiceController
{
    public function index(): string
    {
        $invoice = new Invoice();

        return $invoice->summary();
    }
}

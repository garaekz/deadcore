<?php

namespace App\Http\Controllers;

use App\Http\Requests\StoreOrderRequest;
use App\Http\Resources\OrderResource;

final class ReachableOrderController
{
    public function store(StoreOrderRequest $request): OrderResource
    {
        return new OrderResource([
            'id' => 1,
            'status' => 'created',
            'sku' => $request->input('sku'),
        ]);
    }
}

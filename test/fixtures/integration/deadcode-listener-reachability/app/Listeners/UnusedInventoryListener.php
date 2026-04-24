<?php

namespace App\Listeners;

use App\Events\OrderShipped;

final class UnusedInventoryListener
{
    public function handle(OrderShipped $event): void
    {
        $event->orderId;
    }
}

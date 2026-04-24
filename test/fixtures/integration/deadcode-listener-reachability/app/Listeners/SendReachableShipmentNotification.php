<?php

namespace App\Listeners;

use App\Events\OrderShipped;

final class SendReachableShipmentNotification
{
    public function handle(OrderShipped $event): void
    {
        $event->orderId;
    }
}

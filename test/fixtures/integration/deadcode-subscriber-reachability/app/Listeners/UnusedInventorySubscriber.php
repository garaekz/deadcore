<?php

namespace App\Listeners;

use App\Events\OrderShipped;

final class UnusedInventorySubscriber
{
    public function onOrderShipped(OrderShipped $event): void
    {
        $event->orderId;
    }

    public function subscribe($events): void
    {
        $events->listen(
            OrderShipped::class,
            [self::class, 'onOrderShipped'],
        );
    }
}

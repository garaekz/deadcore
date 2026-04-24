<?php

namespace App\Listeners;

use App\Events\OrderShipped;

final class ReachableOrderSubscriber
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

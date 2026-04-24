<?php

namespace App\Events;

final class OrderShipped
{
    public function __construct(
        public readonly int $orderId,
    ) {
    }
}

<?php

namespace App\Broadcasting;

use App\Models\User;
use App\Models\Order;

class OrderChannel
{
    /**
     * Create a new channel instance.
     */
    public function __construct()
    {
        //
    }

    /**
     * Authenticate the user's access to the channel.
     */
    public function join(User $user, $orderId)
    {
        $order = Order::find($orderId);
        
        return $order && $user->id === $order->user_id;
    }
}
<?php

namespace App\Providers;

use App\Events\OrderShipped;
use App\Listeners\SendReachableShipmentNotification;
use Illuminate\Foundation\Support\Providers\EventServiceProvider as ServiceProvider;

final class EventServiceProvider extends ServiceProvider
{
    protected $listen = [
        OrderShipped::class => [
            SendReachableShipmentNotification::class,
        ],
    ];
}

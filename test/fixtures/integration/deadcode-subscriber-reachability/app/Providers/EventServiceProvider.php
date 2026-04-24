<?php

namespace App\Providers;

use App\Listeners\ReachableOrderSubscriber;
use Illuminate\Foundation\Support\Providers\EventServiceProvider as ServiceProvider;

final class EventServiceProvider extends ServiceProvider
{
    protected $subscribe = [
        ReachableOrderSubscriber::class,
    ];
}

<?php

namespace App\Providers;

use App\Models\PolicyPost;
use App\Policies\ReachablePolicyPostPolicy;
use Illuminate\Foundation\Support\Providers\AuthServiceProvider as ServiceProvider;

final class AuthServiceProvider extends ServiceProvider
{
    protected $policies = [
        PolicyPost::class => ReachablePolicyPostPolicy::class,
    ];
}

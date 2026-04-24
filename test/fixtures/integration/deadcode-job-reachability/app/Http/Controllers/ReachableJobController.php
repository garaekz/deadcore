<?php

namespace App\Http\Controllers;

use App\Jobs\ReachableOrderJob;

final class ReachableJobController
{
    public function store(): array
    {
        ReachableOrderJob::dispatch('reachable-order');

        return ['queued' => true];
    }
}

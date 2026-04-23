<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use Inertia\Inertia;

final class TeamsController
{
    public function store()
    {
        return Inertia::location('/teams/current');
    }
}

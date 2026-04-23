<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use Inertia\Inertia;

final class DashboardController
{
    public function __invoke()
    {
        return Inertia::render('Dashboard/Index', [
            'filters' => [
                'team' => 'product',
            ],
            'stats' => [
                'count' => 5,
            ],
        ]);
    }
}

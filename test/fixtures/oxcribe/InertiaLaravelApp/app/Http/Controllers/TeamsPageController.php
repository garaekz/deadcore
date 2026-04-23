<?php

declare(strict_types=1);

namespace App\Http\Controllers;

final class TeamsPageController
{
    public function show()
    {
        return inertia('Teams/Show', [
            'team' => [
                'name' => 'Core',
            ],
        ]);
    }
}

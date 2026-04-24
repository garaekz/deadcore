<?php

namespace App\Http\Controllers;

use App\Models\User;

final class UserController
{
    public function index(): array
    {
        $user = new User();

        $user->display_name = '  Ada Lovelace  ';

        return [
            $user->display_name,
        ];
    }
}

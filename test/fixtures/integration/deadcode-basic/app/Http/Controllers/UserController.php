<?php

namespace App\Http\Controllers;

final class UserController
{
    public function index()
    {
        return response()->json([
            'users' => [],
        ], 200);
    }

    public function unused()
    {
        return response()->json([
            'unused' => true,
        ], 200);
    }
}

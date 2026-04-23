<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\JsonResponse;

final class InvokeUserController
{
    public function __invoke(): JsonResponse
    {
        return response()->json(User::query()->count());
    }
}

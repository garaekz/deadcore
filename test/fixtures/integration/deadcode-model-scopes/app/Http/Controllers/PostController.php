<?php

namespace App\Http\Controllers;

use App\Models\Post;

final class PostController
{
    public function index(): array
    {
        return Post::query()
            ->published()
            ->get()
            ->all();
    }
}

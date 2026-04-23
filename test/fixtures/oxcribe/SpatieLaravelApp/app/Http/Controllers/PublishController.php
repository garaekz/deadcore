<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use App\Data\PublishPostData;
use App\Http\Resources\PostResource;
use App\Models\Post;
use Illuminate\Http\JsonResponse;

final class PublishController
{
    public function store(Post $post, PublishPostData $payload): JsonResponse
    {
        return response()->json(new PostResource($post), 202);
    }
}

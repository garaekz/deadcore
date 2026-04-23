<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use App\Data\AdvancedPublishPostData;
use App\Http\Resources\PostResource;
use App\Models\Post;

final class AdvancedPublishController
{
    public function __invoke(Post $post, AdvancedPublishPostData $payload): PostResource
    {
        return new PostResource($post);
    }
}

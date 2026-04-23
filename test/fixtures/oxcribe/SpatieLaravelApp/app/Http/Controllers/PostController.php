<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use App\Data\StorePostData;
use App\Http\Resources\PostCollection;
use App\Http\Resources\PostResource;
use App\Models\Post;
use Spatie\QueryBuilder\AllowedFilter;
use Spatie\QueryBuilder\QueryBuilder;

final class PostController
{
    public function index(): PostCollection
    {
        QueryBuilder::for(Post::class)
            ->allowedFilters(['status', AllowedFilter::trashed()])
            ->allowedIncludes(['author'])
            ->allowedSorts(['published_at'])
            ->allowedFields(['posts.title', 'posts.summary']);

        $posts = Post::query()->paginate(15);

        return new PostCollection($posts);
    }

    public function store(StorePostData $payload): PostResource
    {
        return new PostResource($payload);
    }

    public function show(Post $post): PostResource
    {
        return new PostResource($post);
    }
}

<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use App\Http\Resources\PostResource;
use App\Models\Post;
use Spatie\QueryBuilder\AllowedFilter;
use Spatie\QueryBuilder\QueryBuilder;

final class SearchController
{
    public function index()
    {
        QueryBuilder::for(Post::class)
            ->allowedFilters([
                AllowedFilter::exact('status'),
                AllowedFilter::scope('published'),
                AllowedFilter::callback('author', static fn () => null),
                AllowedFilter::trashed(),
            ])
            ->allowedIncludes([
                'author.profile',
                'comments.user',
                'tags',
            ])
            ->allowedSorts([
                '-published_at',
                'title',
                'status',
            ])
            ->allowedFields([
                'posts.id',
                'posts.title',
                'posts.summary',
                'posts.status',
                'authors.name',
                'authors.email',
            ]);

        $posts = Post::query()->get();

        return PostResource::collection($posts);
    }
}

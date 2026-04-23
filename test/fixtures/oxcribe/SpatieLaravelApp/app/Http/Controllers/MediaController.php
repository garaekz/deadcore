<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use App\Models\Post;

final class MediaController
{
    public function store(): void
    {
        $post = new Post();

        $post->addMediaFromRequest('avatar')->toMediaCollection('avatars');
        $post->addMultipleMediaFromRequest(['gallery', 'cover'])->toMediaCollection('images');
    }

    public function gallery(): void
    {
        $post = new Post();

        $post->addMediaFromRequest('hero_image')->toMediaCollection('hero');
        $post->addMediaFromRequest('attachments')->toMediaCollection('attachments');
    }
}

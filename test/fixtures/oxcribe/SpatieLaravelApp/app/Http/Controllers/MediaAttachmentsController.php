<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use App\Models\Post;

final class MediaAttachmentsController
{
    public function store(): void
    {
        $post = new Post();
        $request = request();
        $thumbnail = $request->file('thumbnail');
        $galleryFields = ['gallery_images[]', 'attachments'];

        $post->addMedia($thumbnail)->toMediaCollection('thumbnails');
        $post->addMedia(request()->file('preview_pdf'))->toMediaCollection('documents');
        $post->addMultipleMediaFromRequest($galleryFields)->toMediaCollection('assets');
    }
}

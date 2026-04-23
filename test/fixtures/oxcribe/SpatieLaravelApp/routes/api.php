<?php

declare(strict_types=1);

use App\Http\Controllers\AdvancedPublishController;
use App\Http\Controllers\AdvancedSearchController;
use App\Http\Controllers\MediaController;
use App\Http\Controllers\MediaAttachmentsController;
use App\Http\Controllers\PageController;
use App\Http\Controllers\PublishController;
use App\Http\Controllers\SeriesController;
use App\Http\Controllers\SearchController;
use App\Http\Controllers\PostController;
use Illuminate\Support\Facades\Route;

Route::get('posts/search', [SearchController::class, 'index'])
    ->name('spatie-fixture.posts.search')
    ->middleware(['role:editor|writer,api']);

Route::get('posts', [PostController::class, 'index'])
    ->name('spatie-fixture.posts.index')
    ->middleware(['role:editor']);

Route::post('posts', [PostController::class, 'store'])
    ->name('spatie-fixture.posts.store')
    ->middleware(['auth:sanctum', 'role_or_permission:editor|posts.create,api']);

Route::get('posts/{post}', [PostController::class, 'show'])
    ->name('spatie-fixture.posts.show')
    ->middleware(['auth:sanctum']);

Route::post('posts/{post}/publish', [PublishController::class, 'store'])
    ->name('spatie-fixture.posts.publish')
    ->middleware(['auth:sanctum', 'permission:posts.publish']);

Route::post('posts/{post}/publish-advanced', AdvancedPublishController::class)
    ->name('spatie-fixture.posts.publish-advanced')
    ->middleware(['auth:sanctum', 'role_or_permission:publisher|posts.publish,api']);

Route::post('media', [MediaController::class, 'store'])
    ->name('spatie-fixture.media.store')
    ->middleware(['auth:sanctum', 'permission:media.upload']);

Route::post('media/attachments', [MediaAttachmentsController::class, 'store'])
    ->name('spatie-fixture.media.attachments')
    ->middleware(['auth:sanctum', 'permission:media.upload']);

Route::post('media/gallery', [MediaController::class, 'gallery'])
    ->name('spatie-fixture.media.gallery')
    ->middleware(['auth:sanctum', 'role_or_permission:media-manager|media.manage,api']);

Route::get('posts/advanced-search', [AdvancedSearchController::class, 'index'])
    ->name('spatie-fixture.posts.advanced-search')
    ->middleware(['role_or_permission:editor|writer,api']);

Route::patch('pages/{page}', [PageController::class, 'update'])
    ->name('spatie-fixture.pages.update')
    ->middleware(['role:editor,web']);

Route::patch('series/{series}', [SeriesController::class, 'update'])
    ->name('spatie-fixture.series.update')
    ->middleware(['permission:series.edit']);

<?php

declare(strict_types=1);

use App\Http\Controllers\PostPolicyController;
use Illuminate\Support\Facades\Route;

Route::middleware('auth:sanctum')->group(function (): void {
    Route::get('/policy/posts/{policyPost}', [PostPolicyController::class, 'show'])->name('policy-fixture.posts.show');
    Route::get('/policy/posts/{policyPost}/preview', [PostPolicyController::class, 'preview'])->name('policy-fixture.posts.preview');
});

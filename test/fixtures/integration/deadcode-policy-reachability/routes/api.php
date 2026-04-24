<?php

use App\Http\Controllers\PolicyPostController;
use Illuminate\Support\Facades\Route;

Route::get('/policy-posts/{policyPost}', [PolicyPostController::class, 'show']);

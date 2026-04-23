<?php

use App\Http\Controllers\EntryController;
use App\Http\Controllers\ObjectEntryController;
use App\Http\Controllers\UserController;
use Illuminate\Support\Facades\Route;

Route::get('/entry', [EntryController::class, 'index']);
Route::get('/object-entry', [ObjectEntryController::class, 'index']);
Route::get('/users', [UserController::class, 'index']);

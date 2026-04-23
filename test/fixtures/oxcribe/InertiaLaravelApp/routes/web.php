<?php

use App\Http\Controllers\DashboardController;
use App\Http\Controllers\TeamsController;
use App\Http\Controllers\TeamsPageController;
use Illuminate\Support\Facades\Route;

Route::get('/dashboard', DashboardController::class)->name('inertia-fixture.dashboard');
Route::get('/teams/show', [TeamsPageController::class, 'show'])->name('inertia-fixture.teams.show');
Route::post('/teams/switch', [TeamsController::class, 'store'])->name('inertia-fixture.teams.switch');

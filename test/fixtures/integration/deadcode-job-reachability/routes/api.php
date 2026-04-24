<?php

use App\Http\Controllers\ReachableJobController;
use Illuminate\Support\Facades\Route;

Route::post('/jobs/reachable', [ReachableJobController::class, 'store']);

<?php

use App\Http\Controllers\ReachableOrderController;
use Illuminate\Support\Facades\Route;

Route::post('/orders', [ReachableOrderController::class, 'store']);

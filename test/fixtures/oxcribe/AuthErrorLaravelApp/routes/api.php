<?php

declare(strict_types=1);

use App\Http\Controllers\SecureReportController;
use Illuminate\Support\Facades\Route;

Route::get('/secure/reports', [SecureReportController::class, 'index'])
    ->name('auth-error-fixture.secure-reports.index')
    ->middleware(['auth:sanctum', 'verified', 'password.confirm', 'signed:relative', 'throttle:60,1,uploads', 'can:viewAny,App\\Models\\Report']);

Route::get('/secure/reports/errors', [SecureReportController::class, 'errors'])
    ->name('auth-error-fixture.secure-reports.errors')
    ->middleware(['auth:sanctum', 'throttle:api']);

Route::get('/secure/reports/additional', [SecureReportController::class, 'additionalResource'])
    ->name('auth-error-fixture.secure-reports.additional')
    ->middleware(['auth:sanctum']);

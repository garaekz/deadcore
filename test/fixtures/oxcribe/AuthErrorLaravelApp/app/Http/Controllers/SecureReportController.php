<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use App\Http\Resources\ReportResource;
use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Database\Eloquent\ModelNotFoundException;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Resources\Json\JsonResource;
use Illuminate\Validation\ValidationException;

final class SecureReportController
{
    public function index(): JsonResponse
    {
        return response()->json([
            'data' => [
                'id' => 10,
                'title' => 'Quarterly security report',
            ],
        ]);
    }

    public function errors(): JsonResponse
    {
        $statusCode = 400;

        if (request()->boolean('missing')) {
            abort($statusCode, 'Missing report');
        }

        if (request()->boolean('forbidden')) {
            throw new AuthorizationException('Not allowed');
        }

        if (request()->boolean('gone')) {
            throw new ModelNotFoundException();
        }

        if (request()->boolean('invalid')) {
            throw ValidationException::withMessages([
                'email' => ['Invalid email address'],
                'name' => ['Required'],
            ]);
        }

        return response()->json([
            'ok' => true,
        ]);
    }

    public function additionalResource(): JsonResource
    {
        return ReportResource::make([
            'id' => 11,
            'title' => 'Additional report',
        ])->additional([
            'meta' => [
                'version' => 2,
            ],
            'links' => [
                'self' => 'https://example.test/reports/11',
            ],
        ]);
    }
}

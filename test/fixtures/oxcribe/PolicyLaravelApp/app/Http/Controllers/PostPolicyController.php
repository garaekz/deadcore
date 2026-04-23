<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use App\Http\Requests\ShowPolicyPostRequest;
use App\Models\PolicyPost;
use Illuminate\Database\Eloquent\ModelNotFoundException;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Facades\Gate;

final class PostPolicyController
{
    public function __construct()
    {
        $this->authorizeResource(PolicyPost::class, 'policyPost', ['only' => ['show']]);
    }

    public function show(ShowPolicyPostRequest $request, PolicyPost $policyPost): JsonResponse
    {
        $this->authorize('view', $policyPost);
        Gate::authorize('publish', PolicyPost::class);
        Gate::allows('preview', $policyPost);

        abort_unless($request->boolean('ready'), 409);
        throw_unless($request->boolean('present'), new ModelNotFoundException());
        PolicyPost::query()->firstOrFail();

        return response()->json([
            'id' => 1,
            'title' => 'Policy Post',
        ]);
    }

    public function preview(PolicyPost $policyPost): JsonResponse
    {
        Gate::allows('preview', $policyPost);

        return response()->json([
            'preview' => true,
        ]);
    }
}

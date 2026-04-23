<?php

namespace App\Http\Controllers\API;

use App\Http\Controllers\Controller;
use App\Http\Resources\UserResource;
use App\Http\Resources\ProductResource;
use App\Models\User;
use App\Models\Product;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Validation\ValidationException;

class ApiController extends Controller
{
    /**
     * API endpoint with comprehensive request handling
     * Tests: Multiple request methods, JSON processing, validation
     */
    public function processData(Request $request)
    {
        // JSON data processing
        $jsonPayload = $request->json();
        $specificValue = $request->json('data.key');
        
        // Form data processing
        $formData = $request->all();
        $filtered = $request->only(['name', 'email', 'category']);
        $excluded = $request->except(['password', '_token']);
        
        // Individual input processing
        $name = $request->input('name');
        $email = $request->input('email', 'default@example.com');
        $nested = $request->input('profile.settings.theme', 'light');
        
        // File upload handling
        if ($request->hasFile('attachment')) {
            $file = $request->file('attachment');
            $path = $file->store('attachments');
        }
        
        // Validation
        $validated = $request->validate([
            'name' => 'required|string|max:255',
            'email' => 'required|email',
            'category' => 'required|in:user,admin,guest'
        ]);
        
        $result = array_merge($validated, ['processed' => true]);
        
        return response()->json(['data' => $result], 200);
    }

    /**
     * Complex HTTP status handling
     * Tests: Multiple status codes, abort calls, conditional responses
     */
    public function statusHandling(Request $request)
    {
        $action = $request->input('action');
        
        switch ($action) {
            case 'create':
                $data = $request->all();
                // Simulate creation
                return response()->json(['created' => $data], 201);
                
            case 'update':
                if (!$request->has('id')) {
                    abort(400, 'ID is required');
                }
                return response()->status(202);
                
            case 'delete':
                $id = $request->input('id');
                if (!$id) {
                    abort(404, 'Resource not found');
                }
                return response(null, 204);
                
            case 'error':
                abort(500, 'Internal server error');
                
            case 'forbidden':
                abort(403, 'Access denied');
                
            case 'validation':
                abort(422, 'Validation failed');
                
            default:
                return response()->json(['error' => 'Invalid action'], 400);
        }
    }

    /**
     * Resource handling with different patterns
     * Tests: Mixed resource usage patterns, collections vs singles
     */
    public function resourceHandling(Request $request)
    {
        $type = $request->input('type');
        $format = $request->input('format', 'single');
        
        switch ($type) {
            case 'users':
                $users = [
                    ['id' => 1, 'name' => 'John'],
                    ['id' => 2, 'name' => 'Jane'],
                ];
                
                if ($format === 'collection') {
                    return UserResource::collection($users);
                } else {
                    return new UserResource($users[0]);
                }
                
            case 'products':
                $products = [
                    ['id' => 1, 'name' => 'Product A', 'price' => 100],
                    ['id' => 2, 'name' => 'Product B', 'price' => 200],
                ];
                
                if ($format === 'collection') {
                    return ProductResource::collection($products);
                } else {
                    return ProductResource::make($products[0]);
                }
                
            case 'mixed':
                return response()->json([
                    'users' => UserResource::collection([['id' => 1]]),
                    'products' => ProductResource::collection([['id' => 1]]),
                    'featured_user' => new UserResource(['id' => 1, 'featured' => true])
                ]);
                
            default:
                abort(400, 'Invalid resource type');
        }
    }

    /**
     * File upload with multiple scenarios
     * Tests: Various file upload patterns, multiple files
     */
    public function fileUpload(Request $request)
    {
        $uploadType = $request->input('upload_type');
        
        switch ($uploadType) {
            case 'single':
                if (!$request->hasFile('file')) {
                    abort(400, 'No file provided');
                }
                
                $file = $request->file('file');
                $path = $file->store('uploads');
                
                return response()->json([
                    'uploaded' => true,
                    'path' => $path
                ], 201);
                
            case 'multiple':
                if (!$request->hasFile('files')) {
                    abort(400, 'No files provided');
                }
                
                $files = $request->file('files');
                $paths = [];
                
                foreach ($files as $file) {
                    $paths[] = $file->store('uploads');
                }
                
                return response()->json([
                    'uploaded' => count($paths),
                    'paths' => $paths
                ], 201);
                
            case 'avatar':
                $avatar = $request->file('avatar');
                $document = $request->file('document');
                
                $result = [];
                
                if ($avatar) {
                    $result['avatar'] = $avatar->store('avatars');
                }
                
                if ($document) {
                    $result['document'] = $document->store('documents');
                }
                
                if (empty($result)) {
                    abort(400, 'No files uploaded');
                }
                
                return response()->json($result, 201);
                
            default:
                abort(400, 'Invalid upload type');
        }
    }

    /**
     * Comprehensive API method combining all patterns
     * Tests: Integration of HTTP status, request usage, and resources
     */
    public function comprehensiveApi(Request $request)
    {
        // Input validation and processing
        $validated = $request->validate([
            'action' => 'required|in:create,update,delete,list',
            'data' => 'required|array',
            'format' => 'sometimes|in:json,resource'
        ]);
        
        $action = $validated['action'];
        $data = $validated['data'];
        $format = $request->input('format', 'json');
        
        // JSON payload processing
        $metadata = $request->json('metadata', []);
        
        // File handling if present
        $attachments = [];
        if ($request->hasFile('attachments')) {
            $files = $request->file('attachments');
            foreach ($files as $file) {
                $attachments[] = $file->store('api-attachments');
            }
        }
        
        // Action processing
        switch ($action) {
            case 'create':
                $created = array_merge($data, [
                    'id' => rand(1, 1000),
                    'metadata' => $metadata,
                    'attachments' => $attachments,
                    'created_at' => date('Y-m-d H:i:s')
                ]);
                
                if ($format === 'resource') {
                    return response()->json(new UserResource($created), 201);
                } else {
                    return response()->json(['data' => $created], 201);
                }
                
            case 'update':
                if (!isset($data['id'])) {
                    abort(400, 'ID required for update');
                }
                
                $updated = array_merge($data, [
                    'metadata' => $metadata,
                    'updated_at' => date('Y-m-d H:i:s')
                ]);
                
                if ($format === 'resource') {
                    return UserResource::make($updated);
                } else {
                    return response()->json(['data' => $updated], 200);
                }
                
            case 'delete':
                if (!isset($data['id'])) {
                    abort(400, 'ID required for delete');
                }
                
                // Simulate deletion
                return response(null, 204);
                
            case 'list':
                $items = [
                    array_merge($data, ['id' => 1]),
                    array_merge($data, ['id' => 2]),
                    array_merge($data, ['id' => 3]),
                ];
                
                if ($format === 'resource') {
                    return UserResource::collection($items);
                } else {
                    return response()->json(['data' => $items], 200);
                }
                
            default:
                abort(400, 'Invalid action');
        }
    }

    /**
     * Edge case handling
     * Tests: Complex conditional logic, nested resource usage
     */
    public function edgeCases(Request $request)
    {
        $scenario = $request->input('scenario');
        
        // Complex conditional resource usage
        if ($scenario === 'conditional_resource') {
            $user = ['id' => 1, 'name' => 'Test'];
            
            if ($request->has('include_details')) {
                $resource = new UserResource($user);
                return response()->json($resource)->status(200);
            }
            
            return UserResource::collection([$user]);
        }
        
        // Nested response structures
        if ($scenario === 'nested') {
            return response()->json([
                'data' => [
                    'user' => new UserResource(['id' => 1]),
                    'products' => ProductResource::collection([['id' => 1]]),
                    'meta' => [
                        'count' => 2,
                        'timestamp' => time()
                    ]
                ],
                'status' => 'success'
            ])->status(200);
        }
        
        // Variable assignment patterns
        if ($scenario === 'variable_assignment') {
            $data = $request->all();
            $response = response()->status(201);
            $resource = new UserResource($data);
            
            return $response->json($resource);
        }
        
        // Chained method calls
        if ($scenario === 'chained') {
            return UserResource::make(['id' => 1])
                ->additional(['meta' => 'data'])
                ->response()
                ->status(200);
        }
        
        abort(400, 'Invalid scenario');
    }
}
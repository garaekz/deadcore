<?php

namespace App\Http\Controllers;

use App\Http\Controllers\Controller;
use App\Http\Resources\UserResource;
use App\Http\Resources\PostResource;
use App\Http\Resources\CommentResource;
use App\Http\Resources\FileResource;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Storage;
use Illuminate\Validation\ValidationException;

/**
 * ComplexController for testing advanced pattern matching scenarios
 * 
 * This controller contains complex patterns that should challenge
 * the matchers and test edge cases, confidence scoring, and
 * pattern detection in realistic but complex scenarios.
 */
class ComplexController extends Controller
{
    /**
     * Deeply nested request processing with multiple content types
     * Tests: Complex request pattern detection, nested conditionals
     */
    public function processComplexRequest(Request $request)
    {
        // Multiple request processing patterns
        $baseData = $request->all();
        $jsonPayload = $request->json();
        
        // Conditional request processing
        if ($request->isJson()) {
            $specificData = $request->json('user.profile.settings');
            $nestedArray = $request->json('data.items', []);
        } else {
            $specificData = $request->input('user_profile_settings');
            $nestedArray = $request->input('data_items', []);
        }
        
        // File processing with multiple scenarios
        $processedFiles = [];
        if ($request->hasFile('primary_upload')) {
            $file = $request->file('primary_upload');
            $processedFiles['primary'] = $this->processFile($file);
        }
        
        if ($request->hasFile('secondary_uploads')) {
            $files = $request->file('secondary_uploads');
            foreach ($files as $index => $file) {
                $processedFiles["secondary_{$index}"] = $this->processFile($file);
            }
        }
        
        // Complex validation with conditional rules
        $rules = [
            'action' => 'required|in:create,update,delete,process',
            'data' => 'required|array',
        ];
        
        if ($request->input('action') === 'create') {
            $rules['data.name'] = 'required|string';
            $rules['data.email'] = 'required|email';
        }
        
        $validated = $request->validate($rules);
        
        // Complex filtering and processing
        $allowedFields = ['name', 'email', 'profile', 'preferences'];
        $filteredData = $request->only($allowedFields);
        $cleanedData = $request->except(['password', '_token', 'csrf_token']);
        
        // Determine response based on complex conditions
        $result = [
            'processed_data' => array_merge($baseData, $filteredData),
            'json_payload' => $jsonPayload,
            'files' => $processedFiles,
            'validation_passed' => true
        ];
        
        // Multiple possible response patterns
        switch ($validated['action']) {
            case 'create':
                return response()->json($result, 201);
                
            case 'update':
                return response()->status(202)->json($result);
                
            case 'delete':
                return response(null, 204);
                
            case 'process':
                if (empty($processedFiles)) {
                    abort(400, 'No files to process');
                }
                return response()->json($result, 200);
                
            default:
                abort(422, 'Unknown action');
        }
    }

    /**
     * Resource usage with complex patterns and conditional logic
     * Tests: Complex resource detection, multiple resource types, conditional usage
     */
    public function complexResourceHandling(Request $request)
    {
        $entityType = $request->input('entity_type');
        $outputFormat = $request->input('output_format', 'single');
        $includeRelated = $request->has('include_related');
        
        // Complex data preparation
        $userData = ['id' => 1, 'name' => 'John Doe', 'email' => 'john@example.com'];
        $postData = ['id' => 1, 'title' => 'Sample Post', 'content' => 'Content here'];
        $commentData = ['id' => 1, 'text' => 'Great post!', 'user_id' => 1];
        
        // Nested resource creation with conditionals
        if ($entityType === 'user') {
            if ($outputFormat === 'collection') {
                $users = [$userData, ['id' => 2, 'name' => 'Jane Doe']];
                $userCollection = UserResource::collection($users);
                
                if ($includeRelated) {
                    return response()->json([
                        'users' => $userCollection,
                        'related_posts' => PostResource::collection([$postData]),
                        'meta' => ['total' => count($users)]
                    ]);
                }
                
                return $userCollection;
            } else {
                $userResource = new UserResource($userData);
                
                if ($includeRelated) {
                    $response = [
                        'user' => $userResource,
                        'posts' => PostResource::collection([$postData]),
                        'comments' => CommentResource::collection([$commentData])
                    ];
                    return response()->json($response)->status(200);
                }
                
                return UserResource::make($userData);
            }
        }
        
        if ($entityType === 'post') {
            $postResource = new PostResource($postData);
            
            // Complex chaining and conditional resource usage
            if ($request->has('with_comments')) {
                $comments = [
                    $commentData,
                    ['id' => 2, 'text' => 'Another comment', 'user_id' => 2]
                ];
                
                return response()->json([
                    'post' => $postResource,
                    'comments' => CommentResource::collection($comments),
                    'author' => new UserResource($userData)
                ], 200);
            }
            
            return PostResource::make($postData);
        }
        
        // Complex error handling with specific status codes
        if ($entityType === 'invalid') {
            abort(404, 'Entity type not found');
        }
        
        abort(400, 'Invalid entity type specified');
    }

    /**
     * Mixed patterns with high complexity and multiple response paths
     * Tests: Integration of all pattern types in complex scenarios
     */
    public function mixedComplexPatterns(Request $request)
    {
        $operation = $request->input('operation');
        $mode = $request->input('mode', 'standard');
        
        // Complex request processing
        $requestData = [];
        if ($request->isJson()) {
            $requestData = array_merge(
                $request->json('payload', []),
                ['metadata' => $request->json('metadata', [])]
            );
        } else {
            $requestData = array_merge(
                $request->only(['name', 'description', 'category']),
                ['form_data' => $request->except(['_token', 'operation', 'mode'])]
            );
        }
        
        // File handling with complex logic
        $fileData = [];
        if ($request->hasFile('documents')) {
            $documents = $request->file('documents');
            foreach ($documents as $key => $document) {
                $fileData[$key] = [
                    'original_name' => $document->getClientOriginalName(),
                    'size' => $document->getSize(),
                    'stored_path' => $document->store('complex-documents')
                ];
            }
        }
        
        // Individual file processing
        if ($request->hasFile('avatar') && $request->file('avatar')->isValid()) {
            $avatar = $request->file('avatar');
            $fileData['avatar'] = $avatar->store('avatars');
        }
        
        // Complex validation with dynamic rules
        $validationRules = [];
        if ($operation === 'create_user') {
            $validationRules = [
                'payload.name' => 'required|string|max:255',
                'payload.email' => 'required|email|unique:users,email'
            ];
        } elseif ($operation === 'create_post') {
            $validationRules = [
                'payload.title' => 'required|string|max:255',
                'payload.content' => 'required|string|min:10'
            ];
        }
        
        if (!empty($validationRules)) {
            $validated = $request->validate($validationRules);
        }
        
        // Complex processing based on operation and mode
        switch ($operation) {
            case 'create_user':
                $userData = array_merge($requestData, ['files' => $fileData]);
                
                if ($mode === 'resource') {
                    if ($request->has('return_collection')) {
                        return response()->json(
                            UserResource::collection([$userData, $userData]), 
                            201
                        );
                    }
                    return response()->json(new UserResource($userData), 201);
                }
                
                return response()->json(['data' => $userData], 201);
                
            case 'create_post':
                $postData = array_merge($requestData, ['attachments' => $fileData]);
                
                if ($mode === 'resource') {
                    $postResource = PostResource::make($postData);
                    
                    if ($request->has('include_author')) {
                        $author = ['id' => 1, 'name' => 'Author'];
                        return response()->json([
                            'post' => $postResource,
                            'author' => new UserResource($author)
                        ], 201);
                    }
                    
                    return PostResource::make($postData);
                }
                
                return response()->status(201)->json(['data' => $postData]);
                
            case 'batch_process':
                $items = $request->input('items', []);
                
                if (empty($items)) {
                    abort(400, 'No items provided for batch processing');
                }
                
                $processed = [];
                foreach ($items as $item) {
                    $processed[] = array_merge($item, ['processed' => true]);
                }
                
                if ($mode === 'resource') {
                    return UserResource::collection($processed);
                }
                
                return response()->json(['processed_items' => $processed], 200);
                
            case 'error_simulation':
                $errorType = $request->input('error_type', 'generic');
                
                switch ($errorType) {
                    case 'validation':
                        abort(422, 'Validation error simulated');
                    case 'not_found':
                        abort(404, 'Resource not found');
                    case 'forbidden':
                        abort(403, 'Access forbidden');
                    case 'server_error':
                        abort(500, 'Internal server error');
                    default:
                        abort(400, 'Generic error simulated');
                }
                
            default:
                abort(400, 'Unknown operation requested');
        }
    }

    /**
     * Nested and chained method calls with resources
     * Tests: Complex method chaining, nested resource calls, variable assignments
     */
    public function nestedAndChainedPatterns(Request $request)
    {
        $pattern = $request->input('pattern_type', 'basic');
        
        switch ($pattern) {
            case 'chained_resources':
                $userData = ['id' => 1, 'name' => 'Chained User'];
                return UserResource::make($userData)
                    ->additional(['meta' => 'chained_data'])
                    ->response()
                    ->status(200)
                    ->header('X-Custom-Header', 'ChainedResource');
                    
            case 'nested_response':
                return response()->json([
                    'level1' => [
                        'level2' => [
                            'user' => new UserResource(['id' => 1]),
                            'posts' => PostResource::collection([
                                ['id' => 1, 'title' => 'Nested Post 1'],
                                ['id' => 2, 'title' => 'Nested Post 2']
                            ]),
                            'level3' => [
                                'comments' => CommentResource::collection([
                                    ['id' => 1, 'text' => 'Deep comment']
                                ])
                            ]
                        ]
                    ]
                ])->status(200);
                
            case 'variable_assignments':
                $baseData = $request->all();
                $user = array_merge($baseData, ['id' => 1]);
                $userResource = new UserResource($user);
                $response = response()->json($userResource);
                $statusResponse = $response->status(201);
                
                return $statusResponse;
                
            case 'conditional_chaining':
                $data = $request->only(['name', 'email']);
                $resource = UserResource::make($data);
                
                if ($request->has('include_meta')) {
                    $resource = $resource->additional(['meta' => 'included']);
                }
                
                if ($request->has('custom_status')) {
                    return $resource->response()->status(202);
                }
                
                return $resource;
                
            default:
                $simpleData = ['id' => 1, 'pattern' => $pattern];
                return new UserResource($simpleData);
        }
    }

    /**
     * Helper method for file processing
     */
    private function processFile($file)
    {
        return [
            'name' => $file->getClientOriginalName(),
            'size' => $file->getSize(),
            'mime_type' => $file->getMimeType(),
            'path' => $file->store('processed-files'),
            'processed_at' => now()->toISOString()
        ];
    }

    /**
     * Error handling with complex patterns
     * Tests: Various abort patterns, conditional error responses
     */
    public function complexErrorHandling(Request $request)
    {
        $scenario = $request->input('scenario');
        $context = $request->input('context', []);
        
        // Conditional error patterns
        if ($scenario === 'validation_chain') {
            if (!$request->has('required_field')) {
                abort(400, 'Required field missing');
            }
            
            if (!$request->filled('required_field')) {
                abort(422, 'Required field is empty');
            }
            
            return response()->json(['validation' => 'passed'], 200);
        }
        
        if ($scenario === 'resource_errors') {
            $resourceType = $request->input('resource_type');
            
            if ($resourceType === 'user') {
                if (!isset($context['user_id'])) {
                    abort(404, 'User not found');
                }
                
                $user = ['id' => $context['user_id'], 'name' => 'Found User'];
                return new UserResource($user);
            }
            
            abort(400, 'Invalid resource type');
        }
        
        // Dynamic status codes based on context
        $statusCode = $request->input('status_code', 500);
        $message = $request->input('message', 'Error occurred');
        
        abort($statusCode, $message);
    }
}
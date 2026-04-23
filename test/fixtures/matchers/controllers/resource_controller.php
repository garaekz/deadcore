<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Http\Resources\UserResource;
use App\Http\Resources\PostResource; 
use App\Http\Resources\UserCollection;

class ResourceController extends Controller
{
    /**
     * Return single resource with explicit instantiation
     * Tests: Single resource detection with high confidence
     */
    public function showUser($id)
    {
        $user = ['id' => $id, 'name' => 'John Doe'];
        
        return new UserResource($user);
    }

    /**
     * Return resource collection using static method
     * Tests: Collection detection with maximum confidence
     */
    public function indexUsers()
    {
        $users = [
            ['id' => 1, 'name' => 'John'],
            ['id' => 2, 'name' => 'Jane'],
        ];
        
        return UserResource::collection($users);
    }

    /**
     * Return single resource using make method
     * Tests: Static make method detection
     */
    public function createUser(Request $request)
    {
        $userData = $request->all();
        $user = ['id' => 1] + $userData;
        
        return UserResource::make($user);
    }

    /**
     * Return collection with assignment pattern
     * Tests: Assignment before return
     */
    public function getUsersAssigned()
    {
        $users = [['id' => 1, 'name' => 'Test']];
        $collection = UserResource::collection($users);
        
        return response()->json($collection);
    }

    /**
     * Multiple resource types in one method
     * Tests: Multiple resource classes detected
     */
    public function mixed($userId, $postId)
    {
        $user = ['id' => $userId, 'name' => 'User'];
        $post = ['id' => $postId, 'title' => 'Post'];
        
        $userResource = new UserResource($user);
        $postResource = new PostResource($post);
        
        return response()->json([
            'user' => $userResource,
            'post' => $postResource,
        ]);
    }

    /**
     * Conditional resource usage
     * Tests: Resource usage within conditional blocks
     */
    public function conditional(Request $request, $id)
    {
        $user = ['id' => $id, 'name' => 'User'];
        
        if ($request->has('full')) {
            return new UserResource($user);
        }
        
        return UserResource::collection([$user]);
    }

    /**
     * Resource with status code
     * Tests: Resource + HTTP status combination
     */
    public function createWithStatus(Request $request)
    {
        $data = $request->json();
        $user = ['id' => 1] + $data;
        
        return response(new UserResource($user), 201);
    }

    /**
     * Complex resource instantiation
     * Tests: Resource with complex data expressions
     */
    public function complex($id)
    {
        $user = $this->findUser($id);
        $resource = new UserResource($user);
        
        return $resource->response()->status(200);
    }

    /**
     * Custom collection class
     * Tests: Custom collection vs standard collection
     */
    public function customCollection()
    {
        $users = [['id' => 1], ['id' => 2]];
        
        return new UserCollection($users);
    }

    /**
     * Nested resource usage
     * Tests: Resources within other structures
     */
    public function nested($id)
    {
        $user = ['id' => $id, 'name' => 'User'];
        
        return response()->json([
            'data' => new UserResource($user),
            'meta' => ['count' => 1]
        ]);
    }

    private function findUser($id)
    {
        return ['id' => $id, 'name' => 'Found User'];
    }
}
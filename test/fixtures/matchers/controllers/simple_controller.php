<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Http\Response;
use App\Http\Resources\UserResource;

class SimpleController extends Controller
{
    /**
     * Display a listing of the resource.
     * Tests: Basic HTTP status detection
     */
    public function index()
    {
        return response()->json(['message' => 'Success'], 200);
    }

    /**
     * Store a newly created resource in storage.
     * Tests: Explicit HTTP status + request usage
     */
    public function store(Request $request)
    {
        $data = $request->all();
        
        // Simulate creation logic
        $user = ['id' => 1, 'name' => $data['name']];
        
        return response()->json($user, 201);
    }

    /**
     * Display the specified resource.
     * Tests: Resource usage + default status (implicit)
     */
    public function show($id)
    {
        $user = ['id' => $id, 'name' => 'Test User'];
        
        return new UserResource($user);
    }

    /**
     * Update the specified resource in storage.
     * Tests: Request input method + explicit status
     */
    public function update(Request $request, $id)
    {
        $name = $request->input('name');
        $email = $request->input('email', 'default@example.com');
        
        $user = ['id' => $id, 'name' => $name, 'email' => $email];
        
        return response($user)->status(200);
    }

    /**
     * Remove the specified resource from storage.
     * Tests: No content status
     */
    public function destroy($id)
    {
        // Simulate deletion logic
        
        return response(null, 204);
    }

    /**
     * Handle file upload
     * Tests: File upload detection
     */
    public function upload(Request $request)
    {
        $file = $request->file('avatar');
        
        if (!$file) {
            abort(400, 'No file provided');
        }
        
        return response()->json(['message' => 'File uploaded'], 201);
    }

    /**
     * Get filtered data
     * Tests: Request only/except methods
     */
    public function filtered(Request $request)
    {
        $data = $request->only(['name', 'email']);
        $cleanData = $request->except(['password', '_token']);
        
        return response()->json(['filtered' => $data, 'clean' => $cleanData]);
    }

    /**
     * Handle JSON request
     * Tests: JSON content type detection
     */
    public function jsonHandler(Request $request)
    {
        $jsonData = $request->json();
        $specificValue = $request->json('key');
        
        return response()->json(['received' => $jsonData]);
    }
}
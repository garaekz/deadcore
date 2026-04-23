<?php

namespace App\Http\Controllers;

use App\Models\Post;
use Illuminate\Http\Request;
use Illuminate\Http\Response;

class PostController extends Controller
{
    /**
     * Display a listing of the resource.
     */
    public function index(Request $request)
    {
        $posts = Post::published()
            ->byActiveUsers()
            ->with(['user', 'tags', 'comments'])
            ->when($request->tags, function ($query, $tags) {
                return $query->withTags(explode(',', $tags));
            })
            ->latest()
            ->paginate(15);

        return response()->json($posts);
    }

    /**
     * Store a newly created resource in storage.
     */
    public function store(Request $request)
    {
        $validated = $request->validate([
            'title' => 'required|string|max:255',
            'content' => 'required|string',
            'status' => 'required|in:draft,published',
            'tags' => 'array',
            'tags.*' => 'exists:tags,id'
        ]);

        $post = auth()->user()->posts()->create($validated);

        if ($request->has('tags')) {
            $tagData = collect($request->tags)->mapWithKeys(function ($tagId) {
                return [$tagId => ['relevance_score' => rand(1, 100)]];
            });
            $post->tags()->attach($tagData);
        }

        return response()->json($post->load(['user', 'tags']), 201);
    }

    /**
     * Display the specified resource.
     */
    public function show(Post $post)
    {
        return response()->json($post->load(['user', 'tags', 'comments.user', 'image']));
    }

    /**
     * Update the specified resource in storage.
     */
    public function update(Request $request, Post $post)
    {
        $this->authorize('update', $post);

        $validated = $request->validate([
            'title' => 'sometimes|required|string|max:255',
            'content' => 'sometimes|required|string',
            'status' => 'sometimes|required|in:draft,published',
            'tags' => 'array',
            'tags.*' => 'exists:tags,id'
        ]);

        $post->update($validated);

        if ($request->has('tags')) {
            $tagData = collect($request->tags)->mapWithKeys(function ($tagId) {
                return [$tagId => ['relevance_score' => rand(1, 100)]];
            });
            $post->tags()->sync($tagData);
        }

        return response()->json($post->fresh(['user', 'tags']));
    }

    /**
     * Remove the specified resource from storage.
     */
    public function destroy(Post $post)
    {
        $this->authorize('delete', $post);
        
        $post->delete();
        
        return response()->noContent();
    }
}
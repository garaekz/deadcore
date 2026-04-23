<?php

namespace App\Http\Controllers;

use App\Models\User;
use App\Models\Post;
use Illuminate\Http\Request;

class UserController extends Controller
{
    public function index(Request $request)
    {
        // Direct scope calls with prefix
        $activeUsers = User::scopeActive()->get();
        $publishedPosts = Post::scopePublished()->get();
        
        // Scope calls without prefix (more common usage)
        $users = User::query()->active()->get();
        $posts = Post::query()->published()->recent(30)->get();
        
        // Chained scope calls
        $filteredUsers = User::query()
            ->active()
            ->ofType('admin')
            ->withPosts()
            ->get();
        
        // Scope with parameters
        $recentPosts = Post::recent(7)->published()->get();
        $adminUsers = User::ofType('admin')->active()->get();
        
        // Dynamic query building with scopes
        $query = User::query();
        
        if ($request->has('active')) {
            $query->active();
        }
        
        if ($request->has('type')) {
            $query->ofType($request->type);
        }
        
        $users = $query->get();
        
        return response()->json($users);
    }
    
    public function activeUsers()
    {
        // Multiple ways to call the same scope
        $users1 = User::active()->get();
        $users2 = User::query()->active()->get();
        $users3 = User::where('id', '>', 0)->active()->get();
        
        return $users1;
    }
    
    public function complexQueries()
    {
        // Scope in where subqueries
        $posts = Post::whereHas('author', function ($query) {
            $query->active();
        })->published()->get();
        
        // Scope with joins
        $users = User::join('posts', 'users.id', '=', 'posts.user_id')
                    ->active()
                    ->select('users.*')
                    ->distinct()
                    ->get();
        
        return compact('posts', 'users');
    }
}
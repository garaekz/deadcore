<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;

class Author extends Model
{
    protected $fillable = ['name', 'email', 'active'];

    /**
     * Relationship with scopes applied.
     */
    public function publishedPosts(): HasMany
    {
        return $this->hasMany(Post::class)->published();
    }

    /**
     * Relationship with multiple scopes.
     */
    public function recentActivePosts(): HasMany
    {
        return $this->hasMany(Post::class)
                    ->active()
                    ->recent(30);
    }

    /**
     * Relationship with parameterized scope.
     */
    public function postsOfType(string $type): HasMany
    {
        return $this->hasMany(Post::class)->ofType($type);
    }

    /**
     * Many-to-many with scopes.
     */
    public function activeCategories(): BelongsToMany
    {
        return $this->belongsToMany(Category::class)
                    ->active()
                    ->orderBy('name');
    }

    /**
     * Local scope for authors.
     */
    public function scopeActive(Builder $query): Builder
    {
        return $query->where('active', true);
    }

    /**
     * Local scope with relationship constraints.
     */
    public function scopeWithPublishedPosts(Builder $query): Builder
    {
        return $query->whereHas('posts', function ($q) {
            $q->published();
        });
    }
}

class Category extends Model
{
    protected $fillable = ['name', 'active', 'type'];

    /**
     * Posts relationship with scope.
     */
    public function activePosts(): HasMany
    {
        return $this->hasMany(Post::class)->active();
    }

    /**
     * Scope for active categories.
     */
    public function scopeActive(Builder $query): Builder
    {
        return $query->where('active', true);
    }

    /**
     * Scope for category type.
     */
    public function scopeOfType(Builder $query, string $type): Builder
    {
        return $query->where('type', $type);
    }
}

class Post extends Model
{
    protected $fillable = ['title', 'content', 'status', 'active', 'author_id'];

    /**
     * Author relationship.
     */
    public function author()
    {
        return $this->belongsTo(Author::class);
    }

    /**
     * Categories with scope constraints.
     */
    public function activeCategories(): BelongsToMany
    {
        return $this->belongsToMany(Category::class)->active();
    }

    /**
     * Local scopes.
     */
    public function scopeActive(Builder $query): Builder
    {
        return $query->where('active', true);
    }

    public function scopePublished(Builder $query): Builder
    {
        return $query->where('status', 'published');
    }

    public function scopeRecent(Builder $query, int $days = 30): Builder
    {
        return $query->where('created_at', '>=', now()->subDays($days));
    }

    public function scopeOfType(Builder $query, string $type): Builder
    {
        return $query->where('type', $type);
    }

    /**
     * Scope that uses relationship data.
     */
    public function scopeByActiveAuthor(Builder $query): Builder
    {
        return $query->whereHas('author', function ($q) {
            $q->active();
        });
    }
}
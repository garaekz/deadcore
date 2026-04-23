<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;
use Illuminate\Database\Eloquent\Relations\MorphToMany;

class Tag extends Model
{
    use HasFactory;

    /**
     * The attributes that are mass assignable.
     */
    protected $fillable = [
        'name',
        'slug',
    ];

    /**
     * Get all of the posts that are assigned this tag.
     */
    public function posts(): BelongsToMany
    {
        return $this->belongsToMany(Post::class)
            ->withPivot('relevance_score', 'created_at')
            ->withTimestamps();
    }

    /**
     * Get all of the videos that are assigned this tag.
     */
    public function videos(): MorphToMany
    {
        return $this->morphedByMany(Video::class, 'taggable')
            ->withPivot('relevance_score')
            ->withTimestamps();
    }

    /**
     * Scope a query to only include popular tags.
     */
    public function scopePopular($query)
    {
        return $query->withCount(['posts', 'videos'])
            ->having('posts_count', '>', 10)
            ->orHaving('videos_count', '>', 5);
    }
}
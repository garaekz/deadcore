<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Casts\Attribute;
use Illuminate\Support\Facades\Storage;
use Carbon\Carbon;

/**
 * Test fixture combining modern attributes, legacy accessors/mutators, and casts.
 * Demonstrates how different attribute patterns can coexist in a single model.
 */
class Article extends Model
{
    protected $fillable = [
        'title', 'slug', 'content', 'excerpt', 'author_id', 
        'published_at', 'is_featured', 'view_count', 'metadata'
    ];

    /**
     * Cast definitions for automatic type conversion.
     */
    protected $casts = [
        'published_at' => 'datetime',
        'is_featured' => 'boolean',
        'view_count' => 'integer',
        'metadata' => 'array',
        'tags' => 'json',
        'settings' => 'encrypted:array',
    ];

    // ========================================
    // Modern Attributes (Laravel 9+)
    // ========================================

    /**
     * Modern attribute for title with automatic formatting.
     */
    public function title(): Attribute
    {
        return Attribute::make(
            get: fn ($value) => ucwords(strtolower($value)),
            set: fn ($value) => trim(strip_tags($value))
        );
    }

    /**
     * Modern read-only attribute for word count.
     */
    public function wordCount(): Attribute
    {
        return Attribute::make(
            get: fn ($value, $attributes) => str_word_count(strip_tags($attributes['content'] ?? ''))
        );
    }

    /**
     * Modern attribute combining casts with logic.
     */
    public function publishedStatus(): Attribute
    {
        return Attribute::make(
            get: fn ($value, $attributes) => $attributes['published_at'] && 
                $attributes['published_at']->isPast() ? 'published' : 'draft'
        );
    }

    /**
     * Modern attribute for reading time estimation.
     */
    public function readingTime(): Attribute
    {
        return Attribute::make(
            get: function ($value, $attributes) {
                $wordCount = str_word_count(strip_tags($attributes['content'] ?? ''));
                $minutes = ceil($wordCount / 200); // Average reading speed
                return $minutes . ' min read';
            }
        );
    }

    // ========================================
    // Legacy Accessors (Pre-Laravel 9)
    // ========================================

    /**
     * Legacy accessor for URL generation.
     */
    public function getUrlAttribute()
    {
        return route('articles.show', ['slug' => $this->slug]);
    }

    /**
     * Legacy accessor for excerpt with fallback.
     */
    public function getExcerptAttribute($value)
    {
        if (!empty($value)) {
            return $value;
        }

        // Generate excerpt from content if none exists
        $content = strip_tags($this->content);
        return strlen($content) > 150 
            ? substr($content, 0, 150) . '...' 
            : $content;
    }

    /**
     * Legacy accessor for featured image URL.
     */
    public function getFeaturedImageUrlAttribute()
    {
        $imagePath = $this->metadata['featured_image'] ?? null;
        return $imagePath ? Storage::url($imagePath) : null;
    }

    /**
     * Legacy accessor for human-readable publish date.
     */
    public function getPublishedAtHumanAttribute()
    {
        return $this->published_at?->diffForHumans();
    }

    /**
     * Legacy accessor for author display name.
     */
    public function getAuthorNameAttribute()
    {
        return $this->author?->name ?? 'Unknown Author';
    }

    // ========================================
    // Legacy Mutators (Pre-Laravel 9)
    // ========================================

    /**
     * Legacy mutator for slug generation.
     */
    public function setSlugAttribute($value)
    {
        if (empty($value) && !empty($this->title)) {
            $value = $this->title;
        }
        
        $this->attributes['slug'] = strtolower(
            preg_replace('/[^A-Za-z0-9-]+/', '-', $value)
        );
    }

    /**
     * Legacy mutator for content sanitization.
     */
    public function setContentAttribute($value)
    {
        // Allow specific HTML tags for rich content
        $allowedTags = '<p><br><strong><em><ul><ol><li><a><h1><h2><h3><blockquote>';
        $this->attributes['content'] = strip_tags($value, $allowedTags);
    }

    /**
     * Legacy mutator for view count increment.
     */
    public function setViewCountAttribute($value)
    {
        // Ensure view count only increases
        $this->attributes['view_count'] = max($this->view_count ?? 0, intval($value));
    }

    // ========================================
    // Relationships and Scopes
    // ========================================

    public function author()
    {
        return $this->belongsTo(User::class, 'author_id');
    }

    public function comments()
    {
        return $this->hasMany(Comment::class);
    }

    public function tags()
    {
        return $this->belongsToMany(Tag::class);
    }

    public function scopePublished($query)
    {
        return $query->whereNotNull('published_at')
                    ->where('published_at', '<=', now());
    }

    public function scopeFeatured($query)
    {
        return $query->where('is_featured', true);
    }

    public function scopePopular($query)
    {
        return $query->where('view_count', '>', 1000);
    }
}
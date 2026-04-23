<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphTo;
use Illuminate\Database\Eloquent\Relations\MorphOne;
use Illuminate\Database\Eloquent\Relations\MorphMany;

/**
 * Test fixture demonstrating basic polymorphic relationship patterns:
 * - morphTo() inverse polymorphic relationships
 * - morphOne() one-to-one polymorphic relationships
 * - morphMany() one-to-many polymorphic relationships
 */

// Model that owns polymorphic relationship (morphTo)
class Comment extends Model
{
    protected $fillable = ['body', 'commentable_id', 'commentable_type'];
    
    /**
     * Get the parent commentable model (post, video, etc.)
     */
    public function commentable(): MorphTo
    {
        return $this->morphTo();
    }
    
    /**
     * Alternative morphTo with custom name
     */
    public function parent(): MorphTo
    {
        return $this->morphTo('commentable');
    }
    
    /**
     * MorphTo with explicit type and id columns
     */
    public function target(): MorphTo
    {
        return $this->morphTo('target', 'target_type', 'target_id');
    }
}

// Model providing polymorphic relationship (morphMany)
class Post extends Model
{
    protected $fillable = ['title', 'content', 'user_id'];
    
    /**
     * Get all comments for this post
     */
    public function comments(): MorphMany
    {
        return $this->morphMany(Comment::class, 'commentable');
    }
    
    /**
     * Get the post's image (one-to-one polymorphic)
     */
    public function image(): MorphOne
    {
        return $this->morphOne(Image::class, 'imageable');
    }
    
    /**
     * Get all images for this post (one-to-many polymorphic) 
     */
    public function images(): MorphMany
    {
        return $this->morphMany(Image::class, 'imageable');
    }
}

// Another model providing polymorphic relationship
class Video extends Model
{
    protected $fillable = ['title', 'url', 'duration'];
    
    /**
     * Get all comments for this video
     */
    public function comments(): MorphMany
    {
        return $this->morphMany(Comment::class, 'commentable');
    }
    
    /**
     * Get the video's thumbnail image
     */
    public function thumbnail(): MorphOne
    {
        return $this->morphOne(Image::class, 'imageable');
    }
}

// Model for polymorphic image relationship
class Image extends Model
{
    protected $fillable = ['path', 'alt_text', 'imageable_id', 'imageable_type'];
    
    /**
     * Get the parent imageable model (post, video, user, etc.)
     */
    public function imageable(): MorphTo
    {
        return $this->morphTo();
    }
}

// User model with polymorphic relationships
class User extends Model
{
    protected $fillable = ['name', 'email', 'password'];
    
    /**
     * Get all comments made by this user
     */
    public function comments(): MorphMany
    {
        return $this->morphMany(Comment::class, 'commentable');
    }
    
    /**
     * Get the user's profile image
     */
    public function avatar(): MorphOne
    {
        return $this->morphOne(Image::class, 'imageable');
    }
    
    /**
     * Get all posts by this user
     */
    public function posts()
    {
        return $this->hasMany(Post::class);
    }
}

// Model demonstrating multiple morphTo relationships
class Attachment extends Model
{
    protected $fillable = ['filename', 'mime_type', 'size'];
    
    /**
     * Get the attachable model (post, comment, message, etc.)
     */
    public function attachable(): MorphTo
    {
        return $this->morphTo();
    }
    
    /**
     * Get the uploader (user who uploaded this attachment)
     */
    public function uploader(): MorphTo
    {
        return $this->morphTo('uploader', 'uploader_type', 'uploader_id');
    }
}

// Model with polymorphic relationship using custom foreign key
class Tag extends Model
{
    protected $fillable = ['name'];
    
    /**
     * Get the parent taggable model with custom foreign key
     */
    public function taggable(): MorphTo
    {
        return $this->morphTo('taggable', 'taggable_type', 'taggable_id');
    }
}

// Model providing taggable polymorphic relationship
class Article extends Model
{
    protected $fillable = ['title', 'body', 'published_at'];
    
    /**
     * Get all tags for this article
     */
    public function tags(): MorphMany
    {
        return $this->morphMany(Tag::class, 'taggable');
    }
    
    /**
     * Get the featured image for this article
     */
    public function featuredImage(): MorphOne
    {
        return $this->morphOne(Image::class, 'imageable');
    }
    
    /**
     * Get all attachments for this article
     */
    public function attachments(): MorphMany
    {
        return $this->morphMany(Attachment::class, 'attachable');
    }
}
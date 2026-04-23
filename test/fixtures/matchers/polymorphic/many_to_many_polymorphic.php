<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphToMany;
use Illuminate\Database\Eloquent\Relations\MorphedByMany;

/**
 * Test fixture demonstrating many-to-many polymorphic relationship patterns:
 * - morphToMany() relationships
 * - morphedByMany() inverse relationships  
 * - Custom pivot tables and columns
 * - Polymorphic many-to-many with timestamps and additional data
 * - Complex many-to-many polymorphic scenarios
 */

// Tag model that can be attached to multiple model types
class Tag extends Model
{
    protected $fillable = ['name', 'slug', 'color'];
    
    /**
     * Get all posts that have this tag
     */
    public function posts(): MorphedByMany
    {
        return $this->morphedByMany(Post::class, 'taggable');
    }
    
    /**
     * Get all videos that have this tag
     */
    public function videos(): MorphedByMany
    {
        return $this->morphedByMany(Video::class, 'taggable');
    }
    
    /**
     * Get all articles that have this tag
     */
    public function articles(): MorphedByMany
    {
        return $this->morphedByMany(Article::class, 'taggable');
    }
    
    /**
     * Get all products that have this tag
     */
    public function products(): MorphedByMany
    {
        return $this->morphedByMany(Product::class, 'taggable');
    }
    
    /**
     * Get all users that follow this tag
     */
    public function followers(): MorphedByMany
    {
        return $this->morphedByMany(User::class, 'taggable', 'tag_follows');
    }
}

// Post model with many-to-many polymorphic relationships
class Post extends Model
{
    protected $fillable = ['title', 'content', 'status', 'user_id'];
    
    /**
     * Get all tags for this post
     */
    public function tags(): MorphToMany
    {
        return $this->morphToMany(Tag::class, 'taggable');
    }
    
    /**
     * Get all categories for this post (different from tags)
     */
    public function categories(): MorphToMany
    {
        return $this->morphToMany(Category::class, 'categorizable');
    }
    
    /**
     * Get all users who bookmarked this post
     */
    public function bookmarkedBy(): MorphToMany
    {
        return $this->morphToMany(User::class, 'bookmarkable', 'bookmarks')
            ->withTimestamps()
            ->withPivot('notes', 'is_favorite');
    }
    
    /**
     * Get all permissions for this post
     */
    public function permissions(): MorphToMany
    {
        return $this->morphToMany(Permission::class, 'permissionable', 'model_permissions')
            ->withTimestamps()
            ->withPivot('granted_by', 'expires_at');
    }
}

// Video model with polymorphic many-to-many relationships
class Video extends Model
{
    protected $fillable = ['title', 'url', 'duration', 'description'];
    
    /**
     * Get all tags for this video
     */
    public function tags(): MorphToMany
    {
        return $this->morphToMany(Tag::class, 'taggable');
    }
    
    /**
     * Get all categories for this video
     */
    public function categories(): MorphToMany
    {
        return $this->morphToMany(Category::class, 'categorizable')
            ->withTimestamps()
            ->withPivot('weight', 'is_primary');
    }
    
    /**
     * Get all users who liked this video
     */
    public function likedBy(): MorphToMany
    {
        return $this->morphToMany(User::class, 'likeable', 'likes')
            ->withTimestamps();
    }
    
    /**
     * Get all playlists that contain this video
     */
    public function playlists(): MorphToMany
    {
        return $this->morphToMany(Playlist::class, 'playlistable')
            ->withPivot('position', 'added_by')
            ->withTimestamps()
            ->orderByPivot('position');
    }
}

// User model with multiple polymorphic many-to-many relationships
class User extends Model
{
    protected $fillable = ['name', 'email', 'password'];
    
    /**
     * Get all posts bookmarked by this user
     */
    public function bookmarkedPosts(): MorphToMany
    {
        return $this->morphToMany(Post::class, 'bookmarkable', 'bookmarks')
            ->withTimestamps()
            ->withPivot('notes', 'is_favorite');
    }
    
    /**
     * Get all videos bookmarked by this user
     */
    public function bookmarkedVideos(): MorphToMany
    {
        return $this->morphToMany(Video::class, 'bookmarkable', 'bookmarks')
            ->withTimestamps()
            ->withPivot('notes', 'is_favorite');
    }
    
    /**
     * Get all articles bookmarked by this user
     */
    public function bookmarkedArticles(): MorphToMany
    {
        return $this->morphToMany(Article::class, 'bookmarkable', 'bookmarks')
            ->withTimestamps()
            ->withPivot('notes', 'is_favorite');
    }
    
    /**
     * Get all tags this user follows
     */
    public function followedTags(): MorphToMany
    {
        return $this->morphToMany(Tag::class, 'taggable', 'tag_follows')
            ->withTimestamps()
            ->withPivot('notification_level', 'followed_since');
    }
    
    /**
     * Get all videos this user liked
     */
    public function likedVideos(): MorphToMany
    {
        return $this->morphToMany(Video::class, 'likeable', 'likes')
            ->withTimestamps();
    }
    
    /**
     * Get all roles assigned to this user (polymorphic)
     */
    public function roles(): MorphToMany
    {
        return $this->morphToMany(Role::class, 'roleable', 'model_roles')
            ->withTimestamps()
            ->withPivot('granted_by', 'expires_at', 'scope');
    }
}

// Category model for categorizing different content types
class Category extends Model
{
    protected $fillable = ['name', 'slug', 'description', 'parent_id'];
    
    /**
     * Get all posts in this category
     */
    public function posts(): MorphedByMany
    {
        return $this->morphedByMany(Post::class, 'categorizable');
    }
    
    /**
     * Get all videos in this category
     */
    public function videos(): MorphedByMany
    {
        return $this->morphedByMany(Video::class, 'categorizable')
            ->withPivot('weight', 'is_primary');
    }
    
    /**
     * Get all articles in this category
     */
    public function articles(): MorphedByMany
    {
        return $this->morphedByMany(Article::class, 'categorizable')
            ->withTimestamps()
            ->withPivot('featured', 'position');
    }
    
    /**
     * Get all products in this category
     */
    public function products(): MorphedByMany
    {
        return $this->morphedByMany(Product::class, 'categorizable')
            ->withTimestamps()
            ->withPivot('is_featured', 'sort_order');
    }
}

// Role model with polymorphic many-to-many for different entity types
class Role extends Model
{
    protected $fillable = ['name', 'guard_name', 'description'];
    
    /**
     * Get all users with this role
     */
    public function users(): MorphedByMany
    {
        return $this->morphedByMany(User::class, 'roleable', 'model_roles')
            ->withTimestamps()
            ->withPivot('granted_by', 'expires_at', 'scope');
    }
    
    /**
     * Get all teams with this role
     */
    public function teams(): MorphedByMany
    {
        return $this->morphedByMany(Team::class, 'roleable', 'model_roles')
            ->withTimestamps()
            ->withPivot('granted_by', 'expires_at', 'scope');
    }
    
    /**
     * Get all organizations with this role
     */
    public function organizations(): MorphedByMany
    {
        return $this->morphedByMany(Organization::class, 'roleable', 'model_roles')
            ->withTimestamps()
            ->withPivot('granted_by', 'expires_at', 'scope');
    }
}

// Permission model with polymorphic many-to-many capabilities
class Permission extends Model
{
    protected $fillable = ['name', 'guard_name', 'description'];
    
    /**
     * Get all posts with this permission
     */
    public function posts(): MorphedByMany
    {
        return $this->morphedByMany(Post::class, 'permissionable', 'model_permissions')
            ->withTimestamps()
            ->withPivot('granted_by', 'expires_at');
    }
    
    /**
     * Get all users with this permission
     */
    public function users(): MorphedByMany
    {
        return $this->morphedByMany(User::class, 'permissionable', 'model_permissions')
            ->withTimestamps()
            ->withPivot('granted_by', 'expires_at');
    }
    
    /**
     * Get all teams with this permission
     */
    public function teams(): MorphedByMany
    {
        return $this->morphedByMany(Team::class, 'permissionable', 'model_permissions')
            ->withTimestamps()
            ->withPivot('granted_by', 'expires_at');
    }
}

// Playlist model demonstrating complex many-to-many polymorphic relationships
class Playlist extends Model
{
    protected $fillable = ['name', 'description', 'user_id', 'is_public'];
    
    /**
     * Get all videos in this playlist
     */
    public function videos(): MorphedByMany
    {
        return $this->morphedByMany(Video::class, 'playlistable')
            ->withPivot('position', 'added_by')
            ->withTimestamps()
            ->orderByPivot('position');
    }
    
    /**
     * Get all podcasts in this playlist
     */
    public function podcasts(): MorphedByMany
    {
        return $this->morphedByMany(Podcast::class, 'playlistable')
            ->withPivot('position', 'added_by')
            ->withTimestamps()
            ->orderByPivot('position');
    }
    
    /**
     * Get all audio files in this playlist
     */
    public function audioFiles(): MorphedByMany
    {
        return $this->morphedByMany(AudioFile::class, 'playlistable')
            ->withPivot('position', 'added_by', 'start_time', 'end_time')
            ->withTimestamps()
            ->orderByPivot('position');
    }
}

// Team model with polymorphic many-to-many relationships
class Team extends Model
{
    protected $fillable = ['name', 'description', 'owner_id'];
    
    /**
     * Get all roles for this team
     */
    public function roles(): MorphToMany
    {
        return $this->morphToMany(Role::class, 'roleable', 'model_roles')
            ->withTimestamps()
            ->withPivot('granted_by', 'expires_at', 'scope');
    }
    
    /**
     * Get all permissions for this team
     */
    public function permissions(): MorphToMany
    {
        return $this->morphToMany(Permission::class, 'permissionable', 'model_permissions')
            ->withTimestamps()
            ->withPivot('granted_by', 'expires_at');
    }
    
    /**
     * Get all tags this team follows
     */
    public function tags(): MorphToMany
    {
        return $this->morphToMany(Tag::class, 'taggable', 'team_tags')
            ->withTimestamps()
            ->withPivot('added_by', 'is_primary');
    }
}

// Article model with comprehensive polymorphic many-to-many relationships
class Article extends Model
{
    protected $fillable = ['title', 'content', 'published_at', 'author_id'];
    
    /**
     * Get all tags for this article
     */
    public function tags(): MorphToMany
    {
        return $this->morphToMany(Tag::class, 'taggable');
    }
    
    /**
     * Get all categories for this article
     */
    public function categories(): MorphToMany
    {
        return $this->morphToMany(Category::class, 'categorizable')
            ->withTimestamps()
            ->withPivot('featured', 'position');
    }
    
    /**
     * Get all users who bookmarked this article
     */
    public function bookmarkedBy(): MorphToMany
    {
        return $this->morphToMany(User::class, 'bookmarkable', 'bookmarks')
            ->withTimestamps()
            ->withPivot('notes', 'is_favorite');
    }
    
    /**
     * Get related articles through shared tags
     */
    public function relatedThroughTags(): MorphToMany
    {
        return $this->morphToMany(self::class, 'taggable', 'taggables', 'taggable_id', 'taggable_id')
            ->where('taggable_type', self::class)
            ->where('taggables.taggable_id', '!=', $this->id);
    }
}

// Product model with polymorphic many-to-many relationships
class Product extends Model
{
    protected $fillable = ['name', 'description', 'price', 'sku'];
    
    /**
     * Get all tags for this product
     */
    public function tags(): MorphToMany
    {
        return $this->morphToMany(Tag::class, 'taggable');
    }
    
    /**
     * Get all categories for this product
     */
    public function categories(): MorphToMany
    {
        return $this->morphToMany(Category::class, 'categorizable')
            ->withTimestamps()
            ->withPivot('is_featured', 'sort_order');
    }
    
    /**
     * Get all collections this product belongs to
     */
    public function collections(): MorphToMany
    {
        return $this->morphToMany(Collection::class, 'collectable')
            ->withTimestamps()
            ->withPivot('position', 'is_featured');
    }
}
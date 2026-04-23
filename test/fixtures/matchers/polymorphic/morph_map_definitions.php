<?php

namespace App\Providers;

use App\Models\Post;
use App\Models\Video;
use App\Models\User;
use App\Models\Article;
use App\Models\Product;
use App\Models\Comment;
use App\Models\Image;
use Illuminate\Support\ServiceProvider;
use Illuminate\Database\Eloquent\Relations\Relation;

/**
 * Test fixture demonstrating morph map definitions and global type mappings.
 * Shows various patterns for defining polymorphic type mappings using Relation::morphMap().
 */
class AppServiceProvider extends ServiceProvider
{
    /**
     * Bootstrap any application services.
     */
    public function boot()
    {
        // Basic morph map definition - most common pattern
        Relation::morphMap([
            'post' => Post::class,
            'video' => Video::class, 
            'user' => User::class,
            'article' => Article::class,
        ]);
        
        // Additional morph map for different polymorphic relationships
        $this->registerImageableMorphMap();
        
        // Register taggable morph map
        $this->registerTaggableMorphMap();
        
        // Dynamic morph map based on configuration
        $this->registerDynamicMorphMap();
    }
    
    /**
     * Register morph map for imageable polymorphic relationships
     */
    protected function registerImageableMorphMap()
    {
        Relation::morphMap([
            'post' => 'App\Models\Post',
            'video' => 'App\Models\Video',
            'user' => 'App\Models\User',
            'product' => Product::class,
        ]);
    }
    
    /**
     * Register morph map for taggable relationships
     */
    protected function registerTaggableMorphMap()
    {
        // Using array merge for extending existing mappings
        $existingMap = Relation::morphMap() ?: [];
        
        $taggableMap = [
            'article' => Article::class,
            'post' => Post::class,
            'video' => Video::class,
            'product' => Product::class,
        ];
        
        Relation::morphMap(array_merge($existingMap, $taggableMap));
    }
    
    /**
     * Register dynamic morph map based on config
     */
    protected function registerDynamicMorphMap()
    {
        $morphMap = config('database.morph_map', []);
        
        // Default mappings if not configured
        if (empty($morphMap)) {
            $morphMap = [
                'post' => Post::class,
                'article' => Article::class,
                'video' => Video::class,
                'user' => User::class,
                'comment' => Comment::class,
                'image' => Image::class,
            ];
        }
        
        Relation::morphMap($morphMap);
    }
}

// Alternative service provider pattern
class DatabaseServiceProvider extends ServiceProvider
{
    /**
     * Register morph maps in separate service provider
     */
    public function boot()
    {
        // Morph map with custom aliases
        Relation::morphMap([
            'blog_post' => 'App\Models\Post',
            'news_article' => 'App\Models\Article',
            'media_video' => 'App\Models\Video',
            'site_user' => 'App\Models\User',
        ]);
    }
}

// Example of morph map in model boot method
namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\Relation;

class BaseModel extends Model
{
    /**
     * Boot the model and set up morph map
     */
    protected static function boot()
    {
        parent::boot();
        
        // Register morph map in model boot
        static::registerMorphMap();
    }
    
    /**
     * Register polymorphic type mappings
     */
    protected static function registerMorphMap()
    {
        Relation::morphMap([
            'content_post' => Post::class,
            'content_article' => Article::class,
            'media_video' => Video::class,
            'user_profile' => User::class,
        ]);
    }
}

// Configuration-based morph map
class ConfigurableMorphMap
{
    /**
     * Load morph map from configuration file
     */
    public static function load()
    {
        // Simulate loading from config file
        $morphTypes = [
            'commentables' => [
                'post' => Post::class,
                'video' => Video::class,
                'article' => Article::class,
            ],
            'imageables' => [
                'user' => User::class,
                'post' => Post::class,
                'product' => Product::class,
            ],
            'taggables' => [
                'post' => Post::class,
                'article' => Article::class,
                'video' => Video::class,
            ],
        ];
        
        // Flatten and register all types
        $flatMap = [];
        foreach ($morphTypes as $relationship => $types) {
            $flatMap = array_merge($flatMap, $types);
        }
        
        Relation::morphMap($flatMap);
    }
}

// Example of conditional morph map registration
class ConditionalMorphMap extends ServiceProvider
{
    public function boot()
    {
        // Only register morph map in production
        if (app()->environment('production')) {
            Relation::morphMap([
                'post' => Post::class,
                'article' => Article::class,
            ]);
        } else {
            // Development mappings with additional types
            Relation::morphMap([
                'post' => Post::class,
                'article' => Article::class,
                'test_model' => 'App\Models\TestModel',
                'demo_content' => 'App\Models\DemoContent',
            ]);
        }
    }
}

// Model with custom morph type override
class CustomMorphModel extends Model
{
    /**
     * Override the morph type for this model
     */
    public function getMorphClass()
    {
        return 'custom_type';
    }
}

// Multiple morph map registrations in sequence
class MultipleRegistrations extends ServiceProvider
{
    public function boot()
    {
        // First registration
        Relation::morphMap([
            'post' => Post::class,
            'video' => Video::class,
        ]);
        
        // Second registration (extends/overwrites first)
        Relation::morphMap([
            'article' => Article::class,
            'user' => User::class,
            'post' => 'App\Models\BlogPost', // Override previous mapping
        ]);
        
        // Third registration with array merge
        $existing = Relation::morphMap();
        Relation::morphMap(array_merge($existing, [
            'product' => Product::class,
            'comment' => Comment::class,
        ]));
    }
}
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphTo;
use Illuminate\Database\Eloquent\Relations\MorphOne;
use Illuminate\Database\Eloquent\Relations\MorphMany;
use Illuminate\Database\Eloquent\Relations\MorphToMany;
use Illuminate\Database\Eloquent\Relations\MorphedByMany;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Relations\Relation;

/**
 * Test fixture demonstrating edge cases and unusual but valid polymorphic patterns:
 * - Self-referencing polymorphic relationships
 * - Conditional polymorphic relationships
 * - Dynamic polymorphic column names
 * - Polymorphic relationships with custom constraints
 * - Mixed polymorphic and regular relationship patterns
 * - Complex inheritance scenarios
 * - Performance edge cases
 */

// Self-referencing polymorphic model
class Comment extends Model
{
    protected $fillable = ['body', 'commentable_id', 'commentable_type', 'parent_id'];
    
    /**
     * Get the commentable model (post, video, or another comment)
     */
    public function commentable(): MorphTo
    {
        return $this->morphTo();
    }
    
    /**
     * Get replies to this comment (self-referencing polymorphic)
     */
    public function replies(): MorphMany
    {
        return $this->morphMany(self::class, 'commentable');
    }
    
    /**
     * Get the parent comment if this is a reply (self-referencing morphTo)
     */
    public function parentComment(): MorphTo
    {
        return $this->morphTo('commentable')
            ->where('commentable_type', self::class);
    }
    
    /**
     * Get all nested replies recursively
     */
    public function allReplies(): MorphMany
    {
        return $this->replies()->with('allReplies');
    }
}

// Model with conditional polymorphic relationships
class FlexibleContent extends Model
{
    protected $fillable = ['type', 'content', 'target_id', 'target_type', 'secondary_id', 'secondary_type'];
    
    /**
     * Get the primary target (conditional based on type)
     */
    public function target(): MorphTo
    {
        return $this->morphTo();
    }
    
    /**
     * Get secondary target (only for certain content types)
     */
    public function secondaryTarget(): MorphTo
    {
        return $this->morphTo('secondary')
            ->whereIn('type', ['comparison', 'reference', 'link']);
    }
    
    /**
     * Conditional polymorphic relationship based on content type
     */
    public function relatedContent(): MorphTo
    {
        // This would be handled in application logic, but demonstrates the pattern
        switch ($this->type) {
            case 'article':
                return $this->morphTo('target')->where('target_type', 'App\Models\Article');
            case 'product':
                return $this->morphTo('target')->where('target_type', 'App\Models\Product');
            default:
                return $this->morphTo('target');
        }
    }
}

// Model with dynamic polymorphic column names
class DynamicMorph extends Model
{
    protected $fillable = ['name', 'context'];
    
    /**
     * Get morphTo relationship with dynamic column names based on context
     */
    public function dynamicTarget(): MorphTo
    {
        $typeColumn = $this->context . '_type';
        $idColumn = $this->context . '_id';
        
        return $this->morphTo('dynamicTarget', $typeColumn, $idColumn);
    }
    
    /**
     * Alternative dynamic morphTo for different context
     */
    public function contextualTarget(): MorphTo
    {
        return $this->morphTo(
            'contextualTarget',
            'contextual_type', 
            'contextual_id'
        );
    }
}

// Model with complex polymorphic constraints
class RestrictedMorph extends Model
{
    protected $fillable = ['name', 'target_id', 'target_type', 'permissions'];
    
    protected $casts = [
        'permissions' => 'array',
    ];
    
    /**
     * Polymorphic relationship with security constraints
     */
    public function secureTarget(): MorphTo
    {
        return $this->morphTo('target')
            ->whereIn('target_type', $this->getAllowedTypes())
            ->where(function (Builder $query) {
                $query->where('is_public', true)
                      ->orWhere('created_by', auth()->id());
            });
    }
    
    /**
     * Get allowed target types based on permissions
     */
    protected function getAllowedTypes(): array
    {
        $permissions = $this->permissions ?? [];
        
        $typeMap = [
            'read_posts' => 'App\Models\Post',
            'read_articles' => 'App\Models\Article',
            'read_videos' => 'App\Models\Video',
            'read_products' => 'App\Models\Product',
        ];
        
        return array_intersect_key($typeMap, array_flip($permissions));
    }
    
    /**
     * Polymorphic relationship with time-based constraints
     */
    public function temporalTarget(): MorphTo
    {
        return $this->morphTo('target')
            ->where('created_at', '>=', now()->subDays(30))
            ->whereNotNull('published_at');
    }
}

// Model demonstrating polymorphic relationships with inheritance
class BaseContent extends Model
{
    protected $fillable = ['title', 'status', 'owner_id', 'owner_type'];
    
    /**
     * Get the content owner (User, Team, Organization, etc.)
     */
    public function owner(): MorphTo
    {
        return $this->morphTo();
    }
    
    /**
     * Get content attachments
     */
    public function attachments(): MorphMany
    {
        return $this->morphMany(Attachment::class, 'attachable');
    }
}

// Child model inheriting polymorphic relationships
class SpecialContent extends BaseContent
{
    protected $fillable = ['title', 'status', 'owner_id', 'owner_type', 'special_feature'];
    
    /**
     * Override parent's owner relationship with additional constraints
     */
    public function owner(): MorphTo
    {
        return parent::owner()
            ->whereHas('permissions', function (Builder $query) {
                $query->where('name', 'manage_special_content');
            });
    }
    
    /**
     * Additional polymorphic relationship specific to special content
     */
    public function sponsor(): MorphTo
    {
        return $this->morphTo('sponsor', 'sponsor_type', 'sponsor_id');
    }
}

// Model with polymorphic relationships using custom pivot models
class AdvancedTag extends Model
{
    protected $fillable = ['name', 'metadata'];
    
    protected $casts = [
        'metadata' => 'array',
    ];
    
    /**
     * Polymorphic many-to-many with custom pivot model
     */
    public function taggables(): MorphToMany
    {
        return $this->morphToMany(
            Post::class, 
            'taggable'
        )->using(AdvancedTagPivot::class)
         ->withPivot('weight', 'metadata', 'created_by')
         ->withTimestamps();
    }
}

// Custom pivot model for advanced polymorphic relationships
class AdvancedTagPivot extends \Illuminate\Database\Eloquent\Relations\Pivot
{
    protected $fillable = ['tag_id', 'taggable_id', 'taggable_type', 'weight', 'metadata', 'created_by'];
    
    protected $casts = [
        'metadata' => 'array',
    ];
    
    /**
     * Get the user who created this tag association
     */
    public function creator(): BelongsTo
    {
        return $this->belongsTo(User::class, 'created_by');
    }
}

// Model with performance-critical polymorphic relationships
class OptimizedMorph extends Model
{
    protected $fillable = ['name', 'target_id', 'target_type', 'cached_target_data'];
    
    protected $casts = [
        'cached_target_data' => 'array',
    ];
    
    /**
     * Polymorphic relationship with eager loading constraints
     */
    public function target(): MorphTo
    {
        return $this->morphTo()
            ->select(['id', 'name', 'title', 'created_at']) // Only load needed columns
            ->with(['tags:id,name']); // Eager load specific relationships
    }
    
    /**
     * Cached version of polymorphic relationship data
     */
    public function getCachedTargetAttribute()
    {
        if (!empty($this->cached_target_data)) {
            return $this->cached_target_data;
        }
        
        $target = $this->target;
        $this->cached_target_data = $target ? [
            'id' => $target->id,
            'type' => get_class($target),
            'name' => $target->name ?? $target->title ?? 'Unknown',
            'url' => method_exists($target, 'getUrlAttribute') ? $target->url : null,
        ] : null;
        
        $this->save();
        
        return $this->cached_target_data;
    }
}

// Model demonstrating polymorphic relationships with soft deletes
class SoftDeletableMorph extends Model
{
    use \Illuminate\Database\Eloquent\SoftDeletes;
    
    protected $fillable = ['name', 'target_id', 'target_type'];
    
    protected $dates = ['deleted_at'];
    
    /**
     * Polymorphic relationship including soft deleted records
     */
    public function target(): MorphTo
    {
        return $this->morphTo();
    }
    
    /**
     * Polymorphic relationship excluding soft deleted records
     */
    public function activeTarget(): MorphTo
    {
        return $this->morphTo('target')
            ->whereNull('deleted_at');
    }
    
    /**
     * Polymorphic relationship including only soft deleted records
     */
    public function trashedTarget(): MorphTo
    {
        return $this->morphTo('target')
            ->whereNotNull('deleted_at');
    }
}

// Model with namespace-specific polymorphic constraints
class NamespacedMorph extends Model
{
    protected $fillable = ['name', 'target_id', 'target_type', 'allowed_namespaces'];
    
    protected $casts = [
        'allowed_namespaces' => 'array',
    ];
    
    /**
     * Polymorphic relationship restricted to specific namespaces
     */
    public function target(): MorphTo
    {
        $allowedTypes = $this->getAllowedTargetTypes();
        
        return $this->morphTo()
            ->whereIn('target_type', $allowedTypes);
    }
    
    /**
     * Get allowed target types based on namespace restrictions
     */
    protected function getAllowedTargetTypes(): array
    {
        $namespaces = $this->allowed_namespaces ?? ['App\Models'];
        $allowedTypes = [];
        
        foreach ($namespaces as $namespace) {
            // This would be implemented with proper class discovery
            $allowedTypes = array_merge($allowedTypes, [
                $namespace . '\Post',
                $namespace . '\Article',
                $namespace . '\Video',
                $namespace . '\Product',
            ]);
        }
        
        return $allowedTypes;
    }
}

// Model with circular polymorphic reference detection
class CircularSafeMorph extends Model
{
    protected $fillable = ['name', 'target_id', 'target_type', 'depth'];
    
    /**
     * Polymorphic relationship with circular reference protection
     */
    public function target(): MorphTo
    {
        return $this->morphTo()
            ->where(function (Builder $query) {
                // Prevent circular references
                $query->where('target_type', '!=', self::class)
                      ->orWhere('target_id', '!=', $this->id);
            });
    }
    
    /**
     * Get the relationship chain to detect potential loops
     */
    public function getRelationshipChain($visited = []): array
    {
        if (in_array($this->id, $visited)) {
            return ['circular_reference_detected' => true];
        }
        
        $visited[] = $this->id;
        $target = $this->target;
        
        if (!$target) {
            return $visited;
        }
        
        if ($target instanceof self) {
            return $target->getRelationshipChain($visited);
        }
        
        return $visited;
    }
}

// Model with polymorphic relationships using custom type resolution
class CustomTypeMorph extends Model
{
    protected $fillable = ['name', 'target_id', 'target_type'];
    
    /**
     * Override getMorphs to use custom type resolution
     */
    public function getMorphs($name, $type, $id): array
    {
        // Custom logic to resolve morph types
        $resolvedType = $this->resolveCustomMorphType($this->{$type});
        
        return [
            $resolvedType,
            $this->{$id},
        ];
    }
    
    /**
     * Custom morph type resolution logic
     */
    protected function resolveCustomMorphType(string $type): string
    {
        // Custom mapping logic
        $customMappings = [
            'legacy_user' => User::class,
            'old_post' => Post::class,
            'archived_article' => Article::class,
        ];
        
        return $customMappings[$type] ?? $type;
    }
    
    /**
     * Polymorphic relationship using custom type resolution
     */
    public function target(): MorphTo
    {
        return $this->morphTo();
    }
}

// Model demonstrating polymorphic relationship with JSON constraints
class JsonConstrainedMorph extends Model
{
    protected $fillable = ['name', 'target_id', 'target_type', 'constraints'];
    
    protected $casts = [
        'constraints' => 'array',
    ];
    
    /**
     * Polymorphic relationship with JSON column constraints
     */
    public function target(): MorphTo
    {
        return $this->morphTo()
            ->where(function (Builder $query) {
                if (!empty($this->constraints)) {
                    foreach ($this->constraints as $key => $value) {
                        $query->whereJsonContains("metadata->{$key}", $value);
                    }
                }
            });
    }
}
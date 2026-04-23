<?php

namespace App\Models;

use App\Scopes\ActiveScope;
use App\Scopes\PublishedScope;
use App\Scopes\TenantScope;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;

class Post extends Model
{
    protected $fillable = ['title', 'content', 'status', 'active', 'tenant_id'];

    /**
     * The "booted" method of the model.
     */
    protected static function booted(): void
    {
        // Register global scopes
        static::addGlobalScope(new ActiveScope);
        static::addGlobalScope('published', new PublishedScope);
        
        // Conditional global scope registration
        if (config('app.multi_tenant')) {
            static::addGlobalScope(new TenantScope(auth()->user()?->tenant_id));
        }
        
        // Anonymous global scope
        static::addGlobalScope('visible', function (Builder $builder) {
            $builder->where('visibility', 'public');
        });
    }

    /**
     * Local scopes still work with global scopes.
     */
    public function scopeRecent(Builder $query, int $days = 30): Builder
    {
        return $query->where('created_at', '>=', now()->subDays($days));
    }

    /**
     * Scope to include only featured posts.
     */
    public function scopeFeatured(Builder $query): Builder
    {
        return $query->where('featured', true);
    }
    
    /**
     * Remove global scopes when needed.
     */
    public function scopeWithoutGlobalScopes(Builder $query): Builder
    {
        return $query->withoutGlobalScopes();
    }
    
    /**
     * Remove specific global scope.
     */
    public function scopeWithoutActiveScope(Builder $query): Builder
    {
        return $query->withoutGlobalScope(ActiveScope::class);
    }
}

class User extends Model
{
    protected $fillable = ['name', 'email', 'active', 'type'];

    /**
     * The "booted" method of the model.
     */
    protected static function booted(): void
    {
        // Global scope using closure
        static::addGlobalScope('active', function (Builder $builder) {
            $builder->where('active', true);
        });
    }

    /**
     * Local scope for user type filtering.
     */
    public function scopeOfType(Builder $query, string $type): Builder
    {
        return $query->where('type', $type);
    }

    /**
     * Scope for admin users.
     */
    public function scopeAdmins(Builder $query): Builder
    {
        return $query->where('type', 'admin');
    }
}
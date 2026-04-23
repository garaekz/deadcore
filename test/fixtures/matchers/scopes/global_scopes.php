<?php

namespace App\Scopes;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Scope;

/**
 * Global scope to automatically filter active records.
 */
class ActiveScope implements Scope
{
    /**
     * Apply the scope to a given Eloquent query builder.
     */
    public function apply(Builder $builder, Model $model): void
    {
        $builder->where('active', true);
    }
}

/**
 * Global scope for published content.
 */
class PublishedScope implements Scope
{
    /**
     * Apply the scope to a given Eloquent query builder.
     */
    public function apply(Builder $builder, Model $model): void
    {
        $builder->where('status', 'published')
                ->whereNotNull('published_at');
    }
}

/**
 * Tenant-aware global scope.
 */
class TenantScope implements Scope
{
    protected $tenantId;
    
    public function __construct($tenantId)
    {
        $this->tenantId = $tenantId;
    }
    
    /**
     * Apply the scope to a given Eloquent query builder.
     */
    public function apply(Builder $builder, Model $model): void
    {
        $builder->where('tenant_id', $this->tenantId);
    }
}

/**
 * Complex global scope with multiple conditions.
 */
class AccessibleScope implements Scope
{
    /**
     * Apply the scope to a given Eloquent query builder.
     */
    public function apply(Builder $builder, Model $model): void
    {
        $builder->where('active', true)
                ->where(function ($query) {
                    $query->whereNull('expires_at')
                          ->orWhere('expires_at', '>', now());
                });
    }
}
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;

class User extends Model
{
    /**
     * Scope a query to only include active users.
     */
    public function scopeActive(Builder $query): Builder
    {
        return $query->where('active', true);
    }

    /**
     * Scope a query to only include published posts.
     */
    public function scopePublished(Builder $query): Builder
    {
        return $query->where('status', 'published');
    }

    /**
     * Scope a query to only include users of a given type.
     */
    public function scopeOfType(Builder $query, string $type): Builder
    {
        return $query->where('type', $type);
    }

    /**
     * Scope a query for posts created in the last N days.
     */
    public function scopeRecent(Builder $query, int $days = 7): Builder
    {
        return $query->where('created_at', '>=', now()->subDays($days));
    }

    /**
     * Complex scope with multiple conditions.
     */
    public function scopeActivePublishedUsers(Builder $query): Builder
    {
        return $query->where('active', true)
                    ->where('status', 'published')
                    ->whereNotNull('email_verified_at');
    }

    /**
     * Scope with relationship constraints.
     */
    public function scopeWithPosts(Builder $query): Builder
    {
        return $query->has('posts');
    }

    /**
     * Not a scope - regular method.
     */
    public function getFullNameAttribute(): string
    {
        return $this->first_name . ' ' . $this->last_name;
    }

    /**
     * Not a scope - wrong parameter type.
     */
    public function scopeInvalid(string $query): void
    {
        // This should not be detected as a scope
    }
}
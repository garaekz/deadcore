<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;

class User extends Model
{
    /**
     * Get the roles that belong to the user with pivot fields.
     */
    public function roles(): BelongsToMany
    {
        return $this->belongsToMany(Role::class)
            ->withPivot('permissions', 'granted_at')
            ->withTimestamps();
    }

    /**
     * Get the tags for the user with pivot alias.
     */
    public function tags(): BelongsToMany
    {
        return $this->belongsToMany(Tag::class)
            ->as('tagging')
            ->withTimestamps();
    }

    /**
     * Get user's projects with detailed pivot information.
     */
    public function projects(): BelongsToMany
    {
        return $this->belongsToMany(Project::class, 'project_user')
            ->withPivot('role', 'status', 'joined_at', 'salary')
            ->withTimestamps()
            ->as('membership');
    }
}
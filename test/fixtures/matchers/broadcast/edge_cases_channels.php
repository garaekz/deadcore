<?php

/**
 * Edge cases and unusual broadcast channel patterns test fixture
 * 
 * Tests edge cases, malformed patterns, unusual syntax, and error conditions
 * that the broadcast matcher should handle gracefully
 */

use Illuminate\Support\Facades\Broadcast;

/*
|--------------------------------------------------------------------------
| Edge Cases and Unusual Patterns
|--------------------------------------------------------------------------
|
| These examples test the broadcast matcher's ability to handle unusual,
| malformed, or edge case patterns that might appear in real codebases.
|
*/

/**
 * Channel with no callback (should default to always accessible)
 * Tests: Missing callback function
 */
Broadcast::channel('no-callback-channel');

/**
 * Empty callback function
 * Tests: Callback with no return statement
 */
Broadcast::private('empty-callback', function ($user) {
    // No return statement - should be handled gracefully
});

/**
 * Callback with only comments
 * Tests: Callback containing only comments
 */
Broadcast::presence('commented-callback', function ($user) {
    // TODO: Implement authorization logic
    // return $user->hasAccess();
});

/**
 * Very long channel name
 * Tests: Unusually long channel names
 */
Broadcast::channel('very.long.channel.name.that.goes.on.and.on.with.many.segments.and.keeps.going.until.it.becomes.really.quite.lengthy.indeed', function () {
    return true;
});

/**
 * Channel with special characters
 * Tests: Special characters in channel names (should be handled carefully)
 */
Broadcast::channel('special-chars_123.test@domain', function () {
    return true;
});

/**
 * Numeric channel name
 * Tests: Pure numeric channel names
 */
Broadcast::channel('12345', function ($user) {
    return $user->hasNumericAccess();
});

/**
 * Mixed parameter types and patterns
 * Tests: Unusual parameter combinations
 */
Broadcast::channel('mixed.{id}.params.{slug}.more.{uuid}', function ($user, $id, $slug, $uuid) {
    return true;
});

/**
 * Callback with complex nested conditions
 * Tests: Deeply nested conditional logic
 */
Broadcast::private('nested-conditions', function ($user) {
    if ($user) {
        if ($user->isActive()) {
            if ($user->hasRole('member')) {
                if ($user->subscription) {
                    if ($user->subscription->isActive()) {
                        if ($user->subscription->plan !== 'free') {
                            return true;
                        }
                    }
                }
            }
        }
    }
    return false;
});

/**
 * Callback with switch statement
 * Tests: Switch-based authorization logic
 */
Broadcast::presence('role-based-switch', function ($user) {
    switch ($user->role) {
        case 'admin':
            return [
                'id' => $user->id,
                'name' => $user->name,
                'role' => 'admin',
                'permissions' => 'all',
            ];
        case 'moderator':
            return [
                'id' => $user->id,
                'name' => $user->name,
                'role' => 'moderator',
                'permissions' => 'moderate',
            ];
        case 'user':
            return [
                'id' => $user->id,
                'name' => $user->name,
                'role' => 'user',
                'permissions' => 'read',
            ];
        default:
            return false;
    }
});

/**
 * Callback with loop logic
 * Tests: Loop-based authorization
 */
Broadcast::private('loop-based-auth', function ($user, $groupIds) {
    $userGroups = $user->groups->pluck('id')->toArray();
    
    foreach (explode(',', $groupIds) as $groupId) {
        if (in_array((int) $groupId, $userGroups)) {
            return true;
        }
    }
    
    return false;
});

/**
 * Callback with ternary operator
 * Tests: Complex ternary expressions
 */
Broadcast::channel('ternary-logic', function ($user) {
    return $user ? ($user->isActive() ? ($user->hasSubscription() ? true : false) : false) : false;
});

/**
 * Callback with null coalescing
 * Tests: Null coalescing operator usage
 */
Broadcast::presence('null-coalescing', function ($user) {
    $profile = $user->profile ?? null;
    $displayName = $profile->display_name ?? $user->name ?? 'Anonymous';
    
    return [
        'id' => $user->id,
        'name' => $displayName,
        'avatar' => $profile->avatar ?? $user->avatar ?? '/default-avatar.png',
        'bio' => $profile->bio ?? '',
    ];
});

/**
 * Callback with anonymous function
 * Tests: Nested anonymous functions
 */
Broadcast::private('nested-anonymous', function ($user) {
    $checkPermission = function ($permission) use ($user) {
        return $user->permissions->contains('name', $permission);
    };
    
    return $checkPermission('channel-access');
});

/**
 * Callback with variable variables (unusual PHP pattern)
 * Tests: Variable variables and dynamic property access
 */
Broadcast::channel('variable-variables', function ($user) {
    $property = 'is_active';
    return $user->{$property} ?? false;
});

/**
 * Extremely complex presence return
 * Tests: Very large and complex return arrays
 */
Broadcast::presence('complex-presence-data', function ($user) {
    return [
        'id' => $user->id,
        'basic' => [
            'name' => $user->name,
            'email' => $user->email,
            'avatar' => $user->avatar_url,
        ],
        'profile' => [
            'bio' => $user->profile->bio ?? '',
            'location' => $user->profile->location ?? '',
            'website' => $user->profile->website ?? '',
            'social' => [
                'twitter' => $user->profile->twitter_handle ?? '',
                'github' => $user->profile->github_username ?? '',
                'linkedin' => $user->profile->linkedin_url ?? '',
            ],
        ],
        'preferences' => [
            'theme' => $user->settings->theme ?? 'light',
            'language' => $user->settings->language ?? 'en',
            'notifications' => [
                'email' => $user->settings->email_notifications ?? true,
                'push' => $user->settings->push_notifications ?? true,
                'sms' => $user->settings->sms_notifications ?? false,
            ],
        ],
        'stats' => [
            'posts_count' => $user->posts->count(),
            'followers_count' => $user->followers->count(),
            'following_count' => $user->following->count(),
            'reputation' => $user->reputation_score ?? 0,
        ],
        'meta' => [
            'last_seen' => $user->last_seen_at?->toISOString(),
            'joined_at' => $user->created_at->toISOString(),
            'timezone' => $user->timezone ?? 'UTC',
            'online_status' => $user->online_status ?? 'offline',
        ],
    ];
});

/**
 * Callback using array syntax instead of object property
 * Tests: Array-style property access
 */
Broadcast::private('array-access', function ($user) {
    return $user['active'] ?? false;
});

/**
 * Multiple return statements in different branches
 * Tests: Complex control flow with multiple returns
 */
Broadcast::presence('multi-return-branches', function ($user, $channelType) {
    if ($channelType === 'public') {
        return [
            'id' => $user->id,
            'name' => $user->public_name,
            'type' => 'public',
        ];
    }
    
    if ($channelType === 'private' && $user->hasPrivateAccess()) {
        return [
            'id' => $user->id,
            'name' => $user->name,
            'type' => 'private',
            'permissions' => $user->private_permissions,
        ];
    }
    
    if ($channelType === 'premium' && $user->isPremium()) {
        return [
            'id' => $user->id,
            'name' => $user->name,
            'type' => 'premium',
            'tier' => $user->premium_tier,
            'benefits' => $user->premium_benefits,
        ];
    }
    
    return null; // Default fallback
});

/**
 * Callback with error suppression
 * Tests: Error suppression operator usage
 */
Broadcast::channel('error-suppressed', function ($user) {
    return @$user->risky_property->might_not_exist ?? false;
});

/**
 * Callback using constants
 * Tests: PHP constants in authorization logic
 */
Broadcast::private('constant-based', function ($user) {
    define('ADMIN_ROLE_ID', 1);
    define('MODERATOR_ROLE_ID', 2);
    
    return in_array($user->role_id, [ADMIN_ROLE_ID, MODERATOR_ROLE_ID]);
});

/**
 * Malformed channel definition (missing parameters)
 * Tests: Syntax errors and malformed definitions
 */
// Broadcast::channel(); // This would cause a syntax error

/**
 * Channel with closure that uses global variables
 * Tests: Global variable usage in closures
 */
Broadcast::private('global-variables', function ($user) {
    global $allowedUsers;
    return in_array($user->id, $allowedUsers ?? []);
});

/**
 * Channel definition with trailing comma
 * Tests: Trailing comma in function calls
 */
Broadcast::channel('trailing-comma', function ($user) {
    return true;
}, /* trailing comma */);

/**
 * Very deeply nested parameter structure
 * Tests: Extreme nesting in channel names
 */
Broadcast::presence('deep.{level1}.nested.{level2}.very.{level3}.deep.{level4}.structure.{level5}', function ($user, $level1, $level2, $level3, $level4, $level5) {
    return [
        'id' => $user->id,
        'levels' => compact('level1', 'level2', 'level3', 'level4', 'level5'),
    ];
});

/**
 * Channel with callback that always throws exception
 * Tests: Exception handling in callbacks
 */
Broadcast::private('always-throws', function ($user) {
    throw new \Exception('This callback always throws an exception');
});

/**
 * Channel with callback that uses magic methods
 * Tests: Magic method usage in authorization
 */
Broadcast::channel('magic-methods', function ($user) {
    return $user->__isset('special_access') && $user->__get('special_access');
});
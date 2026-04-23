<?php

/**
 * Basic broadcast channel patterns test fixture
 * 
 * Tests basic Broadcast::channel(), Broadcast::private(), and Broadcast::presence() patterns
 * These would typically be found in routes/channels.php
 */

use Illuminate\Support\Facades\Broadcast;

/*
|--------------------------------------------------------------------------
| Broadcast Channels
|--------------------------------------------------------------------------
|
| Here you may register all of the event broadcasting channels that your
| application supports. The given channel authorization callbacks are
| used to check if an authenticated user can listen to the channel.
|
*/

/**
 * Public channel - no authentication required
 * Tests: Basic public channel detection
 */
Broadcast::channel('notifications', function () {
    return true;
});

/**
 * Public channel with simple callback
 * Tests: Public channel with return value
 */
Broadcast::channel('updates', function () {
    return ['status' => 'active'];
});

/**
 * Private channel - authentication required
 * Tests: Private channel detection and user parameter
 */
Broadcast::private('orders', function ($user) {
    return $user->hasRole('customer');
});

/**
 * Private channel with explicit return boolean
 * Tests: Private channel with boolean authorization
 */
Broadcast::private('admin-notifications', function ($user) {
    return $user->isAdmin();
});

/**
 * Private channel with model binding
 * Tests: Private channel with model access
 */
Broadcast::private('user-settings', function ($user, $model) {
    return $user->id === $model->user_id;
});

/**
 * Presence channel - shows who is online
 * Tests: Presence channel detection with user info return
 */
Broadcast::presence('chat', function ($user) {
    return [
        'id' => $user->id,
        'name' => $user->name,
        'avatar' => $user->avatar_url,
    ];
});

/**
 * Presence channel with authorization check
 * Tests: Presence channel with conditional authorization
 */
Broadcast::presence('team-chat', function ($user) {
    if ($user->team_id) {
        return [
            'id' => $user->id,
            'name' => $user->name,
            'team' => $user->team->name,
        ];
    }
    
    return false;
});

/**
 * Presence channel with null return (unauthorized)
 * Tests: Presence channel returning null/false for unauthorized users
 */
Broadcast::presence('vip-lounge', function ($user) {
    if (!$user->isPremium()) {
        return null;
    }
    
    return [
        'id' => $user->id,
        'name' => $user->name,
        'premium' => true,
    ];
});

/**
 * Public channel with no callback
 * Tests: Channel without authorization callback (always accessible)
 */
Broadcast::channel('public-announcements');

/**
 * Multiple channels defined together
 * Tests: Multiple channel definitions in sequence
 */
Broadcast::private('invoices', function ($user) {
    return $user->can('view-invoices');
});

Broadcast::private('payments', function ($user) {
    return $user->can('view-payments');
});

Broadcast::presence('support', function ($user) {
    if ($user->hasRole('support') || $user->hasRole('admin')) {
        return [
            'id' => $user->id,
            'name' => $user->name,
            'role' => $user->roles->pluck('name')->toArray(),
        ];
    }
    
    return false;
});
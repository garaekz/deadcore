<?php

/**
 * Authorization callback patterns test fixture
 * 
 * Tests various callback patterns, closure types, and authorization logic
 * commonly found in Laravel broadcast channel definitions
 */

use Illuminate\Support\Facades\Broadcast;
use App\Models\User;
use App\Models\Order;
use App\Models\Team;

/*
|--------------------------------------------------------------------------
| Authorization Callback Patterns
|--------------------------------------------------------------------------
|
| These examples demonstrate different ways to write authorization
| callbacks, from simple boolean returns to complex authorization logic.
|
*/

/**
 * Simple boolean return callback
 * Tests: Basic true/false authorization
 */
Broadcast::private('simple-auth', function ($user) {
    return true;
});

/**
 * Boolean with condition
 * Tests: Conditional boolean return
 */
Broadcast::private('admin-only', function ($user) {
    return $user->isAdmin();
});

/**
 * Method call authorization
 * Tests: Method-based authorization
 */
Broadcast::private('moderator-channel', function ($user) {
    return $user->hasRole('moderator');
});

/**
 * Multiple condition authorization
 * Tests: Complex boolean logic
 */
Broadcast::private('premium-support', function ($user) {
    return $user->isPremium() && $user->hasActiveSubscription() && !$user->isBanned();
});

/**
 * Null return for unauthorized
 * Tests: Explicit null return for denied access
 */
Broadcast::presence('exclusive-lounge', function ($user) {
    if (!$user->isVip()) {
        return null;
    }
    
    return [
        'id' => $user->id,
        'name' => $user->name,
        'tier' => $user->vip_tier,
    ];
});

/**
 * False return for unauthorized
 * Tests: Explicit false return for denied access
 */
Broadcast::presence('members-only', function ($user) {
    if (!$user->isMember()) {
        return false;
    }
    
    return [
        'id' => $user->id,
        'name' => $user->name,
        'member_since' => $user->membership_date,
    ];
});

/**
 * Early return authorization
 * Tests: Multiple return points in callback
 */
Broadcast::private('project-access', function ($user, $projectId) {
    $project = \App\Models\Project::find($projectId);
    
    if (!$project) {
        return false;
    }
    
    if ($project->owner_id === $user->id) {
        return true;
    }
    
    if ($project->collaborators->contains($user)) {
        return true;
    }
    
    return $user->hasRole('admin');
});

/**
 * Database query in callback
 * Tests: Database operations within authorization
 */
Broadcast::presence('team-workspace', function ($user, $teamId) {
    $team = Team::with('members')->find($teamId);
    
    if (!$team || !$team->members->contains($user)) {
        return null;
    }
    
    $memberRole = $team->members()
        ->where('user_id', $user->id)
        ->first()
        ->pivot->role;
    
    return [
        'id' => $user->id,
        'name' => $user->name,
        'avatar' => $user->avatar_url,
        'role' => $memberRole,
        'permissions' => $user->getTeamPermissions($team),
        'online_status' => $user->online_status,
    ];
});

/**
 * Policy-based authorization
 * Tests: Laravel policy integration
 */
Broadcast::private('document-editing', function ($user, $documentId) {
    $document = \App\Models\Document::find($documentId);
    
    return $document && $user->can('update', $document);
});

/**
 * Gate-based authorization
 * Tests: Laravel gate integration
 */
Broadcast::private('sensitive-data', function ($user) {
    return \Gate::allows('access-sensitive-data', $user);
});

/**
 * Time-based authorization
 * Tests: Authorization based on time constraints
 */
Broadcast::presence('office-hours-chat', function ($user) {
    $now = now();
    $isBusinessHours = $now->hour >= 9 && $now->hour <= 17 && $now->isWeekday();
    
    if (!$isBusinessHours && !$user->hasRole('support')) {
        return false;
    }
    
    return [
        'id' => $user->id,
        'name' => $user->name,
        'department' => $user->department,
        'available' => $user->is_available,
        'timezone' => $user->timezone,
    ];
});

/**
 * IP-based authorization
 * Tests: Authorization based on request context
 */
Broadcast::private('internal-updates', function ($user) {
    $allowedIps = ['192.168.1.0/24', '10.0.0.0/8'];
    $userIp = request()->ip();
    
    foreach ($allowedIps as $allowedIp) {
        if (\Illuminate\Support\Facades\Network::isInRange($userIp, $allowedIp)) {
            return true;
        }
    }
    
    return $user->hasRole('admin');
});

/**
 * Feature flag authorization
 * Tests: Feature flag integration in authorization
 */
Broadcast::presence('beta-features-chat', function ($user) {
    if (!\Laravel\Pennant\Feature::active('beta-chat', $user)) {
        return null;
    }
    
    return [
        'id' => $user->id,
        'name' => $user->name,
        'beta_tester' => true,
        'features' => \Laravel\Pennant\Feature::allFor($user),
    ];
});

/**
 * Subscription-based authorization
 * Tests: Subscription and billing status checks
 */
Broadcast::presence('premium-workshop', function ($user) {
    if (!$user->subscribed('premium')) {
        return false;
    }
    
    if ($user->subscription('premium')->cancelled()) {
        return false;
    }
    
    return [
        'id' => $user->id,
        'name' => $user->name,
        'subscription_tier' => $user->subscription('premium')->stripe_plan,
        'subscriber_since' => $user->subscription('premium')->created_at,
        'features' => $user->getSubscriptionFeatures(),
    ];
});

/**
 * Rate limiting in authorization
 * Tests: Rate limiting integration
 */
Broadcast::private('api-updates', function ($user) {
    $key = 'channel-access:' . $user->id;
    
    if (\RateLimiter::tooManyAttempts($key, 100)) {
        return false;
    }
    
    \RateLimiter::hit($key, 3600); // 1 hour window
    
    return $user->hasApiAccess();
});

/**
 * Multi-step authorization with logging
 * Tests: Complex authorization with side effects
 */
Broadcast::presence('secure-meeting', function ($user, $meetingId) {
    $meeting = \App\Models\Meeting::find($meetingId);
    
    if (!$meeting) {
        \Log::warning('Unauthorized channel access attempt', [
            'user_id' => $user->id,
            'channel' => 'secure-meeting.' . $meetingId,
            'reason' => 'meeting_not_found'
        ]);
        return false;
    }
    
    if ($meeting->is_confidential && !$user->hasSecurityClearance()) {
        \Log::warning('Unauthorized channel access attempt', [
            'user_id' => $user->id,
            'channel' => 'secure-meeting.' . $meetingId,
            'reason' => 'insufficient_clearance'
        ]);
        return null;
    }
    
    if (!$meeting->attendees->contains($user)) {
        \Log::info('Channel access denied', [
            'user_id' => $user->id,
            'channel' => 'secure-meeting.' . $meetingId,
            'reason' => 'not_invited'
        ]);
        return false;
    }
    
    // Log successful authorization
    \Log::info('Channel access granted', [
        'user_id' => $user->id,
        'channel' => 'secure-meeting.' . $meetingId,
    ]);
    
    return [
        'id' => $user->id,
        'name' => $user->name,
        'email' => $user->email,
        'role' => $user->getMeetingRole($meeting),
        'clearance_level' => $user->security_clearance_level,
        'joined_at' => now()->toISOString(),
    ];
});

/**
 * Callback with exception handling
 * Tests: Error handling in authorization callbacks
 */
Broadcast::private('fault-tolerant', function ($user, $resourceId) {
    try {
        $resource = \App\Models\Resource::findOrFail($resourceId);
        
        return $user->can('access', $resource);
    } catch (\Exception $e) {
        \Log::error('Channel authorization error', [
            'user_id' => $user->id,
            'resource_id' => $resourceId,
            'error' => $e->getMessage()
        ]);
        
        // Fail safely - deny access on error
        return false;
    }
});

/**
 * Callback using external service
 * Tests: External API integration in authorization
 */
Broadcast::presence('third-party-integration', function ($user) {
    try {
        $externalAuth = \Http::timeout(2)->get('https://auth-service.example.com/validate', [
            'user_id' => $user->id,
            'token' => $user->api_token
        ]);
        
        if (!$externalAuth->successful()) {
            return false;
        }
        
        $authData = $externalAuth->json();
        
        return [
            'id' => $user->id,
            'name' => $user->name,
            'external_id' => $authData['external_id'],
            'permissions' => $authData['permissions'],
            'verified_at' => now()->toISOString(),
        ];
    } catch (\Exception $e) {
        \Log::warning('External auth service unavailable', [
            'user_id' => $user->id,
            'error' => $e->getMessage()
        ]);
        
        // Fallback to local authorization
        return $user->hasRole('verified') ? [
            'id' => $user->id,
            'name' => $user->name,
            'external_id' => null,
            'fallback_auth' => true,
        ] : false;
    }
});
<?php

/**
 * Parameterized broadcast channel patterns test fixture
 * 
 * Tests channels with route-style parameters like {id}, {userId}, etc.
 * These demonstrate how Laravel extracts parameters from channel names
 */

use Illuminate\Support\Facades\Broadcast;

/*
|--------------------------------------------------------------------------
| Parameterized Broadcast Channels
|--------------------------------------------------------------------------
|
| These channels demonstrate parameter extraction patterns commonly used
| in Laravel applications for user-specific or resource-specific channels.
|
*/

/**
 * Simple single parameter channel
 * Tests: Basic parameter extraction {id}
 */
Broadcast::private('user.{id}', function ($user, $id) {
    return (int) $user->id === (int) $id;
});

/**
 * User-specific notifications channel
 * Tests: User ID parameter extraction
 */
Broadcast::private('user.{userId}.notifications', function ($user, $userId) {
    return $user->id === (int) $userId;
});

/**
 * Order-specific channel with presence
 * Tests: Order ID parameter in presence channel
 */
Broadcast::presence('order.{orderId}.chat', function ($user, $orderId) {
    $order = \App\Models\Order::find($orderId);
    
    if (!$order || $user->id !== $order->user_id) {
        return false;
    }
    
    return [
        'id' => $user->id,
        'name' => $user->name,
        'order_id' => $orderId,
    ];
});

/**
 * Team-specific channel
 * Tests: Team parameter extraction
 */
Broadcast::private('team.{teamId}', function ($user, $teamId) {
    return $user->teams->contains('id', $teamId);
});

/**
 * Project workspace channel
 * Tests: Project ID parameter with authorization
 */
Broadcast::presence('project.{projectId}.workspace', function ($user, $projectId) {
    $project = \App\Models\Project::find($projectId);
    
    if (!$project || !$user->can('access', $project)) {
        return null;
    }
    
    return [
        'id' => $user->id,
        'name' => $user->name,
        'role' => $user->pivot->role ?? 'member',
        'project_id' => $projectId,
    ];
});

/**
 * Document collaboration channel
 * Tests: Document UUID parameter
 */
Broadcast::presence('document.{documentId}.collaboration', function ($user, $documentId) {
    $document = \App\Models\Document::where('uuid', $documentId)->first();
    
    if (!$document || !$document->collaborators->contains($user)) {
        return false;
    }
    
    return [
        'id' => $user->id,
        'name' => $user->name,
        'avatar' => $user->avatar_url,
        'cursor_color' => $user->cursor_color,
    ];
});

/**
 * Chat room with numeric ID
 * Tests: Chat room ID parameter
 */
Broadcast::presence('chat.{roomId}', function ($user, $roomId) {
    $room = \App\Models\ChatRoom::find($roomId);
    
    if (!$room || !$room->members->contains($user)) {
        return null;
    }
    
    return [
        'id' => $user->id,
        'name' => $user->name,
        'status' => $user->online_status,
        'joined_at' => now()->toISOString(),
    ];
});

/**
 * Game session channel
 * Tests: Game session parameter with complex authorization
 */
Broadcast::presence('game.{sessionId}', function ($user, $sessionId) {
    $session = \App\Models\GameSession::find($sessionId);
    
    if (!$session) {
        return false;
    }
    
    // Check if user is a player or spectator
    if ($session->players->contains($user)) {
        return [
            'id' => $user->id,
            'name' => $user->username,
            'role' => 'player',
            'avatar' => $user->avatar,
        ];
    }
    
    if ($session->allow_spectators && $user->can('spectate-games')) {
        return [
            'id' => $user->id,
            'name' => $user->username,
            'role' => 'spectator',
            'avatar' => $user->avatar,
        ];
    }
    
    return false;
});

/**
 * Organization-specific channel
 * Tests: Organization slug parameter
 */
Broadcast::private('organization.{orgSlug}.announcements', function ($user, $orgSlug) {
    $organization = \App\Models\Organization::where('slug', $orgSlug)->first();
    
    return $organization && $user->organizations->contains($organization);
});

/**
 * Event live updates channel
 * Tests: Event ID parameter with date/time validation
 */
Broadcast::channel('event.{eventId}.live', function ($user, $eventId) {
    $event = \App\Models\Event::find($eventId);
    
    if (!$event) {
        return false;
    }
    
    // Public events are open to all
    if ($event->is_public) {
        return true;
    }
    
    // Private events require registration or invitation
    return $event->attendees->contains($user) || $event->organizers->contains($user);
});

/**
 * Course-specific discussion channel
 * Tests: Course code parameter (alphanumeric)
 */
Broadcast::presence('course.{courseCode}.discussion', function ($user, $courseCode) {
    $course = \App\Models\Course::where('code', $courseCode)->first();
    
    if (!$course) {
        return null;
    }
    
    // Check if user is enrolled or is instructor
    if ($course->students->contains($user)) {
        return [
            'id' => $user->id,
            'name' => $user->name,
            'role' => 'student',
            'enrollment_date' => $user->pivot->created_at->toDateString(),
        ];
    }
    
    if ($course->instructors->contains($user)) {
        return [
            'id' => $user->id,
            'name' => $user->name,
            'role' => 'instructor',
            'title' => $user->title,
        ];
    }
    
    return false;
});

/**
 * Alphanumeric parameter channel
 * Tests: Mixed alphanumeric parameter
 */
Broadcast::private('session.{sessionToken}', function ($user, $sessionToken) {
    $session = \App\Models\UserSession::where('token', $sessionToken)->first();
    
    return $session && $session->user_id === $user->id;
});
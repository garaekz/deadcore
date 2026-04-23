<?php

/**
 * Complex broadcast channel patterns test fixture
 * 
 * Tests complex channels with multiple parameters, nested structures,
 * and advanced authorization patterns
 */

use Illuminate\Support\Facades\Broadcast;

/*
|--------------------------------------------------------------------------
| Complex Multi-Parameter Broadcast Channels
|--------------------------------------------------------------------------
|
| These channels demonstrate advanced parameter patterns with multiple
| parameters, complex authorization logic, and nested data structures.
|
*/

/**
 * Multi-parameter channel - user and conversation
 * Tests: Multiple parameter extraction {userId}.{conversationId}
 */
Broadcast::presence('conversation.{userId}.{conversationId}', function ($user, $userId, $conversationId) {
    // Verify the user matches the parameter
    if ($user->id !== (int) $userId) {
        return false;
    }
    
    $conversation = \App\Models\Conversation::find($conversationId);
    
    if (!$conversation || !$conversation->participants->contains($user)) {
        return null;
    }
    
    return [
        'id' => $user->id,
        'name' => $user->name,
        'avatar' => $user->avatar_url,
        'last_seen' => $user->last_seen_at,
        'conversation_id' => $conversationId,
        'user_id' => $userId,
    ];
});

/**
 * Threaded discussion channel
 * Tests: Forum, topic, and thread parameters
 */
Broadcast::presence('forum.{forumId}.topic.{topicId}.thread.{threadId}', function ($user, $forumId, $topicId, $threadId) {
    $thread = \App\Models\ForumThread::with(['topic.forum'])
        ->where('id', $threadId)
        ->where('topic_id', $topicId)
        ->whereHas('topic.forum', function ($query) use ($forumId) {
            $query->where('id', $forumId);
        })
        ->first();
    
    if (!$thread) {
        return false;
    }
    
    // Check forum access permissions
    if (!$user->can('access', $thread->topic->forum)) {
        return null;
    }
    
    return [
        'id' => $user->id,
        'name' => $user->display_name,
        'avatar' => $user->avatar_url,
        'role' => $user->getForumRole($thread->topic->forum),
        'badges' => $user->forum_badges->pluck('name')->toArray(),
        'post_count' => $user->forum_posts_count,
        'reputation' => $user->forum_reputation,
    ];
});

/**
 * Hierarchical workspace channel
 * Tests: Organization, workspace, and project parameters
 */
Broadcast::presence('org.{orgId}.workspace.{workspaceId}.project.{projectId}', function ($user, $orgId, $workspaceId, $projectId) {
    // Validate the hierarchical relationship
    $project = \App\Models\Project::with(['workspace.organization'])
        ->where('id', $projectId)
        ->whereHas('workspace', function ($query) use ($workspaceId, $orgId) {
            $query->where('id', $workspaceId)
                  ->whereHas('organization', function ($orgQuery) use ($orgId) {
                      $orgQuery->where('id', $orgId);
                  });
        })
        ->first();
    
    if (!$project) {
        return false;
    }
    
    // Check permissions at each level
    if (!$user->can('access', $project->workspace->organization)) {
        return null;
    }
    
    if (!$user->can('access', $project->workspace)) {
        return null;
    }
    
    if (!$user->can('access', $project)) {
        return null;
    }
    
    return [
        'id' => $user->id,
        'name' => $user->name,
        'email' => $user->email,
        'avatar' => $user->avatar_url,
        'role' => $user->getProjectRole($project),
        'permissions' => $user->getProjectPermissions($project),
        'online_status' => $user->online_status,
        'timezone' => $user->timezone,
        'project_member_since' => $user->pivot->created_at ?? null,
    ];
});

/**
 * Game lobby with multiple identifiers
 * Tests: Game type, region, and lobby parameters
 */
Broadcast::presence('game.{gameType}.region.{regionCode}.lobby.{lobbyId}', function ($user, $gameType, $regionCode, $lobbyId) {
    $lobby = \App\Models\GameLobby::where('id', $lobbyId)
        ->where('game_type', $gameType)
        ->where('region_code', $regionCode)
        ->first();
    
    if (!$lobby) {
        return false;
    }
    
    // Check if lobby is full
    if ($lobby->players_count >= $lobby->max_players && !$lobby->players->contains($user)) {
        return null;
    }
    
    // Check user's game access
    if (!$user->hasGameAccess($gameType)) {
        return null;
    }
    
    // Check regional restrictions
    if ($lobby->region_locked && $user->region !== $regionCode) {
        return null;
    }
    
    return [
        'id' => $user->id,
        'username' => $user->gaming_username,
        'avatar' => $user->gaming_avatar,
        'level' => $user->getGameLevel($gameType),
        'rank' => $user->getGameRank($gameType),
        'stats' => $user->getGameStats($gameType),
        'region' => $user->region,
        'connection_quality' => $user->connection_quality,
        'is_ready' => false,
        'joined_at' => now()->toISOString(),
    ];
});

/**
 * Multi-tenant application channel
 * Tests: Tenant, department, and resource parameters
 */
Broadcast::private('tenant.{tenantId}.dept.{deptId}.resource.{resourceId}', function ($user, $tenantId, $deptId, $resourceId) {
    // Verify user belongs to tenant
    if ($user->tenant_id !== (int) $tenantId) {
        return false;
    }
    
    $resource = \App\Models\Resource::with(['department'])
        ->where('id', $resourceId)
        ->whereHas('department', function ($query) use ($deptId, $tenantId) {
            $query->where('id', $deptId)
                  ->where('tenant_id', $tenantId);
        })
        ->first();
    
    if (!$resource) {
        return false;
    }
    
    // Check department access
    if (!$user->departments->contains($resource->department)) {
        return false;
    }
    
    // Check resource-specific permissions
    return $user->can('access', $resource);
});

/**
 * Nested collaboration with version control
 * Tests: Repository, branch, and file parameters
 */
Broadcast::presence('repo.{repoId}.branch.{branchName}.file.{fileId}', function ($user, $repoId, $branchName, $fileId) {
    $repository = \App\Models\Repository::find($repoId);
    
    if (!$repository || !$user->can('access', $repository)) {
        return false;
    }
    
    $file = \App\Models\RepositoryFile::where('id', $fileId)
        ->where('repository_id', $repoId)
        ->where('branch', $branchName)
        ->first();
    
    if (!$file) {
        return null;
    }
    
    // Check if file is currently being edited
    $isEditing = $file->editing_sessions()
        ->where('user_id', $user->id)
        ->where('active', true)
        ->exists();
    
    return [
        'id' => $user->id,
        'name' => $user->name,
        'username' => $user->username,
        'avatar' => $user->avatar_url,
        'cursor_color' => $user->editor_cursor_color,
        'is_editing' => $isEditing,
        'permissions' => [
            'can_edit' => $user->can('edit', $file),
            'can_comment' => $user->can('comment', $file),
            'can_review' => $user->can('review', $repository),
        ],
        'editor_preferences' => [
            'theme' => $user->editor_theme,
            'font_size' => $user->editor_font_size,
            'show_line_numbers' => $user->editor_show_line_numbers,
        ],
    ];
});

/**
 * E-commerce order tracking with multiple IDs
 * Tests: Store, order, and shipment parameters
 */
Broadcast::private('store.{storeId}.order.{orderId}.shipment.{shipmentId}', function ($user, $storeId, $orderId, $shipmentId) {
    // Complex authorization with multiple model relationships
    $shipment = \App\Models\Shipment::with(['order.store', 'order.customer'])
        ->where('id', $shipmentId)
        ->whereHas('order', function ($query) use ($orderId, $storeId) {
            $query->where('id', $orderId)
                  ->where('store_id', $storeId);
        })
        ->first();
    
    if (!$shipment) {
        return false;
    }
    
    // Customer can track their own orders
    if ($user->id === $shipment->order->customer_id) {
        return true;
    }
    
    // Store employees can track store orders
    if ($user->stores->contains('id', $storeId)) {
        return true;
    }
    
    // Shipping company can track their shipments
    if ($user->shipping_company_id === $shipment->shipping_company_id) {
        return true;
    }
    
    return false;
});

/**
 * Advanced gaming tournament channel
 * Tests: Multiple parameters with complex validation
 */
Broadcast::presence('tournament.{tournamentId}.bracket.{bracketId}.match.{matchId}', function ($user, $tournamentId, $bracketId, $matchId) {
    $match = \App\Models\TournamentMatch::with(['bracket.tournament', 'participants'])
        ->where('id', $matchId)
        ->whereHas('bracket', function ($query) use ($bracketId, $tournamentId) {
            $query->where('id', $bracketId)
                  ->where('tournament_id', $tournamentId);
        })
        ->first();
    
    if (!$match) {
        return false;
    }
    
    $tournament = $match->bracket->tournament;
    
    // Participants can always join
    if ($match->participants->contains($user)) {
        return [
            'id' => $user->id,
            'username' => $user->gaming_username,
            'avatar' => $user->gaming_avatar,
            'role' => 'participant',
            'team' => $user->getTeamForMatch($match),
            'stats' => $user->getTournamentStats($tournament),
            'ready_status' => $user->getMatchReadyStatus($match),
        ];
    }
    
    // Tournament organizers can observe
    if ($tournament->organizers->contains($user)) {
        return [
            'id' => $user->id,
            'username' => $user->username,
            'avatar' => $user->avatar_url,
            'role' => 'organizer',
            'permissions' => ['moderate', 'pause', 'restart'],
        ];
    }
    
    // Spectators (if allowed)
    if ($tournament->allow_spectators && $user->can('spectate', $tournament)) {
        return [
            'id' => $user->id,
            'username' => $user->username,
            'avatar' => $user->avatar_url,
            'role' => 'spectator',
            'subscription_tier' => $user->subscription_tier,
        ];
    }
    
    return false;
});
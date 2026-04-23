# Broadcast Channel Pattern Test Fixtures

This directory contains comprehensive test fixtures for Laravel broadcast channel pattern detection and matching. These fixtures are designed to test the broadcast matcher's ability to identify, parse, and extract meaningful information from Laravel's broadcast channel definitions typically found in `routes/channels.php`.

## Overview

Laravel's broadcasting system allows real-time communication through channels. The broadcast matcher needs to detect and analyze:

- **Channel Types**: `Broadcast::channel()` (public), `Broadcast::private()` (private), `Broadcast::presence()` (presence)
- **Channel Parameters**: Route-style parameters like `{id}`, `{userId}`, etc.
- **Authorization Callbacks**: Closure functions that determine channel access
- **Presence Data**: User information returned for presence channels

## Directory Structure

```
broadcast/
├── basic_channels.php              # Simple channel patterns
├── parameterized_channels.php      # Route-style parameter extraction
├── complex_channels.php            # Multi-parameter and nested structures
├── authorization_callbacks.php     # Various callback patterns
├── edge_cases_channels.php         # Edge cases and unusual patterns
└── README.md                       # This documentation

expected/broadcast/
├── basic_*.json                    # Expected outputs for basic patterns
├── parameterized_*.json            # Expected outputs for parameterized channels
├── complex_*.json                  # Expected outputs for complex patterns
├── authorization_*.json            # Expected outputs for authorization patterns
└── edge_case_*.json               # Expected outputs for edge cases
```

## Test Categories

### 1. Basic Channel Patterns (`basic_channels.php`)

Tests fundamental broadcast channel types:

- **Public Channels**: `Broadcast::channel()` - No authentication required
- **Private Channels**: `Broadcast::private()` - Requires user authentication
- **Presence Channels**: `Broadcast::presence()` - Shows who's online

**Coverage:**
- Simple callbacks with boolean returns
- Callbacks with array returns (presence data)
- Channels with and without callbacks
- Multiple sequential channel definitions

**Key Test Cases:**
- `notifications` - Basic public channel
- `orders` - Private channel with role check
- `chat` - Presence channel with user info
- `admin-notifications` - Private channel with method call

### 2. Parameterized Channels (`parameterized_channels.php`)

Tests channels with route-style parameters:

- **Single Parameters**: `user.{id}`, `team.{teamId}`
- **Multiple Parameters**: `order.{orderId}.chat`
- **Mixed Parameter Types**: Numeric, alphanumeric, UUID patterns

**Coverage:**
- Parameter extraction from channel names
- Parameter validation in callbacks
- Database queries using parameters
- Authorization based on parameter values

**Key Test Cases:**
- `user.{id}` - Simple user ID parameter
- `order.{orderId}.chat` - Presence channel with order validation
- `project.{projectId}.workspace` - Complex authorization with parameters
- `session.{sessionToken}` - Alphanumeric token parameter

### 3. Complex Multi-Parameter Patterns (`complex_channels.php`)

Tests advanced patterns with multiple parameters and complex logic:

- **Hierarchical Channels**: `org.{orgId}.workspace.{workspaceId}.project.{projectId}`
- **Nested Structures**: Multiple parameter validation chains
- **Complex Authorization**: Permission checks across multiple models

**Coverage:**
- 2+ parameters per channel
- Hierarchical model relationships
- Complex presence data structures
- Multi-level permission validation

**Key Test Cases:**
- `conversation.{userId}.{conversationId}` - Multi-parameter presence
- `forum.{forumId}.topic.{topicId}.thread.{threadId}` - Deep nesting
- `game.{gameType}.region.{regionCode}.lobby.{lobbyId}` - Game lobby system
- `tournament.{tournamentId}.bracket.{bracketId}.match.{matchId}` - Tournament structure

### 4. Authorization Callback Patterns (`authorization_callbacks.php`)

Tests various callback implementation patterns:

- **Simple Returns**: Boolean true/false
- **Conditional Logic**: If/else, switch statements
- **Database Queries**: Model relationships and queries
- **Laravel Integrations**: Policies, gates, features flags

**Coverage:**
- Different return types (boolean, array, null)
- Database operations in callbacks
- Laravel policy integration
- External service calls
- Time-based authorization
- Feature flag integration

**Key Test Cases:**
- `simple-auth` - Basic boolean return
- `team-workspace` - Database query with pivot data
- `document-editing` - Laravel policy integration
- `premium-workshop` - Subscription-based authorization
- `third-party-integration` - External API with fallback

### 5. Edge Cases and Error Conditions (`edge_cases_channels.php`)

Tests unusual patterns and error handling:

- **Malformed Patterns**: Missing callbacks, empty functions
- **Unusual Syntax**: Long channel names, special characters
- **Complex Logic**: Nested conditions, loops, exceptions
- **PHP Language Features**: Ternary operators, null coalescing

**Coverage:**
- Missing or empty callbacks
- Very long channel names
- Special characters in names
- Complex PHP syntax patterns
- Error handling scenarios

**Key Test Cases:**
- `no-callback-channel` - Missing callback function
- `empty-callback` - Callback with no return
- `very.long.channel.name...` - Extremely long channel name
- `nested-conditions` - Deeply nested conditional logic
- `always-throws` - Exception-throwing callback

## Expected JSON Output Structure

Each fixture has corresponding expected JSON output files that define the expected `BroadcastMatch` structure:

```json
{
  "channel": "user.{id}",
  "type": "private",
  "pattern": "Broadcast::private",
  "hasCallback": true,
  "parameters": [
    {
      "name": "id",
      "type": "route_parameter",
      "position": 1
    }
  ],
  "visibility": "private",
  "authorization": {
    "required": true,
    "callback": "function ($user, $id) { return (int) $user->id === (int) $id; }",
    "complexity": "parameter_comparison",
    "userParameter": true,
    "additionalParameters": ["id"]
  },
  "routeParameters": {
    "count": 1,
    "names": ["id"],
    "pattern": "user.{id}"
  },
  "context": "broadcast_channel_definition"
}
```

### Key Output Fields

- **channel**: The channel name/pattern
- **type**: Channel type (public/private/presence)
- **pattern**: The Broadcast method used
- **hasCallback**: Whether a callback function is present
- **parameters**: Array of route parameters extracted
- **visibility**: Channel visibility level
- **authorization**: Authorization details and complexity analysis
- **presenceData**: For presence channels, structure of returned user data
- **routeParameters**: Parameter extraction details
- **complexity**: Overall complexity assessment
- **edgeCase**: Special handling notes for unusual patterns

## Testing Integration

These fixtures support multiple testing approaches:

### Unit Tests
```go
func TestBroadcastMatcher(t *testing.T) {
    testCases := []struct {
        name           string
        fixture        string
        expectedOutput string
        expectedError  bool
    }{
        {
            name:           "basic_public_channel",
            fixture:        "basic_channels.php",
            expectedOutput: "expected/broadcast/basic_public_notifications.json",
            expectedError:  false,
        },
        // ... more test cases
    }
    
    for _, tc := range testCases {
        t.Run(tc.name, func(t *testing.T) {
            // Test implementation
        })
    }
}
```

### Golden File Testing
The expected JSON files serve as golden files for regression testing, ensuring consistent output across code changes.

### Integration Testing
These fixtures can be used in end-to-end tests to verify the complete broadcast detection and emission pipeline.

## Pattern Complexity Levels

### Simple
- Basic boolean authorization
- No parameters
- Minimal logic

### Medium  
- Single parameter extraction
- Simple database queries
- Method call authorization

### High
- Multiple parameters
- Complex conditional logic
- Policy/gate integration

### Very High
- Hierarchical parameter validation
- External service integration
- Complex presence data structures

### Extreme
- 5+ parameters
- Deep nesting
- Exception handling with fallbacks

## Laravel Broadcasting Context

These patterns reflect real-world Laravel broadcasting usage:

- **Chat Applications**: Real-time messaging with presence
- **Collaborative Tools**: Document editing, project workspaces
- **Gaming Systems**: Lobbies, matches, tournaments
- **E-commerce**: Order tracking, customer support
- **Educational Platforms**: Course discussions, live sessions

## Usage Guidelines

1. **Add New Patterns**: When adding new test cases, include both PHP fixture and expected JSON output
2. **Maintain Realism**: Use patterns that reflect actual Laravel application scenarios  
3. **Test Edge Cases**: Include both happy path and error conditions
4. **Document Complexity**: Clearly mark the complexity level and testing focus
5. **Follow Naming**: Use descriptive names that indicate the pattern being tested

## Validation Requirements

The broadcast matcher should handle:

- ✅ All three channel types (public, private, presence)
- ✅ Route parameter extraction and validation
- ✅ Authorization callback complexity analysis
- ✅ Presence data structure detection
- ✅ Edge cases and error conditions
- ✅ Deterministic output generation
- ✅ Performance with complex patterns

These fixtures ensure comprehensive coverage of Laravel's broadcasting patterns and provide a robust foundation for broadcast channel detection testing.
# Laravel Pattern Matcher Test Fixtures

This directory contains test fixtures for Laravel pattern detection matchers. Each matcher has dedicated fixture files that test specific Laravel patterns and edge cases.

## Directory Structure

```
matchers/
├── controllers/          # Controller class fixtures for testing
│   ├── simple_controller.php
│   ├── api_controller.php
│   ├── resource_controller.php
│   └── complex_controller.php
├── expected/              # Expected matcher output in JSON format
│   ├── http_status/
│   ├── request_usage/
│   └── resource/
└── invalid/               # Invalid/edge case fixtures
    ├── malformed_syntax.php
    ├── incomplete_patterns.php
    └── ambiguous_patterns.php
```

## Test Coverage Strategy

### HTTP Status Matcher Tests
- **Explicit status codes**: `response()->status(201)`, `abort(404)`, `response($data, 201)`
- **Implicit/inferred status**: Default Laravel responses, inferred from context
- **Edge cases**: Dynamic status codes, status from variables
- **Confidence levels**: High confidence for explicit, lower for inferred

### Request Usage Matcher Tests
- **Direct request methods**: `$request->all()`, `$request->json()`, `$request->file()`
- **Parameter extraction**: `$request->input('name')`, `$request->only(['key'])`
- **Content type inference**: JSON detection, file upload detection
- **Validation patterns**: `$request->has()`, `$request->filled()`

### Resource Matcher Tests
- **Single resources**: `new UserResource($user)`, `UserResource::make($user)`
- **Collection resources**: `UserResource::collection($users)`
- **Return statements**: `return new UserResource($user)`
- **Assignment patterns**: `$resource = new UserResource($user)`
- **Import resolution**: Fully qualified names vs imported classes

## Fixture File Naming Convention

- `{pattern_type}_{scenario}_{expected_result}.php`
- Examples:
  - `http_status_explicit_high_confidence.php`
  - `request_usage_json_content_type.php`
  - `resource_collection_import_resolved.php`

## Expected Output Format

Each fixture has a corresponding expected output file in JSON format matching the emitter.Controller structure:

```json
{
  "fqcn": "App\\Http\\Controllers\\TestController",
  "method": "testMethod",
  "http": {
    "status": 201,
    "explicit": true
  },
  "request": {
    "contentTypes": ["application/json"],
    "body": {
      "name": {"type": "string"},
      "email": {"type": "string"}
    }
  },
  "resources": [
    {
      "class": "App\\Http\\Resources\\UserResource", 
      "collection": false
    }
  ]
}
```

## Test Categories

### 1. Golden Path Tests
- Standard Laravel patterns that should work perfectly
- High confidence matches with explicit patterns
- Common controller method patterns

### 2. Edge Case Tests  
- Malformed syntax that should be handled gracefully
- Ambiguous patterns that require confidence scoring
- Complex nested expressions

### 3. Performance Tests
- Large files with many patterns
- Deeply nested AST structures
- Many imports and complex class hierarchies

### 4. Integration Tests
- Multiple pattern types in single methods
- Cross-matcher dependencies
- Full controller analysis workflows

## Usage in Tests

Fixture files are designed to be used with table-driven tests:

```go
func TestHTTPStatusMatcher(t *testing.T) {
    testCases := []struct {
        name           string
        fixture        string
        expectedOutput string
        expectedError  bool
    }{
        {
            name:           "explicit_status_high_confidence",
            fixture:        "http_status_explicit_high_confidence.php", 
            expectedOutput: "expected/http_status/explicit_high_confidence.json",
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
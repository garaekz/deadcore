# Laravel Query Scope Test Fixtures

This directory contains PHP test fixtures for validating the ScopeMatcher implementation in the Oxinfer project. These files demonstrate various Laravel query scope patterns that the matcher should detect and extract.

## Test Files Overview

### 1. `local_scope_definitions.php`
Tests detection of local scope method definitions within models:
- Basic scope methods (`scopeActive`, `scopePublished`)
- Scopes with parameters (`scopeOfType`, `scopeRecent`)
- Complex multi-condition scopes (`scopeActivePublishedUsers`)
- Relationship-based scopes (`scopeWithPosts`)
- Invalid patterns that should NOT be detected as scopes

**Expected Patterns:**
- Method names matching `^scope[A-Z][a-zA-Z0-9]*$`
- First parameter must be `Builder $query`
- Return type should be `Builder`

### 2. `scope_usage_patterns.php`
Tests detection of scope method calls in controllers and services:
- Direct scope calls with prefix (`User::scopeActive()`)
- Scope calls without prefix (`User::query()->active()`)
- Chained scope calls (`User::active()->ofType('admin')`)
- Scopes with parameters (`Post::recent(7)`)
- Dynamic query building with conditional scopes

**Expected Patterns:**
- Method calls matching scope names
- Chaining patterns with query builders
- Parameter extraction from scope calls

### 3. `global_scopes.php`
Tests detection of global scope class definitions:
- Classes implementing `Scope` interface
- `apply()` method implementations
- Complex global scopes with multiple conditions
- Parameterized global scopes (TenantScope)

**Expected Patterns:**
- Class names ending in "Scope"
- Implementation of `Scope` interface
- `apply(Builder $builder, Model $model)` method signature

### 4. `model_with_global_scopes.php`
Tests detection of global scope registration in model boot methods:
- `addGlobalScope()` calls with class instances
- Named global scopes with string keys
- Anonymous global scopes using closures
- Conditional scope registration

**Expected Patterns:**
- `static::addGlobalScope()` calls in boot methods
- Scope registration with both classes and closures
- Scope removal patterns (`withoutGlobalScope()`)

### 5. `relationship_scopes.php`
Tests detection of scopes used within Eloquent relationships:
- Scopes applied to `hasMany` relationships
- Scopes in `belongsToMany` relationships
- Multiple scopes chained on relationships
- Scopes with relationship constraints

**Expected Patterns:**
- Scope methods called on relationship definitions
- Chained scopes within relationship methods
- Cross-model scope usage

### 6. `dynamic_scopes.php`
Tests detection of dynamic scope patterns and conditional usage:
- Runtime scope application based on request parameters
- Dynamic method calls that resolve to scopes
- Whereable patterns (`whereActive()`, `whereFeatured()`)
- Complex query building with multiple scopes

**Expected Patterns:**
- Dynamic scope method calls
- `where*` patterns that map to scopes
- Conditional scope application

## Matcher Configuration

The test fixtures are designed to validate different confidence levels:

- **High Confidence (0.9-1.0)**: Direct scope definitions, explicit scope calls
- **Medium Confidence (0.8-0.89)**: Model::query()->scope() patterns
- **Low Confidence (0.6-0.79)**: Inferred scopes, whereable patterns

## Expected Output Structure

For each detected scope, the matcher should produce a `ScopeMatch` with:

```json
{
  "name": "active",
  "on": "App\\Models\\User", 
  "args": [],
  "isGlobal": false,
  "isLocal": true,
  "pattern": "usage",
  "method": "scopeActive",
  "context": "query"
}
```

## Testing Strategy

1. **Positive Tests**: Verify that valid scope patterns are detected
2. **Negative Tests**: Ensure non-scope methods are not detected
3. **Edge Cases**: Test boundary conditions and malformed patterns
4. **Performance Tests**: Validate matcher performance on large files
5. **Integration Tests**: Test scope detection within complete Laravel applications

These fixtures should be used with the tree-sitter PHP parser to validate that the ScopeMatcher correctly identifies and extracts Laravel query scope patterns across different usage contexts.
# Polymorphic Pattern Test Fixtures

This directory contains comprehensive test fixtures for Laravel polymorphic relationship pattern detection. These fixtures are designed to test the polymorphic matcher's ability to identify, parse, and understand various polymorphic relationship patterns in Laravel applications.

## Directory Structure

```
polymorphic/
├── basic_polymorphic.php              # Simple morphTo/morphOne/morphMany patterns
├── morph_map_definitions.php          # Global morphMap() registrations
├── complex_polymorphic.php            # Advanced polymorphic chains and relationships
├── many_to_many_polymorphic.php       # morphByMany and morphToMany patterns
├── edge_cases_polymorphic.php         # Unusual but valid polymorphic patterns
└── README.md                          # This documentation file

../expected/polymorphic/
├── basic_comment_commentable.json     # Expected output for basic morphTo pattern
├── basic_post_comments.json           # Expected output for basic morphMany pattern
├── basic_post_image.json              # Expected output for basic morphOne pattern
├── morph_map_basic_definition.json    # Expected output for morphMap registration
├── many_to_many_tag_posts.json        # Expected output for morphedByMany pattern
├── many_to_many_post_tags.json        # Expected output for morphToMany pattern
├── complex_activity_subject.json      # Expected output for complex polymorphic chain
├── complex_nested_chain.json          # Expected output for nested polymorphic relationships
├── edge_case_self_referencing.json    # Expected output for self-referencing patterns
├── edge_case_conditional.json         # Expected output for conditional relationships
└── edge_case_constrained.json         # Expected output for constrained relationships
```

## Test Coverage

### 1. Basic Polymorphic Patterns (`basic_polymorphic.php`)

Tests fundamental polymorphic relationship types:

#### **morphTo() Relationships**
- Standard morphTo with default column names (`commentable_type`, `commentable_id`)
- Custom morphTo with explicit name parameter
- morphTo with custom type and ID column names
- Multiple morphTo relationships in single model

#### **morphOne() Relationships**  
- One-to-one polymorphic relationships
- Standard morphOne usage patterns
- morphOne with custom morph name

#### **morphMany() Relationships**
- One-to-many polymorphic relationships
- Standard morphMany usage patterns
- Multiple morphMany relationships per model

**Models Covered:**
- `Comment` (morphTo relationships)
- `Post`, `Video`, `User` (morphOne/morphMany providers)
- `Image`, `Attachment`, `Tag` (polymorphic targets)

### 2. Morph Map Definitions (`morph_map_definitions.php`)

Tests global polymorphic type mapping registration:

#### **Standard Morph Maps**
- Basic `Relation::morphMap()` calls in service providers
- Multiple morph map registrations
- Array merge strategies for extending mappings

#### **Dynamic Morph Maps**
- Configuration-based morph map loading
- Conditional morph map registration
- Environment-specific mappings

#### **Advanced Patterns**
- Morph maps in model boot methods
- Custom morph type resolution
- Override and extension patterns

**Key Test Scenarios:**
- Service provider boot methods
- Dynamic configuration loading
- Conditional registration logic
- Custom type resolution

### 3. Complex Polymorphic Patterns (`complex_polymorphic.php`)

Tests advanced polymorphic relationship scenarios:

#### **Nested Polymorphic Chains**
- Multiple levels of polymorphic relationships
- Cross-referencing polymorphic models
- Activity logging with polymorphic subjects

#### **Multiple Discriminators**
- Models with multiple polymorphic relationships
- Different morph types in same model
- Complex discriminator mapping scenarios

#### **Constrained Polymorphic Relationships**
- Polymorphic relationships with WHERE constraints
- Security-based filtering
- Type-specific constraints

**Models Covered:**
- `ActivityLog` (multi-polymorphic with subject/causer)
- `Notification` (polymorphic chains)
- `MediaItem` (complex discriminators)
- `Audit` (multiple polymorphic relationships)

### 4. Many-to-Many Polymorphic (`many_to_many_polymorphic.php`)

Tests polymorphic many-to-many relationship patterns:

#### **morphToMany() Relationships**
- Standard polymorphic many-to-many from owner side
- Custom pivot table names
- Additional pivot columns and timestamps
- Ordering and constraints

#### **morphedByMany() Relationships**
- Inverse polymorphic many-to-many relationships
- Multiple morphedByMany per model
- Complex pivot data scenarios

#### **Advanced Pivot Scenarios**
- Custom pivot models
- Timestamps and additional pivot data
- Relationship constraints and scoping

**Models Covered:**
- `Tag`, `Category` (morphedByMany providers)
- `Post`, `Video`, `Article` (morphToMany owners)
- `User`, `Role`, `Permission` (complex many-to-many scenarios)

### 5. Edge Cases (`edge_cases_polymorphic.php`)

Tests unusual but valid polymorphic patterns:

#### **Self-Referencing Polymorphic**
- Models that reference themselves polymorphically
- Nested comment structures
- Circular reference prevention

#### **Conditional Polymorphic**
- Relationships that vary based on model state
- Dynamic relationship behavior
- Context-dependent morphing

#### **Performance-Critical Patterns**
- Optimized polymorphic relationships
- Cached relationship data
- Selective column loading

#### **Complex Constraints**
- Security-based filtering
- Time-based constraints
- JSON column constraints
- Namespace restrictions

**Advanced Scenarios:**
- Soft delete handling
- Custom type resolution
- Dynamic column names
- Circular reference detection

## Expected JSON Output Format

All expected output files follow the `PolymorphicMatch` structure:

```json
{
  "relation": "relationship_name",
  "type": "morphTo|morphOne|morphMany|morphToMany|morphedByMany",
  "morphType": "type_column_name",
  "morphId": "id_column_name",
  "model": "Target\\Model\\Class",
  "discriminator": {
    "propertyName": "discriminator_column",
    "mapping": {
      "type_key": "Model\\Class"
    },
    "source": "morphMap|explicit|inferred",
    "isExplicit": true|false
  },
  "depthTruncated": false,
  "maxDepth": 5,
  "pattern": "pattern_classification",
  "method": "relationship_method_name",
  "context": "relationship_context",
  "relatedModels": ["Related\\Model\\Classes"]
}
```

### Key Fields Explained

- **`relation`**: The relationship method name
- **`type`**: The polymorphic relationship type
- **`morphType`/`morphId`**: Column names for type/ID discrimination
- **`model`**: Target model class (for morphOne/morphMany/morphToMany/morphedByMany)
- **`discriminator`**: Discriminator mapping information
- **`depthTruncated`**: Whether max traversal depth was reached
- **`pattern`**: Classification of the pattern type
- **`context`**: Context where the relationship was defined
- **`relatedModels`**: Array of models involved in the relationship

### Discriminator Mapping Sources

- **`morphMap`**: From `Relation::morphMap()` registration
- **`explicit`**: Explicitly defined in relationship definition
- **`inferred`**: Inferred from model class names and usage patterns

## Pattern Classifications

### Relationship Types
- `morphTo_definition` - Standard morphTo relationship
- `morphOne_definition` - Standard morphOne relationship  
- `morphMany_definition` - Standard morphMany relationship
- `morphToMany_definition` - Standard morphToMany relationship
- `morphedByMany_definition` - Standard morphedByMany relationship

### Advanced Patterns
- `morphTo_conditional` - Conditional morphTo relationships
- `morphTo_constrained` - Constrained morphTo relationships
- `morphMany_self_reference` - Self-referencing morphMany
- `morphMap_definition` - Global morph map registration

### Context Classifications
- `model_relationship` - Standard model relationship method
- `service_provider` - Definition in service provider
- `model_relationship_conditional` - Conditional relationship
- `model_relationship_security_constrained` - Security-constrained relationship

## Usage in Tests

These fixtures support comprehensive testing scenarios:

### **Unit Tests**
```go
func TestBasicPolymorphicPatterns(t *testing.T) {
    testCases := []struct {
        fixture        string
        expectedOutput string
        patternCount   int
    }{
        {
            fixture:        "basic_polymorphic.php",
            expectedOutput: "basic_comment_commentable.json", 
            patternCount:   1,
        },
    }
    // Test implementation
}
```

### **Integration Tests**
- End-to-end polymorphic pattern detection
- Cross-file polymorphic relationship resolution  
- Performance testing with complex polymorphic chains

### **Golden File Testing**
- Byte-for-byte comparison of matcher output
- Deterministic JSON output validation
- Regression testing for pattern detection

## Test Categories

### **Golden Path Tests**
- Standard Laravel polymorphic patterns
- High-confidence pattern matches
- Common polymorphic use cases

### **Edge Case Tests**
- Unusual but valid polymorphic patterns
- Complex constraint scenarios
- Self-referencing relationships

### **Performance Tests**
- Deep polymorphic relationship chains
- Large files with many polymorphic relationships
- Memory usage optimization testing

### **Error Handling Tests**
- Malformed polymorphic definitions
- Circular reference detection
- Invalid discriminator mappings

## Discriminator Mapping Testing

### **Explicit Mappings**
- From `Relation::morphMap()` calls
- Custom type resolution
- Configuration-based mappings

### **Inferred Mappings**  
- Model class name inference
- Usage pattern analysis
- Default Laravel conventions

### **Mixed Mapping Scenarios**
- Combination of explicit and inferred mappings
- Override and extension patterns
- Complex inheritance scenarios

## Depth Truncation Testing

Tests the matcher's ability to handle deep polymorphic relationship chains:

- **Max Depth Configuration**: Tests configurable depth limits
- **Circular Reference Detection**: Prevents infinite traversal
- **Performance Protection**: Ensures reasonable processing times

## Integration Points

### **With Other Matchers**
- Resource matcher integration
- HTTP status detection in polymorphic controllers
- Request usage patterns with polymorphic models

### **With Parser Components**
- PSR-4 class resolution
- Import statement analysis
- Namespace handling

### **With Emitter Components**
- JSON serialization testing
- Delta emission integration
- Schema validation compliance

## Maintenance Guidelines

### **Adding New Fixtures**
1. Create PHP file with realistic Laravel patterns
2. Add corresponding expected JSON outputs
3. Update this README with coverage details
4. Add test cases to validate the fixture

### **Expected Output Updates**
- Follow the `PolymorphicMatch` structure exactly  
- Ensure deterministic JSON ordering
- Include all required fields with appropriate defaults
- Validate against the JSON schema

### **Pattern Coverage**
- Ensure all polymorphic relationship types are covered
- Include both common and edge case scenarios
- Test performance and security implications
- Cover integration with other Laravel features

This fixture set provides comprehensive coverage for Laravel polymorphic relationship pattern detection, ensuring the matcher can handle real-world scenarios while maintaining high performance and accuracy.
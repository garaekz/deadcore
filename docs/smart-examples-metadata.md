# Smart Examples Metadata Plan

This document defines the additive static metadata that `oxinfer` should expose to support smart request and response examples in `oxcribe`.

The goal is not for `oxinfer` to generate final examples.
`oxinfer` should expose stable, deterministic field- and response-level hints.
`oxcribe` should turn those hints into scenario-aware examples, snippets, and interactive payloads.

## Design Rule

`oxinfer` owns static facts.
`oxcribe` owns example synthesis.

That split keeps `oxinfer` deterministic and framework-aware without pushing product-specific docs UX into the static analyzer.

## Current Inputs Already Available

Today `oxinfer` already emits enough structure to support a first examples engine:

- `controllers[].request.fields[]`
  - `location`
  - `path`
  - `kind`
  - `type`
  - `scalarType`
  - `format`
  - `itemType`
  - `allowedValues`
  - `required`
  - `optional`
  - `nullable`
  - `isArray`
  - `collection`
  - `source`
  - `via`
- `controllers[].responses[]`
  - response `kind`
  - `status`
  - `contentType`
  - `bodySchema`
  - `redirect` / `download` / `inertia`
  - `source`
  - `via`
- `resources[]`
  - reusable response resource schemas
- request/query/body tree overlays
- static authorization hints

This is enough to build shape-correct examples, but not enough yet to build semantically rich and confidence-scored examples.

## Additive Metadata To Add

The following metadata should be added without bumping the active `oxcribe.oxinfer.v2` contract.
Everything below is additive to the existing `delta`.

### 1. `RequestField` Semantic Metadata

Extend `controllers[].request.fields[]` with:

```json
{
  "location": "body",
  "path": "email",
  "kind": "scalar",
  "type": "string",
  "scalarType": "string",
  "format": "email",
  "semanticType": "email",
  "confidence": 0.98,
  "constraints": {
    "minLength": null,
    "maxLength": 255,
    "minimum": null,
    "maximum": null,
    "pattern": null,
    "enum": null,
    "exists": null,
    "confirmedWith": null,
    "accepted": false
  },
  "source": "validation",
  "via": "rule:email"
}
```

Planned additive fields:

- `semanticType`
  - stable normalized meaning, not raw field name
  - examples: `email`, `password`, `first_name`, `full_name`, `phone`, `company_name`, `url`, `slug`, `uuid`, `ulid`, `token`, `api_key`, `amount`, `percentage`, `date`, `datetime`, `foreign_key_id`
- `confidence`
  - `0.0` to `1.0`
  - confidence of the semantic classification, not of the entire request shape
- `constraints`
  - normalized rule output
  - should prefer structured fields over preserving raw validation strings
- `aliases`
  - optional future field if a package exposes a public alias different from the transport name

### 2. `Response` Semantic Metadata

Extend `controllers[].responses[]` with optional semantic hints:

```json
{
  "kind": "json_object",
  "status": 200,
  "bodySchema": {
    "type": "object"
  },
  "semanticType": "auth.login.response",
  "confidence": 0.84,
  "source": "response()->json",
  "via": "response()->json"
}
```

Response-level semantic hints are intentionally coarse.
They should help `oxcribe` choose a scenario, not lock the product into a static example model.

Examples:

- `auth.login.response`
- `auth.register.response`
- `collection.paginated`
- `resource.show`
- `resource.store`
- `resource.update`
- `validation.error`
- `authorization.error`
- `model_not_found.error`

### 3. `ResourceSchemaNode` Field Hints

`resources[].schema` and inline `bodySchema` nodes should gain optional additive fields for leaf nodes:

- `semanticType`
- `confidence`
- `constraints`
- `source`
- `via`

This is especially valuable for response examples, where field names may not flow through `request.fields`.

### 4. Controller-Level Scenario Hints

Add a new optional controller-level section:

```json
{
  "scenarioHints": {
    "operationCandidates": [
      {
        "name": "auth.login",
        "confidence": 0.92,
        "source": "route+request+response"
      },
      {
        "name": "users.store",
        "confidence": 0.63,
        "source": "resource+request"
      }
    ]
  }
}
```

Important:

- `oxinfer` should only emit candidates
- final `operationKind` should be resolved by `oxcribe`, because method, URI, route name, and runtime grouping live there

## Normalized Constraint Shape

`constraints` should be structured and deterministic.
Raw validation strings are not enough for good synthesis.

Recommended shape:

```json
{
  "minLength": 8,
  "maxLength": 255,
  "minimum": null,
  "maximum": null,
  "multipleOf": null,
  "pattern": "^[A-Z0-9]+$",
  "enum": ["admin", "user"],
  "format": "email",
  "exists": {
    "table": "users",
    "column": "id"
  },
  "confirmedWith": "password_confirmation",
  "accepted": false,
  "nullable": false
}
```

Notes:

- `nullable` should remain duplicated in the field root for ergonomics
- `enum` should be explicit even if already copied into `allowedValues`
- `exists` should remain structured when inferible
- if only a raw regex exists, preserve it in `pattern`

## What `oxinfer` Should Not Do

`oxinfer` should not:

- generate final example values
- choose between `minimal_valid`, `happy_path`, and `realistic_full`
- invent cross-field consistency state
- emit cURL/fetch/axios snippets
- know about product tiers or docs UI behavior

Those are product concerns that belong in `oxcribe`.

## Ownership Split

### `oxinfer` owns

- field type inference
- field semantic classification
- normalized constraints
- leaf-level confidence
- package-aware static hints from Spatie/Laravel conventions
- coarse response scenario hints

### `oxcribe` owns

- final `operationKind`
- scenario selection
- deterministic seed derivation
- request/response example generation
- cross-field consistency
- example modes
- snippets and `try-it`
- attaching examples to OpenAPI and the viewer

## Suggested Rollout Order

1. Add `semanticType`, `confidence`, and `constraints` to `RequestField`
2. Add leaf metadata to `ResourceSchemaNode`
3. Add controller `scenarioHints.operationCandidates`
4. Keep all new fields optional and additive
5. Let `oxcribe` consume them without breaking existing schema generation

## Why This Split Matters

If `oxinfer` starts generating final examples, it will couple the static analyzer to product decisions that should evolve quickly.

If `oxcribe` tries to infer everything from raw field names without the static analyzer, it will lose most of the value already present in request/response inference.

The right cut is:

- `oxinfer`: semantic facts
- `oxcribe`: scenario synthesis

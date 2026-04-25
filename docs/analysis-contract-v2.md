# Legacy Oxcribe Oxinfer Contract V2

Legacy note: this document is retained only as historical Oxinfer contract reference. It is not the active `deadcore` analysis contract; current public output is `deadcode.analysis.v1`.

This document defines the legacy machine contract between `oxcribe` and `oxinfer`.

`oxcribe` owns the Laravel runtime snapshot. `oxinfer` owns the static analysis. The join key is `actionKey = FQCN::method`.

The previous `v1` contract is archived only for historical reference.

## Request

`oxinfer --request -` reads an `AnalysisRequest` JSON document from stdin.

Minimum shape:

```json
{
  "contractVersion": "oxcribe.oxinfer.v2",
  "requestId": "req_01HX...",
  "runtimeFingerprint": "sha256:...",
  "manifest": {
    "project": {
      "root": "/abs/path/to/laravel",
      "composer": "composer.json"
    },
    "scan": {
      "targets": ["app", "routes"],
      "globs": ["**/*.php"]
    }
  },
  "runtime": {
    "app": {
      "basePath": "/abs/path/to/laravel",
      "laravelVersion": "12.0.0",
      "phpVersion": "8.3.0",
      "appEnv": "production"
    },
    "routes": []
  }
}
```

Rules:
- `contractVersion` must be exactly `oxcribe.oxinfer.v2`
- `runtime.app.basePath` must be absolute and must match `manifest.project.root` after normalization
- `runtime.routes` is authoritative for runtime route inventory
- controller routes use `action.kind = controller_method` or `invokable_controller`
- invokable routes are normalized to `action.method = "__invoke"`
- closures and unknown actions are preserved in `oxcribe` but are not route-joined as static controller actions

## Response

`oxinfer --request -` emits an `AnalysisResponse` JSON document on stdout.

The response wraps the existing static `delta` and adds runtime-aware route matches plus diagnostics.

Key rules:
- `status` is `ok` when all runtime routes that can be statically joined are matched
- `status` is `partial` when any route is runtime-only, unsupported, or missing static analysis
- `delta.controllers` is filtered to matched runtime actions only
- `delta.models`, `delta.polymorphic`, and `delta.broadcast` remain the static project graph
- output is deterministic for the same request, excluding only explicitly volatile fields already normalized by contract

### Response IR V2

`controllers[].responses[]` now uses an explicit response shape:

```json
{
  "kind": "inertia",
  "status": 200,
  "explicit": false,
  "contentType": "text/html",
  "headers": {},
  "bodySchema": {
    "type": "object"
  },
  "redirect": {
    "targetKind": "route",
    "target": "dashboard"
  },
  "download": {
    "disposition": "attachment",
    "filename": "report.csv"
  },
  "inertia": {
    "component": "Dashboard/Index",
    "propsSchema": {
      "type": "object"
    }
  },
  "source": "Inertia::render",
  "via": "Inertia::render"
}
```

Supported `kind` values:
- `json_object`
- `json_array`
- `no_content`
- `redirect`
- `download`
- `stream`
- `inertia`

Notes:
- `bodySchema` replaces the old `schema` field for controller responses
- `redirect` is used for normal Laravel redirects and `Inertia::location(...)`
- `download` carries disposition/filename metadata for download/file responses
- `inertia` carries the component name and inferred props schema

## Exit Codes

- `0`: success, including partial results
- `1`: request/schema/flag validation error
- `2`: internal processing error
- `3`: schema load/validation failure

## Diagnostic Codes

The contract layer emits stable diagnostic codes. These are the codes currently produced by `oxinfer --request`:

| Code | Severity | Scope | Meaning |
|------|----------|-------|---------|
| `route.runtime_only.closure` | `info` | `route` | Runtime route uses a closure and cannot be joined to static controller analysis in v2 |
| `route.action.unsupported` | `warn` | `route` | Runtime action kind is not supported for static joining in v2 |
| `route.action.missing_static` | `warn` | `action` | Runtime route maps to a controller action that was not found in the static delta |
| `analysis.static.partial` | `warn` | `global` | Static analysis completed with partial results before the runtime join |

The machine-readable version of this list lives in [diagnostic-codes-v2.json](diagnostic-codes-v2.json).

## Notes

- `oxcribe` remains responsible for runtime route discovery, middleware, guards, bindings, and final OpenAPI assembly
- `oxinfer` remains responsible for static AST analysis, request/response shape inference, models, scopes, pivots, polymorphic relationships, broadcast channels, and response overlays
- the contract is process-local over stdio and is intended to be deterministic and machine-readable

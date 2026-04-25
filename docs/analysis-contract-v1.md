# Legacy Oxcribe Oxinfer Contract V1

Legacy note: this document is retained only as historical Oxinfer contract reference. It is not the active `deadcore` analysis contract; current public output is `deadcode.analysis.v1`.

This document defines the legacy machine contract between `oxcribe` and `oxinfer`.

`oxcribe` owns the Laravel runtime snapshot. `oxinfer` owns the static analysis. The join key is `actionKey = FQCN::method`.

## Request

`oxinfer --request -` reads an `AnalysisRequest` JSON document from stdin.

Minimum shape:

```json
{
  "contractVersion": "oxcribe.oxinfer.v1",
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
- `contractVersion` must be exactly `oxcribe.oxinfer.v1`
- `runtime.app.basePath` must be absolute and must match `manifest.project.root` after normalization
- `runtime.routes` is authoritative for runtime route inventory
- controller routes use `action.kind = controller_method` or `invokable_controller`
- invokable routes are normalized to `action.method = "__invoke"`
- closures and unknown actions are preserved in `oxcribe` but are not route-joined as static controller actions

## Response

`oxinfer --request -` emits an `AnalysisResponse` JSON document on stdout.

Minimum shape:

```json
{
  "contractVersion": "oxcribe.oxinfer.v1",
  "requestId": "req_01HX...",
  "runtimeFingerprint": "sha256:...",
  "status": "partial",
  "meta": {
    "oxinferVersion": "0.1.0",
    "partial": true,
    "stats": {
      "filesParsed": 42,
      "skipped": 0,
      "durationMs": 0
    },
    "diagnosticCounts": {
      "info": 1,
      "warn": 1,
      "error": 0
    }
  },
  "delta": {
    "meta": {
      "partial": false,
      "stats": {
        "filesParsed": 42,
        "skipped": 0,
        "durationMs": 0
      }
    },
    "controllers": [],
    "models": [],
    "polymorphic": [],
    "broadcast": []
  },
  "routeMatches": [],
  "diagnostics": []
}
```

Rules:
- `status` is `ok` when all runtime routes that can be statically joined are matched
- `status` is `partial` when any route is runtime-only, unsupported, or missing static analysis
- `delta.controllers` is filtered to matched runtime actions only
- `delta.models`, `delta.polymorphic`, and `delta.broadcast` remain the static project graph
- output is deterministic for the same request, excluding only explicitly volatile fields already normalized by contract

## Exit Codes

- `0`: success, including partial results
- `1`: request/schema/flag validation error
- `2`: internal processing error
- `3`: schema load/validation failure

## Diagnostic Codes

The contract layer emits stable diagnostic codes. These are the codes currently produced by `oxinfer --request`:

| Code | Severity | Scope | Meaning |
|------|----------|-------|---------|
| `route.runtime_only.closure` | `info` | `route` | Runtime route uses a closure and cannot be joined to static controller analysis in v1 |
| `route.action.unsupported` | `warn` | `route` | Runtime action kind is not supported for static joining in v1 |
| `route.action.missing_static` | `warn` | `action` | Runtime route maps to a controller action that was not found in the static delta |
| `analysis.static.partial` | `warn` | `global` | Static analysis completed with partial results before the runtime join |

## Notes

- `oxcribe` remains responsible for runtime route discovery, middleware, guards, bindings, and final OpenAPI assembly
- `oxinfer` remains responsible for static AST analysis, request/response shape inference, models, scopes, pivots, polymorphic relationships, and broadcast channels
- the contract is process-local over stdio and is intended to be deterministic and machine-readable

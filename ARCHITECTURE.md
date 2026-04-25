# deadcore Architecture

`deadcore` is a Rust analysis engine for Laravel dead code pruning. It reads a runtime-aware request from `deadcode-laravel`, parses PHP source with tree-sitter, builds a conservative reachability model, and emits deterministic `deadcode.analysis.v1` JSON.

## Flow

```text
CLI
  -> request loader
  -> manifest and runtime snapshot normalization
  -> deterministic PHP file discovery
  -> tree-sitter parse pipeline
  -> symbol extraction and reachability expansion
  -> findings and removal-plan assembly
  -> deadcode.analysis.v1 JSON output
```

The key design rule is evidence before deletion. `deadcore` can report broader dead-code candidates than it can safely remove; removal plans are emitted only when the engine has an isolated source range and a supported category.

## Modules

- `src/main.rs`: CLI entrypoint, request handling, output routing, and exit codes.
- `src/contracts.rs`: `deadcode.analysis.v1` request and response types.
- `src/manifest.rs`: manifest decoding and path resolution.
- `src/discovery.rs`: deterministic PHP file discovery.
- `src/parser.rs`: tree-sitter PHP integration.
- `src/source_index.rs`: source indexing and range lookup.
- `src/reachability.rs`: symbol graph and reachability expansion.
- `src/deadcode_model.rs`: dead-code symbols, findings, evidence, and removal plans.
- `src/routes.rs` and `src/matchers.rs`: Laravel-specific source extraction helpers retained for supported framework patterns.

## Concurrency

- Discovery is serial and deterministic.
- Parsing and extraction fan out by file where safe.
- Results are reduced into sorted collections before serialization.
- Output stays byte-stable enough for fixture and contract tests.

## Tests

- `tests/*_reachability_smoke.rs` cover supported Laravel surfaces.
- `tests/deadcode_contract_smoke.rs` guards the request/response contract.
- `test/fixtures/contracts/deadcode/*.json` are request-mode fixtures.
- `test/fixtures/integration/deadcode-*` are focused Laravel sample projects.

## Design Intent

- Keep static analysis native and fast.
- Keep Laravel runtime truth outside the engine.
- Prefer conservative, explainable findings over broad unsafe deletion.
- Let `deadcode-laravel` own installation, reports, staging, and rollback.

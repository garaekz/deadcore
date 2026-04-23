# Oxinfer Architecture

`oxinfer` is a single Rust crate rooted at this repository. The old Go pipeline is gone; the production runtime is the Rust binary built from [Cargo.toml](/Users/garaekz/Documents/projects/go/oxinfer/Cargo.toml).

## Flow

```text
CLI
  -> manifest or request loader
  -> filesystem discovery
  -> parse-once worker pipeline
  -> route extraction + Laravel matchers
  -> grouped delta or AnalysisResponse contract
```

The key design rule is parse once per file. Matchers and route resolution consume the same in-memory tree instead of reparsing source in later phases.

## Modules

- [src/main.rs](/Users/garaekz/Documents/projects/go/oxinfer/src/main.rs): CLI entrypoint, stdin/file handling, exit codes, output routing.
- [src/manifest.rs](/Users/garaekz/Documents/projects/go/oxinfer/src/manifest.rs): manifest decoding and path resolution.
- [src/discovery.rs](/Users/garaekz/Documents/projects/go/oxinfer/src/discovery.rs): deterministic PHP file discovery.
- [src/parser.rs](/Users/garaekz/Documents/projects/go/oxinfer/src/parser.rs): tree-sitter PHP integration.
- [src/routes.rs](/Users/garaekz/Documents/projects/go/oxinfer/src/routes.rs): Laravel route extraction and controller binding.
- [src/matchers.rs](/Users/garaekz/Documents/projects/go/oxinfer/src/matchers.rs): HTTP status, request usage, resources, scopes, pivots, polymorphic relations, and broadcast extraction.
- [src/pipeline.rs](/Users/garaekz/Documents/projects/go/oxinfer/src/pipeline.rs): Rayon-backed orchestration and reduction.
- [src/output.rs](/Users/garaekz/Documents/projects/go/oxinfer/src/output.rs): manifest-mode delta assembly.
- [src/contracts.rs](/Users/garaekz/Documents/projects/go/oxinfer/src/contracts.rs): `oxcribe.oxinfer.v2` request/response contract.

## Concurrency

- Discovery is serial and deterministic.
- Analysis fans out by file using Rayon workers.
- Results are reduced back into sorted collections before serialization.
- Output stays byte-stable across runs so fixture goldens remain exact.

## Tests

- [tests/fixture_smoke.rs](/Users/garaekz/Documents/projects/go/oxinfer/tests/fixture_smoke.rs): end-to-end manifest smoke tests over Laravel fixtures.
- [tests/routes_smoke.rs](/Users/garaekz/Documents/projects/go/oxinfer/tests/routes_smoke.rs): route extraction coverage.
- [tests/request_mode_smoke.rs](/Users/garaekz/Documents/projects/go/oxinfer/tests/request_mode_smoke.rs): contract-mode golden parity.

## Design Intent

- Remove Go-era orchestration overhead.
- Keep the public contract stable while the internals stay Rust-native.
- Favor explicit data models and one-pass extraction over layered reparsing.

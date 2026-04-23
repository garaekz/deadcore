# Contributing

`oxinfer` is a Rust project. The expected contribution loop is: change Rust code in [src](/Users/garaekz/Documents/projects/go/oxinfer/src), cover it with fixture or contract tests in [tests](/Users/garaekz/Documents/projects/go/oxinfer/tests), and keep the public CLI and contract docs aligned.

## Local Setup

Prerequisites:

- Rust stable with Cargo
- `jq` for quick JSON inspection

Core commands:

```bash
cargo build --locked
cargo test --locked
cargo fmt --all
cargo check --all-targets --locked
```

## Repo Layout

- [src](/Users/garaekz/Documents/projects/go/oxinfer/src): production code
- [tests](/Users/garaekz/Documents/projects/go/oxinfer/tests): Rust integration tests
- [fixtures](/Users/garaekz/Documents/projects/go/oxinfer/fixtures): manifest fixtures for smoke tests
- [test/fixtures](/Users/garaekz/Documents/projects/go/oxinfer/test/fixtures): Laravel sample projects and request-mode inputs
- [test/golden](/Users/garaekz/Documents/projects/go/oxinfer/test/golden): expected contract outputs
- [schemas](/Users/garaekz/Documents/projects/go/oxinfer/schemas): published JSON schemas

## Expectations

- Keep parsing single-pass per file.
- Preserve deterministic output ordering.
- Add or update tests when output shape changes.
- Update [README.md](/Users/garaekz/Documents/projects/go/oxinfer/README.md), [ARCHITECTURE.md](/Users/garaekz/Documents/projects/go/oxinfer/ARCHITECTURE.md), and [docs/analysis-contract-v2.md](/Users/garaekz/Documents/projects/go/oxinfer/docs/analysis-contract-v2.md) when the public surface moves.

## Common Workflows

Run the fixture smoke suite:

```bash
cargo test --locked --test fixture_smoke
```

Run request-mode parity tests:

```bash
cargo test --locked --test request_mode_smoke
```

Run the CLI against a fixture manifest:

```bash
cargo run -- --manifest fixtures/minimal.manifest.json
```

## Versioning

- Keep the crate version in [Cargo.toml](/Users/garaekz/Documents/projects/go/oxinfer/Cargo.toml) aligned with the exported version constant in [src/lib.rs](/Users/garaekz/Documents/projects/go/oxinfer/src/lib.rs).
- Record user-visible changes in [CHANGELOG.md](/Users/garaekz/Documents/projects/go/oxinfer/CHANGELOG.md).

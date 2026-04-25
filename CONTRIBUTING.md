# Contributing

`deadcore` is a Rust project. The expected loop is: change Rust code in `src`, cover behavior with fixture or contract tests in `tests`, and keep the public CLI and `deadcode.analysis.v1` docs aligned.

## Local Setup

Prerequisites:

- Rust stable with Cargo
- `jq` or another JSON viewer for inspecting reports

Core commands:

```bash
cargo fmt --all
cargo test --locked
cargo check --all-targets --locked
cargo build --locked --release
```

## Repo Layout

- `src`: production code
- `tests`: Rust integration and contract tests
- `test/fixtures/contracts/deadcode`: request-mode inputs
- `test/fixtures/integration/deadcode-*`: focused Laravel sample projects
- `docs`: release and fixture documentation

## Expectations

- Preserve deterministic output ordering.
- Add or update tests when output shape changes.
- Keep finding evidence truthful and compact.
- Emit removal plans only for isolated, supported source ranges.
- Update `README.md`, `ARCHITECTURE.md`, and `docs/fixtures.md` when the public surface moves.

## Common Workflows

Run all tests:

```bash
cargo test --locked
```

Run a request-mode fixture:

```bash
cargo run -- --request test/fixtures/contracts/deadcode/controller-basic.json
```

Build the release binary:

```bash
cargo build --locked --release
```

## Versioning

- Keep the crate version in `Cargo.toml` aligned with `DEADCORE_VERSION` in `src/lib.rs`.
- Record user-visible changes in `CHANGELOG.md`.

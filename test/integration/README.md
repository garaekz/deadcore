# Integration Fixtures

This directory still holds the Laravel fixture projects used by the Rust test suite. The active coverage now lives in [tests](/Users/garaekz/Documents/projects/go/deadcore/tests).

Current fixture usage:

- `test/fixtures/integration/minimal-laravel`: basic controller, model, and route coverage
- `test/fixtures/integration/api-project`: resources, form requests, pivots, and scopes
- `test/fixtures/integration/complex-app`: polymorphic relations and broadcast channels
Run the active suites with Cargo:

```bash
cargo test --locked --test fixture_smoke
cargo test --locked --test routes_smoke
```

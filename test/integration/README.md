# Integration Fixtures

This directory still holds the Laravel fixture projects used by the Rust test suite. The old Go integration harness is gone; the active coverage now lives in [tests](/Users/garaekz/Documents/projects/go/oxinfer/tests).

Current fixture usage:

- `test/fixtures/integration/minimal-laravel`: basic controller, model, and route coverage
- `test/fixtures/integration/api-project`: resources, form requests, pivots, and scopes
- `test/fixtures/integration/complex-app`: polymorphic relations and broadcast channels
- `test/fixtures/contracts/request-mode`: request payloads for contract-mode tests

Run the active suites with Cargo:

```bash
cargo test --locked --test fixture_smoke
cargo test --locked --test routes_smoke
cargo test --locked --test request_mode_smoke
```

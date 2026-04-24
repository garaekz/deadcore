# deadcore

Local incubation fork of `oxinfer` for Laravel dead code analysis.

This repo is a local-only fork used to build the Rust analysis core for controller reachability, findings, and removal plans.

## Phase 1 Request Mode

The current verified slice is controller and controller-method reachability using Laravel runtime route entrypoints plus direct call evidence.

```bash
cargo run -- --request test/fixtures/contracts/deadcode/controller-basic.json
```

The emitted `deadcode.analysis.v1` payload currently includes:

- `meta`
- `entrypoints`
- `symbols`
- `findings`
- `removalPlan`

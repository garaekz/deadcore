# deadcore

Rust analysis core for Laravel dead code pruning.

`deadcore` reads Laravel runtime facts plus project source, builds a static reachability view, and emits a deterministic `deadcode.analysis.v1` JSON report. It is designed to be called by a Laravel package or automation wrapper, not to be the whole user product by itself.

## What It Does

The current engine can classify:

- controller methods reached from Laravel runtime route entrypoints plus supported direct call expansion
- dead controller classes when all extracted controller methods are unreachable
- typed `FormRequest` classes reached from routed controller methods
- direct resource classes reached from supported controller return patterns
- command classes reached from runtime command registration
- listener classes reached from runtime listener registration
- subscriber classes reached from explicit runtime subscriber registration
- job classes reached from supported explicit dispatch patterns
- policy classes reached from the runtime Gate policy map
- model helper methods reached from supported explicit calls off already-reachable surfaces
- local scopes reached from supported explicit scope-call patterns
- relationship methods reached from supported explicit access and eager-loading patterns
- legacy and modern accessors/mutators reached from supported explicit reads, writes, and append-style metadata

The output includes evidence-oriented fields so consumers can explain why a symbol was kept alive or reported dead.

## Quickstart

Run the test suite:

```bash
cargo test --locked
```

Run a request-mode fixture:

```bash
cargo run -- --request test/fixtures/contracts/deadcode/controller-basic.json
```

Run representative coverage fixtures:

```bash
cargo run -- --request test/fixtures/contracts/deadcode/http-adjacent.json
cargo run -- --request test/fixtures/contracts/deadcode/job-reachability.json
cargo run -- --request test/fixtures/contracts/deadcode/policy-reachability.json
cargo run -- --request test/fixtures/contracts/deadcode/model-methods.json
cargo run -- --request test/fixtures/contracts/deadcode/model-scopes.json
cargo run -- --request test/fixtures/contracts/deadcode/model-relationships.json
cargo run -- --request test/fixtures/contracts/deadcode/model-attributes.json
```

See [docs/fixtures.md](docs/fixtures.md) for the fixture map and output checks.

Build a release binary:

```bash
cargo build --locked --release
```

## Contract

`deadcore` emits `deadcode.analysis.v1`.

Top-level payload fields:

- `contractVersion`
- `status`
- `meta`
- `entrypoints`
- `symbols`
- `findings`
- `removalPlan`

Reachable symbols may include:

- `reasonSummary`
- `reachabilityReasons`

Dead findings may include:

- `reasonSummary`
- `evidence`

Removal plans are emitted only when the engine has a concrete source range for a supported finding. The Laravel package decides which findings are stageable.

## Current Limits

- `FormRequest` reachability is limited to explicit typed controller parameters.
- Resource reachability is limited to direct supported controller usage.
- Controller-class deadness is defined by extracted controller methods.
- Subscriber reachability is limited to explicit runtime subscriber registration.
- Job reachability is limited to `SomeJob::dispatch(...)`, `dispatch(new SomeJob(...))`, and `Bus::dispatch(new SomeJob(...))`.
- Policy support is class-level only; policy methods are out of scope.
- Model-method reachability is limited to supported explicit calls from already-reachable controllers, commands, listeners, subscribers, jobs, policies, and model methods.
- Scope reachability is limited to explicit conventional patterns such as `Model::published()` and supported owner-resolved query-builder calls.
- Relationship reachability is limited to explicit access plus supported eager-loading patterns such as `with()`, `load()`, and `loadMissing()`.
- Accessor reachability is limited to explicit attribute reads plus append-driven serialization support.
- Mutator reachability is limited to explicit attribute writes, `setAttribute(...)`, and supported bulk write paths such as `fill`, `update`, `create`, `firstOrCreate`, `updateOrCreate`, and constructor hydration.
- Reason summaries and evidence are compact, category-level explanations. The engine does not yet expose full internal call chains.

## Relationship To `deadcode-laravel`

Use `deadcode-laravel` for the full local workflow:

- boot Laravel
- capture runtime truth
- invoke `deadcore`
- render reports
- stage conservative removals
- roll back the latest staged change set

`deadcore` owns analysis. `deadcode-laravel` owns Laravel runtime integration and remediation UX.

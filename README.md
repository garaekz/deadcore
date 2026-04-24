# deadcore

Local incubation fork of `oxinfer` for Laravel dead code analysis.

This repo is a local-only fork used to build the Rust analysis core for Laravel dead code reachability, findings, and removal plans.

## Phase 4 Request Mode

The current verified slice now covers HTTP-adjacent reachability, the first execution surfaces beyond HTTP, and the first model-heavy Laravel inference:

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

```bash
cargo run -- --request test/fixtures/contracts/deadcode/http-adjacent.json
cargo run -- --request test/fixtures/contracts/deadcode/job-reachability.json
cargo run -- --request test/fixtures/contracts/deadcode/policy-reachability.json
cargo run -- --request test/fixtures/contracts/deadcode/model-method-reachability.json
cargo run -- --request test/fixtures/contracts/deadcode/model-scope-reachability.json
cargo run -- --request test/fixtures/contracts/deadcode/model-relationship-reachability.json
cargo run -- --request test/fixtures/contracts/deadcode/model-attribute-reachability.json
```

The emitted `deadcode.analysis.v1` payload currently includes:

- `meta`
- `entrypoints`
- `symbols`
- `findings`
- `removalPlan`

Current limits:

- `FormRequest` reachability is limited to explicit typed controller parameters
- resource reachability is limited to direct supported controller usage
- controller-class deadness is still defined in terms of extracted controller methods
- subscriber reachability is limited to explicit runtime subscriber registration
- job reachability is limited to:
  - `SomeJob::dispatch(...)`
  - `dispatch(new SomeJob(...))`
  - `Bus::dispatch(new SomeJob(...))`
- policy support is class-level only; policy methods are intentionally out of scope
- model-method reachability is limited to supported explicit calls from already-reachable controllers, commands, listeners, subscribers, jobs, policies, and other already-reachable model methods
- scope reachability is limited to explicit conventional patterns such as `Model::published()` and supported owner-resolved query-builder calls
- relationship reachability is limited to explicit access plus supported eager-loading patterns such as `with()`, `load()`, and `loadMissing()`
- accessor reachability is limited to explicit attribute reads plus append-driven serialization support
- mutator reachability is limited to explicit attribute writes, `setAttribute(...)`, and supported bulk write paths such as `fill`, `update`, `create`, `firstOrCreate`, `updateOrCreate`, and constructor hydration
- model-heavy findings are additive under `deadcode.analysis.v1`, but this repo alone does not claim they are stage-safe in the Laravel package

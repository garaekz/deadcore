# deadcore

Local incubation fork of `oxinfer` for Laravel dead code analysis.

This repo is a local-only fork used to build the Rust analysis core for Laravel dead code reachability, findings, and removal plans.

## Phase 3 Request Mode

The current verified slice now covers HTTP-adjacent reachability plus the first execution surfaces beyond HTTP:

- controller methods reached from Laravel runtime route entrypoints plus supported direct call expansion
- dead controller classes when all extracted controller methods are unreachable
- typed `FormRequest` classes reached from routed controller methods
- direct resource classes reached from supported controller return patterns
- command classes reached from runtime command registration
- listener classes reached from runtime listener registration
- subscriber classes reached from explicit runtime subscriber registration
- job classes reached from supported explicit dispatch patterns
- policy classes reached from the runtime Gate policy map

```bash
cargo run -- --request test/fixtures/contracts/deadcode/http-adjacent.json
cargo run -- --request test/fixtures/contracts/deadcode/job-reachability.json
cargo run -- --request test/fixtures/contracts/deadcode/policy-reachability.json
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

# deadcore

Local incubation fork of `oxinfer` for Laravel dead code analysis.

This repo is a local-only fork used to build the Rust analysis core for controller reachability, findings, and removal plans.

## Phase 2 Request Mode

The current verified slice is HTTP-adjacent reachability:

- controller methods reached from Laravel runtime route entrypoints plus supported direct call expansion
- dead controller classes when all extracted controller methods are unreachable
- typed `FormRequest` classes reached from routed controller methods
- direct resource classes reached from supported controller return patterns

```bash
cargo run -- --request test/fixtures/contracts/deadcode/http-adjacent.json
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

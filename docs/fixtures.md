# Fixtures

`deadcore` keeps executable fixtures under `test/fixtures` so each supported category can be checked without reading the Rust tests first.

## Request Fixtures

Run any request fixture with:

```bash
cargo run -- --request test/fixtures/contracts/deadcode/controller-basic.json --out target/controller-basic.analysis.json
```

Useful fixtures:

| Fixture | What It Proves |
| --- | --- |
| `test/fixtures/contracts/deadcode/controller-basic.json` | routed controller methods stay reachable and unused controller methods are reported |
| `test/fixtures/contracts/deadcode/http-adjacent.json` | controller classes, typed `FormRequest` classes, and direct resource usage are classified |
| `test/fixtures/contracts/deadcode/command-reachability.json` | runtime-registered commands keep command classes reachable |
| `test/fixtures/contracts/deadcode/listener-reachability.json` | runtime listener registration keeps listener classes reachable |
| `test/fixtures/contracts/deadcode/subscriber-reachability.json` | explicit runtime subscriber registration keeps subscriber classes reachable |
| `test/fixtures/contracts/deadcode/job-reachability.json` | supported dispatch calls keep job classes reachable |
| `test/fixtures/contracts/deadcode/policy-reachability.json` | runtime Gate policy maps keep policy classes reachable |
| `test/fixtures/contracts/deadcode/model-methods.json` | explicit model helper calls from reachable code keep model methods reachable |
| `test/fixtures/contracts/deadcode/model-scopes.json` | supported conventional scope-call patterns keep local scopes reachable |
| `test/fixtures/contracts/deadcode/model-relationships.json` | supported explicit relationship access and eager loading keep relationships reachable |
| `test/fixtures/contracts/deadcode/model-attributes.json` | supported attribute reads, writes, appends, and bulk writes keep accessors and mutators reachable |

## Integration Projects

`test/fixtures/integration` contains small Laravel-shaped source trees. They are not full installable Laravel apps; they are source fixtures for parser, route, and reachability tests.

Use them when changing extraction logic:

```bash
cargo test --locked controller_reachability
cargo test --locked reports_unused_model_scope
```

## Output Checks

For a quick sanity check, inspect these top-level fields in the generated JSON:

- `contractVersion` must be `deadcode.analysis.v1`
- `symbols` should include both reachable and unreachable symbols for the fixture category
- `findings` should include only dead candidates
- `removalPlan.changeSets` should appear only when `deadcore` has a concrete source range

`deadcode-laravel` decides whether a removal plan is safe to stage. `deadcore` only emits the analysis contract.

# Release

`deadcore` is released at `v0.1.5` with these public surfaces treated as stable:

- CLI `deadcore --request ...`
- machine contract `deadcode.analysis.v1`
- release asset naming for the `deadcore` binary

Pre-release checklist:

1. `cargo test --locked`
2. `cargo build --locked --release`
3. Smoke the release binary with a request fixture:

   ```bash
   ./target/release/deadcore --request test/fixtures/contracts/deadcode/controller-basic.json --out target/controller-basic.analysis.json
   ```

4. Confirm the output payload has `contractVersion: "deadcode.analysis.v1"`, `findings`, and `removalPlan`
5. Confirm `README.md`, `docs/release.md`, and `CHANGELOG.md` match the current public surface
6. Confirm the release workflow matrix still matches the intended supported targets
7. Tag `v0.1.5`
8. Publish the GitHub release from that tag

Release asset contract:

- binaries are published as `deadcore_<tag>_<os>_<arch>[.exe]`
- `checksums.txt` is published in the same release bundle

Consumers that need a local binary should use this naming contract for verified installs. If a release is missing assets, the supported fallback is to build from source with Cargo.

## Proof Boundaries

Local proof can verify:

- the Rust test suite
- the optimized release build
- request-mode output shape from the built binary
- the asset naming expected by downstream installers

Local proof does not verify:

- GitHub-hosted release jobs
- uploaded release assets
- `checksums.txt` contents on GitHub
- a downstream package consuming the published release

Do not describe a release as published until the tag, GitHub release, assets, checksums, and hosted workflow run have been checked.

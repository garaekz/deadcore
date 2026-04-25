# Release

`deadcore` is released at `v0.1.4` with these public surfaces treated as stable:

- CLI `deadcore --request ...`
- machine contract `deadcode.analysis.v1`
- release asset naming for the `deadcore` binary

Pre-release checklist:

1. `cargo test --locked`
2. `cargo build --locked --release`
3. Confirm `README.md`, `docs/release.md`, and `CHANGELOG.md` match the current public surface
4. Confirm the release workflow matrix still matches the intended supported targets
5. Tag `v0.1.4`
6. Publish the GitHub release from that tag

Release asset contract:

- binaries are published as `deadcore_<tag>_<os>_<arch>[.exe]`
- `checksums.txt` is published in the same release bundle

Consumers that need a local binary should use this naming contract for verified installs. If a release is missing assets, the supported fallback is to build from source with Cargo.

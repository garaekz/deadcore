# Release

`oxinfer` is released at `v0.1.4` with these public surfaces treated as stable:

- CLI `oxinfer --manifest ...`
- CLI `oxinfer --request ...`
- machine contract `oxcribe.oxinfer.v2`
- active schema documents in `schemas/analysis-request-v2.schema.json` and `schemas/analysis-response-v2.schema.json`

Pre-release checklist:

1. `cargo test --locked`
2. `cargo build --locked --release`
3. Confirm `README.md`, `docs/analysis-contract-v2.md`, and `CHANGELOG.md` match the current public surface
4. Confirm the release workflow matrix still matches the intended supported targets
5. Tag `v0.1.4`
6. Publish the GitHub release from that tag

Release asset contract:

- binaries are published as `oxinfer_<tag>_<os>_<arch>[.exe]`
- `checksums.txt` is published in the same release bundle

`oxcribe:install-binary` relies on that naming contract for verified installs. If a release is missing assets, the supported fallback is to build from source with `OXINFER_SOURCE_ROOT`.

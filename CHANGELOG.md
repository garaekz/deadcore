# Changelog

## v0.1.4 - 2026-04-23

Corrective preview release for end-user binary distribution.

- fix the GitHub release workflow YAML so tagged releases can build and publish release binaries plus `checksums.txt`
- keep the repo-local request-mode fixture bundle and CI-hardening from `v0.1.3`
- preserve the published `oxcribe.oxinfer.v2` contract

## v0.1.3 - 2026-04-23

Corrective preview release for the `v0.1.2` request-mode test harness.

- vendor the request-mode Laravel fixture apps into the repo so CI no longer depends on a sibling `oxcribe` checkout
- resolve request-mode fixture roots from the repo-local fixture bundle first, with local sibling checkout as a fallback for development
- add a regression test that locks the fixture-root contract to the bundled repo path

## v0.1.2 - 2026-04-23

Preview release focused on request-mode fidelity, cache-backed CLI hardening, and release automation.

- split request-mode contract assembly into focused authorization, inertia, error-response, and query-builder modules
- improve route and model matching for standard Laravel controllers and custom base-model subclasses
- infer richer framework responses, resource envelopes, URI formats, and Spatie-heavy request and response metadata
- add cache-aware CLI smoke coverage plus cross-platform CI and release smoke for shipped binaries
- document the current Rust-first build, task, and release flow
- keep the published machine contract at `oxcribe.oxinfer.v2`

## v0.1.1 - 2026-04-14

Maintenance release.

- publish a first-class GitHub release workflow that emits all platform binaries plus `checksums.txt`
- document the release asset contract expected by `oxcribe:install-binary`

## v0.1.0 - 2026-03-25

Initial public freeze of `oxinfer`.

- Stable CLI for manifest-driven static Laravel analysis
- Stable machine contract `oxcribe.oxinfer.v2` via `--request`
- Deterministic JSON v2 output with route matches and diagnostics
- Laravel-aware inference for request shapes, responses, resources, auth hints, and supported Spatie integrations
- Repository build/test flow moved to Cargo

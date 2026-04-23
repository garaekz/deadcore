# Request Mode Goldens

This directory contains request/response golden pairs for the `oxinfer --request` contract.

Each request fixture exercises a specific join behavior between runtime routes and static analysis:

- `matched-invokable.json` verifies `controller_method`, `invokable_controller`, and `closure` handling.
- `missing-static.json` verifies the `missing_static` path and partial response behavior.

The corresponding response files are the byte-for-byte expected outputs from the CLI.

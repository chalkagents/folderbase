# Contributing to Folderbase

Thank you for helping build Folderbase.

## Before starting

- Search existing issues and pull requests.
- Open an issue before undertaking a large feature or architectural change.
- Report vulnerabilities privately as described in `SECURITY.md`.
- Follow `CODE_OF_CONDUCT.md`.

Folderbase is in a full-eclipse rename. New public names must use `Folderbase`,
`folderbase`, `folderbase-core`, or `folderbase-cli` as appropriate. Do not add
legacy compatibility aliases unless an accepted issue explicitly requires one.

## Development

Install Rust 1.96 or newer with the `rustfmt` and `clippy` components. Before
submitting a change, run:

```sh
scripts/check-public-eclipse.sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features --locked
scripts/test-package-install.sh
```

## Pull requests

Keep pull requests focused and explain the user-visible behavior, risks, and
tests. Add or update tests for behavioral changes. CI must pass, and unrelated
formatting or generated files should not be included.

By contributing, you agree that your contribution is licensed under the
Apache License, Version 2.0.

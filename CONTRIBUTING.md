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

Install Rust 1.96 or newer with the `rustfmt` and `clippy` components. Always
run the repository policy checks before submitting a change:

```sh
scripts/check-ci-policy.sh
scripts/check-public-eclipse.sh
```

For Core or protocol changes, also run the Linux Core lane locally:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features --locked
node protocol/conformance/cli-json-v1/run.mjs --implementation ./target/debug/folderbase
node protocol/conformance/capabilities/run.mjs --implementation ./target/debug/folderbase
node --test protocol/conformance/capabilities/run.test.mjs scripts/tests/capability-contract.test.mjs
```

For npm launcher changes, run:

```sh
npm test --prefix packages/npm-cli
node scripts/test-npm-cli-package.mjs
```

For documentation-site changes, run:

```sh
node --test scripts/tests/docs-site.test.mjs
npm ci --prefix apps/docs
npm test --prefix apps/docs
```

For ordinary local feature work, run the fresh package installation proof when
changing Cargo workspace manifests, the native CLI package, packaged Core
assets, or package-install scripts:

```sh
scripts/test-package-install.sh
```

CI classifies changed paths using `scripts/ci/classify-changes.mjs`. Pull
requests run only their applicable Linux or documentation lanes. Cross-platform Core checks run
after merge, every Monday, on demand, and again for native releases. CI also
runs every lane when protocol, release-orchestration, or CI controls change—or
when a new path has not yet been classified—so contract-affecting work fails
closed.

## Pull requests

Keep pull requests focused and explain the user-visible behavior, risks, and
tests. Add or update tests for behavioral changes. CI must pass, and unrelated
formatting or generated files should not be included.

By contributing, you agree that your contribution is licensed under the
Apache License, Version 2.0.

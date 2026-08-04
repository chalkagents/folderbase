# Releasing Folderbase Core

A stable Core release is complete only when the same version works through
GitHub binaries, npm, crates.io, and Homebrew. The tag workflow now performs
the dependency-ordered publication and clean public verification:

1. merge a commit whose Cargo workspace and `@folderbase/cli` versions match;
2. pass CI, package extraction, and the public conformance runner;
3. create the canonical annotated `v<version>` tag and push it;
4. let `release-cli.yml` publish `folderbase-core`, then `folderbase-cli`, the
   four native binaries and `SHA256SUMS`, `@folderbase/cli`, the independently
   versioned `@folderbase/sdk`, and the Homebrew formula; and
5. require the workflow's clean macOS public-install job to pass.

The first npm publication requires the package owner to claim the package and
configure this repository's `release-cli.yml` trusted publisher. Later npm
publishing uses GitHub OIDC. Configure these release authorities:

- `FOLDERBASE_IMMUTABLE_RELEASES_READ_TOKEN`: source-repository
  Administration read only;
- `CARGO_REGISTRY_TOKEN`: crates.io publish authority for the two Folderbase
  crates; and
- `FOLDERBASE_HOMEBREW_TAP_TOKEN`: contents write only for
  `chalkagents/homebrew-tap`.

Release credentials are never committed. The immutable-release read token is a
separate repository-scoped, Administration-read credential; GitHub release
writes continue to use the short-lived workflow token.

## Start or resume a release

```sh
git tag -s vVERSION -m "Folderbase Core vVERSION"
git push origin vVERSION
```

To resume an interrupted exact release, dispatch **Release Folderbase Core
distributions** with the existing tag. Registry integrity checks make the
rerun idempotent; different bytes fail closed.

## Public smoke test

Run these against public registries, not local packages or caches:

```sh
npx --yes @folderbase/cli@VERSION init .
cargo install folderbase-cli --version VERSION --locked
brew install chalkagents/tap/folderbase
npm install @folderbase/sdk@SDK_VERSION @folderbase/cli@VERSION
```

For each installed executable, create a new temporary ordinary folder and run:

```sh
folderbase protocol contract --json
folderbase init . --json
folderbase validate . --json
```

Download each GitHub asset named in `SHA256SUMS`, verify its digest, and execute
the same contract/init/validate smoke on its supported host. A missing channel,
mutable or mismatched asset, registry digest mismatch, or failed smoke test
leaves the release incomplete.

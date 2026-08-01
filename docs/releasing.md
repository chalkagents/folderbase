# Releasing Folderbase Core

A stable Core release is complete only when the same version works through
GitHub binaries, npm, crates.io, and Homebrew. Publish in this dependency order:

1. merge a commit whose Cargo workspace and `@folderbase/cli` versions match;
2. pass CI, package extraction, and the public conformance runner;
3. create the immutable `v<version>` tag and let `release-cli.yml` publish the
   four native binaries, `SHA256SUMS`, and npm launcher;
4. publish `folderbase-core`, wait until crates.io resolves the exact version,
   then publish `folderbase-cli`;
5. update `chalkagents/homebrew-tap/Formula/folderbase.rb` from the immutable
   GitHub asset URLs and exact `SHA256SUMS`; and
6. test every public command from a clean temporary directory.

The first npm publication requires the package owner to claim
`@folderbase/cli` and configure the repository's trusted publisher. Later npm
publishing uses GitHub OIDC. crates.io publication uses a registry token. The
Homebrew tap update uses repository-scoped write authority for the tap only.

Release credentials are never committed. The immutable-release read token is a
separate repository-scoped, Administration-read credential; GitHub release
writes continue to use the short-lived workflow token.

## Public smoke test

Run these against public registries, not local packages or caches:

```sh
npx --yes @folderbase/cli@VERSION init .
cargo install folderbase-cli --version VERSION --locked
brew install chalkagents/tap/folderbase
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

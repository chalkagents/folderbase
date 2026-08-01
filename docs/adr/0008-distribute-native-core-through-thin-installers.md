# ADR-0008: Distribute native Core through thin installers

## Status

Accepted

## Context

Folderbase Core is the portable open-source engine beneath the App, Cloud, and
agent integrations. Requiring every user or remote agent VM to install Rust,
clone the repository, and compile Core prevents the five-minute adoption path.

The installation surface must not redefine Folderbase as a Node.js library.
Folderbase applies to ordinary folders of every kind, and the native Core
binary remains the protocol and filesystem authority. The unscoped npm package
name `folderbase` is also owned by an unrelated project.

Remote coding environments commonly provide Node.js and can run `npx`, while
macOS users expect a signed App or Homebrew installation. These are
distribution surfaces for one native engine, not separate implementations.

## Decision

Folderbase publishes one native `folderbase` executable per supported operating
system and CPU architecture as an immutable GitHub release asset. The initial
matrix is:

- `aarch64-apple-darwin`
- `x86_64-apple-darwin`
- `aarch64-unknown-linux-gnu`
- `x86_64-unknown-linux-gnu`

Every release publishes a closed `SHA256SUMS` record. Existing release assets
are never silently replaced: a repeated release job may accept an exact
byte-for-byte existing asset, but a different artifact under the same name
fails the release.

Native installer releases are published only after GitHub release immutability
is enabled for the repository. The workflow creates a draft, attaches the
complete closed asset set, publishes it, and verifies that GitHub reports the
result as immutable. A published mutable release is rejected rather than
backfilled in place. Historical source-only releases created before this
decision are not retroactively described as immutable.

`@folderbase/cli` is a public, dependency-free npm launcher whose version
matches the native Core release. It:

1. selects the exact native artifact for the host;
2. obtains that artifact and its checksum record over HTTPS;
3. refuses missing, duplicate, malformed, oversized, or mismatched artifacts;
4. installs the verified executable atomically into a versioned user cache;
5. re-hashes a cached executable before every invocation; and
6. forwards arguments, standard streams, signals, and exit status without a
   shell.

The package has no installation lifecycle script. It does not modify the
current project, add itself to `package.json`, or place Core in `node_modules`.
The primary ephemeral command is:

```sh
npx @folderbase/cli init .
```

The npm package is published from a public GitHub-hosted workflow through npm
trusted publishing with short-lived OIDC credentials and provenance. No
long-lived npm write token is stored in the repository.

Exact npm versions are immutable while `latest` and `next` are mutable discovery
channels. Rerunning an already-published exact version verifies its integrity
without requiring that it still owns a channel. Publishing an older missing
version uses and then removes a temporary backfill tag so neither public
channel can move backward.

The macOS App will separately bundle a compatible native Core inside its
signed, notarized application boundary. Homebrew may provide a persistent CLI
installation. Both must execute the same released CLI behavior and protocol
version rather than fork Core.

## Consequences

- Coding-agent VMs receive a one-command bootstrap without changing the Core
  implementation language.
- Node.js is required only for the ephemeral npm launcher, not for a separately
  installed native CLI or the App.
- Every launcher release requires the full native build matrix and exact
  package-version agreement.
- GitHub release availability is part of the initial `npx` installation path.
  A future mirror may be added only with equivalent immutable identity and
  verification.
- GitHub release immutability is a repository-level operational prerequisite.
  Because GitHub applies it only to future releases, an empty mutable release
  that predates native distribution must be removed before the same tag is
  assembled and published through the immutable draft workflow.
- SHA-256 and HTTPS detect accidental corruption and bind the cache to the
  published release record. They do not substitute for platform code signing
  or protect against a hostile same-user account that can alter the launcher
  and its cache.
- The literal `npx folderbase` command remains unavailable unless the unrelated
  package owner voluntarily transfers the npm name. Acquiring that name may
  add a compatibility launcher later, but it does not change this architecture.

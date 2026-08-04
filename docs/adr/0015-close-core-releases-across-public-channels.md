# ADR-0015: Close Core releases across public channels

## Status

Accepted

## Context

A Folderbase Core version is not useful merely because a Git tag exists. The
same executable must be obtainable through the installation paths used by
humans, local agents, native apps, and remote VMs. Core 0.5 reached GitHub,
npm, crates.io, and Homebrew, but the dependency order and tap update still
required manual coordination. The public TypeScript adapter adds a second npm
package whose version is intentionally independent from Core's SemVer.

Partial publication is normal external state. A job can stop after one crate,
after immutable GitHub assets, or before a registry tag advances. Retrying must
never replace published bytes, roll a channel backward, or rebuild a Homebrew
formula from mutable state.

## Decision

### One tag drives one serialized publication closure

The canonical annotated `v<core-version>` tag points at a commit whose Cargo
workspace and `@folderbase/cli` versions match. The release workflow builds and
conforms the exact tag on all supported native targets, seals those binaries in
`SHA256SUMS`, and enters one non-cancelling FIFO publication lock.

Channel writes occur in dependency order:

1. `folderbase-core` on crates.io;
2. `folderbase-cli` on crates.io after the exact Core crate resolves;
3. immutable GitHub native assets and `SHA256SUMS`;
4. `@folderbase/cli` on npm;
5. the independently versioned `@folderbase/sdk` on npm; and
6. `chalkagents/homebrew-tap/Formula/folderbase.rb`, rendered only from the
   immutable GitHub tag and sealed checksums.

After all writes, a clean macOS runner installs and executes the public npm,
SDK, Cargo, and Homebrew paths. A release is incomplete until that job passes.

### Every registry write is idempotent and fail-closed

Before publishing an existing npm package or crate version, the workflow packs
the local artifact and compares its immutable registry integrity or checksum.
Equal bytes skip publication. Different bytes, a yanked crate, an inconsistent
dist-tag, or a backward channel move fails the release.

GitHub releases are assembled as drafts, verified against the exact remote
tag, published once, and required to become immutable. The Homebrew formula is
deterministically rendered from the four expected checksum entries. It updates
only one path in the tap and verifies the stored bytes after the write.

An interrupted run is resumed by dispatching the same tag. It discovers the
completed channel writes and continues from the first missing publication.

### Authorities stay narrow

- GitHub release writes use the repository's short-lived workflow token.
- Immutable-release setting reads use a separate Administration-read token.
- crates.io uses `CARGO_REGISTRY_TOKEN` only in the crate publication step.
- npm uses trusted-publisher OIDC in the npm environment.
- Homebrew uses `FOLDERBASE_HOMEBREW_TAP_TOKEN`, scoped to the tap repository;
  the default workflow token is sufficient only for an already-complete
  read-only rerun.

No credential is committed, copied into an artifact, or shared between these
authorities.

## Consequences

- `npx`, Cargo, Homebrew, GitHub binaries, and `@folderbase/sdk` describe one
  verified public release closure.
- Maintainers can safely rerun a partially completed release.
- Core and SDK may version independently without weakening their immutable npm
  checks.
- A missing narrow registry credential blocks that channel rather than
  silently declaring the release complete.
- Release runs spend native matrix minutes only for tags and explicit
  backfills; pull requests retain the existing path-scoped CI lanes.

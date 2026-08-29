# ADR-0020: Apply exact descendant Versions to existing roots

## Status

Proposed

Proposed: 2026-08-29

Founder confirmation required before implementation.

## Context

Accepted ADR 0016 reconstructs one exact Folderbase Version into an absent
ordinary root. It intentionally never overwrites, merges, deletes, or updates
an existing destination. Those operations are synchronization and conflict
handling.

Platform ADR 0036 separately accepts automatic owner synchronization between
two equal active Devices. A Device must compare exact Version ancestry, fetch
and verify required bytes, apply safe remote work to its existing ordinary
root, and advance its Device Cursor only after local verification. Platform's
current hosted-bootstrap tracer proves publication and clean-device
reconstruction, but it cannot apply the next Remote Head to an already-present
root.

Platform must not recreate Core's portable-path, Version, filesystem,
transaction, Local Head, or conflict semantics. Root reconstruction cannot be
reinterpreted as an in-place update, and replacing the complete root would
silently discard uncaptured local work or excluded ordinary entries.

The tracking issue is
[folderbase#88](https://github.com/chalkagents/folderbase/issues/88).

## Proposed decision

### One separately advertised local reconciliation capability

Core should add the optional capability
`folderbase.version-reconciliation@0.1.0` with one mutating process command:

```text
folderbase version reconcile ROOT PACKAGE --stdin --json
```

`ROOT` is one existing managed ordinary Folderbase root. `PACKAGE` is one
closed root-reconstruction package for the target Version. Standard input is a
closed `folderbase-version-reconciliation-request-v1` document binding:

- one caller-generated opaque operation ID;
- the expected current Local Head Version ID;
- the exact target Folderbase Version ID; and
- the expected SHA-256 of the exact encoded reconstruction-package index.

Arguments are explicit paths. Current working directory, a Remote Head,
provider key, share link, Folder Scope, Device Cursor, Cloud receipt, or package
possession grants no additional authority.

This should be one deep Core module. The caller cannot separately import
Version state, plan path mutations, publish ordinary paths, or move Local Head.
Core owns those steps as one operation and exposes only the typed result.

### Version 0.1 is exact fast-forward application

The target must be a direct descendant of the request's expected current Local
Head. Core first captures the current root through the normal exact capture
path. Application proceeds only when that captured Version is exactly the
expected current Version and the package target names it as a parent.

This rule makes the first capability sufficient for alternating online Device
edits while remaining lossless. A local edit, a different current Version, or
divergent ancestry returns typed attention without changing any ordinary path
or Local Head. Concurrent/offline divergence and object-scoped merging remain
a later capability revision or separately confirmed extension. Version 0.1
never chooses a winner.

Exact replay after the target is already installed returns the original
success when the durable completion record and current root attestation match.
It creates no new Version or visible mutation.

### Exact managed-entry delta

Core validates the complete package and both base and target Versions before
ordinary mutation. It derives the exact managed-entry delta from those
Versions, not from arrival time, provider metadata, path guesses, or caller
instructions.

Application:

1. retains a no-follow capability to the existing physical root and proves it
   remains the same root throughout the operation;
2. validates the package closure, target Version, manifests, chunks,
   Tombstone fidelity, and base-to-target ancestry;
3. captures and verifies the current root, refusing any uncaptured work;
4. prepares every replacement byte and complete forward-recovery record before
   the first visible mutation;
5. applies additions, updates, moves, deletions, executable fidelity, safe
   symlinks, and explicit empty directories as one crash-safe transaction;
6. preserves local entries that both Versions classify as excluded or outside
   the managed portable state;
7. imports the exact target Version and immutable Object Version associations
   into local Core state;
8. moves Local Head to that exact target Version without manufacturing another
   Version; and
9. reopens and verifies the resulting root and Local Head before success.

Nested Folderbases remain independent boundaries. Special nodes, unsafe links,
path aliases, root replacement, changed package identities, or a changed
current capture fail closed. Core never follows provider locations and never
reports a partial success.

### Crash, replay, and output

The operation ID plus canonical request digest is the replay key. A compact
engine-owned journal binds preparation, first mutation, imported immutable
state, Local Head publication, verification, and completion. Every mutating
Core entry point recovers an existing reconciliation journal before starting
new work.

Process loss converges to either the exact pre-apply state or the exact target
state. A visible mixture is never a stable outcome. Reusing an operation ID
with changed request or package bytes is an operational error.

Success exits `0` with one bounded
`folderbase-version-reconciliation-result-v1` document that binds the
operation/request digests, Folderbase ID, previous and target Version IDs,
target canonical digest, package-index digest, resulting root attestation,
verified counts/bytes, and replay status.

Attention exits `1` with one bounded
`folderbase-version-reconciliation-attention-v1` document. The closed initial
dispositions are:

- current local work changed;
- target is not a direct descendant;
- root or nested boundary changed;
- target is already present but cannot be proven as exact replay; and
- destination capacity or filesystem behavior cannot safely complete.

Malformed input, unverifiable packages, unsafe paths, integrity failures, and
operational failures exit `2` with empty stdout and one bounded error on
stderr. No output carries Cloud identity, provider routing, credentials, or
private journal paths.

### Public conformance and release

The capability package, schemas, fixtures, and independent black-box runner
close together before advertisement. Conformance must cover ordinary Markdown,
CSV, PDF, office, database snapshot, media, archive, executable, unknown
binary, Git working-tree, safe-symlink, empty-directory, Tombstone, exclusion,
move, and nested-boundary cases.

Deterministic crash points cover prepared journal, first visible mutation,
immutable-state import, Local Head publication, and completion record. The
runner proves fixed-memory transfer, no-clobber local-work refusal, exact replay,
physical-root continuity, and no mutation outside the managed delta.

## Deliberate non-goals

This proposal does not define Cloud authentication, Remote Head selection,
Device Cursor mutation, provider transfer, event delivery, sharing, recipient
projection checkout, automatic text merge, opaque conflict resolution, Keep
Local, Archive, File Provider, or App UX.

It does not claim that a fast-forward capability completes bidirectional sync.
It supplies the missing exact-Core mutation primitive for the first alternating
two-Device tracer. Divergent inputs remain preserved by refusing mutation.

## Consequences

- Platform can apply a verified direct-descendant Remote Head without becoming
  a second filesystem or Version authority.
- The first MacBook-to-Mac-mini-to-MacBook alternating-edit test can use one
  released process contract and advance each Cursor only after exact success.
- Existing-root mutation and crash recovery add substantial Core work, but the
  complexity remains behind one small interface shared by native and hosted
  callers.
- Offline divergence, automatic disjoint reconciliation, and conflict records
  remain explicit subsequent work rather than being hidden behind overwrite.

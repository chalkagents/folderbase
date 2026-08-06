# ADR-0016: Reconstruct exact Folderbase Versions into new ordinary roots

## Status

Proposed

Founder confirmation: pending for the exact public capability and process
contract below. The product direction and no-clobber boundary were previously
accepted in Folderbase Platform ADR-0026, but that decision did not freeze this
public Core interface.

## Context

`folderbase-version-v1` is the bounded full state of one Folderbase boundary.
Chunk Manifest v1 can transfer and verify one immutable opaque object, and a
`PersistentTransfer` can materialize one verified object beneath a retained
filesystem capability. Neither surface reconstructs an absent Folderbase root.

The existing commands are deliberately different:

- `folderbase version restore` restores one locally retained Object Version to
  one new path inside an existing Folderbase; and
- `folderbase change-set checkout` creates a permission-scoped, disposable
  working projection from an already populated source workspace.

Treating either operation as clean-device restore would misstate authority and
completeness. A fresh device, remote agent VM, or independent implementation
needs one provider-neutral operation that consumes a complete retained Version
and verified object transfer data, reconstructs normal files of every type, and
publishes one absent root only after exact verification.

There is also a closure problem that must not be hidden. A Folderbase Version
directly binds the digest and length of its root manifest and live regular
files. A Tombstone binds its last Object Version ID but does not repeat that
Object Version's digest or byte length. Current managed Version registration
retains only the root manifest and live regular-file references. Reconstructing
only that set would make the visible tree look complete while dropping the
retained bytes needed by later Tombstone restore.

## Decision

### One separately advertised root capability

Core will add the stable optional capability
`folderbase.root-reconstruction@0.1.0`. It does not expand Compatibility
Contract v1 and is advertised only after its public black-box suite passes.

Its only mutating process command is:

```text
folderbase reconstruct SOURCE DESTINATION --stdin --json
```

`SOURCE` is one no-follow reconstruction package directory. `DESTINATION` is
an absent child beneath an existing ordinary directory. Standard input is one
closed `folderbase-root-reconstruction-request-v1` document containing a
caller operation ID and the expected SHA-256 of the exact encoded package
index. Arguments are explicit paths; current-working-directory discovery,
share links, provider locations, and ambient `.folderbase` state grant no
authority.

This capability is root reconstruction only. It never accepts a Folder Scope,
does not create a scoped projection, and never advances a Remote Head, Device
Cursor, or Cloud authorization record. The Platform must invoke it only after
its own Root Reconstruction Session authorizes the exact package.

### Closed provider-neutral package

The package is transport input, not canonical Folderbase history:

```text
SOURCE/
├── index.json
├── version.json
├── manifests/<chunk-manifest-sha256>.json
└── chunks/<chunk-sha256>
```

Every node is an exact allowlisted no-follow regular file or directory. Extra
entries, aliases, symlinks, special nodes, unsafe permissions, changed
identities, or an index whose encoded SHA-256 differs from the request fail
closed. Identical manifests and chunks may be referenced more than once.

`index.json` is a closed, bounded
`folderbase-root-reconstruction-package-v1` record. It binds:

- the exact Folderbase ID, Folderbase Version ID, canonical Version SHA-256,
  and encoded `version.json` SHA-256;
- a strictly sorted, unique array mapping every externally materialized Object
  Version ID to one canonical Chunk Manifest digest;
- each reference's role: `root_manifest`, `live_regular_file`, or
  `retained_tombstone`;
- the stable Object ID when the Version contains one; and
- fixed format and size/count limits.

The exact encoded package-index SHA-256 is a transport pin, not another Version
identity. The Folderbase Version canonical digest remains the complete visible
state identity. Chunk Manifest digests remain transfer-plan identities.

The reference closure is exact:

1. the root manifest has exactly one `root_manifest` reference;
2. every live regular binding has exactly one matching
   `live_regular_file` reference;
3. every Tombstone with `last_object_version_id` has exactly one matching
   `retained_tombstone` reference;
4. directories require no object bytes;
5. live symlink Object Version content is derived from and checked against the
   exact UTF-8 target already bound by the Version; and
6. no unreferenced Object Version or manifest is accepted.

For the root manifest and live regular files, Core cross-checks the canonical
manifest's whole-object digest and length against the Folderbase Version. For a
retained Tombstone, the package index binds the exact Object Version-to-manifest
association because Version v1 intentionally omits the deleted content digest.
Core reports that distinction honestly: it verifies the supplied retained
object bytes and preserves their immutable local association, but does not
claim the Folderbase Version alone authenticates Tombstone content. Platform
must retain the immutable association established during authenticated Version
registration. Future Version formats may bind a closure digest without
reinterpreting v1.

### Deterministic plan, bounded reconstruction, and publication

Core first decodes and validates the complete Folderbase Version and package,
then produces an opaque deterministic request digest and a bounded
reconstruction plan. No workspace path changes during planning.

Execution:

1. retains a no-follow capability to `DESTINATION`'s already-open parent and
   proves the final name is absent;
2. creates one private operation-owned staging root through that capability;
3. validates every manifest, streams every chunk with fixed memory, verifies
   every whole-object identity, and constructs the complete ordinary tree;
4. installs the exact root manifest, portable Folderbase Version, immutable
   local Object Version/blob state, derived object projections, and a
   version-derived Local Head needed for normal subsequent Core operation;
5. creates explicit empty directories and safe symlinks, preserves exact path
   spelling and executable fidelity, and keeps Tombstones non-visible;
6. represents nested Folderbases and unsupported special nodes only through
   the Version's exclusions and never traverses or fabricates their content;
7. verifies the staged root through the same public Core read/validation paths;
8. durably flushes files and supported directory entries; and
9. publishes the complete root through an atomic no-replace operation on the
   retained destination-parent capability.

Markdown, repositories, PDF, CSV, SQLite snapshots, office documents, videos,
archives, and unknown regular files all remain opaque bytes. Core does not
infer application-consistent database provenance from a filename. Generated or
reconstructable content absent from the sealed Version remains absent and is
recreated only by its normal external tool.

Core never overwrites, merges, deletes, evicts, or reorganizes an existing
destination. Updating an existing Folderbase is synchronization and conflict
handling, not reconstruction.

### Restart and trusted completion

The operation ID plus exact request digest is the replay key. A durable private
journal classifies preparation, verified staging, publication, and completion.
Before publication, restart resumes or removes only exact operation-owned
private state. After publication, Core never deletes the visible root.

An exact replay may return the prior success only when a closed engine-owned
completion record inside that root matches the operation, request, Version,
canonical Version digest, package-index digest, and current root attestation.
Any other existing destination is `destination_occupied` attention.

Success exits `0`, writes one bounded
`folderbase-root-reconstruction-result-v1` document to stdout, and leaves
stderr empty. The result binds the operation and request digests, Folderbase and
Version identities, canonical Version and package-index digests, verified
object and visible-entry counts, verified opaque bytes, current root
attestation, and whether the result is a replay. It is trusted only when
produced by the supervised compatible Core process against the current root;
it is not bearer authorization.

Attention exits `1` with one bounded typed document on stdout. Malformed input,
unverifiable bytes, unsupported filesystem behavior, and operational failures
exit `2` with empty stdout and one bounded typed error on stderr. Exact codes
and schemas are part of this capability, not base CLI JSON v1.

### Public conformance and release

The normative package lives under:

- `protocol/capabilities/root-reconstruction/0.1.0/`;
- `protocol/schemas/capabilities/root-reconstruction/0.1/`; and
- `protocol/conformance/capabilities/root-reconstruction-0.1/`.

The independent runner resolves one candidate executable without a shell and
proves behavior from only public fixtures. Advertising the capability requires
the full suite to pass. A Go, TypeScript, or other implementation can consume
the same schemas, fixtures, and runner without reading Rust or Platform code.

## Red-green acceptance

Red fixtures and black-box cases cover:

- malformed, oversized, wrong-Folderbase, wrong-Version, wrong-digest, and
  changed package/index/version inputs;
- missing, duplicate, extra, truncated, corrupt, reordered, and aliased
  references, manifests, descriptors, and chunks;
- omission or substitution of root, live-regular, or retained-Tombstone
  references;
- unsafe paths, exact/NFC/case-fold collisions, symlink escapes, nested
  boundary crossing, special nodes, and destination-parent substitution;
- every existing destination kind and races immediately before publication;
- process loss before and after every durable boundary, lost success output,
  changed-input replay, and private-stage substitution;
- fixed-memory reconstruction of sparse and synthetic multi-gigabyte objects;
  and
- attempts to use a projection, share link, provider key, caller receipt, or
  Cloud identity as Core authority.

Green proves:

- byte-for-byte reconstruction of Markdown, CSV, PDF, DOCX, immutable SQLite,
  media, archive, unknown binary, executable, safe symlink, empty directory,
  Tombstone, nested-boundary, and Git working-tree fixtures;
- a subsequently opened Core sees the exact Version as Local Head and can
  capture ordinary follow-up edits without importing private package state;
- a retained regular-file Tombstone remains restorable after clean-device
  reconstruction;
- bounded memory, exact no-clobber publication, restart convergence, and exact
  replay; and
- independent black-box conformance from a clean extracted source archive.

## Deliberate non-goals

This decision does not define authentication, Cloud session APIs, signed
download URLs, provider routing, Device Cursor advancement, Projection
Checkout, synchronization into an existing root, conflict resolution, archive
policy, File Provider, automatic reorganization, or Cloud Agent scheduling.

## Consequences

- Core gains the missing KISS bridge from immutable retained database state to
  a normal local or VM workspace without becoming Cloud-aware.
- A full root can be reconstructed by independent implementations while scoped
  sharing continues to use the distinct Change Set checkout capability.
- Platform Version registration must retain exact references for Tombstone
  Object Versions, not just the visible root and live regular files.
- The package index is intentionally a transport closure. It does not alter the
  released Folderbase Version v1 digest or Compatibility Contract v1.
- Directory-level no-replace publication and restart recovery add real
  implementation work, but prevent a partially restored tree from being
  mistaken for an agent-ready Folderbase.


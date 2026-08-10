# ADR-0018: Journal exact Folder Scope evidence under Core authority

## Status

Accepted

Proposed: 2026-08-10

Accepted: 2026-08-10

## Context

Folderbase Cloud allocates a durable Folder Scope when a person first shares a
selected ordinary folder. The Folderbase App can hold the selected filesystem
root, but it must not invent another identity method by walking the tree or
binding sharing to a pathname, inode, Git remote, content similarity, or a
Cloud-generated identifier.

Pathnames change. Physical filesystem identifiers are platform-local and may
be reused. A copied `.folderbase` directory must not impersonate the original
root. A nested Folderbase is an independent governance boundary. The current
Local Head may also advance between observation and publication. Exact Core is
the only component that already owns root attestation, metadata capture,
nested-boundary detection, local Version continuity, and private durable state.

The first-share handoff therefore needs a small public process contract that
describes the exact selected folder without leaking an absolute path, raw
filesystem identity, local secret, Cloud credential, grant, observer
capability, file content, or unrelated Object metadata.

## Decision

### One stable optional capability

Core exposes the stable optional capability
`folderbase.folder-scope-evidence@0.1.0`. It does not expand Compatibility
Contract v1. Support is discovered through:

```text
folderbase protocol contract --json
```

The universal mutating process seam is:

```text
folderbase folder-scope observe ROOT SELECTED_PATH --json
```

`ROOT` is one explicitly supplied, attested Folderbase Root.
`SELECTED_PATH` is one safe, nonempty, root-relative ordinary directory. It may
be a repository and may contain files of every type. Selecting `.folderbase`,
`.git`, a symlink, an excluded path, a special node, or a path outside the root
fails closed.

Daemon stdio 0.1 remains a root-pinned query and hint session. It does not
proxy this private-journal mutation. Long-lived clients discover the
capability through the contract command and supervise the one-shot process.

### Evidence and identity ingredients

Success returns exactly one bounded
`folderbase-folder-scope-evidence-v1` document containing:

- the canonical Folderbase ID;
- the canonical selected relative path;
- an idempotent journal event ID;
- a monotonic device-local sequence;
- an opaque Core-owned binding proof; and
- the strictly sorted root-relative nested Folderbase boundaries beneath the
  selection.

Core derives the record while holding the exact root and selected folder with
no-follow filesystem capabilities. The private binding combines the attested
Folderbase identity, root-instance continuity, selected-folder physical
continuity, and one Core-generated non-reusable journal nonce in a
domain-separated digest. The nonce is created once per newly proven folder
binding, recovered from an exact orphan event after a crash, and retained
across proven renames. Raw platform identifiers, the nonce, and other binding
ingredients never cross the public interface.

Physical identity is only a local continuity hint bound to Core-owned journal
state. It is not the public identity, is not portable, is not sufficient
authority by itself, and is never accepted from a caller. The public opaque
binding proof remains stable across a proven physical rename of the selected
folder. Replacing the selected folder, replacing or copying the root, or losing
the retained continuity causes refusal rather than silent reallocation.

The event identity binds the current selected relative path, current Local
Head, opaque proof, and exact nested-boundary attestations. Repeating an
identical observation returns the original event and sequence. A proven rename
or Local Head advance creates a new event while retaining the same binding
proof. An earlier A observation remains replayable after A → B → A without
allocating a second identity for A.

Nested boundaries are reported root-relative so an authorized observer can
confine later work. Internally, Core retains each boundary's Folderbase ID,
protocol version, manifest digest, and physical Root Instance digest and
compares that attested identity relative to the selected folder. A proven
rename rebases the public paths without claiming the boundary changed. Adding,
removing, replacing at the same path, or crossing a nested Folderbase after the
first observation fails closed.

### Exact observation and durable private journal

Core plans the metadata-only capture before and after the observation while
holding the shared transaction lease. Both plans must bind the same exact
Local Head and visible inventory. A stale plan, unsupported node, symlink
escape, nested-boundary change, or physical substitution produces a typed
operational error and does not advance the evidence journal.

The device-local journal lives under
`.folderbase/local/folder-scope-evidence-v1/`. It is engine-owned state, not a
portable Folderbase Version and not shared authorization. Events form one
bounded, deterministic-after-allocation, append-only sequence with an
independently durable head. Core validates the complete retained chain and
exact journal root/event namespaces, rejects unknown entries and tampering,
and limits the profile to 16,384 events and 16,384 nested boundaries.

A crash after writing the exact next event but before advancing the head is
recoverable. Any other orphan, gap, duplicate, changed event, or unrecognized
journal node fails closed. Replay never mutates ordinary workspace files.

### Authority separation

Folder Scope Evidence proves local filesystem continuity only. It is not a
Folder Scope ID, bearer token, grant, Cloud snapshot, membership claim, or
permission decision. Core contains no Cloud account, recipient, role, expiry,
share-link, provider, or transport state.

An authenticated control plane may consume supervised evidence through its
accepted local observer contract, capture or verify the exact immutable
Version bytes, and allocate one stable Folder Scope ID at first share. Cloud
remains authoritative for humans, agents, grants, expiry, audit, and live
publication. Possessing or copying local evidence never grants access.

Apps, SDKs, agent harnesses, and remote VMs invoke the public process contract.
They do not read, write, repair, or reinterpret `.folderbase` internals. The
TypeScript SDK validates required v0.1 result and typed-error fields while
preserving additive fields for forward compatibility; it does not derive
evidence itself. Exact implementations claiming v0.1 still pass the closed
public conformance schema.

### Public contract and conformance

The normative package is:

- `protocol/capabilities/folder-scope-evidence/0.1.0/`;
- `protocol/schemas/capabilities/folder-scope-evidence/0.1/`; and
- `protocol/conformance/capabilities/folder-scope-evidence-0.1/`.

Its eleven-case implementation-neutral suite exercises capability discovery,
metadata-only arbitrary-folder observation, idempotent replay, A → B → A
selection, non-genesis Local Head progress, deterministic stale-observation
refusal, rename continuity, selected-folder and root replacement, same-path
nested-root replacement, nested-boundary topology isolation, unsafe paths,
invalid invocation, cross-platform escaping links, unsupported nodes where the
host exposes them, crash/restart recovery, and the exact aggregate journal
namespace. Two reserved environment seams exist only to reproduce the Local
Head race and event-publication crash inside disposable conformance fixtures;
they grant no authority. The same public suite must pass on macOS, Linux, and
Windows before the capability is advertised by a released Core artifact.

Folderbase Platform issue `chalkagents/folderbase-platform#141` must consume a
tagged Core release with this capability before it can close. The App must not
temporarily duplicate this identity logic in Swift.

## Consequences

- First share can bind an arbitrary ordinary folder or repository to one
  durable Cloud Folder Scope without moving or interpreting its contents.
- Renames preserve continuity when Core can prove physical identity; copies
  and replacements fail closed instead of silently sharing the wrong folder.
- Local journal state is device-specific. Another device produces its own
  evidence and Cloud reconciles it through authenticated Folder Scope
  authority rather than comparing local proofs as bearer credentials.
- The public record deliberately omits file content, absolute paths, Object
  inventories, credentials, and permissions. Publication still requires a
  separately verified Version and authenticated Cloud operation.
- A bounded private journal adds local state and one mutation seam. The cost is
  justified because a path-only or App-owned identity would make durable
  sharing unsafe, while expanding the daemon would couple mutation lifetime to
  a query protocol.
- Files of every regular type remain ordinary opaque bytes. The operation is
  metadata-first and does not upload, parse, reorganize, or evict them.

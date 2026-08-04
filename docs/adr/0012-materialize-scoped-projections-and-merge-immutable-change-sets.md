# ADR-0012: Materialize scoped projections and merge immutable Change Sets

## Status

Accepted

## Context

An agent must be able to receive an ordinary working folder, change any file
type with its normal tools, and return reviewable work without receiving the
rest of a Folderbase. A full `folderbase-version-v1` is intentionally unsuitable
for this job: it is complete restore state for one Folderbase boundary and can
therefore disclose paths, identities, exclusions, or activity outside a shared
Folder Scope.

The repository contains an early
`protocol/schemas/0.1/change-set.schema.json`. That document predates scoped
projections, Folderbase Version 0.5, Chunk Manifest v1, optional-capability
discovery, and durable publication. Reinterpreting it would give one identifier
two incompatible meanings and would make independent implementations appear to
agree when they do not.

Change Sets also need one clear relationship to the familiar Git workflow
without pretending that every ordinary folder is a Git repository. Folderbase
Versions already provide immutable full-state history. What is missing is a
least-authority working projection, an immutable before/after proposal, a
three-way conflict assessment, and an atomic publication transaction that works
for repositories, office documents, databases, media, and unknown regular-file
formats alike.

## Decision

### Capability boundary

Scoped checkout projection and Change Set publication are one separately
advertised stable capability: `folderbase.change-set@0.1.0`. Its package,
schema, and implementation-neutral suite live under:

- `protocol/capabilities/change-set/0.1.0/`;
- `protocol/schemas/capabilities/change-set/0.1/`; and
- `protocol/conformance/capabilities/change-set-0.1/`.

The capability does not expand Compatibility Contract v1, Folderbase CLI JSON
v1, or the immutable protocol 0.5 release closure. It must not be copied into a
capability registry or advertised by an executable until the complete public
suite passes. The old `protocol/schemas/0.1/change-set.schema.json` remains a
legacy prototype. This decision neither changes nor advertises it.

The v0.1 analogy is exact enough to guide users and implementations:

- a Folderbase Version is a commit;
- a scoped checkout projection is a branch-like ordinary working folder;
- an immutable Change Set is a pull request;
- three-way assessment is the conflict check; and
- a two-parent Folderbase Version is a merge.

There are no named or mutable branches in v0.1. A projection is one disposable
working copy pinned to one immutable projection base. A Change Set cannot be
amended in place: changed bytes or metadata produce a different Change Set ID
and digest.

### Folder Scope is the authority ceiling

Checkout materialization starts only after the caller has authority to one
Folder Scope. Core does not infer sharing authority from filesystem nesting,
workspace descriptors, a Folderbase ID, a projection ID, or possession of a
Change Set. A local caller's filesystem authority or a hosted caller's
authenticated grant remains outside the portable record and must be checked
before materialization and again before assessment and apply.

The public checkout request binds:

- one Folderbase ID;
- one opaque projection ID that is navigation, never a bearer credential;
- one Folder Scope ID and exact scope-revision SHA-256;
- a sorted, non-overlapping list of authorized path prefixes; and
- `can_work` as the only v0.1 permission mode.

A `null` prefix denotes the complete Folderbase root. Any other prefix is one
complete portable path and includes that path plus descendants. Distinct
spellings that collide by exact bytes, Unicode 17 NFC, or Unicode 9 full default
case folding are invalid. Redundant or overlapping prefixes are invalid rather
than silently normalized.

Core stores the trusted mapping from projection ID to source Folderbase
Version in engine-owned local or hosted state. It never places a Remote Head,
Local Head, complete Folderbase Version digest, credential, provider location,
storage key, sibling path, sibling exclusion, or sibling activity marker into
the checkout. The portable projection instead binds
`projection_base_sha256`, a domain-separated canonical digest of only:

- Folderbase ID, projection ID, Folder Scope ID, and scope revision;
- the exact authorized prefix list;
- every projected Path Binding and in-scope exclusion; and
- the exact Object Version metadata needed to reconstruct authorized content.

An unrelated source-folder change therefore does not alter or leak the scoped
base digest. The trusted projection mapping retains the source Version needed
for later three-way assessment.

### Checkout is an ordinary folder, not a smaller Folderbase

The checkout command materializes into a caller-selected, new, empty
destination. Authorized directories, regular files, and safe symlinks remain
ordinary filesystem entries. The destination contains one closed,
non-authoritative `.folderbase/checkout.json` projection receipt and no
`.folderbase/manifest.json`; a Folder Scope never becomes a nested Folderbase or
inherits governance authority.

The receipt exposes only scoped base facts and typed in-scope exclusions. It is
closed, bounded, and safe to return with the working folder. Missing receipt
bytes, receipt substitution, destination escape, nested Folderbase traversal,
unsupported nodes, or a changed checkout base fails closed.

Markdown, repositories, PDF, CSV, SQLite, office documents, videos, archives,
and unknown regular files have identical semantics: opaque bytes plus exact
size, SHA-256, executable fidelity, stable Object ID, and Object Version ID.
Core never parses file content to decide whether an edit is mergeable. A large
file is materialized or staged through bounded Chunk Manifest transfer; its
bytes are never embedded in a projection or Change Set JSON document.

### Change Set is one immutable scoped final-state delta

The closed `folderbase-change-set-v1` envelope contains one
`folderbase-change-set-payload-v1` and its canonical SHA-256. The payload binds
the Folderbase, projection, Folder Scope and revision, authorized prefixes,
exact `projection_base_sha256`, creation time, and a canonical sorted array of
object deltas. The complete envelope is no larger than 8 MiB, with at most
16,384 deltas.

Each delta names one stable Knowledge Object and contains an exact `before`
state, an exact `after` state, or both. Create has only `after`; delete has only
`before`; update, move, and move-plus-edit have both. One Object ID appears at
most once. Two equal states are invalid. Paths and final namespace are complete,
portable, collision-free, inside the authorized prefixes, and outside every
nested Folderbase boundary. The object state kind is exactly `directory`,
`regular_file`, or `symlink`.

A regular-file state contains Object Version ID, content SHA-256, byte length,
and executable fidelity. Changed regular-file bytes are external to JSON and
named by one provider-neutral staged-object reference. That reference binds an
engine-assigned staging ID and the canonical digest of one verified
`folderbase-chunk-manifest-v1`; it never contains a provider key, URL,
credential, or caller-selected storage location. Directory and symlink states
carry no staged bytes. Symlinks are lexical, relative, contained, and never
followed.

`folderbase-change-set-sha256-v1` is SHA-256 over the domain
`folderbase-change-set-v1\0` followed by the schema-ordered compact canonical
JSON bytes of the complete payload. No payload field is excluded. Reordering
input object members cannot change it; delta and authorized-prefix order is
normative and independently checked. The envelope digest field is not
recursively part of the payload it authenticates.

### Provider-neutral staging

`change-set propose` writes changed regular-file content to a caller-selected
staging directory outside the checkout. Staging contains immutable Chunk
Manifest records and content-addressed chunks. The Change Set carries only the
staging ID and verified manifest digest. A transport may move those manifests
and chunks between a laptop, Cloud, or a remote agent VM, but provider locations
and authorization remain transport-private.

The provider-neutral directory layout is closed in v0.1:

```text
STAGING/
├── index.json
├── manifests/<chunk-manifest-sha256>.json
└── chunks/<chunk-sha256>
```

`index.json` is one `folderbase-change-set-staging-v1` record whose sorted
objects bind each engine-assigned staging ID to one manifest digest. Manifest
and chunk filenames are their exact lowercase SHA-256 values. Every node is a
no-follow regular file or directory; aliases, extra files, links, and special
nodes are invalid. The layout is transport data, not a provider location or
permission grant.

Assessment and apply verify every manifest, chunk digest, range, total length,
and final object digest before any ordinary source path can change. Empty files
use the canonical empty Chunk Manifest. Sparse and 10 GiB files remain bounded
metadata until their exact bytes are required. Staging paths are opened
no-follow beneath one retained staging root and cannot escape through aliases or
symlinks.

### Three-way assessment

Assessment is read-only. It compares, for every authorized or touched path and
object:

1. the trusted projection base;
2. the current verified source Folderbase state; and
3. the immutable Change Set after-state.

A source Head moving only because of disjoint sibling work is clean and does
not change the projection digest. Disjoint in-scope work is also clean when the
two final namespaces and object identities do not overlap. Assessment never
performs a content merge. Concurrent edits to the same opaque regular file are
an `edit_edit` conflict regardless of format.

The closed v0.1 conflict vocabulary is:

- `delete_edit`;
- `edit_delete`;
- `edit_edit`;
- `move_edit`;
- `move_move`;
- `create_create`;
- `path_occupied`;
- `path_alias`;
- `nested_boundary`; and
- `authorization_changed`.

Every conflict reveals only authorized paths and Object IDs already present in
the projection or proposal. Sibling changes are summarized only as disjoint;
their paths, counts, identities, times, and Version IDs remain hidden.

If the trusted projection mapping or its source Version is absent, malformed,
or no longer retained, assessment returns the retryable `change_set_stale_base`
attention. A changed Folder Scope revision or lost Can Work permission returns
`change_set_authorization_changed`. Neither condition is silently treated as a
content conflict.

### Atomic apply and merge history

Apply accepts only the exact assessed Change Set digest. Under the Folderbase
transaction lease it repeats root attestation, authorization, projection-base,
staging, and three-way checks. It then journals one all-or-nothing transaction.
No ordinary source path changes before the complete replacement state and
forward-recovery evidence are durable.

When the source still equals the projection's trusted source Version, Core
creates one proposal Folderbase Version whose single parent is that source
Version and moves Local Head to it. When current source state includes clean
disjoint work, Core first creates the same proposal Version from the trusted
base, then creates one merge Folderbase Version whose ordered parents are the
current Version and proposal Version. The merge carries the exact union proved
by assessment. A two-parent Version is therefore real merge history, not a
status label. Neither the private proposal Version nor resulting global Head is
disclosed in the scoped checkout result; the result exposes only the applied
Change Set digest and new scoped projection digest.

A conflict, authorization loss, malformed stage, race, or failed revalidation
publishes none of the proposed ordinary changes. Apply never writes outside the
authorized path closure and never enters another Folderbase boundary.

### Crash, restart, and replay

The canonical Change Set digest is the idempotency key. A compact durable apply
journal binds the Change Set ID, Change Set digest, projection, and publication
phase. Digest-named prepared files contain every replacement byte before the
journal becomes visible. Recovery accepts only the exact validated envelope,
the matching immutable ID binding, and workspace paths that still equal a
recognized before, intermediate, or after state. Every mutating entry point
recovers an existing journal before starting new work.

After process or machine loss, the next apply converges to either the exact
pre-apply state or one completely published result. Replaying the same Change
Set returns the original scoped result and creates no additional Folderbase
Version. Reusing a Change Set ID with different bytes or digest is an
operational error. Completed replay does not require staging bytes that were
already verified and durably consumed. Once durable prepared work exists,
incomplete restart recovery does not require the original staging directory.

### Process surface and exit meanings

The capability freezes these machine-readable invocations:

- `folderbase change-set checkout ROOT DESTINATION --stdin --json`;
- `folderbase change-set propose CHECKOUT STAGING --json`;
- `folderbase change-set assess ROOT STAGING --stdin --json`; and
- `folderbase change-set apply ROOT STAGING --stdin --json`.

Checkout reads one `folderbase-checkout-request-v1` document. Assess and apply
read one complete `folderbase-change-set-v1` document. Propose reads the closed
checkout receipt and ordinary checkout tree, stages changed bytes, and returns
one immutable Change Set envelope. Arguments are explicit paths; the process
does not discover authority from its current working directory.

Success exits 0 with one bounded JSON document on stdout and empty stderr.
Conflicts and retryable attentions exit 1 with one typed attention document on
stdout and empty stderr. Invocation, malformed input, missing staging,
unverifiable state, and operational failures exit 2 with empty stdout and one
typed error document on stderr. These documents belong only to this capability
and do not change Folderbase CLI JSON v1.

The independent suite resolves one regular candidate executable without a
shell, places source, checkout, and staging roots beneath one cleanup-owned
temporary directory, and enforces per-command time and output bounds. Fixtures
cover clean and disjoint work, move-plus-edit, missing/stale bases, opaque
binary and large objects, delete/edit, create/create, rename, Unicode and case
aliases, nested boundaries, crash/restart, and idempotent replay. The suite
snapshots every out-of-scope entry with no-follow bounded observations and fails
if a candidate emits or changes sibling state.

Crash convergence has four conformance-only seam values so the black-box check
is deterministic on fast and slow hosts. With
`FOLDERBASE_CHANGE_SET_CONFORMANCE_CRASH_AFTER=prepared-journal`, a conforming
build terminates nonzero after the complete prepared journal is durable and
before its first visible ordinary-path mutation. With the value
`first-mutation`, it terminates nonzero immediately after its first visible
ordinary-path mutation. With `in-place-write`, it terminates after durably
marking a moved Object for recovery, preserving its filesystem identity,
truncating the moved regular file, and writing at most one byte. The next
invocation must finish the same result. With `history-head`, it terminates after
the deterministic proposal or merge Version and its Local Head are durable but
before the completion receipt. The next invocation must reuse that exact
immutable Version and install no additional history record.
Production builds may omit the hook unless they are presented for conformance;
the variable grants no additional operation and is not an advertised product
interface.

## Consequences

- Agents receive a normal least-authority folder and can use existing local or
  remote tools without a Folderbase-specific virtual filesystem.
- Change Sets remain reviewable and replayable across all file types without
  pretending to merge opaque content.
- A full Folderbase Version never doubles as a share projection, so scoped
  collaboration does not leak sibling history or content.
- Disjoint concurrent work can merge while overlap fails explicitly.
- Large-object transfer remains provider-neutral and independently verifiable.
- The first runtime is more work than applying path patches: it must own scoped
  projection records, staging, full-state proposal construction, three-way
  assessment, journaled publication, and replay receipts as one deep module.
- Named branches, textual merge drivers, hosted grants, review UI, comments,
  approval workflow, and transport-provider APIs remain later capabilities.

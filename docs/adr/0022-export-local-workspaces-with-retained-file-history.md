# ADR-0022: Export local workspaces with retained file history

- Status: Accepted for implementation; unreleased experimental capability
- Issue: #99
- Baseline: `d4b09ba4f097e6594a923f118dcf68bec2124ffd`

## Problem

A raw copy preserves bytes but cannot confer this device's Local Head authority
on a different physical root. Existing reconstruction 0.1 correctly creates new
local authority, but its exact selected-Version package contains only that
Version's content closure. It does not retain every earlier per-file Version.
An exporter that emits only that package would silently lose useful history.

## Interface under review

Add one experimental optional capability, `folderbase.local-export@0.1.0`:

```text
folderbase export list ROOT --json
folderbase export create ROOT PACKAGE --json [--version FULL_VERSION_ID]
folderbase export restore PACKAGE DESTINATION --stdin --json
```

Core owns listing, package production, bounded validation and restoration.
The TypeScript SDK adds thin `exportVersions`, `exportWorkspace` and
`restoreWorkspace` methods. No caller opens private files or authors a package.

Restore stdin contains a closed request with an operation ID and the exact
export-index SHA-256 returned by creation. Exact replay binds both, including
every history record and blob. Existing destinations are never merged or
replaced. Structured success reports the selected full Version, portable
Folderbase identity, retained Object/Version counts and selection mode.

`create` without `--version` preflights its absent package destination, then
seals the current capturable workspace using the existing capture operation.
It can add legitimate local capture metadata; it never edits ordinary source
files. The selected immutable Version defines the exported file contents.

With `--version`, creation reads that exact retained full Version without
advancing Local Head. `list` discovers retained full-Version IDs without making
a selection by filename, timestamp or an untrusted copied Local Head. This
explicit path can support a stopped copied archive: physical source attachment
is still checked throughout the read, but old device-local authority is not
adopted. Folderbase membership, selected-Version structure and every immutable
reference must independently verify. Invalid/pending state is refused rather
than recovered implicitly by export.

## Exact retention promise

Profile: `selected-snapshot-file-history-v1`.

1. Preserve one selected full Folderbase Version and its root manifest, live
   ordinary content, directory/symlink representation and retained Tombstone
   content/fidelity through the existing reconstruction 0.1 package.
2. For every ordinary regular-file Object named by that Version's live bindings
   or retained Tombstones, preserve its complete **currently retained** ordered
   per-file Version list, every Version ID, Object ID, content digest/length,
   original `captured_at`, supported Version metadata and all referenced bytes.
   Different Version IDs with identical content remain distinct and ordered.
   Reserved Git metadata is an explicit snapshot-only exception: use the same
   case-insensitive exact `.git` path-component classifier as capture and
   reconstruction. Keep its selected bytes and executable/Tombstone fidelity
   in the unchanged root package. Pin a sorted `snapshot_only_reserved_paths`
   inventory with reason `git_metadata_has_no_stored_file_history` and counts
   in the export index/result. `.gitignore` does not match this exception.
   If a reserved Object unexpectedly has a stored per-file history projection,
   refuse rather than discard it. Missing ordinary-file projections still refuse.
3. A selected older snapshot can name an Object with later retained per-file
   Versions. Those versions are preserved too. The restored visible bytes and
   recorded current Version follow the selected snapshot; retained history is
   not clipped by timestamp or array position.
4. Moved Objects retain their Object identity and complete retained file
   history. Restored paths/lifecycle come from the selected full Version, not
   mutable source projections. Tombstoned regular Objects retain the advertised
   history and remain recoverable through exact Version restoration.
5. Describe the product as "selected folder snapshot and all retained ordinary-file
   history; Git metadata is snapshot-only." This does not promise the entire
   historical full-Version graph, histories
   of Objects absent from the selected snapshot and its verified ancestry, prior symlink
   targets, historical operation journals, physical file identities, local
   scopes/permissions or execution provenance. The index/result states this
   profile and lists omitted Object IDs/counts where source metadata contains
   additional retained Objects. Current-workspace mode refuses an unexplained
   owned regular-file history outside the selected snapshot rather than
   silently calling that export complete. Explicit older-Version selection
   reports the different selected retention set.

### Retired identities from earlier generations

A path can be deleted and recreated several times. The selected full Version
retains only its latest Tombstone for that path, while older Object histories
still exist. The profile therefore also preserves retained ordinary Objects
proven by the selected Version's verified ancestors. A bounded inventory pins
each retired Object ID, its historical path, last witnessed per-file Version ID,
and the observed witness full-Version ID and canonical digest. Each identity
keeps its own ordered history; recreations never become a fabricated single
lineage. Explicit older selection omits later-created identities.

The producer observes ancestor metadata only when selected live/Tombstone
membership is insufficient. It bounds traversal by 16,384 ancestor records and
the existing 64 MiB aggregate observation budget, validates IDs, Folderbase
membership, structure, cycles and observed metadata again before publication.
Existing parent edges contain IDs, not hashes. Pinned observed ancestor digests
are evidence of the bytes read; this does not invent cryptographic parent links.
Retired witnesses are portable profile data, not a claim that their historical
full snapshots are recoverable. No ancestor content graph is copied.

A restored root's completed wrapper digest, exact selected Version ID/digest and
new physical root bind the retired witness inventory. Ownership resolution can
use these witnesses only when traversal reaches that exact imported anchor.
Newer or unrelated missing ancestry still refuses. Re-export may reuse these
verified imported witnesses at that anchor without reviving copied local
authority. Replay verifies the anchor inventory and all retained history.

Ownership resolution obtains this authority through bounded metadata callbacks
covered by each operation's existing observations. Read-only history never
hashes Tombstone blobs or loads the complete export history payload to resolve
ownership. Export, restoration and replay retain their full content verification.
Current bindings/Tombstones that explain every claimant need no anchor lookup.

Missing/corrupt records, duplicate IDs, incomplete Object membership, transferred
out ownership, aliases that cannot be unambiguously projected, unsupported
migration/transfer state, or bounds violations refuse the whole export. There
is no truncation or fallback to the selected current file version alone.
Nested Folderbases and capture-ignored content are not silently added; existing
capture scope still applies and creation reports those exclusions.

## Package and compatibility

Use a closed outer local-export directory, without compression:

```text
PACKAGE/
  export.json       # pins profile, exact inner index and complete history metadata
  root/             # unchanged closed reconstruction 0.1 package
  history/          # Core-produced history metadata/manifests and verified chunks
```

The outer digest pins all metadata and the transitive verified byte closure,
including history-only versions. No private Local Head, transaction journal,
scope evidence, path identity cache or transfer authority is copied. Portable
Version metadata is data, not a grant of local authority. Object projections
are derived afresh from the selected Version and verified history list.

Existing `folderbase.root-reconstruction@0.1.0` wire validation, package layout,
result shape and behavior remain unchanged. Its reader still rejects extra
entries. The new wrapper is opt-in and independently advertised; old binaries
do not claim to understand it. No storage engine, compression, Cloud protocol,
canonical full-Version encoding or existing local history record format changes.

## Publication and shared implementation

Export opens retained source/state handles, observes complete Object/version
membership and checks those observations again before publication. Reuse
`ChunkTransferSource` for owned per-file versions. The root-manifest and other
full-Version-only references require a Core-owned equivalent bound to the
verified immutable capture closure, because they need not have an ordinary
Object projection. Reuse canonical manifest planning and exact chunk checks;
do not manufacture mutable Object records merely to satisfy the transfer API.

Build into an owned sibling staging directory. Flush every staged file and
required directory. Validate the complete package through its consumer before
one no-clobber publication. An interruption leaves no falsely complete final
package. Retained staging and exact operation pins allow deterministic retry
where supported; an occupied unrelated destination always refuses.

Restore reuses the existing retained reconstruction state machine. Add a small
private typed history-profile seam: after ordinary content materialization and
before immutable history/Local Head installation, merge verified original
per-file records and complete ordered histories into the reconstructed closure.
Verify history-only blobs and original current-record metadata before the
existing final publication. The local-export request digest, rather than only
the inner root index, binds stage ownership and replay. Generic 0.1 execution
uses the unchanged base profile. No second post-publication history import and
no copied-root rebind are allowed.

Profile-specific replay revalidates every retained history record and blob in
the restored root, including history-only versions. Binding the outer request
digest alone is insufficient. Existing generic 0.1 replay stays unchanged.

A completed, root-attested local export reconstruction establishes an explicit
ancestry anchor at the exact selected full Version. Tombstone restoration may
stop traversing older parents at that verified anchor and use only its pinned
path/Object/Version/content/executable association. Newer ancestry still needs
normal verification, cycle checks and nearest-fidelity consistency. An ordinary
missing ancestor, unrelated association or stale copied completion does not
create an anchor. Do not add a generic missing-parent fallback.

## Bounds and refusals to resolve in review

- Keep existing full-Version and chunk bounds. Proposed first-profile limits:
  16,384 distinct retained per-file Version records across the complete export,
  1 MiB per Object/Version metadata record, 64 MiB aggregate history metadata
  including manifests, index arrays and repeated chunk references,
  and 8 MiB for each CLI JSON result. The root package retains its existing
  16,384 visible-entry and 1,048,576 distinct-chunk bounds; apply the latter to
  the complete export, not independently to each file. Count/bound collections
  before allocating their full contents. Exceeding any limit refuses everything.
- Preserve the complete public `LocalVersionRecord` value, including unknown
  extension values as inert metadata. Validate the recognized executable field
  through the same Core validator as ordinary local history. These values may
  not populate local authority, completion, scope or identity-cache records.
  Derive mutable Object projections afresh; do not copy arbitrary source Object
  extension/provenance state into them.
- Reuse capture-time or reconstruction-bound executable fidelity for deleted
  regular files. The current file's mode is not evidence of an old Tombstone.
- A cooperating writer lock prevents mixed metadata observations. Uncooperative
  source record/blob replacement or mutation is detected by retained identities,
  exact bytes/digests and final source revalidation. Exported immutable snapshot
  semantics do not freeze another process's ordinary filesystem access.
- Explicit copied-archive selection must distinguish invalid portable content
  from invalid old local authority without relaxing the normal capture path.
- The explicit Git metadata inventory shares the aggregate metadata, visible
  entry and JSON-output bounds. It does not synthesize earlier Git file history,
  delete/skip current Git bytes or imply the whole historical Git object database
  is preserved beyond the files actually contained in the selected snapshot.

## Acceptance

Test only through the new public Core/CLI/SDK interfaces, with focused private
fault injection where required for durability ordering. Include multiple
distinct Version IDs containing identical bytes, opaque attachments, moved and
deleted-file history, exact recovery of every advertised Version, corrupted or
missing history content, replaced source/state/package parents, existing
destinations, unsupported filesystems and interruption/replay around staging
and publication. A clean new process must restore, list history, recover earlier
bytes, create a new task/file, add an attachment and reopen successfully.
List the original file's complete history again **after** continued creation and
attachment operations, and recover an earlier version then; a successful
initial history read is insufficient to establish later identity continuity.
Include selected nested/case `.git` metadata bytes after restore and continued
capture, `.gitignore` retaining ordinary history, ordinary missing projections
refusing, and reserved metadata with unexpected stored history refusing.
Verify original ordinary source bytes and unrelated destination bytes on every
refusal. Process interruption checks do not prove power-loss durability.

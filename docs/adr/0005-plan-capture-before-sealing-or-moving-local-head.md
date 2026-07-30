# Plan capture before sealing or moving Local Head

Status: Proposed

Folderbase needs to turn live ordinary folders into portable Folderbase Versions
without repeating the destructive, content-evicting behavior of consumer sync
drives. The proposed transaction is therefore split at an explicit inert
`CapturePlan`: Core first opens one attested physical Folderbase Root and plans
only bounded metadata; a later phase will verify bytes, assign stable identities,
seal a Folderbase Version, install its durable records, and move Local Head as one
recoverable transaction. Planning never writes, hashes ordinary content, seals a
version, or changes Local Head.

The planning seam is `FolderbaseVersionStore::open(root)` followed by
`plan_capture()`. The opaque plan binds the root's physical-instance digest,
Folderbase identity, effective ordered ignore-policy digest, and optional
device-local head observed at `.folderbase/local/head.json`. A Local Head record
is accepted only when it is closed, bounded, and names the exact Folderbase and
physical root. It also anchors the SHA-256 digest of the exact capture
transaction whose complete Folderbase Version it names. It is device-local
state, not shared or Cloud authority.

Metadata planning treats every regular file identically, including PDFs, videos,
CSV, SQLite, unknown formats, and Git pack files. It records length and executable
fidelity without opening ordinary file bytes; the 10 GiB sparse-file test remains
readable only through metadata. Symlinks are never followed and retain only a
portable, lexically contained UTF-8 target. Hard links and special nodes become
typed v1 exclusions instead of disappearing.

The effective ignore policy applies Core's generated-tree defaults first, then
the root `.folderbaseignore` as Git-style ordered rules. Later matches win,
negation works when its parent directory is not definitively excluded, and
definitively excluded directories are not descended. The two required visible
markers, `.folderbaseignore` and `FOLDERBASE.md`, override ignore matches.
`.folderbase/**` is always excluded from ordinary bindings; the root manifest is
already represented through its reserved reference. A discovered nested
Folderbase becomes one typed boundary exclusion and none of its descendants are
entered.

Planning walks through root-relative, no-follow directory capabilities. It
classifies ignore policy before opening a child directory, probes nested markers
without enumerating their descendants, rechecks opened directory identities, and
streams directory entries directly into the aggregate record bound. It does not
sort or retain an unbounded directory listing before enforcing that bound.

In-scope paths use the exact Folderbase Version v1 portability, Unicode
collision, depth, count, and per-object-size bounds. Non-UTF-8 in-scope paths
fail closed. A bounded, controlled JSON encoder is the only public way to encode
an existing `FolderbaseVersion`; a crate-private producer can assemble every v1
record kind from verified references, but complete validation still runs before
a value can exist. This does not restore raw public Serde deserialization.

The second producer slice consumes an exact `CapturePlan` through
`FolderbaseVersionStore::seal_capture`. It reads every included regular file as
opaque bytes through root-relative no-follow capabilities, rechecks planned
metadata and filesystem identity before and after each read, and installs the
bytes in the existing content-addressed `LocalVersionStore`. PDF, video, CSV,
SQLite, Git, office, and unknown formats take the same path. Directory, symlink,
and executable fidelity remains in the single full-state Folderbase Version.

Before installing an Object Version, Core durably journals every newly assigned
stable Object ID, candidate Object Version ID, Folderbase Version ID, parent,
timestamp, plan digest, expected Local Head, and the complete sorted target
Tombstone set. A prior Object or Object Version may be referenced only after the
exact prior Local Head, complete Folderbase Version, immutable Object Version
record, and content blob verify.

Snapshot capture treats the same exact path with the same supported kind as
logical Knowledge Object continuity by default. This is intentionally friendly
to editors that implement save by atomically replacing a file. A content or
executable-fidelity change creates a new Object Version under the same Object
ID. A prior live path that is absent from the capture becomes a Tombstone. A
same-path supported-kind replacement creates a Tombstone for the prior Object
and a live binding with a new Object ID. Existing Tombstones are carried
forward, with at most the newest deleted Object retained for one exact path.

Device-local physical identity records remain race evidence for the exact
planned read and a future cross-path move hint; they are not the sole authority
for logical continuity across captures. Unix records bind device and inode;
Windows records bind the volume serial number and complete 128-bit File ID
obtained from the no-follow handle. Missing or changed physical-identity
evidence forces byte verification and refreshes the derived identity record, but
does not split a same-path, same-kind Knowledge Object. Capture continuity has
one canonical capture-identity projection; the legacy workspace path-identity
representation is not also written by the capture transaction.

Unix device and inode identify one live filesystem object, but they are not a
globally unique lifetime token: after every handle to an unlinked object closes,
the filesystem may reuse its inode for a later file. More importantly, an
atomic-save replacement usually has a deliberately different physical identity
while remaining the same logical document. Core therefore never guesses
cross-capture logical identity from inode or File ID alone.

A same-path, same-kind delete-and-recreate that happens entirely between
captures is logical continuity unless durable explicit deletion evidence says
otherwise. A sealed intermediate capture with the path absent is such evidence:
its Tombstone makes a later recreation a new Object. A future App filesystem
event journal or explicit Core deletion operation may provide the same durable
signal without an intermediate snapshot. Those evidence-intake surfaces are not
part of this slice. Fault fixtures that claim to simulate distinct live objects
still keep the removed object handle open until the replacement identity is
observed so filesystem identity assertions themselves remain deterministic.

Absence is not inferred when observation scope changed. If a prior live binding
is newly hidden by `.folderbaseignore`, a nested Folderbase boundary, or a typed
unsupported-node exclusion, sealing refuses before capture-journal or Local
Head mutation. This prevents policy and boundary changes from being silently
converted into deletions.

Content blobs, immutable Object Version records, and the complete bounded
Folderbase Version are installed append-only with temp-file fsync, atomic
no-clobber publication, and post-install verification. Only then does Core
compare the observed Local Head and atomically replace it under the shared local
transaction lock, implemented by the standard cross-platform exclusive file
lock rather than an in-process mutex. All capture state publication is relative
to one retained no-follow `.folderbase` directory capability. Sealing opens that
existing capability and re-attests the inert plan before creating a lock,
repairing derived state, or publishing any capture record; it does not invoke
the legacy ambient-path transaction recovery prelude. Data and directory
handles are flushed, and visible `.folderbase` attachment is verified before
and after Head replacement. Exact root and state junctions/reparse points are
rejected on Windows. Windows state directory capabilities request the write
authority required by `FlushFileBuffers`, and native CI executes directory
creation, publication, replacement, and flush through those retained
capabilities. Read-only Folderbase Version verification instead retains
explicitly non-mutating state capabilities, requests only `GENERIC_READ` on
Windows, and rejects accidental mutation before any filesystem operation.
Native CI holds directory handles that deny write sharing while verifying a
complete version. A state-directory swap can leave only a detached orphan and
cannot redirect publication through a symlink or junction.

The active journal uses bounded streaming JSON encoding and the same explicit
byte bound for write and restart read. Before publishing that journal or any
immutable object, Core constructs and bounded-encodes the complete future
Folderbase Version envelope. Its assignment and Tombstone aggregate, every
path, kind, observed identity, reused Object ID, prior Object Version,
root-manifest parent, and complete sorted target Tombstone set are matched
exactly to the approved plan and verified prior Head.
Included content streams are capped at the exact approved length plus one byte:
a growing source is refused as a concurrent state change and staging is
removed, instead of reading an attacker-controlled stream to EOF. The active
capture journal remains until derived regular-file object projections and
physical identity records are repaired. After Head publication, recovery first
verifies the Head-anchored digest of the complete journal and requires the
committed version's parents and timestamp to match that immutable intent before
journal identity evidence can be projected. A retry after interruption at
journal, Object Version, Folderbase Version, Local Head, or cleanup boundaries
converges on the exact journal-assigned version. A stale attempt may discard
only its intent; verified immutable records remain safe, reusable orphans.

An explicit `restore_tombstone(path)` operation now closes the ordinary-file
capture/restore loop. It accepts only an exact regular-file Tombstone in the
current verified Local Head. A bounded, cycle-detecting ancestor search finds
the nearest verified live binding with the same path, Object ID, and last
Object Version ID; that binding is the authority for content digest, byte
length, and executable fidelity. Missing, ambiguous, cyclic, corrupt, or
out-of-bounds lineage fails closed. Directories and symlinks remain unsupported
until they have equally strong cross-platform no-clobber ownership proofs.

Restore is same-path and no-clobber. Core copies the immutable content blob to a
private transaction stage, applies executable fidelity to that independent
inode, and hard-links the retained stage into an absent destination through
no-follow root capabilities. Recovery accepts an existing target only when it
is the same filesystem object as the retained stage; byte equality alone never
authorizes adoption. A preexisting regular file, directory, symlink, or
dangling symlink is left untouched.

The restore journal binds the exact expected Local Head, selected Tombstone,
recovered binding, new Folderbase Version ID, timestamp, and canonical digest.
The transaction and target Version IDs are deterministic domain-separated
derivations of that verified immutable authority, and the target timestamp is
re-derived from the verified parent. Rewriting those fields together with a
self-consistent target digest therefore grants no authority.
The new full-state version copies every other live binding, Tombstone,
exclusion, and root-manifest reference, removes only the selected Tombstone,
and has the deletion Head as its sole parent. Core validates the complete
bounded reachable ancestor DAG for cycles before selecting the nearest
candidate; a nearer binding cannot hide a deeper cycle, while convergent DAGs
remain valid. Local Head advances only after the target still has the exact
retained-stage identity, bytes, length, and executable fidelity, the physical
root is still attached, every path ancestor remains outside a case-folded
nested Folderbase boundary, and the Object Version, blob, and complete
Folderbase Version verify. Those live proofs run again after the Head CAS.
Failure rolls the exact retained root back to the prior Head before returning
a conflict, including recovery after interruption at Head publication.
The capture and restore journals mutually exclude each other under the shared
transaction lock. Interruption at journal, stage, target publication, version,
Head, projection, or cleanup converges on the one assigned version without
overwriting foreign content.

This decision remains **Proposed**. Core now produces productive Tombstones for
captured absence, preserves same-path/same-kind logical continuity, and records
supported-kind replacement as Tombstone plus new identity. Exact regular-file
Tombstone restoration is no-clobber and crash-recoverable. It does not yet
ingest an App filesystem-event deletion journal or expose an explicit Core
deletion operation, detect cross-path moves, restore directory or symlink
Tombstones, coordinate filesystem/database snapshots, publish Remote Head, or
implement sync, sharing, authorization, or Cloud durability. Acceptance still
requires explicit deletion-evidence intake; the implemented regular-file
restore transaction no longer blocks acceptance by itself.

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
physical root. New records use `folderbase-local-head-v2` and a closed authority
discriminator. `capture_transaction_v1` binds the SHA-256 digest of the exact
capture transaction whose complete Folderbase Version it names;
`version_derived_v1` binds a domain-separated digest independently derived from
the Folderbase ID, physical-root instance, Version ID, and Version digest.
Released `folderbase-local-head-v1.transaction_sha256` records retain exactly
their capture-transaction meaning: Core reads them only as
`capture_transaction_v1` and compare-and-swaps them to v2 under the shared
transaction lock after ruling out restore activity. It never reinterprets a v1
field as version-derived authority. Local Head is device-local state, not shared
or Cloud authority.

On Windows, current root authority is V2 (full 64-bit volume serial and 128-bit
`FILE_ID_INFO`), while the exact released Windows V1 digest remains admissible
only through the released compatibility path for durable records. The
admission result carries the record's exact digest; it does not normalize it to
the current attestation. Capture plan digests for an active released-root
journal use that recorded root, including both pre-Head execution and
committed-Head recovery.
Restore transaction and target IDs, expected and target Head authority,
rollback, cleanup, completion, and authority receipts likewise derive from or
retain the transaction's recorded root. Immutable journal and receipt bytes are
never rewritten during compatibility recovery.

Local Head is the sole mutable rebind point. Under the shared transaction lock,
Core first verifies the named immutable Folderbase Version and its canonical
digest. It rebinds a released-root Head only when no capture or restore work is
pending, after recovery retires all pending work, or in the normal next Head
compare-and-swap. A capture-transaction Head keeps the SHA-256 of the exact
journal bytes while changing only its root binding; a version-derived Head
recomputes its authority with the current root. Faults on either side of that
CAS therefore leave exactly one old-valid or new-valid Head. A V2 Head never
admits a different full Windows identity merely because both would have
collided under the released truncation. One-time admission of a released V1
record is necessarily TOFU inside trusted local `.folderbase`: V1 cannot
retroactively prove upper identity bits it did not store. A copied,
self-consistent V1 record on a rare colliding tuple is therefore part of the
same-user local-state trust boundary, not a portable or Cloud authority claim.

### Local trust boundary

`.folderbase/` is trusted, engine-owned local state in the same sense as
`.git/`. Core must reject malformed, partial, or mismatched records; survive
torn execution; close ordinary filesystem races and substitution windows; and
never overwrite an occupied workspace path. Device-local identity and journal
digests provide those integrity and recovery properties, not cryptographic
same-user authenticity.

A same-user process that deliberately rewrites all related `.folderbase/`
records into an internally consistent forgery is outside the local Core threat
model. This decision intentionally does not introduce an OS-protected signing
key, enrollment, recovery, or rotation UX. Cloud grants and server-side Live
Folder authority remain separately authenticated and are never derived from
possession of local `.folderbase/` metadata.

Metadata planning treats every regular file identically, including PDFs, videos,
CSV, SQLite, unknown formats, and Git pack files. It records length and executable
fidelity without opening ordinary file bytes; the 10 GiB sparse-file test remains
readable only through metadata. Symlinks are never followed and retain only a
portable, lexically contained UTF-8 target. Hard links and special nodes become
typed v1 exclusions instead of disappearing.

The effective ignore policy is protocol-profile-specific. Protocol 0.4 applies
Core's generated-tree defaults first, then its required root
`.folderbaseignore` as Git-style ordered rules; both required visible 0.4
markers override ignore matches. Protocol 0.5 instead applies the ordered
manifest `policies.capture_ignore.rules` first, then root
`.folderbaseignore` rules only when that optional regular file exists.
Presence and absence are distinct policy inputs. In 0.5, a present
`.folderbaseignore` is bounded, force-included, and changed only through typed
policy-aware flows, while `FOLDERBASE.md` is fully ordinary content and may be
ignored. Under both profiles, later matches win, negation works when its parent
directory is not definitively excluded, and definitively excluded directories
are not descended. `.folderbase/**` is always excluded from ordinary bindings;
the root manifest is already represented through its reserved reference. This
also keeps the named optional `.folderbase/summary.md` and
`.folderbase/questions.jsonl` hints non-authoritative and outside portable
history. Other `.folderbase/**` content is private and inert without becoming a
named hint format. A discovered nested Folderbase becomes one typed boundary
exclusion and none of its descendants are entered.

Planning walks through root-relative, no-follow directory capabilities. It
classifies ignore policy before opening a child directory, probes the exact
nested manifest marker without enumerating descendants, and treats any exact
regular no-follow marker as an opaque boundary without reading or decoding its
bytes through the parent. Only an operation explicitly opened on that nested
root attests its profile and fails closed if invalid. Planning rechecks opened
directory identities and streams directory entries directly into the aggregate
record bound. It does not sort or retain an unbounded directory listing before
enforcing that bound.

Markerless state and context remain inert. Case aliases, symlink or
non-directory state markers, and symlink or non-regular manifest markers are
unsafe shapes, not nested authority. Read-only analysis may represent them as
an `Unchecked` quarantine (`unchecked` on the wire) and omit descendants;
capture and every other materializing, mutating, transfer, or restore seam
rejects them.

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
For a regular file with retained restore authority, metadata-only planning and
the active journal also bind the exact live link count and one canonical,
ASCII-sorted set of authority receipt paths, SHA-256 digests of the exact
receipt bytes, retained stage paths, and publication identities. Planning
compares retained-stage and workspace identity without data access: Unix uses
no-follow directory metadata and Windows uses zero-data-access, no-follow
metadata handles. Default or released records with no such field normalize only
to one visible link and no authorities, and preserve their original serialized
bytes and Head-anchored SHA-256. The released-v1 decoder has its own closed
assignment type and rejects current-only link-commitment fields. Default-only
plans whose Head is absent or capture-transaction-derived retain the released
v1 digest domain and its exact flat
`current_head.transaction_sha256` encoding. Authority-bearing plans and plans
whose Head is version-derived use the typed-authority v2 domain. Core
re-enumerates that exact set and reads link count from the retained source
handle immediately before and after content streaming. An added user link,
missing receipt or stage, or same-count authority-set swap fails closed before
capture can advance Head.

Recovery retains whether a bounded active journal decoded as released v1 or
current wire. A released-v1 journal is preflighted against the exact raw byte
length already admitted by the bounded reader plus the closed released schema
and normalized semantic invariants; it is not rejected merely because its
larger typed in-memory representation would exceed the same wire bound.
Newly assigned and current journals remain preflighted through the current
encoder. The exact raw journal bytes continue to define capture-transaction
Head authority. Accepted trailing JSON whitespace remains in that exact raw
authority. The actual maximum raw wire is accepted, one byte over is refused,
and truncated JSON is rejected.
Included content streams are capped at the exact approved length plus one byte:
a growing source is refused as a concurrent state change and staging is
removed, instead of reading an attacker-controlled stream to EOF. The active
capture journal remains until derived regular-file object projections and
physical identity records are repaired. After Head publication, recovery first
verifies the Head-anchored digest of the complete journal and requires the
committed version's parents and timestamp to match that immutable intent before
journal identity evidence can be projected. Released v1 non-genesis capture
journals nested the prior Head authority in
`expected_head.transaction_sha256`. Core bounded-decodes that exact closed wire,
converts only its in-memory authority type, and retains the SHA-256 of the exact
durable journal bytes for both pre-Head execution and committed-Head recovery.
It never hashes the normalized representation where a released Head binds the
original bytes. A retry after interruption at
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

Every multi-step workspace observation or restore publication retains a scoped
target capability: the no-follow parent directory handle, its exact physical
identity, the validated relative leaf, and the attested Folderbase Root. Before
publication mutation and again after mutation, hooks, authority retention, and
the final success proof, Core reopens the parent from the retained root without
following links and requires the reopened parent to have that exact identity.
A replacement ancestor can neither redirect an operation into another
directory nor be mistaken for the intended publication. Core moves no Head and
returns no `Restored` result after that proof fails.

This is a cooperative namespace invariant, not a claim that POSIX pathnames
cannot be renamed by an uncoordinated same-user process. On Unix, a process may
move the exact opened parent after the final attachment proof and before or
after the hard link. The held capability still confines mutation to that exact
directory, so the only possible orphan is the exact transaction-owned link in
the moved directory; Core never follows the replacement path and never attempts
a racy pathname rollback that could delete unrelated content. Windows directory
capabilities deny delete sharing while held, so the equivalent parent detach is
blocked by the operating system.

Retry also preserves exact link topology. An absent destination may be
published only while the retained stage has exactly one link. An already
published destination may resume only when it is the same inode as the stage
and the inode has exactly the two expected names: private stage and visible
destination. If an absent destination is paired with an extra link left in a
concurrently moved parent, Core returns typed
`RestoreNamespaceRepairRequired` before adding another link. The user may
inspect and return the moved directory to its intended location, or explicitly
remove the known transaction-owned orphan, then retry. The journal, private
stage, and any committed cleanup receipt remain durable until that repair
converges. Stronger global namespace exclusion would require a managed-workspace
or platform-conditional mutation protocol and is future architecture, not an
implicit v1 guarantee.

The restore journal binds the exact expected Local Head, selected Tombstone,
recovered binding, new Folderbase Version ID, timestamp, and canonical digest.
The transaction and target Version IDs are deterministic domain-separated
derivations of that verified immutable authority, and the target timestamp is
re-derived from the verified parent. Within the trusted-local-state boundary,
rewriting only those mutable journal fields together with a self-consistent
target digest therefore grants no authority.
The new full-state version copies every other live binding, Tombstone,
exclusion, and root-manifest reference, removes only the selected Tombstone,
and has the deletion Head as its sole parent. Core validates the complete
bounded reachable ancestor DAG for cycles before selecting the nearest
candidate; a nearer binding cannot hide a deeper cycle, while convergent DAGs
remain valid. The cycle pass operates on the complete bounded adjacency graph,
independently of traversal deduplication and candidate selection. Both
prior-Head execution and committed-Head recovery re-derive the Tombstone,
binding, deterministic assignment, and exact child Version from the verified
expected parent before accepting mutable journal state. After read-only
eligibility checks and before the restore journal exists, Core atomically
rebinds the verified parent Local Head to a domain-separated authority digest
derived only from the attested physical root, parent Version ID, and parent
Version digest. Restore-produced Heads use the same independently derivable
authority form. Recovery therefore cannot treat the journal's copy of the
prior Head transaction digest as assignment authority after the prior Head has
been replaced. Local Head advances
only after the target still has the exact
retained-stage identity, bytes, length, and executable fidelity, the physical
root is still attached, every path ancestor remains outside a case-folded
nested Folderbase boundary, and the Object Version, blob, and complete
Folderbase Version verify. Those live proofs run again after the Head CAS.
Failure rolls the exact retained root back to the prior Head before returning
a conflict, including recovery after interruption at Head publication.
On Unix, Core explicitly applies the staged `0700` or `0600` mode through the
open file capability after creation, so process umask cannot erase the v1
executable-fidelity decision.
The capture and restore journals mutually exclude each other under the shared
transaction lock. Interruption at journal, stage, target publication, version,
Head, projection, or cleanup converges on the one assigned version without
overwriting foreign content. Post-Head projection stays relative to the retained
state capability; a projection failure restores the exact prior Head. If a user
or agent edits the transaction-owned published file in place before cleanup,
Core preserves those workspace bytes. Cleanup first publishes one durable,
closed singleton receipt with a `committed`, `modified`, or
`committed_modified` disposition. Every disposition rederives the exact
deterministic restore transaction from the immutable parent, Tombstone, and
ancestor binding. Cleanup v2 also records the durable device-local identity of
the published inode. The transaction-unique stage remains as a bounded private
authority link under this ADR. Cleanup performs no authority-link rename or
unlink. It re-proves the private pathname, visible destination, publication
identity, and committed fidelity before and after both cleanup hook boundaries.
A missing or replaced private authority fails closed.

A late same-inode edit after target Head publication transitions to
`committed_modified`: the edit survives, private authority is retained,
capture becomes eligible through the narrow validated-authority exception, and
the restore call does not report success. Once
either modified disposition is durable, later cleanup depends on exact
same-inode ownership rather than the file remaining modified, so a same-inode
revert cannot wedge recovery. Successful committed cleanup atomically replaces
one bounded device-local completion v2 receipt before retiring pending cleanup.
The receipt never blocks capture. It recovers a terminal lost acknowledgement
only while the exact target Head and installed Version remain current and the
authority receipt, retained stage, and workspace path still name the recorded
published inode with the sealed bytes and executable fidelity. Capture accepts
the hard-linked workspace file only when the link count is exactly one visible
link plus every validated authority for that path and identity. Any extra link
remains excluded. The authority set is capped at 4096; this slice provides no
automatic garbage collection. A missing path, authority, foreign inode
(including identical bytes), changed bytes, changed fidelity, Head change, or
Version change makes terminal evidence stale and can never produce a
restored-success result.
Every cleanup hook and state mutation, including active-intent retirement,
completion-receipt durability, pending-receipt removal, and the exposed
cleanup-complete boundary, occurs before one final success linearization proof.
For a released Windows-root transaction, the transaction-locked Local Head
V1-to-V2 root rebind also occurs before that proof. Final and terminal
verification accept exactly either the full recorded-root Head with its
independently derived recorded-root authority or the full current-root rebound
Head with its independently derived current-root authority; Folderbase ID,
root, Version ID, Version digest, and authority must all match one complete
form. The immutable transaction, completion receipt, and retained restore
authority remain byte-for-byte bound to the recorded root. Immediately before
returning `Restored`, Core revalidates those immutable bytes and the exact
target Version and permitted Head, retained stage and destination identity,
sealed digest and length, and executable mode. Nothing mutates or invokes a
test hook after that proof.

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

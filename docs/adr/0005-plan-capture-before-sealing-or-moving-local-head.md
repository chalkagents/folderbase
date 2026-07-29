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
timestamp, plan digest, and expected Local Head. A prior Object or Object Version
may be reused only after the exact prior Local Head, complete Folderbase Version,
immutable Object Version record, and content blob verify. Device-local physical
identity records distinguish a same-inode update from a same-path recreation
after the first verified binding. Missing identity evidence never authorizes
reuse. Unix records bind device and inode; Windows records bind the volume
serial number and complete 128-bit File ID obtained from the no-follow handle.
A replacement after Head publication retains the identity of the sealed entry,
so the next capture detects the mismatch and refuses until Tombstones exist.

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
rejected on Windows. A state-directory swap can leave only a detached orphan
and cannot redirect publication through a symlink or junction.

The active journal uses the same explicit byte bound for write and restart read.
Before any immutable write, its assignment count and every path, kind, observed
identity, reused Object ID, prior Object Version, and root-manifest parent are
matched exactly to the approved plan and verified prior Head. The active capture
journal remains until derived regular-file object projections and physical
identity records are repaired. After Head publication, recovery first verifies
the Head-anchored digest of the complete journal and requires the committed
version's parents and timestamp to match that immutable intent before journal
identity evidence can be projected. A retry after interruption at journal,
Object Version, Folderbase Version, Local Head, or cleanup boundaries converges
on the exact journal-assigned version. A stale attempt may discard only its
intent; verified immutable records remain safe, reusable orphans.

This decision remains **Proposed**. This slice does not yet produce Tombstones,
so deletion, same-path recreation, and kind replacement are refused without
moving Local Head. It also does not implement full no-clobber restore
reconstruction, restore crash recovery, filesystem/database snapshot
coordination, Remote Head publication, sync, sharing, authorization, or Cloud
durability. Acceptance still requires the Tombstone and restore transactions to
close the complete capture/restore lifecycle.

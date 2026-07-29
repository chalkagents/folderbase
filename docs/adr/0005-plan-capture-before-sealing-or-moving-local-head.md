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
physical root. It is device-local state, not shared or Cloud authority.

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

This decision remains Proposed because this slice deliberately does **not**
implement or claim byte verification, Object ID/Object Version assignment,
sealing, Local Head mutation, restore, crash recovery, snapshot atomicity,
database-file consistency, sync, sharing, authorization, or Cloud durability.
Acceptance requires the later producer transaction and recovery protocol to
close those gaps.

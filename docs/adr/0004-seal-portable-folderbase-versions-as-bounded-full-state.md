# Seal portable Folderbase Versions as bounded full state

Status: Accepted

Folderbase needs one provider-neutral state artifact that a local App, independent
implementation, or future remote agent can validate and restore without replaying
private service history. Four credible shapes were considered:

- a flat full-state snapshot is simple to validate and independently restore, but
  repeats unchanged bindings;
- a checkpointed operation log makes small changes compact, but correctness,
  compaction, and restore all depend on replay;
- a Merkle graph supports efficient partial comparison, but immediately commits
  every implementation to tree construction, node storage, and garbage collection;
- a hybrid snapshot plus log or Merkle index can eventually combine those
  properties, but makes the first public contract the union of their failure modes.

Core 0.4 therefore selects one canonical, bounded full-state
`folderbase-version-v1` artifact. This is the KISS baseline and the independent
restore truth; future logs, Merkle indexes, and provider-specific acceleration are
derived artifacts and cannot replace or weaken it.

## Decision

A Folderbase Version has a distinct `fbversion_<lowercase-hyphenated-UUID>`
identity. That identity is not an Object Version ID, a chunk-manifest digest, or
the canonical Folderbase Version digest. The canonical digest binds the complete
validated artifact through an independently specified domain-separated binary
encoding; the digest is an integrity identity for the record, not authorization,
storage presence, or a share projection.

The artifact contains:

- the exact Folderbase identity, Folderbase Version identity, optional ordered
  parent identities, and a canonical UTC creation time;
- one reserved `root_manifest` reference containing the exact Object Version,
  SHA-256, and byte length of `.folderbase/manifest.json`;
- a fixed portable-path policy with NFC data pinned to Unicode 17.0.0 and full
  default case-fold data pinned to Unicode 9.0.0. The two versions are explicit
  because Core's independently versioned normalization and case-fold tables
  expose exactly those data versions; claiming one newer shared version would
  misstate the case-fold implementation;
- current Path Bindings sorted by exact UTF-8 path bytes;
- retained Tombstones sorted by exact UTF-8 path bytes; and
- typed exclusions sorted by exact UTF-8 path bytes.

Every live binding has one stable Object ID and explicit `live` lifecycle.
Regular opaque files bind the exact existing object-level `VersionId`, byte length,
whole-object SHA-256, and executable bit. Symlinks bind an Object Version and exact
UTF-8 target but are never followed; v1 accepts only targets whose lexical
resolution is relative, remains within the Folderbase, and does not enter
`.folderbase` or a declared nested boundary. Directories are explicit so empty
directories restore. Hard links and special nodes are not silently lost: they are
typed exclusions in v1. A later fidelity profile may support them without changing
what v1 claimed.

`.folderbase/manifest.json` is the sole explicit exception to the
`.folderbase/**` self-capture ban and appears only through `root_manifest`, never
as an ordinary Path Binding. This makes the boundary independently reconstructable
without recursively capturing the version records that describe it.
`FOLDERBASE.md` and the root-level `.folderbaseignore` are ordinary visible files
and may be represented by regular Path Bindings.

A Tombstone records the deleted path, stable Object ID, deleted kind, and optional
last Object Version. Its containment in the sealed Folderbase Version establishes
the deleting version; it never repeats the containing ID or digest and therefore
cannot create a self-reference. Recreating the same path requires a new Object ID.
Moving one object may retain a Tombstone for its old path while binding the same
Object ID at its new path.

Portable paths preserve exact UTF-8 spelling and are never normalized or renamed.
Validation rejects empty components, dot and traversal components, absolute paths,
backslashes, drive prefixes, NUL, Windows-reserved names, trailing dot or space,
components over 255 UTF-8 bytes, paths over 4096 UTF-8 bytes, depth over 128, and
exact, NFC, or full-case-fold collisions. `.folderbase` and every descendant are
always rejected. A declared nested Folderbase is represented by one exclusion and
no binding, tombstone, or other exclusion may enter that boundary.

The two derived collision keys are exactly `NFC(path)` and
`NFC(full-default-case-fold(NFC(path)))`. They are rejection keys only: neither
derived spelling is stored, emitted, looked up as an alias, or substituted for the
user's exact path.

The encoded artifact is capped at 64 MiB and 16,384 total bindings, tombstones, and
exclusions. Decoding bounds arrays before allocating their full contents. Large
files are metadata-first: a 10 GiB opaque file costs one bounded binding rather
than loading workspace bytes. A producer must verify every included byte identity
and Object Version reference before sealing; this pure contract decoder validates
the sealed representation but does not claim to have observed workspace bytes.
The filesystem capture transaction is a later TB-33 slice.

Chunk manifests remain transfer plans. Their digests never become Object Version
or Folderbase Version identity and are absent from this closed v1 record. Likewise,
the full Folderbase Version is not a scoped-share manifest: a separate projection
artifact must expose only an authorized folder scope.

Core exposes a pure `folderbase_version` module for bounded decode, semantic
validation, canonical digest, deterministic exact-path lookup, and deterministic
typed state diff. Diff distinguishes stable-ID moves, same-path recreation, updates,
adds, deletes with or without the expected Tombstone, Tombstone-set changes,
exclusion-set changes, and root-manifest changes. It contains no filesystem capture,
Cloud, provider, authentication, authorization, Local Head persistence, or Remote
Head behavior.

## Canonical digest v1

The digest is SHA-256 over an exact domain-separated binary sequence. It begins
with the ASCII bytes `folderbase-version-v1` and one zero byte. A string is encoded
as its unsigned four-byte big-endian UTF-8 byte length followed by those exact
bytes. A digest is its decoded 32 bytes; sizes are unsigned eight-byte big-endian
integers; collection counts are unsigned four-byte big-endian integers except the
bounded parent count, which is one byte; booleans and presence flags are one byte.

The remaining sequence is:

1. protocol version, Folderbase ID, Folderbase Version ID, parent count and parents,
   creation time, then the five path-policy strings in schema order;
2. root-manifest path, Object Version ID, content digest, and byte length;
3. binding count and each already-sorted binding's path, Object ID, `live`
   lifecycle, and one-byte kind (`0` directory, `1` regular file, `2` symlink).
   A regular file continues with Object Version ID, content digest, bytes, and
   executable flag. A symlink continues with Object Version ID, target, and target
   safety;
4. Tombstone count and each already-sorted Tombstone's path, Object ID, `deleted`
   lifecycle, the same one-byte kind mapping, and either a zero presence flag or a
   one flag plus last Object Version ID; and
5. exclusion count and each already-sorted exclusion's path, one-byte kind
   (`0` nested boundary, `1` hard link, `2` FIFO, `3` socket, `4` block device,
   `5` character device, `6` other special), and reason string.

No JSON representation, padding, chunk-manifest digest, provider field, unknown
field, or canonical digest value enters the sequence.

## Acceptance

This decision is Accepted because the closed JSON Schema, independently generated
digest sidecars, valid and invalid public fixtures, and Rust module pass focused
conformance, full workspace, packaging, and independent vector checks.

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

The live binding set always contains `.folderbaseignore` and `FOLDERBASE.md` as
regular files. Both are protocol-mandatory for a valid restored Folderbase. The
schema therefore requires at least two bindings, while semantic validation proves
their exact paths and kinds; array cardinality alone cannot express that condition.

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
exact, NFC, or full-case-fold collisions. Windows-reserved names include ASCII
`COM1`–`COM9` and `LPT1`–`LPT9` plus the Windows-recognized superscript forms
`COM¹`–`COM³` and `LPT¹`–`LPT³`, with or without extensions. `.folderbase` and
every descendant are always rejected. A declared nested Folderbase is represented
by one exclusion; nested-boundary exclusions cannot overlap, and no binding,
tombstone, or other exclusion may enter a boundary.

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
exclusion-set changes, and root-manifest changes. When one stable Object ID moves
and its Object Version or metadata also changes, diff emits both `Moved` and
`Updated`; neither fact masks the other. It contains no filesystem capture, Cloud,
provider, authentication, authorization, Local Head persistence, or Remote Head
behavior.

`FolderbaseVersion` itself is not publicly deserializable. Every public construction
path goes through `decode_bounded`, whose private wire record applies the encoded,
per-array, and aggregate limits before a validated public value can exist.

The repository/tag source archive is the normative cross-language protocol bundle:
it contains the schema, public valid and invalid corpus, runtime limit-vector
generator, independent reference encoder, Rust conformance test, and this decision.
The `folderbase-core` Cargo package is the Rust runtime implementation only and
declares that boundary in package metadata. We do not duplicate the protocol bundle
inside the crate or rely on package paths that escape the crate root. A closed
released source-release manifest and verifier keep that separation explicit.
Focused conformance and independent digest verification run on Ubuntu, macOS, and
Windows CI. The protocol 0.4 release manifest has `released` status, and the
verifier rejects both any other status and a remaining candidate manifest before
tagging.

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

## Acceptance evidence

The corrected closed JSON Schema, repository distribution, independently generated
digest sidecars, expanded public corpus, and Rust module passed focused
conformance, macOS and Windows portability, full-workspace, packaging, independent
vector, and independent final-review gates:

- contract PR: [#22](https://github.com/chalkagents/folderbase/pull/22);
- independent final GO on
  `ba9349217a1654db6ac8af0fc460c488a2e69903`, with no P0–P2 findings;
- PR CI:
  [run 30470638866](https://github.com/chalkagents/folderbase/actions/runs/30470638866);
- accepted contract merge:
  `de760987af058740e2d997923f71a56eb01140d2`; and
- post-main CI:
  [run 30470974909](https://github.com/chalkagents/folderbase/actions/runs/30470974909).

The v0.4.0 release PR, release merge, annotated tag, public tag proof, and GitHub
release remain pending. They are publication evidence, not prerequisites for
accepting the reviewed protocol decision, and must not be claimed until observed.

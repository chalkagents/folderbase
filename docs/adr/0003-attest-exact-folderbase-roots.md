# Attest exact Folderbase roots with logical and device-local identity

Status: Accepted

## Context

Folderbase Core needs a small, trustworthy seam that can answer whether one exact
folder is a usable Folderbase root. Local applications, command-line agents, sync
bridges, and future cloud materializers all need the same answer before they read
or mutate a workspace. Existing inspection and validation paths are broader
product workflows: they do not produce a compact receipt that binds the protocol
identity, exact manifest bytes, and this physical root instance.

A pathname is not an identity. It can be renamed, replaced, redirected through a
symlink, or resolve to an ancestor's Folderbase markers. Conversely, logical
Folderbase identity alone cannot distinguish two physical copies materialized on
one device. The public contract must represent both facts without turning a local
filesystem identifier into portable authorization.

## Decision

Core exposes:

```text
attest_folderbase_root(root)
  -> FolderbaseRootAttestation
```

The receipt is a flat, data-only record containing:

- `root`, the caller's display path;
- `folderbase_id`, preserved exactly from the manifest;
- `protocol_version`, preserved exactly from the manifest;
- `manifest_sha256`, the SHA-256 of the exact bounded manifest bytes; and
- `root_instance_sha256`, a versioned SHA-256 of the device-local physical root
  identity.

The logical Folderbase tuple is:

```text
(folderbase_id, protocol_version, manifest_sha256)
```

`folderbase_id` must be exactly `folderbase_<lowercase-hyphenated-UUID>`.
`protocol_version` must parse as SemVer but is not normalized in the receipt.
Whitespace, key ordering, and every other manifest byte therefore affect
`manifest_sha256`. The display `root` is excluded from both digests.
Rust retains `root` as the exact `PathBuf`. JSON renders it explicitly as a
lossy display string so a valid Unix path containing non-UTF-8 bytes cannot
panic or make the otherwise portable receipt unserializable.

The root-instance digest has a versioned domain. Unix continues to use the
released v1 encoding:

```text
SHA-256(
  UTF8("folderbase-physical-root-instance-v1") || 0x00 ||
  UTF8(platform_tag) || 0x00 ||
  physical_identity_bytes
)
```

On Unix, `platform_tag` is `unix` and `physical_identity_bytes` is the
big-endian `u64` device identifier followed by the big-endian `u64` inode.
Those bytes and their v1 domain are unchanged.

Released Windows records also used the v1 domain, with `platform_tag`
`windows`, a big-endian `u32` volume serial number, and a big-endian `u64` file
index. That released encoding remains a compatibility authority for already
durable local records; it is not redefined.

New Windows attestations use:

```text
SHA-256(
  UTF8("folderbase-physical-root-instance-v2") || 0x00 ||
  UTF8("windows") || 0x00 ||
  BE_U64(volume_serial_number) ||
  FILE_ID_INFO.FileId.Identifier[16]
)
```

Both current and released Windows identities are queried from the same retained
no-follow root handle. V2 retains the complete 64-bit volume serial and all 128
bits of `FILE_ID_INFO`, so two ReFS identities that collided after the released
truncation remain distinct. The digest domain itself selects the identity
version; the five-field public receipt gains no separate wire discriminator.
A rename on one filesystem retains the current instance identity; a physical
copy or replacement does not. The digest is deliberately device-local,
non-portable, and is neither an actor identity nor proof of permission.

Windows Core retains an in-memory root authority containing the current V2
digest and, when available, the exact released V1 digest. It admits a durable
record only when the record contains one of those exact values and carries that
recorded value forward into every transitive derivation. Active capture and
restore journals, deterministic restore IDs, rollback, cleanup, completion,
and retained authority receipts are never normalized or rewritten to V2.
Only mutable Local Head may be rebound: under the shared transaction lock,
after its immutable Version and digest verify and no pending operation remains,
or as part of the normal next Head compare-and-swap. Capture-transaction
authority continues to hash the exact journal bytes; version-derived authority
is recomputed for the new root digest. A crash before that Head CAS leaves the
exact old-valid Head, and a crash after it leaves the new-valid Head.

This compatibility cannot retroactively recover identity bits that V1 never
recorded. On first upgrade, a released Windows V1 record whose digest matches
the retained root's released tuple is admitted as trust on first use within the
trusted local `.folderbase` boundary. If a same-user process copied a
self-consistent released record onto a rare physical root with the same
truncated tuple, V1 alone cannot distinguish the two. That ambiguity is neither
portable authorization nor a V2 collision. Once mutable Head is rebound, its
V2 root rejects any different full identity; immutable legacy evidence remains
explicitly legacy until its pending transaction is retired.

Attestation opens the exact supplied root without following a symbolic link or
Windows reparse point and retains its handle. It always resolves
`.folderbase` and `.folderbase/manifest.json` through root-relative
capabilities, without following links. The state marker must be a directory and
the manifest must be a regular file. Protocol 0.1 and 0.2 additionally require
the root `FOLDERBASE.md` regular-file marker. Native protocol 0.5 does not:
the exact manifest is the root authority, and root `FOLDERBASE.md` is fully
ordinary optional content. An optional root `.folderbaseignore` is user-owned
but remains bounded policy input rather than ordinary narrative. Core retains
and revalidates the identities required by the selected profile before
returning the receipt. It never walks to an ancestor to find markers. A nested
valid 0.5 root therefore attests independently without a narrative file, while
an invalid nested folder fails locally even if its parent is valid.

This explicit-root attestation is distinct from parent traversal. A parent that
observes any exact regular, no-follow `.folderbase/manifest.json` records an
opaque nested boundary without reading or decoding its bytes. Malformed nested
state therefore remains hidden from the parent; only an operation explicitly
opened on that root attempts attestation and reports the local failure.
Markerless state or context is inert. ASCII-case marker aliases, symlink or
non-directory state markers, and symlink or non-regular manifest markers are
unsafe shapes rather than authority. Analysis may quarantine them as
`Unchecked` (`unchecked` on the wire) and omit descendants; materializing,
mutating, transfer, and restore seams reject them.

On Windows, every path and opened handle is additionally rejected when
`FILE_ATTRIBUTE_REPARSE_POINT` is set, regardless of reparse tag. This includes
junctions and other reparse-point types at the exact root, state directory,
manifest, or any profile-required entry marker, both during initial opening and
final revalidation.

The manifest is limited to 16 MiB. JSON parsing rejects duplicate object keys
recursively before extracting the minimum required shape. This prevents a
parser or implementation from silently choosing between two security-relevant
values. No attestation state file is written.

The public error is a typed, non-exhaustive taxonomy. A closed public marker
enum identifies `.folderbase`, `.folderbase/manifest.json`, and the legacy
`FOLDERBASE.md` marker, so callers can handle known profile-specific markers
while remaining forward-compatible with new error categories. Attestation
errors distinguish
`RootNotFound`, `RootSymlink`, and `RootNotDirectory`;
`MarkerMissing`, `MarkerSymlink`, and `MarkerWrongType`; an oversized manifest;
`ManifestInvalidJson`; `ManifestDuplicateField` at any depth; missing and
wrong-type required manifest fields; invalid Folderbase identity; invalid
protocol version; one `RootChangedDuringAttestation` for any changed retained
root, marker, or manifest-byte chain; unavailable physical identity; and
filesystem I/O.

Final validation reopens the exact root, state directory, manifest, and every
additional marker required by the selected profile. It requires the retained
identities to match and bounded-reads the reopened manifest again. The second
exact-byte SHA-256 must equal the receipt's `manifest_sha256`; inode, length, or
timestamp checks alone are insufficient.

The CLI exposes:

```text
folderbase attest PATH [--json]
```

Successful JSON is the same flat receipt. Human output names the same five
facts and labels the platform-current digest domain (V1 on Unix, V2 on
Windows). Failures use the CLI's stable JSON error envelope when `--json` is
set and exit with operational status 2.

Attestation is evidence about a local materialization. It does not prove share
grants, actor authority, cloud readiness, sync completeness, object history, or
workspace health beyond the exact profile contract above. Optional
`.folderbase/summary.md` and `.folderbase/questions.jsonl` hints never enter the
logical tuple and grant no mutation or sharing authority. Other
`.folderbase/**` content remains private and inert without becoming a named
hint format. Those decisions remain in their respective Core and product
layers.

## Rejected alternatives

**Use the canonical path as physical identity.** Renames would spuriously change
identity and a replacement at the same path would be missed.

**Write a root-instance identifier into `.folderbase`.** That would mutate a
read-only operation, create synchronization conflicts, and make copied state
claim to be the same physical materialization.

**Search ancestors for Folderbase markers.** This would make a malformed nested
root silently inherit the wrong security boundary.

**Deserialize the manifest directly with `serde_json`.** Ordinary map
deserialization accepts duplicate keys with last-value-wins behavior and cannot
provide the strict wire contract required here.

**Include the root path in a digest.** The path is useful display context but is
neither stable under rename nor part of logical or physical identity.

**Refactor transfer traversal into a shared helper in this slice.** Root
attestation has a deliberately small private traversal module. Generalizing
existing transfer behavior at the same time would increase review surface and
risk loosening already-published contracts.

## Acceptance

The decision is implemented when Core and CLI tests prove:

- exact-byte logical receipts and stable device-local instance receipts;
- distinct instance receipts for physical copies;
- exact-root behavior for valid and invalid nested roots;
- no-follow and correct-type checks for all markers required by each supported
  profile;
- recursive duplicate-key rejection and the 16 MiB bound;
- invalid canonical IDs and SemVer rejection without normalization;
- retained-identity change detection where a deterministic race can be staged;
- unchanged Unix v1 vectors and independent native Windows v2 encoding;
- rejection of Windows identities that collided under the released truncation;
- exact recovery of released-root capture and restore journals across Head and
  cleanup boundaries without rewriting immutable receipts;
- stable human and JSON CLI output and JSON error envelopes with exit status 2;
- macOS and Windows execution in CI; and
- no filesystem mutation during attestation.

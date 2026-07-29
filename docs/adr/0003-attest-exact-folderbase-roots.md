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

The root-instance digest v1 is:

```text
SHA-256(
  UTF8("folderbase-physical-root-instance-v1") || 0x00 ||
  UTF8(platform_tag) || 0x00 ||
  physical_identity_bytes
)
```

On Unix, `platform_tag` is `unix` and `physical_identity_bytes` is the
big-endian `u64` device identifier followed by the big-endian `u64` inode. On
Windows, `platform_tag` is `windows` and the bytes are the big-endian `u32`
volume serial number followed by the big-endian `u64` file index. A rename on
one filesystem retains this instance identity; a physical copy or replacement
does not. The digest is deliberately device-local, non-portable, and is neither
an actor identity nor proof of permission.

Attestation opens the exact supplied root without following a symbolic link or
Windows reparse point and retains its handle. It then resolves
`.folderbase`, `.folderbase/manifest.json`, and `FOLDERBASE.md` only through
root-relative capabilities, without following links. The state marker must be a
directory and both files must be regular files. Core retains and revalidates the
opened identities before returning the receipt. It never walks to an ancestor
to find markers. A nested valid root therefore attests independently, while an
invalid nested folder fails locally even if its parent is valid.

The manifest is limited to 16 MiB. JSON parsing rejects duplicate object keys
recursively before extracting the minimum required shape. This prevents a
parser or implementation from silently choosing between two security-relevant
values. No attestation state file is written.

The public error is a typed, non-exhaustive taxonomy. A closed public marker
enum identifies `.folderbase`, `.folderbase/manifest.json`, and
`FOLDERBASE.md`, so callers can handle known protocol markers while remaining
forward-compatible with new error categories. Attestation errors distinguish
an invalid root, a missing marker, a linked marker, a wrong marker type, an
oversized manifest, malformed JSON, duplicate keys, invalid required shape,
invalid Folderbase identity, invalid protocol version, changed retained state,
unavailable physical identity, and filesystem I/O.

The CLI exposes:

```text
folderbase attest PATH [--json]
```

Successful JSON is the same flat receipt. Human output names the same five
facts. Failures use the CLI's stable JSON error envelope when `--json` is set
and exit with operational status 2.

Attestation is evidence about a local materialization. It does not prove share
grants, actor authority, cloud readiness, sync completeness, object history, or
workspace health beyond the exact marker contract above. Those decisions remain
in their respective Core and product layers.

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
- no-follow and correct-type checks for all markers;
- recursive duplicate-key rejection and the 16 MiB bound;
- invalid canonical IDs and SemVer rejection without normalization;
- retained-identity change detection where a deterministic race can be staged;
- stable human and JSON CLI output and JSON error envelopes with exit status 2;
- macOS and Windows execution in CI; and
- no filesystem mutation during attestation.

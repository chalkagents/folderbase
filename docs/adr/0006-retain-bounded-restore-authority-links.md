# ADR 0006: Retain bounded restore authority links

- Status: Proposed
- Date: 2026-07-30
- Owners: Folderbase Core
- Related: ADR 0005, FB-41F

## Context

An ordinary-file Tombstone restore stages one independent inode and hard-links
it into an absent workspace path. Earlier cleanup attempted to remove the
private link after checking that it still named the published inode. Portable
pathname APIs cannot make a separate identity check and later rename or unlink
one indivisible operation. A concurrent replacement could therefore be
overwritten or deleted in the gap.

Deleting the private link also made later capture unable to distinguish a
Folderbase-created hard link from a user-created hard link. Treating every hard
link as ordinary content would weaken capture's existing fail-closed behavior.

## Decision

Successful ordinary-file restores retain the transaction-unique private stage
as a device-local authority link. Cleanup does not rename or unlink that link.
Before terminal acknowledgement it verifies, through retained no-follow
capabilities, that:

1. the private pathname still names the opened stage;
2. the workspace pathname names the same filesystem object;
3. every present path has the cleanup receipt's publication identity;
4. committed restores still have the sealed digest, length, and executable
   fidelity; and
5. those proofs remain true before and after both cleanup hook boundaries.

The transaction directory contains one bounded
`folderbase-restore-authority-v1` receipt binding the Folderbase and physical
root, transaction ID, workspace path, private stage path, and publication
identity.

Capture keeps ordinary hard links excluded. It makes one narrow exception for a
workspace regular file when every authority receipt for that exact workspace
path and current identity revalidates its private link, and the filesystem link
count is exactly:

```text
1 visible workspace link + N validated Folderbase authority links
```

Any extra link remains an unsupported hard-link exclusion. An authority for an
older inode or another workspace path cannot authorize the current file.
Same-inode user edits remain capturable because the authority proves ownership,
not immutable content.

Restore authorities are capped at 4096 per Folderbase. The cap applies only to
explicit Tombstone restore authorities, not normal capture, sync, or clean-root
reconstruction. A new restore at the cap fails closed with the typed
`RestoreAuthorityMaintenanceRequired` error. Authority hard links consume
directory metadata but do not duplicate file content.

There is no automatic garbage collection in this slice. A future ADR must
define explicit maintenance/compaction with platform-specific mutation proofs,
recovery, and user-facing policy before any authority pathname is removed.

## Identity guarantees

On Unix, the device-local identity is the filesystem device and inode number.
That pair identifies the live object while the retained authority link keeps
the inode allocated. It is not a global identity and must not be used after the
authority link is missing.

On Windows, the identity is the volume serial number plus the complete 128-bit
`FILE_ID_INFO.FileId.Identifier`. The shorter legacy file-index value is not
used for restore authority.

Neither identity grants cross-device, cross-host, sync, sharing, or logical
Object authority.

## Consequences

- Cleanup has no authority-link overwrite or check-then-unlink race.
- User and agent edits through the live inode remain ordinary capturable work.
- User-created extra hard links still fail closed.
- Terminal completion evidence is valid only while its exact authority receipt
  and private stage still revalidate.
- Repeated restores consume one bounded metadata entry each and eventually
  require explicit maintenance.
- Transaction directories are intentional retained state, not cleanup leaks.

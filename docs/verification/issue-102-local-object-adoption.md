# Per-file history and whole-folder capture

Issue: https://github.com/chalkagents/folderbase/issues/102

## Problem and resulting behavior

Previously, a file captured through the per-file API could receive a second
Object ID on its first whole-folder capture. Its older versions remained on
disk, but subsequent path-based history and saves refused the duplicate claim.
The regression reproduces that failure on the parent candidate.

Whole-folder capture now adopts a verified existing canonical file Object when
the prior Folderbase Version has no binding for it. Capture persists that ID in
its ordinary durable assignment before writing immutable records. It preserves
the ordered per-file history, Object provenance/lifecycle/extension fields, and
each older Version record. The first whole-folder capture may append another
Version even when bytes are unchanged. This does not change Version deduplication
or the existing capture-intent format.

## Deleted paths and later recreation

A deleted file and a later file at the same path remain distinct Objects, as
required by the Folderbase Version contract. Existing modified-restore recovery
can leave such a recreation ready for capture; this workflow stays supported.
The old Object and all its versions remain retained. A verified current live
binding identifies the current path's Object; an exact path/old-ID Tombstone
explains a historical claimant. Unexplained duplicates still refuse.

Repeated recreation can replace the current Version's same-path Tombstone. A
bounded ancestor metadata walk then locates earlier Tombstones as needed. It
also prevents capture from reviving an earlier retired ID. Ordinary captures
whose claims are all explained by current bindings do not walk ancestors.

Path-based history lists only the current Object's versions. It does not join
different Objects into one invented lineage. Earlier Object versions remain
available by their retained IDs and through the applicable Tombstone/export
surfaces. This change does not attempt to repair pre-existing unexplained
duplicates created by earlier binaries.

## Authority, bounds, and refusal

- Capture scans Object records once, preserving full malformed-record,
  filename/ID, path, duplicate, boundary, and transfer checks. It validates
  selected Object/Version membership and hashes each adopted current blob.
  Retaining older history IDs does not certify every historical blob's presence.
- Capture rechecks observed metadata, Object-directory names, and planned file
  evidence before publication. No durable assignment ID is rewritten on retry.
  If a pending assignment loses its Object projection but older same-ID Version
  records remain, replay refuses instead of rebuilding a shortened history.
  The unchanged intent format cannot detect deletion of every older witness by
  an uncooperative actor.
- Path ownership reads use the existing physical-root/Local Head admission,
  bounded Folderbase Version decoding, exact ID/root membership, and observed
  bytes. Head and explicit anchor digest pins are verified. Existing parent
  links contain IDs, not parent digests; this does not add cryptographic ancestry
  guarantees to that format.
- Read-only file history observes and rechecks every Head, Version, ancestor,
  and referenced per-file metadata record used in its decision. It performs no
  capture, repair, recovery, layout creation, or blob scan. Its existing pending
  operation and migration refusals remain unchanged.
- Capture permits at most 16,384 Object-directory entries, 32,768 selected
  per-file Version references, 65,536 observed records, 1 MiB per Object/local
  Version record, and 64 MiB aggregate observed metadata. Ancestor search stops
  after 1,024 full Versions or 64 MiB of ancestor metadata. These are refusals,
  never silent truncation. Existing file-history output/read bounds also apply.
  Ownership/capture state errors identify the bounded or invalid evidence;
  they do not return partial history.
  The ordinary per-file writer's initial Object scan retains its existing
  unbounded record reads; the new 64 MiB ownership-proof bound does not change
  that older lookup limit. Capture and read-only history use bounded scans.
- Missing, cyclic, wrong-root, conflicting, or changed required evidence
  refuses. A private optional export-anchor seam accepts only an encountered
  exact Version ID/digest and sorted retired-Object witnesses supplied by a
  separately verified completed export receipt. This branch's ordinary callers
  pass no anchor; real export receipt integration is separate work. Arbitrary
  missing parents are never treated as an import boundary.

These are cooperative local filesystem checks, not isolation from an
uncooperative process with the same user's permissions. No public schema,
index, SQL engine, command, or SDK method is introduced.

## Verification

Focused tests cover:

- Per-file capture and CAS, whole capture, a second standalone file after Head,
  real Change Set creation plus an ordinary binary attachment, further saves,
  exact earlier recovery, and preserved Object/Version extension metadata.
- Recovery at capture persistence checkpoints with the same assigned identity;
  missing projection refusal with retained earlier history evidence.
- Malformed unrelated records, duplicate/aliased claimants, invalid lifecycle
  and schema, foreign Version membership, missing current blobs, transfer
  receipt damage, and concurrent metadata/file replacement.
- Existing modified-Tombstone recovery cases extended with history, read/CAS,
  later full capture, and exact recovery of the previous Object's bytes.
- Two delete/recreate cycles with three distinct IDs and continued local app
  operations after each cycle.
- Read-only tree equality, authority-byte changes during a read, and private
  ancestry/anchor missing, cycle, membership, finite-count, and digest guards.

Final full gate receipts and exact source pin are recorded in the pull request.

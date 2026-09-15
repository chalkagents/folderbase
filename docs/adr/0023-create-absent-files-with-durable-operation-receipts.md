# ADR-0023: Create absent files with durable operation receipts

## Status

Accepted for experimental implementation September 15, 2026 for issue #101.
The six-case public behavior suite passed before advertisement. Unreleased.

## Interface

`create_workspace_file(root, path, operation_id, bytes)` and
`workspace create ROOT PATH --operation-id UUID --stdin --json` create one
regular file, with at most 8 MiB of exact binary content, in an existing safe
parent. The destination must be absent. Parent creation, overwrite, executable
files and multi-file transactions are outside this interface. SDK
`workspaceCreate(root, path, { operationId, content }, options)` accepts an
exact UTF-8 string or Uint8Array; malformed Unicode is refused before encoding.

The caller persists one canonical lowercase hyphenated UUID before its first
attempt. The operation binds that UUID to the exact portable path and content
digest/length. A different request with the same UUID conflicts. An existing
destination conflicts even if its bytes are identical. A successful response
contains the original Object/Version identity and content metadata, with a
`replayed` flag. A matching completed retry returns that original historical
result; it never recreates a later deleted file or overwrites later edits.

The operation does not perform a whole-workspace capture. Later capture must
preserve this Object identity and history (issue #102). Attachments can be
created first, then referenced by a separate record compare-and-swap update.
If that update conflicts, the attachment remains discoverable ordinary data;
the application owns retry/orphan handling and must not claim atomicity.

Same-path recreation allocates a new Object only when every prior claim is
independently retired by verified full-Version Tombstone ancestry. Completed
creation provenance provides a private ownership proof for immediate history
and CAS before the next full capture: exactly one canonical claimant may remain
unretired, it must never have appeared in the retained full-Version graph, and
there must be no current binding at that path. Its closed completed receipt must
match the current physical root/state, path, Object and original immutable Version
metadata/membership. Every other claimant remains independently retired. Receipt
inventory and authority are rechecked alongside the caller's raw metadata
witnesses. This is identity provenance, not current-byte authority. Pending create
remains refused by readers/writers; no hidden whole capture or merged history is
permitted. Receipt inventory is bounded to 16,384 names and 64 MiB within the
caller's metadata budget; required ancestry retains issue #102's bounds.

## State and durability

One closed, independently versioned intent lives at
`.folderbase/transactions/workspace-create/active.json`. It pins the request,
root/manifest attestation, chosen Object/Version/event identities and exact
private stage identity once prepared. Completed receipts live at
`.folderbase/local/workspace-create/receipts/<operation UUID>.json`.
No field is silently added to the legacy pending-transaction decoder.

Under the shared root write lease:

1. Validate the request, root, safe existing parent, absence, stored path
   claimants and other pending work. Prepare bounded immutable bytes. Before
   intent publication an interruption can leave only immutable orphans; no
   ordinary file is published and no stage alone makes the root busy.
2. Publish the intent with its original IDs durably. Install or verify the
   immutable Object Version before publishing ordinary bytes. Corrupt existing
   metadata fails before any visible file creation.
3. Copy the immutable blob into a fresh UUID private staged inode, flush it and
   its directory, and durably pin its name and physical identity in the intent.
   A crash before that pin leaves an ambiguous artifact which is never reused
   or removed by matching its bytes. Retry prepares a fresh name; at most four
   artifacts per operation are permitted before an explicit retained-artifact
   refusal. Only the pinned stage can be published or cleaned up. The
   visible file must never share an inode with the immutable blob.
4. Publish the stage with a no-clobber hard link through retained no-follow
   directory capabilities. Retry recognizes only the exact stage inode, never
   equivalent foreign bytes. Flush the visible parent on fresh publication
   and on an already-published retry. Revalidate attachment, boundary, identity
   and content before advancing.
5. Install the exact mutable Object/path identity projection and append the
   original journal events idempotently. The create-only journal append strictly
   parses at most 64 MiB, preserves existing bytes, appends missing exact events
   and durably replaces the file even on replay. It refuses partial/corrupt tails
   and conflicting event IDs; it does not invoke legacy journal repair. This can
   rewrite up to 64 MiB per create. Verify the accepted state, then make
   the immutable original-result receipt durable.
6. Remove only the exact owned private stage; cleanup no longer depends on the
   ordinary destination's bytes or existence. Retire the active intent last.
   An interruption after receipt publication is completed work with pending
   cleanup, not permission to recreate the destination.

No destructor establishes success. Failed writes/flushes remain errors. A
pre-publication competing target can be recorded as a terminal conflict and
its owned stage retired without touching the target. Uncertain ownership or
changed private metadata remains an inspectable refusal; no blind repair or
cleanup is permitted. Native changes before completion may require recovery;
changes after a durable receipt do not invalidate the historical result.

## Cooperative writers and compatibility

Every same-build shared root lease refuses an active create except this
operation's own validated continuation. Read-only history/export also refuse
the active marker. Creation refuses other pending capture, restore, Change Set,
reorganization and per-file work, and unsupported migration/transfer state;
it does not recover unrelated work implicitly.

Only the same-build cooperative writer topology is supported. Older binaries
can ignore this new namespace; their whole capture can also replace standalone
identity. A new intent is not a global downgrade fence. Test exact old-writer
behavior at pending and completed phases and document the limitation. Do not
change the root manifest protocol or reinterpret existing failed transactions.

Receipt replay must attest the current physical root and Folderbase operation
namespace. Copying private receipts to another root does not confer authority.
Filesystem guarantees are those of existing retained publication and flush
helpers; no stronger Windows directory power-loss guarantee is introduced.
Native editors and malicious same-user processes are not isolated by metadata.

## Required proof

Exercise zero-byte/binary/Unicode creation, occupied files/directories/symlinks,
safe-parent and nested-boundary refusal, duplicate/path aliases, exact retries,
changed requests, restart, response loss, stale native edits and root/state/
stage replacement. Interrupt at every durable phase, including immediately
after visible linking and after receipt publication; assert observed phase
effects, unrelated bytes, exact IDs/history, flush-on-retry and bounded cleanup.
Inject failed flushes and corrupt immutable records before publication.

Run the real CLI/SDK consumer journey and later the combined identity-adoption
and retained-history export journey. Preserve the normative positive suite;
advertise only after it passes. No tag, release or new compatibility claim is
part of this initial implementation.

# Read-only file history 0.1

Experimental optional capability: `folderbase.file-history@0.1.0`.

The local app example needs every retained version of a task or attachment. The
whole-root `version history` command returns journal events; that is not a complete
per-file version list. In particular, accepted Change Sets can retain versions
without equivalent per-file journal events.

## Interface

```sh
folderbase version list /absolute/path/to/root tasks/task.json --json
```

```rust
use folderbase_core::read_file_history;
let history = read_file_history("/absolute/path/to/root", "tasks/task.json")?;
```

```js
const result = await client.fileHistory(root, "tasks/task.json");
if (result.kind === "success") {
  for (const version of result.document.versions) {
    console.log(version.id, version.captured_at);
  }
}
```

The SDK is a thin executable adapter. Discover the exact optional capability with
`client.contract()` before relying on it. Existing executables need not implement
this command. No daemon method or existing command changes.

Success is one JSON object on stdout, empty stderr, exit 0:

```json
{
  "format": "folderbase-file-history-v1",
  "path": "tasks/task.json",
  "object_id": null,
  "current_version": null,
  "versions": []
}
```

That example describes an existing **untracked** file. For a tracked file, IDs are
opaque strings, and `versions` contains the complete `LocalVersionRecord` values:
`id`, `object_id`, `content` (`algorithm`, `digest`, `bytes`), `captured_at`, and any
extension fields. `captured_at` is returned exactly as recorded, with no journal
or filesystem timestamp substitution. Stored order is not timestamp order;
distinct Version IDs may retain identical bytes. `current_version` is the Object's
recorded head, which need not be the final array item or match live file bytes.

The path must name an **existing regular file** under an initialized, attested
root; binary attachments work. The returned path uses canonical filesystem
spelling and native separators (`tasks\task.json` on Windows). Missing/deleted
files are refused; this version has no Object-ID or
Tombstone selector. The operation neither reads current content nor verifies
retained blobs. A successful metadata list does not certify recoverability of
content or capture an ordinary-file edit.

## Read-only behavior and concurrency

The operation creates no directories, records, locks, journal events, or versions.
It does not repair, capture, replay, quarantine, or reconcile anything. It works
on physically read-only roots. Normal OS access-time effects from reads are outside
this guarantee.

If the existing transaction lock is present, the reader opens it read-only and
attempts a nonblocking shared lock. A cooperating writer yields a busy refusal.
A missing lock remains missing. The reader retains root/state capabilities and
checks record bytes, directory names, file identity, root/manifest identity,
path ownership/aliases, pending work, and lock identity/appearance again before
success, whether or not it obtained a lock. Changes yield a refusal; callers may
retry a changed or busy observation. This is not a general snapshot isolation
promise against an uncooperative process with the same filesystem access.

Known active capture, restore, Change Set, reorganization, protocol-upgrade and
local-version transactions refuse. Transfer staging or an active transfer intent
refuses. Completed transfers can be read at their destination; outgoing receipts
continue to revoke source authority. The bounded journal must parse completely;
an invalid unterminated tail is refused without repair. Historical journal paths
are not treated as current ownership claims for unrelated files.

**Migration limitation:** any nonempty `.folderbase/migrations` directory returns
`file_history_migration_state_unsupported`, including completed migrations. Existing
migration validation can repair staging as a side effect. This experimental reader
therefore never calls that validator. This result is not a recovery instruction;
retrying or recovering a completed migration does not remove the limitation.
A separately reviewed read-only migration validator is needed to lift it.

## Bounds and errors

There is no truncation or pagination. Exceeding a bound refuses the entire result:

| Bound | Maximum |
| --- | ---: |
| Names in each inspected private directory | 16,384 |
| Versions in the selected Object | 16,384 |
| Object, Version or selected transfer-receipt bytes | 1 MiB each |
| Journal, active-work or transfer-intent bytes | 16 MiB each |
| Retained metadata observations | 32,768 records / 64 MiB |
| Pretty-printed result including envelope and newline | 8 MiB |

Existing path/boundary work limits also apply. All Object JSON files are scanned,
including unrelated records, to reject malformed/nonregular records, unsafe
stored paths, filename-ID mismatch, aliases and unexplained duplicate claimants. Selected
Object history rejects duplicate Version IDs, missing records, invalid digests,
filename-ID mismatches and Versions belonging to another Object. This is a
metadata scan, not an index-backed point lookup.

When a deleted path is recreated, the current file has a new Object ID. A
verified live binding and exact path/old-ID Tombstones distinguish retained
historical Objects from the current owner. Earlier Tombstones may require a
bounded ancestor metadata walk: at most 1,024 full Versions and 64 MiB of ancestor
bytes, also subject to the aggregate read budget above. Missing, cyclic,
conflicting, or changed required evidence refuses without a partial result.
Parent links contain IDs, not parent digests; digest pins are verified where
actually supplied by the Head or an explicit verified reconstruction anchor.

History lists only the current Object's Versions. Earlier Object and Version
records remain retained, and recovery by a known earlier Version ID continues
to work. Distinct Objects are not concatenated into one history. See
[the capture/adoption verification note](verification/issue-102-local-object-adoption.md)
for the exact ownership rules and bounded refusal behavior.

Operational refusals use exit 2, empty stdout and the existing closed JSON error
envelope on stderr: `{"error":{"code":"...","message":"..."}}`.

| Code | Meaning / action |
| --- | --- |
| `file_history_file_not_found` | Selected file is missing; inspect its current location. |
| `file_history_busy` | Existing writer holds the lock; retry later. |
| `file_history_changed` | An observed authority changed; retry a fresh read. |
| `file_history_recovery_required` | Pending work exists; use its existing explicit recovery workflow. |
| `file_history_migration_state_unsupported` | Migration metadata is unsupported by this reader; do not enter a recovery loop. |
| `file_history_limit_exceeded` | Named limit exceeded; no partial result. |
| `file_history_state_invalid` | Invalid/unreadable state, unsafe path or boundary; inspect the message. |
| `file_history_root_invalid` | Root attestation refused, including an invalid root or protocol-upgrade recovery gate. |

`FileHistoryError` exposes typed Rust variants and `.code()`. The SDK preserves
operational codes in `FolderbaseOperationalError.document.error.code`; it preserves
additive result fields through the standard JSON transport.

## Verification

The dedicated public capability runner checks untracked/missing reads, complete
Change Set-created JSON and binary attachment history, one additional Version on
a CAS save, uncaptured owner edits, and pending refusal. It checks file hashes,
names and modification times before/after reads. The Rust suite additionally
covers read-only permissions, transfer ownership, migration refusal, corrupt and
oversized metadata, and deterministic identity/record/lock/boundary changes.

```sh
node protocol/conformance/capabilities/run.mjs --implementation ./target/debug/folderbase --capability folderbase.file-history@0.1.0
```

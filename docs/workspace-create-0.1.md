# Expected-absent file creation 0.1

Experimental optional capability: `folderbase.workspace-create@0.1.0`.
Discover this exact profile before using the command or SDK helper. It is not
part of the minimum Compatibility Contract v1 or the released 0.7.2 executable.

```sh
printf '%s' '{"title":"First"}' | folderbase workspace create /absolute/root tasks/new.json --operation-id 019f0000-0000-7000-8000-000000000001 --stdin --json
```

```js
// Persist this exact request before the first attempt; reuse it after a timeout.
const request = {operationId: crypto.randomUUID(), content: '{"title":"First"}'};
const created = await client.workspaceCreate(root, "tasks/new.json", request);
// A retry may report the original success after a later native edit/deletion.
// Read the current file before displaying its current content.
```

Rust: `create_workspace_file(root, path, operation_id, bytes)` returns
`WorkspaceCreateResult` or typed `WorkspaceCreateError`. Content is at most
8 MiB, including zero bytes, with no added newline or UTF-8 conversion. SDK
content accepts a well-formed Unicode string or `Uint8Array`; lone surrogates
and oversize input refuse before spawning. A lower configured SDK input limit
still applies. Files are non-executable. Existing safe parents are required;
parents, multi-file transactions and overwrites are outside this operation.

## Retry and result

Persist one canonical lowercase hyphenated UUID plus the original path/content
before calling. The first durable intent binds the UUID to that exact request.
Different content or path under an accepted UUID returns a conflict. A target
that is already occupied is never adopted, including identical bytes. Requests
refused before intent publication have not reserved their UUID.

Exit 0 returns one JSON object on stdout and empty stderr:

```json
{
  "format": "folderbase-workspace-create-result-v1",
  "operation_id": "019f0000-0000-7000-8000-000000000001",
  "path": "tasks/new.json",
  "object_id": "obj_019f0000-0000-7000-8000-000000000002",
  "version_id": "version_019f0000-0000-7000-8000-000000000003",
  "content": {"algorithm":"sha256","digest":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","bytes":0},
  "created_at": "2026-09-15T00:00:00+00:00",
  "replayed": false
}
```

The example metadata describes an empty file. Object and Version IDs are opaque.
`replayed: true` identifies a completed original-result receipt. A resumed pending
operation can return `false`. In either case the receipt describes the creation,
not a guarantee about current ordinary bytes. A later deletion stays deleted.
Receipts are bound to the same physical Folderbase Root and private state;
copying them elsewhere does not confer retry authority.

One operation holds the existing cooperative root writer lease. Other same-build
writers and read-only history refuse pending creation. Retry the original request
to complete it. Receipt replay can finish private cleanup after native changes
without changing the visible destination. Ambiguous replacement state is retained
and refused. Before the stage identity is durably pinned, retry leaves any orphan
stage untouched and prepares a fresh UUID stage. Four retained preparation
artifacts cause a typed inspection refusal; do not guess which bytes to delete.

## Attachments and history

A successful create installs one complete per-file Object/Version and journal
history without a whole-folder capture. Create an attachment first, then add its
path to an application record with a separate compare-and-swap save. A conflicting
save can leave an unlinked ordinary attachment. The application should list it
and provide explicit retry/link handling. These two operations are not atomic.
After deletion has been recorded by a whole-folder capture, a new operation may
create a new Object at the same absent path. Every older same-path claim must
have independently verified Tombstone ancestry; unexplained claims still refuse.
Old Objects and their Version lists remain separate and unchanged. History and
CAS work immediately before the next whole-folder capture: a completed receipt
proves the new Object's original identity and Version membership, not its current
bytes. No hidden capture or history merge occurs. A competing current full-Version
binding or an ID already known to older full Versions cannot use this exception.

## Bounds and operational refusals

Creation scans at most 16,384 Object entries, 1 MiB per Object record, and 64 MiB
aggregate Object metadata. Parent directories have a 16,384-entry bound. Active
creation/receipt records are closed and at most 64 KiB. Other inspected private
directories are bounded at 16,384 names; transfer intents have a 64 MiB aggregate
bound. The journal is limited to 64 MiB and can be rewritten in full per create.
Existing bytes are preserved; corrupt or partial tails and conflicting duplicate
event IDs refuse instead of invoking legacy repair. None of these limits truncate
history or return a partial success.

When same-path recreation needs creation provenance, ownership resolution scans
at most 16,384 receipts, 64 KiB each, within the caller's 64 MiB metadata budget.
Required full-Version ancestry is bounded to 1,024 records and 64 MiB; missing
ancestry is refused. Reading history observes receipt metadata only and rechecks
the original receipt bytes, inventory and physical authority without blob reads,
recovery or writes. Copying or altering a receipt cannot establish ownership.

Operational failures use exit 2, empty stdout and the normal JSON error envelope
on stderr. SDK callers read `error.document?.error?.code` (transport errors may
have no error document). Codes include:

- `workspace_create_destination_occupied`: target/claim occupied; use another path.
- `workspace_create_operation_conflict`: the UUID belongs to a different request.
- `workspace_create_recovery_required`: another pending operation needs recovery.
- `workspace_create_retained_stage_limit`: retained unclaimed stages need inspection.
- `workspace_create_invalid_operation_id` / `workspace_create_content_too_large`.
- `workspace_create_migration_state_unsupported`: any migration metadata, including
  completed migration metadata, is unsupported; this is not a recovery instruction.
- `workspace_create_authority_changed`: physical root/private state/unfinished parent
  or manifest changed; original completion is not authorized on a copied root.
- `workspace_create_state_invalid` / `workspace_create_root_invalid`: inspect the
  message; corrupt records and unsafe paths are preserved, not repaired.

## Compatibility and verification

Use one checked Core build for all writers. Older executables ignore the new
intent namespace; this is not a downgrade fence. Old whole-folder capture can
replace standalone identity. Do not mix an older app/CLI writer into a root using
this experimental operation, even after creation completes. Native file editors
remain ordinary writers and can make an unfinished operation require inspection.
Windows retains the existing implementation's weaker directory durability limits;
this feature adds no stronger power-loss or same-user isolation guarantee.

The public six-case runner covers exact binary/empty/Unicode creation, original
receipt replay, request conflicts, CAS/history/exact recovery, native edits and
deletions, unsafe/bounded input and pending-work refusal. Rust tests additionally
interrupt real child processes at publication/cleanup joins, verify root/state/
parent/stage replacement refusals, preserve unpinned artifacts, reject corrupt
Versions/journals, and inject fresh/retry parent-flush failures.
The packed SDK proof also runs three creation/deletion generations through
immediate history, CAS, whole capture and exact original-Version recovery.

```sh
node protocol/conformance/capabilities/run.mjs --implementation ./target/debug/folderbase --capability folderbase.workspace-create@0.1.0
```

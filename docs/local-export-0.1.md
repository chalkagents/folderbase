# Local workspace export 0.1

Unreleased experimental capability: `folderbase.local-export@0.1.0`. The public
Core 0.7.2 release does not implement these commands. Discover this exact
capability on your candidate executable before using it. The complete profile
is advertised only on Linux and macOS release targets. Windows retains the
command/refusal surfaces but does not advertise a working restore backend.

Export preserves a selected folder snapshot and all retained ordinary-file
history for its Objects, including earlier retired identities proven by its
ancestry. Git metadata is snapshot-only. Restore creates a usable workspace
with new local authority at an absent destination. It does not reuse a copied
Local Head, overwrite an existing workspace, or require Cloud storage.

## First use

Use an initialized workspace with a saved task or attachment. Choose a package
path and restore path that do not exist, outside the source workspace:

```sh
folderbase export create /absolute/workspace /absolute/backup --json
```

Keep the returned `export_index_sha256`. Restore with a new operation UUID and
that exact digest. Keep this request if you need to retry an interrupted restore:

```sh
folderbase export restore /absolute/backup /absolute/restored --stdin --json <<'JSON'
{
  "operation_id": "reconstruction_01998550-a73c-7000-8000-000000000099",
  "export_index_sha256": "REPLACE_WITH_THE_RETURNED_64_CHARACTER_SHA256"
}
JSON
```

The placeholder digest must be replaced. Restore validates the closed request
and the entire package before publishing the new root. A successful exact retry
returns `replayed: true`. Changes made in an already-restored destination make
that original restore request refuse; export the changed workspace to retain
new work.

Ordinary commands can now read, save, capture, and restore files in the new root.
Keep the source and package until you have verified the restored workspace.
Export does not prune either one's history.

## SDK

Use a candidate executable implementing the capability and this SDK source:

```js
import { randomUUID } from "node:crypto";
import { FolderbaseClient } from "@folderbase/sdk";

const client = new FolderbaseClient({
  executable: "/absolute/path/to/candidate/folderbase",
  timeoutMs: 120_000,
});
const contract = await client.contract();
if (contract.kind !== "success" || !contract.document.capabilities?.some(
  (entry) => entry.name === "folderbase.local-export" && entry.version === "0.1.0",
)) throw new Error("This executable does not advertise local export 0.1");

const exported = await client.exportWorkspace("/absolute/workspace", "/absolute/backup");
if (exported.kind !== "success") throw new Error("Export needs attention");
const request = {
  operation_id: `reconstruction_${randomUUID()}`,
  export_index_sha256: exported.document.export_index_sha256,
};
const restored = await client.restoreWorkspace("/absolute/backup", "/absolute/restored", request);
console.log(restored.document);
```

The SDK invokes Core through a child process. It does not inspect private
metadata or implement a second reconstruction engine. Save the request in your
application before dispatch if that application needs durable retry.

## Selecting a retained snapshot

```sh
folderbase export list /absolute/workspace --json
folderbase export create /absolute/workspace /absolute/older-backup --version FULL_VERSION_ID --json
```

`list` returns verified full-Version **metadata** sorted by ID, without adopting
Local Head, capturing edits, choosing a current snapshot, or certifying that all
content is recoverable. `create --version` verifies the selected content and
history without modifying the source. It can read a stopped copied archive;
normal writes still require valid authority for that physical root.

An older snapshot restores its selected bytes and current per-file Version.
It also includes later retained versions of the same included Objects. It does
not include Objects created only after that snapshot: these are reported in
`omitted_objects`. Capture-ignored content and nested Folderbases remain outside
the selected snapshot; `capture_exclusions` reports the count.

## Retention and limits

- Every included ordinary Object keeps its exact ID and ordered Version list,
  original Version metadata, and all referenced bytes. Different Version IDs
  with identical bytes remain distinct. Stored order is not timestamp order.
- Full-snapshot executable mode comes from the selected binding or Tombstone.
  Explicit per-file executable metadata must agree with it. Older records that
  omitted this field stay unchanged; restoring those individual versions keeps
  Core's existing non-executable default. Export does not invent historical
  permission metadata.
- A deleted-and-recreated path can have several independent Objects. Export
  retains proven earlier identities separately in `retired_objects`. It does
  not join their histories into one identity. Historical paths come from the
  selected snapshot or verified earlier witnesses.
- Exact `.git` components, case-insensitively and at any depth, have no ordinary
  Object projection. Their selected bytes/fidelity remain in the snapshot and
  `snapshot_only_reserved_paths` reports the exception. `.gitignore` retains
  normal file history. This does not promise every historical Git file.
- The package contains one complete selected Folderbase Version, not the entire
  historical full-snapshot graph. Retired witness metadata does not imply those
  older full snapshots can be recovered. Local scopes, journals, physical file
  identities, transfer authority, and execution provenance are not portable.
- Existing reconstruction 0.1 packages and commands retain their old semantics.
  The new wrapper is a separate closed package with `export.json`, `root/`, and
  `history/`. Applications should use Core's interface, not edit these files.
- Bounds refuse the whole operation; nothing is truncated. Limits include
  16,384 retained ordinary-file Versions, 1 MiB per Object/Version record,
  64 MiB aggregate history metadata (including repeated chunk references),
  16,384 observed ancestors, 1,048,576 distinct chunks, and 8 MiB result JSON.
  Existing snapshot/content limits and the reader's 64 MiB observation budget
  still apply.

Current-workspace export preflights its package destination, then captures the
current capturable files. It may add legitimate source history metadata. It
never edits ordinary source files. Explicit Version export is read-only.
Pending work, changed source observations, corrupt or missing required history,
unsupported transfers/migrations, and unsafe paths refuse rather than silently
recovering or dropping history. No command provides isolation from unrelated
processes writing live files. Stop writers when taking a coherent application
backup; a live SQLite file needs SQLite's own consistent-backup procedure.

Every staged file and required directory is flushed before no-clobber
publication. An interrupted export can leave an unadvertised sibling staging
directory; it never reports that partial staging as a finished package. Restore
uses an operation-bound stage and supports exact retry at its durable barriers.
Process interruption tests do not establish a power-loss guarantee on every
filesystem or storage device.

## Wire results

`export list` returns `format: "folderbase-export-version-list-v1"`,
`folderbase_id`, and `versions` entries with `version_id`, `canonical_sha256`,
`created_at`, `visible_entries`, and `retained_tombstones`.

`export create` returns `format: "folderbase-local-export-v1"`,
`export_index_sha256`, `retention_profile: "selected-snapshot-file-history-v1"`,
`selection` (`current_workspace` or `retained_version`), `folderbase_id`,
`folderbase_version_id`, `retained_objects`, `retained_file_versions`,
`capture_exclusions`, `snapshot_only_reserved_paths`, `omitted_objects`, and
`retired_objects`. The counts and inventories describe actual package retention.

`export restore` accepts only `operation_id` and `export_index_sha256` in one
JSON object, at most 65,536 bytes. It returns `{ "replayed": false, "export": ... }`
with the same export inventory. Successful JSON goes to stdout with empty
stderr and exit 0; an operational refusal uses the CLI error object on stderr,
empty stdout and exit 2. No success document is emitted after a failed write.

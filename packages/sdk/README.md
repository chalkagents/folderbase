# `@folderbase/sdk`

Zero-runtime-dependency TypeScript types and Node.js process adapters for the
public Folderbase Core executable. The SDK supervises CLI JSON and daemon stdio;
it does not read engine-owned `.folderbase` records or implement a second Core.

## Install

Install the SDK and provide any conforming Folderbase executable. The official
npm launcher is the shortest Node path:

```sh
npm install @folderbase/sdk @folderbase/cli
```

```js
import { FolderbaseClient } from "@folderbase/sdk";

const folderbase = new FolderbaseClient();
const contract = await folderbase.contract();
if (contract.kind !== "success") throw new Error("contract needs attention");

const query = await folderbase.query("/absolute/workspace", {
  format: "folderbase-query-request-v1",
  scope: { kind: "live" },
  filters: {},
  page: { limit: 100 },
});
console.log(query.document.entries);
```

`executable` and `argumentsPrefix` support an explicit binary, `npx`, a
container command, or another conforming implementation without invoking a
shell:

```js
const folderbase = new FolderbaseClient({
  executable: "/absolute/path/to/folderbase",
  timeoutMs: 30_000,
});
```

## Exit behavior

- exit `0` resolves with `kind: "success"`;
- exit `1` resolves with `kind: "attention"` and preserves the full document;
- exit `2` throws `FolderbaseOperationalError` with the parsed stderr document;
- malformed/noisy output, overflow, timeout, spawn failure, and cancellation
  use distinct exported error classes.

Success and attention stderr must be empty. Any valid JSON value is returned
whole (including history arrays), so compatible unknown additive fields remain
available to callers. Daemon envelopes and operational errors remain objects.

## Daemon sessions

```js
const session = await folderbase.startDaemon("/absolute/workspace");
session.on("event", (hint) => {
  // A hint requests another authoritative query. It is never a file patch.
  console.log(hint.event);
});

await session.request("subscribe");
const response = await session.request("query", queryDocument);
await session.shutdown();
```

Daemon 0.1 is serial. Aborting an active request terminates that session because
the capability does not claim cooperative mid-request cancellation.

## Exact folder-scope evidence

```js
const observed = await folderbase.observeFolderScope(
  "/absolute/workspace",
  "Client Work",
);
console.log(observed.document.event_id);
```

The adapter invokes
`folderbase folder-scope observe ROOT SELECTED_PATH --json`, validates the
known `folderbase-folder-scope-evidence-v1` fields, preserves additive result
fields, and preserves typed Core errors. It never reads `.folderbase` state or
derives continuity from a path, inode, Git remote, or Cloud identifier. This
operation may advance Core's private device-local journal, so daemon 0.1
deliberately does not proxy it.

The closed v0.1 result carries at most 256 nested boundaries. Core reports
`folder_scope_limit_exceeded` before publication when a selected topology is
larger; the SDK preserves that typed error and all future additive fields.

## Root reconstruction

The explicit reconstruction adapter uses the same universal CLI JSON surface
as independent implementations:

```js
const outcome = await folderbase.reconstruct(
  "/absolute/reconstruction-package",
  "/absolute/new-folderbase",
  {
    format: "folderbase-root-reconstruction-request-v1",
    operation_id: "reconstruction_019f0000-0000-7000-8000-000000000001",
    package_index_sha256: "0123456789abcdef".repeat(4),
  },
);
```

The adapter requires explicit absolute source and destination paths and invokes
`folderbase reconstruct SOURCE DESTINATION --stdin --json`. It bounds and
validates the closed request before spawning, then validates the complete
stable result or attention document. Typed operational
errors remain available through `FolderbaseOperationalError`; malformed,
unbounded, open, or request-mismatched reconstruction documents fail closed as
`FolderbaseMalformedOutputError`. The adapter computes the normative request
SHA-256 locally and correlates every returned request digest, including an
optional digest in operational errors. Success must also attest the resolved
destination requested by the caller. The SDK delegates reconstruction
authority and filesystem mutation entirely to the selected conforming
executable.

## Authority boundary

Every root and staging path is an explicit argument. Capability discovery,
portable schemas, CLI JSON, and daemon JSON Lines are the only integration
authority. Managed Cloud storage, permissions, sync, and remote agent VMs are
separate product layers.

### Read-only per-file history (experimental)

With `folderbase.file-history@0.1.0`, read complete stored Version metadata without
capturing the current file or running recovery:

```js
const history = await folderbase.fileHistory("/absolute/workspace", "tasks/task.json");
if (history.kind === "success") {
  console.log(history.document.current_version, history.document.versions);
}
```

Requires an existing regular file in an initialized root. An untracked file returns
null IDs and an empty array. The recorded head may differ from live bytes; stored
Version order is not timestamp order. Binary files are supported. The reader
refuses pending work, changed observations, corrupt or oversized metadata, and
**all roots with nonempty migration metadata**, including completed migrations
(`file_history_migration_state_unsupported`). That last refusal is not a recovery
instruction. See [the capability contract](../../docs/file-history-0.1.md) for
exact bounds, read-only guarantees and error codes. Existing `version history`
continues to describe the whole-root journal, not a complete per-file list.


## Local export and restore (unreleased)

The candidate-only experimental `folderbase.local-export@0.1.0` capability adds
`exportVersions(root)`, `exportWorkspace(root, packagePath, {versionId?})`, and
`restoreWorkspace(packagePath, destination, {operation_id, export_index_sha256})`.
Use `contract()` to discover support; public Core 0.7.2 lacks these commands.
See [the retention contract and complete example](../../docs/local-export-0.1.md).
Packages preserve the selected folder snapshot and retained ordinary-file
histories; Git metadata is snapshot-only. Restore requires an absent destination
or the same unchanged, exactly replayable reconstruction.

## Create one absent file (experimental)

Discover `folderbase.workspace-create@0.1.0` before use. Persist an exact request
UUID, path and original content before the first attempt:

```js
const request = { operationId: crypto.randomUUID(), content: '{"title":"First"}' };
const created = await client.workspaceCreate(root, "tasks/new.json", request);
```

Content is a well-formed UTF-8 string or `Uint8Array`, at most 8 MiB; the existing
safe parent must exist. A completed retry returns the original historical result
with `replayed: true` and never recreates a later deletion. Read current content
before displaying it. Another request under that UUID or any occupied target
conflicts, even with matching bytes. Attachments followed by a separate task save
can leave an unlinked attachment; applications own explicit retry/link handling.
Use a single checked Core build for all writers: older executables do not honor
pending creation. See [the operation contract](https://github.com/chalkagents/folderbase/blob/main/docs/workspace-create-0.1.md)
for bounds, recovery, and compatibility limits.

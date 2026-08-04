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
  source: "live",
  filters: {},
  order: [{ field: "path", direction: "ascending" }],
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

## Authority boundary

Every root and staging path is an explicit argument. Capability discovery,
portable schemas, CLI JSON, and daemon JSON Lines are the only integration
authority. Managed Cloud storage, permissions, sync, and remote agent VMs are
separate product layers.

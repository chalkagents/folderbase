import {
  FolderbaseClient,
  FolderbaseOperationalError,
  type FolderbaseDaemonEvent,
  type FolderbaseResult,
  type JsonObject,
  type JsonValue,
} from "../src/index.js";

const client = new FolderbaseClient({
  executable: "/absolute/path/to/folderbase",
  maxInputBytes: 8 * 1024 * 1024,
  maxOutputBytes: 8 * 1024 * 1024,
});

const queryDocument: JsonObject = {
  format: "folderbase-query-request-v1",
  source: "live",
};

async function useClient(): Promise<void> {
  const result: FolderbaseResult = await client.query(
    "/absolute/workspace",
    queryDocument,
    { signal: new AbortController().signal },
  );
  if (result.kind === "success") {
    const exactExit: 0 = result.exitCode;
    void exactExit;
  } else {
    const exactExit: 1 = result.exitCode;
    void exactExit;
  }

  const history = await client.run<Array<{ action: string }>>([
    "version",
    "history",
    "/absolute/workspace",
    "--json",
  ]);
  const value: JsonValue = history.document;
  void value;

  const daemon = await client.startDaemon("/absolute/workspace");
  daemon.on("event", (event: FolderbaseDaemonEvent) => {
    const sequence: number = event.sequence;
    void sequence;
  });
  await daemon.request("query", queryDocument);
  await daemon.request("subscribe");
  await daemon.shutdown();
}

try {
  await useClient();
} catch (error) {
  if (error instanceof FolderbaseOperationalError) {
    const code: string = error.code;
    const document: JsonObject = error.document;
    void code;
    void document;
  }
}

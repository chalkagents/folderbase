import {
  FolderbaseClient,
  FolderbaseOperationalError,
  type FolderbaseDaemonEvent,
  type FolderbaseResult,
  type FolderbaseRootReconstructionAttention,
  type FolderbaseRootReconstructionError,
  type FolderbaseRootReconstructionRequest,
  type FolderbaseRootReconstructionResult,
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
  const reconstructionRequest: FolderbaseRootReconstructionRequest = {
    format: "folderbase-root-reconstruction-request-v1",
    operation_id: "reconstruction_019f0000-0000-7000-8000-000000000001",
    package_index_sha256: "a".repeat(64),
  };
  const reconstructed: FolderbaseResult<
    FolderbaseRootReconstructionResult,
    FolderbaseRootReconstructionAttention
  > = await client.reconstruct(
    "/absolute/package",
    "/absolute/reconstructed",
    reconstructionRequest,
  );
  const reconstructionDocument:
    | FolderbaseRootReconstructionResult
    | FolderbaseRootReconstructionAttention = reconstructed.document;
  void reconstructionDocument;
  const typedError: FolderbaseRootReconstructionError = {
    format: "folderbase-root-reconstruction-error-v1",
    operation_id: reconstructionRequest.operation_id,
    request_sha256: "b".repeat(64),
    package_index_sha256: reconstructionRequest.package_index_sha256,
    error: { code: "reconstruction_failed", message: "failed safely" },
  };
  void typedError;

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

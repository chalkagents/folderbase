import {
  FolderbaseClient,
  FolderbaseOperationalError,
  type FolderbaseDaemonEvent,
  type FolderbaseFolderScopeEvidence,
  type FolderbaseResult,
  type FolderbaseRootReconstructionAttention,
  type FolderbaseRootReconstructionError,
  type FolderbaseRootReconstructionRequest,
  type FolderbaseRootReconstructionResult,
  type FolderbaseSuccess,
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
  const observed: FolderbaseSuccess<FolderbaseFolderScopeEvidence> =
    await client.observeFolderScope("/absolute/workspace", "Client Work");
  const observedPath: string = observed.document.selected_path;
  void observedPath;

  const listing = await client.workspaceList("/absolute/workspace");
  if (listing.kind === "success") {
    const editable: boolean | undefined = listing.document.entries[0]?.editable;
    void editable;
  }
  const read = await client.workspaceRead("/absolute/workspace", "notes.md");
  if (read.kind === "success") {
    const content: string = read.document.content;
    const saved = await client.workspaceSave("/absolute/workspace", "notes.md", {
      expectedSha256: read.document.sha256,
      content: `${content}\nUpdate`,
    });
    if (saved.kind === "success") {
      const hash: string = saved.document.document.sha256;
      const version: string = saved.document.version_id;
      // @ts-expect-error Save returns metadata; read again to obtain current text.
      const returnedText: string = saved.document.document.content;
      void [hash, version, returnedText];
    }
  }
  // @ts-expect-error A save requires the content hash from a prior read.
  await client.workspaceSave("/absolute/workspace", "notes.md", { content: "draft" });
  // @ts-expect-error This command saves UTF-8 text, not binary attachments.
  await client.workspaceSave("/absolute/workspace", "notes.md", { expectedSha256: "a".repeat(64), content: new Uint8Array() });

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


const fileHistory = await client.fileHistory("/workspace", "tasks/a.json");
if (fileHistory.kind === "success") {
  const recordedVersion: string | null = fileHistory.document.current_version;
  const capturedAt: string | undefined = fileHistory.document.versions[0]?.captured_at;
  void [recordedVersion, capturedAt];
}


const created = await client.workspaceCreate("/workspace", "tasks/new.json", {
  operationId: "019f0000-0000-7000-8000-000000000001", content: new Uint8Array([0,255]),
});
if (created.kind === "success") {
  const objectId: string = created.document.object_id;
  const replayed: boolean = created.document.replayed;
  const digest: string = created.document.content.digest;
  void [objectId, replayed, digest];
}

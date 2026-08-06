export type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | JsonObject | JsonValue[];
export type JsonObject = { [key: string]: JsonValue };

export interface AbortSignalLike {
  readonly aborted: boolean;
  addEventListener(
    type: "abort",
    listener: () => void,
    options?: { once?: boolean },
  ): void;
  removeEventListener(type: "abort", listener: () => void): void;
}

export interface FolderbaseClientOptions {
  executable?: string;
  argumentsPrefix?: readonly string[];
  cwd?: string;
  env?: Readonly<Record<string, string | undefined>>;
  maxInputBytes?: number;
  maxOutputBytes?: number;
  timeoutMs?: number;
}

export interface FolderbaseRunOptions {
  stdin?: string | Uint8Array;
  signal?: AbortSignalLike;
  timeoutMs?: number;
}

export interface FolderbaseSuccess<T extends JsonValue = JsonValue> {
  kind: "success";
  exitCode: 0;
  document: T;
}

export interface FolderbaseAttention<T extends JsonValue = JsonValue> {
  kind: "attention";
  exitCode: 1;
  document: T;
}

export type FolderbaseResult<
  TSuccess extends JsonValue = JsonValue,
  TAttention extends JsonValue = JsonValue,
> = FolderbaseSuccess<TSuccess> | FolderbaseAttention<TAttention>;

export class FolderbaseSdkError extends Error {
  readonly code: string;
}

export class FolderbaseOperationalError<
  T extends JsonObject = JsonObject,
> extends FolderbaseSdkError {
  readonly exitCode: number;
  readonly document: T;
  readonly stderr: string;
}

export class FolderbaseMalformedOutputError extends FolderbaseSdkError {
  readonly exitCode?: number | null;
  readonly stdout: string;
  readonly stderr: string;
}

export class FolderbaseOutputLimitError extends FolderbaseSdkError {
  readonly stream: string;
  readonly limit: number;
}

export class FolderbaseCancelledError extends FolderbaseSdkError {}

export class FolderbaseTimeoutError extends FolderbaseSdkError {
  readonly timeoutMs: number;
}

export class FolderbaseSpawnError extends FolderbaseSdkError {}

export class FolderbaseUnexpectedExitError extends FolderbaseSdkError {
  readonly exitCode?: number | null;
  readonly signal?: string | null;
  readonly stdout: string;
  readonly stderr: string;
}

export interface FolderbaseInitOptions {
  dryRun?: boolean;
  name?: string;
  kind?: "person" | "organization" | "engagement" | "project" | "customer" | "temporary" | "custom";
  agentAdapters?: boolean;
  template?: string;
  answers?: readonly string[];
  expectedPlanDigest?: string;
}

export interface FolderbaseValidateOptions {
  level?: "shallow" | "content";
}

export interface FolderbaseRootReconstructionRequest extends JsonObject {
  format: "folderbase-root-reconstruction-request-v1";
  operation_id: string;
  package_index_sha256: string;
}

export interface FolderbaseRootAttestation extends JsonObject {
  root: string;
  folderbase_id: string;
  protocol_version: string;
  manifest_sha256: string;
  root_instance_sha256: string;
}

export interface FolderbaseRootReconstructionResult extends JsonObject {
  format: "folderbase-root-reconstruction-result-v1";
  operation_id: string;
  request_sha256: string;
  folderbase_id: string;
  folderbase_version_id: string;
  canonical_version_sha256: string;
  package_index_sha256: string;
  verified_object_count: number;
  version_authenticated_object_count: number;
  retained_tombstone_object_count: number;
  visible_entry_count: number;
  verified_opaque_bytes: number;
  root_attestation: FolderbaseRootAttestation;
  replayed: boolean;
}

export type FolderbaseRootReconstructionAttentionCode =
  | "destination_occupied"
  | "reconstruction_in_progress";

export interface FolderbaseRootReconstructionAttentionDetail extends JsonObject {
  code: FolderbaseRootReconstructionAttentionCode;
  message: string;
  retryable: boolean;
}

export interface FolderbaseRootReconstructionAttention extends JsonObject {
  format: "folderbase-root-reconstruction-attention-v1";
  operation_id: string;
  request_sha256: string;
  package_index_sha256: string;
  attention: FolderbaseRootReconstructionAttentionDetail;
}

export type FolderbaseRootReconstructionErrorCode =
  | "invalid_invocation"
  | "invalid_request"
  | "invalid_package"
  | "package_index_mismatch"
  | "package_changed"
  | "invalid_folderbase_version"
  | "folderbase_mismatch"
  | "version_mismatch"
  | "reference_closure_invalid"
  | "manifest_invalid"
  | "chunk_invalid"
  | "object_verification_failed"
  | "unsafe_package"
  | "unsafe_destination"
  | "operation_id_conflict"
  | "unsupported_reconstruction_filesystem"
  | "reconstruction_failed"
  | "output_failed";

export interface FolderbaseRootReconstructionErrorDetail extends JsonObject {
  code: FolderbaseRootReconstructionErrorCode;
  message: string;
}

export interface FolderbaseRootReconstructionError extends JsonObject {
  format: "folderbase-root-reconstruction-error-v1";
  operation_id?: string;
  request_sha256?: string;
  package_index_sha256?: string;
  error: FolderbaseRootReconstructionErrorDetail;
}

export interface FolderbaseDaemonReady extends JsonObject {
  format: "folderbase-daemon-message-v1";
  kind: "ready";
  capability: "folderbase.daemon-stdio@0.1.0";
  epoch: string;
  folderbase_id: string;
  root_instance_sha256: string;
  root: string;
}

export interface FolderbaseDaemonResponse<
  T extends JsonObject = JsonObject,
> extends JsonObject {
  format: "folderbase-daemon-message-v1";
  kind: "response";
  request_id: string;
  operation: FolderbaseDaemonOperation;
  status: "ok" | "attention" | "error";
  document: T;
}

export interface FolderbaseDaemonEvent extends JsonObject {
  format: "folderbase-daemon-message-v1";
  kind: "event";
  event: "workspace_changed" | "rescan_required";
  epoch: string;
  sequence: number;
}

export type FolderbaseDaemonOperation =
  | "query"
  | "explain"
  | "index_status"
  | "refresh"
  | "subscribe"
  | "unsubscribe"
  | "shutdown";

export interface FolderbaseDaemonOptions {
  signal?: AbortSignalLike;
  timeoutMs?: number;
}

export class FolderbaseDaemonSession {
  readonly ready: FolderbaseDaemonReady;
  readonly closed: Promise<{ exitCode: number | null; signal: string | null }>;

  on(event: "event", listener: (event: FolderbaseDaemonEvent) => void): this;
  once(event: "event", listener: (event: FolderbaseDaemonEvent) => void): this;
  off(event: "event", listener: (event: FolderbaseDaemonEvent) => void): this;

  request<T extends JsonObject = JsonObject>(
    operation: "query" | "explain",
    document: JsonObject,
    options?: FolderbaseDaemonOptions,
  ): Promise<FolderbaseDaemonResponse<T>>;
  request<T extends JsonObject = JsonObject>(
    operation: Exclude<FolderbaseDaemonOperation, "query" | "explain">,
    document?: undefined,
    options?: FolderbaseDaemonOptions,
  ): Promise<FolderbaseDaemonResponse<T>>;
  shutdown<T extends JsonObject = JsonObject>(
    options?: FolderbaseDaemonOptions,
  ): Promise<FolderbaseDaemonResponse<T>>;
  stop(): Promise<{ exitCode: number | null; signal: string | null }>;
}

export class FolderbaseClient {
  constructor(options?: FolderbaseClientOptions);

  run<TSuccess extends JsonValue = JsonValue, TAttention extends JsonValue = JsonValue>(
    arguments_: readonly string[],
    options?: FolderbaseRunOptions,
  ): Promise<FolderbaseResult<TSuccess, TAttention>>;

  contract<T extends JsonValue = JsonObject>(options?: FolderbaseRunOptions): Promise<FolderbaseResult<T>>;
  inspect<T extends JsonValue = JsonObject>(root: string, options?: FolderbaseRunOptions): Promise<FolderbaseResult<T>>;
  attest<T extends JsonValue = JsonObject>(root: string, options?: FolderbaseRunOptions): Promise<FolderbaseResult<T>>;
  init<T extends JsonValue = JsonObject>(root: string, initOptions?: FolderbaseInitOptions, options?: FolderbaseRunOptions): Promise<FolderbaseResult<T>>;
  validate<T extends JsonValue = JsonObject>(root: string, validateOptions?: FolderbaseValidateOptions, options?: FolderbaseRunOptions): Promise<FolderbaseResult<T>>;
  query<T extends JsonValue = JsonObject>(root: string, document: JsonObject, options?: FolderbaseRunOptions): Promise<FolderbaseResult<T>>;
  explain<T extends JsonValue = JsonObject>(root: string, document: JsonObject, options?: FolderbaseRunOptions): Promise<FolderbaseResult<T>>;
  indexStatus<T extends JsonValue = JsonObject>(root: string, options?: FolderbaseRunOptions): Promise<FolderbaseResult<T>>;
  indexRebuild<T extends JsonValue = JsonObject>(root: string, options?: FolderbaseRunOptions): Promise<FolderbaseResult<T>>;
  templatePlan<T extends JsonValue = JsonObject>(root: string, document: JsonObject, options?: FolderbaseRunOptions): Promise<FolderbaseResult<T>>;
  templateApply<T extends JsonValue = JsonObject>(root: string, expectedPlanDigest: string, document: JsonObject, options?: FolderbaseRunOptions): Promise<FolderbaseResult<T>>;
  changeSetCheckout<T extends JsonValue = JsonObject>(root: string, destination: string, document: JsonObject, options?: FolderbaseRunOptions): Promise<FolderbaseResult<T>>;
  changeSetPropose<T extends JsonValue = JsonObject>(checkout: string, staging: string, options?: FolderbaseRunOptions): Promise<FolderbaseResult<T>>;
  changeSetAssess<T extends JsonValue = JsonObject>(root: string, staging: string, document: JsonObject, options?: FolderbaseRunOptions): Promise<FolderbaseResult<T>>;
  changeSetApply<T extends JsonValue = JsonObject>(root: string, staging: string, document: JsonObject, options?: FolderbaseRunOptions): Promise<FolderbaseResult<T>>;
  reconstruct(
    source: string,
    destination: string,
    request: FolderbaseRootReconstructionRequest,
    options?: FolderbaseRunOptions,
  ): Promise<FolderbaseResult<
    FolderbaseRootReconstructionResult,
    FolderbaseRootReconstructionAttention
  >>;
  startDaemon(root: string, options?: FolderbaseDaemonOptions): Promise<FolderbaseDaemonSession>;
}

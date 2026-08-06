import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { EventEmitter } from "node:events";
import { isAbsolute, resolve } from "node:path";

const DEFAULT_INPUT_BYTES = 8 * 1024 * 1024;
const DEFAULT_OUTPUT_BYTES = 8 * 1024 * 1024;
const HARD_MAX_BYTES = 64 * 1024 * 1024;
const DEFAULT_TIMEOUT_MS = 30_000;
const MAX_TIMEOUT_MS = 10 * 60_000;
const DAEMON_REQUEST_FORMAT = "folderbase-daemon-request-v1";
const DAEMON_MESSAGE_FORMAT = "folderbase-daemon-message-v1";
const DAEMON_CAPABILITY = "folderbase.daemon-stdio@0.1.0";
const SHA256_PATTERN = /^[0-9a-f]{64}$/u;
const FOLDERBASE_ID_PATTERN = /^folderbase_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const FOLDERBASE_VERSION_ID_PATTERN = /^fbversion_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const RECONSTRUCTION_OPERATION_ID_PATTERN = /^reconstruction_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const LEGACY_MANIFEST_PROTOCOL_PATTERN = /^0\.(?:1|2)\.(?:0|[1-9][0-9]*)(?:-(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/u;
const RECONSTRUCTION_ATTENTION_CODES = new Set([
  "destination_occupied",
  "reconstruction_in_progress",
]);
const RECONSTRUCTION_ERROR_CODES = new Set([
  "invalid_invocation",
  "invalid_request",
  "invalid_package",
  "package_index_mismatch",
  "package_changed",
  "invalid_folderbase_version",
  "folderbase_mismatch",
  "version_mismatch",
  "reference_closure_invalid",
  "manifest_invalid",
  "chunk_invalid",
  "object_verification_failed",
  "unsafe_package",
  "unsafe_destination",
  "operation_id_conflict",
  "unsupported_reconstruction_filesystem",
  "reconstruction_failed",
  "output_failed",
]);
const DAEMON_OPERATIONS = new Set([
  "query",
  "explain",
  "index_status",
  "refresh",
  "subscribe",
  "unsubscribe",
  "shutdown",
]);

export class FolderbaseSdkError extends Error {
  constructor(message, code, options = {}) {
    super(message, options);
    this.name = new.target.name;
    this.code = code;
  }
}

export class FolderbaseOperationalError extends FolderbaseSdkError {
  constructor(message, { exitCode = 2, document, stderr = "", cause } = {}) {
    super(message, "folderbase_operational_error", { cause });
    this.exitCode = exitCode;
    this.document = document;
    this.stderr = stderr;
  }
}

export class FolderbaseMalformedOutputError extends FolderbaseSdkError {
  constructor(message, { exitCode, stdout = "", stderr = "", cause } = {}) {
    super(message, "folderbase_malformed_output", { cause });
    this.exitCode = exitCode;
    this.stdout = stdout;
    this.stderr = stderr;
  }
}

export class FolderbaseOutputLimitError extends FolderbaseSdkError {
  constructor(stream, limit) {
    super(
      `Folderbase ${stream} exceeded the ${limit} byte adapter limit`,
      "folderbase_output_limit",
    );
    this.stream = stream;
    this.limit = limit;
  }
}

export class FolderbaseCancelledError extends FolderbaseSdkError {
  constructor(message = "Folderbase operation was cancelled") {
    super(message, "folderbase_cancelled");
  }
}

export class FolderbaseTimeoutError extends FolderbaseSdkError {
  constructor(timeoutMs) {
    super(
      `Folderbase operation exceeded ${timeoutMs} ms`,
      "folderbase_timeout",
    );
    this.timeoutMs = timeoutMs;
  }
}

export class FolderbaseSpawnError extends FolderbaseSdkError {
  constructor(message, cause) {
    super(message, "folderbase_spawn_failed", { cause });
  }
}

export class FolderbaseUnexpectedExitError extends FolderbaseSdkError {
  constructor(message, { exitCode, signal, stdout = "", stderr = "" } = {}) {
    super(message, "folderbase_unexpected_exit");
    this.exitCode = exitCode;
    this.signal = signal;
    this.stdout = stdout;
    this.stderr = stderr;
  }
}

function requireByteLimit(value, name, fallback) {
  const selected = value ?? fallback;
  if (!Number.isSafeInteger(selected) || selected < 1 || selected > HARD_MAX_BYTES) {
    throw new TypeError(`${name} must be an integer between 1 and ${HARD_MAX_BYTES}`);
  }
  return selected;
}

function requireTimeout(value, fallback = DEFAULT_TIMEOUT_MS) {
  const selected = value ?? fallback;
  if (!Number.isSafeInteger(selected) || selected < 1 || selected > MAX_TIMEOUT_MS) {
    throw new TypeError(`timeoutMs must be an integer between 1 and ${MAX_TIMEOUT_MS}`);
  }
  return selected;
}

function requireStringArray(value, name) {
  if (!Array.isArray(value) || value.some((entry) => typeof entry !== "string")) {
    throw new TypeError(`${name} must be an array of strings`);
  }
  return [...value];
}

function requireJsonObject(value, name = "document") {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError(`${name} must be a JSON object`);
  }
  return value;
}

function encodeInput(input, limit) {
  let bytes;
  if (input === undefined) {
    bytes = Buffer.alloc(0);
  } else if (typeof input === "string") {
    bytes = Buffer.from(input, "utf8");
  } else if (input instanceof Uint8Array) {
    bytes = Buffer.from(input.buffer, input.byteOffset, input.byteLength);
  } else {
    throw new TypeError("stdin must be a string or Uint8Array");
  }
  if (bytes.length > limit) {
    throw new FolderbaseOutputLimitError("stdin", limit);
  }
  return bytes;
}

function encodeJsonLine(document, limit) {
  requireJsonObject(document);
  let encoded;
  try {
    encoded = `${JSON.stringify(document)}\n`;
  } catch (error) {
    throw new TypeError(`document must be JSON serializable: ${error.message}`);
  }
  return encodeInput(encoded, limit);
}

function parseJson(bytes, context, details = {}) {
  let text;
  try {
    text = Buffer.isBuffer(bytes)
      ? new TextDecoder("utf-8", { fatal: true }).decode(bytes)
      : String(bytes);
  } catch (error) {
    throw new FolderbaseMalformedOutputError(
      `${context} was not valid UTF-8`,
      { ...details, cause: error },
    );
  }
  let document;
  try {
    document = JSON.parse(text);
  } catch (error) {
    throw new FolderbaseMalformedOutputError(
      `${context} was not one JSON document`,
      { ...details, cause: error },
    );
  }
  return document;
}

function parseObject(bytes, context, details = {}) {
  const document = parseJson(bytes, context, details);
  if (document === null || typeof document !== "object" || Array.isArray(document)) {
    throw new FolderbaseMalformedOutputError(
      `${context} must be a JSON object`,
      details,
    );
  }
  return document;
}

function hasExactKeys(document, keys) {
  const actual = Object.keys(document).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length
    && actual.every((key, index) => key === expected[index]);
}

function hasClosedKeys(document, required, optional = []) {
  const actual = Object.keys(document);
  const allowed = new Set([...required, ...optional]);
  return required.every((key) => Object.hasOwn(document, key))
    && actual.every((key) => allowed.has(key));
}

function isBoundedString(value, maximum = 4_096) {
  return typeof value === "string"
    && value.length > 0
    && [...value].length <= maximum;
}

function isBoundedInteger(value, minimum, maximum) {
  return Number.isSafeInteger(value) && value >= minimum && value <= maximum;
}

function requireReconstructionPath(value, name) {
  if (!isBoundedString(value) || value.includes("\u0000") || !isAbsolute(value)) {
    throw new TypeError(`${name} must be an absolute path no longer than 4096 characters`);
  }
  return value;
}

function validateRootReconstructionRequest(document) {
  requireJsonObject(document, "request");
  if (!hasExactKeys(document, ["format", "operation_id", "package_index_sha256"])
    || document.format !== "folderbase-root-reconstruction-request-v1"
    || !RECONSTRUCTION_OPERATION_ID_PATTERN.test(document.operation_id)
    || !SHA256_PATTERN.test(document.package_index_sha256)) {
    throw new TypeError("request must be one closed Folderbase root-reconstruction request");
  }
  return document;
}

function rootReconstructionRequestSha256(request) {
  const operationId = Buffer.from(request.operation_id, "utf8");
  const operationIdLength = Buffer.alloc(4);
  operationIdLength.writeUInt32BE(operationId.length);
  return createHash("sha256")
    .update(Buffer.from("folderbase-root-reconstruction-request-v1\0", "ascii"))
    .update(operationIdLength)
    .update(operationId)
    .update(Buffer.from(request.package_index_sha256, "hex"))
    .digest("hex");
}

function malformedReconstruction(message, details = {}) {
  throw new FolderbaseMalformedOutputError(
    `Folderbase root reconstruction ${message}`,
    details,
  );
}

function validateRootAttestation(document) {
  if (document === null || typeof document !== "object" || Array.isArray(document)
    || !hasExactKeys(document, [
      "root",
      "folderbase_id",
      "protocol_version",
      "manifest_sha256",
      "root_instance_sha256",
    ])
    || !isBoundedString(document.root)
    || !FOLDERBASE_ID_PATTERN.test(document.folderbase_id)
    || !(document.protocol_version === "0.5.0"
      || (typeof document.protocol_version === "string"
        && LEGACY_MANIFEST_PROTOCOL_PATTERN.test(document.protocol_version)))
    || !SHA256_PATTERN.test(document.manifest_sha256)
    || !SHA256_PATTERN.test(document.root_instance_sha256)) {
    malformedReconstruction("emitted an invalid root attestation");
  }
}

function validateRootReconstructionResult(
  document,
  request,
  requestSha256,
  resolvedDestination,
) {
  if (document === null || typeof document !== "object" || Array.isArray(document)
    || !hasExactKeys(document, [
      "format",
      "operation_id",
      "request_sha256",
      "folderbase_id",
      "folderbase_version_id",
      "canonical_version_sha256",
      "package_index_sha256",
      "verified_object_count",
      "version_authenticated_object_count",
      "retained_tombstone_object_count",
      "visible_entry_count",
      "verified_opaque_bytes",
      "root_attestation",
      "replayed",
    ])
    || document.format !== "folderbase-root-reconstruction-result-v1"
    || document.operation_id !== request.operation_id
    || document.request_sha256 !== requestSha256
    || !FOLDERBASE_ID_PATTERN.test(document.folderbase_id)
    || !FOLDERBASE_VERSION_ID_PATTERN.test(document.folderbase_version_id)
    || !SHA256_PATTERN.test(document.canonical_version_sha256)
    || document.package_index_sha256 !== request.package_index_sha256
    || !isBoundedInteger(document.verified_object_count, 1, 16_385)
    || !isBoundedInteger(document.version_authenticated_object_count, 1, 16_385)
    || !isBoundedInteger(document.retained_tombstone_object_count, 0, 16_384)
    || !isBoundedInteger(document.visible_entry_count, 0, 16_384)
    || !isBoundedInteger(document.verified_opaque_bytes, 1, Number.MAX_SAFE_INTEGER)
    || typeof document.replayed !== "boolean") {
    malformedReconstruction("emitted an invalid result");
  }
  validateRootAttestation(document.root_attestation);
  if (document.root_attestation.folderbase_id !== document.folderbase_id) {
    malformedReconstruction("result and root attestation name different Folderbases");
  }
  if (resolve(document.root_attestation.root) !== resolvedDestination) {
    malformedReconstruction("result attests a different destination root");
  }
  return document;
}

function validateRootReconstructionAttention(document, request, requestSha256) {
  if (document === null || typeof document !== "object" || Array.isArray(document)
    || !hasExactKeys(document, [
      "format",
      "operation_id",
      "request_sha256",
      "package_index_sha256",
      "attention",
    ])
    || document.format !== "folderbase-root-reconstruction-attention-v1"
    || document.operation_id !== request.operation_id
    || document.request_sha256 !== requestSha256
    || document.package_index_sha256 !== request.package_index_sha256
    || document.attention === null
    || typeof document.attention !== "object"
    || Array.isArray(document.attention)
    || !hasExactKeys(document.attention, ["code", "message", "retryable"])
    || !RECONSTRUCTION_ATTENTION_CODES.has(document.attention.code)
    || !isBoundedString(document.attention.message)
    || typeof document.attention.retryable !== "boolean") {
    malformedReconstruction("emitted invalid attention");
  }
  return document;
}

function validateRootReconstructionError(document, request, requestSha256, details) {
  if (document === null || typeof document !== "object" || Array.isArray(document)
    || !hasClosedKeys(
      document,
      ["format", "error"],
      ["operation_id", "request_sha256", "package_index_sha256"],
    )
    || document.format !== "folderbase-root-reconstruction-error-v1"
    || (document.operation_id !== undefined
      && (!RECONSTRUCTION_OPERATION_ID_PATTERN.test(document.operation_id)
        || document.operation_id !== request.operation_id))
    || (document.request_sha256 !== undefined
      && document.request_sha256 !== requestSha256)
    || (document.package_index_sha256 !== undefined
      && (document.package_index_sha256 !== request.package_index_sha256))
    || document.error === null
    || typeof document.error !== "object"
    || Array.isArray(document.error)
    || !hasExactKeys(document.error, ["code", "message"])
    || !RECONSTRUCTION_ERROR_CODES.has(document.error.code)
    || !isBoundedString(document.error.message)) {
    malformedReconstruction("emitted an invalid error", details);
  }
  return document;
}

function appendBounded(chunks, chunk, total, limit, stream) {
  const next = total + chunk.length;
  if (next > limit) throw new FolderbaseOutputLimitError(stream, limit);
  chunks.push(chunk);
  return next;
}

function terminateProcessTree(child) {
  if (!child || child.exitCode !== null || child.signalCode !== null) return;
  if (process.platform === "win32") {
    const killer = spawn("taskkill", ["/pid", String(child.pid), "/T", "/F"], {
      stdio: "ignore",
      windowsHide: true,
    });
    killer.on("error", () => child.kill());
    killer.unref();
    return;
  }
  try {
    process.kill(-child.pid, "SIGTERM");
  } catch {
    child.kill("SIGTERM");
  }
  const force = setTimeout(() => {
    if (child.exitCode !== null || child.signalCode !== null) return;
    try {
      process.kill(-child.pid, "SIGKILL");
    } catch {
      child.kill("SIGKILL");
    }
  }, 250);
  force.unref();
}

function spawnOptions(configuration) {
  return {
    cwd: configuration.cwd,
    env: configuration.env
      ? { ...process.env, ...configuration.env }
      : process.env,
    detached: process.platform !== "win32",
    stdio: ["pipe", "pipe", "pipe"],
    windowsHide: true,
  };
}

function runJsonProcess(configuration, arguments_, options = {}) {
  const args = [
    ...configuration.argumentsPrefix,
    ...requireStringArray(arguments_, "arguments"),
  ];
  const timeoutMs = requireTimeout(options.timeoutMs, configuration.timeoutMs);
  const input = encodeInput(options.stdin, configuration.maxInputBytes);
  const signal = options.signal;
  if (signal?.aborted) {
    return Promise.reject(new FolderbaseCancelledError());
  }

  return new Promise((resolve, reject) => {
    let child;
    try {
      child = spawn(configuration.executable, args, spawnOptions(configuration));
    } catch (error) {
      reject(new FolderbaseSpawnError(`Unable to start ${configuration.executable}`, error));
      return;
    }

    const stdout = [];
    const stderr = [];
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let terminalError;
    let settled = false;

    const finish = (operation) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      signal?.removeEventListener("abort", abort);
      operation();
    };
    const fail = (error) => {
      if (terminalError) return;
      terminalError = error;
      terminateProcessTree(child);
    };
    const abort = () => fail(new FolderbaseCancelledError());
    signal?.addEventListener("abort", abort, { once: true });
    const timeout = setTimeout(
      () => fail(new FolderbaseTimeoutError(timeoutMs)),
      timeoutMs,
    );
    timeout.unref();

    child.once("error", (error) => {
      finish(() => reject(new FolderbaseSpawnError(
        `Unable to start ${configuration.executable}`,
        error,
      )));
    });
    child.stdout.on("data", (chunk) => {
      if (terminalError) return;
      try {
        stdoutBytes = appendBounded(
          stdout,
          chunk,
          stdoutBytes,
          configuration.maxOutputBytes,
          "stdout",
        );
      } catch (error) {
        fail(error);
      }
    });
    child.stderr.on("data", (chunk) => {
      if (terminalError) return;
      try {
        stderrBytes = appendBounded(
          stderr,
          chunk,
          stderrBytes,
          configuration.maxOutputBytes,
          "stderr",
        );
      } catch (error) {
        fail(error);
      }
    });
    child.once("close", (exitCode, exitSignal) => {
      finish(() => {
        if (terminalError) {
          reject(terminalError);
          return;
        }
        const stdoutBuffer = Buffer.concat(stdout);
        const stderrBuffer = Buffer.concat(stderr);
        const stdoutText = stdoutBuffer.toString("utf8");
        const stderrText = stderrBuffer.toString("utf8");
        if (exitCode === 0 || exitCode === 1) {
          if (stderrBuffer.length !== 0) {
            reject(new FolderbaseMalformedOutputError(
              "Folderbase success or attention output wrote unexpected stderr",
              { exitCode, stdout: stdoutText, stderr: stderrText },
            ));
            return;
          }
          try {
            const document = parseJson(stdoutBuffer, "Folderbase stdout", {
              exitCode,
              stdout: stdoutText,
              stderr: stderrText,
            });
            resolve({
              kind: exitCode === 0 ? "success" : "attention",
              exitCode,
              document,
            });
          } catch (error) {
            reject(error);
          }
          return;
        }
        if (exitCode === 2 && stdoutBuffer.length === 0) {
          try {
            const document = parseObject(stderrBuffer, "Folderbase stderr", {
              exitCode,
              stdout: stdoutText,
              stderr: stderrText,
            });
            reject(new FolderbaseOperationalError(
              document.error?.message ?? "Folderbase operation failed",
              { exitCode, document, stderr: stderrText },
            ));
          } catch (error) {
            reject(error);
          }
          return;
        }
        reject(new FolderbaseUnexpectedExitError(
          `Folderbase exited unexpectedly with ${exitCode ?? exitSignal ?? "unknown status"}`,
          {
            exitCode,
            signal: exitSignal,
            stdout: stdoutText,
            stderr: stderrText,
          },
        ));
      });
    });
    child.stdin.on("error", (error) => {
      if (error.code !== "EPIPE") fail(new FolderbaseOperationalError(
        "Unable to write Folderbase stdin",
        { cause: error },
      ));
    });
    child.stdin.end(input);
  });
}

function configurationFrom(options = {}) {
  const executable = options.executable ?? "folderbase";
  if (typeof executable !== "string" || executable.length === 0) {
    throw new TypeError("executable must be a non-empty string");
  }
  return Object.freeze({
    executable,
    argumentsPrefix: requireStringArray(options.argumentsPrefix ?? [], "argumentsPrefix"),
    cwd: options.cwd,
    env: options.env ? { ...options.env } : undefined,
    maxInputBytes: requireByteLimit(
      options.maxInputBytes,
      "maxInputBytes",
      DEFAULT_INPUT_BYTES,
    ),
    maxOutputBytes: requireByteLimit(
      options.maxOutputBytes,
      "maxOutputBytes",
      DEFAULT_OUTPUT_BYTES,
    ),
    timeoutMs: requireTimeout(options.timeoutMs),
  });
}

export class FolderbaseClient {
  #configuration;

  constructor(options = {}) {
    this.#configuration = configurationFrom(options);
  }

  run(arguments_, options = {}) {
    return runJsonProcess(this.#configuration, arguments_, options);
  }

  #runJson(arguments_, document, options = {}) {
    return this.run(arguments_, {
      ...options,
      stdin: encodeJsonLine(document, this.#configuration.maxInputBytes),
    });
  }

  contract(options) {
    return this.run(["protocol", "contract", "--json"], options);
  }

  inspect(root, options) {
    return this.run(["inspect", root, "--json"], options);
  }

  attest(root, options) {
    return this.run(["attest", root, "--json"], options);
  }

  init(root, initOptions = {}, runOptions) {
    const args = ["init", root];
    if (initOptions.dryRun) args.push("--dry-run");
    if (initOptions.name !== undefined) args.push("--name", initOptions.name);
    if (initOptions.kind !== undefined) args.push("--kind", initOptions.kind);
    if (initOptions.agentAdapters) args.push("--agent-adapters");
    if (initOptions.template !== undefined) args.push("--template", initOptions.template);
    for (const answer of initOptions.answers ?? []) args.push("--answer", answer);
    if (initOptions.expectedPlanDigest !== undefined) {
      args.push("--expected-plan-digest", initOptions.expectedPlanDigest);
    }
    args.push("--json");
    return this.run(args, runOptions);
  }

  validate(root, validateOptions = {}, runOptions) {
    const args = ["validate", root];
    if (validateOptions.level !== undefined) args.push("--level", validateOptions.level);
    args.push("--json");
    return this.run(args, runOptions);
  }

  query(root, document, options) {
    return this.#runJson(["query", "run", root, "--json"], document, options);
  }

  explain(root, document, options) {
    return this.#runJson(["query", "explain", root, "--json"], document, options);
  }

  indexStatus(root, options) {
    return this.run(["index", "status", root, "--json"], options);
  }

  indexRebuild(root, options) {
    return this.run(["index", "rebuild", root, "--json"], options);
  }

  templatePlan(root, document, options) {
    return this.#runJson(
      ["template", "plan", root, "--stdin", "--json"],
      document,
      options,
    );
  }

  templateApply(root, expectedPlanDigest, document, options) {
    return this.#runJson(
      [
        "template",
        "apply",
        root,
        "--expected-plan-digest",
        expectedPlanDigest,
        "--stdin",
        "--json",
      ],
      document,
      options,
    );
  }

  changeSetCheckout(root, destination, document, options) {
    return this.#runJson(
      ["change-set", "checkout", root, destination, "--stdin", "--json"],
      document,
      options,
    );
  }

  changeSetPropose(checkout, staging, options) {
    return this.run(
      ["change-set", "propose", checkout, staging, "--json"],
      options,
    );
  }

  changeSetAssess(root, staging, document, options) {
    return this.#runJson(
      ["change-set", "assess", root, staging, "--stdin", "--json"],
      document,
      options,
    );
  }

  changeSetApply(root, staging, document, options) {
    return this.#runJson(
      ["change-set", "apply", root, staging, "--stdin", "--json"],
      document,
      options,
    );
  }

  async reconstruct(source, destination, request, options) {
    requireReconstructionPath(source, "source");
    requireReconstructionPath(destination, "destination");
    validateRootReconstructionRequest(request);
    const requestSha256 = rootReconstructionRequestSha256(request);
    const resolvedDestination = resolve(destination);
    try {
      const outcome = await this.#runJson(
        ["reconstruct", source, destination, "--stdin", "--json"],
        request,
        options,
      );
      if (outcome.kind === "success") {
        validateRootReconstructionResult(
          outcome.document,
          request,
          requestSha256,
          resolvedDestination,
        );
      } else {
        validateRootReconstructionAttention(outcome.document, request, requestSha256);
      }
      return outcome;
    } catch (error) {
      if (error instanceof FolderbaseOperationalError) {
        validateRootReconstructionError(error.document, request, requestSha256, {
          exitCode: error.exitCode,
          stderr: error.stderr,
        });
      }
      throw error;
    }
  }

  startDaemon(root, options = {}) {
    return FolderbaseDaemonSession.start(this.#configuration, root, options);
  }
}

export class FolderbaseDaemonSession extends EventEmitter {
  #child;
  #configuration;
  #buffer = Buffer.alloc(0);
  #stderr = [];
  #stderrBytes = 0;
  #pending;
  #queue = Promise.resolve();
  #requestSequence = 0;
  #terminalError;
  #readyResolve;
  #readyReject;
  #readyPromise;
  #closedResolve;
  #closedReject;
  #closedSettled = false;
  #startupTimer;

  constructor(configuration, root, options) {
    super();
    this.#configuration = configuration;
    this.ready = undefined;
    this.closed = new Promise((resolve, reject) => {
      this.#closedResolve = resolve;
      this.#closedReject = reject;
    });
    // Startup callers await the separate ready promise. Attach a rejection
    // observer so a startup failure cannot become an unhandled closed promise.
    this.closed.catch(() => {});
    this.#readyPromise = new Promise((resolve, reject) => {
      this.#readyResolve = resolve;
      this.#readyReject = reject;
    });
    const signal = options.signal;
    const args = [
      ...configuration.argumentsPrefix,
      "daemon",
      "serve",
      root,
      "--stdio-jsonl",
    ];
    try {
      this.#child = spawn(configuration.executable, args, spawnOptions(configuration));
    } catch (error) {
      this.#fail(new FolderbaseSpawnError(
        `Unable to start ${configuration.executable}`,
        error,
      ));
      return;
    }
    const startupTimeout = requireTimeout(options.timeoutMs, configuration.timeoutMs);
    this.#startupTimer = setTimeout(
      () => this.#fail(new FolderbaseTimeoutError(startupTimeout)),
      startupTimeout,
    );
    this.#startupTimer.unref();
    const abort = () => this.#fail(new FolderbaseCancelledError());
    signal?.addEventListener("abort", abort, { once: true });
    this.closed.finally(() => signal?.removeEventListener("abort", abort)).catch(() => {});
    this.#child.once("error", (error) => this.#fail(new FolderbaseSpawnError(
      `Unable to start ${configuration.executable}`,
      error,
    )));
    this.#child.stdout.on("data", (chunk) => this.#consume(chunk));
    this.#child.stderr.on("data", (chunk) => {
      if (this.#terminalError) return;
      try {
        this.#stderrBytes = appendBounded(
          this.#stderr,
          chunk,
          this.#stderrBytes,
          configuration.maxOutputBytes,
          "stderr",
        );
      } catch (error) {
        this.#fail(error);
      }
    });
    this.#child.once("close", (code, exitSignal) => this.#onClose(code, exitSignal));
    this.#child.stdin.on("error", (error) => {
      if (error.code !== "EPIPE") this.#fail(new FolderbaseOperationalError(
        "Unable to write daemon stdin",
        { cause: error },
      ));
    });
  }

  static async start(configuration, root, options = {}) {
    if (options.signal?.aborted) throw new FolderbaseCancelledError();
    const session = new FolderbaseDaemonSession(configuration, root, options);
    await session.#readyPromise;
    return session;
  }

  #consume(chunk) {
    if (this.#terminalError) return;
    this.#buffer = Buffer.concat([this.#buffer, chunk]);
    if (this.#buffer.length > this.#configuration.maxOutputBytes
      && !this.#buffer.includes(0x0a)) {
      this.#fail(new FolderbaseOutputLimitError(
        "daemon stdout line",
        this.#configuration.maxOutputBytes,
      ));
      return;
    }
    while (true) {
      const newline = this.#buffer.indexOf(0x0a);
      if (newline < 0) return;
      if (newline + 1 > this.#configuration.maxOutputBytes) {
        this.#fail(new FolderbaseOutputLimitError(
          "daemon stdout line",
          this.#configuration.maxOutputBytes,
        ));
        return;
      }
      const line = this.#buffer.subarray(0, newline);
      this.#buffer = this.#buffer.subarray(newline + 1);
      let message;
      try {
        message = parseObject(line, "Folderbase daemon stdout", {
          stdout: line.toString("utf8"),
        });
        this.#acceptMessage(message);
      } catch (error) {
        this.#fail(error);
        return;
      }
    }
  }

  #acceptMessage(message) {
    if (message.format !== DAEMON_MESSAGE_FORMAT) {
      throw new FolderbaseMalformedOutputError(
        `Daemon message format must be ${DAEMON_MESSAGE_FORMAT}`,
      );
    }
    if (message.kind === "ready") {
      if (this.ready !== undefined
        || !hasExactKeys(message, [
          "format",
          "kind",
          "capability",
          "epoch",
          "folderbase_id",
          "root_instance_sha256",
          "root",
        ])
        || message.capability !== DAEMON_CAPABILITY
        || typeof message.epoch !== "string"
        || typeof message.folderbase_id !== "string"
        || typeof message.root_instance_sha256 !== "string"
        || typeof message.root !== "string") {
        throw new FolderbaseMalformedOutputError("Daemon emitted an invalid ready message");
      }
      this.ready = message;
      clearTimeout(this.#startupTimer);
      this.#readyResolve(message);
      return;
    }
    if (this.ready === undefined) {
      throw new FolderbaseMalformedOutputError("Daemon emitted output before ready");
    }
    if (message.kind === "event") {
      if (!hasExactKeys(message, [
        "format",
        "kind",
        "event",
        "epoch",
        "sequence",
      ])
        || !["workspace_changed", "rescan_required"].includes(message.event)
        || message.epoch !== this.ready.epoch
        || !Number.isSafeInteger(message.sequence)
        || message.sequence < 1) {
        throw new FolderbaseMalformedOutputError("Daemon emitted an invalid event");
      }
      this.emit("event", message);
      return;
    }
    if (message.kind !== "response"
      || !hasExactKeys(message, [
        "format",
        "kind",
        "request_id",
        "operation",
        "status",
        "document",
      ])
      || !this.#pending
      || message.document === null
      || typeof message.document !== "object"
      || Array.isArray(message.document)) {
      throw new FolderbaseMalformedOutputError("Daemon emitted an unexpected response");
    }
    if (message.request_id !== this.#pending.requestId
      || message.operation !== this.#pending.operation) {
      throw new FolderbaseMalformedOutputError("Daemon response did not match its request");
    }
    if (!["ok", "attention", "error"].includes(message.status)) {
      throw new FolderbaseMalformedOutputError("Daemon response has an invalid status");
    }
    const pending = this.#pending;
    this.#pending = undefined;
    clearTimeout(pending.timer);
    pending.signal?.removeEventListener("abort", pending.abort);
    pending.resolve(message);
  }

  request(operation, document, options = {}) {
    const execute = () => this.#request(operation, document, options);
    const result = this.#queue.then(execute);
    this.#queue = result.catch(() => {});
    return result;
  }

  #request(operation, document, options) {
    if (!DAEMON_OPERATIONS.has(operation)) {
      return Promise.reject(new TypeError(`unsupported daemon operation: ${operation}`));
    }
    const needsDocument = operation === "query" || operation === "explain";
    if (needsDocument !== (document !== undefined)) {
      return Promise.reject(new TypeError(
        needsDocument
          ? `${operation} requires a document`
          : `${operation} does not accept a document`,
      ));
    }
    if (document !== undefined) requireJsonObject(document);
    if (this.#terminalError || !this.#child || this.#child.exitCode !== null) {
      return Promise.reject(this.#terminalError ?? new FolderbaseUnexpectedExitError(
        "Folderbase daemon session is closed",
      ));
    }
    const signal = options.signal;
    if (signal?.aborted) {
      this.#fail(new FolderbaseCancelledError());
      return Promise.reject(this.#terminalError);
    }
    this.#requestSequence += 1;
    const requestId = `sdk:${this.#requestSequence}`;
    const request = {
      format: DAEMON_REQUEST_FORMAT,
      request_id: requestId,
      operation,
      ...(document === undefined ? {} : { document }),
    };
    const bytes = encodeJsonLine(request, this.#configuration.maxInputBytes);
    const timeoutMs = requireTimeout(options.timeoutMs, this.#configuration.timeoutMs);
    return new Promise((resolve, reject) => {
      const abort = () => this.#fail(new FolderbaseCancelledError());
      const timer = setTimeout(
        () => this.#fail(new FolderbaseTimeoutError(timeoutMs)),
        timeoutMs,
      );
      timer.unref();
      this.#pending = { requestId, operation, resolve, reject, timer, signal, abort };
      signal?.addEventListener("abort", abort, { once: true });
      this.#child.stdin.write(bytes, (error) => {
        if (error && error.code !== "EPIPE") {
          this.#fail(new FolderbaseOperationalError(
            "Unable to write daemon request",
            { cause: error },
          ));
        }
      });
    });
  }

  async shutdown(options) {
    const response = await this.request("shutdown", undefined, options);
    this.#child.stdin.end();
    await this.closed;
    return response;
  }

  async stop() {
    if (!this.#child || this.#child.exitCode !== null) return this.closed;
    terminateProcessTree(this.#child);
    return this.closed;
  }

  #fail(error) {
    if (this.#terminalError) return;
    this.#terminalError = error;
    clearTimeout(this.#startupTimer);
    this.#readyReject(error);
    if (this.#pending) {
      clearTimeout(this.#pending.timer);
      this.#pending.signal?.removeEventListener("abort", this.#pending.abort);
      this.#pending.reject(error);
      this.#pending = undefined;
    }
    terminateProcessTree(this.#child);
    if (!this.#child) this.#settleClosed(error);
  }

  #settleClosed(error, result) {
    if (this.#closedSettled) return;
    this.#closedSettled = true;
    if (error) this.#closedReject(error);
    else this.#closedResolve(result);
  }

  #onClose(exitCode, signal) {
    clearTimeout(this.#startupTimer);
    if (!this.ready && !this.#terminalError && exitCode === 2) {
      const stderr = Buffer.concat(this.#stderr).toString("utf8");
      try {
        const document = parseObject(stderr, "Folderbase daemon stderr", {
          exitCode,
          stderr,
        });
        this.#fail(new FolderbaseOperationalError(
          document.error?.message ?? "Folderbase daemon startup failed",
          { exitCode, document, stderr },
        ));
      } catch (error) {
        this.#fail(error);
      }
    }
    if (!this.ready && !this.#terminalError) {
      this.#fail(new FolderbaseUnexpectedExitError(
        `Folderbase daemon exited before ready with ${exitCode ?? signal ?? "unknown status"}`,
        {
          exitCode,
          signal,
          stderr: Buffer.concat(this.#stderr).toString("utf8"),
        },
      ));
    }
    if (!this.#terminalError && (exitCode !== 0 || this.#pending)) {
      this.#fail(new FolderbaseUnexpectedExitError(
        `Folderbase daemon exited with ${exitCode ?? signal ?? "unknown status"}`,
        {
          exitCode,
          signal,
          stderr: Buffer.concat(this.#stderr).toString("utf8"),
        },
      ));
    }
    if (this.#terminalError) {
      this.#settleClosed(this.#terminalError);
    } else {
      this.#settleClosed(undefined, { exitCode, signal });
    }
  }
}

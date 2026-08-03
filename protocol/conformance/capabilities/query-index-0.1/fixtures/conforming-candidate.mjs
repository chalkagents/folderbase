#!/usr/bin/env node

import { createHash } from "node:crypto";
import {
  lstat,
  mkdir,
  readFile,
  readdir,
  readlink,
  realpath,
  stat,
  writeFile,
} from "node:fs/promises";
import { join, resolve } from "node:path";

import {
  normalizeQueryRequest,
  pathMatchesPrefix,
  queryRequestSha256,
  validatePortablePath,
} from "../reference-request-digest.mjs";

const FOLDERBASE_ID = "folderbase_018f43c2-9a1b-7def-8123-456789abcdef";
const INDEX_PATH = ".folderbase/local/query-index-v1";
const MAX_INVENTORY_ENTRIES = 16_384;

class QueryCapabilityError extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
  }
}

function portableCompare(left, right) {
  return Buffer.compare(Buffer.from(left.path, "utf8"), Buffer.from(right.path, "utf8"));
}

function hash(value) {
  return createHash("sha256").update(value).digest("hex");
}

async function exists(path) {
  try {
    await stat(path);
    return true;
  } catch (error) {
    if (error?.code === "ENOENT") return false;
    throw error;
  }
}

function metadataFingerprint(metadata) {
  const mode = metadata.mode;
  return {
    bytes: metadata.size.toString(),
    modified_unix_nanos: metadata.mtimeNs?.toString() ?? null,
    readonly: (mode & 0o200n) === 0n,
    executable: (mode & 0o111n) !== 0n,
    device: metadata.dev?.toString() ?? null,
    inode: metadata.ino?.toString() ?? null,
    physical_identity: metadata.dev === undefined || metadata.ino === undefined
      ? null
      : `unix:${metadata.dev.toString(16).padStart(16, "0")}:${metadata.ino.toString(16).padStart(16, "0")}`,
  };
}

function ignoredByRules(path, rules) {
  return rules.some((rule) => path === rule || path.startsWith(`${rule}/`));
}

async function exactRegularFile(path) {
  try {
    const metadata = await lstat(path);
    return metadata.isFile() && !metadata.isSymbolicLink();
  } catch (error) {
    if (error?.code === "ENOENT") return false;
    throw error;
  }
}

async function rootInstanceIdentity(root, folderbaseId) {
  const exactRoot = await realpath(root);
  return hash(JSON.stringify({
    realpath: exactRoot,
    folderbase_id: folderbaseId,
    fingerprint: metadataFingerprint(await lstat(exactRoot, { bigint: true })),
  }));
}

async function liveObservation(root) {
  const exactRoot = await realpath(root);
  const rootMetadata = await lstat(exactRoot, { bigint: true });
  const manifestPath = join(exactRoot, ".folderbase/manifest.json");
  const manifestBytes = await readFile(manifestPath);
  const manifest = JSON.parse(manifestBytes);
  const folderbaseId = manifest.folderbase?.id;
  if (folderbaseId !== FOLDERBASE_ID) throw new Error("fixture Folderbase identity changed");
  const manifestMetadata = await lstat(manifestPath, { bigint: true });
  const ignorePath = join(exactRoot, ".folderbaseignore");
  const ignoreBytes = await readFile(ignorePath);
  const ignoreRules = ignoreBytes
    .toString("utf8")
    .split(/\r?\n/u)
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith("#"))
    .map((line) => line.endsWith("/") ? line.slice(0, -1) : line);
  const effectiveIgnoreDigest = hash(JSON.stringify({
    manifest: manifest.policies?.capture_ignore ?? null,
    folderbaseignore_sha256: hash(ignoreBytes),
    rules: ignoreRules,
  }));
  const entries = [];
  const exclusions = [];
  const observed = [];
  async function visit(relativeDirectory) {
    const children = await readdir(join(exactRoot, relativeDirectory), { withFileTypes: true });
    children.sort((left, right) => Buffer.compare(Buffer.from(left.name), Buffer.from(right.name)));
    for (const child of children) {
      const path = relativeDirectory ? `${relativeDirectory}/${child.name}` : child.name;
      if (!relativeDirectory && child.name === ".folderbase") continue;
      validatePortablePath(path);
      if (path !== ".folderbaseignore" && ignoredByRules(path, ignoreRules)) {
        if (!exclusions.some((entry) => entry.path === ignoreRules.find((rule) => path === rule || path.startsWith(`${rule}/`)))) {
          const rule = ignoreRules.find((candidate) => path === candidate || path.startsWith(`${candidate}/`));
          exclusions.push({ path: rule, reason: "capture-ignore-policy" });
        }
        continue;
      }
      const absolute = join(exactRoot, path);
      const metadata = await lstat(absolute, { bigint: true });
      const fingerprint = metadataFingerprint(metadata);
      const item = {
        path,
        kind: "directory",
        lifecycle: "live",
        bytes: null,
        object_id: null,
        object_version_id: null,
        folderbase_version_id: null,
        source: "capture_plan",
      };
      let symlinkTarget = null;
      if (metadata.isSymbolicLink()) {
        item.kind = "symlink";
        symlinkTarget = await readlink(absolute);
        item.symlink_target = symlinkTarget;
      } else if (metadata.isDirectory()) {
        if (await exactRegularFile(join(absolute, ".folderbase/manifest.json"))) {
          item.kind = "nested_folderbase";
          item.boundary_reason = "nested-folderbase-boundary";
          exclusions.push({
            path,
            kind: "nested_folderbase",
            reason: "nested-folderbase-boundary",
          });
        }
      } else if (metadata.isFile()) {
        item.kind = "regular_file";
        item.bytes = Number(metadata.size);
        item.executable = fingerprint.executable;
      } else {
        exclusions.push({ path, reason: "unsupported-v1", kind: "other_special" });
        continue;
      }
      entries.push(item);
      observed.push({ path, kind: item.kind, fingerprint, symlink_target: symlinkTarget });
      if (metadata.isDirectory() && item.kind !== "nested_folderbase") await visit(path);
      if (entries.length + exclusions.length > MAX_INVENTORY_ENTRIES) {
        throw new Error("query inventory limit exceeded");
      }
    }
  }
  await visit("");
  const localHeadPath = join(exactRoot, ".folderbase/local/head.json");
  const localHead = await exists(localHeadPath)
    ? {
        bytes_sha256: hash(await readFile(localHeadPath)),
        fingerprint: metadataFingerprint(await lstat(localHeadPath, { bigint: true })),
      }
    : null;
  const rootIdentity = hash(JSON.stringify({
    realpath: exactRoot,
    folderbase_id: folderbaseId,
    fingerprint: metadataFingerprint(rootMetadata),
  }));
  const generation = hash(JSON.stringify({
    root_instance: rootIdentity,
    folderbase_id: folderbaseId,
    root_manifest_sha256: hash(manifestBytes),
    root_manifest_fingerprint: metadataFingerprint(manifestMetadata),
    effective_ignore_sha256: effectiveIgnoreDigest,
    local_head: localHead,
    entries: observed.sort((left, right) => Buffer.compare(Buffer.from(left.path), Buffer.from(right.path))),
    exclusions: exclusions.sort(portableCompare),
  }));
  return {
    entries: entries.sort(portableCompare),
    exclusions: exclusions.sort(portableCompare),
    generation,
    rootIdentity,
    scopeSource: "capture_plan",
  };
}

async function historicalObservation(root, versionId) {
  const path = join(root, ".folderbase/versions/folderbase", `${versionId}.json`);
  let bytes;
  try {
    bytes = await readFile(path);
  } catch (error) {
    if (error?.code === "ENOENT") {
      throw new QueryCapabilityError(
        "query_scope_version_missing",
        "the exact historical Folderbase Version is missing",
      );
    }
    throw error;
  }
  let version;
  try {
    version = JSON.parse(bytes);
    if (
      version.format !== "folderbase-version-v1" ||
      version.protocol_version !== "0.5" ||
      version.version_id !== versionId ||
      version.folderbase_id !== FOLDERBASE_ID ||
      version.path_policy?.format !== "folderbase-portable-path-v1" ||
      !Array.isArray(version.bindings) ||
      !Array.isArray(version.tombstones) ||
      !Array.isArray(version.exclusions)
    ) throw new Error("closed Folderbase Version fields are invalid");
    const allPaths = [
      ...version.bindings.map((entry) => entry.path),
      ...version.tombstones.map((entry) => entry.path),
      ...version.exclusions.map((entry) => entry.path),
    ];
    for (const portablePath of allPaths) validatePortablePath(portablePath);
    for (const collection of [version.bindings, version.tombstones, version.exclusions]) {
      for (let index = 1; index < collection.length; index += 1) {
        if (Buffer.compare(Buffer.from(collection[index - 1].path), Buffer.from(collection[index].path)) >= 0) {
          throw new Error("Folderbase Version paths are not strictly sorted");
        }
      }
    }
  } catch (error) {
    throw new QueryCapabilityError(
      "query_scope_version_invalid",
      `the exact historical Folderbase Version is invalid: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
  const entries = version.bindings.map((binding) => ({
    path: binding.path,
    kind: binding.kind,
    lifecycle: "live",
    bytes: binding.bytes ?? null,
    ...(binding.executable === undefined ? {} : { executable: binding.executable }),
    ...(binding.target === undefined ? {} : { symlink_target: binding.target }),
    object_id: binding.object_id,
    object_version_id: binding.object_version_id ?? null,
    folderbase_version_id: versionId,
    source: "folderbase_version",
  }));
  for (const tombstone of version.tombstones) {
    entries.push({
      path: tombstone.path,
      kind: tombstone.deleted_kind,
      lifecycle: "deleted",
      bytes: null,
      object_id: tombstone.object_id,
      object_version_id: tombstone.last_object_version_id,
      folderbase_version_id: versionId,
      source: "folderbase_version",
    });
  }
  for (const exclusion of version.exclusions) {
    if (exclusion.kind === "nested_folderbase") {
      entries.push({
        path: exclusion.path,
        kind: "nested_folderbase",
        lifecycle: "live",
        bytes: null,
        object_id: null,
        object_version_id: null,
        folderbase_version_id: versionId,
        source: "folderbase_version",
        boundary_reason: "nested-folderbase-boundary",
      });
    }
  }
  return {
    entries: entries.sort(portableCompare),
    exclusions: version.exclusions,
    generation: hash(`${resolve(root)}\0${versionId}\0${hash(bytes)}`),
    rootIdentity: await rootInstanceIdentity(root, version.folderbase_id),
    scopeSource: "folderbase_version",
  };
}

function applies(entry, filters) {
  if (filters.paths.length && !filters.paths.includes(entry.path)) return false;
  if (
    filters.path_prefixes.length &&
    !filters.path_prefixes.some((prefix) => pathMatchesPrefix(entry.path, prefix))
  ) return false;
  if (filters.kinds.length && !filters.kinds.includes(entry.kind)) return false;
  if (filters.lifecycles.length && !filters.lifecycles.includes(entry.lifecycle)) return false;
  if (filters.object_ids.length && !filters.object_ids.includes(entry.object_id)) return false;
  if (
    filters.object_version_ids.length &&
    !filters.object_version_ids.includes(entry.object_version_id)
  ) return false;
  if (filters.minimum_bytes !== null && (entry.bytes === null || entry.bytes < filters.minimum_bytes)) {
    return false;
  }
  if (filters.maximum_bytes !== null && (entry.bytes === null || entry.bytes > filters.maximum_bytes)) {
    return false;
  }
  return true;
}

function encodeCursor(rootIdentity, requestSha256, generation, lastPath) {
  const value = Buffer.from(JSON.stringify({
    root: rootIdentity,
    request_sha256: requestSha256,
    generation,
    last_path: lastPath,
  })).toString("base64url");
  return `fbq1_${value}`;
}

function decodeCursor(cursor) {
  if (!cursor?.startsWith("fbq1_")) throw new Error("invalid query cursor");
  return JSON.parse(Buffer.from(cursor.slice(5), "base64url").toString("utf8"));
}

async function observation(root, scope) {
  return scope.kind === "historical"
    ? historicalObservation(root, scope.folderbase_version_id)
    : liveObservation(root);
}

async function indexState(root, observedGeneration) {
  const record = join(root, INDEX_PATH, "generation.json");
  if (!(await exists(record))) return { state: "absent", generation: null, records: 0 };
  const stored = JSON.parse(await readFile(record, "utf8"));
  return {
    state: stored.generation === observedGeneration ? "fresh" : "stale",
    generation: stored.generation,
    records: stored.records,
  };
}

function writeSuccess(value) {
  process.stdout.write(`${JSON.stringify(value)}\n`);
}

function writeAttention(message) {
  writeSuccess({
    format: "folderbase-query-attention-v1",
    error: { code: "query_snapshot_changed", message, retryable: true },
  });
  process.exitCode = 1;
}

function writeError(code, message) {
  process.stderr.write(`${JSON.stringify({
    format: "folderbase-query-error-v1",
    error: { code, message },
  })}\n`);
  process.exitCode = 2;
}

async function readStandardInput() {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

async function query(command, root) {
  const request = await readStandardInput();
  const normalized = normalizeQueryRequest(request);
  const requestSha256 = queryRequestSha256(request);
  const observed = await observation(root, request.scope);
  let lastPath = null;
  if (request.page.cursor) {
    const cursor = decodeCursor(request.page.cursor);
    if (cursor.root !== observed.rootIdentity || cursor.request_sha256 !== requestSha256) {
      writeError("invalid_query_cursor", "cursor does not bind this root and request");
      return;
    }
    if (cursor.generation !== observed.generation) {
      writeAttention("the query observation changed; restart without a cursor");
      return;
    }
    lastPath = cursor.last_path;
  }
  const matching = observed.entries
    .filter((entry) => applies(entry, normalized.filters))
    .filter((entry) => lastPath === null || Buffer.compare(Buffer.from(entry.path), Buffer.from(lastPath)) > 0);
  const pageEntries = matching.slice(0, request.page.limit);
  const hasMore = matching.length > pageEntries.length;
  const index = await indexState(root, observed.generation);
  if (command === "explain") {
    writeSuccess({
      format: "folderbase-query-explain-v1",
      root: resolve(root),
      folderbase_id: FOLDERBASE_ID,
      request_sha256: requestSha256,
      observation_generation: observed.generation,
      normalized_request: normalized,
      scope_source: observed.scopeSource,
      ordering: "portable_path_utf8_bytes_ascending",
      filter_algebra: "families_and_values_or",
      ordinary_content_access: "metadata_only",
      index_strategy: index.state === "fresh" ? "private_index" : "bounded_scan",
      matched: matching.length,
      excluded: observed.exclusions,
    });
    return;
  }
  writeSuccess({
    format: "folderbase-query-result-v1",
    root: resolve(root),
    folderbase_id: FOLDERBASE_ID,
    request_sha256: requestSha256,
    observation_generation: observed.generation,
    execution: index.state === "fresh" ? "private_index" : "bounded_scan",
    entries: pageEntries,
    exclusions: observed.exclusions,
    exclusions_truncated: false,
    page: {
      limit: request.page.limit,
      returned: pageEntries.length,
      has_more: hasMore,
      next_cursor: hasMore
        ? encodeCursor(observed.rootIdentity, requestSha256, observed.generation, pageEntries.at(-1).path)
        : null,
    },
  });
}

async function index(command, root) {
  const observed = await liveObservation(root);
  const current = await indexState(root, observed.generation);
  if (command === "status") {
    writeSuccess({
      format: "folderbase-query-index-status-v1",
      root: resolve(root),
      folderbase_id: FOLDERBASE_ID,
      state: current.state,
      generation: current.generation,
      observed_generation: observed.generation,
      records: current.records,
      storage_path: INDEX_PATH,
      disposable: true,
    });
    return;
  }
  await mkdir(join(root, INDEX_PATH), { recursive: true });
  await writeFile(join(root, INDEX_PATH, "generation.json"), `${JSON.stringify({
    generation: observed.generation,
    records: observed.entries.length,
  })}\n`);
  writeSuccess({
    format: "folderbase-query-index-rebuild-result-v1",
    root: resolve(root),
    folderbase_id: FOLDERBASE_ID,
    generation: observed.generation,
    records: observed.entries.length,
    exclusions: observed.exclusions.length,
    storage_path: INDEX_PATH,
    portable_files_changed: false,
    ordinary_files_changed: false,
  });
}

try {
  const [family, command, root, json] = process.argv.slice(2);
  if (json !== "--json" || !["query", "index"].includes(family)) {
    throw new Error("unsupported invocation");
  }
  if (family === "query" && ["run", "explain"].includes(command)) {
    await query(command, root);
  } else if (family === "index" && ["status", "rebuild"].includes(command)) {
    await index(command, root);
  } else {
    throw new Error("unsupported invocation");
  }
} catch (error) {
  if (process.exitCode === undefined) {
    writeError(
      error instanceof QueryCapabilityError ? error.code : "invalid_query_request",
      error instanceof Error ? error.message : String(error),
    );
  }
}

#!/usr/bin/env node

import { createHash } from "node:crypto";
import {
  lstat,
  mkdir,
  readFile,
  readlink,
  stat,
  writeFile,
} from "node:fs/promises";
import { join, resolve } from "node:path";

import {
  normalizeQueryRequest,
  pathMatchesPrefix,
  queryRequestSha256,
} from "../reference-request-digest.mjs";

const FOLDERBASE_ID = "folderbase_018f43c2-9a1b-7def-8123-456789abcdef";
const INDEX_PATH = ".folderbase/local/query-index-v1";
const LIVE_PATHS = [
  ".folderbaseignore",
  "AGENTS.md",
  "data",
  "data/app.sqlite",
  "data/table.csv",
  "database.md",
  "documents",
  "documents/Brief.pdf",
  "links",
  "links/brief-link",
  "media",
  "media/archive.mov",
  "media/clip.mp4",
  "notes",
  "notes/Brief.md",
  "repo",
  "repo/.git",
  "repo/.git/HEAD",
  "repo/README.md",
  "vendors",
  "vendors/nested",
];

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

async function liveObservation(root) {
  const entries = [];
  const generationParts = [];
  for (const path of LIVE_PATHS) {
    const metadata = await lstat(join(root, path));
    let kind;
    let bytes = null;
    const item = {
      path,
      kind: "directory",
      lifecycle: "live",
      bytes,
      object_id: null,
      object_version_id: null,
      folderbase_version_id: null,
      source: "capture_plan",
    };
    if (path === "vendors/nested") {
      kind = "nested_folderbase";
      item.boundary_reason = "nested-folderbase-boundary";
    } else if (metadata.isSymbolicLink()) {
      kind = "symlink";
      item.symlink_target = await readlink(join(root, path));
    } else if (metadata.isDirectory()) {
      kind = "directory";
    } else {
      kind = "regular_file";
      bytes = metadata.size;
      item.bytes = bytes;
      item.executable = (metadata.mode & 0o111) !== 0;
    }
    item.kind = kind;
    entries.push(item);
    generationParts.push([path, kind, bytes, Math.trunc(metadata.mtimeMs)]);
  }
  const manifest = await lstat(join(root, ".folderbase/manifest.json"));
  generationParts.push([".folderbase/manifest.json", manifest.size, Math.trunc(manifest.mtimeMs)]);
  return {
    entries: entries.sort(portableCompare),
    exclusions: [
      { path: "ignored", reason: "capture-ignore-policy" },
      {
        path: "vendors/nested",
        kind: "nested_folderbase",
        reason: "nested-folderbase-boundary",
      },
    ],
    generation: hash(JSON.stringify(generationParts)),
    scopeSource: "capture_plan",
  };
}

async function historicalObservation(root, versionId) {
  const path = join(root, ".folderbase/versions/folderbase", `${versionId}.json`);
  const bytes = await readFile(path);
  const version = JSON.parse(bytes);
  if (version.version_id !== versionId || version.folderbase_id !== FOLDERBASE_ID) {
    throw new Error("query scope Version is invalid");
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

function rootBinding(root) {
  return hash(resolve(root));
}

function encodeCursor(root, requestSha256, generation, lastPath) {
  const value = Buffer.from(JSON.stringify({
    root: rootBinding(root),
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
    if (cursor.root !== rootBinding(root) || cursor.request_sha256 !== requestSha256) {
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
        ? encodeCursor(root, requestSha256, observed.generation, pageEntries.at(-1).path)
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
    writeError("invalid_query_request", error instanceof Error ? error.message : String(error));
  }
}

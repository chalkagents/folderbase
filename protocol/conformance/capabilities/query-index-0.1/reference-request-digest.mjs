#!/usr/bin/env node

import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";

const DOMAIN = Buffer.from("folderbase-query-request-v1\0", "utf8");

function byteCompare(left, right) {
  return Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"));
}

function canonicalSet(values = []) {
  return [...new Set(values)].sort(byteCompare);
}

export function pathMatchesPrefix(path, prefix) {
  return path === prefix || path.startsWith(`${prefix}/`);
}

export function normalizeQueryRequest(request) {
  const filters = request.filters ?? {};
  const normalized = {
    format: "folderbase-query-request-v1",
    scope: request.scope.kind === "historical"
      ? {
          kind: "historical",
          folderbase_version_id: request.scope.folderbase_version_id,
        }
      : { kind: "live" },
    filters: {
      paths: canonicalSet(filters.paths),
      path_prefixes: canonicalSet(filters.path_prefixes),
      kinds: canonicalSet(filters.kinds),
      lifecycles: canonicalSet(filters.lifecycles),
      object_ids: canonicalSet(filters.object_ids),
      object_version_ids: canonicalSet(filters.object_version_ids),
      minimum_bytes: filters.minimum_bytes ?? null,
      maximum_bytes: filters.maximum_bytes ?? null,
    },
    page: { limit: request.page.limit },
  };
  if (
    normalized.filters.minimum_bytes !== null &&
    normalized.filters.maximum_bytes !== null &&
    normalized.filters.minimum_bytes > normalized.filters.maximum_bytes
  ) {
    throw new Error("minimum_bytes must not exceed maximum_bytes");
  }
  return normalized;
}

export function canonicalQueryRequestBytes(request) {
  return Buffer.from(JSON.stringify(normalizeQueryRequest(request)), "utf8");
}

export function queryRequestSha256(request) {
  return createHash("sha256")
    .update(DOMAIN)
    .update(canonicalQueryRequestBytes(request))
    .digest("hex");
}

if (import.meta.url === `file://${process.argv[1]}`) {
  if (process.argv.length !== 3) {
    process.stderr.write("usage: reference-request-digest.mjs REQUEST.json\n");
    process.exit(2);
  }
  const request = JSON.parse(await readFile(process.argv[2], "utf8"));
  process.stdout.write(`${queryRequestSha256(request)}\n`);
}

#!/usr/bin/env node

import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";

const DOMAIN = Buffer.from("folderbase-query-request-v1\0", "utf8");
const MAX_PATH_BYTES = 4_096;
const MAX_PATH_COMPONENT_BYTES = 255;
const MAX_PATH_DEPTH = 128;
const WINDOWS_RESERVED_STEMS = new Set([
  "CON", "PRN", "AUX", "NUL",
  ...Array.from({ length: 9 }, (_, index) => `COM${index + 1}`),
  ...Array.from({ length: 9 }, (_, index) => `LPT${index + 1}`),
  "COM¹", "COM²", "COM³", "LPT¹", "LPT²", "LPT³",
]);

function byteCompare(left, right) {
  return Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"));
}

function canonicalSet(values = []) {
  return [...new Set(values)].sort(byteCompare);
}

function portableCollisionKey(path) {
  // The normative policy pins Unicode 17 NFC and Unicode 9 full default case
  // folding. U+1ACF was assigned combining class 230 in Unicode 17; the
  // replacement below preserves the table-discriminating public vector on
  // hosts whose built-in normalizer predates Unicode 17. Implementations remain
  // responsible for the complete pinned tables, not this representative shim.
  const unicode17Nfc = path
    .replaceAll("\u{1acf}\u{0323}", "\u{0323}\u{1acf}")
    .normalize("NFC");
  return unicode17Nfc.toUpperCase().toLowerCase().normalize("NFC");
}

function validatePortablePathSet(values, label) {
  const normalized = new Map();
  const folded = new Map();
  for (const path of values) {
    validatePortablePath(path);
    const nfc = path.normalize("NFC");
    const fold = portableCollisionKey(path);
    const nfcOwner = normalized.get(nfc);
    const foldedOwner = folded.get(fold);
    if ((nfcOwner && nfcOwner !== path) || (foldedOwner && foldedOwner !== path)) {
      throw new Error(`${label} contains a portable-path collision`);
    }
    normalized.set(nfc, path);
    folded.set(fold, path);
  }
}

export function validatePortablePath(path) {
  if (typeof path !== "string" || path.length === 0) {
    throw new Error("portable path must be a non-empty UTF-8 string");
  }
  const bytes = Buffer.from(path, "utf8");
  for (let index = 0; index < path.length; index += 1) {
    const unit = path.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const following = path.charCodeAt(index + 1);
      if (!(following >= 0xdc00 && following <= 0xdfff)) {
        throw new Error("portable path contains an unpaired UTF-16 surrogate");
      }
      index += 1;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      throw new Error("portable path contains an unpaired UTF-16 surrogate");
    }
  }
  if (
    bytes.length > MAX_PATH_BYTES ||
    path.startsWith("/") ||
    path.endsWith("/") ||
    path.includes("\\") ||
    /^[A-Za-z]:/u.test(path)
  ) throw new Error(`unsafe portable path: ${path}`);
  const components = path.split("/");
  if (components.length > MAX_PATH_DEPTH) {
    throw new Error("portable path exceeds the v1 depth limit");
  }
  for (const component of components) {
    const componentBytes = Buffer.from(component, "utf8");
    if (
      component.length === 0 ||
      component === "." ||
      component === ".." ||
      componentBytes.length > MAX_PATH_COMPONENT_BYTES ||
      /[. ]$/u.test(component) ||
      component.toLowerCase() === ".folderbase" ||
      /[\u0000-\u001f<>:"|?*]/u.test(component)
    ) throw new Error(`unsafe portable path component: ${component}`);
    const stem = component.split(".", 1)[0].toUpperCase();
    if (WINDOWS_RESERVED_STEMS.has(stem)) {
      throw new Error(`Windows-reserved portable path component: ${component}`);
    }
  }
  return path;
}

export function pathMatchesPrefix(path, prefix) {
  return path === prefix || path.startsWith(`${prefix}/`);
}

export function normalizeQueryRequest(request) {
  if (
    !request ||
    request.format !== "folderbase-query-request-v1" ||
    !request.scope ||
    !["live", "historical"].includes(request.scope.kind) ||
    !request.page ||
    !Number.isInteger(request.page.limit) ||
    request.page.limit < 1 ||
    request.page.limit > 1_000
  ) throw new Error("invalid query request shape");
  const filters = request.filters ?? {};
  validatePortablePathSet(filters.paths ?? [], "paths");
  validatePortablePathSet(filters.path_prefixes ?? [], "path_prefixes");
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
  return canonicalJsonBytes(normalizeQueryRequest(request));
}

export function canonicalJsonBytes(value) {
  const encoded = JSON.stringify(value);
  if (encoded === undefined) throw new Error("canonical JSON value is not serializable");
  return Buffer.from(encoded, "utf8");
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

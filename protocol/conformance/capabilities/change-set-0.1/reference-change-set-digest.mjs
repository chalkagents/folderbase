import assert from "node:assert/strict";
import { createHash } from "node:crypto";

const DOMAIN = Buffer.from("folderbase-change-set-v1\0", "utf8");

function closedOrdered(input, keys, label) {
  assert.ok(input !== null && typeof input === "object" && !Array.isArray(input), `${label} is an object`);
  assert.deepEqual(new Set(Object.keys(input)), new Set(keys), `${label} has the closed field set`);
  return Object.fromEntries(keys.map((key) => [key, input[key]]));
}

function orderedAuthorizedPath(input) {
  return closedOrdered(input, ["path_prefix"], "authorized path");
}

function orderedContent(input) {
  if (input.source === "projection_base") {
    return closedOrdered(input, ["source"], "base content reference");
  }
  assert.equal(input.source, "staged", "content source");
  return closedOrdered(
    input,
    ["source", "staging_id", "chunk_manifest_sha256"],
    "staged content reference",
  );
}

function orderedState(input) {
  if (input === null) return null;
  if (input.kind === "directory") {
    return closedOrdered(input, ["path", "kind"], "directory state");
  }
  if (input.kind === "symlink") {
    return closedOrdered(
      input,
      ["path", "kind", "object_version_id", "target", "target_safety"],
      "symlink state",
    );
  }
  assert.equal(input.kind, "regular_file", "state kind");
  const ordered = closedOrdered(
    input,
    ["path", "kind", "object_version_id", "content_sha256", "bytes", "executable", "content"],
    "regular-file state",
  );
  ordered.content = orderedContent(input.content);
  return ordered;
}

function orderedDelta(input) {
  const ordered = closedOrdered(input, ["object_id", "before", "after"], "object delta");
  ordered.before = orderedState(input.before);
  ordered.after = orderedState(input.after);
  return ordered;
}

export function canonicalChangeSetPayload(payload) {
  const ordered = closedOrdered(
    payload,
    [
      "format",
      "change_set_id",
      "checkout_id",
      "folderbase_id",
      "projection_id",
      "folder_scope_id",
      "scope_revision_sha256",
      "permission",
      "authorized_paths",
      "projection_base_sha256",
      "created_at",
      "deltas",
    ],
    "Change Set payload",
  );
  ordered.authorized_paths = payload.authorized_paths.map(orderedAuthorizedPath);
  ordered.deltas = payload.deltas.map(orderedDelta);
  return ordered;
}

export function canonicalChangeSetPayloadBytes(payload) {
  return Buffer.from(JSON.stringify(canonicalChangeSetPayload(payload)), "utf8");
}

export function changeSetSha256(payload) {
  return createHash("sha256")
    .update(DOMAIN)
    .update(canonicalChangeSetPayloadBytes(payload))
    .digest("hex");
}

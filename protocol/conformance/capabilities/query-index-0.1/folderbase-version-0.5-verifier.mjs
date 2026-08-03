import { createHash } from "node:crypto";

import { assertJsonSchema } from "./schema.mjs";
import {
  PortablePathCollisionIndex,
  portablePathKeys,
} from "./portable-path-v1.mjs";
import { validatePortablePath } from "./reference-request-digest.mjs";

const MAX_ENCODED_BYTES = 64 * 1024 * 1024;
const MAX_ENTRIES = 16_384;
const MAX_OBJECT_BYTES = 1024 * 1024 * 1024 * 1024;
const MAX_MANIFEST_BYTES = 16 * 1024 * 1024;
const decoder = new TextDecoder("utf-8", { fatal: true });

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function assertIdentifier(value, prefix) {
  assert(typeof value === "string" && value.startsWith(prefix), "identifier uses the wrong namespace");
  const uuid = value.slice(prefix.length);
  const match = /^([0-9a-f]{8})-([0-9a-f]{4})-([1-8][0-9a-f]{3})-([89ab][0-9a-f]{3})-([0-9a-f]{12})$/u.exec(uuid);
  assert(match !== null, "identifier is not a canonical supported UUID");
}

function assertSha256(value) {
  assert(/^[0-9a-f]{64}$/u.test(value), "content digest is not lowercase hexadecimal SHA-256");
}

function rejectDuplicateJsonKeys(source) {
  let offset = 0;
  const whitespace = () => { while (/\s/u.test(source[offset] ?? "")) offset += 1; };
  const string = () => {
    const start = offset++;
    while (offset < source.length) {
      if (source[offset] === "\\") { offset += 2; continue; }
      if (source[offset++] === "\"") return JSON.parse(source.slice(start, offset));
    }
    throw new Error("unterminated JSON string");
  };
  const value = () => {
    whitespace();
    if (source[offset] === "{") {
      offset += 1; whitespace();
      const keys = new Set();
      if (source[offset] === "}") { offset += 1; return; }
      for (;;) {
        assert(source[offset] === "\"", "invalid JSON object key");
        const key = string();
        assert(!keys.has(key), `duplicate JSON object key: ${key}`);
        keys.add(key); whitespace(); assert(source[offset++] === ":", "invalid JSON object");
        value(); whitespace();
        if (source[offset] === "}") { offset += 1; return; }
        assert(source[offset++] === ",", "invalid JSON object separator"); whitespace();
      }
    }
    if (source[offset] === "[") {
      offset += 1; whitespace();
      if (source[offset] === "]") { offset += 1; return; }
      for (;;) {
        value(); whitespace();
        if (source[offset] === "]") { offset += 1; return; }
        assert(source[offset++] === ",", "invalid JSON array separator");
      }
    }
    if (source[offset] === "\"") { string(); return; }
    const match = /^(?:-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?|true|false|null)/u.exec(source.slice(offset));
    assert(match !== null, "invalid JSON value");
    offset += match[0].length;
  };
  value(); whitespace(); assert(offset === source.length, "trailing JSON data");
}

function rejectUnpairedSurrogates(value) {
  if (typeof value === "string") {
    for (let index = 0; index < value.length; index += 1) {
      const unit = value.charCodeAt(index);
      if (unit >= 0xd800 && unit <= 0xdbff) {
        const following = value.charCodeAt(index + 1);
        assert(following >= 0xdc00 && following <= 0xdfff, "JSON string contains an unpaired surrogate");
        index += 1;
      } else assert(!(unit >= 0xdc00 && unit <= 0xdfff), "JSON string contains an unpaired surrogate");
    }
  } else if (Array.isArray(value)) value.forEach(rejectUnpairedSurrogates);
  else if (value !== null && typeof value === "object") {
    for (const [key, child] of Object.entries(value)) {
      rejectUnpairedSurrogates(key); rejectUnpairedSurrogates(child);
    }
  }
}

function strictPathOrder(entries, label) {
  let previous;
  for (const entry of entries) {
    validatePortablePath(entry.path);
    if (previous !== undefined) {
      assert(Buffer.compare(Buffer.from(previous), Buffer.from(entry.path)) < 0,
        `${label} must be strictly sorted by exact UTF-8 path bytes`);
    }
    previous = entry.path;
  }
}

function strictAncestor(path, boundary) {
  return path.startsWith(`${boundary}/`);
}

function resolveSymlinkTarget(linkPath, target, boundaries) {
  const bytes = Buffer.from(target, "utf8");
  assert(
    bytes.length > 0 && bytes.length <= 4096 &&
      !target.startsWith("/") && !target.endsWith("/") &&
      !target.includes("\\") && !target.includes("\0") && !target.includes("//") &&
      !/^[A-Za-z]:/u.test(target),
    "symlink target is not a portable relative target",
  );
  const resolved = linkPath.split("/").slice(0, -1);
  for (const component of target.split("/")) {
    if (component === ".") continue;
    if (component === "..") {
      assert(resolved.pop() !== undefined, "symlink target escapes the Folderbase root");
    } else {
      // Reuse the path component policy through a harmless single-component path.
      validatePortablePath(component);
      resolved.push(component);
      assert(resolved.length <= 128, "symlink target exceeds the v1 path depth limit");
    }
  }
  const path = resolved.join("/");
  if (path === "") return;
  validatePortablePath(path);
  assert(path.split("/")[0].toLowerCase() !== ".folderbase",
    "symlink target enters Folderbase protocol state");
  const folded = portablePathKeys(path).folded;
  assert(!boundaries.some((boundary) =>
    folded === boundary || strictAncestor(folded, boundary)),
  "symlink target enters a nested Folderbase boundary");
}

function semanticValidate(version) {
  assert(version.format === "folderbase-version-v1" && version.protocol_version === "0.5",
    "unsupported Folderbase Version format or protocol");
  assertIdentifier(version.folderbase_id, "folderbase_");
  assertIdentifier(version.version_id, "fbversion_");
  assert(version.parents.length <= 2, "a Folderbase Version has at most two parents");
  for (const parent of version.parents) {
    assertIdentifier(parent, "fbversion_");
    assert(parent !== version.version_id, "a Folderbase Version cannot be its own parent");
  }
  assert(new Set(version.parents).size === version.parents.length,
    "Folderbase Version parents must be unique");
  const parsed = new Date(version.created_at);
  assert(!Number.isNaN(parsed.valueOf()) && parsed.toISOString().replace(".000Z", "Z") === version.created_at,
    "created_at must be canonical UTC RFC 3339 seconds");
  assert(
    version.path_policy.format === "folderbase-portable-path-v1" &&
      version.path_policy.normalization === "NFC" &&
      version.path_policy.normalization_unicode_version === "17.0.0" &&
      version.path_policy.case_folding === "full-default" &&
      version.path_policy.case_folding_unicode_version === "9.0.0",
    "unsupported portable path policy",
  );
  assert(version.root_manifest.path === ".folderbase/manifest.json",
    "root_manifest must name the exact reserved manifest path");
  assertIdentifier(version.root_manifest.object_version_id, "version_");
  assertSha256(version.root_manifest.content_sha256);
  assert(version.root_manifest.bytes > 0 && version.root_manifest.bytes <= MAX_MANIFEST_BYTES,
    "root_manifest byte length is outside the v1 limit");
  assert(version.bindings.length + version.tombstones.length + version.exclusions.length <= MAX_ENTRIES,
    "Folderbase Version entry count exceeds the v1 limit");
  strictPathOrder(version.bindings, "bindings");
  strictPathOrder(version.tombstones, "tombstones");
  strictPathOrder(version.exclusions, "exclusions");

  const currentPaths = new PortablePathCollisionIndex();
  const liveObjectIds = new Set();
  const objectVersionOwners = new Map([[version.root_manifest.object_version_id, "__root__"]]);
  const bindObjectVersion = (objectVersionId, objectId) => {
    assertIdentifier(objectVersionId, "version_");
    const owner = objectVersionOwners.get(objectVersionId);
    assert(owner === undefined || owner === objectId,
      "one Object Version is referenced by different Object IDs");
    objectVersionOwners.set(objectVersionId, objectId);
  };
  for (const binding of version.bindings) {
    currentPaths.insert(binding.path, binding.object_id);
    assertIdentifier(binding.object_id, "obj_");
    assert(!liveObjectIds.has(binding.object_id), "one live Object ID is bound to more than one path");
    liveObjectIds.add(binding.object_id);
    if (binding.kind === "regular_file") {
      bindObjectVersion(binding.object_version_id, binding.object_id);
      assertSha256(binding.content_sha256);
      assert(binding.bytes <= MAX_OBJECT_BYTES, "regular file exceeds the v1 object-size limit");
    } else if (binding.kind === "symlink") {
      bindObjectVersion(binding.object_version_id, binding.object_id);
    }
  }
  for (const exclusion of version.exclusions) {
    currentPaths.insert(exclusion.path);
    const valid = exclusion.kind === "nested_folderbase"
      ? exclusion.reason === "nested-folderbase-boundary"
      : exclusion.reason === "unsupported-v1";
    assert(valid, "exclusion kind and reason do not match");
  }
  const tombstonePaths = new PortablePathCollisionIndex();
  for (const tombstone of version.tombstones) {
    tombstonePaths.insert(tombstone.path, tombstone.object_id);
    const currentOwner = currentPaths.exactOwner(tombstone.path);
    if (currentOwner !== undefined) {
      assert(currentOwner !== null, "a tombstone cannot occupy an excluded current path");
      assert(currentOwner !== tombstone.object_id,
        "same-path recreation must use a new stable Object ID");
    } else {
      currentPaths.rejectAlias(tombstone.path);
    }
    assertIdentifier(tombstone.object_id, "obj_");
    if (tombstone.last_object_version_id !== null) {
      bindObjectVersion(tombstone.last_object_version_id, tombstone.object_id);
    }
    assert(
      (tombstone.deleted_kind === "directory" && tombstone.last_object_version_id === null) ||
        (["regular_file", "symlink"].includes(tombstone.deleted_kind) &&
          tombstone.last_object_version_id !== null),
      "directory tombstones omit Object Version; content tombstones require it",
    );
  }

  const boundaries = version.exclusions
    .filter(({ kind }) => kind === "nested_folderbase")
    .map(({ path }) => portablePathKeys(path).folded);
  for (const boundary of boundaries) {
    assert(!boundaries.some((other) => other !== boundary && strictAncestor(boundary, other)),
      `nested Folderbase boundary overlaps its ancestor: ${boundary}`);
  }
  const rejectNested = (path) => {
    const folded = portablePathKeys(path).folded;
    assert(!boundaries.some((boundary) => strictAncestor(folded, boundary)),
      `path enters an excluded nested Folderbase boundary: ${path}`);
  };
  version.bindings.forEach(({ path }) => rejectNested(path));
  version.tombstones.forEach(({ path }) => rejectNested(path));
  version.exclusions.filter(({ kind }) => kind !== "nested_folderbase")
    .forEach(({ path }) => rejectNested(path));
  version.bindings.filter(({ kind }) => kind === "symlink")
    .forEach(({ path, target }) => resolveSymlinkTarget(path, target, boundaries));
}

function canonicalDigest(version) {
  const parts = [Buffer.from("folderbase-version-v1\0", "ascii")];
  const identifier = (value) => {
    const bytes = Buffer.from(value, "utf8");
    const length = Buffer.alloc(4); length.writeUInt32BE(bytes.length);
    parts.push(length, bytes);
  };
  const u8 = (value) => { const bytes = Buffer.alloc(1); bytes.writeUInt8(value); parts.push(bytes); };
  const u32 = (value) => { const bytes = Buffer.alloc(4); bytes.writeUInt32BE(value); parts.push(bytes); };
  const u64 = (value) => { const bytes = Buffer.alloc(8); bytes.writeBigUInt64BE(BigInt(value)); parts.push(bytes); };
  const digest = (value) => parts.push(Buffer.from(value, "hex"));
  identifier(version.protocol_version); identifier(version.folderbase_id); identifier(version.version_id);
  u8(version.parents.length); version.parents.forEach(identifier); identifier(version.created_at);
  for (const key of ["format", "normalization", "normalization_unicode_version", "case_folding", "case_folding_unicode_version"]) identifier(version.path_policy[key]);
  identifier(version.root_manifest.path); identifier(version.root_manifest.object_version_id);
  digest(version.root_manifest.content_sha256); u64(version.root_manifest.bytes);
  u32(version.bindings.length);
  for (const binding of version.bindings) {
    identifier(binding.path); identifier(binding.object_id); identifier(binding.lifecycle);
    if (binding.kind === "directory") u8(0);
    else if (binding.kind === "regular_file") {
      u8(1); identifier(binding.object_version_id); digest(binding.content_sha256);
      u64(binding.bytes); u8(binding.executable ? 1 : 0);
    } else {
      u8(2); identifier(binding.object_version_id); identifier(binding.target); identifier(binding.target_safety);
    }
  }
  u32(version.tombstones.length);
  for (const tombstone of version.tombstones) {
    identifier(tombstone.path); identifier(tombstone.object_id); identifier(tombstone.lifecycle);
    u8({ directory: 0, regular_file: 1, symlink: 2 }[tombstone.deleted_kind]);
    if (tombstone.last_object_version_id === null) u8(0);
    else { u8(1); identifier(tombstone.last_object_version_id); }
  }
  u32(version.exclusions.length);
  for (const exclusion of version.exclusions) {
    identifier(exclusion.path);
    u8({ nested_folderbase: 0, hard_link: 1, fifo: 2, socket: 3, block_device: 4,
      character_device: 5, other_special: 6 }[exclusion.kind]);
    identifier(exclusion.reason);
  }
  return createHash("sha256").update(Buffer.concat(parts)).digest("hex");
}

export function verifyFolderbaseVersion05(encoded, schema) {
  const bytes = Buffer.isBuffer(encoded) ? encoded : Buffer.from(encoded);
  assert(bytes.length <= MAX_ENCODED_BYTES, "Folderbase Version encoded length exceeds 64 MiB");
  const source = decoder.decode(bytes);
  rejectDuplicateJsonKeys(source);
  const version = JSON.parse(source);
  rejectUnpairedSurrogates(version);
  assertJsonSchema(version, schema, "folderbaseVersion");
  semanticValidate(version);
  return { version, canonicalDigest: canonicalDigest(version) };
}

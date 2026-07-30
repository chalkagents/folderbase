import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

const versionPath = process.argv[2];
if (!versionPath) {
  throw new Error(
    "usage: node reference-digest.mjs <folderbase-version-0.5.json>",
  );
}

const version = JSON.parse(readFileSync(versionPath, "utf8"));
if (version.protocol_version !== "0.5") {
  throw new Error(
    `protocol 0.5 reference encoder rejects ${JSON.stringify(version.protocol_version)}`,
  );
}

const parts = [Buffer.from("folderbase-version-v1\0", "ascii")];

function identifier(value) {
  const encoded = Buffer.from(value, "utf8");
  const length = Buffer.alloc(4);
  length.writeUInt32BE(encoded.length);
  parts.push(length, encoded);
}

function unsigned8(value) {
  const encoded = Buffer.alloc(1);
  encoded.writeUInt8(value);
  parts.push(encoded);
}

function unsigned32(value) {
  const encoded = Buffer.alloc(4);
  encoded.writeUInt32BE(value);
  parts.push(encoded);
}

function unsigned64(value) {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error(`not an exact non-negative safe integer: ${value}`);
  }
  const encoded = Buffer.alloc(8);
  encoded.writeBigUInt64BE(BigInt(value));
  parts.push(encoded);
}

function sha256(value) {
  if (!/^[0-9a-f]{64}$/.test(value)) {
    throw new Error(`not lowercase SHA-256: ${value}`);
  }
  parts.push(Buffer.from(value, "hex"));
}

identifier(version.protocol_version);
identifier(version.folderbase_id);
identifier(version.version_id);
unsigned8(version.parents.length);
for (const parent of version.parents) identifier(parent);
identifier(version.created_at);
identifier(version.path_policy.format);
identifier(version.path_policy.normalization);
identifier(version.path_policy.normalization_unicode_version);
identifier(version.path_policy.case_folding);
identifier(version.path_policy.case_folding_unicode_version);
identifier(version.root_manifest.path);
identifier(version.root_manifest.object_version_id);
sha256(version.root_manifest.content_sha256);
unsigned64(version.root_manifest.bytes);

unsigned32(version.bindings.length);
for (const binding of version.bindings) {
  identifier(binding.path);
  identifier(binding.object_id);
  identifier(binding.lifecycle);
  switch (binding.kind) {
    case "directory":
      unsigned8(0);
      break;
    case "regular_file":
      unsigned8(1);
      identifier(binding.object_version_id);
      sha256(binding.content_sha256);
      unsigned64(binding.bytes);
      unsigned8(binding.executable ? 1 : 0);
      break;
    case "symlink":
      unsigned8(2);
      identifier(binding.object_version_id);
      identifier(binding.target);
      identifier(binding.target_safety);
      break;
    default:
      throw new Error(`unknown binding kind: ${binding.kind}`);
  }
}

unsigned32(version.tombstones.length);
for (const tombstone of version.tombstones) {
  identifier(tombstone.path);
  identifier(tombstone.object_id);
  identifier(tombstone.lifecycle);
  const deletedKind = {
    directory: 0,
    regular_file: 1,
    symlink: 2,
  }[tombstone.deleted_kind];
  if (deletedKind === undefined) {
    throw new Error(`unknown tombstone kind: ${tombstone.deleted_kind}`);
  }
  unsigned8(deletedKind);
  if (tombstone.last_object_version_id === null) {
    unsigned8(0);
  } else {
    unsigned8(1);
    identifier(tombstone.last_object_version_id);
  }
}

unsigned32(version.exclusions.length);
for (const exclusion of version.exclusions) {
  identifier(exclusion.path);
  const exclusionKind = {
    nested_folderbase: 0,
    hard_link: 1,
    fifo: 2,
    socket: 3,
    block_device: 4,
    character_device: 5,
    other_special: 6,
  }[exclusion.kind];
  if (exclusionKind === undefined) {
    throw new Error(`unknown exclusion kind: ${exclusion.kind}`);
  }
  unsigned8(exclusionKind);
  identifier(exclusion.reason);
}

process.stdout.write(
  `${createHash("sha256").update(Buffer.concat(parts)).digest("hex")}\n`,
);

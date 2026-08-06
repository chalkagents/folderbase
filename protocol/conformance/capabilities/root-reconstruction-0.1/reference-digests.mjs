import { createHash } from "node:crypto";

function sha256Bytes(value) {
  if (!/^[0-9a-f]{64}$/u.test(value)) {
    throw new Error(`not lowercase SHA-256: ${value}`);
  }
  return Buffer.from(value, "hex");
}

function identifier(parts, value) {
  const encoded = Buffer.from(value, "utf8");
  const length = Buffer.alloc(4);
  length.writeUInt32BE(encoded.length);
  parts.push(length, encoded);
}

function unsigned8(parts, value) {
  const encoded = Buffer.alloc(1);
  encoded.writeUInt8(value);
  parts.push(encoded);
}

function unsigned32(parts, value) {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffff_ffff) {
    throw new Error(`not an exact u32: ${value}`);
  }
  const encoded = Buffer.alloc(4);
  encoded.writeUInt32BE(value);
  parts.push(encoded);
}

function unsigned64(parts, value) {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error(`not an exact safe JSON integer: ${value}`);
  }
  const encoded = Buffer.alloc(8);
  encoded.writeBigUInt64BE(BigInt(value));
  parts.push(encoded);
}

function finish(parts) {
  return createHash("sha256").update(Buffer.concat(parts)).digest("hex");
}

export function encodedSha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

export function rootReconstructionRequestSha256(request) {
  if (request.format !== "folderbase-root-reconstruction-request-v1") {
    throw new Error("unsupported root-reconstruction request format");
  }
  const parts = [Buffer.from("folderbase-root-reconstruction-request-v1\0", "ascii")];
  identifier(parts, request.operation_id);
  parts.push(sha256Bytes(request.package_index_sha256));
  return finish(parts);
}

export function chunkManifestSha256(manifest) {
  if (manifest.format !== "folderbase-chunk-manifest-v1") {
    throw new Error("unsupported chunk manifest format");
  }
  const parts = [Buffer.from("folderbase-chunk-manifest-v1\0", "ascii")];
  identifier(parts, manifest.algorithm);
  identifier(parts, manifest.profile);
  unsigned64(parts, manifest.minimum_chunk_bytes);
  unsigned64(parts, manifest.average_chunk_bytes);
  unsigned64(parts, manifest.maximum_chunk_bytes);
  parts.push(sha256Bytes(manifest.object_sha256));
  unsigned64(parts, manifest.object_bytes);
  unsigned32(parts, manifest.chunks.length);
  for (const chunk of manifest.chunks) {
    unsigned32(parts, chunk.index);
    unsigned64(parts, chunk.offset);
    unsigned64(parts, chunk.bytes);
    parts.push(sha256Bytes(chunk.sha256));
  }
  return finish(parts);
}

export function canonicalFolderbaseVersionSha256(version) {
  if (
    version.format !== "folderbase-version-v1"
    || !["0.4", "0.5"].includes(version.protocol_version)
  ) {
    throw new Error("unsupported Folderbase Version format");
  }
  const parts = [Buffer.from("folderbase-version-v1\0", "ascii")];
  identifier(parts, version.protocol_version);
  identifier(parts, version.folderbase_id);
  identifier(parts, version.version_id);
  unsigned8(parts, version.parents.length);
  version.parents.forEach((parent) => identifier(parts, parent));
  identifier(parts, version.created_at);
  for (const key of [
    "format",
    "normalization",
    "normalization_unicode_version",
    "case_folding",
    "case_folding_unicode_version",
  ]) identifier(parts, version.path_policy[key]);
  identifier(parts, version.root_manifest.path);
  identifier(parts, version.root_manifest.object_version_id);
  parts.push(sha256Bytes(version.root_manifest.content_sha256));
  unsigned64(parts, version.root_manifest.bytes);
  unsigned32(parts, version.bindings.length);
  for (const binding of version.bindings) {
    identifier(parts, binding.path);
    identifier(parts, binding.object_id);
    identifier(parts, binding.lifecycle);
    if (binding.kind === "directory") unsigned8(parts, 0);
    else if (binding.kind === "regular_file") {
      unsigned8(parts, 1);
      identifier(parts, binding.object_version_id);
      parts.push(sha256Bytes(binding.content_sha256));
      unsigned64(parts, binding.bytes);
      unsigned8(parts, binding.executable ? 1 : 0);
    } else if (binding.kind === "symlink") {
      unsigned8(parts, 2);
      identifier(parts, binding.object_version_id);
      identifier(parts, binding.target);
      identifier(parts, binding.target_safety);
    } else throw new Error(`unsupported binding kind: ${binding.kind}`);
  }
  unsigned32(parts, version.tombstones.length);
  for (const tombstone of version.tombstones) {
    identifier(parts, tombstone.path);
    identifier(parts, tombstone.object_id);
    identifier(parts, tombstone.lifecycle);
    unsigned8(parts, { directory: 0, regular_file: 1, symlink: 2 }[tombstone.deleted_kind]);
    if (tombstone.last_object_version_id === null) unsigned8(parts, 0);
    else {
      unsigned8(parts, 1);
      identifier(parts, tombstone.last_object_version_id);
    }
  }
  unsigned32(parts, version.exclusions.length);
  for (const exclusion of version.exclusions) {
    identifier(parts, exclusion.path);
    unsigned8(parts, {
      nested_folderbase: 0,
      hard_link: 1,
      fifo: 2,
      socket: 3,
      block_device: 4,
      character_device: 5,
      other_special: 6,
    }[exclusion.kind]);
    identifier(parts, exclusion.reason);
  }
  return finish(parts);
}

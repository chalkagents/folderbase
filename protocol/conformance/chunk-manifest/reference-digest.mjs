import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

const manifestPath = process.argv[2];
if (!manifestPath) {
  throw new Error("usage: node reference-digest.mjs <manifest.json>");
}

const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
const parts = [Buffer.from("folderbase-chunk-manifest-v1\0", "ascii")];

function identifier(value) {
  const encoded = Buffer.from(value, "utf8");
  const length = Buffer.alloc(4);
  length.writeUInt32BE(encoded.length);
  parts.push(length, encoded);
}

function unsigned32(value) {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffff_ffff) {
    throw new Error(`not an exact u32: ${value}`);
  }
  const encoded = Buffer.alloc(4);
  encoded.writeUInt32BE(value);
  parts.push(encoded);
}

function unsigned64(value) {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error(`not an exact safe JSON integer: ${value}`);
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

identifier(manifest.algorithm);
identifier(manifest.profile);
unsigned64(manifest.minimum_chunk_bytes);
unsigned64(manifest.average_chunk_bytes);
unsigned64(manifest.maximum_chunk_bytes);
sha256(manifest.object_sha256);
unsigned64(manifest.object_bytes);
unsigned32(manifest.chunks.length);
for (const descriptor of manifest.chunks) {
  unsigned32(descriptor.index);
  unsigned64(descriptor.offset);
  unsigned64(descriptor.bytes);
  sha256(descriptor.sha256);
}

process.stdout.write(`${createHash("sha256").update(Buffer.concat(parts)).digest("hex")}\n`);

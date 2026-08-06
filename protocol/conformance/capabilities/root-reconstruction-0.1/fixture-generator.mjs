#!/usr/bin/env node

import assert from "node:assert/strict";
import { mkdir, readdir, writeFile } from "node:fs/promises";
import { resolve, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  canonicalFolderbaseVersionSha256,
  chunkManifestSha256,
  encodedSha256,
  rootReconstructionRequestSha256,
} from "./reference-digests.mjs";

const FOLDERBASE_ID = "folderbase_019f0000-0000-7000-8000-000000000001";
const FOLDERBASE_VERSION_ID = "fbversion_019f0000-0000-7000-8000-000000000001";
const OPERATION_ID = "reconstruction_019f0000-0000-7000-8000-000000000001";
const LIMITS = Object.freeze({
  max_index_bytes: 8388608,
  max_version_bytes: 67108864,
  max_manifest_bytes: 67108864,
  max_references: 16385,
  max_distinct_manifests: 16385,
  max_distinct_chunks: 1048576,
  max_chunks_per_manifest: 262144,
  max_object_bytes: 1099511627776,
  max_total_object_bytes: 9007199254740991,
  max_visible_entries: 16384,
});

function uuidId(prefix, suffix) {
  return `${prefix}019f0000-0000-7000-8000-${suffix.padStart(12, "0")}`;
}

function encodeJson(value) {
  return Buffer.from(`${JSON.stringify(value, null, 2)}\n`, "utf8");
}

function exactSort(values, key) {
  return [...values].sort((left, right) =>
    Buffer.compare(Buffer.from(key(left), "utf8"), Buffer.from(key(right), "utf8")));
}

function directory(path, suffix) {
  return {
    path,
    object_id: uuidId("obj_", suffix),
    lifecycle: "live",
    kind: "directory",
  };
}

function regular(path, suffix, content, executable = false) {
  const bytes = Buffer.from(content);
  return {
    binding: {
      path,
      object_id: uuidId("obj_", suffix),
      lifecycle: "live",
      kind: "regular_file",
      object_version_id: uuidId("version_", `${suffix}1`),
      content_sha256: encodedSha256(bytes),
      bytes: bytes.length,
      executable,
    },
    content: bytes,
  };
}

function canonicalRootManifest() {
  return encodeJson({
    $schema: "https://folderbase.ai/protocol/0.5/folderbase.schema.json",
    protocol_version: "0.5.0",
    folderbase: {
      id: FOLDERBASE_ID,
      name: "Root reconstruction conformance fixture",
      kind: "project",
      status: "active",
      created_at: "2026-08-06T00:00:00Z",
    },
    adapters: [],
    policies: {
      availability: "keep_local",
      structural_changes: "approve",
      archive: "manual",
      cloud_sync: "disabled",
      capture_ignore: {
        format: "folderbase-capture-ignore-v1",
        rules: [],
      },
    },
  });
}

function legacyRootManifest() {
  return encodeJson({
    $schema: "https://folderbase.ai/protocol/0.2/folderbase.schema.json",
    protocol_version: "0.2.0+reconstruction",
    folderbase: {
      id: FOLDERBASE_ID,
      name: "Legacy root reconstruction conformance fixture",
      kind: "project",
      status: "active",
      created_at: "2026-08-06T00:00:00Z",
      entry: "FOLDERBASE.md",
    },
    adapters: [],
    policies: {
      availability: "keep_local",
      structural_changes: "approve",
      archive: "manual",
      cloud_sync: "disabled",
    },
  });
}

function chunkManifest(content) {
  const digest = encodedSha256(content);
  return {
    format: "folderbase-chunk-manifest-v1",
    algorithm: "folderbase-cdc-v1+sha256",
    profile: "standard-v1",
    minimum_chunk_bytes: 262144,
    average_chunk_bytes: 1048576,
    maximum_chunk_bytes: 4194304,
    object_sha256: digest,
    object_bytes: content.length,
    chunks: content.length === 0
      ? []
      : [{ index: 0, offset: 0, bytes: content.length, sha256: digest }],
  };
}

function fixtureModel(profile) {
  const legacy = profile === "legacy-0.4";
  const rootManifest = legacy ? legacyRootManifest() : canonicalRootManifest();
  const regularFiles = [
    ...(legacy ? [
      regular(".folderbaseignore", "0e0", "node_modules/\n"),
      regular("FOLDERBASE.md", "0f0", "# Legacy reconstructed Folderbase\n"),
    ] : []),
    regular("README.md", "010", "# Exact reconstructed root\n\nOpaque files stay opaque.\n"),
    regular("archives/bundle.zip", "020", Buffer.from("504b0304140000000000", "hex")),
    regular("data/table.csv", "030", "name,value\nalpha,1\n"),
    regular("databases/state.sqlite", "040", Buffer.concat([
      Buffer.from("SQLite format 3\0", "ascii"),
      Buffer.alloc(32, 0x53),
    ])),
    regular("documents/Brief.pdf", "050", "%PDF-1.7\n1 0 obj<</Type/Catalog>>endobj\n%%EOF\n"),
    regular("media/clip.mp4", "060", Buffer.from("00000018667479706d70343200000000", "hex")),
    regular("notes/Moved.md", "070", "same immutable bytes after a move\n"),
    regular("office/Proposal.docx", "080", Buffer.from("504b0304140000000000646f63782d6f7061717565", "hex")),
    regular("opaque/unknown.bin", "090", Buffer.from([0x00, 0xff, 0x7f, 0x42, 0x00, 0x19])),
    regular("repo/.git/HEAD", "0a0", "ref: refs/heads/main\n"),
    regular("scripts/run.sh", "0b0", "#!/bin/sh\nprintf '%s\\n' reconstructed\n", true),
  ];
  const moved = regularFiles.find(({ binding }) => binding.path === "notes/Moved.md");
  const deleted = regular("deleted/approved-proposal.docx", "0c0", Buffer.from(
    "504b030414000000000072657461696e65642d746f6d6273746f6e65",
    "hex",
  ));
  const directories = [
    ["archives", "101"],
    ["data", "102"],
    ["databases", "103"],
    ["documents", "104"],
    ["empty", "105"],
    ["links", "106"],
    ["media", "107"],
    ["notes", "108"],
    ["office", "109"],
    ["opaque", "10a"],
    ["repo", "10b"],
    ["repo/.git", "10c"],
    ["scripts", "10d"],
  ].map(([path, suffix]) => directory(path, suffix));
  const symlink = {
    path: "links/brief-link",
    object_id: uuidId("obj_", "0d0"),
    lifecycle: "live",
    kind: "symlink",
    object_version_id: uuidId("version_", "0d01"),
    target: "../documents/Brief.pdf",
    target_safety: "relative-within-folderbase",
  };
  const version = {
    format: "folderbase-version-v1",
    protocol_version: legacy ? "0.4" : "0.5",
    folderbase_id: FOLDERBASE_ID,
    version_id: FOLDERBASE_VERSION_ID,
    parents: [],
    created_at: "2026-08-06T00:00:00Z",
    path_policy: {
      format: "folderbase-portable-path-v1",
      normalization: "NFC",
      normalization_unicode_version: "17.0.0",
      case_folding: "full-default",
      case_folding_unicode_version: "9.0.0",
    },
    root_manifest: {
      path: ".folderbase/manifest.json",
      object_version_id: uuidId("version_", "001"),
      content_sha256: encodedSha256(rootManifest),
      bytes: rootManifest.length,
    },
    bindings: exactSort([
      ...directories,
      ...regularFiles.map(({ binding }) => binding),
      symlink,
    ], ({ path }) => path),
    tombstones: exactSort([
      {
        path: "archive/Moved.md",
        object_id: moved.binding.object_id,
        lifecycle: "deleted",
        deleted_kind: "regular_file",
        last_object_version_id: moved.binding.object_version_id,
      },
      {
        path: deleted.binding.path,
        object_id: deleted.binding.object_id,
        lifecycle: "deleted",
        deleted_kind: "regular_file",
        last_object_version_id: deleted.binding.object_version_id,
      },
    ], ({ path }) => path),
    exclusions: [
      {
        path: "vendors/nested",
        kind: "nested_folderbase",
        reason: "nested-folderbase-boundary",
      },
    ],
  };
  return { rootManifest, regularFiles, deleted, version };
}

function addReference(references, binding, role, content) {
  const existing = references.get(binding.object_version_id);
  if (existing) {
    assert.equal(existing.object_id, binding.object_id);
    assert.deepEqual(existing.content, content);
    existing.roles.add(role);
    return;
  }
  references.set(binding.object_version_id, {
    object_id: binding.object_id,
    roles: new Set([role]),
    content,
  });
}

async function writeFixture(output, profile) {
  const source = resolve(output);
  assert.deepEqual(await readdir(source), [], "fixture output directory must be empty");
  await Promise.all([
    mkdir(join(source, "manifests")),
    mkdir(join(source, "chunks")),
  ]);
  const { rootManifest, regularFiles, deleted, version } = fixtureModel(profile);
  const references = new Map();
  references.set(version.root_manifest.object_version_id, {
    roles: new Set(["root_manifest"]),
    content: rootManifest,
  });
  for (const file of regularFiles) {
    addReference(references, file.binding, "live_regular_file", file.content);
  }
  addReference(references, deleted.binding, "retained_tombstone", deleted.content);
  const moved = regularFiles.find(({ binding }) => binding.path === "notes/Moved.md");
  addReference(references, moved.binding, "retained_tombstone", moved.content);

  const manifestBytes = new Map();
  const chunks = new Map();
  const packageReferences = [];
  for (const [objectVersionId, reference] of references) {
    const manifest = chunkManifest(reference.content);
    const manifestDigest = chunkManifestSha256(manifest);
    manifestBytes.set(manifestDigest, encodeJson(manifest));
    for (const chunk of manifest.chunks) chunks.set(chunk.sha256, reference.content);
    packageReferences.push({
      object_version_id: objectVersionId,
      ...(reference.object_id === undefined ? {} : { object_id: reference.object_id }),
      roles: [...reference.roles].sort(),
      chunk_manifest_sha256: manifestDigest,
    });
  }
  const versionBytes = encodeJson(version);
  const index = {
    format: "folderbase-root-reconstruction-package-v1",
    folderbase_id: version.folderbase_id,
    folderbase_version_id: version.version_id,
    canonical_version_sha256: canonicalFolderbaseVersionSha256(version),
    encoded_version_sha256: encodedSha256(versionBytes),
    limits: { ...LIMITS },
    references: exactSort(packageReferences, ({ object_version_id }) => object_version_id),
  };
  const indexBytes = encodeJson(index);
  const packageIndexSha256 = encodedSha256(indexBytes);
  const request = {
    format: "folderbase-root-reconstruction-request-v1",
    operation_id: OPERATION_ID,
    package_index_sha256: packageIndexSha256,
  };
  const expected = {
    folderbase_id: version.folderbase_id,
    folderbase_version_id: version.version_id,
    canonical_version_sha256: index.canonical_version_sha256,
    encoded_version_sha256: index.encoded_version_sha256,
    package_index_sha256: packageIndexSha256,
    request_sha256: rootReconstructionRequestSha256(request),
    verified_object_count: index.references.length,
    version_authenticated_object_count: index.references.filter(({ roles }) =>
      roles.includes("root_manifest") || roles.includes("live_regular_file")).length,
    retained_tombstone_object_count: index.references.filter(({ roles }) =>
      roles.includes("retained_tombstone")).length,
    visible_entry_count: version.bindings.length,
    verified_opaque_bytes: [...references.values()].reduce(
      (total, { content }) => total + content.length,
      0,
    ),
  };

  await Promise.all([
    writeFile(join(source, "index.json"), indexBytes),
    writeFile(join(source, "version.json"), versionBytes),
    ...[...manifestBytes].map(([digest, bytes]) =>
      writeFile(join(source, "manifests", `${digest}.json`), bytes)),
    ...[...chunks].map(([digest, bytes]) => writeFile(join(source, "chunks", digest), bytes)),
  ]);
  return { index, request, version, expected };
}

export async function writeCanonicalFixture(output) {
  return writeFixture(output, "canonical-0.5");
}

export async function writeLegacyFixture(output) {
  return writeFixture(output, "legacy-0.4");
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const flag = process.argv.indexOf("--output");
  if (flag === -1 || !process.argv[flag + 1] || process.argv.length !== 4) {
    throw new Error("usage: fixture-generator.mjs --output /path/to/empty-directory");
  }
  const fixture = await writeCanonicalFixture(process.argv[flag + 1]);
  process.stdout.write(`${JSON.stringify(fixture.expected, null, 2)}\n`);
}

#!/usr/bin/env node

import { execFileSync } from "node:child_process";
import {
  lstatSync,
  readFileSync,
  readdirSync,
} from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const repositoryRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const releaseManifestPath = join(
  repositoryRoot,
  "protocol",
  "releases",
  "0.4",
  "folderbase-version-v1.candidate.json",
);
const release = JSON.parse(readFileSync(releaseManifestPath, "utf8"));
const expectedKeys = [
  "cargo_package_role",
  "contract",
  "distribution",
  "files",
  "format",
  "protocol_version",
  "repository",
  "status",
];
if (
  JSON.stringify(Object.keys(release).sort()) !== JSON.stringify(expectedKeys)
) {
  throw new Error("protocol source-release manifest is not a closed record");
}
const expectedHeader = {
  format: "folderbase-protocol-source-release-v1",
  status: "candidate",
  protocol_version: "0.4",
  contract: "folderbase-version-v1",
  distribution: "repository-tag-source-archive",
  repository: "https://github.com/chalkagents/folderbase",
  cargo_package_role: "runtime-implementation-only",
};
for (const [key, value] of Object.entries(expectedHeader)) {
  if (release[key] !== value) {
    throw new Error(`unexpected release-manifest ${key}: ${release[key]}`);
  }
}
if (
  !Array.isArray(release.files) ||
  release.files.length === 0 ||
  !release.files.every((path) => typeof path === "string")
) {
  throw new Error("protocol source-release files must be a non-empty string set");
}
const sortedFiles = [...release.files].sort();
if (
  new Set(release.files).size !== release.files.length ||
  JSON.stringify(sortedFiles) !== JSON.stringify(release.files)
) {
  throw new Error("protocol source-release files must be unique and sorted");
}
for (const path of release.files) {
  const absolute = join(repositoryRoot, path);
  const stat = lstatSync(absolute);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size === 0) {
    throw new Error(`protocol source-release member is not a nonempty regular file: ${path}`);
  }
  if (path.endsWith(".json")) {
    JSON.parse(readFileSync(absolute, "utf8"));
  }
  if (
    path.endsWith(".sha256") &&
    !/^[0-9a-f]{64}\n?$/.test(readFileSync(absolute, "utf8"))
  ) {
    throw new Error(`invalid SHA-256 sidecar: ${path}`);
  }
}

const conformanceRoot = join(
  repositoryRoot,
  "protocol",
  "conformance",
  "folderbase-version",
);
function walk(directory) {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const absolute = join(directory, entry.name);
    if (entry.isDirectory()) return walk(absolute);
    if (!entry.isFile() || entry.isSymbolicLink()) {
      throw new Error(`non-regular conformance member: ${absolute}`);
    }
    return [relative(repositoryRoot, absolute)];
  });
}
const actualConformanceFiles = walk(conformanceRoot).sort();
const expectedReleaseFileCount = 32;
const requiredNonConformanceFiles = [
  "crates/folderbase-core/src/folderbase_version.rs",
  "crates/folderbase-core/tests/folderbase_version_conformance.rs",
  "docs/adr/0004-seal-portable-folderbase-versions-as-bounded-full-state.md",
  "protocol/releases/0.4/folderbase-version-v1.candidate.json",
  "protocol/schemas/0.4/folderbase-version.schema.json",
  "scripts/verify-folderbase-version-digest-vectors.mjs",
  "scripts/verify-folderbase-version-distribution.mjs",
];
function validateReleaseInventory(files) {
  if (files.length !== expectedReleaseFileCount) {
    throw new Error(
      `protocol source-release inventory must contain exactly ${expectedReleaseFileCount} files`,
    );
  }
  const declaredConformanceFiles = files
    .filter((path) =>
      path.startsWith("protocol/conformance/folderbase-version/"),
    )
    .sort();
  if (
    JSON.stringify(actualConformanceFiles) !==
    JSON.stringify(declaredConformanceFiles)
  ) {
    throw new Error(
      "release manifest does not enumerate the exact conformance tree",
    );
  }
  const declaredNonConformanceFiles = files
    .filter(
      (path) =>
        !path.startsWith("protocol/conformance/folderbase-version/"),
    )
    .sort();
  if (
    JSON.stringify(requiredNonConformanceFiles) !==
    JSON.stringify(declaredNonConformanceFiles)
  ) {
    throw new Error(
      "release manifest does not enumerate the exact non-conformance contract surface",
    );
  }
}
validateReleaseInventory(release.files);
// Every verifier run proves that no required source-release member can be
// omitted or replaced while leaving the conformance subtree untouched.
for (const requiredPath of requiredNonConformanceFiles) {
  const withoutRequiredPath = release.files.filter(
    (path) => path !== requiredPath,
  );
  let omissionRejected = false;
  try {
    validateReleaseInventory(withoutRequiredPath);
  } catch {
    omissionRejected = true;
  }
  if (!omissionRejected) {
    throw new Error(
      `release inventory verifier is insensitive to omission: ${requiredPath}`,
    );
  }
  const withReplacementPath = release.files
    .map((path) => (path === requiredPath ? "README.md" : path))
    .sort();
  let replacementRejected = false;
  try {
    validateReleaseInventory(withReplacementPath);
  } catch {
    replacementRejected = true;
  }
  if (!replacementRejected) {
    throw new Error(
      `release inventory verifier is insensitive to replacement: ${requiredPath}`,
    );
  }
}

const generator = join(
  conformanceRoot,
  "invalid",
  "generate-runtime-limit-vector.mjs",
);
function generated(name) {
  return JSON.parse(
    execFileSync(process.execPath, [generator, name], {
      encoding: "utf8",
      maxBuffer: 16 * 1024 * 1024,
    }),
  );
}
const aggregate = generated("aggregate-split");
if (
  aggregate.bindings.length !== 8_193 ||
  aggregate.tombstones.length !== 8_192 ||
  aggregate.exclusions.length !== 0 ||
  aggregate.bindings.length + aggregate.tombstones.length !== 16_385
) {
  throw new Error("aggregate-split vector does not cross only the aggregate cap");
}
const component = generated("component-byte-limit").bindings.at(-1).path;
if ([...component].length !== 128 || Buffer.byteLength(component) !== 256) {
  throw new Error("component-byte-limit vector is not the declared counterexample");
}
const path = generated("path-byte-limit").bindings.at(-1).path;
if ([...path].length > 4_096 || Buffer.byteLength(path) !== 4_097) {
  throw new Error("path-byte-limit vector is not the declared counterexample");
}
const depth = generated("depth-limit").bindings.at(-1).path;
if (depth.split("/").length !== 129) {
  throw new Error("depth-limit vector is not the declared counterexample");
}

const cargoManifest = readFileSync(
  join(repositoryRoot, "crates", "folderbase-core", "Cargo.toml"),
  "utf8",
);
for (const declaration of [
  '[package.metadata.folderbase-protocol]',
  'contract = "folderbase-version-v1"',
  'protocol-version = "0.4"',
  'distribution = "repository-tag-source-archive"',
  'cargo-package-role = "runtime-implementation-only"',
]) {
  if (!cargoManifest.includes(declaration)) {
    throw new Error(`folderbase-core package metadata omits: ${declaration}`);
  }
}

console.log(
  `Folderbase Version repository distribution verified: ${release.files.length} files`,
);

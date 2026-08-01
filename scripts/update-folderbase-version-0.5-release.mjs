#!/usr/bin/env node

import { createHash } from "node:crypto";
import {
  lstatSync,
  readFileSync,
  readdirSync,
  writeFileSync,
} from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const repositoryRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const releaseRoot = join(repositoryRoot, "protocol", "releases", "0.5");
const manifestPath = join(releaseRoot, "folderbase-version-v1.json");
const sidecarPath = join(releaseRoot, "folderbase-version-v1.sha256");

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function walk(directory) {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const absolute = join(directory, entry.name);
    if (entry.isDirectory()) return walk(absolute);
    if (!entry.isFile() || entry.isSymbolicLink()) {
      throw new Error(`non-regular release member: ${absolute}`);
    }
    return [relative(repositoryRoot, absolute)];
  });
}

const runtimeClosure = [
  "Cargo.lock",
  "Cargo.toml",
  "LICENSE",
  "NOTICE",
  "README.md",
  ...walk(join(repositoryRoot, "crates", "folderbase-core")),
  ...walk(join(repositoryRoot, "crates", "folderbase-cli")),
];
const requiredFiles = [
  ".gitattributes",
  ".github/workflows/ci.yml",
  "README.md",
  "docs/adr/0003-attest-exact-folderbase-roots.md",
  "docs/adr/0004-seal-portable-folderbase-versions-as-bounded-full-state.md",
  "docs/adr/0005-plan-capture-before-sealing-or-moving-local-head.md",
  "docs/adr/0006-version-ordinary-folder-roots-and-optional-narratives.md",
  "docs/adr/0008-distribute-native-core-through-thin-installers.md",
  "docs/adr/0009-freeze-the-minimal-core-compatibility-contract.md",
  "docs/cli-json-v1.md",
  "docs/compatibility-v1.md",
  "docs/protocol-spec.md",
  "docs/releasing.md",
  "docs/reorganization-protocol.md",
  "docs/template-protocol.md",
  "protocol/README.md",
  "protocol/compatibility/v1/contract.json",
  "protocol/schemas/0.2/template-application.schema.json",
  "protocol/schemas/0.3/chunk-manifest.schema.json",
  "protocol/schemas/0.3/reorganization-draft.schema.json",
  "protocol/schemas/0.4/folderbase-version.schema.json",
  "protocol/schemas/0.5/folderbase-version.schema.json",
  "protocol/schemas/0.5/folderbase.schema.json",
  "protocol/schemas/cli/1/folderbase-cli-json.schema.json",
  "scripts/test-extracted-package-source-sensitivity.sh",
  "scripts/test-extracted-packages.sh",
  "scripts/test-package-install.sh",
  "scripts/tests/compatibility-contract.test.mjs",
  "scripts/update-folderbase-version-0.5-release.mjs",
  "scripts/verify-folderbase-version-0.5-digest-vectors.mjs",
  "scripts/verify-folderbase-version-0.5-distribution.mjs",
];
const fixtureClosure = [
  "fixtures/client-company-2-shaped-unmanaged.expected.json",
  ...walk(join(repositoryRoot, "fixtures", "client-company-2-shaped-unmanaged")),
];
const conformanceClosure = [
  ...walk(join(repositoryRoot, "protocol", "conformance", "chunk-manifest")),
  ...walk(join(repositoryRoot, "protocol", "conformance", "folderbase-version")),
  ...walk(
    join(repositoryRoot, "protocol", "conformance", "folderbase-version-0.5"),
  ),
  ...walk(join(repositoryRoot, "protocol", "conformance", "cli-json-v1")),
];
const paths = [
  ...runtimeClosure,
  ...requiredFiles,
  ...fixtureClosure,
  ...conformanceClosure,
];
const uniquePaths = [...new Set(paths)].sort();
const files = uniquePaths.map((path) => {
  const absolute = join(repositoryRoot, path);
  const file = lstatSync(absolute);
  if (!file.isFile() || file.isSymbolicLink() || file.size === 0) {
    throw new Error(`invalid release member: ${path}`);
  }
  return { path, sha256: sha256(readFileSync(absolute)) };
});
const manifest = {
  format: "folderbase-protocol-source-release-v2",
  status: "released",
  protocol_version: "0.5",
  contract: "folderbase-version-v1",
  distribution: "repository-tag-source-archive",
  repository: "https://github.com/chalkagents/folderbase",
  files,
};
const encoded = `${JSON.stringify(manifest, null, 2)}\n`;
writeFileSync(manifestPath, encoded);
writeFileSync(sidecarPath, `${sha256(encoded)}\n`);
process.stdout.write(`Updated protocol 0.5 release manifest: ${files.length} files\n`);

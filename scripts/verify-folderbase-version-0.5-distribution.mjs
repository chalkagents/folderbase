#!/usr/bin/env node

import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import {
  lstatSync,
  readFileSync,
  readdirSync,
} from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const repositoryRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const releaseRoot = join(repositoryRoot, "protocol", "releases", "0.5");
const releaseManifestPath = join(
  releaseRoot,
  "folderbase-version-v1.json",
);
const releaseSidecarPath = join(
  releaseRoot,
  "folderbase-version-v1.sha256",
);
const conformanceRoot = join(
  repositoryRoot,
  "protocol",
  "conformance",
  "folderbase-version-0.5",
);

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function walk(directory) {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const absolute = join(directory, entry.name);
    if (entry.isDirectory()) return walk(absolute);
    if (!entry.isFile() || entry.isSymbolicLink()) {
      throw new Error(`non-regular distribution member: ${absolute}`);
    }
    return [relative(repositoryRoot, absolute)];
  });
}

const releaseDirectoryMembers = readdirSync(releaseRoot).sort();
if (
  JSON.stringify(releaseDirectoryMembers) !==
  JSON.stringify([
    "folderbase-version-v1.json",
    "folderbase-version-v1.sha256",
  ])
) {
  throw new Error("protocol 0.5 release directory is not a closed pair");
}

const manifestBytes = readFileSync(releaseManifestPath);
const release = JSON.parse(manifestBytes);
const expectedManifestKeys = [
  "contract",
  "distribution",
  "files",
  "format",
  "protocol_version",
  "repository",
  "status",
];
if (
  JSON.stringify(Object.keys(release).sort()) !==
  JSON.stringify(expectedManifestKeys)
) {
  throw new Error("protocol 0.5 source-release manifest is not a closed record");
}
const expectedHeader = {
  format: "folderbase-protocol-source-release-v2",
  status: "candidate",
  protocol_version: "0.5",
  contract: "folderbase-version-v1",
  distribution: "repository-candidate-source-tree",
  repository: "https://github.com/chalkagents/folderbase",
};
for (const [key, value] of Object.entries(expectedHeader)) {
  if (release[key] !== value) {
    throw new Error(`unexpected protocol 0.5 release ${key}: ${release[key]}`);
  }
}

const releaseSidecar = readFileSync(releaseSidecarPath, "utf8");
if (!/^[0-9a-f]{64}\n?$/.test(releaseSidecar)) {
  throw new Error("invalid protocol 0.5 release-manifest SHA-256 sidecar");
}
if (releaseSidecar.trim() !== sha256(manifestBytes)) {
  throw new Error("protocol 0.5 release-manifest sidecar does not match exact bytes");
}

if (
  !Array.isArray(release.files) ||
  release.files.length === 0 ||
  !release.files.every(
    (member) =>
      member &&
      typeof member === "object" &&
      !Array.isArray(member) &&
      JSON.stringify(Object.keys(member).sort()) ===
        JSON.stringify(["path", "sha256"]) &&
      typeof member.path === "string" &&
      /^[0-9a-f]{64}$/.test(member.sha256),
  )
) {
  throw new Error("protocol 0.5 files must be closed path/SHA-256 records");
}
const declaredPaths = release.files.map((member) => member.path);
if (
  new Set(declaredPaths).size !== declaredPaths.length ||
  JSON.stringify([...declaredPaths].sort()) !== JSON.stringify(declaredPaths)
) {
  throw new Error("protocol 0.5 source-release paths must be unique and sorted");
}

const exactConformanceFiles = walk(conformanceRoot).sort();
const implementingRustFiles = [
  "crates/folderbase-cli/src/main.rs",
  "crates/folderbase-cli/tests/cli.rs",
  "crates/folderbase-core/Cargo.toml",
  "crates/folderbase-core/src/error.rs",
  "crates/folderbase-core/src/folder_analysis.rs",
  "crates/folderbase-core/src/folderbase_capture.rs",
  "crates/folderbase-core/src/folderbase_seal.rs",
  "crates/folderbase-core/src/folderbase_state.rs",
  "crates/folderbase-core/src/folderbase_version.rs",
  "crates/folderbase-core/src/initialization.rs",
  "crates/folderbase-core/src/lib.rs",
  "crates/folderbase-core/src/local_versions.rs",
  "crates/folderbase-core/src/migration.rs",
  "crates/folderbase-core/src/model.rs",
  "crates/folderbase-core/src/protocol_upgrade.rs",
  "crates/folderbase-core/src/reorganization.rs",
  "crates/folderbase-core/src/root_attestation.rs",
  "crates/folderbase-core/src/template_expansion.rs",
  "crates/folderbase-core/src/transfer_source.rs",
  "crates/folderbase-core/src/traversal_policy.rs",
  "crates/folderbase-core/src/validation.rs",
  "crates/folderbase-core/src/workspace.rs",
  "crates/folderbase-core/tests/fb41h_optional_narratives.rs",
  "crates/folderbase-core/tests/folderbase_version_05_conformance.rs",
  "crates/folderbase-core/tests/protocol_upgrade_security.rs",
];
const requiredNonConformanceFiles = [
  ".github/workflows/ci.yml",
  "README.md",
  "docs/adr/0003-attest-exact-folderbase-roots.md",
  "docs/adr/0004-seal-portable-folderbase-versions-as-bounded-full-state.md",
  "docs/adr/0005-plan-capture-before-sealing-or-moving-local-head.md",
  "docs/adr/0006-version-ordinary-folder-roots-and-optional-narratives.md",
  "docs/protocol-spec.md",
  "docs/reorganization-protocol.md",
  "docs/template-protocol.md",
  "protocol/README.md",
  "protocol/schemas/0.2/template-application.schema.json",
  "protocol/schemas/0.3/reorganization-draft.schema.json",
  "protocol/schemas/0.5/folderbase-version.schema.json",
  "protocol/schemas/0.5/folderbase.schema.json",
  "scripts/test-extracted-packages.sh",
  "scripts/test-package-install.sh",
  "scripts/verify-folderbase-version-0.5-digest-vectors.mjs",
  "scripts/verify-folderbase-version-0.5-distribution.mjs",
];
const expectedPaths = [
  ...exactConformanceFiles,
  ...implementingRustFiles,
  ...requiredNonConformanceFiles,
].sort();
if (JSON.stringify(declaredPaths) !== JSON.stringify(expectedPaths)) {
  throw new Error(
    "protocol 0.5 release manifest does not enumerate the exact candidate surface",
  );
}

for (const member of release.files) {
  const absolute = join(repositoryRoot, member.path);
  const stat = lstatSync(absolute);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size === 0) {
    throw new Error(`invalid protocol 0.5 member: ${member.path}`);
  }
  const bytes = readFileSync(absolute);
  if (sha256(bytes) !== member.sha256) {
    throw new Error(`protocol 0.5 member digest mismatch: ${member.path}`);
  }
  if (member.path.endsWith(".json")) JSON.parse(bytes);
  if (
    member.path.endsWith(".sha256") &&
    !/^[0-9a-f]{64}\n?$/.test(bytes.toString("utf8"))
  ) {
    throw new Error(`invalid member sidecar: ${member.path}`);
  }
}

const versionSchema = JSON.parse(
  readFileSync(
    join(repositoryRoot, "protocol", "schemas", "0.5", "folderbase-version.schema.json"),
    "utf8",
  ),
);
if (
  versionSchema.additionalProperties !== false ||
  versionSchema.properties.protocol_version.const !== "0.5" ||
  "minItems" in versionSchema.properties.bindings ||
  !versionSchema.$defs.portable_path.pattern.includes("\\.folderbase")
) {
  throw new Error("protocol 0.5 Version schema does not encode the exact delta");
}

const rootSchema = JSON.parse(
  readFileSync(
    join(repositoryRoot, "protocol", "schemas", "0.5", "folderbase.schema.json"),
    "utf8",
  ),
);
const captureSchema = rootSchema.properties.policies.properties.capture_ignore;
const ruleSchema = captureSchema.properties.rules.items;
const safeAdapterPath = new RegExp(rootSchema.$defs.safeRelativePath.pattern);
const unsafeAdapterPaths = [
  ".",
  "AGENTS\0.md",
  "C:/AGENTS.md",
  "../AGENTS.md",
  ".folderbase",
  ".FoLdErBaSe/AGENTS.md",
  ".git",
  ".GiT/AGENTS.md",
];
if (
  rootSchema.properties.protocol_version.const !== "0.5.0" ||
  !rootSchema.properties.policies.required.includes("capture_ignore") ||
  captureSchema.additionalProperties !== false ||
  captureSchema.properties.format.const !== "folderbase-capture-ignore-v1" ||
  captureSchema.properties.rules.maxItems !== 1024 ||
  ruleSchema.type !== "string" ||
  ruleSchema.minLength !== 1 ||
  ruleSchema.maxLength !== 4096 ||
  !ruleSchema.pattern.includes("\\u0000") ||
  !safeAdapterPath.test("AGENTS.md") ||
  unsafeAdapterPaths.some((path) => safeAdapterPath.test(path))
) {
  throw new Error("protocol 0.5 root-manifest schema is not the strict profile");
}

const templateApplicationSchema = JSON.parse(
  readFileSync(
    join(
      repositoryRoot,
      "protocol",
      "schemas",
      "0.2",
      "template-application.schema.json",
    ),
    "utf8",
  ),
);
const comparisonSchema = templateApplicationSchema.properties.comparison;
const unmanagedComparison = comparisonSchema.allOf.find(
  (rule) => rule?.if?.properties?.source?.const === "unmanaged",
);
if (
  !comparisonSchema.properties.source.enum.includes("unmanaged") ||
  unmanagedComparison?.then?.properties?.version?.const !== "0.0.0" ||
  unmanagedComparison?.then?.properties?.application_id?.type !== "null"
) {
  throw new Error("native 0.5 unmanaged template adoption is not exact");
}

const reorganizationDraftSchema = JSON.parse(
  readFileSync(
    join(
      repositoryRoot,
      "protocol",
      "schemas",
      "0.3",
      "reorganization-draft.schema.json",
    ),
    "utf8",
  ),
);
const protectedRootPattern =
  reorganizationDraftSchema.$defs.ordinaryContentPath.allOf
    .map((rule) => rule?.not?.pattern)
    .filter(Boolean)
    .find((pattern) => pattern.includes("[aA][gG][eE][nN][tT][sS]"));
const protectedRoot = new RegExp(protectedRootPattern);
if (
  protectedRoot.test("FOLDERBASE.md") ||
  !protectedRoot.test("AGENTS.md") ||
  !protectedRoot.test("CLAUDE.md") ||
  !protectedRoot.test(".folderbaseignore")
) {
  throw new Error("protocol 0.5 ordinary FOLDERBASE.md path policy is not exact");
}

const versionTopLevelKeys = [
  "bindings",
  "created_at",
  "exclusions",
  "folderbase_id",
  "format",
  "parents",
  "path_policy",
  "protocol_version",
  "root_manifest",
  "tombstones",
  "version_id",
];
function versionDeltaErrors(value) {
  const errors = [];
  if (
    JSON.stringify(Object.keys(value).sort()) !==
    JSON.stringify(versionTopLevelKeys)
  ) {
    errors.push("top-level envelope");
  }
  if (value.format !== "folderbase-version-v1") errors.push("format");
  if (value.protocol_version !== "0.5") errors.push("protocol_version");
  if (!Array.isArray(value.bindings)) {
    errors.push("bindings");
  } else if (
    value.bindings.some(
      (binding) =>
        typeof binding.path !== "string" ||
        binding.path === ".folderbase" ||
        binding.path.startsWith(".folderbase/"),
    )
  ) {
    errors.push("private binding");
  }
  return errors;
}

const markerless = JSON.parse(
  readFileSync(join(conformanceRoot, "valid", "minimal-ordinary-v1.json"), "utf8"),
);
if (versionDeltaErrors(markerless).length !== 0 || markerless.bindings.length !== 0) {
  throw new Error("native protocol 0.5 markerless Version vector is not valid");
}
const optionalRootFiles = JSON.parse(
  readFileSync(join(conformanceRoot, "valid", "optional-root-files-v1.json"), "utf8"),
);
if (
  versionDeltaErrors(optionalRootFiles).length !== 0 ||
  JSON.stringify(optionalRootFiles.bindings.map(({ path }) => path)) !==
    JSON.stringify([".folderbaseignore", "FOLDERBASE.md"])
) {
  throw new Error("protocol 0.5 optional root-file vector is not exact");
}
for (const name of readdirSync(join(conformanceRoot, "invalid"))) {
  if (!name.endsWith(".json")) continue;
  const value = JSON.parse(
    readFileSync(join(conformanceRoot, "invalid", name), "utf8"),
  );
  if (versionDeltaErrors(value).length === 0) {
    throw new Error(`Version invalid vector was accepted: ${name}`);
  }
}

function rootManifest05Errors(value) {
  const errors = [];
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return ["root record"];
  }
  if (
    value.$schema !== undefined &&
    value.$schema !== "https://folderbase.ai/protocol/0.5/folderbase.schema.json"
  ) {
    errors.push("$schema");
  }
  if (value.protocol_version !== "0.5.0") errors.push("protocol_version");
  const folderbase = value.folderbase;
  if (!folderbase || typeof folderbase !== "object" || Array.isArray(folderbase)) {
    errors.push("folderbase");
  } else {
    if (
      typeof folderbase.id !== "string" ||
      !/^folderbase_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(
        folderbase.id,
      )
    ) {
      errors.push("folderbase id");
    }
    if (typeof folderbase.name !== "string" || folderbase.name.length === 0) {
      errors.push("folderbase name");
    }
    if (
      ![
        "person",
        "organization",
        "engagement",
        "project",
        "customer",
        "temporary",
        "custom",
      ].includes(folderbase.kind)
    ) {
      errors.push("folderbase kind");
    }
    if (!["active", "paused", "archived"].includes(folderbase.status)) {
      errors.push("folderbase status");
    }
    if (
      typeof folderbase.created_at !== "string" ||
      !/^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?(?:Z|[+-][0-9]{2}:[0-9]{2})$/.test(
        folderbase.created_at,
      ) ||
      Number.isNaN(Date.parse(folderbase.created_at))
    ) {
      errors.push("folderbase created_at");
    }
    if (
      folderbase.template_provenance !== undefined &&
      (!folderbase.template_provenance ||
        typeof folderbase.template_provenance !== "object" ||
        Array.isArray(folderbase.template_provenance))
    ) {
      errors.push("template provenance");
    }
  }
  const policies = value.policies;
  if (!policies || typeof policies !== "object" || Array.isArray(policies)) {
    errors.push("policies");
  } else {
    if (!["keep_local", "managed", "cloud_only"].includes(policies.availability)) {
      errors.push("availability");
    }
    if (
      !["suggest", "approve", "autonomous"].includes(
        policies.structural_changes,
      )
    ) {
      errors.push("structural_changes");
    }
    if (!["manual", "approve", "automatic"].includes(policies.archive)) {
      errors.push("archive");
    }
    if (!["disabled", "enabled"].includes(policies.cloud_sync)) {
      errors.push("cloud_sync");
    }
  }
  if (value.adapters !== undefined) {
    if (!Array.isArray(value.adapters)) {
      errors.push("adapters");
    } else {
      for (const adapter of value.adapters) {
        if (
          !adapter ||
          typeof adapter !== "object" ||
          Array.isArray(adapter) ||
          typeof adapter.agent !== "string" ||
          !/^[a-z0-9][a-z0-9_-]*$/.test(adapter.agent) ||
          typeof adapter.path !== "string" ||
          !safeAdapterPath.test(adapter.path)
        ) {
          errors.push("adapter");
        }
      }
    }
  }
  const capture = value?.policies?.capture_ignore;
  if (!capture || typeof capture !== "object" || Array.isArray(capture)) {
    errors.push("capture_ignore");
    return errors;
  }
  if (
    JSON.stringify(Object.keys(capture).sort()) !==
    JSON.stringify(["format", "rules"])
  ) {
    errors.push("capture members");
  }
  if (capture.format !== "folderbase-capture-ignore-v1") {
    errors.push("capture format");
  }
  if (!Array.isArray(capture.rules) || capture.rules.length > 1024) {
    errors.push("capture rules");
  } else {
    for (const rule of capture.rules) {
      if (
        typeof rule !== "string" ||
        [...rule].length === 0 ||
        [...rule].length > 4096 ||
        rule.includes("\0") ||
        Buffer.byteLength(rule, "utf8") > 4096
      ) {
        errors.push("capture rule");
      }
    }
  }
  return errors;
}

for (const name of readdirSync(
  join(conformanceRoot, "root-manifest", "valid"),
)) {
  if (!name.endsWith(".json")) continue;
  const value = JSON.parse(
    readFileSync(
      join(conformanceRoot, "root-manifest", "valid", name),
      "utf8",
    ),
  );
  if (rootManifest05Errors(value).length !== 0) {
    throw new Error(`native protocol 0.5 root-manifest vector is not valid: ${name}`);
  }
}
for (const name of readdirSync(
  join(conformanceRoot, "root-manifest", "invalid"),
)) {
  if (!name.endsWith(".json")) continue;
  const value = JSON.parse(
    readFileSync(
      join(conformanceRoot, "root-manifest", "invalid", name),
      "utf8",
    ),
  );
  if (rootManifest05Errors(value).length === 0) {
    throw new Error(`root-manifest invalid vector was accepted: ${name}`);
  }
}

const frozen04 = new Map([
  [
    "protocol/releases/0.4/folderbase-version-v1.json",
    "50b9a61887acd472a154860f2a99b024b3b1f34e4e36ddafec3c6d6b2a4bc9fd",
  ],
  [
    "protocol/schemas/0.4/folderbase-version.schema.json",
    "2327e2c795cc67123f227bd9ab98e7d7d2ba0bef540cb1c493d910172a38597b",
  ],
  [
    "scripts/verify-folderbase-version-distribution.mjs",
    "836c05bf1b20259c666526b2c18d3d1cef69233edd7c66d7f38b2f615510ab5b",
  ],
  [
    "scripts/verify-folderbase-version-digest-vectors.mjs",
    "46f37335b05337367acca98607472548665fee33bfb57d5a77ef765ae75dba78",
  ],
]);
for (const [path, expected] of frozen04) {
  if (sha256(readFileSync(join(repositoryRoot, path))) !== expected) {
    throw new Error(`frozen protocol 0.4 byte surface changed: ${path}`);
  }
}
const frozen04ConformanceRoot = join(
  repositoryRoot,
  "protocol",
  "conformance",
  "folderbase-version",
);
const frozen04Tree = createHash("sha256");
for (const path of walk(frozen04ConformanceRoot).sort()) {
  frozen04Tree.update(path, "utf8");
  frozen04Tree.update(Buffer.from([0]));
  frozen04Tree.update(readFileSync(join(repositoryRoot, path)));
  frozen04Tree.update(Buffer.from([0]));
}
if (
  frozen04Tree.digest("hex") !==
  "273b84cbbfcddcda8b65fdd71e385cd6b6e92582147afa7f2f60124fe490eb18"
) {
  throw new Error("frozen protocol 0.4 conformance bytes changed");
}

execFileSync(
  process.execPath,
  [join(repositoryRoot, "scripts", "verify-folderbase-version-0.5-digest-vectors.mjs")],
  { stdio: "inherit" },
);
console.log(
  `Folderbase protocol 0.5 candidate distribution verified: ${release.files.length} files`,
);

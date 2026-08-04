import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { classifyChanges } from "../ci/classify-changes.mjs";

const repositoryRoot = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const classifier = join(repositoryRoot, "scripts", "ci", "classify-changes.mjs");
const ciWorkflow = join(repositoryRoot, ".github", "workflows", "ci.yml");
const extractedPackageProof = join(
  repositoryRoot,
  "scripts",
  "test-extracted-packages.sh",
);

function workflowJob(source, jobName) {
  const start = source.indexOf(`\n  ${jobName}:\n`);
  assert.notEqual(start, -1, `missing workflow job: ${jobName}`);
  const remaining = source.slice(start + 1);
  const next = remaining.slice(1).search(/\n  [a-z][a-z0-9-]*:\n/u);
  return next === -1 ? remaining : remaining.slice(0, next + 1);
}

test("documentation-only changes require no expensive CI lanes", () => {
  assert.deepEqual(
    classifyChanges([
      "README.md",
      "docs/superpowers/plans/2026-08-01-readme-banner.md",
    ]),
    {
      docs: false,
      install: false,
      npm: false,
      platform: false,
      rust: false,
    },
  );
});

test("new unclassified Markdown paths fail safe to every lane", () => {
  assert.deepEqual(classifyChanges(["docs/new-contract-v2.md"]), {
    docs: true,
    install: true,
    npm: true,
    platform: true,
    rust: true,
  });
});

test("normative compatibility documents require every verification lane", () => {
  assert.deepEqual(classifyChanges(["docs/compatibility-v1.md"]), {
    docs: true,
    install: true,
    npm: true,
    platform: true,
    rust: true,
  });
});

test("npm launcher changes stay in the fast npm lane", () => {
  assert.deepEqual(
    classifyChanges(["packages/npm-cli/lib/launcher.mjs"]),
    {
      docs: false,
      install: false,
      npm: true,
      platform: false,
      rust: false,
    },
  );
});

test("npm publication policy changes stay in the fast npm lane", () => {
  assert.deepEqual(classifyChanges(["scripts/npm-publication-policy.mjs"]), {
    docs: false,
    install: false,
    npm: true,
    platform: false,
    rust: false,
  });
});

test("Core changes require Linux and platform verification", () => {
  assert.deepEqual(classifyChanges(["crates/folderbase-core/src/lib.rs"]), {
    docs: false,
    install: false,
    npm: false,
    platform: true,
    rust: true,
  });
});

test("native CLI changes also require fresh package installation", () => {
  assert.deepEqual(classifyChanges(["crates/folderbase-cli/src/main.rs"]), {
    docs: false,
    install: true,
    npm: false,
    platform: true,
    rust: true,
  });
});

test("workspace manifest changes require every verification lane", () => {
  assert.deepEqual(classifyChanges(["Cargo.toml"]), {
    docs: true,
    install: true,
    npm: true,
    platform: true,
    rust: true,
  });
});

test("protocol contract changes require every verification lane", () => {
  assert.deepEqual(
    classifyChanges(["protocol/schemas/cli/1/folderbase-cli-json.schema.json"]),
    {
      docs: true,
      install: true,
      npm: true,
      platform: true,
      rust: true,
    },
  );
});

test("release workflow changes require every verification lane", () => {
  assert.deepEqual(classifyChanges([".github/workflows/release-cli.yml"]), {
    docs: true,
    install: true,
    npm: true,
    platform: true,
    rust: true,
  });
});

test("scheduled and manual confidence runs require every lane", () => {
  assert.deepEqual(classifyChanges([], { full: true }), {
    docs: true,
    install: true,
    npm: true,
    platform: true,
    rust: true,
  });
});

test("CI control changes exercise every lane", () => {
  assert.deepEqual(classifyChanges([".github/workflows/ci.yml"]), {
    docs: true,
    install: true,
    npm: true,
    platform: true,
    rust: true,
  });
});

test("unknown paths fail safe to every verification lane", () => {
  assert.deepEqual(classifyChanges(["new-surface/contract.bin"]), {
    docs: true,
    install: true,
    npm: true,
    platform: true,
    rust: true,
  });
});

test("the classifier command writes GitHub Actions outputs", () => {
  const temporaryRoot = mkdtempSync(join(tmpdir(), "folderbase-ci-scope-"));
  const githubOutput = join(temporaryRoot, "github-output");

  try {
    execFileSync(process.execPath, [classifier], {
      input: "packages/npm-cli/lib/launcher.mjs\n",
      env: { ...process.env, GITHUB_OUTPUT: githubOutput },
    });
    assert.equal(
      readFileSync(githubOutput, "utf8"),
      "docs=false\ninstall=false\nnpm=true\nplatform=false\nrust=false\n",
    );
  } finally {
    rmSync(temporaryRoot, { force: true, recursive: true });
  }
});

test("CI cancels superseded runs and retains full confidence triggers", () => {
  const source = readFileSync(ciWorkflow, "utf8");

  assert.match(source, /\n  schedule:\n/);
  assert.match(source, /\n  workflow_dispatch:\n/);
  assert.match(source, /\nconcurrency:\n/);
  assert.match(source, /  cancel-in-progress: true\n/);
});

test("CI plans expensive lanes from the changed paths", () => {
  const source = readFileSync(ciWorkflow, "utf8");

  assert.match(source, /\n  plan:\n/);
  assert.match(source, /node scripts\/ci\/classify-changes\.mjs/);
  assert.match(source, /CI_BASE_SHA:/);
  assert.match(source, /CI_HEAD_SHA:/);
});

test("the npm policy lane executes scoped result verification tests", () => {
  const source = readFileSync(ciWorkflow, "utf8");
  const npm = workflowJob(source, "npm-cli");

  assert.match(npm, /scripts\/tests\/ci-required-results\.test\.mjs/);
});

test("the extracted CLI prefetches dependencies before its offline proof", () => {
  const source = readFileSync(extractedPackageProof, "utf8");
  const fetch = source.indexOf("cargo fetch \\");
  const offlineCliTest = source.indexOf(
    'cargo test \\\n  --manifest-path "$cli_source/Cargo.toml" \\\n  --offline',
  );

  assert.notEqual(fetch, -1, "missing extracted CLI dependency prefetch");
  assert.notEqual(offlineCliTest, -1, "missing extracted CLI offline proof");
  assert(fetch < offlineCliTest, "dependency prefetch must precede offline proof");
});

test("fresh installation proof is isolated from the Linux Core gate", () => {
  const source = readFileSync(ciWorkflow, "utf8");
  const rust = workflowJob(source, "rust");
  const install = workflowJob(source, "package-install");

  assert.doesNotMatch(rust, /scripts\/test-package-install\.sh/);
  assert.match(install, /if: needs\.plan\.outputs\.install == 'true'/);
  assert.match(install, /scripts\/test-package-install\.sh/);
});

test("cross-platform gates run after merge or during full confidence runs", () => {
  const source = readFileSync(ciWorkflow, "utf8");
  const platforms = workflowJob(source, "core-platforms");

  assert.match(platforms, /needs: plan/);
  assert.match(
    platforms,
    /if: github\.event_name != 'pull_request' && needs\.plan\.outputs\.platform == 'true'/,
  );
  assert.match(platforms, /node-version: 24/);
  assert.match(
    platforms,
    /cargo build --package folderbase-cli --locked/,
  );
  assert.match(
    platforms,
    /node protocol\/conformance\/capabilities\/run\.mjs --implementation \.\/target\/debug\/folderbase/,
  );
});

test("one stable required check aggregates every applicable lane", () => {
  const source = readFileSync(ciWorkflow, "utf8");
  const required = workflowJob(source, "required");

  assert.match(required, /name: Rust quality gate/);
  assert.match(required, /needs: \[plan, docs, npm-cli, rust, package-install, core-platforms\]/);
  assert.match(required, /if: always\(\)/);
  assert.match(required, /DOCS_REQUIRED: \$\{\{ needs\.plan\.outputs\.docs \}\}/);
  assert.match(required, /NPM_REQUIRED: \$\{\{ needs\.plan\.outputs\.npm \}\}/);
  assert.match(required, /RUST_REQUIRED: \$\{\{ needs\.plan\.outputs\.rust \}\}/);
  assert.match(required, /INSTALL_REQUIRED: \$\{\{ needs\.plan\.outputs\.install \}\}/);
  assert.match(
    required,
    /PLATFORM_REQUIRED: \$\{\{ github\.event_name != 'pull_request' && needs\.plan\.outputs\.platform == 'true' \}\}/,
  );
  assert.match(required, /uses: actions\/checkout@/);
  assert.match(required, /node scripts\/ci\/verify-required-results\.mjs/);
  assert.doesNotMatch(required, /success\|skipped/);
});

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { decideCratePublication } from "../release/crate-publication-policy.mjs";
import {
  parseChecksums,
  renderHomebrewFormula,
} from "../release/render-homebrew-formula.mjs";

test("an unpublished crate is publishable", () => {
  assert.deepEqual(
    decideCratePublication({
      crateName: "folderbase-core",
      version: "0.6.0",
      localChecksum: "a".repeat(64),
      published: null,
    }),
    { skipPublish: false },
  );
});

test("an exact crate rerun is idempotent", () => {
  assert.deepEqual(
    decideCratePublication({
      crateName: "folderbase-core",
      version: "0.6.0",
      localChecksum: "a".repeat(64),
      published: {
        version: "0.6.0",
        checksum: "a".repeat(64),
        yanked: false,
      },
    }),
    { skipPublish: true },
  );
});

test("crate publication fails closed on immutable-byte or yank divergence", () => {
  assert.throws(
    () => decideCratePublication({
      crateName: "folderbase-core",
      version: "0.6.0",
      localChecksum: "a".repeat(64),
      published: {
        version: "0.6.0",
        checksum: "b".repeat(64),
        yanked: false,
      },
    }),
    /checksum does not match/u,
  );
  assert.throws(
    () => decideCratePublication({
      crateName: "folderbase-core",
      version: "0.6.0",
      localChecksum: "a".repeat(64),
      published: {
        version: "0.6.0",
        checksum: "a".repeat(64),
        yanked: true,
      },
    }),
    /is yanked/u,
  );
});

test("Homebrew formula is derived only from the sealed four-target checksums", () => {
  const version = "0.6.0";
  const entries = [
    ["1".repeat(64), `folderbase-v${version}-aarch64-apple-darwin`],
    ["2".repeat(64), `folderbase-v${version}-x86_64-apple-darwin`],
    ["3".repeat(64), `folderbase-v${version}-aarch64-unknown-linux-gnu`],
    ["4".repeat(64), `folderbase-v${version}-x86_64-unknown-linux-gnu`],
  ];
  const checksums = parseChecksums(
    `${entries.map(([digest, name]) => `${digest}  ${name}`).join("\n")}\n`,
    `v${version}`,
  );
  const formula = renderHomebrewFormula({ version, checksums });

  assert.match(formula, /version "0\.6\.0"/u);
  for (const [digest, name] of entries) {
    assert.match(formula, new RegExp(`releases/download/v0\\.6\\.0/${name}`, "u"));
    assert.match(formula, new RegExp(`sha256 "${digest}"`, "u"));
  }
  assert.match(formula, /folderbase protocol contract --json/u);
  assert.match(formula, /\.folderbase\/manifest\.json/u);
});

test("Homebrew checksum parsing rejects omissions, extras, and unsafe names", () => {
  const valid = [
    `${"1".repeat(64)}  folderbase-v0.6.0-aarch64-apple-darwin`,
    `${"2".repeat(64)}  folderbase-v0.6.0-x86_64-apple-darwin`,
    `${"3".repeat(64)}  folderbase-v0.6.0-aarch64-unknown-linux-gnu`,
    `${"4".repeat(64)}  folderbase-v0.6.0-x86_64-unknown-linux-gnu`,
  ];
  assert.throws(() => parseChecksums(`${valid.slice(0, 3).join("\n")}\n`, "v0.6.0"));
  assert.throws(() => parseChecksums(`${[...valid, `${"5".repeat(64)}  extra`].join("\n")}\n`, "v0.6.0"));
  assert.throws(() => parseChecksums(`${valid.join("\n")}\n`, "v0.6.1"));
});

test("release workflow closes crates, GitHub, npm, SDK, and Homebrew in dependency order", async () => {
  const workflow = await readFile(new URL("../../.github/workflows/release-cli.yml", import.meta.url), "utf8");
  const crates = workflow.indexOf("scripts/release/publish-crates.sh");
  const github = workflow.indexOf("scripts/release/publish-github-release.sh");
  const npmCli = workflow.indexOf("working-directory: packages/npm-cli", github);
  const npmSdk = workflow.indexOf("working-directory: packages/sdk", npmCli);
  const homebrew = workflow.indexOf("scripts/release/publish-homebrew-formula.sh", npmSdk);

  for (const [label, position] of Object.entries({ crates, github, npmCli, npmSdk, homebrew })) {
    assert.notEqual(position, -1, `release workflow omits ${label}`);
  }
  assert.ok(crates < github && github < npmCli && npmCli < npmSdk && npmSdk < homebrew);
  assert.match(workflow, /CARGO_REGISTRY_TOKEN: \$\{\{ secrets\.CARGO_REGISTRY_TOKEN \}\}/u);
  assert.match(workflow, /GH_TOKEN: \$\{\{ secrets\.FOLDERBASE_HOMEBREW_TAP_TOKEN \|\| github\.token \}\}/u);
  assert.match(workflow, /node scripts\/test-sdk-package\.mjs/u);
  assert.match(workflow, /name: Verify public multi-channel release/u);
});

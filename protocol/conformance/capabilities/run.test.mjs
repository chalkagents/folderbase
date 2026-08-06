import assert from "node:assert/strict";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import test from "node:test";

const directory = dirname(fileURLToPath(import.meta.url));
const runner = resolve(directory, "run.mjs");
const versionSuite = resolve(directory, "version-cli-json-0.1/run.mjs");
const fixtures = resolve(directory, "fixtures");

function run(candidate, extra = []) {
  return spawnSync(
    process.execPath,
    [runner, "--implementation", resolve(fixtures, candidate), ...extra],
    {
      encoding: "utf8",
      env: {
        ...process.env,
        FOLDERBASE_CAPABILITY_DISCOVERY_TIMEOUT_MS: "100",
      },
      maxBuffer: 16 * 1024 * 1024,
      timeout: 5_000,
    },
  );
}

test("a hanging candidate produces a failed JSON report within the discovery bound", () => {
  const result = run("hanging-candidate.mjs");
  assert.equal(result.status, 1, result.error?.message || result.stderr || result.stdout);
  const report = JSON.parse(result.stdout);
  assert.equal(report.failed, 1);
  assert.deepEqual(report.cases, [
    {
      id: "discover-capabilities",
      status: "failed",
      message: "capability discovery timed out after 100ms",
    },
  ]);
});

test("a hanging candidate command produces a bounded capability-suite report", () => {
  const result = spawnSync(
    process.execPath,
    [versionSuite, "--implementation", resolve(fixtures, "hanging-candidate.mjs")],
    {
      encoding: "utf8",
      env: {
        ...process.env,
        FOLDERBASE_CAPABILITY_COMMAND_TIMEOUT_MS: "100",
      },
      maxBuffer: 16 * 1024 * 1024,
      timeout: 5_000,
    },
  );
  assert.equal(result.status, 1, result.error?.message || result.stderr || result.stdout);
  const report = JSON.parse(result.stdout);
  assert.equal(report.failed, 1);
  assert.equal(report.cases.length, 1);
  assert.equal(report.cases[0].id, "capture-ordinary-file");
  assert.equal(report.cases[0].status, "failed");
  assert.match(
    report.cases[0].message,
    /candidate command version capture .* Decision\.md --json timed out after 100ms/,
  );
});

test("a v1 implementation without capability discovery remains conformant", () => {
  const result = run("v1-without-capabilities.mjs");
  assert.equal(result.status, 0, result.stderr || result.stdout);
  const report = JSON.parse(result.stdout);
  assert.equal(report.selected, 0);
  assert.equal(report.failed, 0);

  const required = run("v1-without-capabilities.mjs", [
    "--capability",
    "folderbase.version-cli-json@0.1.0",
  ]);
  assert.equal(required.status, 1);
  const requiredReport = JSON.parse(required.stdout);
  assert.equal(requiredReport.selected, 1);
  assert.equal(requiredReport.failed, 1);
  assert.match(requiredReport.cases[0].message, /is not advertised/);
});

test("root reconstruction is known but fails closed while the executable is unadvertised", () => {
  const result = run("v1-without-capabilities.mjs", [
    "--capability",
    "folderbase.root-reconstruction@0.1.0",
  ]);
  assert.equal(result.status, 1, result.stderr || result.stdout);
  const report = JSON.parse(result.stdout);
  assert.equal(report.selected, 1);
  assert.equal(report.passed, 0);
  assert.equal(report.failed, 1);
  assert.deepEqual(report.cases, [
    {
      id: "folderbase.root-reconstruction@0.1.0",
      status: "failed",
      message:
        "folderbase.root-reconstruction@0.1.0 is not advertised by the implementation",
    },
  ]);
});

test("unknown advertised capabilities are ignored unless explicitly requested", () => {
  const ignored = run("unknown-capability.mjs");
  assert.equal(ignored.status, 0, ignored.stderr || ignored.stdout);
  const report = JSON.parse(ignored.stdout);
  assert.deepEqual(report.ignored, ["vendor.future-query@9.0.0"]);
  assert.equal(report.selected, 0);

  const requested = run("unknown-capability.mjs", [
    "--capability",
    "vendor.future-query@9.0.0",
  ]);
  assert.equal(requested.status, 2);
  assert.match(requested.stderr, /unknown capability profile/);
});

test("advertising a known capability cannot skip its black-box suite", () => {
  const result = run("advertises-version-without-implementation.mjs");
  assert.equal(result.status, 1, result.stderr || result.stdout);
  const report = JSON.parse(result.stdout);
  assert.equal(report.selected, 1);
  assert.equal(report.passed, 0);
  assert.equal(report.failed, 1);
  assert.equal(report.cases[0].id, "folderbase.version-cli-json@0.1.0");
  assert.equal(report.cases[0].status, "failed");
});

test("advertised capability profiles must use canonical deterministic order", () => {
  const result = run("out-of-order-capabilities.mjs");
  assert.equal(result.status, 1);
  const report = JSON.parse(result.stdout);
  assert.equal(report.selected, 0);
  assert.equal(report.failed, 1);
  assert.match(report.cases[0].message, /order is canonical/);
});

test("known capability stability must match the public registry", () => {
  const result = run("wrong-known-stability.mjs");
  assert.equal(result.status, 1);
  const report = JSON.parse(result.stdout);
  assert.equal(report.failed, 1);
  assert.match(report.cases[0].message, /stability does not match the registry/);
});

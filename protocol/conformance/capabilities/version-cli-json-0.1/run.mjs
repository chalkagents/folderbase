#!/usr/bin/env node

import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, extname, join, resolve } from "node:path";
import { spawnSync } from "node:child_process";

const FORMAT = "folderbase-capability-suite-report-v1";
const CAPABILITY = "folderbase.version-cli-json@0.1.0";
const UUID = "[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}";
const VERSION_ID = new RegExp(`^version_${UUID}$`);
const DEFAULT_COMMAND_TIMEOUT_MS = 120_000;

function configuredTimeout(name, fallback) {
  const value = process.env[name];
  if (value === undefined) return fallback;
  const milliseconds = Number(value);
  if (
    !/^[1-9][0-9]*$/.test(value)
    || !Number.isSafeInteger(milliseconds)
    || milliseconds > 2_147_483_647
  ) {
    throw new Error(`${name} must be a positive integer`);
  }
  return milliseconds;
}

function throwIfTimedOut(result, label, timeoutMs) {
  if (result.error?.code === "ETIMEDOUT") {
    throw new Error(`${label} timed out after ${timeoutMs}ms`);
  }
  if (result.error) throw result.error;
}

function implementationArgument(argv) {
  const flag = argv.indexOf("--implementation");
  if (flag === -1 || !argv[flag + 1] || argv.length !== 2) {
    throw new Error("usage: run.mjs --implementation /path/to/folderbase");
  }
  return resolve(argv[flag + 1]);
}

function execute(implementation, arguments_, timeoutMs) {
  const command = [".js", ".cjs", ".mjs"].includes(extname(implementation))
    ? process.execPath
    : implementation;
  const args = command === process.execPath
    ? [implementation, ...arguments_]
    : arguments_;
  const result = spawnSync(command, args, {
    encoding: "utf8",
    killSignal: "SIGKILL",
    maxBuffer: 8 * 1024 * 1024,
    timeout: timeoutMs,
  });
  throwIfTimedOut(result, `candidate command ${arguments_.join(" ")}`, timeoutMs);
  return result;
}

function successJson(implementation, arguments_, timeoutMs) {
  const result = execute(implementation, arguments_, timeoutMs);
  assert.equal(result.status, 0, result.stderr || result.stdout);
  assert.equal(result.stderr, "");
  return JSON.parse(result.stdout);
}

const implementation = implementationArgument(process.argv.slice(2));
const commandTimeoutMs = configuredTimeout(
  "FOLDERBASE_CAPABILITY_COMMAND_TIMEOUT_MS",
  DEFAULT_COMMAND_TIMEOUT_MS,
);
const root = await mkdtemp(join(tmpdir(), "folderbase-version-capability-"));
const report = {
  format: FORMAT,
  capability: CAPABILITY,
  implementation: basename(implementation),
  passed: 0,
  failed: 0,
  cases: [],
};
const state = {};
const cases = [
  {
    id: "capture-ordinary-file",
    run() {
      const output = successJson(implementation, [
        "version",
        "capture",
        root,
        "Decision.md",
        "--json",
      ], commandTimeoutMs);
      assert.equal(output.object.path, "Decision.md");
      assert.match(output.version.id, VERSION_ID);
      state.versionId = output.version.id;
    },
  },
  {
    id: "restore-without-overwrite",
    async run() {
      await writeFile(join(root, "Decision.md"), "second\n");
      const output = successJson(implementation, [
        "version",
        "restore",
        root,
        state.versionId,
        "Restored/Decision.md",
        "--json",
      ], commandTimeoutMs);
      assert.equal(output.version_id, state.versionId);
      assert.equal(await readFile(join(root, "Restored/Decision.md"), "utf8"), "first\n");
    },
  },
  {
    id: "read-append-only-history",
    run() {
      const output = successJson(implementation, [
        "version",
        "history",
        root,
        "--json",
      ], commandTimeoutMs);
      assert.ok(Array.isArray(output));
      assert.ok(output.length >= 2);
      assert.ok(output.some((event) => event.action === "version.restored"));
    },
  },
];

try {
  await writeFile(join(root, "Decision.md"), "first\n");
  for (const testCase of cases) {
    const result = { id: testCase.id, status: "passed" };
    try {
      await testCase.run();
      report.passed += 1;
    } catch (error) {
      result.status = "failed";
      result.message = error instanceof Error ? error.message : String(error);
      report.failed += 1;
    }
    report.cases.push(result);
    if (result.status === "failed") break;
  }
} finally {
  await rm(root, { recursive: true, force: true });
}

process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
process.exitCode = report.failed === 0 ? 0 : 1;

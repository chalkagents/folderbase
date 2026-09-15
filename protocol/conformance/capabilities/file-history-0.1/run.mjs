#!/usr/bin/env node

import assert from "node:assert/strict";
import { randomUUID, createHash } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile, mkdir, readdir, lstat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, extname, join, normalize, resolve } from "node:path";
import { spawnSync } from "node:child_process";

const FORMAT = "folderbase-capability-suite-report-v1";
const CAPABILITY = "folderbase.file-history@0.1.0";
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

function execute(implementation, arguments_, timeoutMs, input) {
  const command = [".js", ".cjs", ".mjs"].includes(extname(implementation))
    ? process.execPath
    : implementation;
  const args = command === process.execPath
    ? [implementation, ...arguments_]
    : arguments_;
  const result = spawnSync(command, args, {
    input: input === undefined ? undefined : `${JSON.stringify(input)}\n`,
    encoding: "utf8",
    killSignal: "SIGKILL",
    maxBuffer: 8 * 1024 * 1024,
    timeout: timeoutMs,
  });
  throwIfTimedOut(result, `candidate command ${arguments_.join(" ")}`, timeoutMs);
  return result;
}

function successJson(implementation, arguments_, timeoutMs, input) {
  const result = execute(implementation, arguments_, timeoutMs, input);
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
const owner = root;
const source = join(root, "source");
const state = {};
const ok = (args, input) => successJson(implementation, args, commandTimeoutMs, input);
async function snapshot(path, prefix = "") {
  const result = [];
  for (const name of (await readdir(path)).sort()) {
    const child = join(path, name);
    const info = await lstat(child);
    const relative = `${prefix}${name}`;
    assert.equal(info.isSymbolicLink(), false);
    result.push([relative, info.mtimeMs, info.isFile() ? createHash("sha256").update(await readFile(child)).digest("hex") : "directory"]);
    if (info.isDirectory()) result.push(...await snapshot(child, `${relative}/`));
  }
  return result;
}
const cases = [
  {
    id: "untracked-and-missing-read-without-state-creation",
    async run() {
      await mkdir(join(source, "tasks"), {recursive: true});
      await writeFile(join(source, "untracked.bin"), Buffer.from([0, 255, 17]));
      state.initialized = ok(["init", source, "--json"]);
      const before = await snapshot(source);
      const output = ok(["version", "list", source, "untracked.bin", "--json"]);
      assert.deepEqual(output, {format: "folderbase-file-history-v1", path: "untracked.bin", object_id: null, current_version: null, versions: []});
      const missing = execute(implementation, ["version", "list", source, "missing", "--json"], commandTimeoutMs);
      assert.equal(missing.status, 2); assert.equal(missing.stdout, "");
      assert.equal(JSON.parse(missing.stderr).error.code, "file_history_file_not_found");
      assert.deepEqual(await snapshot(source), before);
    },
  },
  {
    id: "change-set-created-history-is-complete-without-capture",
    async run() {
      const checkout = join(owner, "checkout");
      const staging = join(owner, "staging");
      ok(["change-set", "checkout", source, checkout, "--stdin", "--json"], {
        format: "folderbase-checkout-request-v1", folderbase_id: state.initialized.folderbase_id,
        projection_id: `projection_${randomUUID()}`, folder_scope_id: `folderscope_${randomUUID()}`,
        scope_revision_sha256: "1".repeat(64), permission: "can_work", authorized_paths: [{path_prefix: "tasks"}],
      });
      await writeFile(join(checkout, "tasks/created.json"), '{"title":"First"}');
      await writeFile(join(checkout, "tasks/attachment.bin"), Buffer.from([0, 255, 17]));
      const envelope = ok(["change-set", "propose", checkout, staging, "--json"]);
      assert.equal(ok(["change-set", "assess", source, staging, "--stdin", "--json"], envelope).status, "clean");
      assert.equal(ok(["change-set", "apply", source, staging, "--stdin", "--json"], envelope).status, "applied");
      const before = await snapshot(source);
      for (const path of ["tasks/created.json", "tasks/attachment.bin"]) {
        const output = ok(["version", "list", source, path, "--json"]);
        assert.equal(output.format, "folderbase-file-history-v1");
        assert.equal(output.path, normalize(path), "history returns canonical native filesystem spelling");
        assert.ok(output.versions.length > 0);
        assert.match(output.current_version, VERSION_ID);
        assert.ok(output.versions.some((version) => version.id === output.current_version));
        const bytes = await readFile(join(source, path));
        assert.equal(new Set(output.versions.map(({id}) => id)).size, output.versions.length);
        for (const version of output.versions) {
          assert.match(version.id, VERSION_ID);
          assert.equal(version.object_id, output.object_id);
          assert.equal(version.content.algorithm, "sha256");
          assert.equal(version.content.digest, createHash("sha256").update(bytes).digest("hex"));
          assert.equal(version.content.bytes, bytes.length);
          assert.ok(Number.isFinite(Date.parse(version.captured_at)));
        }
        if (path.endsWith("created.json")) state.initial = output;
      }
      assert.deepEqual(await snapshot(source), before);
      // Compare with the existing public complete Object projection only AFTER
      // the read-only tree assertion. Do not infer one Version per creation:
      // an accepted Change Set may retain both capture and proposal Versions.
      for (const path of ["tasks/created.json", "tasks/attachment.bin"]) {
        const history = ok(["version", "list", source, path, "--json"]);
        const captured = ok(["version", "capture", source, path, "--json"]);
        assert.equal(captured.version_created, false);
        assert.deepEqual(history.versions.map(({id}) => id), captured.object.versions);
        assert.equal(history.current_version, captured.object.current_version);
        assert.equal(history.object_id, captured.object.id);
        assert.deepEqual(history.versions.find(({id}) => id === history.current_version), captured.version);
      }
    },
  },
  {
    id: "cas-adds-one-version-and-read-does-not-capture-owner-edits",
    async run() {
      const read = ok(["workspace", "read", source, "tasks/created.json", "--json"]);
      const saved = execute(implementation, ["workspace", "save", source, "tasks/created.json", "--expected-sha256", read.sha256, "--stdin", "--json"], commandTimeoutMs, {title: "Second"});
      assert.notEqual(saved.status, null);
      if (saved.status !== 0) throw new Error(saved.stderr);
      const saveResult = JSON.parse(saved.stdout);
      const recorded = ok(["version", "list", source, "tasks/created.json", "--json"]);
      assert.equal(recorded.versions.length, state.initial.versions.length + 1);
      assert.deepEqual(recorded.versions.slice(0, -1), state.initial.versions);
      assert.equal(recorded.current_version, saveResult.version_id);
      await writeFile(join(source, "tasks/created.json"), "external owner edit");
      const before = await snapshot(source);
      assert.deepEqual(ok(["version", "list", source, "tasks/created.json", "--json"]), recorded);
      assert.deepEqual(await snapshot(source), before);
    },
  },
  {
    id: "pending-operation-refused-without-recovery",
    async run() {
      await mkdir(join(source, ".folderbase/transactions/change-set"), {recursive: true});
      await writeFile(join(source, ".folderbase/transactions/change-set/active.json"), '{"interrupted":');
      const before = await snapshot(source);
      const result = execute(implementation, ["version", "list", source, "tasks/created.json", "--json"], commandTimeoutMs);
      assert.equal(result.status, 2); assert.equal(result.stdout, "");
      assert.equal(JSON.parse(result.stderr).error.code, "file_history_recovery_required");
      assert.deepEqual(await snapshot(source), before);
    },
  },
];

try {
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

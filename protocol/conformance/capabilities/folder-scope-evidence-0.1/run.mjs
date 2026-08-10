#!/usr/bin/env node

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  access,
  cp,
  mkdir,
  mkdtemp,
  readFile,
  rename,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, extname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { assertFolderScopeEvidenceSchema } from "./schema.mjs";

const CAPABILITY = "folderbase.folder-scope-evidence@0.1.0";
const FORMAT = "folderbase-capability-suite-report-v1";
const FOLDERBASE_ID = "folderbase_019fb97e-9c5f-73ca-9bb2-03dc80f94792";
const NESTED_ID = "folderbase_019fb97e-9c5f-73ca-9bb2-03dc80f94793";
const directory = dirname(fileURLToPath(import.meta.url));
const schema = JSON.parse(
  await readFile(
    resolve(
      directory,
      "../../../schemas/capabilities/folder-scope-evidence/0.1/folder-scope-evidence.schema.json",
    ),
    "utf8",
  ),
);

function implementationArgument(argv) {
  const flag = argv.indexOf("--implementation");
  if (flag === -1 || !argv[flag + 1] || argv.length !== 2) {
    throw new Error("usage: run.mjs --implementation /path/to/folderbase");
  }
  if (argv[flag + 1].includes("\u0000")) throw new Error("implementation path contains NUL");
  return resolve(argv[flag + 1]);
}

function commandFor(implementation, arguments_) {
  return [".js", ".cjs", ".mjs"].includes(extname(implementation))
    ? { command: process.execPath, args: [implementation, ...arguments_] }
    : { command: implementation, args: arguments_ };
}

function execute(implementation, arguments_, environment = {}) {
  const invocation = commandFor(implementation, arguments_);
  const result = spawnSync(invocation.command, invocation.args, {
    encoding: "utf8",
    shell: false,
    windowsHide: true,
    env: { ...process.env, ...environment },
    timeout: 30_000,
    maxBuffer: 2 * 1024 * 1024,
  });
  if (result.error) throw result.error;
  return result;
}

function validateEvidence(document) {
  assertFolderScopeEvidenceSchema(document, schema, "evidence");
  const prefix = `${document.selected_path}/`;
  let prior;
  for (const boundary of document.nested_boundaries) {
    assert.ok(boundary.startsWith(prefix) && boundary.length > prefix.length);
    if (prior !== undefined) assert.ok(Buffer.compare(Buffer.from(prior), Buffer.from(boundary)) < 0);
    prior = boundary;
  }
  assert.equal(Object.values(document).some((value) => typeof value === "string" && value.startsWith("/")), false);
  return document;
}

function validateError(document, expectedCode) {
  assertFolderScopeEvidenceSchema(document, schema, "error");
  assert.equal(document.error.code, expectedCode);
  return document;
}

function observe(implementation, root, selectedPath, environment = {}) {
  const result = execute(implementation, [
    "folder-scope", "observe", root, selectedPath, "--json",
  ], environment);
  assert.equal(result.status, 0, result.stderr || result.stdout);
  assert.equal(result.stderr, "");
  return validateEvidence(JSON.parse(result.stdout));
}

function observeError(implementation, root, selectedPath, expectedCode, environment = {}) {
  const result = execute(implementation, [
    "folder-scope", "observe", root, selectedPath, "--json",
  ], environment);
  assert.equal(result.status, 2, result.stderr || result.stdout);
  assert.equal(result.stdout, "");
  return validateError(JSON.parse(result.stderr), expectedCode);
}

async function writeRoot(root, id = FOLDERBASE_ID) {
  await mkdir(join(root, ".folderbase"), { recursive: true });
  await writeFile(
    join(root, ".folderbase", "manifest.json"),
    `${JSON.stringify({
      $schema: "https://folderbase.ai/protocol/0.5/folderbase.schema.json",
      protocol_version: "0.5.0",
      folderbase: {
        id,
        name: "Scope conformance fixture",
        kind: "project",
        status: "active",
        created_at: "2026-08-10T00:00:00Z",
      },
      adapters: [],
      policies: {
        availability: "keep_local",
        structural_changes: "approve",
        archive: "manual",
        cloud_sync: "disabled",
        capture_ignore: { format: "folderbase-capture-ignore-v1", rules: [] },
      },
    })}\n`,
  );
  await mkdir(join(root, "Client Work", "Briefs"), { recursive: true });
  await writeFile(join(root, "Client Work", "Briefs", "current.md"), "current\n");
  await writeFile(join(root, "Client Work", "records.csv"), "name,value\nalpha,1\n");
  await writeFile(join(root, "Client Work", "document.pdf"), "%PDF-1.7 opaque\n");
  await writeFile(join(root, "Client Work", "database.sqlite"), Buffer.from([0, 1, 2, 3, 255]));
  await mkdir(join(root, "Client Work", "repository", ".git"), { recursive: true });
  await writeFile(join(root, "Client Work", "repository", ".git", "HEAD"), "ref: refs/heads/main\n");
}

async function addNested(root, relative, id = NESTED_ID) {
  const state = join(root, relative, ".folderbase");
  await mkdir(state, { recursive: true });
  await writeFile(
    join(state, "manifest.json"),
    `${JSON.stringify({
      $schema: "https://folderbase.ai/protocol/0.5/folderbase.schema.json",
      protocol_version: "0.5.0",
      folderbase: {
        id,
        name: "Nested scope boundary",
        kind: "project",
        status: "active",
        created_at: "2026-08-10T00:00:00Z",
      },
      adapters: [],
      policies: {
        availability: "keep_local",
        structural_changes: "approve",
        archive: "manual",
        cloud_sync: "disabled",
        capture_ignore: { format: "folderbase-capture-ignore-v1", rules: [] },
      },
    })}\n`,
  );
}

const report = {
  format: FORMAT,
  capability: CAPABILITY,
  implementation: "",
  passed: 0,
  failed: 0,
  cases: [],
};
let cleanup;

try {
  const implementation = implementationArgument(process.argv.slice(2));
  report.implementation = basename(implementation);
  cleanup = await mkdtemp(join(tmpdir(), "folderbase-scope-conformance-"));
  const cases = [
    {
      id: "capability-discovery",
      async run() {
        const result = execute(implementation, ["protocol", "contract", "--json"]);
        assert.equal(result.status, 0, result.stderr);
        const contract = JSON.parse(result.stdout);
        assert.ok(contract.capabilities.some(({ name, version }) =>
          `${name}@${version}` === CAPABILITY));
      },
    },
    {
      id: "idempotent-arbitrary-folder-observation",
      async run() {
        const root = join(cleanup, "arbitrary");
        await writeRoot(root);
        await mkdir(join(root, "Personal"));
        const first = observe(implementation, root, "Client Work");
        const repeated = observe(implementation, root, "Client Work");
        assert.deepEqual(repeated, first);
        const personal = observe(implementation, root, "Personal");
        assert.equal(personal.device_sequence, 2);
        assert.deepEqual(observe(implementation, root, "Client Work"), first);
      },
    },
    {
      id: "non-genesis-head-progress-and-stale-observation-refusal",
      async run() {
        const root = join(cleanup, "local-head");
        await writeRoot(root);
        observeError(
          implementation,
          root,
          "Client Work",
          "folder_scope_observation_changed",
          { FOLDERBASE_FOLDER_SCOPE_CONFORMANCE_ADVANCE_HEAD_AFTER_PLAN: "1" },
        );
        await assert.rejects(
          access(join(root, ".folderbase", "local", "folder-scope-evidence-v1")),
        );
        const first = observe(implementation, root, "Client Work");
        assert.equal(first.device_sequence, 1);
        await writeFile(join(root, "Client Work", "new-head.md"), "new head\n");
        observeError(
          implementation,
          root,
          "Client Work",
          "folder_scope_observation_changed",
          { FOLDERBASE_FOLDER_SCOPE_CONFORMANCE_ADVANCE_HEAD_AFTER_PLAN: "1" },
        );
        const advanced = observe(implementation, root, "Client Work");
        assert.equal(advanced.device_sequence, 2);
        assert.equal(advanced.opaque_binding_proof, first.opaque_binding_proof);
      },
    },
    {
      id: "rename-continuity-and-replacement-refusal",
      async run() {
        const root = join(cleanup, "rename");
        await writeRoot(root);
        const before = observe(implementation, root, "Client Work");
        await rename(join(root, "Client Work"), join(root, "Active Client Work"));
        const after = observe(implementation, root, "Active Client Work");
        assert.equal(after.opaque_binding_proof, before.opaque_binding_proof);
        await mkdir(join(root, "Client Work"));
        observeError(implementation, root, "Client Work", "selected_folder_replaced");
      },
    },
    {
      id: "nested-boundary-isolation",
      async run() {
        const root = join(cleanup, "boundary");
        await writeRoot(root);
        await addNested(root, join("Client Work", "Partner"));
        const first = observe(implementation, root, "Client Work");
        assert.deepEqual(first.nested_boundaries, ["Client Work/Partner"]);
        await addNested(
          root,
          join("Client Work", "Partner"),
          "folderbase_019fb97e-9c5f-73ca-9bb2-03dc80f94794",
        );
        observeError(implementation, root, "Client Work", "nested_boundary_changed");

        const topologyRoot = join(cleanup, "boundary-topology");
        await writeRoot(topologyRoot, "folderbase_019fb97e-9c5f-73ca-9bb2-03dc80f94795");
        observe(implementation, topologyRoot, "Client Work");
        await addNested(
          topologyRoot,
          join("Client Work", "Second Partner"),
          "folderbase_019fb97e-9c5f-73ca-9bb2-03dc80f94796",
        );
        observeError(implementation, topologyRoot, "Client Work", "nested_boundary_changed");
      },
    },
    {
      id: "physical-root-replacement-refusal",
      async run() {
        const root = join(cleanup, "root-replacement");
        const backup = join(cleanup, "root-replacement-backup");
        await writeRoot(root);
        observe(implementation, root, "Client Work");
        await cp(root, backup, { recursive: true, force: false });
        await rm(root, { recursive: true, force: true });
        await cp(backup, root, { recursive: true, force: false });
        const result = execute(implementation, [
          "folder-scope", "observe", root, "Client Work", "--json",
        ]);
        assert.equal(result.status, 2, result.stderr || result.stdout);
        assert.equal(result.stdout, "");
      },
    },
    {
      id: "unsafe-path-and-invocation-errors",
      async run() {
        const root = join(cleanup, "unsafe");
        await writeRoot(root);
        observeError(implementation, root, "../outside", "unsafe_selected_path");
        const result = execute(implementation, ["folder-scope", "observe"]);
        assert.equal(result.status, 2);
        assert.equal(result.stdout, "");
        validateError(JSON.parse(result.stderr), "invalid_invocation");
      },
    },
    {
      id: "escaping-symlink-refusal",
      async run() {
        const root = join(cleanup, "symlink");
        const outside = join(cleanup, "outside-directory");
        await writeRoot(root);
        await mkdir(outside);
        await writeFile(join(outside, "outside.txt"), "outside\n");
        await symlink(
          outside,
          join(root, "Client Work", "escape"),
          process.platform === "win32" ? "junction" : "dir",
        );
        observeError(implementation, root, "Client Work", "folder_scope_capture_invalid");
      },
    },
    {
      id: "unsupported-node-refusal",
      async run() {
        if (process.platform === "win32") return;
        const root = join(cleanup, "unsupported");
        await writeRoot(root);
        const fifo = join(root, "Client Work", "agent.pipe");
        const created = spawnSync("mkfifo", [fifo], {
          encoding: "utf8",
          shell: false,
          windowsHide: true,
          timeout: 10_000,
        });
        if (created.error) throw created.error;
        assert.equal(created.status, 0, created.stderr || created.stdout);
        observeError(implementation, root, "Client Work", "unsupported_selected_node");
      },
    },
    {
      id: "event-publication-crash-recovery",
      async run() {
        const root = join(cleanup, "crash-recovery");
        await writeRoot(root);
        const crashed = execute(
          implementation,
          ["folder-scope", "observe", root, "Client Work", "--json"],
          { FOLDERBASE_FOLDER_SCOPE_CONFORMANCE_CRASH_AFTER: "event-publication" },
        );
        assert.equal(crashed.status, 86, crashed.stderr || crashed.stdout);
        assert.equal(crashed.stdout, "");
        assert.equal(crashed.stderr, "");
        const recovered = observe(implementation, root, "Client Work");
        assert.equal(recovered.device_sequence, 1);
        assert.deepEqual(observe(implementation, root, "Client Work"), recovered);
      },
    },
    {
      id: "closed-bounded-journal-refusal",
      async run() {
        const root = join(cleanup, "journal-bound");
        await writeRoot(root);
        const first = observe(implementation, root, "Client Work");
        const journal = join(root, ".folderbase", "local", "folder-scope-evidence-v1");
        const originalHead = await readFile(join(journal, "head.json"));
        await writeFile(join(journal, "rogue.bin"), Buffer.alloc(128));
        observeError(implementation, root, "Client Work", "invalid_folder_scope_journal");
        assert.deepEqual(await readFile(join(journal, "head.json")), originalHead);
        assert.equal(first.device_sequence, 1);
      },
    },
  ];

  for (const testCase of cases) {
    const result = { id: testCase.id, status: "passed" };
    try {
      await testCase.run();
      report.passed += 1;
    } catch (error) {
      result.status = "failed";
      result.message = error instanceof Error ? error.message : String(error);
      report.failed += 1;
      report.cases.push(result);
      break;
    }
    report.cases.push(result);
  }
} catch (error) {
  report.failed += 1;
  report.cases.push({
    id: "suite-setup",
    status: "failed",
    message: error instanceof Error ? error.message : String(error),
  });
} finally {
  if (cleanup) await rm(cleanup, { recursive: true, force: true });
}

process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
process.exitCode = report.failed === 0 ? 0 : 1;

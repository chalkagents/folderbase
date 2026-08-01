#!/usr/bin/env node

import assert from "node:assert/strict";
import {
  mkdtemp,
  mkdir,
  readdir,
  readFile,
  realpath,
  rm,
  stat,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

import { assertJsonSchema } from "./schema.mjs";

const FORMAT = "folderbase-conformance-report-v1";
const SHA256 = /^[0-9a-f]{64}$/;
const UUID = "[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}";
const FOLDERBASE_ID = new RegExp(`^folderbase_${UUID}$`);
const OBJECT_ID = new RegExp(`^obj_${UUID}$`);
const VERSION_ID = new RegExp(`^version_${UUID}$`);
const NOTE_BYTES = "hello\n";
const NOTE_SHA256 = "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03";
const UPDATED_BYTES = "updated\n";
const UPDATED_SHA256 = "e06f60fa8cf5bea891e59dc0ed5b7af55b8cccd081ba9cfbca0ff1acadd9a47f";
const LEGACY_MANIFEST = `{
  "$schema": "https://folderbase.ai/protocol/0.1/folderbase.schema.json",
  "protocol_version": "0.1.0",
  "folderbase": {
    "id": "folderbase_019f9b75-4f42-7f65-a012-2bfecdd8c475",
    "name": "Project 2",
    "kind": "project",
    "status": "active",
    "created_at": "2026-07-26T00:00:00Z",
    "entry": "FOLDERBASE.md"
  },
  "policies": {
    "availability": "keep_local",
    "structural_changes": "approve",
    "archive": "approve",
    "cloud_sync": "disabled"
  }
}
`;

function implementationArgument(argv) {
  const flag = argv.indexOf("--implementation");
  if (flag === -1 || !argv[flag + 1] || argv.length !== 2) {
    throw new Error("usage: run.mjs --implementation /path/to/folderbase");
  }
  return argv[flag + 1];
}

function execute(implementation, arguments_, input) {
  const result = spawnSync(implementation, arguments_, {
    encoding: "utf8",
    input,
    maxBuffer: 8 * 1024 * 1024,
  });
  if (result.error) throw result.error;
  return {
    status: result.status,
    stdout: result.stdout,
    stderr: result.stderr,
  };
}

function successJson(implementation, arguments_, definition, input) {
  const result = execute(implementation, arguments_, input);
  assert.equal(result.status, 0, result.stderr || result.stdout);
  assert.equal(result.stderr, "", "successful JSON commands leave stderr empty");
  const output = JSON.parse(result.stdout);
  assertJsonSchema(output, cliSchema, definition);
  return output;
}

function assertObject(value, label) {
  assert.ok(value && typeof value === "object" && !Array.isArray(value), label);
}

async function exists(path) {
  try {
    await stat(path);
    return true;
  } catch (error) {
    if (error?.code === "ENOENT") return false;
    throw error;
  }
}

const suitePath = fileURLToPath(new URL("suite.json", import.meta.url));
const suite = JSON.parse(await readFile(suitePath, "utf8"));
const cliSchema = JSON.parse(
  await readFile(new URL("../../schemas/cli/1/folderbase-cli-json.schema.json", import.meta.url), "utf8"),
);
const implementation = implementationArgument(process.argv.slice(2));
const root = await realpath(await mkdtemp(join(tmpdir(), "folderbase-cli-conformance-")));
const legacyRoot = await realpath(
  await mkdtemp(join(tmpdir(), "folderbase-upgrade-conformance-")),
);
const notePath = join(root, "notes.md");
const state = {};
const handlers = {
  "discover-compatibility-contract": async () => {
    const output = successJson(
      implementation,
      ["protocol", "contract", "--json"],
      "compatibilityDescriptor",
    );
    assert.equal(output.format, "folderbase-compatibility-contract-v1");
    assert.equal(output.contract_version, "1.0.0");
    assert.equal(output.cli_json, "folderbase-cli-json-v1");
    assert.ok(output.protocol_profiles.root_manifest.includes("0.5.0"));
    assert.ok(output.protocol_profiles.folderbase_version.includes("0.4"));
    assert.ok(output.protocol_profiles.folderbase_version.includes("0.5"));
    assert.ok(
      output.protocol_profiles.chunk_manifest.includes("folderbase-chunk-manifest-v1"),
    );
  },
  "inspect-ordinary-folder": async () => {
    const output = successJson(implementation, ["inspect", root, "--json"], "inspection");
    assert.equal(output.root, root);
    assertObject(output.inventory, "inspection inventory");
    assert.ok(output.inventory.file_count >= 3);
    assert.ok(output.inventory.total_bytes >= 6);
    for (const field of [
      "classified_paths",
      "git_repositories",
      "context_files",
      "boundary_hints",
      "reconstructable_trees",
      "nested_folderbases",
      "warnings",
    ]) {
      assert.ok(Array.isArray(output[field]), `${field} is an array`);
    }
    assert.ok(output.classified_paths.length > 0, "classification item contract is exercised");
    assert.ok(output.git_repositories.length > 0, "Git repository item contract is exercised");
    assert.ok(output.context_files.length > 0, "context item contract is exercised");
    assert.ok(output.reconstructable_trees.length > 0, "reconstructable item contract is exercised");
  },
  "plan-read-only-initialization": async () => {
    const output = successJson(
      implementation,
      ["init", root, "--dry-run", "--json"],
      "initializationPlan",
    );
    assert.equal(output.root, root);
    assert.match(output.folderbase_id, FOLDERBASE_ID);
    assert.equal(output.folderbase_kind, "project");
    assert.equal(output.plan_digest.algorithm, "sha256");
    assert.match(output.plan_digest.digest, SHA256);
    assert.ok(output.writes.some((write) => write.path === ".folderbase/manifest.json"));
    assert.equal(await exists(join(root, ".folderbase")), false);
    assert.equal(await readFile(notePath, "utf8"), NOTE_BYTES);
    state.planDigest = output.plan_digest.digest;
  },
  "apply-reviewed-initialization": async () => {
    assert.match(state.planDigest, SHA256);
    const output = successJson(
      implementation,
      ["init", root, "--expected-plan-digest", state.planDigest, "--json"],
      "initializationResult",
    );
    assert.match(output.folderbase_id, FOLDERBASE_ID);
    assert.equal(output.applied_plan_digest.digest, state.planDigest);
    assert.ok(output.created_paths.includes(".folderbase/manifest.json"));
    assert.equal(await exists(join(root, ".folderbase", "manifest.json")), true);
    assert.equal(await readFile(notePath, "utf8"), NOTE_BYTES);
  },
  "plan-reviewed-upgrade": async () => {
    const output = successJson(
      implementation,
      ["upgrade", legacyRoot, "--dry-run", "--json"],
      "upgradePlan",
    );
    assert.equal(output.root, legacyRoot);
    assert.equal(output.folderbase_id, "folderbase_019f9b75-4f42-7f65-a012-2bfecdd8c475");
    assert.equal(output.from_protocol_version, "0.1.0");
    assert.equal(output.to_protocol_version, "0.5.0");
    assert.ok(output.changed_paths.includes(".folderbase/manifest.json"));
    assert.equal(output.plan_digest.algorithm, "sha256");
    assert.match(output.plan_digest.digest, SHA256);
    assert.equal(
      await readFile(join(legacyRoot, ".folderbase/manifest.json"), "utf8"),
      LEGACY_MANIFEST,
    );
    assert.equal(await readFile(join(legacyRoot, "proposal.docx"), "utf8"), "ordinary bytes");
    state.upgradePlanDigest = output.plan_digest.digest;
  },
  "apply-reviewed-upgrade": async () => {
    assert.match(state.upgradePlanDigest, SHA256);
    const output = successJson(
      implementation,
      ["upgrade", legacyRoot, "--expected-plan-digest", state.upgradePlanDigest, "--json"],
      "upgradeResult",
    );
    assert.equal(output.from_protocol_version, "0.1.0");
    assert.equal(output.to_protocol_version, "0.5.0");
    assert.equal(output.applied_plan_digest.digest, state.upgradePlanDigest);
    assert.equal(await readFile(join(legacyRoot, "FOLDERBASE.md"), "utf8"), "# Project 2\n");
    assert.equal(await readFile(join(legacyRoot, ".folderbaseignore"), "utf8"), "node_modules/\n");
    assert.equal(await readFile(join(legacyRoot, "proposal.docx"), "utf8"), "ordinary bytes");
    const manifest = JSON.parse(
      await readFile(join(legacyRoot, ".folderbase/manifest.json"), "utf8"),
    );
    assert.equal(manifest.protocol_version, "0.5.0");
  },
  "attest-exact-root": async () => {
    const output = successJson(implementation, ["attest", root, "--json"], "attestation");
    assert.match(output.folderbase_id, FOLDERBASE_ID);
    assert.equal(output.protocol_version, "0.5.0");
    assert.match(output.manifest_sha256, SHA256);
    assert.match(output.root_instance_sha256, SHA256);
  },
  "validate-shallow": async () => {
    const output = successJson(
      implementation,
      ["validate", root, "--level", "shallow", "--json"],
      "validation",
    );
    assert.equal(output.root, root);
    assert.equal(output.level, "shallow");
    assert.equal(output.valid, true);
    assert.deepEqual(output.findings, []);
  },
  "list-workspace": async () => {
    await symlink("notes.md", join(root, "notes-link"));
    const output = successJson(
      implementation,
      ["workspace", "list", root, "--json"],
      "workspaceListing",
    );
    assert.equal(output.root, root);
    const note = output.entries.find((entry) => entry.path === "notes.md");
    assertObject(note, "notes.md listing");
    assert.equal(note.name, "notes.md");
    assert.equal(note.kind, "file");
    assert.equal(note.bytes, 6);
    assert.equal(note.editable, true);
    assert.equal(note.reconstructable, false);
    const link = output.entries.find((entry) => entry.path === "notes-link");
    assertObject(link, "notes-link listing");
    assert.equal(link.kind, "symlink");
    assert.equal(link.editable, false);
  },
  "read-workspace-text": async () => {
    const output = successJson(
      implementation,
      ["workspace", "read", root, "notes.md", "--json"],
      "workspaceRead",
    );
    assert.equal(output.path, "notes.md");
    assert.equal(output.content, NOTE_BYTES);
    assert.equal(output.sha256, NOTE_SHA256);
    assert.equal(output.bytes, 6);
  },
  "save-workspace-text": async () => {
    const output = successJson(
      implementation,
      [
        "workspace",
        "save",
        root,
        "notes.md",
        "--expected-sha256",
        NOTE_SHA256,
        "--stdin",
        "--json",
      ],
      "workspaceSave",
      UPDATED_BYTES,
    );
    assert.equal(output.path, "notes.md");
    assert.equal(output.previous_sha256, NOTE_SHA256);
    assert.equal(output.document.path, "notes.md");
    assert.equal(output.document.sha256, UPDATED_SHA256);
    assert.equal(output.document.bytes, 8);
    assert.match(output.object_id, OBJECT_ID);
    assert.match(output.version_id, VERSION_ID);
    assert.equal(await readFile(notePath, "utf8"), UPDATED_BYTES);
  },
  "encode-operational-error": async () => {
    const result = execute(implementation, ["inspect", join(root, "missing"), "--json"]);
    assert.equal(result.status, 2);
    assert.equal(result.stdout, "");
    const output = JSON.parse(result.stderr);
    assertJsonSchema(output, cliSchema, "error");
    assert.deepEqual(Object.keys(output), ["error"]);
    assert.deepEqual(Object.keys(output.error).sort(), ["code", "message"]);
    assert.equal(output.error.code, "invalid_root");
    assert.equal(typeof output.error.message, "string");
    assert.ok(output.error.message.length > 0);
  },
};

const report = {
  format: FORMAT,
  suite: suite.format,
  interface: suite.interface,
  implementation: basename(implementation),
  protocol_cases: 0,
  passed: 0,
  failed: 0,
  cases: [],
};

async function runProtocolGroup(group) {
  for (const expectation of ["valid", "invalid"]) {
    const directory = resolve(dirname(suitePath), group[expectation]);
    const fixtures = (await readdir(directory, { withFileTypes: true }))
      .filter((entry) => entry.isFile() && entry.name.endsWith(".json"))
      .map((entry) => entry.name)
      .sort();
    for (const fixture of fixtures) {
      const id = `${group.artifact}:${expectation}:${fixture}`;
      const result = { id, status: "passed" };
      report.protocol_cases += 1;
      try {
        const encoded = await readFile(join(directory, fixture));
        if (group.artifact === "root-manifest") {
          const caseRoot = await realpath(
            await mkdtemp(join(tmpdir(), "folderbase-manifest-conformance-")),
          );
          try {
            await mkdir(join(caseRoot, ".folderbase"));
            await writeFile(join(caseRoot, ".folderbase", "manifest.json"), encoded);
            const execution = execute(implementation, ["attest", caseRoot, "--json"]);
            if (expectation === "valid") {
              assert.equal(execution.status, 0, execution.stderr);
              assert.equal(execution.stderr, "");
              const output = JSON.parse(execution.stdout);
              assertJsonSchema(output, cliSchema, "attestation");
              assert.equal(output.root, caseRoot);
              assert.equal(output.protocol_version, "0.5.0");
              assert.match(output.folderbase_id, FOLDERBASE_ID);
              assert.match(output.manifest_sha256, SHA256);
              assert.match(output.root_instance_sha256, SHA256);
              const sidecar = join(directory, fixture.replace(/\.json$/, ".sha256"));
              assert.equal(output.manifest_sha256, (await readFile(sidecar, "utf8")).trim());
            } else {
              assert.equal(execution.status, 2, id);
              assert.equal(execution.stdout, "");
              const output = JSON.parse(execution.stderr);
              assertJsonSchema(output, cliSchema, "error");
              assert.equal(typeof output.error.code, "string");
              assert.ok(output.error.code.length > 0);
              assert.equal(typeof output.error.message, "string");
              assert.ok(output.error.message.length > 0);
            }
          } finally {
            await rm(caseRoot, { recursive: true, force: true });
          }
          report.passed += 1;
          report.cases.push(result);
          continue;
        }
        const execution = execute(
          implementation,
          ["protocol", "check", group.artifact, "--stdin", "--json"],
          encoded,
        );
        assert.equal(execution.stderr, "", `${id} leaves stderr empty`);
        const output = JSON.parse(execution.stdout);
        assertJsonSchema(output, cliSchema, "protocolCheck");
        assert.equal(output.artifact, group.artifact);
        if (expectation === "valid") {
          assert.equal(execution.status, 0, id);
          assert.equal(output.valid, true);
          assert.match(output.canonical_digest, SHA256);
          const sidecar = join(directory, fixture.replace(/\.json$/, ".sha256"));
          if (await exists(sidecar)) {
            assert.equal(output.canonical_digest, (await readFile(sidecar, "utf8")).trim());
          }
        } else {
          assert.equal(execution.status, 1, id);
          assert.equal(output.valid, false);
          assert.equal(output.error.code, "invalid_artifact");
          assert.equal(typeof output.error.message, "string");
          assert.ok(output.error.message.length > 0);
        }
        report.passed += 1;
      } catch (error) {
        result.status = "failed";
        result.message = error instanceof Error ? error.message : String(error);
        report.failed += 1;
      }
      report.cases.push(result);
    }
  }
}

try {
  await writeFile(notePath, NOTE_BYTES);
  await writeFile(join(root, "README.md"), "# Project 2\n");
  await writeFile(join(root, ".env"), "TOKEN=fixture\n");
  await mkdir(join(root, "node_modules", "fixture"), { recursive: true });
  await writeFile(join(root, "node_modules", "fixture", "index.js"), "export {};\n");
  await mkdir(join(root, ".git"));
  await writeFile(join(root, ".git", "HEAD"), "ref: refs/heads/main\n");
  await mkdir(join(legacyRoot, ".folderbase"));
  await writeFile(join(legacyRoot, ".folderbase", "manifest.json"), LEGACY_MANIFEST);
  await writeFile(join(legacyRoot, "FOLDERBASE.md"), "# Project 2\n");
  await writeFile(join(legacyRoot, ".folderbaseignore"), "node_modules/\n");
  await writeFile(join(legacyRoot, "proposal.docx"), "ordinary bytes");
  for (const group of suite.artifact_groups) {
    await runProtocolGroup(group);
  }
  for (const testCase of suite.cases) {
    const result = { id: testCase.id, status: "passed" };
    try {
      const handler = handlers[testCase.id];
      assert.equal(typeof handler, "function", `unknown suite case ${testCase.id}`);
      await handler();
      report.passed += 1;
    } catch (error) {
      result.status = "failed";
      result.message = error instanceof Error ? error.message : String(error);
      report.failed += 1;
    }
    report.cases.push(result);
  }
} finally {
  await rm(root, { recursive: true, force: true });
  await rm(legacyRoot, { recursive: true, force: true });
}

process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
process.exitCode = report.failed === 0 ? 0 : 1;

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { access, mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { assertFolderScopeEvidenceSchema, assertJsonSchema } from "./schema.mjs";

const directory = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = resolve(directory, "../../../..");
const schema = JSON.parse(
  await readFile(
    resolve(
      directory,
      "../../../schemas/capabilities/folder-scope-evidence/0.1/folder-scope-evidence.schema.json",
    ),
    "utf8",
  ),
);

const success = {
  format: "folderbase-folder-scope-evidence-v1",
  folderbase_id: "folderbase_019fb97e-9c5f-73ca-9bb2-03dc80f94792",
  selected_path: "Client Work",
  event_id: `folder_scope_event_${"a".repeat(64)}`,
  device_sequence: 1,
  opaque_binding_proof: `fb_scope_binding_v1_${"b".repeat(64)}`,
  nested_boundaries: ["Client Work/Partner"],
};

const error = {
  format: "folderbase-folder-scope-evidence-error-v1",
  error: {
    code: "selected_folder_replaced",
    message: "the selected folder was replaced",
  },
};

test("stable capability package is advertised identically", async () => {
  const packageEntry = JSON.parse(
    await readFile(
      resolve(directory, "../../../capabilities/folder-scope-evidence/0.1.0/capability.json"),
      "utf8",
    ),
  );
  assert.deepEqual(packageEntry, {
    name: "folderbase.folder-scope-evidence",
    version: "0.1.0",
    stability: "stable",
    conformance_runner:
      "protocol/conformance/capabilities/folder-scope-evidence-0.1/run.mjs",
  });
  for (const registry of [
    "protocol/capabilities/v1/registry.json",
    "crates/folderbase-cli/assets/capability-registry-v1.json",
  ]) {
    const document = JSON.parse(await readFile(join(repositoryRoot, registry), "utf8"));
    assert.deepEqual(
      document.capabilities.find(({ name }) => name === packageEntry.name),
      packageEntry,
      registry,
    );
  }
});

test("public evidence and error records are closed bounded Draft 2020-12 schemas", () => {
  assert.equal(schema.$schema, "https://json-schema.org/draft/2020-12/schema");
  assert.equal(
    schema.$id,
    "https://folderbase.ai/protocol/capabilities/folder-scope-evidence/0.1/folder-scope-evidence.schema.json",
  );
  assert.equal(schema.$defs.evidence.additionalProperties, false);
  assert.equal(schema.$defs.error.additionalProperties, false);
  assert.equal(schema.$defs.errorDetail.additionalProperties, false);
  assert.equal(schema.$defs.evidence.properties.device_sequence.maximum, 16_384);
  assert.equal(schema.$defs.evidence.properties.nested_boundaries.maxItems, 256);

  assertFolderScopeEvidenceSchema(success, schema, "evidence");
  assertFolderScopeEvidenceSchema(error, schema, "error");
  assertJsonSchema(success, schema);
  assertJsonSchema(error, schema);

  const openEvidence = { ...success, cloud_grant: "ambient-authority" };
  assert.throws(
    () => assertFolderScopeEvidenceSchema(openEvidence, schema, "evidence"),
    /cloud_grant is not allowed/,
  );
  const absolutePath = { ...success, selected_path: "/Users/example/Client Work" };
  assert.throws(
    () => assertFolderScopeEvidenceSchema(absolutePath, schema, "evidence"),
    /invalid format/,
  );
  const reservedAlias = { ...success, selected_path: "Client Work/.FOLDERBASE" };
  assert.throws(
    () => assertFolderScopeEvidenceSchema(reservedAlias, schema, "evidence"),
    /invalid format/,
  );
  const duplicateBoundary = {
    ...success,
    nested_boundaries: ["Client Work/Partner", "Client Work/Partner"],
  };
  assert.throws(
    () => assertFolderScopeEvidenceSchema(duplicateBoundary, schema, "evidence"),
    /duplicate items/,
  );
});

test("missing operation produces one complete deterministic eleven-case RED report", () => {
  const candidate = join(directory, "fixtures", "missing-folder-scope-candidate.mjs");
  const result = spawnSync(
    process.execPath,
    [join(directory, "run.mjs"), "--implementation", candidate],
    { encoding: "utf8", maxBuffer: 2 * 1024 * 1024, timeout: 30_000 },
  );
  assert.equal(result.status, 1, result.error?.message || result.stderr || result.stdout);
  const report = JSON.parse(result.stdout);
  assert.equal(report.format, "folderbase-capability-suite-report-v1");
  assert.equal(report.capability, "folderbase.folder-scope-evidence@0.1.0");
  assert.equal(report.passed, 0);
  assert.equal(report.failed, 1);
  assert.equal(report.cases[0].id, "capability-discovery");
  assert.equal(report.cases[0].status, "failed");
});

test("schema-invalid evidence cannot pass the stable black-box suite", () => {
  const candidate = join(directory, "fixtures", "malformed-folder-scope-candidate.mjs");
  const result = spawnSync(
    process.execPath,
    [join(directory, "run.mjs"), "--implementation", candidate],
    { encoding: "utf8", maxBuffer: 2 * 1024 * 1024, timeout: 30_000 },
  );
  assert.equal(result.status, 1, result.error?.message || result.stderr || result.stdout);
  const report = JSON.parse(result.stdout);
  assert.equal(report.passed, 1);
  assert.equal(report.failed, 1);
  assert.equal(report.cases[0].id, "capability-discovery");
  assert.equal(report.cases[0].status, "passed");
  assert.equal(report.cases[1].id, "idempotent-arbitrary-folder-observation");
  assert.equal(report.cases[1].status, "failed");
  assert.match(report.cases[1].message, /folderbase_id has an invalid format/u);
});

test("candidate timeout reaps its descendant process tree", async () => {
  const temporary = await mkdtemp(join(tmpdir(), "folderbase-scope-supervisor-"));
  const marker = join(temporary, "escaped-descendant.txt");
  try {
    const candidate = join(directory, "fixtures", "hanging-folder-scope-candidate.mjs");
    const result = spawnSync(
      process.execPath,
      [join(directory, "run.mjs"), "--implementation", candidate],
      {
        encoding: "utf8",
        env: {
          ...process.env,
          FOLDERBASE_FOLDER_SCOPE_CONFORMANCE_COMMAND_TIMEOUT_MS: "100",
          FOLDERBASE_FOLDER_SCOPE_DESCENDANT_MARKER: marker,
        },
        maxBuffer: 2 * 1024 * 1024,
        timeout: 5_000,
      },
    );
    assert.equal(result.status, 1, result.error?.message || result.stderr || result.stdout);
    assert.match(JSON.parse(result.stdout).cases[0].message, /timed out/u);
    await new Promise((resolveDelay) => setTimeout(resolveDelay, 1_200));
    await assert.rejects(access(marker));
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("candidate exit still reaps its descendant process tree", async () => {
  const temporary = await mkdtemp(join(tmpdir(), "folderbase-scope-exit-supervisor-"));
  const marker = join(temporary, "escaped-descendant.txt");
  try {
    const candidate = join(directory, "fixtures", "exiting-folder-scope-candidate.mjs");
    const result = spawnSync(
      process.execPath,
      [join(directory, "run.mjs"), "--implementation", candidate],
      {
        encoding: "utf8",
        env: {
          ...process.env,
          FOLDERBASE_FOLDER_SCOPE_DESCENDANT_MARKER: marker,
        },
        maxBuffer: 2 * 1024 * 1024,
        timeout: 5_000,
      },
    );
    assert.equal(result.status, 1, result.error?.message || result.stderr || result.stdout);
    const report = JSON.parse(result.stdout);
    assert.equal(report.cases[0].status, "passed");
    assert.equal(report.cases[1].status, "failed");
    await new Promise((resolveDelay) => setTimeout(resolveDelay, 1_200));
    await assert.rejects(access(marker));
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("Windows supervision assigns the blocked worker to a kill-on-close Job Object", async () => {
  const source = await readFile(join(directory, "command-supervisor-windows.ps1"), "utf8");
  assert.match(source, /JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE/u);
  assert.match(source, /UTF8Encoding\(\$false\)/u);
  assert.match(source, /System\.IO\.StreamWriter\]::new/u);
  assert.match(
    source,
    /System\.IO\.StreamWriter\]::new\([\s\S]*?4096,[\s\S]*?\$false\)/u,
  );
  assert.equal((source.match(/System\.IO\.StreamReader\]::new/gu) ?? []).length, 2);
  const assigned = source.indexOf("[FolderbaseKillOnCloseJob]::Assign($job, $worker)");
  const released = source.indexOf("$workerInput.Write($payloadText)");
  assert.ok(assigned !== -1 && released !== -1 && assigned < released);
});

test(
  "Windows Job Object supervision preserves Unicode JSON and candidate output",
  { skip: process.platform !== "win32" },
  () => {
    const marker = "C:\\\\项目\\\\résumé\\\\δοκιμή";
    const payload = JSON.stringify({
      command: process.execPath,
      args: ["-e", "process.stdout.write(process.env.FOLDERBASE_UNICODE_MARKER)"],
      input: "",
      timeoutMs: 5_000,
      maxBytes: 1024 * 1024,
      environment: { FOLDERBASE_UNICODE_MARKER: marker },
    });
    const result = spawnSync(process.execPath, [join(directory, "command-supervisor.mjs")], {
      encoding: "utf8",
      input: payload,
      maxBuffer: 2 * 1024 * 1024,
      timeout: 10_000,
    });
    assert.equal(result.status, 0, result.error?.message || result.stderr || result.stdout);
    const outcome = JSON.parse(result.stdout);
    assert.equal(outcome.status, 0);
    assert.equal(outcome.stdout, marker);
  },
);

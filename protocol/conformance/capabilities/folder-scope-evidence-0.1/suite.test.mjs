import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFile } from "node:fs/promises";
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
  assert.equal(schema.$defs.evidence.properties.nested_boundaries.maxItems, 16_384);

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

test("missing operation produces one complete deterministic seven-case RED report", () => {
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

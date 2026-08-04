import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile, readdir } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { changeSetSha256 } from "./reference-change-set-digest.mjs";
import { assertChangeSetSchema } from "./schema.mjs";

const directory = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = resolve(directory, "../../../..");
const fixtures = join(directory, "fixtures");
const schema = JSON.parse(
  await readFile(
    resolve(directory, "../../../schemas/capabilities/change-set/0.1/change-set.schema.json"),
    "utf8",
  ),
);

test("stable capability package is advertised identically", async () => {
  const packageEntry = JSON.parse(
    await readFile(
      resolve(directory, "../../../capabilities/change-set/0.1.0/capability.json"),
      "utf8",
    ),
  );
  assert.deepEqual(packageEntry, {
    name: "folderbase.change-set",
    version: "0.1.0",
    stability: "stable",
    conformance_runner: "protocol/conformance/capabilities/change-set-0.1/run.mjs",
  });
  for (const registry of [
    "protocol/capabilities/v1/registry.json",
    "crates/folderbase-cli/assets/capability-registry-v1.json",
  ]) {
    const value = JSON.parse(await readFile(join(repositoryRoot, registry), "utf8"));
    assert.deepEqual(
      value.capabilities.find(({ name }) => name === "folderbase.change-set"),
      packageEntry,
      registry,
    );
  }
});

test("public schema is closed Draft 2020-12 and the legacy prototype is unchanged", async () => {
  assert.equal(schema.$schema, "https://json-schema.org/draft/2020-12/schema");
  assert.equal(
    schema.$id,
    "https://folderbase.ai/protocol/capabilities/change-set/0.1/change-set.schema.json",
  );
  const legacy = await readFile(join(repositoryRoot, "protocol/schemas/0.1/change-set.schema.json"));
  assert.equal(
    createHash("sha256").update(legacy).digest("hex"),
    "1f489a1cefe0e0dc70e604e79ce4c9727160944f5129d6f6b75353fcb533363c",
  );
});

test("canonical Change Set digest is fixed independently of JSON member order", async () => {
  const envelope = JSON.parse(await readFile(join(fixtures, "canonical-change-set.json"), "utf8"));
  const expected = (await readFile(join(fixtures, "canonical-change-set.sha256"), "utf8")).trim();
  assertChangeSetSchema(envelope, schema, "changeSetEnvelope");
  assert.equal(changeSetSha256(envelope.payload), expected);
  assert.equal(envelope.change_set_sha256, expected);
  const reordered = Object.fromEntries(Object.entries(envelope.payload).reverse());
  assert.equal(changeSetSha256(reordered), expected);

  const unknown = structuredClone(envelope);
  unknown.payload.unapproved_extension = true;
  assert.throws(() => assertChangeSetSchema(unknown, schema, "changeSetEnvelope"));
  const emptyDelta = structuredClone(envelope);
  emptyDelta.payload.deltas[0].before = null;
  emptyDelta.payload.deltas[0].after = null;
  assert.throws(() => assertChangeSetSchema(emptyDelta, schema, "changeSetEnvelope"));
});

test("every public process document has one closed independently validated shape", () => {
  const sha = "a".repeat(64);
  const ids = {
    folderbase_id: "folderbase_019f0000-0000-7000-8000-000000000001",
    projection_id: "projection_019f0000-0000-7000-8000-000000000101",
    folder_scope_id: "folderscope_019f0000-0000-7000-8000-000000000001",
  };
  const scope = {
    ...ids,
    scope_revision_sha256: sha,
    permission: "can_work",
    authorized_paths: [{ path_prefix: "shared" }],
  };
  assert.doesNotThrow(() => assertChangeSetSchema({
    format: "folderbase-checkout-request-v1",
    ...scope,
  }, schema, "checkoutRequest"));
  assert.doesNotThrow(() => assertChangeSetSchema({
    format: "folderbase-checkout-projection-v1",
    checkout_id: "checkout_019f0000-0000-7000-8000-000000000201",
    ...scope,
    projection_base_sha256: sha,
    entries: [],
    exclusions: [],
  }, schema, "checkoutReceipt"));
  assert.doesNotThrow(() => assertChangeSetSchema({
    format: "folderbase-checkout-result-v1",
    checkout_id: "checkout_019f0000-0000-7000-8000-000000000201",
    projection_id: ids.projection_id,
    projection_base_sha256: sha,
    entry_count: 0,
    exclusion_count: 0,
  }, schema, "checkoutResult"));
  assert.doesNotThrow(() => assertChangeSetSchema({
    format: "folderbase-change-set-staging-v1",
    objects: [],
  }, schema, "stagingIndex"));
  assert.doesNotThrow(() => assertChangeSetSchema({
    format: "folderbase-change-set-assessment-v1",
    change_set_sha256: sha,
    status: "clean",
    conflicts: [],
    current_projection_sha256: sha,
  }, schema, "changeSetAssessment"));
  assert.doesNotThrow(() => assertChangeSetSchema({
    format: "folderbase-change-set-apply-result-v1",
    change_set_sha256: sha,
    status: "applied",
    projection_result_sha256: sha,
  }, schema, "changeSetApplyResult"));
  assert.doesNotThrow(() => assertChangeSetSchema({
    format: "folderbase-change-set-attention-v1",
    change_set_sha256: sha,
    attention: {
      code: "change_set_stale_base",
      message: "projection base is no longer retained",
      retryable: true,
      conflicts: [],
    },
  }, schema, "changeSetAttention"));
  assert.doesNotThrow(() => assertChangeSetSchema({
    format: "folderbase-change-set-error-v1",
    error: {
      code: "invalid_staging",
      message: "staging is incomplete",
    },
  }, schema, "changeSetError"));
});

test("fixture inventory covers every accepted Change Set risk before runtime exists", async () => {
  const scenarios = await Promise.all(
    (await readdir(join(fixtures, "scenarios")))
      .filter((name) => name.endsWith(".json"))
      .sort()
      .map(async (name) => JSON.parse(await readFile(join(fixtures, "scenarios", name), "utf8"))),
  );
  assert.equal(scenarios.length, 10);
  const covered = new Set(scenarios.flatMap(({ covers }) => covers));
  for (const required of [
    "clean",
    "disjoint",
    "move",
    "edit",
    "opaque-binary",
    "large-object",
    "chunk-manifest-staging",
    "delete-edit",
    "create-create",
    "rename",
    "unicode-nfc",
    "unicode-case-fold",
    "nested-folderbase-boundary",
    "missing-projection-base",
    "crash-after-prepare",
    "crash-mid-publication",
    "crash-mid-in-place-write",
    "crash-after-history-head",
    "restart-recovery",
    "idempotent-replay",
  ]) assert.ok(covered.has(required), required);
});

test("missing capability produces one complete ten-case RED report", () => {
  const candidate = join(fixtures, "missing-change-set-candidate.mjs");
  const result = spawnSync(
    process.execPath,
    [join(directory, "run.mjs"), "--implementation", candidate],
    { encoding: "utf8", maxBuffer: 16 * 1024 * 1024, timeout: 30_000 },
  );
  assert.equal(result.status, 1, result.stderr);
  const report = JSON.parse(result.stdout);
  assert.equal(report.format, "folderbase-capability-suite-report-v1");
  assert.equal(report.capability, "folderbase.change-set@0.1.0");
  assert.equal(report.total, 10);
  assert.equal(report.passed, 0);
  assert.equal(report.failed, 10);
  assert.ok(report.cases.every(({ status }) => status === "failed"));
});

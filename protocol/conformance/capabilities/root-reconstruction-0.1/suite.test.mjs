import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { mkdtemp, readFile, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { writeCanonicalFixture } from "./fixture-generator.mjs";
import { rootReconstructionRequestSha256 } from "./reference-digests.mjs";
import { assertRootReconstructionSchema } from "./schema.mjs";

const directory = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = resolve(directory, "../../../..");
const fixtures = join(directory, "fixtures");
const schema = JSON.parse(
  await readFile(
    resolve(
      directory,
      "../../../schemas/capabilities/root-reconstruction/0.1/root-reconstruction.schema.json",
    ),
    "utf8",
  ),
);

async function treeDigests(root, relative = "") {
  const result = [];
  for (const entry of await readdir(join(root, relative), { withFileTypes: true })) {
    const child = join(relative, entry.name);
    if (entry.isDirectory()) result.push(...await treeDigests(root, child));
    else {
      assert.equal(entry.isFile(), true, `${child} is a regular file`);
      const bytes = await readFile(join(root, child));
      result.push([child, createHash("sha256").update(bytes).digest("hex"), bytes.length]);
    }
  }
  return result.sort(([left], [right]) => Buffer.compare(Buffer.from(left), Buffer.from(right)));
}

test("stable package is selectable but the executable does not advertise it before GREEN", async () => {
  const packageEntry = JSON.parse(
    await readFile(
      resolve(directory, "../../../capabilities/root-reconstruction/0.1.0/capability.json"),
      "utf8",
    ),
  );
  assert.deepEqual(packageEntry, {
    name: "folderbase.root-reconstruction",
    version: "0.1.0",
    stability: "stable",
    conformance_runner:
      "protocol/conformance/capabilities/root-reconstruction-0.1/run.mjs",
  });
  const publicRegistry = JSON.parse(
    await readFile(join(repositoryRoot, "protocol/capabilities/v1/registry.json"), "utf8"),
  );
  assert.deepEqual(
    publicRegistry.capabilities.find(({ name }) => name === packageEntry.name),
    packageEntry,
  );
  const embeddedRegistry = JSON.parse(
    await readFile(
      join(repositoryRoot, "crates/folderbase-cli/assets/capability-registry-v1.json"),
      "utf8",
    ),
  );
  assert.equal(
    embeddedRegistry.capabilities.some(({ name }) => name === packageEntry.name),
    false,
  );
});

test("public package and process records are closed bounded Draft 2020-12 schemas", async () => {
  assert.equal(schema.$schema, "https://json-schema.org/draft/2020-12/schema");
  assert.equal(
    schema.$id,
    "https://folderbase.ai/protocol/capabilities/root-reconstruction/0.1/root-reconstruction.schema.json",
  );
  for (const definition of [
    "packageIndex",
    "packageReference",
    "packageLimits",
    "request",
    "result",
    "attention",
    "error",
    "rootAttestation",
  ]) {
    assert.equal(schema.$defs[definition].additionalProperties, false, definition);
  }
  assert.deepEqual(schema.$defs.packageLimits.properties, {
    max_index_bytes: { const: 8388608 },
    max_version_bytes: { const: 67108864 },
    max_manifest_bytes: { const: 67108864 },
    max_references: { const: 16385 },
    max_distinct_manifests: { const: 16385 },
    max_distinct_chunks: { const: 1048576 },
    max_chunks_per_manifest: { const: 262144 },
    max_object_bytes: { const: 1099511627776 },
    max_total_object_bytes: { const: 9007199254740991 },
    max_visible_entries: { const: 16384 },
  });
  assert.deepEqual(schema.$defs.rootAttestation.properties.protocol_version.enum, [
    "0.4.0",
    "0.5.0",
  ]);
  assert.ok(
    schema.$defs.errorDetail.properties.code.enum.includes(
      "unsupported_reconstruction_filesystem",
    ),
  );
});

test("canonical package generator is deterministic and pins exact encoded transport bytes", async () => {
  const first = await mkdtemp(join(tmpdir(), "folderbase-reconstruction-fixture-a-"));
  const second = await mkdtemp(join(tmpdir(), "folderbase-reconstruction-fixture-b-"));
  try {
    const firstFixture = await writeCanonicalFixture(first);
    const secondFixture = await writeCanonicalFixture(second);
    assert.deepEqual(await treeDigests(first), await treeDigests(second));
    assert.deepEqual(firstFixture, secondFixture);

    const expected = JSON.parse(await readFile(join(fixtures, "canonical-expected.json"), "utf8"));
    assert.deepEqual(firstFixture.expected, expected);
    assertRootReconstructionSchema(firstFixture.index, schema, "packageIndex");
    assertRootReconstructionSchema(firstFixture.request, schema, "request");
    assert.equal(
      rootReconstructionRequestSha256(firstFixture.request),
      expected.request_sha256,
    );
    assert.deepEqual(
      firstFixture.index.references.map(({ object_version_id }) => object_version_id),
      [...firstFixture.index.references.map(({ object_version_id }) => object_version_id)].sort(),
    );
    assert.equal(
      firstFixture.index.references.filter(({ roles }) => roles.includes("root_manifest")).length,
      1,
    );
    assert.ok(
      firstFixture.index.references.some(({ roles }) => roles.includes("retained_tombstone")),
    );
    assert.ok(
      firstFixture.index.references.some(({ roles }) =>
        roles.length === 2
        && roles[0] === "live_regular_file"
        && roles[1] === "retained_tombstone"),
    );

    const unknown = structuredClone(firstFixture.index);
    unknown.provider = "ambient-cloud";
    assert.throws(
      () => assertRootReconstructionSchema(unknown, schema, "packageIndex"),
      /provider is not allowed/,
    );
  } finally {
    await Promise.all([
      rm(first, { recursive: true, force: true }),
      rm(second, { recursive: true, force: true }),
    ]);
  }
});

test("scenario inventory covers bounded transport, closure, no-clobber, and restart risks", async () => {
  const scenarios = JSON.parse(await readFile(join(fixtures, "scenarios.json"), "utf8"));
  assert.equal(scenarios.format, "folderbase-root-reconstruction-scenarios-v1");
  assert.equal(scenarios.cases.length, 11);
  assert.deepEqual(
    scenarios.cases.map(({ id }) => id),
    [...new Set(scenarios.cases.map(({ id }) => id))].sort(),
  );
  const covered = new Set(scenarios.cases.flatMap(({ covers }) => covers));
  for (const required of [
    "mixed-opaque-files",
    "retained-tombstone-closure",
    "move-with-tombstone-shared-reference",
    "exact-package-index-pin",
    "malformed-request",
    "changed-version-bytes",
    "missing-retained-reference",
    "corrupt-chunk",
    "no-follow-package",
    "destination-no-clobber",
    "crash-before-publication",
    "crash-after-publication",
    "exact-replay",
    "no-ambient-authority",
    "unsupported-filesystem-preflight",
  ]) assert.ok(covered.has(required), required);
});

test("missing transport produces one complete deterministic RED report", () => {
  const result = spawnSync(
    process.execPath,
    [
      join(directory, "run.mjs"),
      "--implementation",
      join(fixtures, "missing-reconstruction-candidate.mjs"),
    ],
    { encoding: "utf8", maxBuffer: 16 * 1024 * 1024, timeout: 30_000 },
  );
  assert.equal(result.status, 1, result.stderr);
  const report = JSON.parse(result.stdout);
  assert.equal(report.format, "folderbase-capability-suite-report-v1");
  assert.equal(report.capability, "folderbase.root-reconstruction@0.1.0");
  assert.equal(report.total, 11);
  assert.equal(report.passed, 0);
  assert.equal(report.failed, 11);
  assert.ok(report.cases.every(({ status }) => status === "failed"));
});

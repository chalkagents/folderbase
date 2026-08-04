import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const directory = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = resolve(directory, "../../../..");

test("experimental daemon package is advertised identically after GREEN", async () => {
  const packageEntry = JSON.parse(
    await readFile(
      resolve(directory, "../../../capabilities/daemon-stdio/0.1.0/capability.json"),
      "utf8",
    ),
  );
  assert.deepEqual(packageEntry, {
    name: "folderbase.daemon-stdio",
    version: "0.1.0",
    stability: "experimental",
    conformance_runner: "protocol/conformance/capabilities/daemon-stdio-0.1/run.mjs",
  });
  const registry = JSON.parse(
    await readFile(join(repositoryRoot, "protocol/capabilities/v1/registry.json"), "utf8"),
  );
  assert.deepEqual(
    registry.capabilities.find(({ name }) => name === "folderbase.daemon-stdio"),
    packageEntry,
  );
  const embedded = JSON.parse(
    await readFile(
      join(repositoryRoot, "crates/folderbase-cli/assets/capability-registry-v1.json"),
      "utf8",
    ),
  );
  assert.deepEqual(
    embedded.capabilities.find(({ name }) => name === "folderbase.daemon-stdio"),
    packageEntry,
  );
});

test("public schema is closed Draft 2020-12 with one request and message family", async () => {
  const schema = JSON.parse(
    await readFile(
      resolve(directory, "../../../schemas/capabilities/daemon-stdio/0.1/daemon-stdio.schema.json"),
      "utf8",
    ),
  );
  assert.equal(schema.$schema, "https://json-schema.org/draft/2020-12/schema");
  assert.equal(
    schema.$id,
    "https://folderbase.ai/protocol/capabilities/daemon-stdio/0.1/daemon-stdio.schema.json",
  );
  assert.equal(schema.$defs.request.additionalProperties, false);
  assert.equal(schema.$defs.ready.additionalProperties, false);
  assert.equal(schema.$defs.response.additionalProperties, false);
  assert.equal(schema.$defs.event.additionalProperties, false);
});

test("missing daemon produces one complete ten-case RED report", () => {
  const result = spawnSync(
    process.execPath,
    [
      join(directory, "run.mjs"),
      "--implementation",
      join(directory, "fixtures", "missing-daemon-candidate.mjs"),
    ],
    { encoding: "utf8", maxBuffer: 16 * 1024 * 1024, timeout: 30_000 },
  );
  assert.equal(result.status, 1, result.stderr);
  const report = JSON.parse(result.stdout);
  assert.equal(report.format, "folderbase-capability-suite-report-v1");
  assert.equal(report.capability, "folderbase.daemon-stdio@0.1.0");
  assert.equal(report.total, 10);
  assert.equal(report.passed, 0);
  assert.equal(report.failed, 10);
});

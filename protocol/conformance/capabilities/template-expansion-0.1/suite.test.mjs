import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { assertQuerySchema as assertCapabilitySchema } from "../query-index-0.1/schema.mjs";

const directory = dirname(fileURLToPath(import.meta.url));
const schema = JSON.parse(await readFile(resolve(
  directory,
  "../../../schemas/capabilities/template-expansion/0.1/template-expansion.schema.json",
), "utf8"));

test("public template request fixture satisfies the closed capability schema", async () => {
  const request = JSON.parse(await readFile(join(directory, "fixtures/request.json"), "utf8"));
  assert.doesNotThrow(() => assertCapabilitySchema(request, schema, "request"));
});

test("black-box suite rejects a candidate without the template commands", () => {
  const result = spawnSync(process.execPath, [
    join(directory, "run.mjs"),
    "--implementation",
    join(directory, "fixtures/missing-template-candidate.mjs"),
  ], { encoding: "utf8", timeout: 30_000 });
  assert.equal(result.status, 1, result.stderr);
  const report = JSON.parse(result.stdout);
  assert.equal(report.capability, "folderbase.template-expansion@0.1.0");
  assert.ok(report.failed > 0);
});

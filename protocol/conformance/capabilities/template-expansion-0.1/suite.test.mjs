import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { assertQuerySchema as assertCapabilitySchema } from "../query-index-0.1/schema.mjs";

const directory = dirname(fileURLToPath(import.meta.url));
const COMPLETE_RUNNER_TIMEOUT_MS = 120_000;
const schema = JSON.parse(await readFile(resolve(
  directory,
  "../../../schemas/capabilities/template-expansion/0.1/template-expansion.schema.json",
), "utf8"));

function run(candidate, environment = {}) {
  return spawnSync(process.execPath, [
    join(directory, "run.mjs"),
    "--implementation",
    join(directory, "fixtures", candidate),
  ], {
    encoding: "utf8",
    env: { ...process.env, ...environment },
    killSignal: "SIGKILL",
    maxBuffer: 16 * 1024 * 1024,
    timeout: COMPLETE_RUNNER_TIMEOUT_MS,
  });
}

test("public template request fixture satisfies the closed capability schema", async () => {
  const request = JSON.parse(await readFile(join(directory, "fixtures/request.json"), "utf8"));
  assert.doesNotThrow(() => assertCapabilitySchema(request, schema, "request"));
});

test("black-box suite rejects a candidate without the template commands", () => {
  const result = run("missing-template-candidate.mjs");
  assert.equal(result.status, 1, result.stderr);
  const report = JSON.parse(result.stdout);
  assert.equal(report.capability, "folderbase.template-expansion@0.1.0");
  assert.ok(report.failed > 0);
});

test("the runner hard-kills hanging, forking, and overproducing candidates", async () => {
  const owner = await mkdtemp(join(tmpdir(), "folderbase-template-process-proof-"));
  try {
    for (const candidate of [
      "hanging-candidate.mjs",
      "forking-hanging-candidate.mjs",
      "noisy-candidate.mjs",
    ]) {
      const pidFile = join(owner, `${candidate}.pid`);
      const started = Date.now();
      const result = run(candidate, {
        FOLDERBASE_TEMPLATE_CONFORMANCE_COMMAND_MAX_BYTES: "4096",
        FOLDERBASE_TEMPLATE_CONFORMANCE_COMMAND_TIMEOUT_MS: "250",
        FOLDERBASE_TEMPLATE_CONFORMANCE_PID_FILE: pidFile,
      });
      assert.equal(result.status, 1, result.stderr || result.stdout);
      assert.ok(Date.now() - started < 5_000, `${candidate} was not bounded`);
      const report = JSON.parse(result.stdout);
      assert.ok(report.failed > 0);
      assert.ok(
        report.cases
          .filter(({ status }) => status === "failed")
          .some(({ message }) => /timed out|output limit/u.test(message)),
      );
      const pids = (await readFile(pidFile, "utf8")).trim().split("\n").map(Number);
      for (const pid of pids) {
        assert.throws(
          () => process.kill(pid, 0),
          (error) => error?.code === "ESRCH",
          `${candidate} PID ${pid} survived its hard bound`,
        );
      }
    }
  } finally {
    await rm(owner, { recursive: true, force: true });
  }
});

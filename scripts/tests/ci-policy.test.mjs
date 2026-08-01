import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import test from "node:test";

const repositoryRoot = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const policy = join(repositoryRoot, "scripts", "check-ci-policy.sh");
const releaseWorkflow = join(
  repositoryRoot,
  ".github",
  "workflows",
  "release-cli.yml",
);

function runPolicy(releaseWorkflowPath) {
  return new Promise((resolve, reject) => {
    const child = spawn("bash", [policy], {
      cwd: repositoryRoot,
      env: {
        ...process.env,
        CI_WORKFLOW: join(repositoryRoot, ".github", "workflows", "ci.yml"),
        RELEASE_WORKFLOW: releaseWorkflowPath,
      },
      stdio: ["ignore", "pipe", "pipe"],
    });
    const stderr = [];
    child.stderr.on("data", (chunk) => stderr.push(chunk));
    child.on("error", reject);
    child.on("close", (code) =>
      resolve({ code, stderr: Buffer.concat(stderr).toString("utf8") }),
    );
  });
}

test("the canonical release workflow satisfies scoped policy", async () => {
  const result = await runPolicy(releaseWorkflow);
  assert.equal(result.code, 0, result.stderr);
});

test("a publication-policy call outside its named step cannot satisfy policy", async () => {
  const temporaryRoot = await mkdtemp(join(tmpdir(), "folderbase-ci-policy-"));
  try {
    const fixture = join(temporaryRoot, "release.yml");
    const source = await readFile(releaseWorkflow, "utf8");
    const critical = "node ../../scripts/npm-publication-policy.mjs";
    assert(source.includes(critical));
    await writeFile(
      fixture,
      `${source.replace(critical, "node ../../scripts/removed-policy.mjs")}\n# ${critical}\n`,
    );
    const result = await runPolicy(fixture);
    assert.notEqual(result.code, 0);
    assert.match(result.stderr, /publication policy/);
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true });
  }
});

test("an immutable check outside the GitHub publication step cannot satisfy policy", async () => {
  const temporaryRoot = await mkdtemp(join(tmpdir(), "folderbase-ci-policy-"));
  try {
    const fixture = join(temporaryRoot, "release.yml");
    const source = await readFile(releaseWorkflow, "utf8");
    const critical = "--json isImmutable --jq '.isImmutable'";
    assert(source.includes(critical));
    await writeFile(
      fixture,
      `${source.replace(critical, "--json isDraft --jq '.isDraft'")}\n# ${critical}\n`,
    );
    const result = await runPolicy(fixture);
    assert.notEqual(result.code, 0);
    assert.match(result.stderr, /final GitHub release is immutable/);
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true });
  }
});

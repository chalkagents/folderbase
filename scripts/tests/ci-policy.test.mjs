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

test("a commented immutable-release preflight cannot satisfy policy", async () => {
  const temporaryRoot = await mkdtemp(join(tmpdir(), "folderbase-ci-policy-"));
  try {
    const fixture = join(temporaryRoot, "release.yml");
    const source = await readFile(releaseWorkflow, "utf8");
    const critical =
      'gh api "repos/$GITHUB_REPOSITORY/immutable-releases" --jq \'.enabled\'';
    assert(source.includes(critical));
    await writeFile(
      fixture,
      source.replace(critical, `# ${critical}`),
    );
    const result = await runPolicy(fixture);
    assert.notEqual(result.code, 0);
    assert.match(result.stderr, /before publication/);
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true });
  }
});

test("a release operation before the immutable preflight is rejected", async () => {
  const temporaryRoot = await mkdtemp(join(tmpdir(), "folderbase-ci-policy-"));
  try {
    const fixture = join(temporaryRoot, "release.yml");
    const source = await readFile(releaseWorkflow, "utf8");
    const boundary = "      - name: Require repository immutable releases";
    assert(source.includes(boundary));
    await writeFile(
      fixture,
      source.replace(
        boundary,
        `      - name: Unsafe early release access\n        run: gh release view "$RELEASE_TAG"\n\n${boundary}`,
      ),
    );
    const result = await runPolicy(fixture);
    assert.notEqual(result.code, 0);
    assert.match(result.stderr, /after the immutable-release proof/);
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true });
  }
});

test("publications must share one non-cancelling concurrency group", async () => {
  const temporaryRoot = await mkdtemp(join(tmpdir(), "folderbase-ci-policy-"));
  try {
    const fixture = join(temporaryRoot, "release.yml");
    const source = await readFile(releaseWorkflow, "utf8");
    const critical = "      group: folderbase-publication";
    assert(source.includes(critical));
    await writeFile(fixture, source.replace(critical, "      group: per-ref"));
    const result = await runPolicy(fixture);
    assert.notEqual(result.code, 0);
    assert.match(result.stderr, /serialized/);
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true });
  }
});

test("all publication waiters use the maximal FIFO queue", async () => {
  const temporaryRoot = await mkdtemp(join(tmpdir(), "folderbase-ci-policy-"));
  try {
    const fixture = join(temporaryRoot, "release.yml");
    const source = await readFile(releaseWorkflow, "utf8");
    const critical = "      queue: max";
    assert(source.includes(critical));
    await writeFile(fixture, source.replace(critical, "      queue: single"));
    const result = await runPolicy(fixture);
    assert.notEqual(result.code, 0);
    assert.match(result.stderr, /queue/);
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true });
  }
});

test("the Administration-read token cannot become a release-write token", async () => {
  const temporaryRoot = await mkdtemp(join(tmpdir(), "folderbase-ci-policy-"));
  try {
    const fixture = join(temporaryRoot, "release.yml");
    const source = await readFile(releaseWorkflow, "utf8");
    const critical = "GH_TOKEN: ${{ github.token }}";
    assert(source.includes(critical));
    await writeFile(
      fixture,
      source.replaceAll(
        critical,
        "GH_TOKEN: ${{ secrets.FOLDERBASE_IMMUTABLE_RELEASES_READ_TOKEN }}",
      ),
    );
    const result = await runPolicy(fixture);
    assert.notEqual(result.code, 0);
    assert.match(result.stderr, /workflow token/);
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true });
  }
});

test("the immutable-release preflight cannot use the default workflow token", async () => {
  const temporaryRoot = await mkdtemp(join(tmpdir(), "folderbase-ci-policy-"));
  try {
    const fixture = join(temporaryRoot, "release.yml");
    const source = await readFile(releaseWorkflow, "utf8");
    const critical =
      "GH_TOKEN: ${{ secrets.FOLDERBASE_IMMUTABLE_RELEASES_READ_TOKEN }}";
    assert(source.includes(critical));
    await writeFile(
      fixture,
      source.replace(critical, "GH_TOKEN: ${{ github.token }}"),
    );
    const result = await runPolicy(fixture);
    assert.notEqual(result.code, 0);
    assert.match(result.stderr, /Administration-read token/);
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true });
  }
});

test("the immutable-release setting must equal literal true", async () => {
  const temporaryRoot = await mkdtemp(join(tmpdir(), "folderbase-ci-policy-"));
  try {
    const fixture = join(temporaryRoot, "release.yml");
    const source = await readFile(releaseWorkflow, "utf8");
    const critical = ')" = true';
    assert(source.includes(critical));
    await writeFile(fixture, source.replace(critical, ')" != false'));
    const result = await runPolicy(fixture);
    assert.notEqual(result.code, 0);
    assert.match(result.stderr, /literal true/);
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true });
  }
});

test("the immutable-release preflight cannot continue on error", async () => {
  const temporaryRoot = await mkdtemp(join(tmpdir(), "folderbase-ci-policy-"));
  try {
    const fixture = join(temporaryRoot, "release.yml");
    const source = await readFile(releaseWorkflow, "utf8");
    const boundary = "      - name: Require repository immutable releases";
    assert(source.includes(boundary));
    await writeFile(
      fixture,
      source.replace(boundary, `${boundary}\n        continue-on-error: true`),
    );
    const result = await runPolicy(fixture);
    assert.notEqual(result.code, 0);
    assert.match(result.stderr, /fail closed/);
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true });
  }
});

test("the monotonic channel decision precedes every GitHub release operation", async () => {
  const source = await readFile(releaseWorkflow, "utf8");
  const decision = "      - name: Check immutable npm publication state";
  const publication = "      - name: Publish GitHub release artifacts";
  assert(source.includes(decision));
  assert(source.includes(publication));
  assert(
    source.indexOf(decision) < source.indexOf(publication),
    "npm/GitHub channel policy must run before GitHub publication",
  );
});

test("release classification uses the tested SemVer parser", async () => {
  const source = await readFile(releaseWorkflow, "utf8");
  assert(
    source.includes(
      'node scripts/npm-publication-policy.mjs classify "$package_version"',
    ),
  );
  assert(!source.includes('[[ "$package_version" == *-* ]]'));
});

test("GitHub Latest uses its own registry-state decision", async () => {
  const source = await readFile(releaseWorkflow, "utf8");
  assert(source.includes(".advanceGithubLatest"));
  assert(
    source.includes(
      "GITHUB_LATEST: ${{ steps.npm-publication.outputs.advance_github_latest }}",
    ),
  );
});

test("a same-step release operation before immutable proof is rejected", async () => {
  const temporaryRoot = await mkdtemp(join(tmpdir(), "folderbase-ci-policy-"));
  try {
    const fixture = join(temporaryRoot, "release.yml");
    const source = await readFile(releaseWorkflow, "utf8");
    const boundary = `      - name: Require repository immutable releases
        env:
          GH_TOKEN: \${{ secrets.FOLDERBASE_IMMUTABLE_RELEASES_READ_TOKEN }}
        shell: bash
        run: |`;
    assert(source.includes(boundary));
    await writeFile(
      fixture,
      source.replace(
        boundary,
        `${boundary}\n          gh release view "$RELEASE_TAG"`,
      ),
    );
    const result = await runPolicy(fixture);
    assert.notEqual(result.code, 0);
    assert.match(result.stderr, /immutable-release proof/);
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true });
  }
});

test("a same-step release operation before the channel decision is rejected", async () => {
  const temporaryRoot = await mkdtemp(join(tmpdir(), "folderbase-ci-policy-"));
  try {
    const fixture = join(temporaryRoot, "release.yml");
    const source = await readFile(releaseWorkflow, "utf8");
    const marker = "          package_name=\"$(node -p \"require('./package.json').name\")\"";
    assert(source.includes(marker));
    await writeFile(
      fixture,
      source.replace(marker, `          gh release view "$RELEASE_TAG"\n${marker}`),
    );
    const result = await runPolicy(fixture);
    assert.notEqual(result.code, 0);
    assert.match(result.stderr, /channel decision/);
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true });
  }
});

test("GitHub Latest follows the tested monotonic channel decision", async () => {
  const temporaryRoot = await mkdtemp(join(tmpdir(), "folderbase-ci-policy-"));
  try {
    const fixture = join(temporaryRoot, "release.yml");
    const source = await readFile(releaseWorkflow, "utf8");
    const critical = '--latest="$GITHUB_LATEST"';
    assert(source.includes(critical));
    await writeFile(fixture, source.replaceAll(critical, "--latest=true"));
    const result = await runPolicy(fixture);
    assert.notEqual(result.code, 0);
    assert.match(result.stderr, /GitHub Latest/);
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true });
  }
});

test("a commented npm publish command cannot satisfy policy", async () => {
  const temporaryRoot = await mkdtemp(join(tmpdir(), "folderbase-ci-policy-"));
  try {
    const fixture = join(temporaryRoot, "release.yml");
    const source = await readFile(releaseWorkflow, "utf8");
    const critical = 'npm publish --access public --tag "$PUBLISH_TAG"';
    assert(source.includes(critical));
    await writeFile(fixture, source.replace(critical, `# ${critical}`));
    const result = await runPolicy(fixture);
    assert.notEqual(result.code, 0);
    assert.match(result.stderr, /publication must use/);
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true });
  }
});

test("an inline-comment npm publish decoy cannot satisfy policy", async () => {
  const temporaryRoot = await mkdtemp(join(tmpdir(), "folderbase-ci-policy-"));
  try {
    const fixture = join(temporaryRoot, "release.yml");
    const source = await readFile(releaseWorkflow, "utf8");
    const critical = 'npm publish --access public --tag "$PUBLISH_TAG"';
    assert(source.includes(critical));
    await writeFile(fixture, source.replace(critical, `true # ${critical}`));
    const result = await runPolicy(fixture);
    assert.notEqual(result.code, 0);
    assert.match(result.stderr, /publication must use/);
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true });
  }
});

test("an inline-comment concurrency decoy cannot satisfy policy", async () => {
  const temporaryRoot = await mkdtemp(join(tmpdir(), "folderbase-ci-policy-"));
  try {
    const fixture = join(temporaryRoot, "release.yml");
    const source = await readFile(releaseWorkflow, "utf8");
    const critical = "      group: folderbase-publication";
    assert(source.includes(critical));
    await writeFile(
      fixture,
      source.replace(critical, "      group: single # group: folderbase-publication"),
    );
    const result = await runPolicy(fixture);
    assert.notEqual(result.code, 0);
    assert.match(result.stderr, /serialized/);
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true });
  }
});

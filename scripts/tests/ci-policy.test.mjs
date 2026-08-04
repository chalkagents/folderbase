import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import test from "node:test";

const repositoryRoot = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const policy = join(repositoryRoot, "scripts", "check-ci-policy.sh");
const ciWorkflow = join(repositoryRoot, ".github", "workflows", "ci.yml");
const releaseWorkflow = join(
  repositoryRoot,
  ".github",
  "workflows",
  "release-cli.yml",
);
const immutableEntrypoint =
  "scripts/release/require-immutable-releases.sh";
const decisionEntrypoint = "scripts/release/decide-publication-state.sh";
const publicationEntrypoint = "scripts/release/publish-github-release.sh";
const decisionScript = join(repositoryRoot, decisionEntrypoint);

function runPolicy(releaseWorkflowPath, ciWorkflowPath = ciWorkflow) {
  return new Promise((resolve, reject) => {
    const child = spawn("bash", [policy], {
      cwd: repositoryRoot,
      env: {
        ...process.env,
        CI_WORKFLOW: ciWorkflowPath,
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

function moveStepBefore(source, stepName, beforeStepName) {
  const stepHeader = `      - name: ${stepName}`;
  const beforeHeader = `      - name: ${beforeStepName}`;
  const start = source.indexOf(stepHeader);
  assert.notEqual(start, -1);
  const next = source.indexOf("\n      - name:", start + stepHeader.length);
  assert.notEqual(next, -1);
  const block = source.slice(start, next + 1);
  const withoutBlock = `${source.slice(0, start)}${source.slice(next + 1)}`;
  const insertion = withoutBlock.indexOf(beforeHeader);
  assert.notEqual(insertion, -1);
  return `${withoutBlock.slice(0, insertion)}${block}${withoutBlock.slice(insertion)}`;
}

test("the canonical release workflow satisfies scoped policy", async () => {
  const result = await runPolicy(releaseWorkflow);
  assert.equal(result.code, 0, result.stderr);
});

test("optional capability contract tests are policy-pinned in CI", async () => {
  const temporaryRoot = await mkdtemp(join(tmpdir(), "folderbase-ci-policy-"));
  try {
    const fixture = join(temporaryRoot, "ci.yml");
    const source = await readFile(ciWorkflow, "utf8");
    const critical =
      "        run: node --test protocol/conformance/capabilities/query-index-0.1/suite.test.mjs";
    assert(source.includes(critical));
    await writeFile(fixture, source.replace(critical, "        run: true"));
    const result = await runPolicy(releaseWorkflow, fixture);
    assert.notEqual(result.code, 0);
    assert.match(result.stderr, /optional capability contract/u);
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true });
  }
});

test("template capability contract tests are policy-pinned in CI", async () => {
  const temporaryRoot = await mkdtemp(join(tmpdir(), "folderbase-ci-policy-"));
  try {
    const fixture = join(temporaryRoot, "ci.yml");
    const source = await readFile(ciWorkflow, "utf8");
    const critical =
      "        run: node --test protocol/conformance/capabilities/template-expansion-0.1/suite.test.mjs";
    assert(source.includes(critical));
    await writeFile(fixture, source.replace(critical, "        run: true"));
    const result = await runPolicy(releaseWorkflow, fixture);
    assert.notEqual(result.code, 0);
    assert.match(result.stderr, /template capability contract/u);
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true });
  }
});

test("daemon stdio capability contract tests are policy-pinned in CI", async () => {
  const temporaryRoot = await mkdtemp(join(tmpdir(), "folderbase-ci-policy-"));
  try {
    const fixture = join(temporaryRoot, "ci.yml");
    const source = await readFile(ciWorkflow, "utf8");
    const critical =
      "        run: node --test protocol/conformance/capabilities/daemon-stdio-0.1/suite.test.mjs";
    assert(source.includes(critical));
    await writeFile(fixture, source.replace(critical, "        run: true"));
    const result = await runPolicy(releaseWorkflow, fixture);
    assert.notEqual(result.code, 0);
    assert.match(result.stderr, /daemon stdio capability contract/u);
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true });
  }
});

test("native post-merge advertised capability proof is policy-pinned", async () => {
  const temporaryRoot = await mkdtemp(join(tmpdir(), "folderbase-ci-policy-"));
  try {
    const fixture = join(temporaryRoot, "ci.yml");
    const source = await readFile(ciWorkflow, "utf8");
    const start = source.indexOf("  core-platforms:");
    const end = source.indexOf("\n  required:", start);
    const block = source.slice(start, end);
    const critical =
      "        run: node protocol/conformance/capabilities/run.mjs --implementation ./target/debug/folderbase${{ runner.os == 'Windows' && '.exe' || '' }}";
    assert(block.includes(critical));
    await writeFile(fixture, `${source.slice(0, start)}${block.replace(critical, "        run: true")}${source.slice(end)}`);
    const result = await runPolicy(releaseWorkflow, fixture);
    assert.notEqual(result.code, 0);
    assert.match(result.stderr, /native post-merge|every advertised capability/u);
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true });
  }
});

test("superseded CI runs must remain cancellable", async () => {
  const temporaryRoot = await mkdtemp(join(tmpdir(), "folderbase-ci-policy-"));
  try {
    const fixture = join(temporaryRoot, "ci.yml");
    const source = await readFile(ciWorkflow, "utf8");
    await writeFile(
      fixture,
      source.replace("  cancel-in-progress: true", "  cancel-in-progress: false"),
    );
    const result = await runPolicy(releaseWorkflow, fixture);
    assert.notEqual(result.code, 0);
    assert.match(result.stderr, /superseded CI/);
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true });
  }
});

test("fresh installation proof cannot return to the Linux Core lane", async () => {
  const temporaryRoot = await mkdtemp(join(tmpdir(), "folderbase-ci-policy-"));
  try {
    const fixture = join(temporaryRoot, "ci.yml");
    const source = await readFile(ciWorkflow, "utf8");
    const boundary = "      - name: Run public implementation-neutral conformance";
    assert(source.includes(boundary));
    await writeFile(
      fixture,
      source.replace(
        boundary,
        `      - name: Unsafe duplicate installation proof\n        run: scripts/test-package-install.sh\n\n${boundary}`,
      ),
    );
    const result = await runPolicy(releaseWorkflow, fixture);
    assert.notEqual(result.code, 0);
    assert.match(result.stderr, /separate scoped job/);
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true });
  }
});

test("pull requests cannot spend cross-platform runner minutes", async () => {
  const temporaryRoot = await mkdtemp(join(tmpdir(), "folderbase-ci-policy-"));
  try {
    const fixture = join(temporaryRoot, "ci.yml");
    const source = await readFile(ciWorkflow, "utf8");
    const scoped =
      "    if: github.event_name != 'pull_request' && needs.plan.outputs.platform == 'true'";
    assert(source.includes(scoped));
    await writeFile(
      fixture,
      source.replace(scoped, "    if: needs.plan.outputs.platform == 'true'"),
    );
    const result = await runPolicy(releaseWorkflow, fixture);
    assert.notEqual(result.code, 0);
    assert.match(result.stderr, /pull requests/);
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true });
  }
});

test("the required check cannot bypass scoped result verification", async () => {
  const temporaryRoot = await mkdtemp(join(tmpdir(), "folderbase-ci-policy-"));
  try {
    const fixture = join(temporaryRoot, "ci.yml");
    const source = await readFile(ciWorkflow, "utf8");
    const verifier = "        run: node scripts/ci/verify-required-results.mjs";
    assert(source.includes(verifier));
    await writeFile(fixture, source.replace(verifier, "        run: true"));
    const result = await runPolicy(releaseWorkflow, fixture);
    assert.notEqual(result.code, 0);
    assert.match(result.stderr, /scoped CI results/);
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true });
  }
});

test("the required check cannot forge a dependency result", async () => {
  const temporaryRoot = await mkdtemp(join(tmpdir(), "folderbase-ci-policy-"));
  try {
    const fixture = join(temporaryRoot, "ci.yml");
    const source = await readFile(ciWorkflow, "utf8");
    const resultMapping = "      RUST_RESULT: ${{ needs.rust.result }}";
    assert(source.includes(resultMapping));
    await writeFile(
      fixture,
      source.replace(resultMapping, "      RUST_RESULT: success"),
    );
    const result = await runPolicy(releaseWorkflow, fixture);
    assert.notEqual(result.code, 0);
    assert.match(result.stderr, /dependency results/);
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true });
  }
});

test("the documentation gate cannot bypass its locked install and build", async () => {
  const temporaryRoot = await mkdtemp(join(tmpdir(), "folderbase-ci-policy-"));
  try {
    const fixture = join(temporaryRoot, "ci.yml");
    const source = await readFile(ciWorkflow, "utf8");
    const critical = "        run: npm test --prefix apps/docs";
    assert(source.includes(critical));
    await writeFile(fixture, source.replace(critical, "        run: true"));
    const result = await runPolicy(releaseWorkflow, fixture);
    assert.notEqual(result.code, 0);
    assert.match(result.stderr, /documentation gate/);
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true });
  }
});

test("the registry-state step cannot call a different entrypoint", async () => {
  const temporaryRoot = await mkdtemp(join(tmpdir(), "folderbase-ci-policy-"));
  try {
    const fixture = join(temporaryRoot, "release.yml");
    const source = await readFile(releaseWorkflow, "utf8");
    const critical = `        run: ${decisionEntrypoint}`;
    assert(source.includes(critical));
    await writeFile(
      fixture,
      `${source.replace(critical, "        run: scripts/release/removed-decision.sh")}\n# ${critical}\n`,
    );
    const result = await runPolicy(fixture);
    assert.notEqual(result.code, 0);
    assert.match(result.stderr, /registry-state decision/);
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true });
  }
});

test("a commented immutable-release entrypoint cannot satisfy policy", async () => {
  const temporaryRoot = await mkdtemp(join(tmpdir(), "folderbase-ci-policy-"));
  try {
    const fixture = join(temporaryRoot, "release.yml");
    const source = await readFile(releaseWorkflow, "utf8");
    const critical = `        run: ${immutableEntrypoint}`;
    assert(source.includes(critical));
    await writeFile(
      fixture,
      source.replace(critical, `        run: true # ${immutableEntrypoint}`),
    );
    const result = await runPolicy(fixture);
    assert.notEqual(result.code, 0);
    assert.match(result.stderr, /immutable-release preflight/);
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
    assert.match(result.stderr, /Raw workflow/);
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

test("the immutable preflight cannot have a duplicate run override", async () => {
  const temporaryRoot = await mkdtemp(join(tmpdir(), "folderbase-ci-policy-"));
  try {
    const fixture = join(temporaryRoot, "release.yml");
    const source = await readFile(releaseWorkflow, "utf8");
    const critical = `        run: ${immutableEntrypoint}`;
    assert(source.includes(critical));
    await writeFile(fixture, source.replace(critical, `${critical}\n        run: true`));
    const result = await runPolicy(fixture);
    assert.notEqual(result.code, 0);
    assert.match(result.stderr, /exactly one run key/);
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

test("the immutable-release preflight cannot be conditionally disabled", async () => {
  const temporaryRoot = await mkdtemp(join(tmpdir(), "folderbase-ci-policy-"));
  try {
    const fixture = join(temporaryRoot, "release.yml");
    const source = await readFile(releaseWorkflow, "utf8");
    const boundary = "      - name: Require repository immutable releases";
    assert(source.includes(boundary));
    await writeFile(
      fixture,
      source.replace(boundary, `${boundary}\n        if: false`),
    );
    const result = await runPolicy(fixture);
    assert.notEqual(result.code, 0);
    assert.match(result.stderr, /sealed release control/);
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true });
  }
});

test("a quoted duplicate run key cannot override the immutable preflight", async () => {
  const temporaryRoot = await mkdtemp(join(tmpdir(), "folderbase-ci-policy-"));
  try {
    const fixture = join(temporaryRoot, "release.yml");
    const source = await readFile(releaseWorkflow, "utf8");
    const critical = `        run: ${immutableEntrypoint}`;
    assert(source.includes(critical));
    await writeFile(
      fixture,
      source.replace(critical, `${critical}\n        "run": true`),
    );
    const result = await runPolicy(fixture);
    assert.notEqual(result.code, 0);
    assert.match(result.stderr, /sealed release control/);
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true });
  }
});

test("an escaped raw GitHub command cannot bypass release controls", async () => {
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
        `      - name: Escaped raw release command\n        run: g\\h release view "$RELEASE_TAG"\n\n${boundary}`,
      ),
    );
    const result = await runPolicy(fixture);
    assert.notEqual(result.code, 0);
    assert.match(result.stderr, /sealed release control/);
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true });
  }
});

test("critical release entrypoints must remain in fail-closed order", async () => {
  const temporaryRoot = await mkdtemp(join(tmpdir(), "folderbase-ci-policy-"));
  try {
    const fixture = join(temporaryRoot, "release.yml");
    const source = await readFile(releaseWorkflow, "utf8");
    const unsafe = moveStepBefore(
      source,
      "Require repository immutable releases",
      "Publish GitHub release artifacts",
    );
    await writeFile(fixture, unsafe);
    const result = await runPolicy(fixture);
    assert.notEqual(result.code, 0);
    assert.match(result.stderr, /preflight must precede/);
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true });
  }
});

test("the registry decision must remain before GitHub publication", async () => {
  const temporaryRoot = await mkdtemp(join(tmpdir(), "folderbase-ci-policy-"));
  try {
    const fixture = join(temporaryRoot, "release.yml");
    const source = await readFile(releaseWorkflow, "utf8");
    const unsafe = moveStepBefore(
      source,
      "Publish GitHub release artifacts",
      "Check immutable npm publication state",
    );
    await writeFile(fixture, unsafe);
    const result = await runPolicy(fixture);
    assert.notEqual(result.code, 0);
    assert.match(result.stderr, /(decision must precede|crates must publish)/);
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true });
  }
});

test("the canonical workflow orders all critical release entrypoints", async () => {
  const source = await readFile(releaseWorkflow, "utf8");
  const preflight = source.indexOf(
    "      - name: Require repository immutable releases",
  );
  const decision = source.indexOf(
    "      - name: Check immutable npm publication state",
  );
  const publication = source.indexOf(
    "      - name: Publish GitHub release artifacts",
  );
  assert(preflight < decision && decision < publication);
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
  const decisionSource = await readFile(decisionScript, "utf8");
  assert(decisionSource.includes(".advanceGithubLatest"));
  assert(
    source.includes(
      "GITHUB_LATEST: ${{ steps.npm-publication.outputs.advance_github_latest }}",
    ),
  );
});

test("GitHub publication cannot have a duplicate run override", async () => {
  const temporaryRoot = await mkdtemp(join(tmpdir(), "folderbase-ci-policy-"));
  try {
    const fixture = join(temporaryRoot, "release.yml");
    const source = await readFile(releaseWorkflow, "utf8");
    const critical = `        run: ${publicationEntrypoint}`;
    assert(source.includes(critical));
    await writeFile(
      fixture,
      source.replace(critical, `${critical}\n        run: true`),
    );
    const result = await runPolicy(fixture);
    assert.notEqual(result.code, 0);
    assert.match(result.stderr, /GitHub publication must have exactly one run key/);
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true });
  }
});

test("a semicolon-comment decoy cannot bypass immutable proof ordering", async () => {
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
        `      - name: Semicolon comment decoy
        shell: bash
        run: |
          true;# )" = true
          true;# echo "advance_github_latest=
          gh release view "$RELEASE_TAG"

${boundary}`,
      ),
    );
    const result = await runPolicy(fixture);
    assert.notEqual(result.code, 0);
    assert.match(result.stderr, /Raw workflow/);
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true });
  }
});

test("an escaped-quote comment decoy cannot bypass release ordering", async () => {
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
        `      - name: Escaped quote comment decoy
        shell: bash
        run: |
          true \\';# )" = true
          true \\';# echo "advance_github_latest=
          gh release view "$RELEASE_TAG"

${boundary}`,
      ),
    );
    const result = await runPolicy(fixture);
    assert.notEqual(result.code, 0);
    assert.match(result.stderr, /Raw workflow/);
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true });
  }
});

test("a multiline-quote comment decoy cannot bypass release ordering", async () => {
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
        `      - name: Multiline quote comment decoy
        shell: bash
        run: |
          printf '%s\\n' 'noop
          ';# )" = true
          printf '%s\\n' 'noop
          ';# echo "advance_github_latest=
          gh release view "$RELEASE_TAG"

${boundary}`,
      ),
    );
    const result = await runPolicy(fixture);
    assert.notEqual(result.code, 0);
    assert.match(result.stderr, /Raw workflow/);
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true });
  }
});

test("an ANSI-C quote comment decoy cannot bypass release ordering", async () => {
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
        `      - name: ANSI-C quote comment decoy
        shell: bash
        run: |
          true $'noop\\'';# )" = true
          true $'noop\\'';# echo "advance_github_latest=
          gh release view "$RELEASE_TAG"

${boundary}`,
      ),
    );
    const result = await runPolicy(fixture);
    assert.notEqual(result.code, 0);
    assert.match(result.stderr, /Raw workflow/);
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true });
  }
});

test("a quoted heredoc cannot satisfy release-ordering gates", async () => {
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
        `      - name: Quoted heredoc decoy
        shell: bash
        run: |
          cat <<'POLICY_DECOY'
          )" = true
          echo "advance_github_latest=
          POLICY_DECOY
          gh release view "$RELEASE_TAG"

${boundary}`,
      ),
    );
    const result = await runPolicy(fixture);
    assert.notEqual(result.code, 0);
    assert.match(result.stderr, /Raw workflow/);
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true });
  }
});

test("the registry-state decision cannot have a duplicate run override", async () => {
  const temporaryRoot = await mkdtemp(join(tmpdir(), "folderbase-ci-policy-"));
  try {
    const fixture = join(temporaryRoot, "release.yml");
    const source = await readFile(releaseWorkflow, "utf8");
    const critical = `        run: ${decisionEntrypoint}`;
    assert(source.includes(critical));
    await writeFile(
      fixture,
      source.replace(critical, `${critical}\n        run: true`),
    );
    const result = await runPolicy(fixture);
    assert.notEqual(result.code, 0);
    assert.match(result.stderr, /registry-state decision must have exactly one run key/);
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true });
  }
});

test("a semicolon-comment decoy cannot bypass channel decision ordering", async () => {
  const temporaryRoot = await mkdtemp(join(tmpdir(), "folderbase-ci-policy-"));
  try {
    const fixture = join(temporaryRoot, "release.yml");
    const source = await readFile(releaseWorkflow, "utf8");
    const boundary = "      - name: Check immutable npm publication state";
    assert(source.includes(boundary));
    await writeFile(
      fixture,
      source.replace(
        boundary,
        `      - name: Semicolon channel decoy
        shell: bash
        run: |
          true;# echo "advance_github_latest=
          gh release view "$RELEASE_TAG"

${boundary}`,
      ),
    );
    const result = await runPolicy(fixture);
    assert.notEqual(result.code, 0);
    assert.match(result.stderr, /Raw workflow/);
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true });
  }
});

test("GitHub Latest follows the tested monotonic channel decision", async () => {
  const temporaryRoot = await mkdtemp(join(tmpdir(), "folderbase-ci-policy-"));
  try {
    const fixture = join(temporaryRoot, "release.yml");
    const source = await readFile(releaseWorkflow, "utf8");
    const critical =
      "          GITHUB_LATEST: ${{ steps.npm-publication.outputs.advance_github_latest }}";
    assert(source.includes(critical));
    await writeFile(
      fixture,
      source.replace(critical, "          GITHUB_LATEST: true"),
    );
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

import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import {
  chmod,
  copyFile,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const repositoryRoot = join(
  dirname(fileURLToPath(import.meta.url)),
  "..",
  "..",
);
const immutableScript = join(
  repositoryRoot,
  "scripts",
  "release",
  "require-immutable-releases.sh",
);
const decisionScript = join(
  repositoryRoot,
  "scripts",
  "release",
  "decide-publication-state.sh",
);
const publicationScript = join(
  repositoryRoot,
  "scripts",
  "release",
  "publish-github-release.sh",
);

function runScript(script, { cwd = repositoryRoot, env = {} } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(script, {
      cwd,
      env: { ...process.env, ...env },
      stdio: ["ignore", "pipe", "pipe"],
    });
    const stdout = [];
    const stderr = [];
    child.stdout.on("data", (chunk) => stdout.push(chunk));
    child.stderr.on("data", (chunk) => stderr.push(chunk));
    child.on("error", reject);
    child.on("close", (code) =>
      resolve({
        code,
        stdout: Buffer.concat(stdout).toString("utf8"),
        stderr: Buffer.concat(stderr).toString("utf8"),
      }),
    );
  });
}

async function writeExecutable(path, source) {
  await writeFile(path, source);
  await chmod(path, 0o755);
}

test(
  "immutable-release preflight requires its Administration-read token",
  async () => {
    const result = await runScript(immutableScript, {
      env: {
        GH_TOKEN: "",
        GITHUB_REPOSITORY: "chalkagents/folderbase",
      },
    });
    assert.notEqual(result.code, 0);
    assert.match(
      result.stderr,
      /FOLDERBASE_IMMUTABLE_RELEASES_READ_TOKEN is required/,
    );
  },
);

test("immutable-release preflight accepts only literal enabled state", async () => {
  const temporaryRoot = await mkdtemp(join(tmpdir(), "folderbase-release-script-"));
  try {
    const bin = join(temporaryRoot, "bin");
    const log = join(temporaryRoot, "commands.log");
    await mkdir(bin);
    await writeExecutable(
      join(bin, "gh"),
      `#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$COMMAND_LOG"
printf '%s\n' "$FAKE_IMMUTABLE_VALUE"
`,
    );
    const baseEnvironment = {
      COMMAND_LOG: log,
      GH_TOKEN: "read-only-token",
      GITHUB_REPOSITORY: "chalkagents/folderbase",
      PATH: `${bin}:${process.env.PATH}`,
    };

    const enabled = await runScript(immutableScript, {
      env: { ...baseEnvironment, FAKE_IMMUTABLE_VALUE: "true" },
    });
    assert.equal(enabled.code, 0, enabled.stderr);
    assert.equal(
      await readFile(log, "utf8"),
      "api repos/chalkagents/folderbase/immutable-releases --jq .enabled\n",
    );

    const disabled = await runScript(immutableScript, {
      env: { ...baseEnvironment, FAKE_IMMUTABLE_VALUE: "false" },
    });
    assert.notEqual(disabled.code, 0);
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true });
  }
});

test("registry-state entrypoint advances npm and GitHub independently", async () => {
  const temporaryRoot = await mkdtemp(
    join(tmpdir(), "folderbase-release-script-"),
  );
  try {
    const bin = join(temporaryRoot, "bin");
    const output = join(temporaryRoot, "github-output");
    await mkdir(bin);
    await writeExecutable(
      join(bin, "gh"),
      `#!/usr/bin/env bash
set -euo pipefail
if [[ "$*" == "api repos/chalkagents/folderbase/releases/latest --jq .tag_name" ]]; then
  printf '%s\n' 'v0.5.0'
  exit 0
fi
exit 64
`,
    );
    await writeExecutable(
      join(bin, "npm"),
      `#!/usr/bin/env bash
set -euo pipefail
case "$*" in
  "pack --dry-run --json")
    printf '%s\n' '[{"integrity":"sha512-local"}]'
    ;;
  "view @folderbase/cli@0.4.0 version dist.integrity --json")
    printf '%s\n' 'npm error code E404' >&2
    exit 1
    ;;
  "view @folderbase/cli dist-tags --json")
    printf '%s\n' '{"latest":"0.3.0"}'
    ;;
  *)
    exit 64
    ;;
esac
`,
    );

    const result = await runScript(decisionScript, {
      env: {
        GH_TOKEN: "workflow-token",
        GITHUB_OUTPUT: output,
        GITHUB_REPOSITORY: "chalkagents/folderbase",
        NPM_DIST_TAG: "latest",
        PATH: `${bin}:${process.env.PATH}`,
      },
    });
    assert.equal(result.code, 0, result.stderr);
    assert.equal(
      await readFile(output, "utf8"),
      `skip_publish=false
publish_tag=latest
cleanup_tag=
advance_channel=true
advance_github_latest=false
`,
    );
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true });
  }
});

test("GitHub publication assembles a draft and verifies immutable publication", async () => {
  const temporaryRoot = await mkdtemp(
    join(tmpdir(), "folderbase-release-script-"),
  );
  try {
    const copiedScript = join(
      temporaryRoot,
      "repository",
      "scripts",
      "release",
      "publish-github-release.sh",
    );
    const dist = join(temporaryRoot, "repository", "dist");
    const bin = join(temporaryRoot, "bin");
    const log = join(temporaryRoot, "commands.log");
    await mkdir(dirname(copiedScript), { recursive: true });
    await mkdir(dist, { recursive: true });
    await mkdir(bin);
    await copyFile(publicationScript, copiedScript);
    await chmod(copiedScript, 0o755);
    await writeFile(join(dist, "SHA256SUMS"), "checksums\n");
    await writeFile(join(dist, "folderbase-v0.4.0-test-target"), "binary\n");
    await writeExecutable(
      join(bin, "gh"),
      `#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$COMMAND_LOG"
case "$*" in
  "release view v0.4.0")
    exit 1
    ;;
  "release view v0.4.0 --json assets --jq .assets[].name")
    exit 0
    ;;
  "release view v0.4.0 --json isImmutable --jq .isImmutable")
    printf '%s\n' 'true'
    ;;
  "release create "*|"release upload "*|"release edit "*)
    exit 0
    ;;
  *)
    exit 64
    ;;
esac
`,
    );

    const result = await runScript(copiedScript, {
      cwd: join(temporaryRoot, "repository"),
      env: {
        COMMAND_LOG: log,
        GH_TOKEN: "workflow-token",
        GITHUB_LATEST: "false",
        GITHUB_PRERELEASE: "false",
        PATH: `${bin}:${process.env.PATH}`,
        RELEASE_TAG: "v0.4.0",
      },
    });
    assert.equal(result.code, 0, result.stderr);
    const commands = await readFile(log, "utf8");
    assert.match(
      commands,
      /release create v0\.4\.0 .*--verify-tag --draft --latest=false/,
    );
    assert.match(commands, /release upload v0\.4\.0 .*SHA256SUMS/);
    assert.match(commands, /release upload v0\.4\.0 .*test-target/);
    assert.match(
      commands,
      /release edit v0\.4\.0 --draft=false --latest=false --prerelease=false/,
    );
    assert.match(
      commands,
      /release view v0\.4\.0 --json isImmutable --jq \.isImmutable/,
    );
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true });
  }
});

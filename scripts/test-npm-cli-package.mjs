import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";

const repositoryRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const packageRoot = join(repositoryRoot, "packages", "npm-cli");
const packageMetadata = JSON.parse(
  await readFile(join(packageRoot, "package.json"), "utf8"),
);
const releaseTag = `v${packageMetadata.version}`;

function run(command, arguments_, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, arguments_, {
      cwd: options.cwd || repositoryRoot,
      env: { ...process.env, ...options.env },
      stdio: ["ignore", "pipe", "pipe"],
    });
    const stdout = [];
    const stderr = [];
    child.stdout.on("data", (chunk) => stdout.push(chunk));
    child.stderr.on("data", (chunk) => stderr.push(chunk));
    child.on("error", reject);
    child.on("close", (code, signal) => {
      resolve({
        code,
        signal,
        stdout: Buffer.concat(stdout).toString("utf8"),
        stderr: Buffer.concat(stderr).toString("utf8"),
      });
    });
  });
}

function targetForCurrentHost() {
  const targets = new Map([
    ["darwin:arm64", "aarch64-apple-darwin"],
    ["darwin:x64", "x86_64-apple-darwin"],
    ["linux:arm64", "aarch64-unknown-linux-gnu"],
    ["linux:x64", "x86_64-unknown-linux-gnu"],
  ]);
  const target = targets.get(`${process.platform}:${process.arch}`);
  assert(target, `package acceptance host is unsupported: ${process.platform}/${process.arch}`);
  return target;
}

const temporaryRoot = await mkdtemp(join(tmpdir(), "folderbase-npm-package-"));
try {
  const packed = await run(
    "npm",
    ["pack", "--json", "--pack-destination", temporaryRoot],
    { cwd: packageRoot },
  );
  assert.equal(packed.code, 0, packed.stderr);
  const packReport = JSON.parse(packed.stdout);
  assert.equal(packReport.length, 1);
  assert.deepEqual(
    packReport[0].files.map(({ path }) => path).sort(),
    ["LICENSE", "NOTICE", "README.md", "bin/folderbase.js", "package.json"],
  );

  const archive = join(temporaryRoot, packReport[0].filename);
  const consumerRoot = join(temporaryRoot, "consumer");
  const installed = await run(
    "npm",
    [
      "install",
      "--ignore-scripts",
      "--no-audit",
      "--no-fund",
      "--prefix",
      consumerRoot,
      archive,
    ],
  );
  assert.equal(installed.code, 0, installed.stderr);

  const target = targetForCurrentHost();
  const assetName = `folderbase-${releaseTag}-${target}`;
  const versionCache = join(temporaryRoot, "cache", releaseTag);
  const fixtureCli = Buffer.from(
    `#!/bin/sh\nprintf 'folderbase ${packageMetadata.version}\\n'\n`,
  );
  const digest = createHash("sha256").update(fixtureCli).digest("hex");
  await mkdir(versionCache, { recursive: true });
  await writeFile(join(versionCache, "SHA256SUMS"), `${digest}  ${assetName}\n`);
  await writeFile(join(versionCache, assetName), fixtureCli);
  await chmod(join(versionCache, assetName), 0o700);

  const executable = join(
    consumerRoot,
    "node_modules",
    ".bin",
    process.platform === "win32" ? "folderbase.cmd" : "folderbase",
  );
  const invoked = await run(executable, ["--version"], {
    env: { FOLDERBASE_CLI_CACHE_DIR: join(temporaryRoot, "cache") },
  });
  assert.deepEqual(invoked, {
    code: 0,
    signal: null,
    stdout: `folderbase ${packageMetadata.version}\n`,
    stderr: "",
  });

  console.log(
    `Packed @folderbase/cli ${packageMetadata.version} invoked the verified ${target} fixture.`,
  );
} finally {
  await rm(temporaryRoot, { recursive: true, force: true });
}

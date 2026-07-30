#!/usr/bin/env node

import { createHash, randomUUID } from "node:crypto";
import {
  chmod,
  mkdir,
  open,
  readFile,
  rename,
  rm,
} from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";

const packageRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const packageMetadata = JSON.parse(
  await readFile(join(packageRoot, "package.json"), "utf8"),
);
const version = packageMetadata.version;
const releaseTag = `v${version}`;
const maximumChecksumBytes = 1024 * 1024;
const maximumBinaryBytes = 256 * 1024 * 1024;

function targetFor(platform, architecture) {
  const targets = new Map([
    ["darwin:arm64", "aarch64-apple-darwin"],
    ["darwin:x64", "x86_64-apple-darwin"],
    ["linux:arm64", "aarch64-unknown-linux-gnu"],
    ["linux:x64", "x86_64-unknown-linux-gnu"],
  ]);
  const target = targets.get(`${platform}:${architecture}`);
  if (!target) {
    throw new Error(
      `unsupported platform ${platform}/${architecture}; supported platforms are macOS and Linux on arm64 or x64`,
    );
  }
  return target;
}

function cacheRoot() {
  if (process.env.FOLDERBASE_CLI_CACHE_DIR) {
    return process.env.FOLDERBASE_CLI_CACHE_DIR;
  }
  if (process.platform === "darwin") {
    return join(homedir(), "Library", "Caches", "folderbase", "cli");
  }
  return join(
    process.env.XDG_CACHE_HOME || join(homedir(), ".cache"),
    "folderbase",
    "cli",
  );
}

function releaseBaseUrl() {
  const base =
    process.env.FOLDERBASE_CLI_RELEASE_BASE_URL ||
    "https://github.com/chalkagents/folderbase/releases/download";
  const url = new URL(base);
  const allowLoopbackHttp =
    process.env.FOLDERBASE_CLI_TEST_ALLOW_HTTP === "1" &&
    (url.hostname === "127.0.0.1" || url.hostname === "localhost");
  if (url.protocol !== "https:" && !allowLoopbackHttp) {
    throw new Error("release downloads require HTTPS");
  }
  return base.replace(/\/+$/, "");
}

async function download(url, maximumBytes) {
  const response = await fetch(url, { redirect: "follow" });
  if (!response.ok || !response.body) {
    throw new Error(`download failed with HTTP ${response.status}: ${url}`);
  }
  const declaredLength = Number(response.headers.get("content-length"));
  if (Number.isFinite(declaredLength) && declaredLength > maximumBytes) {
    throw new Error(`download exceeds the ${maximumBytes}-byte limit: ${url}`);
  }

  const chunks = [];
  let bytes = 0;
  for await (const chunk of response.body) {
    bytes += chunk.length;
    if (bytes > maximumBytes) {
      throw new Error(`download exceeds the ${maximumBytes}-byte limit: ${url}`);
    }
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

async function writeAtomically(path, bytes, mode) {
  const temporaryPath = `${path}.${randomUUID()}.tmp`;
  const handle = await open(temporaryPath, "wx", mode);
  try {
    await handle.writeFile(bytes);
    await handle.sync();
  } finally {
    await handle.close();
  }
  try {
    await rename(temporaryPath, path);
  } finally {
    await rm(temporaryPath, { force: true });
  }
}

function expectedDigest(checksums, assetName) {
  const matches = [];
  for (const line of checksums.split(/\r?\n/)) {
    const match = line.match(/^([0-9a-f]{64}) [ *](\S+)$/);
    if (match && match[2] === assetName) {
      matches.push(match[1]);
    }
  }
  if (matches.length === 0) {
    throw new Error(`release checksums do not contain ${assetName}`);
  }
  if (matches.length !== 1) {
    throw new Error(`release contains ambiguous checksum entries for ${assetName}`);
  }
  return matches[0];
}

async function digestFile(path) {
  const bytes = await readFile(path);
  return createHash("sha256").update(bytes).digest("hex");
}

async function resolveNativeCli() {
  const platform =
    process.env.FOLDERBASE_CLI_TEST_PLATFORM || process.platform;
  const architecture = process.env.FOLDERBASE_CLI_TEST_ARCH || process.arch;
  const target = targetFor(platform, architecture);
  const assetName = `folderbase-${releaseTag}-${target}`;
  const versionCache = join(cacheRoot(), releaseTag);
  const checksumPath = join(versionCache, "SHA256SUMS");
  const binaryPath = join(versionCache, assetName);
  const releaseUrl = `${releaseBaseUrl()}/${releaseTag}`;

  await mkdir(versionCache, { recursive: true, mode: 0o700 });

  let checksums;
  try {
    checksums = await readFile(checksumPath, "utf8");
  } catch (error) {
    if (error.code !== "ENOENT") {
      throw error;
    }
    const downloaded = await download(
      `${releaseUrl}/SHA256SUMS`,
      maximumChecksumBytes,
    );
    await writeAtomically(checksumPath, downloaded, 0o600);
    checksums = downloaded.toString("utf8");
  }
  const expected = expectedDigest(checksums, assetName);

  try {
    if ((await digestFile(binaryPath)) === expected) {
      await chmod(binaryPath, 0o700);
      return binaryPath;
    }
    await rm(binaryPath, { force: true });
  } catch (error) {
    if (error.code !== "ENOENT") {
      throw error;
    }
  }

  const downloaded = await download(
    `${releaseUrl}/${assetName}`,
    maximumBinaryBytes,
  );
  const actual = createHash("sha256").update(downloaded).digest("hex");
  if (actual !== expected) {
    throw new Error(
      `SHA-256 mismatch for ${assetName}: expected ${expected}, received ${actual}`,
    );
  }
  await writeAtomically(binaryPath, downloaded, 0o700);
  await chmod(binaryPath, 0o700);
  return binaryPath;
}

async function run() {
  const binary = await resolveNativeCli();
  const child = spawn(binary, process.argv.slice(2), {
    stdio: "inherit",
    windowsHide: true,
  });
  child.on("error", (error) => {
    console.error(`folderbase: could not start the native CLI: ${error.message}`);
    process.exitCode = 1;
  });
  child.on("exit", (code, signal) => {
    if (signal) {
      process.kill(process.pid, signal);
      return;
    }
    process.exitCode = code ?? 1;
  });
}

run().catch((error) => {
  console.error(`folderbase: ${error.message}`);
  process.exitCode = 1;
});

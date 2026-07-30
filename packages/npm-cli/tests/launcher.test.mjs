import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import test from "node:test";

const packageRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const launcher = join(packageRoot, "bin", "folderbase.js");

function runLauncher(arguments_, environment) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [launcher, ...arguments_], {
      env: { ...process.env, ...environment },
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

test("a user invocation downloads, verifies, and runs the exact native CLI", async () => {
  const cacheRoot = await mkdtemp(join(tmpdir(), "folderbase-npx-test-"));
  const assetName = "folderbase-v0.4.0-aarch64-apple-darwin";
  const nativeCli = Buffer.from(
    "#!/bin/sh\nprintf 'native:%s|%s\\n' \"$1\" \"$2\"\n",
  );
  const sha256 = createHash("sha256").update(nativeCli).digest("hex");
  const checksums = Buffer.from(`${sha256}  ${assetName}\n`);

  const server = createServer((request, response) => {
    const body = request.url?.endsWith("/SHA256SUMS")
      ? checksums
      : request.url?.endsWith(`/${assetName}`)
        ? nativeCli
        : undefined;
    if (body === undefined) {
      response.writeHead(404).end();
      return;
    }
    response.writeHead(200, { "content-length": body.length }).end(body);
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  assert(address && typeof address === "object");

  try {
    const result = await runLauncher(["init", "project folder"], {
      FOLDERBASE_CLI_CACHE_DIR: cacheRoot,
      FOLDERBASE_CLI_RELEASE_BASE_URL: `http://127.0.0.1:${address.port}`,
      FOLDERBASE_CLI_TEST_ALLOW_HTTP: "1",
      FOLDERBASE_CLI_TEST_ARCH: "arm64",
      FOLDERBASE_CLI_TEST_PLATFORM: "darwin",
    });

    assert.deepEqual(result, {
      code: 0,
      signal: null,
      stdout: "native:init|project folder\n",
      stderr: "",
    });
    assert.deepEqual(
      await readFile(join(cacheRoot, "v0.4.0", assetName)),
      nativeCli,
    );
  } finally {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
    await rm(cacheRoot, { recursive: true, force: true });
  }
});

test("an ambiguous release checksum fails closed before native execution", async () => {
  const cacheRoot = await mkdtemp(join(tmpdir(), "folderbase-npx-test-"));
  const assetName = "folderbase-v0.4.0-aarch64-apple-darwin";
  const nativeCli = Buffer.from("#!/bin/sh\nprintf 'must-not-run\\n'\n");
  const sha256 = createHash("sha256").update(nativeCli).digest("hex");
  const checksums = Buffer.from(
    `${sha256}  ${assetName}\n${"0".repeat(64)}  ${assetName}\n`,
  );
  let binaryRequests = 0;

  const server = createServer((request, response) => {
    if (request.url?.endsWith("/SHA256SUMS")) {
      response
        .writeHead(200, { "content-length": checksums.length })
        .end(checksums);
      return;
    }
    if (request.url?.endsWith(`/${assetName}`)) {
      binaryRequests += 1;
      response
        .writeHead(200, { "content-length": nativeCli.length })
        .end(nativeCli);
      return;
    }
    response.writeHead(404).end();
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  assert(address && typeof address === "object");

  try {
    const result = await runLauncher([], {
      FOLDERBASE_CLI_CACHE_DIR: cacheRoot,
      FOLDERBASE_CLI_RELEASE_BASE_URL: `http://127.0.0.1:${address.port}`,
      FOLDERBASE_CLI_TEST_ALLOW_HTTP: "1",
      FOLDERBASE_CLI_TEST_ARCH: "arm64",
      FOLDERBASE_CLI_TEST_PLATFORM: "darwin",
    });

    assert.equal(result.code, 1);
    assert.match(result.stderr, /ambiguous checksum entries/);
    assert.equal(result.stdout, "");
    assert.equal(binaryRequests, 0);
  } finally {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
    await rm(cacheRoot, { recursive: true, force: true });
  }
});

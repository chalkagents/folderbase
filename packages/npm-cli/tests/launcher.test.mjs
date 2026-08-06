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
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import test from "node:test";

const packageRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const launcher = join(packageRoot, "bin", "folderbase.js");
const releaseAssetNames = [
  "folderbase-v0.7.1-aarch64-apple-darwin",
  "folderbase-v0.7.1-x86_64-apple-darwin",
  "folderbase-v0.7.1-aarch64-unknown-linux-gnu",
  "folderbase-v0.7.1-x86_64-unknown-linux-gnu",
];

function closedChecksums(digests) {
  return Buffer.from(
    `${releaseAssetNames
      .map(
        (name, index) =>
          `${digests.get(name) || String(index).repeat(64)}  ${name}`,
      )
      .join("\n")}\n`,
  );
}

function runLauncher(arguments_, environment, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [launcher, ...arguments_], {
      cwd: options.cwd,
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

function processIsAlive(processId) {
  try {
    process.kill(processId, 0);
    return true;
  } catch (error) {
    if (error.code === "ESRCH") {
      return false;
    }
    throw error;
  }
}

test("a user invocation downloads, verifies, and runs the exact native CLI", async () => {
  const cacheRoot = await mkdtemp(join(tmpdir(), "folderbase-npx-test-"));
  const assetName = "folderbase-v0.7.1-aarch64-apple-darwin";
  const nativeCli = Buffer.from(
    "#!/bin/sh\nprintf 'native:%s|%s\\n' \"$1\" \"$2\"\n",
  );
  const sha256 = createHash("sha256").update(nativeCli).digest("hex");
  const checksums = closedChecksums(new Map([[assetName, sha256]]));

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
      await readFile(join(cacheRoot, "v0.7.1", assetName)),
      nativeCli,
    );
  } finally {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
    await rm(cacheRoot, { recursive: true, force: true });
  }
});

test("a relative XDG cache path falls back to the home cache", async () => {
  const temporaryRoot = await mkdtemp(join(tmpdir(), "folderbase-npx-test-"));
  const homeRoot = join(temporaryRoot, "home");
  const assetName = "folderbase-v0.7.1-aarch64-unknown-linux-gnu";
  const nativeCli = Buffer.from("#!/bin/sh\nprintf 'xdg-safe\\n'\n");
  const sha256 = createHash("sha256").update(nativeCli).digest("hex");
  const checksums = closedChecksums(new Map([[assetName, sha256]]));

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
    const result = await runLauncher(
      [],
      {
        FOLDERBASE_CLI_CACHE_DIR: "",
        FOLDERBASE_CLI_RELEASE_BASE_URL: `http://127.0.0.1:${address.port}`,
        FOLDERBASE_CLI_TEST_ALLOW_HTTP: "1",
        FOLDERBASE_CLI_TEST_ARCH: "arm64",
        FOLDERBASE_CLI_TEST_PLATFORM: "linux",
        HOME: homeRoot,
        XDG_CACHE_HOME: "relative-xdg-cache",
      },
      { cwd: temporaryRoot },
    );

    assert.deepEqual(result, {
      code: 0,
      signal: null,
      stdout: "xdg-safe\n",
      stderr: "",
    });
    assert.deepEqual(
      await readFile(
        join(
          homeRoot,
          ".cache",
          "folderbase",
          "cli",
          "v0.7.1",
          assetName,
        ),
      ),
      nativeCli,
    );
    await assert.rejects(
      readFile(
        join(
          temporaryRoot,
          "relative-xdg-cache",
          "folderbase",
          "cli",
          "v0.7.1",
          assetName,
        ),
      ),
      { code: "ENOENT" },
    );
  } finally {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
    await rm(temporaryRoot, { recursive: true, force: true });
  }
});

test("an ambiguous release checksum fails closed before native execution", async () => {
  const cacheRoot = await mkdtemp(join(tmpdir(), "folderbase-npx-test-"));
  const assetName = "folderbase-v0.7.1-aarch64-apple-darwin";
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

test("a release checksum matrix missing a non-host asset fails closed", async () => {
  const cacheRoot = await mkdtemp(join(tmpdir(), "folderbase-npx-test-"));
  const assetName = "folderbase-v0.7.1-aarch64-apple-darwin";
  const missingAssetName = "folderbase-v0.7.1-x86_64-unknown-linux-gnu";
  const nativeCli = Buffer.from("#!/bin/sh\nprintf 'must-not-run\\n'\n");
  const sha256 = createHash("sha256").update(nativeCli).digest("hex");
  const checksums = Buffer.from(
    `${releaseAssetNames
      .filter((name) => name !== missingAssetName)
      .map(
        (name, index) =>
          `${name === assetName ? sha256 : String(index + 1).repeat(64)}  ${name}`,
      )
      .join("\n")}\n`,
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
    assert.match(result.stderr, /checksums do not contain/);
    assert.match(result.stderr, new RegExp(missingAssetName));
    assert.equal(result.stdout, "");
    assert.equal(binaryRequests, 0);
  } finally {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
    await rm(cacheRoot, { recursive: true, force: true });
  }
});

test("a declared binary download larger than the bounded test limit fails closed", async () => {
  const cacheRoot = await mkdtemp(join(tmpdir(), "folderbase-npx-test-"));
  const assetName = "folderbase-v0.7.1-aarch64-apple-darwin";
  const script = Buffer.from("#!/bin/sh\nprintf 'must-not-run\\n'\n#");
  const nativeCli = Buffer.concat([
    script,
    Buffer.alloc(65 - script.length, 0x20),
  ]);
  const sha256 = createHash("sha256").update(nativeCli).digest("hex");
  const checksums = closedChecksums(new Map([[assetName, sha256]]));
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
      response.writeHead(200, { "content-length": 65 }).end(nativeCli);
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
      FOLDERBASE_CLI_TEST_MAX_BINARY_BYTES: "64",
      FOLDERBASE_CLI_TEST_PLATFORM: "darwin",
    });

    assert.equal(result.code, 1);
    assert.match(result.stderr, /download exceeds the 64-byte limit/);
    assert.equal(result.stdout, "");
    assert.equal(binaryRequests, 1);
  } finally {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
    await rm(cacheRoot, { recursive: true, force: true });
  }
});

test("a streamed binary download larger than the bounded test limit fails closed", async () => {
  const cacheRoot = await mkdtemp(join(tmpdir(), "folderbase-npx-test-"));
  const assetName = "folderbase-v0.7.1-aarch64-apple-darwin";
  const oversized = Buffer.alloc(65, 0x61);
  const sha256 = createHash("sha256").update(oversized).digest("hex");
  const checksums = closedChecksums(new Map([[assetName, sha256]]));

  const server = createServer((request, response) => {
    if (request.url?.endsWith("/SHA256SUMS")) {
      response
        .writeHead(200, { "content-length": checksums.length })
        .end(checksums);
      return;
    }
    if (request.url?.endsWith(`/${assetName}`)) {
      response.writeHead(200);
      response.write(oversized.subarray(0, 32));
      response.end(oversized.subarray(32));
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
      FOLDERBASE_CLI_TEST_MAX_BINARY_BYTES: "64",
      FOLDERBASE_CLI_TEST_PLATFORM: "darwin",
    });

    assert.equal(result.code, 1);
    assert.match(result.stderr, /download exceeds the 64-byte limit/);
    assert.equal(result.stdout, "");
    await assert.rejects(
      readFile(join(cacheRoot, "v0.7.1", assetName)),
      { code: "ENOENT" },
    );
  } finally {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
    await rm(cacheRoot, { recursive: true, force: true });
  }
});

test("invalid bounded-test byte limits fail closed before download", async () => {
  const cacheRoot = await mkdtemp(join(tmpdir(), "folderbase-npx-test-"));
  try {
    for (const [value, expectedError] of [
      ["", /positive safe integer/],
      ["0", /positive safe integer/],
      ["1.5", /positive safe integer/],
      [String(256 * 1024 * 1024 + 1), /must not exceed 268435456/],
    ]) {
      const result = await runLauncher([], {
        FOLDERBASE_CLI_CACHE_DIR: cacheRoot,
        FOLDERBASE_CLI_TEST_ALLOW_HTTP: "1",
        FOLDERBASE_CLI_TEST_ARCH: "arm64",
        FOLDERBASE_CLI_TEST_MAX_BINARY_BYTES: value,
        FOLDERBASE_CLI_TEST_PLATFORM: "darwin",
      });

      assert.equal(result.code, 1);
      assert.match(result.stderr, expectedError);
      assert.equal(result.stdout, "");
    }
    await assert.rejects(readFile(join(cacheRoot, "v0.7.1", "SHA256SUMS")), {
      code: "ENOENT",
    });
  } finally {
    await rm(cacheRoot, { recursive: true, force: true });
  }
});

test("the bounded-test byte override is inert outside loopback test mode", async () => {
  const cacheRoot = await mkdtemp(join(tmpdir(), "folderbase-npx-test-"));
  const versionCache = join(cacheRoot, "v0.7.1");
  const assetName = "folderbase-v0.7.1-aarch64-apple-darwin";
  const nativeCli = Buffer.from("#!/bin/sh\nprintf 'production-limit\\n'\n");
  const sha256 = createHash("sha256").update(nativeCli).digest("hex");
  await mkdir(versionCache, { recursive: true });
  await writeFile(
    join(versionCache, "SHA256SUMS"),
    closedChecksums(new Map([[assetName, sha256]])),
  );
  await writeFile(join(versionCache, assetName), nativeCli);
  await chmod(join(versionCache, assetName), 0o700);

  try {
    const result = await runLauncher([], {
      FOLDERBASE_CLI_CACHE_DIR: cacheRoot,
      FOLDERBASE_CLI_TEST_ALLOW_HTTP: "0",
      FOLDERBASE_CLI_TEST_ARCH: "arm64",
      FOLDERBASE_CLI_TEST_MAX_BINARY_BYTES: "0",
      FOLDERBASE_CLI_TEST_PLATFORM: "darwin",
    });

    assert.deepEqual(result, {
      code: 0,
      signal: null,
      stdout: "production-limit\n",
      stderr: "",
    });
  } finally {
    await rm(cacheRoot, { recursive: true, force: true });
  }
});

test("a release download cannot exceed the redirect-count limit", async () => {
  const cacheRoot = await mkdtemp(join(tmpdir(), "folderbase-npx-test-"));
  let requests = 0;
  const server = createServer((request, response) => {
    requests += 1;
    const requestUrl = new URL(request.url || "/", "http://127.0.0.1");
    const hop = Number(requestUrl.searchParams.get("hop") || "0") + 1;
    response
      .writeHead(302, { location: `${requestUrl.pathname}?hop=${hop}` })
      .end();
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
    assert.match(result.stderr, /10-redirect limit/);
    assert.equal(result.stdout, "");
    assert.equal(requests, 11);
  } finally {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
    await rm(cacheRoot, { recursive: true, force: true });
  }
});

test("a corrupt cached binary is replaced with the verified release asset", async () => {
  const cacheRoot = await mkdtemp(join(tmpdir(), "folderbase-npx-test-"));
  const versionCache = join(cacheRoot, "v0.7.1");
  const assetName = "folderbase-v0.7.1-aarch64-apple-darwin";
  const nativeCli = Buffer.from("#!/bin/sh\nprintf 'cache-replaced\\n'\n");
  const sha256 = createHash("sha256").update(nativeCli).digest("hex");
  const checksums = closedChecksums(new Map([[assetName, sha256]]));
  let checksumRequests = 0;
  let binaryRequests = 0;
  await mkdir(versionCache, { recursive: true });
  await writeFile(join(versionCache, "SHA256SUMS"), checksums);
  await writeFile(join(versionCache, assetName), "corrupt cache");

  const server = createServer((request, response) => {
    if (request.url?.endsWith("/SHA256SUMS")) {
      checksumRequests += 1;
      response.writeHead(500).end();
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

    assert.deepEqual(result, {
      code: 0,
      signal: null,
      stdout: "cache-replaced\n",
      stderr: "",
    });
    assert.equal(checksumRequests, 0);
    assert.equal(binaryRequests, 1);
    assert.deepEqual(await readFile(join(versionCache, assetName)), nativeCli);
  } finally {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
    await rm(cacheRoot, { recursive: true, force: true });
  }
});

test("a downloaded binary with the wrong digest is never cached or executed", async () => {
  const cacheRoot = await mkdtemp(join(tmpdir(), "folderbase-npx-test-"));
  const assetName = "folderbase-v0.7.1-aarch64-apple-darwin";
  const expectedCli = Buffer.from("#!/bin/sh\nprintf 'expected\\n'\n");
  const downloadedCli = Buffer.from("#!/bin/sh\nprintf 'must-not-run\\n'\n");
  const expectedSha256 = createHash("sha256").update(expectedCli).digest("hex");
  const checksums = closedChecksums(new Map([[assetName, expectedSha256]]));

  const server = createServer((request, response) => {
    const body = request.url?.endsWith("/SHA256SUMS")
      ? checksums
      : request.url?.endsWith(`/${assetName}`)
        ? downloadedCli
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
    const result = await runLauncher([], {
      FOLDERBASE_CLI_CACHE_DIR: cacheRoot,
      FOLDERBASE_CLI_RELEASE_BASE_URL: `http://127.0.0.1:${address.port}`,
      FOLDERBASE_CLI_TEST_ALLOW_HTTP: "1",
      FOLDERBASE_CLI_TEST_ARCH: "arm64",
      FOLDERBASE_CLI_TEST_PLATFORM: "darwin",
    });

    assert.equal(result.code, 1);
    assert.match(result.stderr, /SHA-256 mismatch/);
    assert.equal(result.stdout, "");
    await assert.rejects(
      readFile(join(cacheRoot, "v0.7.1", assetName)),
      { code: "ENOENT" },
    );
  } finally {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
    await rm(cacheRoot, { recursive: true, force: true });
  }
});

test("a malformed closed checksum record fails before native execution", async () => {
  const cacheRoot = await mkdtemp(join(tmpdir(), "folderbase-npx-test-"));
  const assetName = "folderbase-v0.7.1-aarch64-apple-darwin";
  const nativeCli = Buffer.from("#!/bin/sh\nprintf 'must-not-run\\n'\n");
  const sha256 = createHash("sha256").update(nativeCli).digest("hex");
  const checksums = Buffer.from(
    [
      `${sha256}  ${assetName}`,
      `${"1".repeat(64)}  folderbase-v0.7.1-x86_64-apple-darwin`,
      "this line is not a checksum",
      `${"2".repeat(64)}  folderbase-v0.7.1-aarch64-unknown-linux-gnu`,
      `${"3".repeat(64)}  folderbase-v0.7.1-x86_64-unknown-linux-gnu`,
      "",
    ].join("\n"),
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
    assert.match(result.stderr, /malformed checksum record/);
    assert.equal(result.stdout, "");
    assert.equal(binaryRequests, 0);
  } finally {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
    await rm(cacheRoot, { recursive: true, force: true });
  }
});

test("an unexpected checksum entry fails before native execution", async () => {
  const cacheRoot = await mkdtemp(join(tmpdir(), "folderbase-npx-test-"));
  const assetName = "folderbase-v0.7.1-aarch64-apple-darwin";
  const nativeCli = Buffer.from("#!/bin/sh\nprintf 'must-not-run\\n'\n");
  const sha256 = createHash("sha256").update(nativeCli).digest("hex");
  const checksums = Buffer.from(
    [
      `${sha256}  ${assetName}`,
      `${"4".repeat(64)}  folderbase-v0.7.1-x86_64-unknown-freebsd`,
      "",
    ].join("\n"),
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
    assert.match(result.stderr, /unexpected checksum entry/);
    assert.equal(result.stdout, "");
    assert.equal(binaryRequests, 0);
  } finally {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
    await rm(cacheRoot, { recursive: true, force: true });
  }
});

test("an HTTP redirect outside the explicit loopback test hosts fails closed", async () => {
  const cacheRoot = await mkdtemp(join(tmpdir(), "folderbase-npx-test-"));
  const assetName = "folderbase-v0.7.1-aarch64-apple-darwin";
  const nativeCli = Buffer.from("#!/bin/sh\nprintf 'must-not-run\\n'\n");
  const sha256 = createHash("sha256").update(nativeCli).digest("hex");
  const checksums = closedChecksums(new Map([[assetName, sha256]]));
  let redirectedRequests = 0;

  const redirectedServer = createServer((request, response) => {
    redirectedRequests += 1;
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
  await new Promise((resolve) =>
    redirectedServer.listen(0, "0.0.0.0", resolve),
  );
  const redirectedAddress = redirectedServer.address();
  assert(redirectedAddress && typeof redirectedAddress === "object");

  const releaseServer = createServer((request, response) => {
    response
      .writeHead(302, {
        location: `http://127.0.0.2:${redirectedAddress.port}${request.url}`,
      })
      .end();
  });
  await new Promise((resolve) =>
    releaseServer.listen(0, "127.0.0.1", resolve),
  );
  const releaseAddress = releaseServer.address();
  assert(releaseAddress && typeof releaseAddress === "object");

  try {
    const result = await runLauncher([], {
      FOLDERBASE_CLI_CACHE_DIR: cacheRoot,
      FOLDERBASE_CLI_RELEASE_BASE_URL: `http://127.0.0.1:${releaseAddress.port}`,
      FOLDERBASE_CLI_TEST_ALLOW_HTTP: "1",
      FOLDERBASE_CLI_TEST_ARCH: "arm64",
      FOLDERBASE_CLI_TEST_PLATFORM: "darwin",
    });

    assert.equal(result.code, 1);
    assert.match(result.stderr, /redirect target requires HTTPS/);
    assert.equal(result.stdout, "");
    assert.equal(redirectedRequests, 0);
  } finally {
    releaseServer.closeAllConnections();
    redirectedServer.closeAllConnections();
    await Promise.all([
      new Promise((resolve) => releaseServer.close(resolve)),
      new Promise((resolve) => redirectedServer.close(resolve)),
    ]);
    await rm(cacheRoot, { recursive: true, force: true });
  }
});

test("the explicit loopback test exception applies across redirect hops", async () => {
  const cacheRoot = await mkdtemp(join(tmpdir(), "folderbase-npx-test-"));
  const assetName = "folderbase-v0.7.1-aarch64-apple-darwin";
  const nativeCli = Buffer.from("#!/bin/sh\nprintf 'redirected-native\\n'\n");
  const sha256 = createHash("sha256").update(nativeCli).digest("hex");
  const checksums = closedChecksums(new Map([[assetName, sha256]]));

  const redirectedServer = createServer((request, response) => {
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
  await new Promise((resolve) =>
    redirectedServer.listen(0, "127.0.0.1", resolve),
  );
  const redirectedAddress = redirectedServer.address();
  assert(redirectedAddress && typeof redirectedAddress === "object");

  const releaseServer = createServer((request, response) => {
    response
      .writeHead(302, {
        location: `http://127.0.0.1:${redirectedAddress.port}${request.url}`,
      })
      .end();
  });
  await new Promise((resolve) =>
    releaseServer.listen(0, "127.0.0.1", resolve),
  );
  const releaseAddress = releaseServer.address();
  assert(releaseAddress && typeof releaseAddress === "object");

  try {
    const result = await runLauncher([], {
      FOLDERBASE_CLI_CACHE_DIR: cacheRoot,
      FOLDERBASE_CLI_RELEASE_BASE_URL: `http://127.0.0.1:${releaseAddress.port}`,
      FOLDERBASE_CLI_TEST_ALLOW_HTTP: "1",
      FOLDERBASE_CLI_TEST_ARCH: "arm64",
      FOLDERBASE_CLI_TEST_PLATFORM: "darwin",
    });

    assert.deepEqual(result, {
      code: 0,
      signal: null,
      stdout: "redirected-native\n",
      stderr: "",
    });
  } finally {
    releaseServer.closeAllConnections();
    redirectedServer.closeAllConnections();
    await Promise.all([
      new Promise((resolve) => releaseServer.close(resolve)),
      new Promise((resolve) => redirectedServer.close(resolve)),
    ]);
    await rm(cacheRoot, { recursive: true, force: true });
  }
});

test("a termination signal reaches the native CLI without leaving an orphan", async () => {
  const temporaryRoot = await mkdtemp(join(tmpdir(), "folderbase-npx-test-"));
  const cacheRoot = join(temporaryRoot, "cache");
  const versionCache = join(cacheRoot, "v0.7.1");
  const assetName = "folderbase-v0.7.1-aarch64-apple-darwin";
  const signalRecord = join(temporaryRoot, "received-signal");
  const processRecord = join(temporaryRoot, "native-process");
  const nativeCli = Buffer.from(
    [
      "#!/bin/sh",
      'signal_record="$1"',
      'process_record="$2"',
      "trap 'printf TERM > \"$signal_record\"; trap - TERM; kill -TERM $$' TERM",
      'printf \'%s\' "$$" > "$process_record"',
      "while :; do :; done",
      "",
    ].join("\n"),
  );
  const sha256 = createHash("sha256").update(nativeCli).digest("hex");
  await mkdir(versionCache, { recursive: true });
  await writeFile(
    join(versionCache, "SHA256SUMS"),
    closedChecksums(new Map([[assetName, sha256]])),
  );
  await writeFile(join(versionCache, assetName), nativeCli);
  await chmod(join(versionCache, assetName), 0o700);

  const wrapper = spawn(
    process.execPath,
    [launcher, signalRecord, processRecord],
    {
      env: {
        ...process.env,
        FOLDERBASE_CLI_CACHE_DIR: cacheRoot,
        FOLDERBASE_CLI_TEST_ARCH: "arm64",
        FOLDERBASE_CLI_TEST_PLATFORM: "darwin",
      },
      stdio: "ignore",
    },
  );
  let nativeProcessId;
  let wrapperResult;
  let receivedSignal;
  let nativeWasAlive;
  try {
    for (let attempts = 0; attempts < 100; attempts += 1) {
      try {
        nativeProcessId = Number(await readFile(processRecord, "utf8"));
        break;
      } catch (error) {
        if (error.code !== "ENOENT") {
          throw error;
        }
        await new Promise((resolve) => setTimeout(resolve, 10));
      }
    }
    assert(Number.isSafeInteger(nativeProcessId));

    wrapper.kill("SIGTERM");
    wrapperResult = await new Promise((resolve) =>
      wrapper.on("close", (code, signal) => resolve({ code, signal })),
    );
    try {
      receivedSignal = await readFile(signalRecord, "utf8");
    } catch (error) {
      if (error.code !== "ENOENT") {
        throw error;
      }
    }
    nativeWasAlive = processIsAlive(nativeProcessId);
  } finally {
    if (wrapper.exitCode === null && wrapper.signalCode === null) {
      wrapper.kill("SIGKILL");
    }
    if (nativeProcessId && processIsAlive(nativeProcessId)) {
      process.kill(nativeProcessId, "SIGKILL");
    }
    await rm(temporaryRoot, { recursive: true, force: true });
  }

  assert.deepEqual(wrapperResult, { code: null, signal: "SIGTERM" });
  assert.equal(receivedSignal, "TERM");
  assert.equal(nativeWasAlive, false);
});

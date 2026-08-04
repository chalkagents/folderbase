#!/usr/bin/env node

import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import {
  mkdir,
  mkdtemp,
  readFile,
  rename,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, extname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const CAPABILITY = "folderbase.daemon-stdio@0.1.0";
const REPORT_FORMAT = "folderbase-capability-suite-report-v1";
const REQUEST_FORMAT = "folderbase-daemon-request-v1";
const MESSAGE_FORMAT = "folderbase-daemon-message-v1";
const MAX_LINE_BYTES = 8 * 1024 * 1024;
const MAX_SESSION_OUTPUT_BYTES = 32 * 1024 * 1024;
const RESPONSE_TIMEOUT_MS = 15_000;
const PROCESS_TIMEOUT_MS = 30_000;
const liveRequest = {
  format: "folderbase-query-request-v1",
  scope: { kind: "live" },
  page: { limit: 1000 },
};

function implementationArgument(argv) {
  const flag = argv.indexOf("--implementation");
  if (flag === -1 || !argv[flag + 1] || argv.length !== 2) {
    throw new Error("usage: run.mjs --implementation /path/to/folderbase");
  }
  if (argv[flag + 1].includes("\u0000")) throw new Error("implementation path contains NUL");
  return resolve(argv[flag + 1]);
}

function commandFor(implementation, arguments_) {
  return [".js", ".cjs", ".mjs"].includes(extname(implementation))
    ? { command: process.execPath, args: [implementation, ...arguments_] }
    : { command: implementation, args: arguments_ };
}

function execute(implementation, arguments_, input = "") {
  const invocation = commandFor(implementation, arguments_);
  const result = spawnSync(invocation.command, invocation.args, {
    encoding: "utf8",
    input,
    shell: false,
    windowsHide: true,
    maxBuffer: MAX_LINE_BYTES,
    timeout: PROCESS_TIMEOUT_MS,
    killSignal: "SIGKILL",
  });
  if (result.error) throw result.error;
  return result;
}

function successJson(implementation, arguments_, input = "") {
  const result = execute(implementation, arguments_, input);
  assert.equal(result.status, 0, result.stderr || result.stdout);
  assert.equal(result.stderr, "", "successful one-shot command leaves stderr empty");
  return JSON.parse(result.stdout);
}

function assertExactKeys(value, expected, label) {
  assert.deepEqual(Object.keys(value).sort(), [...expected].sort(), `${label} keys`);
}

function assertDaemonMessage(message) {
  assert.equal(message.format, MESSAGE_FORMAT);
  if (message.kind === "ready") {
    assertExactKeys(message, [
      "format",
      "kind",
      "capability",
      "epoch",
      "folderbase_id",
      "root_instance_sha256",
      "root",
    ], "ready");
    assert.equal(message.capability, CAPABILITY);
    assert.match(message.epoch, /^daemon_[0-9a-f-]{36}$/u);
    assert.match(message.folderbase_id, /^folderbase_[0-9a-f-]{36}$/u);
    assert.match(message.root_instance_sha256, /^[0-9a-f]{64}$/u);
    assert.equal(typeof message.root, "string");
    return;
  }
  if (message.kind === "response") {
    assertExactKeys(message, [
      "format",
      "kind",
      "request_id",
      "operation",
      "status",
      "document",
    ], "response");
    assert.ok(message.request_id === null || typeof message.request_id === "string");
    assert.ok(message.operation === null || [
      "query",
      "explain",
      "index_status",
      "refresh",
      "subscribe",
      "unsubscribe",
      "shutdown",
    ].includes(message.operation));
    assert.ok(["ok", "attention", "error"].includes(message.status));
    assert.ok(message.document && typeof message.document === "object" && !Array.isArray(message.document));
    return;
  }
  assert.equal(message.kind, "event");
  assertExactKeys(message, ["format", "kind", "event", "epoch", "sequence"], "event");
  assert.ok(["workspace_changed", "rescan_required"].includes(message.event));
  assert.match(message.epoch, /^daemon_[0-9a-f-]{36}$/u);
  assert.ok(Number.isSafeInteger(message.sequence) && message.sequence >= 1);
}

async function killTree(child) {
  if (child.exitCode !== null || child.signalCode !== null) return;
  if (process.platform === "win32") {
    await new Promise((resolve_) => {
      const killer = spawn("taskkill.exe", ["/PID", String(child.pid), "/T", "/F"], {
        stdio: "ignore",
        windowsHide: true,
      });
      killer.once("error", resolve_);
      killer.once("close", resolve_);
    });
  } else {
    try {
      process.kill(-child.pid, "SIGKILL");
    } catch (error) {
      if (error?.code !== "ESRCH") {
        try { child.kill("SIGKILL"); } catch {}
      }
    }
  }
  try { child.kill("SIGKILL"); } catch {}
}

class DaemonSession {
  constructor(child) {
    this.child = child;
    this.buffer = Buffer.alloc(0);
    this.queue = [];
    this.waiters = [];
    this.stderr = Buffer.alloc(0);
    this.outputBytes = 0;
    this.closed = false;
    this.closedPromise = new Promise((resolve_) => {
      this.resolveClosed = resolve_;
    });
    child.stdout.on("data", (chunk) => this.#stdout(chunk));
    child.stderr.on("data", (chunk) => {
      this.stderr = Buffer.concat([this.stderr, chunk]);
      if (this.stderr.length > MAX_LINE_BYTES) void killTree(child);
    });
    child.once("error", (error) => this.#close(error));
    child.once("close", (status, signal) => {
      this.status = status;
      this.signal = signal;
      this.resolveClosed({ status, signal });
      this.#close(new Error(`daemon closed with status ${status} signal ${signal ?? "none"}`));
    });
  }

  static async start(implementation, root) {
    const invocation = commandFor(implementation, ["daemon", "serve", root, "--stdio-jsonl"]);
    const child = spawn(invocation.command, invocation.args, {
      detached: process.platform !== "win32",
      shell: false,
      stdio: ["pipe", "pipe", "pipe"],
      windowsHide: true,
    });
    const session = new DaemonSession(child);
    const ready = await session.next((message) => message.kind === "ready");
    assert.equal(ready.format, MESSAGE_FORMAT);
    assert.equal(ready.capability, CAPABILITY);
    assert.match(ready.epoch, /^daemon_[0-9a-f-]{36}$/u);
    assert.match(ready.folderbase_id, /^folderbase_[0-9a-f-]{36}$/u);
    assert.match(ready.root_instance_sha256, /^[0-9a-f]{64}$/u);
    session.ready = ready;
    return session;
  }

  #stdout(chunk) {
    this.outputBytes += chunk.length;
    if (this.outputBytes > MAX_SESSION_OUTPUT_BYTES) {
      this.#close(new Error("daemon session output exceeded 32 MiB"));
      void killTree(this.child);
      return;
    }
    this.buffer = Buffer.concat([this.buffer, chunk]);
    if (this.buffer.length > MAX_LINE_BYTES && !this.buffer.includes(0x0a)) {
      this.#close(new Error("daemon output line exceeded 8 MiB"));
      void killTree(this.child);
      return;
    }
    while (true) {
      const newline = this.buffer.indexOf(0x0a);
      if (newline === -1) return;
      const line = this.buffer.subarray(0, newline);
      this.buffer = this.buffer.subarray(newline + 1);
      if (line.length === 0) {
        this.#close(new Error("daemon emitted an empty frame"));
        void killTree(this.child);
        return;
      }
      let message;
      try {
        message = JSON.parse(line.toString("utf8"));
      } catch (error) {
        this.#close(new Error(`daemon emitted invalid JSON: ${error.message}`));
        void killTree(this.child);
        return;
      }
      try {
        assertDaemonMessage(message);
      } catch (error) {
        this.#close(error);
        void killTree(this.child);
        return;
      }
      const waiter = this.waiters.find(({ predicate }) => predicate(message));
      if (waiter) {
        this.waiters.splice(this.waiters.indexOf(waiter), 1);
        clearTimeout(waiter.timer);
        waiter.resolve(message);
      } else {
        this.queue.push(message);
      }
    }
  }

  #close(error) {
    if (this.closed) return;
    this.closed = true;
    for (const waiter of this.waiters.splice(0)) {
      clearTimeout(waiter.timer);
      waiter.reject(error);
    }
  }

  next(predicate, timeoutMs = RESPONSE_TIMEOUT_MS) {
    const index = this.queue.findIndex(predicate);
    if (index !== -1) return Promise.resolve(this.queue.splice(index, 1)[0]);
    if (this.closed) return Promise.reject(new Error("daemon is already closed"));
    return new Promise((resolve_, reject) => {
      const waiter = {
        predicate,
        resolve: resolve_,
        reject,
        timer: setTimeout(() => {
          const position = this.waiters.indexOf(waiter);
          if (position !== -1) this.waiters.splice(position, 1);
          reject(new Error(`daemon response timed out after ${timeoutMs} ms`));
        }, timeoutMs),
      };
      this.waiters.push(waiter);
    });
  }

  async request(operation, document) {
    const requestId = `request-${randomUUID()}`;
    const request = {
      format: REQUEST_FORMAT,
      request_id: requestId,
      operation,
      ...(document === undefined ? {} : { document }),
    };
    this.child.stdin.write(`${JSON.stringify(request)}\n`);
    const response = await this.next(
      (message) => message.kind === "response" && message.request_id === requestId,
    );
    assert.equal(response.operation, operation);
    return response;
  }

  event(timeoutMs = RESPONSE_TIMEOUT_MS) {
    return this.next((message) => message.kind === "event", timeoutMs);
  }

  async assertNoEvent(timeoutMs = 300) {
    try {
      const event = await this.event(timeoutMs);
      assert.fail(`unexpected daemon event ${JSON.stringify(event)}`);
    } catch (error) {
      if (!String(error.message).includes("timed out")) throw error;
    }
  }

  async stop() {
    await killTree(this.child);
  }

  async waitClosed(timeoutMs = 2_000) {
    return Promise.race([
      this.closedPromise,
      new Promise((_, reject) => setTimeout(
        () => reject(new Error(`daemon did not exit within ${timeoutMs} ms`)),
        timeoutMs,
      )),
    ]);
  }
}

async function fixture(implementation) {
  const owner = await mkdtemp(join(tmpdir(), "folderbase-daemon-0.1-"));
  const root = join(owner, "root");
  await mkdir(join(root, "docs"), { recursive: true });
  await writeFile(join(root, "docs", "summary.md"), "initial\n");
  await writeFile(join(root, "data.csv"), "id,value\n1,alpha\n");
  successJson(implementation, ["init", root, "--json"]);
  return { owner, root };
}

function assertOk(response, expectedFormat) {
  assert.equal(response.status, "ok", JSON.stringify(response.document));
  assert.equal(response.document.format, expectedFormat);
  return response.document;
}

async function withSession(implementation, operation) {
  const state = await fixture(implementation);
  let session;
  try {
    session = await DaemonSession.start(implementation, state.root);
    await operation({ ...state, session });
  } finally {
    if (session) await session.stop();
    await rm(state.owner, { force: true, recursive: true });
  }
}

const cases = [
  {
    name: "ready-and-query-equivalence",
    covers: ["explicit-root", "ready-attestation", "one-shot-equivalence"],
    run: (implementation) => withSession(implementation, async ({ root, session }) => {
      const direct = successJson(
        implementation,
        ["query", "run", root, "--json"],
        `${JSON.stringify(liveRequest)}\n`,
      );
      const response = await session.request("query", liveRequest);
      assert.deepEqual(assertOk(response, "folderbase-query-result-v1"), direct);
    }),
  },
  {
    name: "explain-status-refresh-delegation",
    covers: ["explain-equivalence", "index-status", "explicit-refresh"],
    run: (implementation) => withSession(implementation, async ({ root, session }) => {
      const direct = successJson(
        implementation,
        ["query", "explain", root, "--json"],
        `${JSON.stringify(liveRequest)}\n`,
      );
      assert.deepEqual(
        assertOk(await session.request("explain", liveRequest), "folderbase-query-explain-v1"),
        direct,
      );
      assertOk(await session.request("index_status"), "folderbase-query-index-status-v1");
      assertOk(await session.request("refresh"), "folderbase-query-index-rebuild-result-v1");
    }),
  },
  {
    name: "create-edit-move-delete-convergence",
    covers: ["create", "edit", "move", "delete", "authoritative-query"],
    run: (implementation) => withSession(implementation, async ({ root, session }) => {
      assertOk(await session.request("subscribe"), "folderbase-daemon-subscription-v1");
      const created = join(root, "docs", "working.txt");
      await writeFile(created, "one\n");
      assert.equal((await session.event()).event, "workspace_changed");
      let rows = assertOk(await session.request("query", liveRequest), "folderbase-query-result-v1").entries;
      assert.ok(rows.some(({ path }) => path === "docs/working.txt"));
      await writeFile(created, "two\n");
      rows = assertOk(await session.request("query", liveRequest), "folderbase-query-result-v1").entries;
      assert.ok(rows.some(({ path }) => path === "docs/working.txt"));
      await rename(created, join(root, "docs", "final.txt"));
      rows = assertOk(await session.request("query", liveRequest), "folderbase-query-result-v1").entries;
      assert.ok(rows.some(({ path }) => path === "docs/final.txt"));
      await rm(join(root, "docs", "final.txt"));
      rows = assertOk(await session.request("query", liveRequest), "folderbase-query-result-v1").entries;
      assert.ok(!rows.some(({ path }) => path === "docs/final.txt"));
    }),
  },
  {
    name: "burst-events-are-coalesced",
    covers: ["duplicate-events", "out-of-order-events", "bounded-coalescing"],
    run: (implementation) => withSession(implementation, async ({ root, session }) => {
      assertOk(await session.request("subscribe"), "folderbase-daemon-subscription-v1");
      await Promise.all(Array.from({ length: 32 }, (_, index) =>
        writeFile(join(root, `burst-${String(index).padStart(2, "0")}.txt`), `${index}\n`)));
      const event = await session.event();
      assert.equal(event.event, "workspace_changed");
      await session.assertNoEvent(500);
      const result = assertOk(await session.request("query", liveRequest), "folderbase-query-result-v1");
      assert.equal(result.entries.filter(({ path }) => path.startsWith("burst-")).length, 32);
    }),
  },
  {
    name: "missing-corrupt-index-falls-back",
    covers: ["missing-index", "corrupt-index", "rescan"],
    run: (implementation) => withSession(implementation, async ({ root, session }) => {
      assertOk(await session.request("refresh"), "folderbase-query-index-rebuild-result-v1");
      const index = join(root, ".folderbase", "local", "query-index-v1", "index.json");
      await writeFile(index, "{corrupt\n");
      const corrupt = assertOk(await session.request("query", liveRequest), "folderbase-query-result-v1");
      assert.ok(corrupt.entries.some(({ path }) => path === "data.csv"));
      await rm(index);
      const missing = assertOk(await session.request("query", liveRequest), "folderbase-query-result-v1");
      assert.deepEqual(missing.entries, corrupt.entries);
    }),
  },
  {
    name: "nested-folderbase-is-opaque",
    covers: ["nested-boundary", "no-authority-inheritance"],
    run: (implementation) => withSession(implementation, async ({ owner, root, session }) => {
      const source = join(owner, "nested-source");
      await mkdir(source);
      successJson(implementation, ["init", source, "--json"]);
      await writeFile(join(source, "secret.txt"), "must remain opaque\n");
      await rename(source, join(root, "vendor"));
      const result = assertOk(await session.request("query", liveRequest), "folderbase-query-result-v1");
      assert.ok(result.entries.some(({ path, kind }) => path === "vendor" && kind === "nested_folderbase"));
      assert.ok(!JSON.stringify(result).includes("secret.txt"));
    }),
  },
  {
    name: "physical-root-replacement-fails-closed",
    covers: ["root-replacement", "root-pinning"],
    run: (implementation) => withSession(implementation, async ({ owner, root, session }) => {
      const displaced = join(owner, "displaced");
      await rename(root, displaced);
      await mkdir(root);
      successJson(implementation, ["init", root, "--json"]);
      const response = await session.request("query", liveRequest);
      assert.equal(response.status, "error");
      assert.equal(response.document.format, "folderbase-query-error-v1");
      assert.equal(response.document.error.code, "query_root_changed");
      const closed = await session.waitClosed();
      assert.equal(closed.status, 2);
    }),
  },
  {
    name: "invalid-frames-are-bounded-and-recoverable",
    covers: ["malformed-json", "oversized-frame", "framing-recovery"],
    run: (implementation) => withSession(implementation, async ({ session }) => {
      session.child.stdin.write("{}\n");
      let response = await session.next(
        (message) => message.kind === "response" && message.request_id === null,
      );
      assert.equal(response.status, "error");
      assert.equal(response.document.error.code, "invalid_daemon_request");
      session.child.stdin.write(`${"x".repeat(4 * 1024 * 1024 + 1)}\n`);
      response = await session.next(
        (message) => message.kind === "response" && message.request_id === null,
      );
      assert.equal(response.status, "error");
      assertOk(await session.request("query", liveRequest), "folderbase-query-result-v1");
    }),
  },
  {
    name: "subscription-lifecycle-does-not-hide-changes",
    covers: ["subscribe", "unsubscribe", "event-loss-safety"],
    run: (implementation) => withSession(implementation, async ({ root, session }) => {
      assertOk(await session.request("subscribe"), "folderbase-daemon-subscription-v1");
      assertOk(await session.request("unsubscribe"), "folderbase-daemon-subscription-v1");
      await writeFile(join(root, "offline-hint.txt"), "visible anyway\n");
      const result = assertOk(await session.request("query", liveRequest), "folderbase-query-result-v1");
      assert.ok(result.entries.some(({ path }) => path === "offline-hint.txt"));
    }),
  },
  {
    name: "shutdown-eof-and-restart-are-disposable",
    covers: ["shutdown", "eof", "restart", "edits-while-down"],
    run: async (implementation) => {
      const state = await fixture(implementation);
      let first;
      let second;
      let third;
      try {
        first = await DaemonSession.start(implementation, state.root);
        assertOk(await first.request("shutdown"), "folderbase-daemon-shutdown-v1");
        const shutdown = await first.waitClosed();
        assert.equal(shutdown.status, 0);
        await writeFile(join(state.root, "while-down.txt"), "later\n");
        second = await DaemonSession.start(implementation, state.root);
        const result = assertOk(await second.request("query", liveRequest), "folderbase-query-result-v1");
        assert.ok(result.entries.some(({ path }) => path === "while-down.txt"));
        second.child.stdin.end();
        await new Promise((resolve_) => second.child.once("close", resolve_));
        assert.equal(second.status, 0);
        third = await DaemonSession.start(implementation, state.root);
        assert.notEqual(third.ready.epoch, first.ready.epoch);
      } finally {
        for (const session of [first, second, third]) if (session) await session.stop();
        await rm(state.owner, { force: true, recursive: true });
      }
    },
  },
];

async function main() {
  const implementation = implementationArgument(process.argv.slice(2));
  const results = [];
  for (const definition of cases) {
    try {
      await definition.run(implementation);
      results.push({ name: definition.name, status: "passed", covers: definition.covers });
    } catch (error) {
      results.push({
        name: definition.name,
        status: "failed",
        covers: definition.covers,
        message: error instanceof Error ? error.message : String(error),
      });
    }
  }
  const passed = results.filter(({ status }) => status === "passed").length;
  const report = {
    format: REPORT_FORMAT,
    capability: CAPABILITY,
    total: results.length,
    passed,
    failed: results.length - passed,
    cases: results,
  };
  process.stdout.write(`${JSON.stringify(report)}\n`);
  process.exitCode = report.failed === 0 ? 0 : 1;
}

await main();

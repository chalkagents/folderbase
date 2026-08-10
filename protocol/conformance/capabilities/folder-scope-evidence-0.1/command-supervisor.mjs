#!/usr/bin/env node

import { spawn } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const chunks = [];
for await (const chunk of process.stdin) chunks.push(chunk);
const payloadText = Buffer.concat(chunks).toString("utf8");
const payload = JSON.parse(payloadText);
const directory = dirname(fileURLToPath(import.meta.url));
const workerScript = join(directory, "command-supervisor-worker.mjs");
const workerCommand = process.platform === "win32" ? "powershell.exe" : process.execPath;
const workerArguments = process.platform === "win32"
  ? [
      "-NoLogo",
      "-NoProfile",
      "-NonInteractive",
      "-ExecutionPolicy",
      "Bypass",
      "-File",
      join(directory, "command-supervisor-windows.ps1"),
    ]
  : [workerScript];
const worker = spawn(
  workerCommand,
  workerArguments,
  {
    detached: process.platform !== "win32",
    env: process.platform === "win32"
      ? {
          ...process.env,
          FOLDERBASE_NODE_EXECUTABLE: process.execPath,
          FOLDERBASE_SUPERVISOR_WORKER: workerScript,
        }
      : process.env,
    shell: false,
    stdio: ["pipe", "pipe", "pipe"],
    windowsHide: true,
  },
);

let workerOutput = Buffer.alloc(0);
let workerError = Buffer.alloc(0);
let resultLine;
let failure;
const maximumWorkerBytes = payload.maxBytes * 2 + 1024 * 1024;

function boundedAppend(current, chunk, maximum) {
  const remaining = Math.max(0, maximum - current.length);
  return remaining === 0 ? current : Buffer.concat([current, chunk.subarray(0, remaining)]);
}

async function taskkill(pid) {
  await new Promise((resolveTaskkill) => {
    const killer = spawn("taskkill.exe", ["/PID", String(pid), "/T", "/F"], {
      stdio: "ignore",
      windowsHide: true,
    });
    killer.once("error", resolveTaskkill);
    killer.once("close", resolveTaskkill);
  });
}

async function killWorkerGroup() {
  if (process.platform === "win32") {
    await taskkill(worker.pid);
  } else {
    for (let attempt = 0; attempt < 50; attempt += 1) {
      try {
        process.kill(-worker.pid, "SIGKILL");
      } catch (error) {
        if (error?.code === "ESRCH") break;
        try { worker.kill("SIGKILL"); } catch {}
      }
      await new Promise((resolveDelay) => setTimeout(resolveDelay, 10));
    }
  }
  try { worker.kill("SIGKILL"); } catch {}
}

let resolveWorkerResult;
const resultPromise = new Promise((resolveResult) => {
  resolveWorkerResult = resolveResult;
  worker.stdout.on("data", (chunk) => {
    workerOutput = boundedAppend(workerOutput, chunk, maximumWorkerBytes);
    const newline = workerOutput.indexOf(0x0a);
    if (newline !== -1 && resultLine === undefined) {
      resultLine = workerOutput.subarray(0, newline).toString("utf8");
      resolveResult();
    } else if (workerOutput.length >= maximumWorkerBytes && failure === undefined) {
      failure = "candidate supervisor worker exceeded its bounded result";
      resolveResult();
    }
  });
  worker.stderr.on("data", (chunk) => {
    workerError = boundedAppend(workerError, chunk, 1024 * 1024);
  });
  worker.once("error", (error) => {
    failure = error.message;
    resolveResult();
  });
  worker.once("exit", (status, signal) => {
    if (resultLine === undefined && failure === undefined) {
      failure = workerError.toString("utf8")
        || `candidate supervisor worker exited ${status ?? signal ?? "without a result"}`;
      resolveResult();
    }
  });
});

worker.stdin.on("error", (error) => {
  if (error?.code !== "EPIPE" && error?.code !== "ERR_STREAM_DESTROYED") {
    failure = error.message;
    resolveWorkerResult();
  }
});
worker.stdin.end(payloadText);
let timedOut = false;
const timer = setTimeout(() => {
  timedOut = true;
  failure = "candidate supervisor worker did not return a bounded result";
  void killWorkerGroup();
  resolveWorkerResult();
}, payload.timeoutMs + 2_000);

await resultPromise;
clearTimeout(timer);
await killWorkerGroup();

if (resultLine !== undefined && !timedOut) {
  process.stdout.write(resultLine);
} else {
  process.stdout.write(JSON.stringify({
    error: { message: failure ?? "candidate supervisor failed" },
    bound: timedOut ? "timeout" : null,
    stdout: "",
    stderr: workerError.toString("utf8"),
  }));
}

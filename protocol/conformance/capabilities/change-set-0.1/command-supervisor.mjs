#!/usr/bin/env node

import { spawn } from "node:child_process";

const chunks = [];
for await (const chunk of process.stdin) chunks.push(chunk);
const payload = JSON.parse(Buffer.concat(chunks).toString("utf8"));
let child;
let timer;
let bound = null;
let stdout = Buffer.alloc(0);
let stderr = Buffer.alloc(0);

function append(current, chunk, otherLength) {
  const remaining = Math.max(0, payload.maxBytes - current.length - otherLength);
  return remaining === 0 ? current : Buffer.concat([current, chunk.subarray(0, remaining)]);
}

async function taskkill(pid) {
  await new Promise((resolve) => {
    const killer = spawn("taskkill.exe", ["/PID", String(pid), "/T", "/F"], {
      stdio: "ignore",
      windowsHide: true,
    });
    killer.once("error", resolve);
    killer.once("close", resolve);
  });
}

async function killTree() {
  if (!child || child.exitCode !== null || child.signalCode !== null) return;
  if (process.platform === "win32") await taskkill(child.pid);
  else {
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

try {
  child = spawn(payload.command, payload.args, {
    detached: process.platform !== "win32",
    env: { ...process.env, ...(payload.environment ?? {}) },
    shell: false,
    stdio: ["pipe", "pipe", "pipe"],
    windowsHide: true,
  });
  child.stdout.on("data", (chunk) => {
    stdout = append(stdout, chunk, stderr.length);
    if (stdout.length + stderr.length >= payload.maxBytes && bound === null) {
      bound = "output";
      void killTree();
    }
  });
  child.stderr.on("data", (chunk) => {
    stderr = append(stderr, chunk, stdout.length);
    if (stdout.length + stderr.length >= payload.maxBytes && bound === null) {
      bound = "output";
      void killTree();
    }
  });
  child.stdin.end(Buffer.from(payload.input, "base64"));
  timer = setTimeout(() => {
    if (bound === null) bound = "timeout";
    void killTree();
  }, payload.timeoutMs);
  const outcome = await new Promise((resolve) => {
    child.once("error", (error) => resolve({ error: { code: error.code, message: error.message } }));
    child.once("close", (status, signal) => resolve({ status, signal }));
  });
  clearTimeout(timer);
  if (bound !== null) await killTree();
  process.stdout.write(JSON.stringify({
    ...outcome,
    bound,
    stdout: stdout.toString("utf8"),
    stderr: stderr.toString("utf8"),
  }));
} catch (error) {
  clearTimeout(timer);
  await killTree();
  process.stdout.write(JSON.stringify({
    error: { code: error?.code, message: error instanceof Error ? error.message : String(error) },
    bound,
    stdout: stdout.toString("utf8"),
    stderr: stderr.toString("utf8"),
  }));
}

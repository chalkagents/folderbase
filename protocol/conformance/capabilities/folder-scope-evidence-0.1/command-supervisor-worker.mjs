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
let emitted = false;

function append(current, chunk, otherLength) {
  const remaining = Math.max(0, payload.maxBytes - current.length - otherLength);
  return remaining === 0 ? current : Buffer.concat([current, chunk.subarray(0, remaining)]);
}

function killLeader() {
  try { child?.kill("SIGKILL"); } catch {}
}

function emit(outcome) {
  if (emitted) return;
  emitted = true;
  clearTimeout(timer);
  process.stdout.write(`${JSON.stringify({
    ...outcome,
    bound,
    stdout: stdout.toString("utf8"),
    stderr: stderr.toString("utf8"),
  })}\n`);
}

try {
  child = spawn(payload.command, payload.args, {
    detached: false,
    env: { ...process.env, ...(payload.environment ?? {}) },
    shell: false,
    stdio: ["pipe", "pipe", "pipe"],
    windowsHide: true,
  });
  child.stdout.on("data", (chunk) => {
    stdout = append(stdout, chunk, stderr.length);
    if (stdout.length + stderr.length >= payload.maxBytes && bound === null) {
      bound = "output";
      killLeader();
    }
  });
  child.stderr.on("data", (chunk) => {
    stderr = append(stderr, chunk, stdout.length);
    if (stdout.length + stderr.length >= payload.maxBytes && bound === null) {
      bound = "output";
      killLeader();
    }
  });
  child.stdin.on("error", (error) => {
    if (error?.code !== "EPIPE" && error?.code !== "ERR_STREAM_DESTROYED") {
      emit({ error: { code: error?.code, message: error?.message ?? String(error) } });
    }
  });
  child.stdin.end(Buffer.from(payload.input, "base64"));
  timer = setTimeout(() => {
    if (bound === null) bound = "timeout";
    killLeader();
  }, payload.timeoutMs);
  child.once("error", (error) => {
    emit({ error: { code: error.code, message: error.message } });
  });
  child.once("exit", (status, signal) => emit({ status, signal }));
} catch (error) {
  killLeader();
  emit({
    error: {
      code: error?.code,
      message: error instanceof Error ? error.message : String(error),
    },
  });
}

await new Promise(() => {});

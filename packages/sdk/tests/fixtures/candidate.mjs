#!/usr/bin/env node

import { createInterface } from "node:readline";

const [mode, ...arguments_] = process.argv.slice(2);

async function stdinText() {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  return Buffer.concat(chunks).toString("utf8");
}

function writeJson(stream, value) {
  stream.write(`${JSON.stringify(value)}\n`);
}

if (mode === "attention") {
  writeJson(process.stdout, {
    format: "fixture-attention-v1",
    reason: "review_required",
    unknown_vendor: { retained: true },
  });
  process.exitCode = 1;
} else if (mode === "operational-error") {
  writeJson(process.stderr, {
    format: "fixture-error-v1",
    error: { code: "fixture_failed", message: "fixture failed safely" },
  });
  process.exitCode = 2;
} else if (mode === "malformed") {
  process.stdout.write("{not-json\n");
} else if (mode === "noisy") {
  writeJson(process.stdout, { format: "fixture-success-v1" });
  process.stderr.write("human noise\n");
} else if (mode === "overflow") {
  process.stdout.write("x".repeat(64 * 1024));
} else if (mode === "hang") {
  setInterval(() => {}, 60_000);
} else if (mode === "daemon") {
  const root = arguments_[1];
  const epoch = "daemon_018f23f8-7bf2-7000-8000-000000000001";
  writeJson(process.stdout, {
    format: "folderbase-daemon-message-v1",
    kind: "ready",
    capability: "folderbase.daemon-stdio@0.1.0",
    epoch,
    folderbase_id: "folderbase_018f23f8-7bf2-7000-8000-000000000002",
    root_instance_sha256: "a".repeat(64),
    root,
  });
  const lines = createInterface({ input: process.stdin, crlfDelay: Infinity });
  for await (const line of lines) {
    const request = JSON.parse(line);
    let document;
    if (request.operation === "query") {
      document = {
        format: "folderbase-query-result-v1",
        entries: [],
        unknown_vendor: { retained: true },
      };
    } else if (request.operation === "subscribe") {
      document = {
        format: "folderbase-daemon-subscription-v1",
        subscribed: true,
      };
    } else if (request.operation === "shutdown") {
      document = {
        format: "folderbase-daemon-shutdown-v1",
        status: "shutting_down",
      };
    } else {
      document = { format: "fixture-daemon-result-v1" };
    }
    writeJson(process.stdout, {
      format: "folderbase-daemon-message-v1",
      kind: "response",
      request_id: request.request_id,
      operation: request.operation,
      status: "ok",
      document,
    });
    if (request.operation === "subscribe") {
      writeJson(process.stdout, {
        format: "folderbase-daemon-message-v1",
        kind: "event",
        event: "workspace_changed",
        epoch,
        sequence: 1,
      });
    }
    if (request.operation === "shutdown") break;
  }
} else {
  writeJson(process.stdout, {
    format: "fixture-success-v1",
    argv: [mode, ...arguments_],
    stdin: await stdinText(),
    unknown_vendor: { retained: true },
  });
}

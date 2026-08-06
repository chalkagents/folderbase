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

const RECONSTRUCTION_REQUEST_SHA256 =
  "5efe8d56bc354c89ec52006c25e123dfb42cbdb1eeed2b1f4013a634590133e5";

if (mode === "reconstruct") {
  const [source, destination, ...flags] = arguments_;
  const request = JSON.parse(await stdinText());
  if (source !== "/tmp/package"
    || flags.length !== 2
    || flags[0] !== "--stdin"
    || flags[1] !== "--json") {
    writeJson(process.stderr, {
      format: "folderbase-root-reconstruction-error-v1",
      error: { code: "invalid_invocation", message: "wrong reconstruction arguments" },
    });
    process.exitCode = 2;
  } else if ([
    "/tmp/error",
    "/tmp/malformed-error",
    "/tmp/wrong-error-request-digest",
  ].includes(destination)) {
    writeJson(process.stderr, {
      format: "folderbase-root-reconstruction-error-v1",
      operation_id: request.operation_id,
      ...(destination === "/tmp/wrong-error-request-digest"
        ? { request_sha256: "f".repeat(64) }
        : { request_sha256: RECONSTRUCTION_REQUEST_SHA256 }),
      package_index_sha256: request.package_index_sha256,
      error: { code: "reconstruction_failed", message: "failed safely" },
      ...(destination === "/tmp/malformed-error" ? { ambient_cloud: true } : {}),
    });
    process.exitCode = 2;
  } else if (destination === "/tmp/occupied"
    || destination === "/tmp/wrong-attention-request-digest") {
    writeJson(process.stdout, {
      format: "folderbase-root-reconstruction-attention-v1",
      operation_id: request.operation_id,
      request_sha256: destination === "/tmp/wrong-attention-request-digest"
        ? "f".repeat(64)
        : RECONSTRUCTION_REQUEST_SHA256,
      package_index_sha256: request.package_index_sha256,
      attention: {
        code: "destination_occupied",
        message: "destination already exists",
        retryable: false,
      },
    });
    process.exitCode = 1;
  } else {
    writeJson(process.stdout, {
      format: "folderbase-root-reconstruction-result-v1",
      operation_id: request.operation_id,
      request_sha256: destination === "/tmp/wrong-result-request-digest"
        ? "f".repeat(64)
        : RECONSTRUCTION_REQUEST_SHA256,
      folderbase_id: "folderbase_019f0000-0000-7000-8000-000000000001",
      folderbase_version_id: "fbversion_019f0000-0000-7000-8000-000000000001",
      canonical_version_sha256: "c".repeat(64),
      package_index_sha256: request.package_index_sha256,
      verified_object_count: 1,
      version_authenticated_object_count: 1,
      retained_tombstone_object_count: 0,
      visible_entry_count: 1,
      verified_opaque_bytes: 1,
      root_attestation: {
        root: destination === "/tmp/wrong-root" ? "/tmp/substituted-root" : destination,
        folderbase_id: "folderbase_019f0000-0000-7000-8000-000000000001",
        protocol_version: "0.5.0",
        manifest_sha256: "d".repeat(64),
        root_instance_sha256: "e".repeat(64),
      },
      replayed: false,
      ...(destination === "/tmp/malformed-result" ? { ambient_cloud: true } : {}),
    });
  }
} else if (mode === "attention") {
  writeJson(process.stdout, {
    format: "fixture-attention-v1",
    reason: "review_required",
    unknown_vendor: { retained: true },
  });
  process.exitCode = 1;
} else if (mode === "array") {
  writeJson(process.stdout, [{ action: "version.captured" }]);
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

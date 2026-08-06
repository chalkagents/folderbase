import assert from "node:assert/strict";
import { once } from "node:events";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  FolderbaseCancelledError,
  FolderbaseClient,
  FolderbaseMalformedOutputError,
  FolderbaseOperationalError,
  FolderbaseOutputLimitError,
} from "../src/index.js";

const directory = dirname(fileURLToPath(import.meta.url));
const fixture = join(directory, "fixtures", "candidate.mjs");

function client(options = {}) {
  return new FolderbaseClient({
    executable: process.execPath,
    argumentsPrefix: [fixture],
    timeoutMs: 2_000,
    ...options,
  });
}

test("success and attention preserve complete additive JSON documents", async () => {
  const success = await client().run(["success"]);
  assert.deepEqual(success, {
    kind: "success",
    exitCode: 0,
    document: {
      format: "fixture-success-v1",
      argv: ["success"],
      stdin: "",
      unknown_vendor: { retained: true },
    },
  });

  const attention = await client().run(["attention"]);
  assert.equal(attention.kind, "attention");
  assert.equal(attention.exitCode, 1);
  assert.deepEqual(attention.document.unknown_vendor, { retained: true });

  const history = await client().run(["array"]);
  assert.deepEqual(history.document, [{ action: "version.captured" }]);
});

test("operational errors retain the typed stderr document", async () => {
  await assert.rejects(
    client().run(["operational-error"]),
    (error) => {
      assert.ok(error instanceof FolderbaseOperationalError);
      assert.equal(error.exitCode, 2);
      assert.equal(error.document.error.code, "fixture_failed");
      return true;
    },
  );
});

test("malformed, noisy, and oversized output fail closed", async () => {
  await assert.rejects(
    client().run(["malformed"]),
    FolderbaseMalformedOutputError,
  );
  await assert.rejects(
    client().run(["noisy"]),
    FolderbaseMalformedOutputError,
  );
  await assert.rejects(
    client({ maxOutputBytes: 1_024 }).run(["overflow"]),
    FolderbaseOutputLimitError,
  );
});

test("abort terminates a hanging command within a bounded interval", async () => {
  const controller = new AbortController();
  const started = Date.now();
  const result = client({ timeoutMs: 5_000 }).run(["hang"], {
    signal: controller.signal,
  });
  setTimeout(() => controller.abort(), 50);
  await assert.rejects(result, FolderbaseCancelledError);
  assert.ok(Date.now() - started < 1_500);
});

test("helpers use exact public arguments and bounded JSON stdin", async () => {
  const sdk = client();
  const contract = await sdk.contract();
  assert.deepEqual(contract.document.argv, ["protocol", "contract", "--json"]);

  const query = { format: "folderbase-query-request-v1", source: "live" };
  const queried = await sdk.query("/tmp/folder", query);
  assert.deepEqual(queried.document.argv, ["query", "run", "/tmp/folder", "--json"]);
  assert.equal(queried.document.stdin, `${JSON.stringify(query)}\n`);

  const template = { format: "folderbase-template-expansion-request-v1" };
  const planned = await sdk.templatePlan("/tmp/folder", template);
  assert.deepEqual(planned.document.argv, [
    "template", "plan", "/tmp/folder", "--stdin", "--json",
  ]);
  assert.equal(planned.document.stdin, `${JSON.stringify(template)}\n`);

  const changeSet = { format: "folderbase-change-set-v1" };
  const assessed = await sdk.changeSetAssess(
    "/tmp/folder",
    "/tmp/staging",
    changeSet,
  );
  assert.deepEqual(assessed.document.argv, [
    "change-set", "assess", "/tmp/folder", "/tmp/staging", "--stdin", "--json",
  ]);
});

test("reconstruct uses the exact universal JSON surface and validates closed outcomes", async () => {
  const request = {
    format: "folderbase-root-reconstruction-request-v1",
    operation_id: "reconstruction_019f0000-0000-7000-8000-000000000001",
    package_index_sha256: "a".repeat(64),
  };
  const reconstructed = await client().reconstruct(
    "/tmp/package",
    "/tmp/reconstructed",
    request,
  );
  assert.equal(reconstructed.kind, "success");
  assert.equal(reconstructed.document.operation_id, request.operation_id);
  assert.equal(
    reconstructed.document.package_index_sha256,
    request.package_index_sha256,
  );
  assert.equal(reconstructed.document.root_attestation.root, "/tmp/reconstructed");

  const attention = await client().reconstruct(
    "/tmp/package",
    "/tmp/occupied",
    request,
  );
  assert.equal(attention.kind, "attention");
  assert.equal(attention.document.attention.code, "destination_occupied");

  await assert.rejects(
    client().reconstruct("/tmp/package", "/tmp/error", request),
    (error) => {
      assert.ok(error instanceof FolderbaseOperationalError);
      assert.equal(error.document.format, "folderbase-root-reconstruction-error-v1");
      assert.equal(error.document.error.code, "reconstruction_failed");
      return true;
    },
  );
  await assert.rejects(
    client().reconstruct("/tmp/package", "/tmp/malformed-result", request),
    FolderbaseMalformedOutputError,
  );
  await assert.rejects(
    client().reconstruct("/tmp/package", "/tmp/malformed-error", request),
    FolderbaseMalformedOutputError,
  );
});

test("reconstruct rejects unbounded or open requests before spawning", async () => {
  const request = {
    format: "folderbase-root-reconstruction-request-v1",
    operation_id: "reconstruction_019f0000-0000-7000-8000-000000000001",
    package_index_sha256: "a".repeat(64),
  };
  await assert.rejects(
    client().reconstruct("/tmp/package", "/tmp/reconstructed", {
      ...request,
      provider_url: "https://ambient.invalid/package",
    }),
    TypeError,
  );
  await assert.rejects(
    client().reconstruct("/tmp/package", "/tmp/reconstructed", {
      ...request,
      operation_id: `reconstruction_${"x".repeat(5_000)}`,
    }),
    TypeError,
  );
  await assert.rejects(
    client().reconstruct("relative/package", "/tmp/reconstructed", request),
    TypeError,
  );
  await assert.rejects(
    client().reconstruct("/tmp/package", "relative/destination", request),
    TypeError,
  );
});

test("reconstruct rejects request-digest and destination substitution", async () => {
  const request = {
    format: "folderbase-root-reconstruction-request-v1",
    operation_id: "reconstruction_019f0000-0000-7000-8000-000000000001",
    package_index_sha256: "a".repeat(64),
  };
  for (const destination of [
    "/tmp/wrong-result-request-digest",
    "/tmp/wrong-attention-request-digest",
    "/tmp/wrong-error-request-digest",
    "/tmp/wrong-root",
  ]) {
    await assert.rejects(
      client().reconstruct("/tmp/package", destination, request),
      FolderbaseMalformedOutputError,
      destination,
    );
  }
});

test("daemon session exposes ready, serial responses, hints, and shutdown", async () => {
  const session = await client().startDaemon("/tmp/folder");
  assert.equal(session.ready.root, "/tmp/folder");
  assert.equal(session.ready.capability, "folderbase.daemon-stdio@0.1.0");

  const query = await session.request("query", {
    format: "folderbase-query-request-v1",
    source: "live",
  });
  assert.equal(query.status, "ok");
  assert.deepEqual(query.document.unknown_vendor, { retained: true });

  const eventPromise = once(session, "event");
  await session.request("subscribe");
  const [event] = await eventPromise;
  assert.equal(event.event, "workspace_changed");
  assert.equal(event.sequence, 1);

  const shutdown = await session.shutdown();
  assert.equal(shutdown.document.status, "shutting_down");
  await session.closed;
});

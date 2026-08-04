#!/usr/bin/env node

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  access,
  lstat,
  mkdir,
  mkdtemp,
  open,
  readFile,
  readdir,
  readlink,
  rename,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { createReadStream } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, extname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

import { changeSetSha256 } from "./reference-change-set-digest.mjs";
import { assertChangeSetSchema } from "./schema.mjs";
import {
  DEFAULT_COMMAND_TIMEOUT_MS,
  MAXIMUM_COMMAND_TIMEOUT_MS,
} from "./limits.mjs";

const REPORT_FORMAT = "folderbase-capability-suite-report-v1";
const CAPABILITY = "folderbase.change-set@0.1.0";
const PRIVATE_MARKER = "FOLDERBASE-CONFORMANCE-PRIVATE-SIBLING-MUST-NEVER-LEAK";
const DEFAULT_MAX_BYTES = 8 * 1024 * 1024;
const directory = dirname(fileURLToPath(import.meta.url));
const scenarioDirectory = join(directory, "fixtures", "scenarios");
const supervisor = join(directory, "command-supervisor.mjs");
const schema = JSON.parse(
  await readFile(
    resolve(directory, "../../../schemas/capabilities/change-set/0.1/change-set.schema.json"),
    "utf8",
  ),
);

function boundedEnvironmentInteger(name, fallback, minimum, maximum) {
  const source = process.env[name];
  if (source === undefined) return fallback;
  const value = Number(source);
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new Error(`${name} must be an integer from ${minimum} through ${maximum}`);
  }
  return value;
}

const timeoutMs = boundedEnvironmentInteger(
  "FOLDERBASE_CHANGE_SET_CONFORMANCE_COMMAND_TIMEOUT_MS",
  DEFAULT_COMMAND_TIMEOUT_MS,
  100,
  MAXIMUM_COMMAND_TIMEOUT_MS,
);
const maxBytes = boundedEnvironmentInteger(
  "FOLDERBASE_CHANGE_SET_CONFORMANCE_COMMAND_MAX_BYTES",
  DEFAULT_MAX_BYTES,
  1024,
  16 * 1024 * 1024,
);

function implementationArgument(argv) {
  const flag = argv.indexOf("--implementation");
  if (flag === -1 || !argv[flag + 1] || argv.length !== 2) {
    throw new Error("usage: run.mjs --implementation /path/to/folderbase");
  }
  if (argv[flag + 1].includes("\u0000")) throw new Error("implementation path contains NUL");
  return resolve(argv[flag + 1]);
}

function execute(implementation, arguments_, input = "", environment = {}) {
  const command = [".js", ".cjs", ".mjs"].includes(extname(implementation))
    ? process.execPath
    : implementation;
  const args = command === process.execPath ? [implementation, ...arguments_] : arguments_;
  const payload = JSON.stringify({
    command,
    args,
    input: Buffer.from(input).toString("base64"),
    timeoutMs,
    maxBytes,
    environment,
  });
  const supervised = spawnSync(process.execPath, [supervisor], {
    encoding: "utf8",
    input: payload,
    killSignal: "SIGKILL",
    maxBuffer: maxBytes + 1024 * 1024,
    timeout: timeoutMs + 10_000,
  });
  if (supervised.error) throw supervised.error;
  if (supervised.status !== 0) {
    throw new Error(supervised.stderr || "candidate process supervisor failed");
  }
  const result = JSON.parse(supervised.stdout);
  if (result.bound === "timeout") {
    throw new Error(`candidate command ${arguments_.join(" ")} timed out after ${timeoutMs} ms`);
  }
  if (result.bound === "output") throw new Error(`candidate command exceeded ${maxBytes} bytes`);
  if (result.error) throw Object.assign(new Error(result.error.message), { code: result.error.code });
  return result;
}

function parseJsonOutput(result, stream) {
  const text = result[stream];
  assert.ok(text, `${stream} contains one JSON document`);
  return JSON.parse(text);
}

function successJson(implementation, arguments_, input, definition, environment) {
  const result = execute(implementation, arguments_, input, environment);
  assert.equal(result.status, 0, result.stderr || result.stdout);
  assert.equal(result.stderr, "", "successful commands leave stderr empty");
  const value = parseJsonOutput(result, "stdout");
  assertChangeSetSchema(value, schema, definition);
  return value;
}

function attentionJson(implementation, arguments_, input, expectedCode) {
  const result = execute(implementation, arguments_, input);
  assert.equal(result.status, 1, result.stderr || result.stdout);
  assert.equal(result.stderr, "", "attention results leave stderr empty");
  const value = parseJsonOutput(result, "stdout");
  assertChangeSetSchema(value, schema, "changeSetAttention");
  assert.equal(value.attention.code, expectedCode);
  return value;
}

function assertNoScopedLeak(value, label) {
  const encoded = JSON.stringify(value);
  for (const forbidden of [PRIVATE_MARKER, "private/sibling.txt", "private\\sibling.txt"]) {
    assert.ok(!encoded.includes(forbidden), `${label} leaked ${forbidden}`);
  }
  function visit(node, path) {
    if (Array.isArray(node)) return node.forEach((child, index) => visit(child, `${path}[${index}]`));
    if (node === null || typeof node !== "object") return;
    for (const [key, child] of Object.entries(node)) {
      assert.doesNotMatch(
        key,
        /(?:^|_)(?:local_head|remote_head|head_version|credential|access_token|storage_key|provider_location)(?:$|_)/u,
        `${label} exposes forbidden authority field at ${path}.${key}`,
      );
      visit(child, `${path}.${key}`);
    }
  }
  visit(value, label);
}

function resolveBeneath(root, portablePath) {
  assert.equal(typeof portablePath, "string");
  assert.ok(portablePath && !portablePath.startsWith("/") && !portablePath.includes("\\"));
  const target = resolve(root, ...portablePath.split("/"));
  assert.ok(target === root || target.startsWith(`${root}${sep}`), `path escapes root: ${portablePath}`);
  return target;
}

async function applyOperation(root, operation) {
  if (operation.operation === "rename") {
    const destination = resolveBeneath(root, operation.to);
    await mkdir(dirname(destination), { recursive: true });
    await rename(resolveBeneath(root, operation.from), destination);
    return;
  }
  const path = resolveBeneath(root, operation.path);
  if (operation.operation === "delete") {
    await rm(path, { force: true, recursive: true });
    return;
  }
  if (operation.operation === "nested_folderbase") {
    await mkdir(join(path, ".folderbase"), { recursive: true });
    await writeFile(
      join(path, ".folderbase", "manifest.json"),
      `${JSON.stringify({
        $schema: "https://folderbase.ai/protocol/0.5/folderbase.schema.json",
        protocol_version: "0.5.0",
        folderbase: {
          id: "folderbase_019f0000-0000-7000-8000-000000000099",
          name: "Opaque nested boundary",
          kind: "project",
          status: "active",
          created_at: "2026-08-04T00:00:00Z",
        },
        adapters: [],
        policies: {
          availability: "keep_local",
          structural_changes: "approve",
          archive: "manual",
          cloud_sync: "disabled",
          capture_ignore: { format: "folderbase-capture-ignore-v1", rules: [] },
        },
      }, null, 2)}\n`,
    );
    await writeFile(join(path, "nested-secret.txt"), "nested authority\n");
    return;
  }
  await mkdir(dirname(path), { recursive: true });
  if (operation.operation === "write_utf8") {
    await writeFile(path, operation.content, "utf8");
    return;
  }
  if (operation.operation === "write_base64") {
    await writeFile(path, Buffer.from(operation.content_base64, "base64"));
    return;
  }
  if (operation.operation === "sparse") {
    const descriptor = await open(path, "w+");
    try {
      await descriptor.truncate(operation.bytes);
      for (const patch of operation.patches ?? []) {
        const bytes = Buffer.from(patch.content_base64, "base64");
        await descriptor.write(bytes, 0, bytes.length, patch.offset);
      }
      await descriptor.sync();
    } finally {
      await descriptor.close();
    }
    return;
  }
  throw new Error(`unsupported fixture operation ${operation.operation}`);
}

async function applyOperations(root, operations = []) {
  for (const operation of operations) await applyOperation(root, operation);
}

async function sha256File(path) {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(path)) hash.update(chunk);
  return hash.digest("hex");
}

async function boundedFileIdentity(path, metadata) {
  if (metadata.size <= 1024 * 1024) return { sha256: await sha256File(path) };
  const descriptor = await open(path, "r");
  try {
    const head = Buffer.alloc(4096);
    const tail = Buffer.alloc(4096);
    const headResult = await descriptor.read(head, 0, head.length, 0);
    const tailOffset = Math.max(0, metadata.size - tail.length);
    const tailResult = await descriptor.read(tail, 0, tail.length, tailOffset);
    return {
      head_sha256: createHash("sha256").update(head.subarray(0, headResult.bytesRead)).digest("hex"),
      tail_sha256: createHash("sha256").update(tail.subarray(0, tailResult.bytesRead)).digest("hex"),
    };
  } finally {
    await descriptor.close();
  }
}

async function treeSnapshot(root, include) {
  const records = [];
  async function visit(absolute, portable) {
    const names = await readdir(absolute);
    names.sort((left, right) => Buffer.compare(Buffer.from(left), Buffer.from(right)));
    for (const name of names) {
      const childPortable = portable ? `${portable}/${name}` : name;
      if (!include(childPortable)) continue;
      const child = join(absolute, name);
      const metadata = await lstat(child);
      if (metadata.isDirectory()) {
        records.push({ path: childPortable, kind: "directory", mode: metadata.mode });
        await visit(child, childPortable);
      } else if (metadata.isSymbolicLink()) {
        records.push({ path: childPortable, kind: "symlink", target: await readlink(child) });
      } else if (metadata.isFile()) {
        records.push({
          path: childPortable,
          kind: "regular_file",
          mode: metadata.mode,
          bytes: metadata.size,
          ...(await boundedFileIdentity(child, metadata)),
        });
      } else {
        records.push({ path: childPortable, kind: "unsupported" });
      }
    }
  }
  await visit(root, "");
  return records;
}

function includeOutOfScope(path) {
  return path !== ".folderbase" &&
    !path.startsWith(".folderbase/") &&
    path !== "shared" &&
    !path.startsWith("shared/");
}

function includeCheckoutOrdinary(path) {
  return path !== ".folderbase" && !path.startsWith(".folderbase/");
}

function u32(parts, value) {
  const bytes = Buffer.alloc(4);
  bytes.writeUInt32BE(value);
  parts.push(bytes);
}

function u64(parts, value) {
  assert.ok(Number.isSafeInteger(value) && value >= 0);
  const bytes = Buffer.alloc(8);
  bytes.writeBigUInt64BE(BigInt(value));
  parts.push(bytes);
}

function identifier(parts, value) {
  const bytes = Buffer.from(value, "utf8");
  u32(parts, bytes.length);
  parts.push(bytes);
}

function hexDigest(parts, value) {
  assert.match(value, /^[0-9a-f]{64}$/u);
  parts.push(Buffer.from(value, "hex"));
}

function chunkManifestDigest(manifest) {
  const parts = [Buffer.from("folderbase-chunk-manifest-v1\0", "ascii")];
  identifier(parts, manifest.algorithm);
  identifier(parts, manifest.profile);
  u64(parts, manifest.minimum_chunk_bytes);
  u64(parts, manifest.average_chunk_bytes);
  u64(parts, manifest.maximum_chunk_bytes);
  hexDigest(parts, manifest.object_sha256);
  u64(parts, manifest.object_bytes);
  u32(parts, manifest.chunks.length);
  for (const chunk of manifest.chunks) {
    u32(parts, chunk.index);
    u64(parts, chunk.offset);
    u64(parts, chunk.bytes);
    hexDigest(parts, chunk.sha256);
  }
  return createHash("sha256").update(Buffer.concat(parts)).digest("hex");
}

async function verifyStaging(staging, envelope) {
  const index = JSON.parse(await readFile(join(staging, "index.json"), "utf8"));
  assertChangeSetSchema(index, schema, "stagingIndex");
  const sorted = [...index.objects].sort((left, right) =>
    Buffer.compare(Buffer.from(left.staging_id), Buffer.from(right.staging_id)));
  assert.deepEqual(index.objects, sorted, "staging objects are byte-sorted by staging ID");
  const expectedReferences = [];
  for (const delta of envelope.payload.deltas) {
    for (const state of [delta.before, delta.after]) {
      if (state?.kind === "regular_file" && state.content.source === "staged") {
        expectedReferences.push({
          staging_id: state.content.staging_id,
          chunk_manifest_sha256: state.content.chunk_manifest_sha256,
        });
      }
    }
  }
  expectedReferences.sort((left, right) =>
    Buffer.compare(Buffer.from(left.staging_id), Buffer.from(right.staging_id)));
  assert.deepEqual(index.objects, expectedReferences, "staging index exactly covers staged references");

  const expectedFiles = new Set(["index.json"]);
  for (const object of index.objects) {
    const manifestRelative = `manifests/${object.chunk_manifest_sha256}.json`;
    expectedFiles.add(manifestRelative);
    const manifest = JSON.parse(await readFile(join(staging, manifestRelative), "utf8"));
    assert.equal(chunkManifestDigest(manifest), object.chunk_manifest_sha256);
    let offset = 0;
    const objectHash = createHash("sha256");
    for (const [index_, chunk] of manifest.chunks.entries()) {
      assert.equal(chunk.index, index_);
      assert.equal(chunk.offset, offset);
      const chunkRelative = `chunks/${chunk.sha256}`;
      expectedFiles.add(chunkRelative);
      const chunkPath = join(staging, chunkRelative);
      const metadata = await lstat(chunkPath);
      assert.ok(metadata.isFile() && !metadata.isSymbolicLink(), `${chunkRelative} is a regular file`);
      assert.equal(metadata.size, chunk.bytes);
      assert.equal(await sha256File(chunkPath), chunk.sha256);
      for await (const bytes of createReadStream(chunkPath)) objectHash.update(bytes);
      offset += chunk.bytes;
    }
    assert.equal(offset, manifest.object_bytes);
    assert.equal(objectHash.digest("hex"), manifest.object_sha256);
  }

  const actualFiles = new Set();
  async function visit(absolute, portable) {
    for (const name of await readdir(absolute)) {
      const childPortable = portable ? `${portable}/${name}` : name;
      const child = join(absolute, name);
      const metadata = await lstat(child);
      assert.ok(!metadata.isSymbolicLink(), `staging symlink is forbidden: ${childPortable}`);
      if (metadata.isDirectory()) await visit(child, childPortable);
      else {
        assert.ok(metadata.isFile(), `staging special node is forbidden: ${childPortable}`);
        actualFiles.add(childPortable);
      }
    }
  }
  await visit(staging, "");
  assert.deepEqual(actualFiles, expectedFiles, "staging has no aliases or extra files");
}

function validateEnvelope(envelope) {
  assertChangeSetSchema(envelope, schema, "changeSetEnvelope");
  assert.equal(changeSetSha256(envelope.payload), envelope.change_set_sha256);
  assert.deepEqual(envelope.payload.authorized_paths, [{ path_prefix: "shared" }]);
  const objectIds = envelope.payload.deltas.map(({ object_id }) => object_id);
  assert.equal(new Set(objectIds).size, objectIds.length, "one final-state delta per object");
  assert.deepEqual(
    objectIds,
    [...objectIds].sort((left, right) => Buffer.compare(Buffer.from(left), Buffer.from(right))),
    "deltas are byte-sorted by Object ID",
  );
  for (const delta of envelope.payload.deltas) {
    assert.ok(delta.before !== null || delta.after !== null);
    assert.notDeepEqual(delta.before, delta.after);
    for (const state of [delta.before, delta.after]) {
      if (state) assert.ok(state.path === "shared" || state.path.startsWith("shared/"));
    }
    if (delta.before === null && delta.after?.kind === "regular_file") {
      assert.equal(delta.after.content.source, "staged", "created bytes are staged");
    }
  }
  assertNoScopedLeak(envelope, "Change Set");
}

function assertScenarioEnvelope(scenario, envelope) {
  const deltas = envelope.payload.deltas;
  if (scenario.name === "move-and-edit") {
    assert.equal(deltas.length, 1, "move plus edit is one before/after delta");
    assert.equal(deltas[0].before.path, "shared/notes.md");
    assert.equal(deltas[0].after.path, "shared/final.md");
    assert.notEqual(deltas[0].before.content_sha256, deltas[0].after.content_sha256);
    assert.equal(deltas[0].after.content.source, "staged");
  }
  if (scenario.name === "rename") {
    assert.equal(deltas.length, 1, "rename is one stable-object delta");
    assert.equal(deltas[0].before.path, "shared/draft.txt");
    assert.equal(deltas[0].after.path, "shared/approved.txt");
    assert.equal(deltas[0].before.object_version_id, deltas[0].after.object_version_id);
    assert.equal(deltas[0].before.content_sha256, deltas[0].after.content_sha256);
    assert.equal(deltas[0].after.content.source, "projection_base");
  }
  if (scenario.name === "binary-and-large-object") {
    const binary = deltas.find(({ before }) => before?.path === "shared/data.sqlite");
    const large = deltas.find(({ before }) => before?.path === "shared/movie.mov");
    assert.equal(binary.after.content.source, "staged");
    assert.equal(large.after.path, "shared/movie-final.mov");
    assert.equal(large.after.bytes, 67_108_865);
    assert.equal(large.after.content.source, "projection_base");
  }
}

async function assertScenarioResults(root, assertions = []) {
  for (const expectation of assertions) {
    const path = resolveBeneath(root, expectation.path);
    if (expectation.kind === "absent") {
      await assert.rejects(access(path));
    } else if (expectation.kind === "utf8") {
      assert.equal(await readFile(path, "utf8"), expectation.content);
    } else if (expectation.kind === "sha256") {
      assert.equal(await sha256File(path), expectation.sha256);
    } else if (expectation.kind === "bytes") {
      assert.equal((await stat(path)).size, expectation.bytes);
    } else {
      throw new Error(`unknown assertion kind ${expectation.kind}`);
    }
  }
}

async function readFolderbaseVersion(root, versionId) {
  assert.match(versionId, /^fbversion_[0-9a-f-]+$/u);
  return JSON.parse(
    await readFile(join(root, ".folderbase", "versions", "folderbase", `${versionId}.json`), "utf8"),
  );
}

async function immutableVersionSnapshot(root) {
  return (await readdir(join(root, ".folderbase", "versions", "folderbase")))
    .filter((name) => name.endsWith(".json"))
    .sort();
}

async function assertChangeSetHistory(root, scenario, envelope) {
  const head = JSON.parse(await readFile(join(root, ".folderbase", "local", "head.json"), "utf8"));
  const version = await readFolderbaseVersion(root, head.version_id);
  assert.equal(version.version_id, head.version_id);
  assert.equal(version.folderbase_id, envelope.payload.folderbase_id);

  if (scenario.name === "clean-disjoint") {
    assert.equal(version.parents.length, 2, "disjoint work produces a real two-parent merge");
    const current = await readFolderbaseVersion(root, version.parents[0]);
    const proposal = await readFolderbaseVersion(root, version.parents[1]);
    assert.ok(current.bindings.some(({ path }) => path === "shared/source-only.md"));
    assert.ok(!proposal.bindings.some(({ path }) => path === "shared/source-only.md"));
    assert.equal(proposal.parents.length, 1, "proposal is pinned to one projection base");
  } else {
    assert.equal(version.parents.length, 1, "non-divergent apply publishes the proposal Version");
  }

  for (const delta of envelope.payload.deltas) {
    if (delta.after === null) {
      assert.ok(!version.bindings.some(({ object_id }) => object_id === delta.object_id));
      assert.ok(version.tombstones.some(({ object_id }) => object_id === delta.object_id));
      continue;
    }
    const binding = version.bindings.find(({ path }) => path === delta.after.path);
    assert.ok(binding, `history contains ${delta.after.path}`);
    assert.equal(binding.object_id, delta.object_id, "history retains Change Set Object identity");
    if (delta.after.kind !== "directory") {
      assert.equal(
        binding.object_version_id,
        delta.after.object_version_id,
        "history retains the exact Change Set Object Version",
      );
    }
  }
}

async function readScenarios() {
  const selected = process.env.FOLDERBASE_CHANGE_SET_CONFORMANCE_SCENARIO;
  const names = (await readdir(scenarioDirectory))
    .filter((name) => name.endsWith(".json"))
    .filter((name) => selected === undefined || name === selected)
    .sort();
  if (selected !== undefined && names.length !== 1) {
    throw new Error(`unknown Change Set conformance scenario ${selected}`);
  }
  return Promise.all(names.map(async (name) => JSON.parse(await readFile(join(scenarioDirectory, name), "utf8"))));
}

async function runScenario(implementation, scenario, index) {
  assert.equal(scenario.format, "folderbase-change-set-conformance-scenario-v1");
  const owner = await mkdtemp(join(tmpdir(), "folderbase-change-set-0.1-"));
  try {
    const root = join(owner, "source");
    const checkout = join(owner, "checkout");
    const staging = join(owner, "staging");
    await mkdir(join(root, "shared"), { recursive: true });
    await mkdir(join(root, "private"), { recursive: true });
    await writeFile(join(root, "shared", "notes.md"), "base notes\n");
    await writeFile(join(root, "private", "sibling.txt"), `${PRIVATE_MARKER}\n`);
    await applyOperations(root, scenario.initial);

    const initialized = execute(implementation, ["init", root, "--json"]);
    assert.equal(initialized.status, 0, initialized.stderr || initialized.stdout);
    const manifest = JSON.parse(await readFile(join(root, ".folderbase", "manifest.json"), "utf8"));
    const folderbaseId = manifest.folderbase.id;
    const suffix = String(index + 1).padStart(12, "0");
    const projectionId = `projection_019f0000-0000-7000-8000-${suffix}`;
    const request = {
      format: "folderbase-checkout-request-v1",
      folderbase_id: folderbaseId,
      projection_id: projectionId,
      folder_scope_id: "folderscope_019f0000-0000-7000-8000-000000000001",
      scope_revision_sha256: "1111111111111111111111111111111111111111111111111111111111111111",
      permission: "can_work",
      authorized_paths: [{ path_prefix: "shared" }],
    };
    assertChangeSetSchema(request, schema, "checkoutRequest");
    const checkoutResult = successJson(
      implementation,
      ["change-set", "checkout", root, checkout, "--stdin", "--json"],
      `${JSON.stringify(request)}\n`,
      "checkoutResult",
    );
    assertNoScopedLeak(checkoutResult, "checkout result");
    const receipt = JSON.parse(await readFile(join(checkout, ".folderbase", "checkout.json"), "utf8"));
    assertChangeSetSchema(receipt, schema, "checkoutReceipt");
    assertNoScopedLeak(receipt, "checkout receipt");
    assert.equal(receipt.projection_id, projectionId);
    assert.equal(receipt.projection_base_sha256, checkoutResult.projection_base_sha256);
    await assert.rejects(access(join(checkout, ".folderbase", "manifest.json")));
    await assert.rejects(access(join(checkout, "private")));

    await applyOperations(checkout, scenario.checkout_changes);
    await applyOperations(root, scenario.concurrent_source_changes);
    const outOfScopeBefore = await treeSnapshot(root, includeOutOfScope);
    const checkoutOrdinaryBefore = await treeSnapshot(checkout, includeCheckoutOrdinary);
    const envelope = successJson(
      implementation,
      ["change-set", "propose", checkout, staging, "--json"],
      "",
      "changeSetEnvelope",
    );
    validateEnvelope(envelope);
    assertScenarioEnvelope(scenario, envelope);
    assert.deepEqual(await treeSnapshot(checkout, includeCheckoutOrdinary), checkoutOrdinaryBefore);
    await verifyStaging(staging, envelope);

    let assessedEnvelope = envelope;
    if (scenario.before_assess === "replace_projection_id_with_unknown") {
      assessedEnvelope = structuredClone(envelope);
      assessedEnvelope.payload.projection_id = "projection_019f0000-0000-7000-8000-000000000099";
      assessedEnvelope.change_set_sha256 = changeSetSha256(assessedEnvelope.payload);
      validateEnvelope(assessedEnvelope);
    }
    const input = `${JSON.stringify(assessedEnvelope)}\n`;

    if (scenario.expected.outcome === "conflict") {
      const attention = attentionJson(
        implementation,
        ["change-set", "assess", root, staging, "--stdin", "--json"],
        input,
        "change_set_conflicted",
      );
      assert.ok(attention.attention.conflicts.some(({ code }) => code === scenario.expected.conflict_code));
      assertNoScopedLeak(attention, "conflict attention");
      assert.deepEqual(await treeSnapshot(root, includeOutOfScope), outOfScopeBefore);
      return;
    }
    if (scenario.expected.outcome === "attention") {
      const attention = attentionJson(
        implementation,
        ["change-set", "assess", root, staging, "--stdin", "--json"],
        input,
        scenario.expected.attention_code,
      );
      assertNoScopedLeak(attention, "retryable attention");
      assert.deepEqual(await treeSnapshot(root, includeOutOfScope), outOfScopeBefore);
      return;
    }

    const assessed = successJson(
      implementation,
      ["change-set", "assess", root, staging, "--stdin", "--json"],
      input,
      "changeSetAssessment",
    );
    assert.equal(assessed.change_set_sha256, envelope.change_set_sha256);
    assertNoScopedLeak(assessed, "assessment");
    assert.deepEqual(await treeSnapshot(root, includeOutOfScope), outOfScopeBefore);

    let historyHeadSnapshot;
    for (const crashPoint of scenario.crash_sequence ?? []) {
      const crashed = execute(
        implementation,
        ["change-set", "apply", root, staging, "--stdin", "--json"],
        input,
        { FOLDERBASE_CHANGE_SET_CONFORMANCE_CRASH_AFTER: crashPoint },
      );
      assert.notEqual(crashed.status, 0, `conformance crash hook terminates at ${crashPoint}`);
      if (crashPoint === "history-head") {
        historyHeadSnapshot = await immutableVersionSnapshot(root);
      }
    }

    const applied = successJson(
      implementation,
      ["change-set", "apply", root, staging, "--stdin", "--json"],
      input,
      "changeSetApplyResult",
    );
    assert.equal(applied.status, "applied");
    assert.equal(applied.change_set_sha256, envelope.change_set_sha256);
    assertNoScopedLeak(applied, "apply result");
    assert.deepEqual(await treeSnapshot(root, includeOutOfScope), outOfScopeBefore);
    await assertScenarioResults(root, scenario.expected.assertions);
    await assertChangeSetHistory(root, scenario, envelope);
    const versionsBeforeReplay = await immutableVersionSnapshot(root);
    if (historyHeadSnapshot !== undefined) {
      assert.deepEqual(
        versionsBeforeReplay,
        historyHeadSnapshot,
        "restart after publishing history Head installs no additional immutable Versions",
      );
    }

    const replayed = successJson(
      implementation,
      ["change-set", "apply", root, staging, "--stdin", "--json"],
      input,
      "changeSetApplyResult",
    );
    assert.equal(replayed.status, "already_applied");
    assert.equal(replayed.projection_result_sha256, applied.projection_result_sha256);
    assert.deepEqual(await treeSnapshot(root, includeOutOfScope), outOfScopeBefore);
    assert.deepEqual(
      await immutableVersionSnapshot(root),
      versionsBeforeReplay,
      "idempotent replay installs no additional immutable Versions",
    );
  } finally {
    await rm(owner, { force: true, recursive: true });
  }
}

async function main() {
  const implementation = implementationArgument(process.argv.slice(2));
  const scenarios = await readScenarios();
  const cases = [];
  for (const [index, scenario] of scenarios.entries()) {
    try {
      await runScenario(implementation, scenario, index);
      cases.push({ name: scenario.name, status: "passed", covers: scenario.covers });
    } catch (error) {
      cases.push({
        name: scenario.name,
        status: "failed",
        covers: scenario.covers,
        message: error instanceof Error ? error.message : String(error),
      });
    }
  }
  const failed = cases.filter(({ status }) => status === "failed").length;
  process.stdout.write(`${JSON.stringify({
    format: REPORT_FORMAT,
    capability: CAPABILITY,
    total: cases.length,
    passed: cases.length - failed,
    failed,
    cases,
  })}\n`);
  process.exitCode = failed === 0 ? 0 : 1;
}

main().catch((error) => {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 2;
});

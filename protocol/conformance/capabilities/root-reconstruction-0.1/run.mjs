#!/usr/bin/env node

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  appendFile,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  readlink,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, extname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { writeCanonicalFixture } from "./fixture-generator.mjs";
import {
  canonicalFolderbaseVersionSha256,
  chunkManifestSha256,
  encodedSha256,
  rootReconstructionRequestSha256,
} from "./reference-digests.mjs";
import {
  assertJsonSchema,
  assertRootReconstructionSchema,
} from "./schema.mjs";

const CAPABILITY = "folderbase.root-reconstruction@0.1.0";
const REPORT_FORMAT = "folderbase-capability-suite-report-v1";
const DEFAULT_COMMAND_TIMEOUT_MS = 30_000;
const MAXIMUM_COMMAND_TIMEOUT_MS = 120_000;
const DEFAULT_COMMAND_MAX_BYTES = 8 * 1024 * 1024;
const MAXIMUM_COMMAND_MAX_BYTES = 16 * 1024 * 1024;
const directory = dirname(fileURLToPath(import.meta.url));
const supervisor = join(directory, "command-supervisor.mjs");
const scenariosPath = join(directory, "fixtures", "scenarios.json");
const schema = JSON.parse(
  await readFile(
    resolve(
      directory,
      "../../../schemas/capabilities/root-reconstruction/0.1/root-reconstruction.schema.json",
    ),
    "utf8",
  ),
);
const versionSchemas = new Map(await Promise.all(["0.4", "0.5"].map(async (version) => [
  version,
  JSON.parse(await readFile(
    resolve(directory, `../../../schemas/${version}/folderbase-version.schema.json`),
    "utf8",
  )),
])));
const chunkManifestSchema = JSON.parse(
  await readFile(
    resolve(directory, "../../../schemas/0.3/chunk-manifest.schema.json"),
    "utf8",
  ),
);

function implementationArgument(argv) {
  const flag = argv.indexOf("--implementation");
  if (flag === -1 || !argv[flag + 1] || argv.length !== 2) {
    throw new Error("usage: run.mjs --implementation /path/to/folderbase");
  }
  if (argv[flag + 1].includes("\u0000")) throw new Error("implementation path contains NUL");
  return resolve(argv[flag + 1]);
}

function configuredInteger(name, fallback, maximum) {
  const value = process.env[name];
  if (value === undefined) return fallback;
  const number = Number(value);
  if (
    !/^[1-9][0-9]*$/u.test(value)
    || !Number.isSafeInteger(number)
    || number > maximum
  ) throw new Error(`${name} must be a positive integer no greater than ${maximum}`);
  return number;
}

function commandFor(implementation, arguments_) {
  return [".js", ".cjs", ".mjs"].includes(extname(implementation))
    ? { command: process.execPath, args: [implementation, ...arguments_] }
    : { command: implementation, args: arguments_ };
}

function execute(implementation, arguments_, input, environment, limits) {
  const invocation = commandFor(implementation, arguments_);
  const supervised = spawnSync(process.execPath, [supervisor], {
    encoding: "utf8",
    input: JSON.stringify({
      command: invocation.command,
      args: invocation.args,
      input: Buffer.from(input).toString("base64"),
      timeoutMs: limits.timeoutMs,
      maxBytes: limits.maxBytes,
      environment,
    }),
    shell: false,
    windowsHide: true,
    maxBuffer: limits.maxBytes + 1024 * 1024,
    timeout: limits.timeoutMs + 10_000,
    killSignal: "SIGKILL",
  });
  if (supervised.error) throw supervised.error;
  assert.equal(supervised.status, 0, supervised.stderr || "candidate supervisor failed");
  const result = JSON.parse(supervised.stdout);
  if (result.bound === "timeout") {
    throw new Error(`candidate command ${arguments_.join(" ")} timed out`);
  }
  if (result.bound === "output") {
    throw new Error(`candidate command ${arguments_.join(" ")} exceeded output bound`);
  }
  if (result.error) {
    throw Object.assign(new Error(result.error.message), { code: result.error.code });
  }
  return result;
}

function requestInput(request) {
  return `${JSON.stringify(request)}\n`;
}

function reconstructArguments(source, destination) {
  return ["reconstruct", source, destination, "--stdin", "--json"];
}

function successJson(implementation, source, destination, request, limits, environment = {}) {
  const result = execute(
    implementation,
    reconstructArguments(source, destination),
    requestInput(request),
    environment,
    limits,
  );
  assert.equal(result.status, 0, result.stderr || result.stdout);
  assert.equal(result.stderr, "", "successful reconstruction leaves stderr empty");
  const document = JSON.parse(result.stdout);
  assertRootReconstructionSchema(document, schema, "result");
  return document;
}

function errorJson(
  implementation,
  source,
  destination,
  request,
  expectedCode,
  limits,
  environment = {},
) {
  const result = execute(
    implementation,
    reconstructArguments(source, destination),
    requestInput(request),
    environment,
    limits,
  );
  assert.equal(result.status, 2, result.stderr || result.stdout);
  assert.equal(result.stdout, "", "root-reconstruction error leaves stdout empty");
  const document = JSON.parse(result.stderr);
  assertRootReconstructionSchema(document, schema, "error");
  assert.equal(document.error.code, expectedCode);
  return document;
}

function attentionJson(
  implementation,
  source,
  destination,
  request,
  expectedCode,
  limits,
) {
  const result = execute(
    implementation,
    reconstructArguments(source, destination),
    requestInput(request),
    {},
    limits,
  );
  assert.equal(result.status, 1, result.stderr || result.stdout);
  assert.equal(result.stderr, "", "root-reconstruction attention leaves stderr empty");
  const document = JSON.parse(result.stdout);
  assertRootReconstructionSchema(document, schema, "attention");
  assert.equal(document.attention.code, expectedCode);
  return document;
}

async function assertRegular(path, label) {
  const metadata = await lstat(path);
  assert.equal(metadata.isFile(), true, `${label} must be a no-follow regular file`);
  assert.equal(metadata.isSymbolicLink(), false, `${label} must not be a symlink`);
}

async function assertDirectory(path, label) {
  const metadata = await lstat(path);
  assert.equal(metadata.isDirectory(), true, `${label} must be a no-follow directory`);
  assert.equal(metadata.isSymbolicLink(), false, `${label} must not be a symlink`);
}

async function assertMissing(path, label) {
  await assert.rejects(lstat(path), (error) => {
    assert.equal(error?.code, "ENOENT", label);
    return true;
  });
}

async function verifyPackage(source, fixture) {
  assert.deepEqual((await readdir(source)).sort(), [
    "chunks",
    "index.json",
    "manifests",
    "version.json",
  ]);
  await Promise.all([
    assertRegular(join(source, "index.json"), "index.json"),
    assertRegular(join(source, "version.json"), "version.json"),
    assertDirectory(join(source, "manifests"), "manifests"),
    assertDirectory(join(source, "chunks"), "chunks"),
  ]);
  const indexBytes = await readFile(join(source, "index.json"));
  assert.equal(encodedSha256(indexBytes), fixture.request.package_index_sha256);
  const index = JSON.parse(indexBytes);
  assertRootReconstructionSchema(index, schema, "packageIndex");
  const versionBytes = await readFile(join(source, "version.json"));
  assert.equal(encodedSha256(versionBytes), index.encoded_version_sha256);
  const version = JSON.parse(versionBytes);
  const versionSchema = versionSchemas.get(version.protocol_version);
  assert.ok(versionSchema, `unsupported fixture protocol ${version.protocol_version}`);
  assertJsonSchema(version, versionSchema, "folderbaseVersion");
  assert.equal(canonicalFolderbaseVersionSha256(version), index.canonical_version_sha256);
  assert.equal(version.folderbase_id, index.folderbase_id);
  assert.equal(version.version_id, index.folderbase_version_id);

  const objectBytes = new Map();
  const expectedManifests = new Set();
  const expectedChunks = new Set();
  for (const reference of index.references) {
    const manifestName = `${reference.chunk_manifest_sha256}.json`;
    expectedManifests.add(manifestName);
    const manifestPath = join(source, "manifests", manifestName);
    await assertRegular(manifestPath, manifestName);
    const manifest = JSON.parse(await readFile(manifestPath));
    assertJsonSchema(manifest, chunkManifestSchema, "chunkManifest");
    assert.equal(chunkManifestSha256(manifest), reference.chunk_manifest_sha256);
    const chunks = [];
    let offset = 0;
    for (const descriptor of manifest.chunks) {
      assert.equal(descriptor.index, chunks.length);
      assert.equal(descriptor.offset, offset);
      expectedChunks.add(descriptor.sha256);
      const chunkPath = join(source, "chunks", descriptor.sha256);
      await assertRegular(chunkPath, `chunk ${descriptor.sha256}`);
      const bytes = await readFile(chunkPath);
      assert.equal(bytes.length, descriptor.bytes);
      assert.equal(encodedSha256(bytes), descriptor.sha256);
      chunks.push(bytes);
      offset += bytes.length;
    }
    const object = Buffer.concat(chunks);
    assert.equal(object.length, manifest.object_bytes);
    assert.equal(encodedSha256(object), manifest.object_sha256);
    objectBytes.set(reference.object_version_id, object);
  }
  assert.deepEqual((await readdir(join(source, "manifests"))).sort(), [...expectedManifests].sort());
  assert.deepEqual((await readdir(join(source, "chunks"))).sort(), [...expectedChunks].sort());

  const required = new Map([[version.root_manifest.object_version_id, new Set(["root_manifest"])]]);
  for (const binding of version.bindings.filter(({ kind }) => kind === "regular_file")) {
    required.set(
      binding.object_version_id,
      new Set([...(required.get(binding.object_version_id) ?? []), "live_regular_file"]),
    );
  }
  for (const tombstone of version.tombstones) {
    if (tombstone.last_object_version_id !== null) {
      required.set(
        tombstone.last_object_version_id,
        new Set([...(required.get(tombstone.last_object_version_id) ?? []), "retained_tombstone"]),
      );
    }
  }
  assert.deepEqual(
    index.references.map(({ object_version_id, roles }) => [object_version_id, roles]),
    [...required].sort(([left], [right]) => Buffer.compare(Buffer.from(left), Buffer.from(right)))
      .map(([objectVersionId, roles]) => [objectVersionId, [...roles].sort()]),
  );
  return { index, version, objectBytes };
}

function assertResult(document, fixture, destination) {
  for (const [field, expected] of Object.entries(fixture.expected)) {
    if (field !== "encoded_version_sha256") assert.equal(document[field], expected, field);
  }
  assert.equal(document.operation_id, fixture.request.operation_id);
  assert.equal(
    document.request_sha256,
    rootReconstructionRequestSha256(fixture.request),
  );
  assert.equal(resolve(document.root_attestation.root), resolve(destination));
  assert.equal(document.root_attestation.folderbase_id, fixture.expected.folderbase_id);
}

async function verifyReconstructedRoot(
  implementation,
  destination,
  package_,
  fixture,
  result,
  limits,
) {
  assertResult(result, fixture, destination);
  const rootReference = package_.index.references.find(({ roles }) =>
    roles.includes("root_manifest"));
  assert.deepEqual(
    await readFile(join(destination, ".folderbase", "manifest.json")),
    package_.objectBytes.get(rootReference.object_version_id),
  );
  for (const binding of package_.version.bindings) {
    const path = join(destination, ...binding.path.split("/"));
    if (binding.kind === "directory") await assertDirectory(path, binding.path);
    else if (binding.kind === "regular_file") {
      await assertRegular(path, binding.path);
      assert.deepEqual(await readFile(path), package_.objectBytes.get(binding.object_version_id));
      if (process.platform !== "win32") {
        const mode = (await lstat(path)).mode & 0o111;
        assert.equal(mode !== 0, binding.executable, `${binding.path} executable fidelity`);
      }
    } else {
      const metadata = await lstat(path);
      assert.equal(metadata.isSymbolicLink(), true, `${binding.path} must be a symlink`);
      assert.equal(await readlink(path), binding.target);
    }
  }
  for (const tombstone of package_.version.tombstones) {
    await assertMissing(join(destination, ...tombstone.path.split("/")), tombstone.path);
  }
  for (const exclusion of package_.version.exclusions) {
    await assertMissing(join(destination, ...exclusion.path.split("/")), exclusion.path);
  }

  const retained = package_.version.tombstones.find(({ path }) => path.startsWith("deleted/"));
  const restoredPath = "Restored/approved-proposal.docx";
  const restored = execute(
    implementation,
    ["version", "restore", destination, retained.last_object_version_id, restoredPath, "--json"],
    "",
    {},
    limits,
  );
  assert.equal(restored.status, 0, restored.stderr || restored.stdout);
  assert.equal(restored.stderr, "");
  assert.deepEqual(
    await readFile(join(destination, ...restoredPath.split("/"))),
    package_.objectBytes.get(retained.last_object_version_id),
  );
}

async function prepare(caseRoot) {
  await mkdir(caseRoot, { recursive: true });
  const source = join(caseRoot, "source");
  const destinationParent = join(caseRoot, "destination-parent");
  await Promise.all([mkdir(source), mkdir(destinationParent)]);
  const fixture = await writeCanonicalFixture(source);
  const destination = join(destinationParent, "Reconstructed");
  return { source, destinationParent, destination, fixture };
}

async function directorySnapshot(path) {
  return Promise.all((await readdir(path)).sort().map(async (name) => {
    const metadata = await lstat(join(path, name));
    return [name, metadata.isFile(), metadata.isDirectory(), metadata.isSymbolicLink()];
  }));
}

async function runCase(implementation, scenario, caseRoot, limits) {
  if (scenario.id === "09-restart-convergence-and-replay") {
    for (const [crashPoint, published] of [
      ["prepared-journal", false],
      ["verified-staging", false],
      ["publication", true],
      ["completion-record", true],
    ]) {
      const context = await prepare(join(caseRoot, crashPoint));
      const crashed = execute(
        implementation,
        reconstructArguments(context.source, context.destination),
        requestInput(context.fixture.request),
        { FOLDERBASE_ROOT_RECONSTRUCTION_CONFORMANCE_CRASH_AFTER: crashPoint },
        limits,
      );
      assert.notEqual(crashed.status, 0, `conformance crash hook terminates at ${crashPoint}`);
      const recovered = successJson(
        implementation,
        context.source,
        context.destination,
        context.fixture.request,
        limits,
      );
      assert.equal(recovered.replayed, published, `${crashPoint} recovery replay classification`);
      const replayed = successJson(
        implementation,
        context.source,
        context.destination,
        context.fixture.request,
        limits,
      );
      assert.equal(replayed.replayed, true);
      for (const field of [
        "operation_id",
        "request_sha256",
        "folderbase_version_id",
        "canonical_version_sha256",
        "package_index_sha256",
      ]) assert.equal(replayed[field], recovered[field], `${crashPoint} ${field}`);
    }
    return;
  }

  const context = await prepare(caseRoot);
  if (scenario.id === "01-reconstruct-mixed-tree") {
    const package_ = await verifyPackage(context.source, context.fixture);
    const result = successJson(
      implementation,
      context.source,
      context.destination,
      context.fixture.request,
      limits,
    );
    assert.equal(result.replayed, false);
    await verifyReconstructedRoot(
      implementation,
      context.destination,
      package_,
      context.fixture,
      result,
      limits,
    );
    return;
  }
  if (scenario.id === "02-reject-wrong-package-index-pin") {
    const request = { ...context.fixture.request, package_index_sha256: "f".repeat(64) };
    errorJson(
      implementation,
      context.source,
      context.destination,
      request,
      "package_index_mismatch",
      limits,
    );
    return;
  }
  if (scenario.id === "03-reject-malformed-request") {
    const request = { ...context.fixture.request, provider_url: "https://provider.invalid/package" };
    errorJson(
      implementation,
      context.source,
      context.destination,
      request,
      "invalid_request",
      limits,
    );
    return;
  }
  if (scenario.id === "04-reject-changed-version") {
    await appendFile(join(context.source, "version.json"), "\n");
    errorJson(
      implementation,
      context.source,
      context.destination,
      context.fixture.request,
      "package_changed",
      limits,
    );
    return;
  }
  if (scenario.id === "05-reject-missing-retained-reference") {
    const index = structuredClone(context.fixture.index);
    const position = index.references.findIndex(({ roles }) =>
      roles.length === 1 && roles[0] === "retained_tombstone");
    assert.ok(position >= 0);
    index.references.splice(position, 1);
    const indexBytes = Buffer.from(`${JSON.stringify(index, null, 2)}\n`);
    await writeFile(join(context.source, "index.json"), indexBytes);
    const request = {
      ...context.fixture.request,
      package_index_sha256: encodedSha256(indexBytes),
    };
    errorJson(
      implementation,
      context.source,
      context.destination,
      request,
      "reference_closure_invalid",
      limits,
    );
    return;
  }
  if (scenario.id === "06-reject-corrupt-chunk") {
    const [chunk] = (await readdir(join(context.source, "chunks"))).sort();
    const path = join(context.source, "chunks", chunk);
    const bytes = await readFile(path);
    bytes[0] ^= 0xff;
    await writeFile(path, bytes);
    errorJson(
      implementation,
      context.source,
      context.destination,
      context.fixture.request,
      "chunk_invalid",
      limits,
    );
    return;
  }
  if (scenario.id === "07-reject-unsafe-package-node") {
    await symlink("version.json", join(context.source, "version-alias.json"), "file");
    errorJson(
      implementation,
      context.source,
      context.destination,
      context.fixture.request,
      "unsafe_package",
      limits,
    );
    return;
  }
  if (scenario.id === "08-preserve-existing-destination") {
    await mkdir(context.destination);
    await writeFile(join(context.destination, "sentinel.txt"), "preserve\n");
    const before = await directorySnapshot(context.destinationParent);
    const attention = attentionJson(
      implementation,
      context.source,
      context.destination,
      context.fixture.request,
      "destination_occupied",
      limits,
    );
    assert.equal(attention.operation_id, context.fixture.request.operation_id);
    assert.deepEqual(await directorySnapshot(context.destinationParent), before);
    assert.equal(await readFile(join(context.destination, "sentinel.txt"), "utf8"), "preserve\n");
    return;
  }
  if (scenario.id === "10-reject-unsupported-filesystem-before-staging") {
    const before = await directorySnapshot(context.destinationParent);
    errorJson(
      implementation,
      context.source,
      context.destination,
      context.fixture.request,
      "unsupported_reconstruction_filesystem",
      limits,
      { FOLDERBASE_ROOT_RECONSTRUCTION_CONFORMANCE_FORCE_UNSUPPORTED_FILESYSTEM: "1" },
    );
    assert.deepEqual(
      await directorySnapshot(context.destinationParent),
      before,
      "unsupported filesystem fails before staging",
    );
    return;
  }
  if (scenario.id === "11-reject-ambient-authority") {
    const request = {
      ...context.fixture.request,
      folder_scope_id: "folderscope_019f0000-0000-7000-8000-000000000001",
      share_link: "https://share.invalid/token",
      cloud_identity: "cloud-user",
    };
    errorJson(
      implementation,
      context.source,
      context.destination,
      request,
      "invalid_request",
      limits,
    );
    return;
  }
  throw new Error(`unknown root-reconstruction scenario ${scenario.id}`);
}

let implementation;
let limits;
try {
  implementation = implementationArgument(process.argv.slice(2));
  limits = {
    timeoutMs: configuredInteger(
      "FOLDERBASE_ROOT_RECONSTRUCTION_CONFORMANCE_COMMAND_TIMEOUT_MS",
      DEFAULT_COMMAND_TIMEOUT_MS,
      MAXIMUM_COMMAND_TIMEOUT_MS,
    ),
    maxBytes: configuredInteger(
      "FOLDERBASE_ROOT_RECONSTRUCTION_CONFORMANCE_COMMAND_MAX_BYTES",
      DEFAULT_COMMAND_MAX_BYTES,
      MAXIMUM_COMMAND_MAX_BYTES,
    ),
  };
} catch (error) {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exit(2);
}

const root = await mkdtemp(join(tmpdir(), "folderbase-root-reconstruction-conformance-"));
const scenariosDocument = JSON.parse(await readFile(scenariosPath, "utf8"));
assert.equal(scenariosDocument.format, "folderbase-root-reconstruction-scenarios-v1");
const report = {
  format: REPORT_FORMAT,
  capability: CAPABILITY,
  implementation: basename(implementation),
  total: scenariosDocument.cases.length,
  passed: 0,
  failed: 0,
  cases: [],
};

try {
  for (const scenario of scenariosDocument.cases) {
    const result = { id: scenario.id, status: "passed", covers: scenario.covers };
    try {
      await runCase(implementation, scenario, join(root, scenario.id), limits);
      report.passed += 1;
    } catch (error) {
      result.status = "failed";
      result.message = error instanceof Error ? error.message : String(error);
      report.failed += 1;
    }
    report.cases.push(result);
  }
} finally {
  await rm(root, { recursive: true, force: true });
}

process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
process.exitCode = report.failed === 0 ? 0 : 1;

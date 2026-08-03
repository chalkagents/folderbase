#!/usr/bin/env node

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  realpath,
  rename,
  rm,
  stat,
  symlink,
  truncate,
  utimes,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, extname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  closeSync,
  lstatSync,
  openSync,
  readFileSync,
  readdirSync,
  readlinkSync,
  readSync,
} from "node:fs";

import { assertQuerySchema } from "./schema.mjs";
import { queryRequestSha256 } from "./reference-request-digest.mjs";
import { assertSparseFixture } from "./sparse-fixture.mjs";

const FORMAT = "folderbase-capability-suite-report-v1";
const CAPABILITY = "folderbase.query-index@0.1.0";
const FOLDERBASE_ID = "folderbase_018f43c2-9a1b-7def-8123-456789abcdef";
const VERSION_ID = "fbversion_019f0000-0000-7000-8000-000000000001";
const MISSING_VERSION_ID = "fbversion_019f0000-0000-7000-8000-000000000099";
const LARGE_BYTES = 10 * 1024 * 1024 * 1024;
const DEFAULT_COMMAND_TIMEOUT_MS = 30_000;
const DEFAULT_COMMAND_MAX_BYTES = 8 * 1024 * 1024;
const directory = dirname(fileURLToPath(import.meta.url));
const fixtures = join(directory, "fixtures");
const schema = JSON.parse(
  await readFile(
    resolve(directory, "../../../schemas/capabilities/query-index/0.1/query-index.schema.json"),
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

const commandTimeoutMs = boundedEnvironmentInteger(
  "FOLDERBASE_QUERY_CONFORMANCE_COMMAND_TIMEOUT_MS",
  DEFAULT_COMMAND_TIMEOUT_MS,
  100,
  300_000,
);
const commandMaxBytes = boundedEnvironmentInteger(
  "FOLDERBASE_QUERY_CONFORMANCE_COMMAND_MAX_BYTES",
  DEFAULT_COMMAND_MAX_BYTES,
  1_024,
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

function execute(implementation, arguments_, input) {
  const command = [".js", ".cjs", ".mjs"].includes(extname(implementation))
    ? process.execPath
    : implementation;
  const args = command === process.execPath ? [implementation, ...arguments_] : arguments_;
  const payload = JSON.stringify({
    command,
    args,
    input: Buffer.from(input ?? "").toString("base64"),
    timeoutMs: commandTimeoutMs,
    maxBytes: commandMaxBytes,
  });
  const supervised = spawnSync(process.execPath, [join(directory, "command-supervisor.mjs")], {
    encoding: "utf8",
    input: payload,
    killSignal: "SIGKILL",
    maxBuffer: commandMaxBytes + 1024 * 1024,
    timeout: commandTimeoutMs + 10_000,
  });
  if (supervised.error?.code === "ETIMEDOUT") {
    throw new Error("candidate process supervisor failed to reap its process tree");
  }
  if (supervised.error) throw supervised.error;
  const result = JSON.parse(supervised.stdout);
  if (result.bound === "timeout") {
    throw new Error(`candidate command timed out after ${commandTimeoutMs} ms`);
  }
  if (result.bound === "output") {
    throw new Error(`candidate command exceeded the ${commandMaxBytes}-byte output limit`);
  }
  if (result.error) throw Object.assign(new Error(result.error.message), { code: result.error.code });
  return result;
}

function wholeTreeSnapshot(root, {
  excludeIndex = false,
  allowIndexParentMutation = false,
} = {}) {
  const records = [];
  function visit(relative) {
    const absolute = join(root, relative);
    for (const name of readdirSync(absolute).sort((left, right) =>
      Buffer.compare(Buffer.from(left), Buffer.from(right)))) {
      const path = relative ? `${relative}/${name}` : name;
      if (excludeIndex && path === ".folderbase/local/query-index-v1") continue;
      const metadata = lstatSync(join(root, path), { bigint: true });
      if (metadata.isDirectory()) {
        const stable = {
          path,
          kind: "directory",
          mode: metadata.mode.toString(),
          device: metadata.dev.toString(),
          inode: metadata.ino.toString(),
        };
        records.push(allowIndexParentMutation && path === ".folderbase/local"
          ? stable
          : {
              ...stable,
              size: metadata.size.toString(),
              mtime_ns: metadata.mtimeNs.toString(),
              ctime_ns: metadata.ctimeNs.toString(),
              blocks: metadata.blocks?.toString() ?? null,
            });
        visit(path);
      } else if (metadata.isSymbolicLink()) {
        records.push({
          path,
          kind: "symlink",
          mode: metadata.mode.toString(),
          size: metadata.size.toString(),
          mtime_ns: metadata.mtimeNs.toString(),
          device: metadata.dev.toString(),
          inode: metadata.ino.toString(),
          blocks: metadata.blocks?.toString() ?? null,
          target: readlinkSync(join(root, path)),
        });
      } else if (metadata.isFile()) {
        const common = {
          path,
          kind: "regular_file",
          mode: metadata.mode.toString(),
          size: metadata.size.toString(),
          mtime_ns: metadata.mtimeNs.toString(),
          device: metadata.dev.toString(),
          inode: metadata.ino.toString(),
          blocks: metadata.blocks?.toString() ?? null,
        };
        if (metadata.size <= 1024n * 1024n) {
          records.push({ ...common, sha256: sha256(readFileSync(join(root, path))) });
        } else {
          const descriptor = openSync(join(root, path), "r");
          try {
            const head = Buffer.alloc(4096);
            const tail = Buffer.alloc(4096);
            const headRead = readSync(descriptor, head, 0, head.length, 0);
            const tailPosition = metadata.size > 4096n ? metadata.size - 4096n : 0n;
            const tailRead = readSync(descriptor, tail, 0, tail.length, Number(tailPosition));
            records.push({
              ...common,
              bounded_head_sha256: sha256(head.subarray(0, headRead)),
              bounded_tail_sha256: sha256(tail.subarray(0, tailRead)),
            });
          } finally { closeSync(descriptor); }
        }
      } else {
        records.push({ path, kind: "other", mode: metadata.mode.toString() });
      }
    }
  }
  visit("");
  return records;
}

function executeAtRoot(implementation, arguments_, input, root) {
  const explicitRebuild = arguments_[0] === "index" && arguments_[1] === "rebuild";
  const snapshotOptions = explicitRebuild
    ? { excludeIndex: true, allowIndexParentMutation: true }
    : {};
  const before = wholeTreeSnapshot(root, snapshotOptions);
  try {
    return execute(implementation, arguments_, input);
  } finally {
    assert.deepEqual(wholeTreeSnapshot(root, snapshotOptions), before,
      "candidate changed content outside its exact disposable query-index namespace");
  }
}

function indexNamespaceSnapshot(root) {
  return wholeTreeSnapshot(root).filter(({ path }) =>
    path === ".folderbase/local/query-index-v1" ||
      path.startsWith(".folderbase/local/query-index-v1/"));
}

function successJson(implementation, arguments_, definition, input, root) {
  const result = executeAtRoot(implementation, arguments_, input, root);
  assert.equal(result.status, 0, result.stderr || result.stdout);
  assert.equal(result.stderr, "", "successful query capability commands leave stderr empty");
  const output = JSON.parse(result.stdout);
  assertQuerySchema(output, schema, definition);
  return output;
}

function errorJson(implementation, arguments_, expectedCode, input, root) {
  const result = executeAtRoot(implementation, arguments_, input, root);
  assert.equal(result.status, 2, result.stderr || result.stdout);
  assert.equal(result.stdout, "", "operational failures leave stdout empty");
  const output = JSON.parse(result.stderr);
  assertQuerySchema(output, schema, "queryError");
  assert.equal(output.error.code, expectedCode);
  return output;
}

async function fixtureRequest(name) {
  return JSON.parse(await readFile(join(fixtures, "requests", "valid", name), "utf8"));
}

async function invalidFixtureRequest(name) {
  return JSON.parse(await readFile(join(fixtures, "requests", "invalid", name), "utf8"));
}

function query(implementation, command, root, request) {
  return successJson(
    implementation,
    ["query", command, root, "--json"],
    command === "run" ? "queryResult" : "queryExplain",
    `${JSON.stringify(request)}\n`,
    root,
  );
}

function queryError(implementation, root, request, expectedCode) {
  return errorJson(
    implementation,
    ["query", "run", root, "--json"],
    expectedCode,
    `${JSON.stringify(request)}\n`,
    root,
  );
}

function index(implementation, command, root) {
  const output = successJson(
    implementation,
    ["index", command, root, "--json"],
    command === "status" ? "indexStatus" : "indexRebuildResult",
    undefined,
    root,
  );
  if (command === "rebuild") {
    const indexRoot = join(root, ".folderbase/local/query-index-v1");
    const metadata = lstatSync(indexRoot, { bigint: true });
    assert.ok(metadata.isDirectory() && !metadata.isSymbolicLink(),
      "query index root must be an exact private directory, not a symlink");
    let records = 0;
    let bytes = 0n;
    const visit = (path) => {
      for (const entry of readdirSync(path)) {
        const child = join(path, entry);
        const childMetadata = lstatSync(child, { bigint: true });
        assert.ok(!childMetadata.isSymbolicLink(), "query index must not contain symlinks");
        records += 1;
        bytes += childMetadata.size;
        assert.ok(records <= 16_384 && bytes <= 64n * 1024n * 1024n,
          "query index exceeds the public conformance bound");
        if (childMetadata.isDirectory()) visit(child);
        else assert.ok(childMetadata.isFile(), "query index contains unsupported state");
      }
    };
    visit(indexRoot);
  }
  return output;
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function metadataRecord(metadata) {
  return {
    size: metadata.size,
    mode: metadata.mode,
    mtime_ms: metadata.mtimeMs,
    device: metadata.dev,
    inode: metadata.ino,
  };
}

async function protectedProof(root) {
  const records = [];
  for (const path of [
    ".folderbase/manifest.json",
    `.folderbase/versions/folderbase/${VERSION_ID}.json`,
    ".folderbase/local/other-engine/sentinel.txt",
    "ignored/private.txt",
    "vendors/nested/secret/video.mp4",
  ]) {
    const bytes = await readFile(join(root, path));
    records.push([path, metadataRecord(await lstat(join(root, path))), sha256(bytes)]);
  }
  return records;
}

async function privateStatePaths(root) {
  const paths = [];
  async function visit(relative) {
    for (const entry of await readdir(join(root, relative), { withFileTypes: true })) {
      const path = join(relative, entry.name).replaceAll("\\", "/");
      paths.push(path);
      if (entry.isDirectory()) await visit(path);
    }
  }
  await visit(".folderbase");
  return paths.sort();
}

async function createFixtureRoot(owner, name, { folderbaseignore = true } = {}) {
  const root = join(owner, name);
  await mkdir(root);
  for (const path of [
    ".folderbase/local/other-engine",
    ".folderbase/versions/folderbase",
    "data",
    "documents",
    "generated/keep",
    "ignored",
    "logs",
    "links",
    "media",
    "notes",
    "node_modules/package",
    "opaque",
    "reports/current",
    "repo/.git",
    "vendors/nested/.folderbase",
    "vendors/nested/secret",
  ]) await mkdir(join(root, path), { recursive: true });
  const writes = [
    [".folderbase/manifest.json", await readFile(join(fixtures, "root-manifest.json"))],
    [".folderbase/local/other-engine/sentinel.txt", "another private engine owns this\n"],
    [".folderbaseignore", "ignored/*\n!ignored/keep.txt\nlogs/*.log\n!logs/keep.log\n!generated/keep/\n!generated/keep/**\n!reports/current/\n!reports/current/**\nreports/current/reignored.txt\n!opaque/child.txt\n"],
    ["AGENTS.md", "agent instructions\n"],
    ["data/app.sqlite", Buffer.from("SQLite format 3\0", "binary")],
    ["data/table.csv", "a,b\none,two\n"],
    ["database.md", "# Database sibling!\n"],
    ["documents/Brief.pdf", "%PDF-1.7\nquery\n"],
    ["generated/drop.txt", "engine ignored\n"],
    ["generated/keep/context.txt", "engine rule overridden\n"],
    ["ignored/private.txt", "must stay excluded\n"],
    ["ignored/keep.txt", "negation keeps this\n"],
    ["logs/drop.log", "ignored log\n"],
    ["logs/keep.log", "kept log\n"],
    ["node_modules/package/index.js", "reconstructable\n"],
    ["opaque/child.txt", "parent remains pruned\n"],
    ["reports/drop.txt", "ignored report\n"],
    ["reports/current/keep.txt", "kept report\n"],
    ["reports/current/reignored.txt", "last match wins\n"],
    ["scratch.tmp", "engine ignored\n"],
    ["media/clip.mp4", "video-bytes\n"],
    ["notes/Brief.md", "# Brief\ncontext\n"],
    ["repo/.git/HEAD", "ref: refs/heads/main\n"],
    ["repo/README.md", "repository docs\n"],
    [
      "vendors/nested/.folderbase/manifest.json",
      await readFile(join(fixtures, "nested-root-manifest.json")),
    ],
    ["vendors/nested/secret/video.mp4", "must remain opaque\n"],
    [
      `.folderbase/versions/folderbase/${VERSION_ID}.json`,
      await readFile(join(fixtures, "historical-version.json")),
    ],
  ];
  for (const [path, bytes] of writes) {
    if (path === ".folderbaseignore" && !folderbaseignore) continue;
    await writeFile(join(root, path), bytes);
  }
  const sparsePath = join(root, "media/archive.mov");
  await writeFile(sparsePath, "");
  await truncate(sparsePath, LARGE_BYTES);
  const sparse = await stat(sparsePath, { bigint: true });
  assertSparseFixture(sparse, LARGE_BYTES);
  await symlink("../notes/Brief.md", join(root, "links/brief-link"));
  return root;
}

function paths(output) {
  return output.entries.map((entry) => entry.path);
}

function liveRequest(limit = 1, cursor) {
  return {
    format: "folderbase-query-request-v1",
    scope: { kind: "live" },
    page: { limit, ...(cursor ? { cursor } : {}) },
  };
}

function historicalRequest(versionId = VERSION_ID) {
  return {
    format: "folderbase-query-request-v1",
    scope: { kind: "historical", folderbase_version_id: versionId },
    page: { limit: 1000 },
  };
}

function concatenatePages(implementation, root, limit) {
  const all = [];
  let cursor;
  do {
    const output = query(implementation, "run", root, liveRequest(limit, cursor));
    all.push(...paths(output));
    cursor = output.page.next_cursor;
  } while (cursor);
  return all;
}

function continuation(implementation, root, first) {
  return executeAtRoot(
    implementation,
    ["query", "run", root, "--json"],
    `${JSON.stringify(liveRequest(1, first.page.next_cursor))}\n`,
    root,
  );
}

function assertSnapshotChanged(result) {
  assert.equal(result.status, 1, result.stderr || result.stdout);
  assert.equal(result.stderr, "");
  const attention = JSON.parse(result.stdout);
  assertQuerySchema(attention, schema, "queryAttention");
  assert.equal(attention.error.code, "query_snapshot_changed");
}

async function cursorThenMutate(implementation, root, mutate, restore) {
  const first = query(implementation, "run", root, liveRequest());
  assert.ok(first.page.next_cursor);
  try {
    await mutate();
    assertSnapshotChanged(continuation(implementation, root, first));
  } finally {
    await restore();
  }
}

let implementation;
try {
  implementation = await realpath(implementationArgument(process.argv.slice(2)));
  if (!(await stat(implementation)).isFile()) {
    throw new Error("implementation path must name a regular file");
  }
} catch (error) {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exit(2);
}

const cleanupRoot = await mkdtemp(join(tmpdir(), "folderbase-query-conformance-owner-"));
const report = {
  format: FORMAT,
  capability: CAPABILITY,
  implementation: basename(implementation),
  passed: 0,
  failed: 0,
  cases: [],
};

try {
  const root = await createFixtureRoot(cleanupRoot, "primary");
  const cases = [
    {
      id: "query-live-mixed-files-metadata-first",
      async run() {
        const request = await fixtureRequest("live-all.json");
        const output = query(implementation, "run", root, request);
        const blueprint = JSON.parse(
          await readFile(join(fixtures, "mixed-observations.json"), "utf8"),
        );
        assert.deepEqual(paths(output), blueprint.entries.map((entry) => entry.path));
        assert.deepEqual(
          output.entries.map(({ path, kind, bytes }) => ({ path, kind, bytes })),
          blueprint.entries.map(({ path, kind, bytes }) => ({ path, kind, bytes })),
        );
        assert.equal(output.execution, "bounded_scan");
        assert.equal(output.entries.find((entry) => entry.path === "media/archive.mov").bytes, LARGE_BYTES);
        assert.equal(output.entries.find((entry) => entry.path === "links/brief-link").kind, "symlink");
        assert.ok(!paths(output).includes("ignored/private.txt"));
        assert.ok(!paths(output).includes("vendors/nested/secret/video.mp4"));
      },
    },
    {
      id: "query-live-supports-an-optional-folderbaseignore",
      async run() {
        const noIgnoreRoot = await createFixtureRoot(cleanupRoot, "without-ignore", {
          folderbaseignore: false,
        });
        const output = query(implementation, "run", noIgnoreRoot, liveRequest(1000));
        const expected = JSON.parse(
          await readFile(join(fixtures, "no-folderbaseignore-observation.json"), "utf8"),
        );
        assert.equal(expected.folderbaseignore_present, false);
        assert.ok(!paths(output).includes(expected.absent_path));
        assert.ok(!paths(output).includes(expected.engine_exclusion.path));
        assert.ok(output.exclusions.some(({ path, reason }) =>
          path === expected.engine_exclusion.path &&
            reason === expected.engine_exclusion.reason));
        assert.ok(paths(output).includes(expected.ordinary_included_path),
          "without the optional user file, only manifest engine rules apply");
        const optionalPath = join(noIgnoreRoot, ".folderbaseignore");
        const absentGeneration = output.observation_generation;
        try {
          await writeFile(optionalPath, "");
          const presentEmpty = query(implementation, "run", noIgnoreRoot, liveRequest(1000));
          assert.notEqual(presentEmpty.observation_generation, absentGeneration);
        } finally { await rm(optionalPath, { force: true }); }
      },
    },
    {
      id: "query-filter-algebra-is-families-and-values-or",
      run() {
        const orPaths = query(implementation, "run", root, {
          format: "folderbase-query-request-v1",
          scope: { kind: "live" },
          filters: { paths: ["data/table.csv", "notes/Brief.md", "data/table.csv"] },
          page: { limit: 100 },
        });
        assert.deepEqual(paths(orPaths), ["data/table.csv", "notes/Brief.md"]);
        const intersected = query(implementation, "run", root, {
          format: "folderbase-query-request-v1",
          scope: { kind: "live" },
          filters: {
            path_prefixes: ["data", "media"],
            kinds: ["regular_file"],
            lifecycles: ["live"],
            minimum_bytes: 13,
            maximum_bytes: 20,
          },
          page: { limit: 100 },
        });
        assert.deepEqual(paths(intersected), ["data/app.sqlite"]);
        const historical = query(implementation, "run", root, {
          format: "folderbase-query-request-v1",
          scope: { kind: "historical", folderbase_version_id: VERSION_ID },
          filters: {
            object_ids: [
              "obj_019f0000-0000-7000-8000-000000000020",
              "obj_019f0000-0000-7000-8000-000000000030",
            ],
            object_version_ids: ["version_019f0000-0000-7000-8000-000000000031"],
            lifecycles: ["live", "deleted"],
          },
          page: { limit: 100 },
        });
        assert.deepEqual(paths(historical), ["documents/Brief.pdf"]);
      },
    },
    {
      id: "query-candidate-emits-the-fixed-canonical-request-digest",
      async run() {
        for (const stem of ["canonical-request", "canonical-unicode-request"]) {
          const request = await fixtureRequest(`${stem}.json`);
          const expected = (
            await readFile(join(fixtures, `requests/valid/${stem}.sha256`), "utf8")
          ).trim();
          const explained = query(implementation, "explain", root, request);
          assert.equal(explained.request_sha256, expected);
          assert.equal(explained.request_sha256, queryRequestSha256(request));
          assert.deepEqual(
            explained.normalized_request,
            JSON.parse(
              await readFile(join(fixtures, `requests/valid/${stem}.normalized.json`), "utf8"),
            ),
          );
        }
      },
    },
    {
      id: "query-prefix-is-component-aware",
      async run() {
        const output = query(implementation, "run", root, await fixtureRequest("live-prefix-data.json"));
        assert.deepEqual(paths(output), ["data", "data/app.sqlite", "data/table.csv"]);
        assert.ok(!paths(output).includes("database.md"));
      },
    },
    {
      id: "query-size-and-kind-keep-large-assets-metadata-only",
      async run() {
        const output = query(implementation, "run", root, await fixtureRequest("live-large-files.json"));
        assert.deepEqual(paths(output), ["media/archive.mov"]);
        assert.equal(output.entries[0].bytes, LARGE_BYTES);
      },
    },
    {
      id: "query-pages-have-one-deterministic-order",
      run() {
        const byOne = concatenatePages(implementation, root, 1);
        const byTwo = concatenatePages(implementation, root, 2);
        const byAll = concatenatePages(implementation, root, 1000);
        assert.deepEqual(byOne, byAll);
        assert.deepEqual(byTwo, byAll);
        assert.equal(new Set(byAll).size, byAll.length);
      },
    },
    {
      id: "query-historical-version-has-exact-identity-and-deletion",
      async run() {
        const output = query(
          implementation,
          "run",
          root,
          await fixtureRequest("historical-deleted-object.json"),
        );
        assert.deepEqual(paths(output), ["archive/approved-proposal.docx"]);
        assert.equal(output.entries[0].lifecycle, "deleted");
        assert.equal(output.entries[0].object_id, "obj_019f0000-0000-7000-8000-000000000010");
        assert.equal(output.entries[0].object_version_id, "version_019f0000-0000-7000-8000-000000000011");
        assert.equal(output.entries[0].folderbase_version_id, VERSION_ID);
      },
    },
    {
      id: "query-total-row-key-pages-same-path-recreation-without-loss",
      run() {
        const request = (limit, cursor) => ({
          format: "folderbase-query-request-v1",
          scope: { kind: "historical", folderbase_version_id: VERSION_ID },
          filters: { paths: ["data/table.csv"] },
          page: { limit, ...(cursor ? { cursor } : {}) },
        });
        const all = query(implementation, "run", root, request(1000));
        const first = query(implementation, "run", root, request(1));
        assert.ok(first.page.next_cursor);
        const second = query(
          implementation,
          "run",
          root,
          request(1, first.page.next_cursor),
        );
        assert.equal(second.page.next_cursor, null);
        assert.deepEqual([...first.entries, ...second.entries], all.entries);
        assert.deepEqual(paths(all), ["data/table.csv", "data/table.csv"]);
        assert.deepEqual(all.entries.map(({ lifecycle }) => lifecycle), ["live", "deleted"]);
        assert.notEqual(all.entries[0].object_id, all.entries[1].object_id);
      },
    },
    {
      id: "query-invalid-and-tampered-historical-versions-are-typed-operational-errors",
      async run() {
        queryError(implementation, root, historicalRequest(MISSING_VERSION_ID), "query_scope_version_missing");
        const versionPath = join(root, ".folderbase/versions/folderbase", `${VERSION_ID}.json`);
        const exact = await readFile(versionPath);
        try {
          await writeFile(versionPath, "{not-json\n");
          queryError(implementation, root, historicalRequest(), "query_scope_version_invalid");
          const tampered = JSON.parse(exact);
          tampered.version_id = MISSING_VERSION_ID;
          await writeFile(versionPath, `${JSON.stringify(tampered)}\n`);
          queryError(implementation, root, historicalRequest(), "query_scope_version_invalid");
          const schemaInvalid = JSON.parse(exact);
          schemaInvalid.future_field = true;
          await writeFile(versionPath, `${JSON.stringify(schemaInvalid)}\n`);
          queryError(implementation, root, historicalRequest(), "query_scope_version_invalid");
          const semanticInvalid = JSON.parse(exact);
          semanticInvalid.parents = [semanticInvalid.version_id];
          await writeFile(versionPath, `${JSON.stringify(semanticInvalid)}\n`);
          queryError(implementation, root, historicalRequest(), "query_scope_version_invalid");
        } finally {
          await writeFile(versionPath, exact);
        }
      },
    },
    {
      id: "query-historical-generation-binds-canonical-version-digest",
      async run() {
        const versionPath = join(root, ".folderbase/versions/folderbase", `${VERSION_ID}.json`);
        const exact = await readFile(versionPath);
        const request = { ...historicalRequest(), page: { limit: 1 } };
        const first = query(implementation, "run", root, request);
        assert.ok(first.page.next_cursor);
        try {
          const reformatted = JSON.stringify(JSON.parse(exact), null, 2)
            .replace('"bytes": 624', '"bytes": 6.24e2');
          await writeFile(versionPath, `${reformatted}\n`);
          const continued = query(implementation, "run", root, {
            ...request,
            page: { limit: 1, cursor: first.page.next_cursor },
          });
          assert.equal(continued.observation_generation, first.observation_generation);
        } finally { await writeFile(versionPath, exact); }
      },
    },
    {
      id: "query-validates-the-closed-request-before-normalization",
      async run() {
        for (const name of await readdir(join(fixtures, "requests", "invalid"))) {
          if (!name.endsWith(".json")) continue;
          queryError(implementation, root, await invalidFixtureRequest(name), "invalid_query_request");
        }
      },
    },
    {
      id: "query-invalid-portable-paths-and-collisions-exit-two-on-stderr",
      run() {
        const invalidFilters = [
          { paths: ["../escape"] },
          { paths: [".FOLDERBASE/private"] },
          { paths: ["COM1.txt"] },
          { paths: ["é".repeat(128)] },
          { paths: [Array.from({ length: 129 }, () => "x").join("/")] },
          { paths: [`${"é".repeat(2048)}/x`] },
          { paths: ["Notes/Brief.md", "notes/brief.md"] },
          { paths: ["unicode/é.md", "unicode/e\u0301.md"] },
          { paths: ["unicode/ạ᫏", "unicode/a᫏̣"] },
          { paths: ["unicode/𐒰", "unicode/𐓘"] },
          { paths: ["unicode/straße.md", "unicode/strasse.md"] },
        ];
        for (const filters of invalidFilters) {
          queryError(implementation, root, {
            format: "folderbase-query-request-v1",
            scope: { kind: "live" },
            filters,
            page: { limit: 10 },
          }, "invalid_query_request");
        }
      },
    },
    {
      id: "query-live-inventory-rejects-full-fold-collisions",
      async run() {
        const directory = join(root, "unicode-collision");
        await mkdir(directory);
        await writeFile(join(directory, "ẞ.md"), "one\n");
        await writeFile(join(directory, "ss.md"), "two\n");
        try {
          const distinct = await readdir(directory);
          if (distinct.length === 2) {
            queryError(implementation, root, liveRequest(10), "invalid_query_request");
          } else {
            // A case-insensitive filesystem prevented construction of the
            // counterexample. The pure table/index test still proves ẞ vs ss;
            // Linux conformance runs exercise this black-box inventory path.
            assert.equal(distinct.length, 1);
          }
        } finally { await rm(directory, { recursive: true, force: true }); }
      },
    },
    {
      id: "query-explain-names-source-order-access-and-exclusions",
      async run() {
        const output = query(implementation, "explain", root, await fixtureRequest("live-all.json"));
        assert.equal(output.scope_source, "capture_plan");
        assert.equal(output.ordering, "query_row_key_v1");
        assert.equal(output.ordinary_content_access, "metadata_only");
        assert.ok(output.excluded.some((item) => item.reason === "capture-ignore-policy"));
        assert.ok(output.excluded.some((item) => item.reason === "nested-folderbase-boundary"));
      },
    },
    {
      id: "query-explain-and-status-preserve-every-protected-sentinel",
      async run() {
        const before = await protectedProof(root);
        const beforeState = await privateStatePaths(root);
        query(implementation, "run", root, await fixtureRequest("live-all.json"));
        assert.deepEqual(await protectedProof(root), before, "query run changed a protected sentinel");
        assert.deepEqual(await privateStatePaths(root), beforeState, "query run changed private state");
        query(implementation, "explain", root, await fixtureRequest("live-all.json"));
        assert.deepEqual(await protectedProof(root), before, "query explain changed a protected sentinel");
        assert.deepEqual(await privateStatePaths(root), beforeState, "query explain changed private state");
        const status = index(implementation, "status", root);
        assert.equal(status.state, "absent");
        await assert.rejects(stat(join(root, ".folderbase/local/query-index-v1")), /ENOENT/u);
        assert.deepEqual(await protectedProof(root), before, "index status changed a protected sentinel");
        assert.deepEqual(await privateStatePaths(root), beforeState, "index status changed private state");
      },
    },
    {
      id: "explicit-index-rebuild-writes-only-its-private-disposable-namespace",
      async run() {
        const before = await protectedProof(root);
        const beforeState = await privateStatePaths(root);
        const result = index(implementation, "rebuild", root);
        assert.equal(result.storage_path, ".folderbase/local/query-index-v1");
        assert.equal(result.ordinary_files_changed, false);
        assert.equal(result.portable_files_changed, false);
        assert.deepEqual((await readdir(join(root, ".folderbase/local"))).sort(), [
          "other-engine",
          "query-index-v1",
        ]);
        assert.deepEqual(await protectedProof(root), before);
        assert.deepEqual(
          (await privateStatePaths(root)).filter(
            (path) => path !== ".folderbase/local/query-index-v1" &&
              !path.startsWith(".folderbase/local/query-index-v1/"),
          ),
          beforeState,
        );
        const exactIndex = indexNamespaceSnapshot(root);
        assert.ok(exactIndex.length >= 2, "rebuilt index snapshot is non-empty");
        assert.equal(index(implementation, "status", root).state, "fresh");
        assert.deepEqual(indexNamespaceSnapshot(root), exactIndex,
          "index status mutated the exact rebuilt index");
        assert.equal(
          query(implementation, "run", root, await fixtureRequest("live-all.json")).execution,
          "private_index",
        );
        assert.deepEqual(indexNamespaceSnapshot(root), exactIndex,
          "query run mutated the exact rebuilt index");
        assert.equal(
          query(implementation, "explain", root, await fixtureRequest("live-all.json")).index_strategy,
          "private_index",
        );
        assert.deepEqual(indexNamespaceSnapshot(root), exactIndex,
          "query explain mutated the exact rebuilt index");
      },
    },
    {
      id: "cursor-binds-the-exact-physical-root-instance",
      async run() {
        const first = query(implementation, "run", root, liveRequest());
        const other = await createFixtureRoot(cleanupRoot, "other-root");
        errorJson(
          implementation,
          ["query", "run", other, "--json"],
          "invalid_query_cursor",
          `${JSON.stringify(liveRequest(1, first.page.next_cursor))}\n`,
          other,
        );
      },
    },
    {
      id: "cursor-generation-binds-the-root-manifest",
      async run() {
        const path = join(root, ".folderbase/manifest.json");
        const exact = await readFile(path);
        const changed = JSON.parse(exact);
        changed.folderbase.name = "Changed manifest generation";
        await cursorThenMutate(
          implementation,
          root,
          () => writeFile(path, `${JSON.stringify(changed)}\n`),
          () => writeFile(path, exact),
        );
      },
    },
    {
      id: "cursor-generation-binds-the-effective-ignore-policy",
      async run() {
        const path = join(root, ".folderbaseignore");
        const exact = await readFile(path);
        await cursorThenMutate(
          implementation,
          root,
          () => writeFile(path, "ignored/\nnotes/\n"),
          () => writeFile(path, exact),
        );
      },
    },
    {
      id: "cursor-generation-binds-the-optional-local-head",
      async run() {
        const path = join(root, ".folderbase/local/head.json");
        await cursorThenMutate(
          implementation,
          root,
          () => writeFile(path, "{\"format\":\"fixture-local-head\"}\n"),
          () => rm(path, { force: true }),
        );
      },
    },
    {
      id: "cursor-generation-binds-complete-entry-metadata-fingerprints",
      async run() {
        const path = join(root, "notes/Brief.md");
        const exact = await readFile(path);
        const metadata = await stat(path);
        await cursorThenMutate(
          implementation,
          root,
          // Windows chmod only models the write bit. Making the fixture
          // read-only changes the portable metadata fingerprint on every
          // supported host; an executable-bit-only mutation does not.
          () => chmod(path, 0o444),
          () => chmod(path, metadata.mode),
        );
        if (process.platform !== "win32") {
          await cursorThenMutate(
            implementation,
            root,
            () => chmod(path, 0o755),
            () => chmod(path, metadata.mode),
          );
        }
        await cursorThenMutate(
          implementation,
          root,
          async () => {
            const replacement = join(root, "notes/replacement.tmp");
            await writeFile(replacement, exact);
            await rm(path);
            await rename(replacement, path);
            await utimes(path, metadata.atime, metadata.mtime);
          },
          async () => {
            await writeFile(path, exact);
            await chmod(path, metadata.mode);
          },
        );
      },
    },
    {
      id: "cursor-refuses-to-mix-live-generations-after-content-metadata-change",
      async run() {
        const path = join(root, "notes/Brief.md");
        const exact = await readFile(path);
        await cursorThenMutate(
          implementation,
          root,
          () => writeFile(path, "# Brief\ncontext changed\n"),
          () => writeFile(path, exact),
        );
      },
    },
  ];

  for (const testCase of cases) {
    const result = { id: testCase.id, status: "passed" };
    try {
      await testCase.run();
      report.passed += 1;
    } catch (error) {
      result.status = "failed";
      result.message = error instanceof Error ? error.message : String(error);
      report.failed += 1;
      report.cases.push(result);
      break;
    }
    report.cases.push(result);
  }
} catch (error) {
  report.failed += 1;
  report.cases.push({
    id: "suite-fixture-setup",
    status: "failed",
    message: error instanceof Error ? error.message : String(error),
  });
} finally {
  await rm(cleanupRoot, { recursive: true, force: true });
}

process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
process.exitCode = report.failed === 0 ? 0 : 1;

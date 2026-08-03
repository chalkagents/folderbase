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

import { assertQuerySchema } from "./schema.mjs";
import { queryRequestSha256 } from "./reference-request-digest.mjs";

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
  const result = spawnSync(command, args, {
    encoding: "utf8",
    input,
    killSignal: "SIGKILL",
    maxBuffer: commandMaxBytes,
    timeout: commandTimeoutMs,
  });
  if (result.error?.code === "ETIMEDOUT") {
    throw new Error(`candidate command timed out after ${commandTimeoutMs} ms`);
  }
  if (result.error?.code === "ENOBUFS") {
    throw new Error(`candidate command exceeded the ${commandMaxBytes}-byte output limit`);
  }
  if (result.error) throw result.error;
  return result;
}

function successJson(implementation, arguments_, definition, input) {
  const result = execute(implementation, arguments_, input);
  assert.equal(result.status, 0, result.stderr || result.stdout);
  assert.equal(result.stderr, "", "successful query capability commands leave stderr empty");
  const output = JSON.parse(result.stdout);
  assertQuerySchema(output, schema, definition);
  return output;
}

function errorJson(implementation, arguments_, expectedCode, input) {
  const result = execute(implementation, arguments_, input);
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

function query(implementation, command, root, request) {
  return successJson(
    implementation,
    ["query", command, root, "--json"],
    command === "run" ? "queryResult" : "queryExplain",
    `${JSON.stringify(request)}\n`,
  );
}

function queryError(implementation, root, request, expectedCode) {
  return errorJson(
    implementation,
    ["query", "run", root, "--json"],
    expectedCode,
    `${JSON.stringify(request)}\n`,
  );
}

function index(implementation, command, root) {
  return successJson(
    implementation,
    ["index", command, root, "--json"],
    command === "status" ? "indexStatus" : "indexRebuildResult",
  );
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

async function createFixtureRoot(owner, name) {
  const root = join(owner, name);
  await mkdir(root);
  for (const path of [
    ".folderbase/local/other-engine",
    ".folderbase/versions/folderbase",
    "data",
    "documents",
    "ignored",
    "links",
    "media",
    "notes",
    "repo/.git",
    "vendors/nested/.folderbase",
    "vendors/nested/secret",
  ]) await mkdir(join(root, path), { recursive: true });
  const writes = [
    [".folderbase/manifest.json", await readFile(join(fixtures, "root-manifest.json"))],
    [".folderbase/local/other-engine/sentinel.txt", "another private engine owns this\n"],
    [".folderbaseignore", "ignored/\n"],
    ["AGENTS.md", "agent instructions\n"],
    ["data/app.sqlite", Buffer.from("SQLite format 3\0", "binary")],
    ["data/table.csv", "a,b\none,two\n"],
    ["database.md", "# Database sibling!\n"],
    ["documents/Brief.pdf", "%PDF-1.7\nquery\n"],
    ["ignored/private.txt", "must stay excluded\n"],
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
  for (const [path, bytes] of writes) await writeFile(join(root, path), bytes);
  const sparsePath = join(root, "media/archive.mov");
  await writeFile(sparsePath, "");
  await truncate(sparsePath, LARGE_BYTES);
  const sparse = await stat(sparsePath, { bigint: true });
  assert.equal(sparse.size, BigInt(LARGE_BYTES));
  assert.ok(typeof sparse.blocks === "bigint", "filesystem must expose sparse allocation blocks");
  assert.ok(
    sparse.blocks * 512n <= 16n * 1024n * 1024n,
    "the 10 GiB fixture must remain sparsely allocated below 16 MiB",
  );
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
  return execute(
    implementation,
    ["query", "run", root, "--json"],
    `${JSON.stringify(liveRequest(1, first.page.next_cursor))}\n`,
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
        } finally {
          await writeFile(versionPath, exact);
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
      id: "query-explain-names-source-order-access-and-exclusions",
      async run() {
        const output = query(implementation, "explain", root, await fixtureRequest("live-all.json"));
        assert.equal(output.scope_source, "capture_plan");
        assert.equal(output.ordering, "portable_path_utf8_bytes_ascending");
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
        assert.equal(index(implementation, "status", root).state, "fresh");
        assert.equal(
          query(implementation, "run", root, await fixtureRequest("live-all.json")).execution,
          "private_index",
        );
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
          () => chmod(path, 0o755),
          () => chmod(path, metadata.mode),
        );
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

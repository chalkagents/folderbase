#!/usr/bin/env node

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  stat,
  symlink,
  truncate,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, extname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { assertQuerySchema } from "./schema.mjs";

const FORMAT = "folderbase-capability-suite-report-v1";
const CAPABILITY = "folderbase.query-index@0.1.0";
const VERSION_ID = "fbversion_019f0000-0000-7000-8000-000000000001";
const LARGE_BYTES = 10 * 1024 * 1024 * 1024;
const directory = dirname(fileURLToPath(import.meta.url));
const fixtures = join(directory, "fixtures");
const schema = JSON.parse(
  await readFile(
    resolve(directory, "../../../schemas/capabilities/query-index/0.1/query-index.schema.json"),
    "utf8",
  ),
);

function implementationArgument(argv) {
  const flag = argv.indexOf("--implementation");
  if (flag === -1 || !argv[flag + 1] || argv.length !== 2) {
    throw new Error("usage: run.mjs --implementation /path/to/folderbase");
  }
  return resolve(argv[flag + 1]);
}

function execute(implementation, arguments_, input) {
  const command = [".js", ".cjs", ".mjs"].includes(extname(implementation))
    ? process.execPath
    : implementation;
  const args = command === process.execPath
    ? [implementation, ...arguments_]
    : arguments_;
  const result = spawnSync(command, args, {
    encoding: "utf8",
    input,
    maxBuffer: 16 * 1024 * 1024,
  });
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

async function fixtureRequest(name) {
  return JSON.parse(
    await readFile(join(fixtures, "requests", "valid", name), "utf8"),
  );
}

function query(implementation, command, root, request) {
  return successJson(
    implementation,
    ["query", command, root, "--json"],
    command === "run" ? "queryResult" : "queryExplain",
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

async function ordinaryMetadata(root) {
  const blueprint = JSON.parse(await readFile(join(fixtures, "mixed-observations.json"), "utf8"));
  const records = [];
  for (const entry of blueprint.entries) {
    if (entry.kind === "nested_folderbase") continue;
    const metadata = await lstat(join(root, entry.path));
    records.push([entry.path, metadata.size, Math.trunc(metadata.mtimeMs), metadata.mode]);
  }
  return records;
}

async function protectedMetadata(root) {
  const records = await ordinaryMetadata(root);
  for (const path of [
    ".folderbase/manifest.json",
    `.folderbase/versions/folderbase/${VERSION_ID}.json`,
  ]) {
    const metadata = await lstat(join(root, path));
    records.push([path, metadata.size, Math.trunc(metadata.mtimeMs), metadata.mode]);
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

async function createFixtureRoot() {
  const root = await mkdtemp(join(tmpdir(), "folderbase-query-conformance-"));
  for (const path of [
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
    ["vendors/nested/.folderbase/manifest.json", await readFile(join(fixtures, "nested-root-manifest.json"))],
    ["vendors/nested/secret/video.mp4", "must remain opaque\n"],
    [`.folderbase/versions/folderbase/${VERSION_ID}.json`, await readFile(join(fixtures, "historical-version.json"))],
  ];
  for (const [path, bytes] of writes) await writeFile(join(root, path), bytes);
  await writeFile(join(root, "media/archive.mov"), "");
  await truncate(join(root, "media/archive.mov"), LARGE_BYTES);
  await symlink("../notes/Brief.md", join(root, "links/brief-link"));
  return root;
}

function paths(output) {
  return output.entries.map((entry) => entry.path);
}

function concatenatePages(implementation, root, limit) {
  const all = [];
  let cursor;
  do {
    const request = {
      format: "folderbase-query-request-v1",
      scope: { kind: "live" },
      page: { limit, ...(cursor ? { cursor } : {}) },
    };
    const output = query(implementation, "run", root, request);
    all.push(...paths(output));
    cursor = output.page.next_cursor;
  } while (cursor);
  return all;
}

let implementation;
try {
  implementation = implementationArgument(process.argv.slice(2));
} catch (error) {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exit(2);
}
const root = await createFixtureRoot();
const report = {
  format: FORMAT,
  capability: CAPABILITY,
  implementation: basename(implementation),
  passed: 0,
  failed: 0,
  cases: [],
};
const state = {};
const cases = [
  {
    id: "query-live-mixed-files-metadata-first",
    async run() {
      state.before = await protectedMetadata(root);
      state.beforeStatePaths = await privateStatePaths(root);
      const request = await fixtureRequest("live-all.json");
      const output = query(implementation, "run", root, request);
      const blueprint = JSON.parse(await readFile(join(fixtures, "mixed-observations.json"), "utf8"));
      assert.deepEqual(paths(output), blueprint.entries.map((entry) => entry.path));
      assert.deepEqual(
        output.entries.map(({ path, kind, bytes }) => ({ path, kind, bytes })),
        blueprint.entries.map(({ path, kind, bytes }) => ({ path, kind, bytes })),
        "candidate metadata matches the deterministic mixed-file fixture",
      );
      assert.equal(output.execution, "bounded_scan");
      assert.equal(output.entries.find((entry) => entry.path === "media/archive.mov").bytes, LARGE_BYTES);
      assert.equal(output.entries.find((entry) => entry.path === "data/app.sqlite").kind, "regular_file");
      assert.equal(output.entries.find((entry) => entry.path === "documents/Brief.pdf").kind, "regular_file");
      assert.equal(output.entries.find((entry) => entry.path === "media/clip.mp4").kind, "regular_file");
      assert.equal(output.entries.find((entry) => entry.path === "links/brief-link").kind, "symlink");
      assert.ok(!paths(output).includes("ignored/private.txt"));
      assert.ok(!paths(output).includes("vendors/nested/secret/video.mp4"));
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
    id: "query-and-status-do-not-write-index-or-user-files",
    async run() {
      const status = index(implementation, "status", root);
      assert.equal(status.state, "absent");
      await stat(join(root, ".folderbase/versions/folderbase", `${VERSION_ID}.json`));
      await assert.rejects(stat(join(root, ".folderbase/local/query-index-v1")), /ENOENT/);
      assert.deepEqual(await protectedMetadata(root), state.before);
      assert.deepEqual(await privateStatePaths(root), state.beforeStatePaths);
    },
  },
  {
    id: "explicit-index-rebuild-writes-only-private-disposable-state",
    async run() {
      const result = index(implementation, "rebuild", root);
      assert.equal(result.storage_path, ".folderbase/local/query-index-v1");
      assert.equal(result.ordinary_files_changed, false);
      assert.equal(result.portable_files_changed, false);
      assert.deepEqual(await readdir(join(root, ".folderbase/local")), ["query-index-v1"]);
      assert.deepEqual(await protectedMetadata(root), state.before);
      assert.deepEqual(
        (await privateStatePaths(root)).filter(
          (path) => path !== ".folderbase/local" && !path.startsWith(".folderbase/local/query-index-v1"),
        ),
        state.beforeStatePaths,
      );
      const status = index(implementation, "status", root);
      assert.equal(status.state, "fresh");
      const output = query(implementation, "run", root, await fixtureRequest("live-all.json"));
      assert.equal(output.execution, "private_index");
    },
  },
  {
    id: "cursor-refuses-to-mix-live-generations",
    async run() {
      const firstRequest = {
        format: "folderbase-query-request-v1",
        scope: { kind: "live" },
        page: { limit: 1 },
      };
      const first = query(implementation, "run", root, firstRequest);
      assert.ok(first.page.next_cursor);
      await writeFile(join(root, "notes/Brief.md"), "# Brief\ncontext changed\n");
      const result = execute(
        implementation,
        ["query", "run", root, "--json"],
        `${JSON.stringify({
          ...firstRequest,
          page: { limit: 1, cursor: first.page.next_cursor },
        })}\n`,
      );
      assert.equal(result.status, 1, result.stderr || result.stdout);
      assert.equal(result.stderr, "");
      const attention = JSON.parse(result.stdout);
      assertQuerySchema(attention, schema, "queryAttention");
      assert.equal(attention.error.code, "query_snapshot_changed");
    },
  },
];

try {
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
} finally {
  await rm(root, { recursive: true, force: true });
}

process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
process.exitCode = report.failed === 0 ? 0 : 1;

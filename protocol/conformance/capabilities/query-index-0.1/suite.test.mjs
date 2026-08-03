import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { assertQuerySchema } from "./schema.mjs";
import {
  compileGitignore,
  effectiveCaptureIgnoreDigest,
  ignoredByGitignore,
} from "./capture-ignore-v2.mjs";
import { verifyFolderbaseVersion05 } from "./folderbase-version-0.5-verifier.mjs";
import {
  fullDefaultCaseFoldV9,
  PortablePathCollisionIndex,
  unicode17Nfc,
} from "./portable-path-v1.mjs";
import { FULL_DEFAULT_CASE_FOLD_V9 } from "./unicode-casefold-v9-data.mjs";
import {
  CANONICAL_COMBINING_CLASS_V17,
  CANONICAL_COMPOSITION_V17,
  CANONICAL_DECOMPOSITION_V17,
} from "./unicode-nfc-v17-data.mjs";
import {
  canonicalJsonBytes,
  normalizeQueryRequest,
  pathMatchesPrefix,
  queryRequestSha256,
  validatePortablePath,
} from "./reference-request-digest.mjs";
import {
  assertSparseFixture,
  markSparseFileForLogicalSizing,
} from "./sparse-fixture.mjs";

const directory = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = resolve(directory, "../../../..");
const fixtureDirectory = join(directory, "fixtures");
const requestDirectory = join(fixtureDirectory, "requests");
const schema = JSON.parse(
  await readFile(
    resolve(directory, "../../../schemas/capabilities/query-index/0.1/query-index.schema.json"),
    "utf8",
  ),
);

async function json(path) {
  return JSON.parse(await readFile(path, "utf8"));
}

function run(candidate, environment = {}) {
  return spawnSync(
    process.execPath,
    [join(directory, "run.mjs"), "--implementation", join(fixtureDirectory, candidate)],
    {
      encoding: "utf8",
      env: { ...process.env, ...environment },
      killSignal: "SIGKILL",
      maxBuffer: 16 * 1024 * 1024,
      timeout: 30_000,
    },
  );
}

test("public query request fixtures separate schema and semantic negatives", async () => {
  for (const name of await readdir(join(requestDirectory, "valid"))) {
    if (!name.endsWith(".json") || name.endsWith(".normalized.json")) continue;
    const request = await json(join(requestDirectory, "valid", name));
    assert.doesNotThrow(() => assertQuerySchema(request, schema, "queryRequest"), name);
    assert.doesNotThrow(() => normalizeQueryRequest(request), name);
  }

  for (const name of [
    "relationship-filter.json",
    "path-traversal.json",
    "page-too-large.json",
    "unknown-top-level.json",
    "invalid-kind-enum.json",
    "negative-minimum.json",
    "unknown-filter.json",
  ]) {
    const request = await json(join(requestDirectory, "invalid", name));
    assert.throws(() => assertQuerySchema(request, schema, "queryRequest"), name);
  }

  const reversed = await json(join(requestDirectory, "invalid", "reversed-byte-range.json"));
  assert.doesNotThrow(() => assertQuerySchema(reversed, schema, "queryRequest"));
  assert.throws(() => normalizeQueryRequest(reversed), /minimum_bytes/);
});

test("request normalization and domain-separated digest match fixed vectors", async () => {
  for (const stem of ["canonical-request", "canonical-unicode-request"]) {
    const request = await json(join(requestDirectory, "valid", `${stem}.json`));
    const normalized = await json(join(requestDirectory, "valid", `${stem}.normalized.json`));
    const expectedDigest = (
      await readFile(join(requestDirectory, "valid", `${stem}.sha256`), "utf8")
    ).trim();
    assert.deepEqual(normalizeQueryRequest(request), normalized);
    assert.equal(queryRequestSha256(request), expectedDigest);
    const withCursor = {
      ...request,
      page: { ...request.page, cursor: "fbq1_b3BhcXVl" },
    };
    assert.equal(
      queryRequestSha256(withCursor),
      expectedDigest,
      `${stem}: cursor is not recursively digested`,
    );
  }
});

test("canonical Unicode request freezes U+2028 and U+2029 JSON behavior", async () => {
  const request = await json(join(requestDirectory, "valid", "canonical-unicode-request.json"));
  const paths = request.filters.paths.join("");
  assert.ok(paths.includes("\u2028"));
  assert.ok(paths.includes("\u2029"));
});

test("portable-path reference uses complete pinned Unicode tables", () => {
  assert.equal(FULL_DEFAULT_CASE_FOLD_V9.size, 1401);
  assert.equal(fullDefaultCaseFoldV9("ẞ"), "ss");
  assert.equal(fullDefaultCaseFoldV9("ß"), "ss");
  assert.equal(fullDefaultCaseFoldV9("𐒰"), "𐓘");
  assert.equal(unicode17Nfc("e\u0301"), "é");
  assert.equal(unicode17Nfc("\u1100\u1161"), "가");
  assert.equal(unicode17Nfc("a\u{1acf}\u0323"), "ạ\u{1acf}");
  const inventory = new PortablePathCollisionIndex();
  inventory.insert("unicode/ẞ.md");
  assert.throws(() => inventory.insert("unicode/ss.md"), /full default case folding/u);
  assert.deepEqual(
    [CANONICAL_COMBINING_CLASS_V17.size, CANONICAL_DECOMPOSITION_V17.size,
      CANONICAL_COMPOSITION_V17.size],
    [968, 13253, 12133],
  );
});

test("checked-in Unicode table artifacts have pinned reproducible provenance", async () => {
  for (const [name, expected] of [
    ["unicode-casefold-v9-data.mjs", "72c69c88d27d3e7802dee055fb6b862a363ef95b85266e491056f5948b0e3883"],
    ["unicode-nfc-v17-data.mjs", "f225c5ff043797c5d95901a358383caef126ebb99bb259a5da6439f618a897d7"],
  ]) {
    const bytes = await readFile(join(directory, name));
    assert.equal(createHash("sha256").update(bytes).digest("hex"), expected);
  }
});

test("canonical JSON bytes freeze key order, Unicode, and every JSON string escape", () => {
  assert.equal(
    canonicalJsonBytes({
      z: "line\nquote\"slash\\tab\treturn\rback\bform\fzero\u0000",
      a: "é/東京/😀/\u2028/\u2029",
      integer: 10737418240,
      boolean: true,
      nothing: null,
      array: ["\u0001", false, 0],
    }).toString("utf8"),
    "{\"z\":\"line\\nquote\\\"slash\\\\tab\\treturn\\rback\\bform\\fzero\\u0000\",\"a\":\"é/東京/😀/ / \",\"integer\":10737418240,\"boolean\":true,\"nothing\":null,\"array\":[\"\\u0001\",false,0]}",
  );
});

test("portable query paths inherit the complete Folderbase portable-path policy", () => {
  for (const valid of ["repo/.git/HEAD", "unicode/é.md", "space inside/name.txt"]) {
    assert.doesNotThrow(() => validatePortablePath(valid), valid);
  }
  for (const invalid of [
    "/absolute",
    "C:/drive",
    "back\\slash",
    "double//separator",
    "dot/./entry",
    "parent/../entry",
    "trailing/",
    "trailing-dot.",
    "trailing-space ",
    "control/line\nfeed",
    "reserved/.FOLDERBASE/state",
    "reserved/COM1.txt",
    "reserved/LPT².log",
    "forbidden/question?.txt",
    "bad/\ud800.txt",
    "x".repeat(256),
    `${"é".repeat(128)}/x`,
    Array.from({ length: 129 }, () => "x").join("/"),
    `${"é".repeat(2048)}/x`,
  ]) assert.throws(() => validatePortablePath(invalid), invalid);

  assert.throws(
    () => normalizeQueryRequest({
      format: "folderbase-query-request-v1",
      scope: { kind: "live" },
      filters: { paths: ["Notes/Brief.md", "notes/brief.md"] },
      page: { limit: 10 },
    }),
    /collision/u,
  );
  assert.throws(
    () => normalizeQueryRequest({
      format: "folderbase-query-request-v1",
      scope: { kind: "live" },
      filters: { paths: ["unicode/é.md", "unicode/e\u0301.md"] },
      page: { limit: 10 },
    }),
    /collision/u,
  );
  for (const collision of [
    ["unicode/ạ᫏", "unicode/a᫏̣"],
    ["unicode/𐒰", "unicode/𐓘"],
    ["unicode/straße.md", "unicode/strasse.md"],
  ]) {
    assert.throws(
      () => normalizeQueryRequest({
        format: "folderbase-query-request-v1",
        scope: { kind: "live" },
        filters: { paths: collision },
        page: { limit: 10 },
      }),
      /collision/u,
    );
  }
});

test("prefix matching is component-aware", () => {
  assert.equal(pathMatchesPrefix("data", "data"), true);
  assert.equal(pathMatchesPrefix("data/table.csv", "data"), true);
  assert.equal(pathMatchesPrefix("database.md", "data"), false);
  assert.equal(pathMatchesPrefix("data-old/table.csv", "data"), false);
});

test("mixed fixture covers every opaque file shape and a simulated 10 GiB asset", async () => {
  const fixture = await json(join(fixtureDirectory, "mixed-observations.json"));
  const formats = new Set(fixture.entries.map((entry) => entry.representative_format));
  for (const format of [
    "repository",
    "markdown",
    "pdf",
    "csv",
    "sqlite",
    "video",
    "symlink",
    "sparse-10-gib-video-metadata",
    "opaque-boundary",
  ]) assert.ok(formats.has(format), format);
  assert.equal(
    fixture.entries.find((entry) => entry.representative_format === "sparse-10-gib-video-metadata").bytes,
    10 * 1024 * 1024 * 1024,
  );
  assert.equal(fixture.ordinary_content_access, "metadata_only");
});

test("sparse fixture allocation uses POSIX blocks but only logical size on Windows", () => {
  const bytes = 10 * 1024 * 1024 * 1024;
  assert.doesNotThrow(() =>
    assertSparseFixture({ size: BigInt(bytes), blocks: 8n }, bytes, "linux"));
  assert.throws(
    () => assertSparseFixture({ size: BigInt(bytes), blocks: BigInt(bytes) }, bytes, "linux"),
    /sparsely allocated below 16 MiB/u,
  );
  assert.doesNotThrow(() =>
    assertSparseFixture({ size: BigInt(bytes), blocks: BigInt(bytes) }, bytes, "win32"));
  assert.throws(
    () => assertSparseFixture({ size: BigInt(bytes - 1), blocks: 0n }, bytes, "win32"),
    /Expected values to be strictly equal/u,
  );
});

test("Windows marks the large fixture sparse before assigning its logical length", () => {
  const calls = [];
  markSparseFileForLogicalSizing("C:\\fixture\\archive.mov", "win32", (...args) => {
    calls.push(args);
    return { status: 0, stderr: "" };
  });
  assert.deepEqual(calls, [[
    "fsutil",
    ["sparse", "setflag", "C:\\fixture\\archive.mov"],
    { encoding: "utf8", windowsHide: true },
  ]]);
  assert.throws(
    () => markSparseFileForLogicalSizing("C:\\fixture\\archive.mov", "win32", () => ({
      status: 1,
      stderr: "access denied",
    })),
    /access denied/u,
  );

  let nonWindowsCalls = 0;
  markSparseFileForLogicalSizing("/fixture/archive.mov", "linux", () => {
    nonWindowsCalls += 1;
    return { status: 0 };
  });
  assert.equal(nonWindowsCalls, 0);
});

test("public Gitignore corpus freezes ordered edge semantics", async () => {
  const corpus = await json(join(fixtureDirectory, "gitignore-edge-corpus.json"));
  const rules = compileGitignore([...corpus.engine_rules, ...corpus.folderbaseignore_lines]);
  for (const vector of corpus.cases) {
    assert.equal(
      ignoredByGitignore(vector.path, vector.is_directory, rules),
      vector.ignored,
      `${vector.feature}: ${vector.path}`,
    );
  }
  const pruning = corpus.parent_pruning;
  assert.equal(ignoredByGitignore(pruning.ignored_parent, true, rules), true);
  assert.equal(ignoredByGitignore(pruning.unignored_child, false, rules), false);
  assert.equal(
    !ignoredByGitignore(pruning.ignored_parent, true, rules) &&
      !ignoredByGitignore(pruning.unignored_child, false, rules),
    false,
    pruning.expected_traversal,
  );
  assert.notEqual(
    effectiveCaptureIgnoreDigest(corpus.engine_rules, Buffer.alloc(0), false),
    effectiveCaptureIgnoreDigest(corpus.engine_rules, Buffer.alloc(0), true),
    "absent and present-empty ignore policies have distinct v2 digests",
  );
});

test("historical fixture digest is fixed by the independent Version reference", async () => {
  const expected = (
    await readFile(join(fixtureDirectory, "historical-version.sha256"), "utf8")
  ).trim();
  const result = spawnSync(
    process.execPath,
    [
      resolve(repositoryRoot, "protocol/conformance/folderbase-version-0.5/reference-digest.mjs"),
      join(fixtureDirectory, "historical-version.json"),
    ],
    { encoding: "utf8" },
  );
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout.trim(), expected);
  const bytes = await readFile(join(fixtureDirectory, "historical-version.json"));
  const versionSchema = await json(resolve(repositoryRoot, "protocol/schemas/0.5/folderbase-version.schema.json"));
  assert.equal(verifyFolderbaseVersion05(bytes, versionSchema).canonicalDigest, expected);
  const schemaInvalid = JSON.parse(bytes);
  schemaInvalid.future = true;
  assert.throws(() => verifyFolderbaseVersion05(JSON.stringify(schemaInvalid), versionSchema));
  const semanticInvalid = JSON.parse(bytes);
  semanticInvalid.parents = [semanticInvalid.version_id];
  assert.throws(() => verifyFolderbaseVersion05(JSON.stringify(semanticInvalid), versionSchema), /own parent/u);
  const source = bytes.toString("utf8");
  assert.throws(
    () => verifyFolderbaseVersion05(source.replace('"format":', '"format":"folderbase-version-v1","format_duplicate":').replace('"format_duplicate"', '"format"'), versionSchema),
    /duplicate JSON object key/u,
  );
});

test("query-owned Version verifier accepts 0.5 corpus and rejects semantic corpus", async () => {
  const versionSchema = await json(resolve(repositoryRoot, "protocol/schemas/0.5/folderbase-version.schema.json"));
  const v05 = resolve(repositoryRoot, "protocol/conformance/folderbase-version-0.5");
  for (const name of await readdir(join(v05, "valid"))) {
    if (!name.endsWith(".json")) continue;
    const verified = verifyFolderbaseVersion05(await readFile(join(v05, "valid", name)), versionSchema);
    const expected = (await readFile(join(v05, "valid", name.replace(/\.json$/u, ".sha256")), "utf8")).trim();
    assert.equal(verified.canonicalDigest, expected, name);
  }
  for (const name of await readdir(join(v05, "invalid"))) {
    if (!name.endsWith(".json")) continue;
    const bytes = await readFile(join(v05, "invalid", name));
    assert.throws(() => verifyFolderbaseVersion05(bytes, versionSchema), name);
  }
  const legacy = resolve(repositoryRoot, "protocol/conformance/folderbase-version/invalid");
  for (const name of await readdir(legacy)) {
    if (!name.endsWith(".json") || name.startsWith("missing-")) continue;
    const value = await json(join(legacy, name));
    value.protocol_version = "0.5";
    assert.throws(() => verifyFolderbaseVersion05(JSON.stringify(value), versionSchema), name);
  }
});

test("minimal non-Rust candidate passes the complete black-box runner", () => {
  const result = run("conforming-candidate.mjs");
  assert.equal(result.status, 0, result.stderr || result.stdout);
  const report = JSON.parse(result.stdout);
  assert.equal(report.capability, "folderbase.query-index@0.1.0");
  assert.equal(report.failed, 0);
  assert.equal(report.passed, 24);
});

test("the runner hard-kills hanging and overproducing candidate commands", async () => {
  const ownershipRoot = await mkdtemp(join(tmpdir(), "folderbase-query-process-proof-"));
  try {
    for (const candidate of [
      "hanging-candidate.mjs",
      "forking-hanging-candidate.mjs",
      "noisy-candidate.mjs",
    ]) {
      const pidFile = join(ownershipRoot, `${candidate}.pid`);
      const started = Date.now();
      const result = run(candidate, {
        FOLDERBASE_QUERY_CONFORMANCE_COMMAND_MAX_BYTES: "4096",
        FOLDERBASE_QUERY_CONFORMANCE_COMMAND_TIMEOUT_MS: "250",
        FOLDERBASE_QUERY_CONFORMANCE_PID_FILE: pidFile,
      });
      assert.equal(result.status, 1, result.stderr || result.stdout);
      assert.ok(Date.now() - started < 5_000, `${candidate} was not bounded`);
      const report = JSON.parse(result.stdout);
      assert.equal(report.failed, 1);
      assert.match(report.cases[0].message, /timed out|output limit/u);
      const pids = (await readFile(pidFile, "utf8")).trim().split("\n").map(Number);
      for (const pid of pids) {
        assert.throws(
          () => process.kill(pid, 0),
          (error) => error?.code === "ESRCH",
          `${candidate} PID ${pid} survived its hard bound`,
        );
      }
    }
  } finally {
    await rm(ownershipRoot, { recursive: true, force: true });
  }
});

test("a candidate without query/index reports the intentional runtime gap", () => {
  const result = run("missing-query-candidate.mjs");
  assert.equal(result.status, 1, result.stderr || result.stdout);
  const report = JSON.parse(result.stdout);
  assert.equal(report.passed, 0);
  assert.equal(report.failed, 1);
  assert.equal(report.cases[0].id, "query-live-mixed-files-metadata-first");
  assert.match(report.cases[0].message, /intentionally not implemented/);
});

test("query capability remains outside Compatibility v1 and CLI JSON v1", async () => {
  const contract = await json(resolve(repositoryRoot, "protocol/compatibility/v1/contract.json"));
  const cliSchema = await json(
    resolve(repositoryRoot, "protocol/schemas/cli/1/folderbase-cli-json.schema.json"),
  );
  assert.ok(!contract.cli_json.commands.some((command) => command.startsWith("query")));
  assert.ok(!contract.cli_json.commands.some((command) => command.startsWith("index")));
  assert.ok(!Object.keys(cliSchema.$defs).some((name) => /^query|^index/u.test(name)));
});

test("capability package has the optional registry entry shape", async () => {
  const capability = await json(
    resolve(repositoryRoot, "protocol/capabilities/query-index/0.1.0/capability.json"),
  );
  assert.deepEqual(Object.keys(capability), [
    "name",
    "version",
    "stability",
    "conformance_runner",
  ]);
  assert.deepEqual(capability, {
    name: "folderbase.query-index",
    version: "0.1.0",
    stability: "experimental",
    conformance_runner: "protocol/conformance/capabilities/query-index-0.1/run.mjs",
  });
});

test("schema publishes every required capability document", () => {
  for (const definition of [
    "queryRequest",
    "queryResult",
    "queryExplain",
    "indexStatus",
    "indexRebuildResult",
    "queryCursor",
    "queryAttention",
    "queryError",
  ]) assert.ok(schema.$defs[definition], definition);
  assert.doesNotThrow(() => assertQuerySchema({
    format: "folderbase-query-error-v1",
    error: { code: "query_scope_version_missing", message: "missing" },
  }, schema, "queryError"));

  const nested = {
    path: "vendors/nested",
    kind: "nested_folderbase",
    lifecycle: "live",
    bytes: null,
    object_id: null,
    object_version_id: null,
    folderbase_version_id: null,
    source: "capture_plan",
    boundary_reason: "nested-folderbase-boundary",
  };
  assert.doesNotThrow(() => assertQuerySchema(nested, schema, "queryEntry"));
  assert.throws(
    () => assertQuerySchema({ ...nested, bytes: 1 }, schema, "queryEntry"),
    /branch|constant/u,
  );
  const { boundary_reason: _boundaryReason, ...missingBoundary } = nested;
  assert.throws(() => assertQuerySchema(missingBoundary, schema, "queryEntry"));
  assert.throws(() => assertQuerySchema({
    ...nested,
    kind: "directory",
  }, schema, "queryEntry"));

  const normalized = schema.$defs.normalizedRequest.properties.filters.properties;
  for (const [field, maximum] of [
    ["paths", 256], ["path_prefixes", 256], ["kinds", 4], ["lifecycles", 2],
    ["object_ids", 256], ["object_version_ids", 256],
  ]) {
    assert.equal(normalized[field].maxItems, maximum, field);
    assert.equal(normalized[field].uniqueItems, true, field);
  }
});

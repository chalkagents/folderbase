#!/usr/bin/env node

import assert from "node:assert/strict";
import {randomUUID, createHash} from "node:crypto";
import {mkdtemp, mkdir, writeFile, readFile, readdir, cp, rm, stat} from "node:fs/promises";
import {tmpdir} from "node:os";
import {join, resolve, extname} from "node:path";
import {spawnSync} from "node:child_process";

const argv = process.argv.slice(2);
assert.equal(argv.length, 2, "usage: run.mjs --implementation /path/to/folderbase");
assert.equal(argv[0], "--implementation");
const implementation = resolve(argv[1]);
const milliseconds = Number(process.env.FOLDERBASE_CAPABILITY_COMMAND_TIMEOUT_MS ?? 120000);
assert.ok(Number.isSafeInteger(milliseconds) && milliseconds > 0 && milliseconds <= 2147483647);
function execute(args, input) {
  const node = [".js", ".cjs", ".mjs"].includes(extname(implementation));
  const result = spawnSync(node ? process.execPath : implementation, node ? [implementation, ...args] : args, {
    input, encoding: "utf8", maxBuffer: 8 * 1024 * 1024, timeout: milliseconds, killSignal: "SIGKILL",
  });
  if (result.error) throw result.error;
  return result;
}
function ok(args, input) {
  const result = execute(args, input);
  assert.equal(result.status, 0, result.stderr || result.stdout);
  assert.equal(result.stderr, "");
  return JSON.parse(result.stdout);
}
function refused(args, input) {
  const result = execute(args, input);
  assert.equal(result.status, 2, result.stderr || result.stdout);
  assert.equal(result.stdout, "");
  assert.equal(typeof JSON.parse(result.stderr).error.code, "string");
}
const sha = bytes => createHash("sha256").update(bytes).digest("hex");
async function snapshot(root, prefix = "") {
  const files = {};
  for (const entry of await readdir(join(root, prefix), {withFileTypes: true})) {
    const path = join(prefix, entry.name);
    if (entry.isDirectory()) Object.assign(files, await snapshot(root, path));
    else files[path] = sha(await readFile(join(root, path)));
  }
  return files;
}
const fixture = await mkdtemp(join(tmpdir(), "folderbase-local-export-"));
const source = join(fixture, "source");
const packagePath = join(fixture, "package");
const restored = join(fixture, "restored");
const report = {format: "folderbase-capability-suite-report-v1", capability: "folderbase.local-export@0.1.0", implementation, passed: 0, failed: 0, cases: []};
let exported; let restoreRequest; let sourceHistory;
const cases = [
  {id: "current-export-pins-complete-history-and-selected-git-bytes", async run() {
    await mkdir(join(source, "tasks"), {recursive: true});
    await mkdir(join(source, "nested/.GIT"), {recursive: true});
    await writeFile(join(source, "tasks/a.json"), '{"title":"first"}\n');
    await writeFile(join(source, "nested/.GIT/HEAD"), "ref: refs/heads/main\n");
    await writeFile(join(source, ".gitignore"), "target/\n");
    await writeFile(join(source, "attachment.bin"), Buffer.from([0, 1, 255, 2]));
    ok(["init", source, "--json"]);
    const first = ok(["export", "create", source, join(fixture, "initial"), "--json"]);
    assert.equal(first.retention_profile, "selected-snapshot-file-history-v1");
    const read = ok(["workspace", "read", source, "tasks/a.json", "--json"]);
    ok(["workspace", "save", source, "tasks/a.json", "--expected-sha256", read.sha256, "--stdin", "--json"], '{"title":"second"}\n');
    exported = ok(["export", "create", source, packagePath, "--json"]);
    sourceHistory = ok(["version", "list", source, "tasks/a.json", "--json"]);
    assert.ok(sourceHistory.versions.length >= 2);
    assert.equal(exported.retained_objects, 3);
    assert.deepEqual(exported.snapshot_only_reserved_paths.map(({path}) => path), ["nested/.GIT/HEAD"]);
    assert.deepEqual(exported.omitted_objects, []);
    assert.match(exported.export_index_sha256, /^[0-9a-f]{64}$/u);
    assert.equal(sha(await readFile(join(packagePath, "export.json"))), exported.export_index_sha256);
    restoreRequest = {operation_id: `reconstruction_${randomUUID()}`, export_index_sha256: exported.export_index_sha256};
  }},
  {id: "clean-process-restore-retains-history-replays-and-continues", async run() {
    const before = await snapshot(source);
    const result = ok(["export", "restore", packagePath, restored, "--stdin", "--json"], JSON.stringify(restoreRequest));
    assert.equal(result.replayed, false);
    assert.deepEqual(ok(["version", "list", restored, "tasks/a.json", "--json"]), sourceHistory);
    assert.deepEqual(await readFile(join(restored, "attachment.bin")), Buffer.from([0, 1, 255, 2]));
    assert.equal(await readFile(join(restored, "nested/.GIT/HEAD"), "utf8"), "ref: refs/heads/main\n");
    assert.equal(ok(["export", "restore", packagePath, restored, "--stdin", "--json"], JSON.stringify(restoreRequest)).replayed, true);
    const read = ok(["workspace", "read", restored, "tasks/a.json", "--json"]);
    ok(["workspace", "save", restored, "tasks/a.json", "--expected-sha256", read.sha256, "--stdin", "--json"], '{"title":"continued"}\n');
    await writeFile(join(restored, "tasks/new.json"), '{"title":"new task"}\n');
    await writeFile(join(restored, "new-attachment.bin"), Buffer.from([9, 0, 8]));
    ok(["export", "create", restored, join(fixture, "continued"), "--json"]);
    const after = ok(["version", "list", restored, "tasks/a.json", "--json"]);
    assert.equal(after.object_id, sourceHistory.object_id);
    assert.deepEqual(after.versions.slice(0, sourceHistory.versions.length), sourceHistory.versions);
    assert.equal(await readFile(join(restored, "nested/.GIT/HEAD"), "utf8"), "ref: refs/heads/main\n");
    assert.ok(ok(["version", "list", restored, "tasks/new.json", "--json"]).object_id);
    assert.ok(ok(["version", "list", restored, "new-attachment.bin", "--json"]).object_id);
    ok(["version", "restore", restored, sourceHistory.versions[0].id, "recovered-first.json", "--json"]);
    assert.equal(await readFile(join(restored, "recovered-first.json"), "utf8"), '{"title":"first"}\n');
    refused(["export", "restore", packagePath, restored, "--stdin", "--json"], JSON.stringify(restoreRequest));
    assert.equal(await readFile(join(restored, "tasks/a.json"), "utf8"), '{"title":"continued"}\n');
    assert.deepEqual(await snapshot(source), before);
  }},
  {id: "copied-archive-explicit-version-export-without-head-adoption", async run() {
    const copied = join(fixture, "copied"); await cp(source, copied, {recursive: true});
    const before = await snapshot(copied);
    const versions = ok(["export", "list", copied, "--json"]);
    assert.ok(versions.versions.some(({version_id}) => version_id === exported.folderbase_version_id));
    const archiveExport = ok(["export", "create", copied, join(fixture, "archive-export"), "--version", exported.folderbase_version_id, "--json"]);
    assert.equal(archiveExport.selection, "retained_version");
    assert.deepEqual(await snapshot(copied), before);
    const request = {operation_id: `reconstruction_${randomUUID()}`, export_index_sha256: archiveExport.export_index_sha256};
    const destination = join(fixture, "archive-restored");
    ok(["export", "restore", join(fixture, "archive-export"), destination, "--stdin", "--json"], JSON.stringify(request));
    assert.deepEqual(ok(["version", "list", destination, "tasks/a.json", "--json"]), sourceHistory);
  }},
  {id: "existing-package-and-malformed-restore-refuse-without-side-effects", async run() {
    const before = await snapshot(source); const packageBefore = await snapshot(packagePath);
    refused(["export", "create", source, packagePath, "--json"]);
    assert.deepEqual(await snapshot(source), before); assert.deepEqual(await snapshot(packagePath), packageBefore);
    const destination = join(fixture, "invalid-request");
    refused(["export", "restore", packagePath, destination, "--stdin", "--json"], JSON.stringify({...restoreRequest, unknown: true}));
    await assert.rejects(stat(destination), {code: "ENOENT"});
  }},
  {id: "history-only-package-corruption-never-publishes-root", async run() {
    const corrupted = join(fixture, "corrupt"); await cp(packagePath, corrupted, {recursive: true});
    const history = JSON.parse(await readFile(join(corrupted, "history/index.json"), "utf8"));
    const earlier = sourceHistory.versions[0];
    const manifest = JSON.parse(await readFile(join(corrupted, "history/manifests", `${history.manifests[earlier.id]}.json`), "utf8"));
    await writeFile(join(corrupted, "history/chunks", manifest.chunks[0].sha256), "corrupt");
    const destination = join(fixture, "corrupt-restored");
    refused(["export", "restore", corrupted, destination, "--stdin", "--json"], JSON.stringify(restoreRequest));
    await assert.rejects(stat(destination), {code: "ENOENT"});
  }},
];
try {
  for (const testCase of cases) {
    const result = {id: testCase.id, status: "passed"};
    try {await testCase.run(); report.passed += 1;}
    catch (error) {result.status = "failed"; result.message = error.message; report.failed += 1;}
    report.cases.push(result);
    if (result.status === "failed") break;
  }
} finally {await rm(fixture, {recursive: true, force: true});}
process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
process.exitCode = report.failed ? 1 : 0;

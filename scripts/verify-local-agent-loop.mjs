import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { existsSync, mkdtempSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const args = process.argv.slice(2);
function option(name) {
  const index = args.indexOf(name);
  return index < 0 ? undefined : args[index + 1];
}
const implementation = resolve(option("--implementation") ?? "target/debug/folderbase");
const legacy = option("--legacy-implementation");
const owner = mkdtempSync(join(tmpdir(), "folderbase-local-agent-loop-"));
const steps = [];

function call(binary, arguments_, input) {
  const result = spawnSync(binary, arguments_, {
    input: input === undefined ? undefined : `${JSON.stringify(input)}\n`,
    encoding: "utf8",
    timeout: 30_000,
    maxBuffer: 8 * 1024 * 1024,
  });
  if (result.error) throw result.error;
  return { exit: result.status, document: JSON.parse(result.stdout || result.stderr) };
}

function ok(arguments_, input, binary = implementation) {
  const result = call(binary, arguments_, input);
  assert.equal(result.exit, 0, JSON.stringify(result));
  return result.document;
}

function setup(name, binary = implementation) {
  const directory = join(owner, name);
  const root = join(directory, "source");
  mkdirSync(join(root, "shared"), { recursive: true });
  mkdirSync(join(root, "private"));
  writeFileSync(join(root, "shared/brief.md"), "Research three practical agent workflows.\n");
  writeFileSync(join(root, "private/budget.txt"), "Private customer budget.\n");
  const initialized = ok(["init", root, "--json"], undefined, binary);
  return { directory, root, folderbaseId: initialized.folderbase_id };
}

function checkout(fixture, name, binary = implementation) {
  const path = join(fixture.directory, name);
  // Synthetic local scope evidence: these IDs are not hosted grants or credentials.
  ok(["change-set", "checkout", fixture.root, path, "--stdin", "--json"], {
    format: "folderbase-checkout-request-v1",
    folderbase_id: fixture.folderbaseId,
    projection_id: `projection_${randomUUID()}`,
    folder_scope_id: `folderscope_${randomUUID()}`,
    scope_revision_sha256: "1".repeat(64),
    permission: "can_work",
    authorized_paths: [{ path_prefix: "shared" }],
  }, binary);
  assert.equal(existsSync(join(path, "private")), false);
  return path;
}

function propose(fixture, working, name, binary = implementation) {
  const staging = join(fixture.directory, name);
  const envelope = ok(["change-set", "propose", working, staging, "--json"], undefined, binary);
  const assessment = ok(["change-set", "assess", fixture.root, staging, "--stdin", "--json"], envelope, binary);
  assert.equal(assessment.status, "clean");
  return { staging, envelope };
}

function apply(fixture, proposal) {
  const args = ["change-set", "apply", fixture.root, proposal.staging, "--stdin", "--json"];
  assert.equal(ok(args, proposal.envelope).status, "applied");
  assert.equal(ok(args, proposal.envelope).status, "already_applied");
}

try {
  const fixture = setup("working-loop");
  steps.push("Initialized an existing ordinary folder in place.");
  const first = checkout(fixture, "session-one");
  writeFileSync(join(first, "shared/brief.md"), "Research complete; see report.md.\n");
  const firstReport = "# Agent research\n\n1. Research\n2. Drafting\n3. Review\n";
  writeFileSync(join(first, "shared/report.md"), firstReport);
  const proposal = propose(fixture, first, "stage-one");
  const created = proposal.envelope.payload.deltas.find(({ before, after }) => before === null && after.path === "shared/report.md");
  assert.ok(created, "first proposal creates a new artifact");
  apply(fixture, proposal);
  assert.equal(readFileSync(join(fixture.root, "shared/report.md"), "utf8"), firstReport);
  steps.push("Reviewed and applied a source edit plus a new agent report; replay was idempotent.");

  const saved = ok(["version", "capture", fixture.root, "shared/report.md", "--json"]);
  const second = checkout(fixture, "session-two");
  assert.equal(readFileSync(join(second, "shared/report.md"), "utf8"), firstReport);
  writeFileSync(join(second, "shared/report.md"), `${firstReport}\nSecond session verified the recommendations.\n`);
  const continuation = propose(fixture, second, "stage-two");
  const revised = continuation.envelope.payload.deltas.find(({ after }) => after?.path === "shared/report.md");
  assert.equal(revised.object_id, created.object_id, "new artifact identity survives into the next session");
  apply(fixture, continuation);
  steps.push("A second fresh session continued the created report under the same Object ID.");

  ok(["version", "restore", fixture.root, saved.version.id, "shared/recovered-report.md", "--json"]);
  assert.equal(readFileSync(join(fixture.root, "shared/recovered-report.md"), "utf8"), firstReport);
  const noClobber = call(implementation, ["version", "restore", fixture.root, saved.version.id, "shared/recovered-report.md", "--json"]);
  assert.notEqual(noClobber.exit, 0);
  assert.equal(readFileSync(join(fixture.root, "shared/recovered-report.md"), "utf8"), firstReport);
  assert.equal(readFileSync(join(fixture.root, "private/budget.txt"), "utf8"), "Private customer budget.\n");
  ok(["validate", fixture.root, "--json"]);
  steps.push("Restored the first report to a separate path; an overwrite attempt failed without changing it.");

  let legacyRecovery;
  if (legacy !== undefined) {
    const oldBinary = resolve(legacy);
    const oldFixture = setup("legacy-pending", oldBinary);
    const working = checkout(oldFixture, "legacy-session", oldBinary);
    writeFileSync(join(working, "shared/result.md"), "Legacy proposed bytes.\n");
    const oldProposal = propose(oldFixture, working, "legacy-stage", oldBinary);
    const args = ["change-set", "apply", oldFixture.root, oldProposal.staging, "--stdin", "--json"];
    const failed = call(oldBinary, args, oldProposal.envelope);
    assert.equal(failed.exit, 2, "legacy fixture reproduces issue #78");
    const visibleBeforeRetry = readFileSync(join(oldFixture.root, "shared/result.md"), "utf8");
    const retry = call(implementation, args, oldProposal.envelope);
    assert.equal(retry.exit, 2, "this repair does not migrate legacy failed capture identities");
    assert.equal(readFileSync(join(oldFixture.root, "shared/result.md"), "utf8"), visibleBeforeRetry);
    legacyRecovery = { legacyApply: failed, patchedRetry: retry, proposedBytesPreserved: true, migrated: false };
  }
  const report = { status: "passed", implementation, fixture: owner, steps, legacyRecovery };
  writeFileSync(join(owner, "report.json"), `${JSON.stringify(report, null, 2)}\n`);
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
} catch (error) {
  process.stderr.write(`${JSON.stringify({ status: "failed", fixture: owner, steps, error: String(error) }, null, 2)}\n`);
  process.exitCode = 1;
}

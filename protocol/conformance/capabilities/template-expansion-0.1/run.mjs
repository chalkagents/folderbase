#!/usr/bin/env node

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, extname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { assertQuerySchema as assertCapabilitySchema } from "../query-index-0.1/schema.mjs";

const FORMAT = "folderbase-capability-suite-report-v1";
const CAPABILITY = "folderbase.template-expansion@0.1.0";
const MAX_INPUT_BYTES = 4 * 1024 * 1024;
const MAX_OUTPUT_BYTES = 8 * 1024 * 1024;
const DEFAULT_COMMAND_TIMEOUT_MS = 30_000;
const directory = dirname(fileURLToPath(import.meta.url));
const fixtures = join(directory, "fixtures");
const schema = JSON.parse(readFileSync(resolve(
  directory,
  "../../../schemas/capabilities/template-expansion/0.1/template-expansion.schema.json",
), "utf8"));

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
  "FOLDERBASE_TEMPLATE_CONFORMANCE_COMMAND_TIMEOUT_MS",
  DEFAULT_COMMAND_TIMEOUT_MS,
  100,
  300_000,
);
const commandMaxBytes = boundedEnvironmentInteger(
  "FOLDERBASE_TEMPLATE_CONFORMANCE_COMMAND_MAX_BYTES",
  MAX_OUTPUT_BYTES,
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

function execute(implementation, arguments_, input = "") {
  const command = [".js", ".cjs", ".mjs"].includes(extname(implementation))
    ? process.execPath
    : implementation;
  const args = command === process.execPath ? [implementation, ...arguments_] : arguments_;
  const payload = JSON.stringify({
    command,
    args,
    input: Buffer.from(input).toString("base64"),
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

function treeSnapshot(root) {
  const entries = [];
  function visit(relative) {
    for (const name of readdirSync(join(root, relative)).sort((left, right) =>
      Buffer.compare(Buffer.from(left), Buffer.from(right)))) {
      const path = relative ? `${relative}/${name}` : name;
      const metadata = lstatSync(join(root, path));
      if (metadata.isDirectory()) {
        entries.push({ path, kind: "directory" });
        visit(path);
      } else if (metadata.isFile()) {
        entries.push({
          path,
          kind: "file",
          bytes: metadata.size,
          sha256: createHash("sha256").update(readFileSync(join(root, path))).digest("hex"),
        });
      } else {
        entries.push({ path, kind: "other" });
      }
    }
  }
  visit("");
  return entries;
}

function createRoot(owner, name) {
  const root = join(owner, name);
  mkdirSync(join(root, ".folderbase"), { recursive: true });
  writeFileSync(
    join(root, ".folderbase/manifest.json"),
    readFileSync(join(fixtures, "root-manifest.json")),
  );
  writeFileSync(join(root, "Existing.md"), "user-owned bytes stay exact\n");
  return root;
}

function success(implementation, arguments_, input, definition) {
  const result = execute(implementation, arguments_, input);
  assert.equal(result.status, 0, result.stderr || result.stdout);
  assert.equal(result.stderr, "", "successful commands leave stderr empty");
  const output = JSON.parse(result.stdout);
  assertCapabilitySchema(output, schema, definition);
  return output;
}

function attention(implementation, arguments_, input, code) {
  const result = execute(implementation, arguments_, input);
  assert.equal(result.status, 1, result.stderr || result.stdout);
  assert.equal(result.stderr, "", "attention outcomes leave stderr empty");
  const output = JSON.parse(result.stdout);
  assertCapabilitySchema(output, schema, "attention");
  assert.equal(output.attention.code, code);
  return output;
}

function operationalError(implementation, arguments_, input, code) {
  const result = execute(implementation, arguments_, input);
  assert.equal(result.status, 2, result.stderr || result.stdout);
  assert.equal(result.stdout, "", "operational failures leave stdout empty");
  const output = JSON.parse(result.stderr);
  assertCapabilitySchema(output, schema, "error");
  assert.equal(output.error.code, code);
  return output;
}

function plan(implementation, root, request) {
  const before = treeSnapshot(root);
  const output = success(
    implementation,
    ["template", "plan", root, "--stdin", "--json"],
    `${JSON.stringify(request)}\n`,
    "plan",
  );
  assert.deepEqual(treeSnapshot(root), before, "planning must be read-only");
  return output;
}

function apply(implementation, root, request, digest) {
  return success(
    implementation,
    ["template", "apply", root, "--expected-plan-digest", digest, "--stdin", "--json"],
    `${JSON.stringify(request)}\n`,
    "applyResult",
  );
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

async function main() {
  const implementation = implementationArgument(process.argv.slice(2));
  const owner = mkdtempSync(join(tmpdir(), "folderbase-template-expansion-"));
  const request = JSON.parse(readFileSync(join(fixtures, "request.json"), "utf8"));
  const cases = [];

  async function check(id, run) {
    const result = { id, status: "passed" };
    try {
      await run();
    } catch (error) {
      result.status = "failed";
      result.message = error instanceof Error ? error.message : String(error);
    }
    cases.push(result);
  }

  try {
    await check("template-parser-errors-use-the-typed-capability-envelope", () => {
      for (const arguments_ of [
        ["template", "plan", "--stdin", "--json"],
        ["template", "plan", createRoot(owner, "missing-stdin"), "--json"],
        ["template", "plan", createRoot(owner, "missing-json"), "--stdin"],
        ["template", "plan", createRoot(owner, "unknown-flag"), "--stdin", "--json", "--unknown-option"],
        ["template", "unknown", createRoot(owner, "unknown-command"), "--stdin", "--json"],
      ]) {
        operationalError(implementation, arguments_, "", "invalid_template_request");
      }
    });

    await check("plan-is-bounded-read-only-and-preserves-existing-paths", () => {
      const root = createRoot(owner, "plan");
      const output = plan(implementation, root, request);
      assert.equal(output.disposition, "ready");
      assert.deepEqual(output.preserved_paths, ["Existing.md"]);
      assert.deepEqual(output.additions.map(({ path }) => path), ["Notes", "Notes/README.md"]);
    });

    await check("apply-replans-approved-digest-and-never-clobbers", () => {
      const root = createRoot(owner, "apply");
      const planned = plan(implementation, root, request);
      const output = apply(implementation, root, request, planned.plan_digest.digest);
      assert.equal(output.status, "applied");
      assert.deepEqual(output.created_paths, ["Notes", "Notes/README.md"]);
      assert.equal(readFileSync(join(root, "Existing.md"), "utf8"), "user-owned bytes stay exact\n");
      assert.equal(
        readFileSync(join(root, "Notes/README.md"), "utf8"),
        "# Notes\n\nKeep agent context understandable across time.\n",
      );
    });

    await check("idempotent-replay-is-a-noop-without-duplicate-history", () => {
      const root = createRoot(owner, "replay");
      const first = plan(implementation, root, request);
      apply(implementation, root, request, first.plan_digest.digest);
      const history = join(root, ".folderbase/template-applications");
      const before = readdirSync(history).sort();
      const replay = plan(implementation, root, request);
      assert.equal(replay.disposition, "noop");
      const output = apply(implementation, root, request, replay.plan_digest.digest);
      assert.equal(output.status, "noop");
      assert.deepEqual(readdirSync(history).sort(), before);
    });

    await check("stale-approved-digest-fails-before-template-writes", () => {
      const root = createRoot(owner, "stale");
      const planned = plan(implementation, root, request);
      const manifest = join(root, ".folderbase/manifest.json");
      writeFileSync(manifest, `${readFileSync(manifest, "utf8")}\n`);
      const before = treeSnapshot(root);
      attention(
        implementation,
        ["template", "apply", root, "--expected-plan-digest", planned.plan_digest.digest, "--stdin", "--json"],
        `${JSON.stringify(request)}\n`,
        "expected_plan_digest_mismatch",
      );
      assert.deepEqual(treeSnapshot(root), before);
    });

    await check("lineage-and-transition-changes-hand-off-to-reorganization", () => {
      const root = createRoot(owner, "structural");
      const initial = plan(implementation, root, request);
      apply(implementation, root, request, initial.plan_digest.digest);
      const different = clone(request);
      different.template.id = "other.project";
      const structural = plan(implementation, root, different);
      assert.equal(structural.disposition, "reorganization_required");
      assert.equal(structural.structural_changes[0].kind, "lineage");
      attention(
        implementation,
        ["template", "apply", root, "--expected-plan-digest", structural.plan_digest.digest, "--stdin", "--json"],
        `${JSON.stringify(different)}\n`,
        "reorganization_required",
      );
    });

    await check("portable-path-aliases-use-nfc17-and-full-fold9", () => {
      const invalid = clone(request);
      invalid.template.artifacts = [
        { target: "Straße.md", kind: "text", content: "one\n", install: "create_if_missing" },
        { target: "STRASSE.md", kind: "text", content: "two\n", install: "create_if_missing" },
      ];
      operationalError(
        implementation,
        ["template", "plan", createRoot(owner, "fold"), "--stdin", "--json"],
        `${JSON.stringify(invalid)}\n`,
        "invalid_template_request",
      );
      const nfc = clone(request);
      nfc.template.artifacts = [
        { target: "é.md", kind: "text", content: "one\n", install: "create_if_missing" },
        { target: "e\u0301.md", kind: "text", content: "two\n", install: "create_if_missing" },
      ];
      operationalError(
        implementation,
        ["template", "plan", createRoot(owner, "nfc"), "--stdin", "--json"],
        `${JSON.stringify(nfc)}\n`,
        "invalid_template_request",
      );
    });

    await check("stdin-is-bounded-before-json-decoding", () => {
      const root = createRoot(owner, "bounded");
      const prefix = "{\"format\":\"folderbase-template-expansion-request-v1\",\"padding\":\"";
      const suffix = "\"}";
      const oversized = `${prefix}${"x".repeat(MAX_INPUT_BYTES + 1 - prefix.length - suffix.length)}${suffix}`;
      assert.equal(Buffer.byteLength(oversized), MAX_INPUT_BYTES + 1);
      operationalError(
        implementation,
        ["template", "plan", root, "--stdin", "--json"],
        oversized,
        "template_request_too_large",
      );
    });
  } finally {
    rmSync(owner, { recursive: true, force: true });
  }

  const failed = cases.filter(({ status }) => status === "failed").length;
  const report = {
    format: FORMAT,
    capability: CAPABILITY,
    implementation,
    passed: cases.length - failed,
    failed,
    cases,
  };
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  process.exitCode = failed === 0 ? 0 : 1;
}

main().catch((error) => {
  process.stderr.write(`${error instanceof Error ? error.stack : String(error)}\n`);
  process.exitCode = 2;
});

#!/usr/bin/env node

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { basename, dirname, extname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

import { assertJsonSchema } from "../cli-json-v1/schema.mjs";

const FORMAT = "folderbase-capability-conformance-report-v1";
const PROFILE_NAME = /^[a-z0-9]+(?:[.-][a-z0-9]+)*$/;
const SEMVER = /^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$/;
const DEFAULT_DISCOVERY_TIMEOUT_MS = 15_000;
const DEFAULT_SUITE_TIMEOUT_MS = 300_000;
const runnerDirectory = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = resolve(runnerDirectory, "../../..");
const registry = JSON.parse(
  await readFile(resolve(runnerDirectory, "../../capabilities/v1/registry.json"), "utf8"),
);
const cliSchema = JSON.parse(
  await readFile(resolve(runnerDirectory, "../../schemas/cli/1/folderbase-cli-json.schema.json"), "utf8"),
);

function parseArguments(argv) {
  let implementation;
  const requested = [];
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--implementation" && !implementation && argv[index + 1]) {
      implementation = resolve(argv[index + 1]);
      index += 1;
    } else if (argument === "--capability" && argv[index + 1]) {
      requested.push(argv[index + 1]);
      index += 1;
    } else {
      throw new Error(
        "usage: run.mjs --implementation /path/to/folderbase [--capability NAME@VERSION]",
      );
    }
  }
  if (!implementation) {
    throw new Error(
      "usage: run.mjs --implementation /path/to/folderbase [--capability NAME@VERSION]",
    );
  }
  return { implementation, requested };
}

function implementationCommand(implementation, arguments_) {
  if ([".js", ".cjs", ".mjs"].includes(extname(implementation))) {
    return [process.execPath, [implementation, ...arguments_]];
  }
  return [implementation, arguments_];
}

function configuredTimeout(name, fallback) {
  const value = process.env[name];
  if (value === undefined) return fallback;
  const milliseconds = Number(value);
  if (
    !/^[1-9][0-9]*$/.test(value)
    || !Number.isSafeInteger(milliseconds)
    || milliseconds > 2_147_483_647
  ) {
    throw new Error(`${name} must be a positive integer`);
  }
  return milliseconds;
}

function throwIfTimedOut(result, label, timeoutMs) {
  if (result.error?.code === "ETIMEDOUT") {
    throw new Error(`${label} timed out after ${timeoutMs}ms`);
  }
  if (result.error) throw result.error;
}

function executeImplementation(implementation, arguments_, timeoutMs) {
  const [command, args] = implementationCommand(implementation, arguments_);
  const result = spawnSync(command, args, {
    encoding: "utf8",
    killSignal: "SIGKILL",
    maxBuffer: 8 * 1024 * 1024,
    timeout: timeoutMs,
  });
  throwIfTimedOut(result, "capability discovery", timeoutMs);
  return result;
}

function selector(profile) {
  return `${profile.name}@${profile.version}`;
}

function assertProfile(profile, label) {
  assert.ok(profile && typeof profile === "object" && !Array.isArray(profile), label);
  assert.match(profile.name, PROFILE_NAME, `${label}.name`);
  assert.match(profile.version, SEMVER, `${label}.version`);
  assert.ok(
    profile.stability === "stable" || profile.stability === "experimental",
    `${label}.stability`,
  );
}

function validateRegistry() {
  assert.equal(registry.format, "folderbase-capability-registry-v1");
  assert.ok(Array.isArray(registry.capabilities));
  const selectors = registry.capabilities.map((profile, index) => {
    assertProfile(profile, `registry.capabilities[${index}]`);
    assert.equal(typeof profile.conformance_runner, "string");
    assert.match(
      profile.conformance_runner,
      /^protocol\/conformance\/(?:[a-z0-9-]+(?:\.[a-z0-9-]+)*\/)+run\.mjs$/,
    );
    return selector(profile);
  });
  assert.deepEqual(selectors, [...new Set(selectors)].sort(), "registry order is canonical");
}

function discover(implementation, timeoutMs) {
  const result = executeImplementation(
    implementation,
    ["protocol", "contract", "--json"],
    timeoutMs,
  );
  assert.equal(result.status, 0, result.stderr || result.stdout);
  assert.equal(result.stderr, "", "capability discovery leaves stderr empty");
  const descriptor = JSON.parse(result.stdout);
  assertJsonSchema(descriptor, cliSchema, "compatibilityDescriptor");
  const capabilities = descriptor.capabilities ?? [];
  assert.ok(Array.isArray(capabilities));
  const selectors = capabilities.map((profile, index) => {
    assertProfile(profile, `capabilities[${index}]`);
    return selector(profile);
  });
  assert.deepEqual(selectors, [...new Set(selectors)].sort(), "capability order is canonical");
  return capabilities;
}

function runCapability(profile, implementation, timeoutMs) {
  const runner = resolve(repositoryRoot, profile.conformance_runner);
  const result = spawnSync(
    process.execPath,
    [runner, "--implementation", implementation],
    {
      encoding: "utf8",
      killSignal: "SIGKILL",
      maxBuffer: 16 * 1024 * 1024,
      timeout: timeoutMs,
    },
  );
  throwIfTimedOut(result, `capability suite ${selector(profile)}`, timeoutMs);
  assert.equal(result.status, 0, result.stderr || result.stdout);
  const report = JSON.parse(result.stdout);
  assert.equal(report.failed, 0);
  return report;
}

let inputs;
let timeouts;
try {
  validateRegistry();
  inputs = parseArguments(process.argv.slice(2));
  timeouts = {
    discovery: configuredTimeout(
      "FOLDERBASE_CAPABILITY_DISCOVERY_TIMEOUT_MS",
      DEFAULT_DISCOVERY_TIMEOUT_MS,
    ),
    suite: configuredTimeout(
      "FOLDERBASE_CAPABILITY_SUITE_TIMEOUT_MS",
      DEFAULT_SUITE_TIMEOUT_MS,
    ),
  };
} catch (error) {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exit(2);
}

const known = new Map(registry.capabilities.map((profile) => [selector(profile), profile]));
for (const requested of inputs.requested) {
  if (!known.has(requested)) {
    process.stderr.write(`unknown capability profile: ${requested}\n`);
    process.exit(2);
  }
}

const report = {
  format: FORMAT,
  implementation: basename(inputs.implementation),
  advertised: [],
  ignored: [],
  requested: [...inputs.requested],
  selected: 0,
  passed: 0,
  failed: 0,
  cases: [],
};

try {
  const advertised = discover(inputs.implementation, timeouts.discovery);
  report.advertised = advertised.map(selector);
  report.ignored = advertised.filter((profile) => !known.has(selector(profile))).map(selector);
  const advertisedBySelector = new Map(advertised.map((profile) => [selector(profile), profile]));

  for (const profile of advertised) {
    const expected = known.get(selector(profile));
    if (expected) {
      assert.equal(
        profile.stability,
        expected.stability,
        `${selector(profile)} stability does not match the registry`,
      );
    }
  }

  const selected = inputs.requested.length > 0
    ? inputs.requested.map((requested) => known.get(requested))
    : registry.capabilities.filter((profile) => advertisedBySelector.has(selector(profile)));
  report.selected = selected.length;

  for (const profile of selected) {
    const id = selector(profile);
    const result = { id, status: "passed" };
    try {
      assert.ok(advertisedBySelector.has(id), `${id} is not advertised by the implementation`);
      result.report = runCapability(profile, inputs.implementation, timeouts.suite);
      report.passed += 1;
    } catch (error) {
      result.status = "failed";
      result.message = error instanceof Error ? error.message : String(error);
      report.failed += 1;
    }
    report.cases.push(result);
  }
} catch (error) {
  report.failed += 1;
  report.cases.push({
    id: "discover-capabilities",
    status: "failed",
    message: error instanceof Error ? error.message : String(error),
  });
}

process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
process.exitCode = report.failed === 0 ? 0 : 1;

#!/usr/bin/env node

import assert from "node:assert/strict";
import { once } from "node:events";
import {
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { spawnSync } from "node:child_process";

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const sdkRoot = join(repositoryRoot, "packages", "sdk");
const expectedArchivePaths = [
  "LICENSE",
  "NOTICE",
  "README.md",
  "package.json",
  "src/index.d.ts",
  "src/index.js",
];

function implementationArgument(argv) {
  const flag = argv.indexOf("--implementation");
  if (flag === -1 || !argv[flag + 1] || argv.length !== 2) {
    throw new Error("usage: test-sdk-package.mjs --implementation /path/to/folderbase");
  }
  return resolve(argv[flag + 1]);
}

function execute(command, arguments_, options = {}) {
  const result = spawnSync(command, arguments_, {
    cwd: options.cwd,
    encoding: "utf8",
    env: options.env ?? process.env,
    input: options.input,
    killSignal: "SIGKILL",
    maxBuffer: options.maxBuffer ?? 32 * 1024 * 1024,
    shell: false,
    timeout: options.timeout ?? 10 * 60_000,
  });
  if (result.error) throw result.error;
  assert.equal(result.status, options.status ?? 0, result.stderr || result.stdout);
  return result;
}

function reportPassed(result, format) {
  const report = JSON.parse(result.stdout);
  assert.equal(report.format, format);
  assert.equal(report.failed, 0, result.stdout);
  return report;
}

function waitForEvent(session, timeoutMs = 15_000) {
  let timer;
  return Promise.race([
    once(session, "event").then(([event]) => event),
    new Promise((_, reject) => {
      timer = setTimeout(
        () => reject(new Error(`Folderbase daemon emitted no freshness hint within ${timeoutMs}ms`)),
        timeoutMs,
      );
    }),
  ]).finally(() => clearTimeout(timer));
}

const adapterSource = `#!/usr/bin/env node
import { FolderbaseClient, FolderbaseOperationalError } from "@folderbase/sdk";

const executable = process.env.FOLDERBASE_SDK_IMPLEMENTATION;
if (!executable) {
  process.stderr.write('{"format":"folderbase-error-v1","error":{"code":"sdk_configuration_missing","message":"FOLDERBASE_SDK_IMPLEMENTATION is required"}}\\n');
  process.exit(2);
}

const chunks = [];
for await (const chunk of process.stdin) chunks.push(chunk);
const client = new FolderbaseClient({
  executable,
  maxInputBytes: 64 * 1024 * 1024,
  maxOutputBytes: 64 * 1024 * 1024,
  timeoutMs: 10 * 60_000,
});

try {
  const result = await client.run(process.argv.slice(2), {
    stdin: Buffer.concat(chunks),
  });
  process.stdout.write(JSON.stringify(result.document) + "\\n");
  process.exitCode = result.exitCode;
} catch (error) {
  if (error instanceof FolderbaseOperationalError) {
    process.stderr.write(JSON.stringify(error.document) + "\\n");
    process.exitCode = 2;
  } else {
    process.stderr.write(JSON.stringify({
      format: "folderbase-error-v1",
      error: {
        code: error?.code ?? "sdk_adapter_failed",
        message: error instanceof Error ? error.message : String(error),
      },
    }) + "\\n");
    process.exitCode = 2;
  }
}
`;

const implementation = await realpath(implementationArgument(process.argv.slice(2)));
const owner = await mkdtemp(join(tmpdir(), "folderbase-sdk-package-"));

try {
  const packResult = execute(
    "npm",
    ["pack", "--json", "--pack-destination", owner],
    { cwd: sdkRoot },
  );
  const packed = JSON.parse(packResult.stdout);
  assert.equal(packed.length, 1);
  assert.deepEqual(
    packed[0].files.map(({ path }) => path).sort(),
    expectedArchivePaths,
    "the SDK archive must expose only the supported adapter surface",
  );
  const archive = join(owner, packed[0].filename);

  const consumer = join(owner, "consumer");
  await mkdir(consumer);
  await writeFile(join(consumer, "package.json"), JSON.stringify({
    name: "folderbase-sdk-clean-consumer",
    private: true,
    type: "module",
  }));
  execute(
    "npm",
    ["install", "--ignore-scripts", "--no-audit", "--no-fund", archive],
    { cwd: consumer },
  );

  const sdk = await import(pathToFileURL(
    join(consumer, "node_modules", "@folderbase", "sdk", "src", "index.js"),
  ));
  const client = new sdk.FolderbaseClient({
    executable: implementation,
    maxInputBytes: 64 * 1024 * 1024,
    maxOutputBytes: 64 * 1024 * 1024,
    timeoutMs: 10 * 60_000,
  });

  const root = join(owner, "ordinary-folder");
  await mkdir(join(root, "shared"), { recursive: true });
  await mkdir(join(root, "media"), { recursive: true });
  await mkdir(join(root, "data"), { recursive: true });
  await writeFile(join(root, "shared", "notes.md"), "base notes\n");
  await writeFile(join(root, "data", "records.csv"), "id,value\n1,alpha\n");
  await writeFile(join(root, "brief.pdf"), Buffer.from("%PDF-1.7\nfixture\n", "utf8"));
  await writeFile(join(root, "media", "demo.mov"), Buffer.alloc(1024, 7));

  const initialized = await client.init(root);
  assert.equal(initialized.kind, "success");
  const attestation = await client.attest(root);
  assert.equal(attestation.kind, "success");

  const queryRequest = {
    format: "folderbase-query-request-v1",
    scope: { kind: "live" },
    page: { limit: 1_000 },
  };
  const queried = await client.query(root, queryRequest);
  assert.equal(queried.kind, "success");
  const queriedPaths = queried.document.entries.map(({ path }) => path);
  for (const path of ["brief.pdf", "data/records.csv", "media/demo.mov", "shared/notes.md"]) {
    assert.ok(queriedPaths.includes(path), `query omitted ordinary file ${path}`);
  }

  const templateRequest = {
    format: "folderbase-template-expansion-request-v1",
    template: {
      $schema: "https://folderbase.ai/protocol/0.2/template.schema.json",
      protocol_version: "0.2.0",
      id: "sdk.clean-consumer",
      version: "1.0.0",
      name: "SDK clean-consumer guidance",
      suggested_folderbase_kind: "project",
      questions: [],
      artifacts: [{
        target: "Guide.md",
        kind: "text",
        content: "# Guide\n",
        install: "create_if_missing",
      }],
      upgrade_edges: [],
    },
    answers: {},
  };
  const templatePlan = await client.templatePlan(root, templateRequest);
  assert.equal(templatePlan.kind, "success");
  const templateApply = await client.templateApply(
    root,
    templatePlan.document.plan_digest.digest,
    templateRequest,
  );
  assert.equal(templateApply.kind, "success");
  assert.equal(await readFile(join(root, "Guide.md"), "utf8"), "# Guide\n");

  const checkout = join(owner, "checkout");
  const staging = join(owner, "staging");
  const checkoutRequest = {
    format: "folderbase-checkout-request-v1",
    folderbase_id: attestation.document.folderbase_id,
    projection_id: "projection_019f0000-0000-7000-8000-000000000001",
    folder_scope_id: "folderscope_019f0000-0000-7000-8000-000000000001",
    scope_revision_sha256: "1".repeat(64),
    permission: "can_work",
    authorized_paths: [{ path_prefix: "shared" }],
  };
  const checkedOut = await client.changeSetCheckout(root, checkout, checkoutRequest);
  assert.equal(checkedOut.kind, "success");
  await writeFile(join(checkout, "shared", "notes.md"), "updated through SDK\n");
  const proposed = await client.changeSetPropose(checkout, staging);
  assert.equal(proposed.kind, "success");
  const assessed = await client.changeSetAssess(root, staging, proposed.document);
  assert.equal(assessed.kind, "success");
  const applied = await client.changeSetApply(root, staging, proposed.document);
  assert.equal(applied.kind, "success");
  assert.equal(await readFile(join(root, "shared", "notes.md"), "utf8"), "updated through SDK\n");

  const session = await client.startDaemon(root);
  const firstEpoch = session.ready.epoch;
  try {
    const event = waitForEvent(session);
    const subscribed = await session.request("subscribe");
    assert.equal(subscribed.status, "ok");
    await writeFile(join(root, "shared", "daemon.txt"), "fresh\n");
    assert.ok(["workspace_changed", "rescan_required"].includes((await event).event));
    const daemonQuery = await session.request("query", queryRequest);
    assert.equal(daemonQuery.status, "ok");
    assert.ok(daemonQuery.document.entries.some(({ path }) => path === "shared/daemon.txt"));
    await session.shutdown();
  } finally {
    await session.stop().catch(() => {});
  }
  const restartedSession = await client.startDaemon(root);
  try {
    assert.notEqual(restartedSession.ready.epoch, firstEpoch);
    await restartedSession.shutdown();
  } finally {
    await restartedSession.stop().catch(() => {});
  }

  const adapter = join(consumer, "folderbase-sdk-adapter.js");
  await writeFile(adapter, adapterSource);
  await chmod(adapter, 0o755);
  const conformanceEnvironment = {
    ...process.env,
    FOLDERBASE_SDK_IMPLEMENTATION: implementation,
    FOLDERBASE_CAPABILITY_SUITE_TIMEOUT_MS: "600000",
  };
  const cliReport = execute(
    process.execPath,
    [
      join(repositoryRoot, "protocol", "conformance", "cli-json-v1", "run.mjs"),
      "--implementation",
      adapter,
    ],
    { env: conformanceEnvironment },
  );
  reportPassed(cliReport, "folderbase-conformance-report-v1");

  const capabilityReport = execute(
    process.execPath,
    [
      join(repositoryRoot, "protocol", "conformance", "capabilities", "run.mjs"),
      "--implementation",
      adapter,
      "--capability",
      "folderbase.change-set@0.1.0",
      "--capability",
      "folderbase.query-index@0.1.0",
      "--capability",
      "folderbase.template-expansion@0.1.0",
      "--capability",
      "folderbase.version-cli-json@0.1.0",
    ],
    { env: conformanceEnvironment, timeout: 20 * 60_000 },
  );
  const capabilities = reportPassed(
    capabilityReport,
    "folderbase-capability-conformance-report-v1",
  );
  assert.equal(capabilities.passed, 4);

  process.stdout.write(
    "Packed SDK installed outside the checkout and passed the real-Core adapter journey.\n",
  );
} finally {
  await rm(owner, { recursive: true, force: true });
}

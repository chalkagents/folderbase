import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const contractUrl = new URL(
  "../../protocol/compatibility/v1/contract.json",
  import.meta.url,
);
const cliSchemaUrl = new URL(
  "../../protocol/schemas/cli/1/folderbase-cli-json.schema.json",
  import.meta.url,
);

test("compatibility v1 freezes the minimal portable and CLI surfaces", async () => {
  const contract = JSON.parse(await readFile(contractUrl, "utf8"));

  assert.equal(contract.format, "folderbase-compatibility-contract-v1");
  assert.equal(contract.contract_version, "1.0.0");
  assert.deepEqual(contract.protocol_profiles, {
    root_manifest: ["0.5.0"],
    folderbase_version: ["0.4", "0.5"],
    chunk_manifest: ["folderbase-chunk-manifest-v1"],
  });
  assert.deepEqual(contract.cli_json.commands, [
    "inspect",
    "attest",
    "init.plan",
    "init.apply",
    "upgrade.plan",
    "upgrade.apply",
    "validate.shallow",
    "protocol.contract",
    "protocol.check.chunk-manifest",
    "protocol.check.folderbase-version",
    "workspace.list",
    "workspace.read",
    "workspace.save",
  ]);
  assert.deepEqual(contract.cli_json.exit_codes, {
    success: 0,
    attention_required: 1,
    operational_error: 2,
  });
  assert.deepEqual(contract.record_classes.portable, [
    ".folderbase/manifest.json",
    ".folderbase/versions/folderbase/*.json",
  ]);
  assert.equal(
    contract.record_classes.engine_owned_default,
    "all-unclassified-.folderbase-records",
  );
  for (const path of [
    ".folderbase/versions/records/**",
    ".folderbase/versions/blobs/**",
    ".folderbase/journal/**",
    ".folderbase/locks/**",
    ".folderbase/history-transfers/**",
    ".folderbase/migrations/**",
  ]) {
    assert.ok(contract.record_classes.engine_owned.includes(path), path);
  }
  for (const code of [
    "invalid_root",
    "initialization_plan_changed",
    "workspace_content_changed",
    "root_not_found",
    "manifest_invalid_json",
    "output_serialization",
  ]) {
    assert.ok(contract.cli_json.error_codes.includes(code), code);
  }
  assert.equal(contract.upgrades.automatic, false);
  assert.equal(contract.upgrades.downgrades, "unsupported");
});

test("CLI JSON v1 publishes schemas for every stable result and error", async () => {
  const schema = JSON.parse(await readFile(cliSchemaUrl, "utf8"));

  assert.equal(
    schema.$id,
    "https://folderbase.ai/protocol/cli/1/folderbase-cli-json.schema.json",
  );
  assert.equal(schema.$schema, "https://json-schema.org/draft/2020-12/schema");
  assert.deepEqual(Object.keys(schema.$defs).sort(), [
    "attestation",
    "compatibilityDescriptor",
    "error",
    "initializationPlan",
    "initializationResult",
    "inspection",
    "protocolCheck",
    "upgradePlan",
    "upgradeResult",
    "validation",
    "workspaceListing",
    "workspaceRead",
    "workspaceSave",
  ]);
});

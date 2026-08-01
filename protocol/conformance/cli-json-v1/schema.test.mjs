import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { assertJsonSchema } from "./schema.mjs";

const schema = JSON.parse(
  await readFile(
    new URL("../../schemas/cli/1/folderbase-cli-json.schema.json", import.meta.url),
    "utf8",
  ),
);

test("inspection validation requires the complete stable inventory and permits additions", () => {
  const inspection = {
    root: "/tmp/project-2",
    inventory: {
      file_count: 1,
      total_bytes: 6,
      generated_file_count: 0,
      reconstructable_tree_count: 0,
      secret_shaped_file_count: 0,
      temporary_file_count: 0,
      large_file_count: 0,
      versioned_file_count: 0,
      future_counter: 0,
    },
    classified_paths: [],
    git_repositories: [],
    context_files: [],
    boundary_hints: [],
    reconstructable_trees: [],
    nested_folderbases: [],
    warnings: [],
    future_result: true,
  };

  assert.doesNotThrow(() => assertJsonSchema(inspection, schema, "inspection"));
  delete inspection.inventory.versioned_file_count;
  assert.throws(
    () => assertJsonSchema(inspection, schema, "inspection"),
    /versioned_file_count/,
  );
  inspection.inventory.versioned_file_count = 0;
  inspection.classified_paths = [42];
  assert.throws(() => assertJsonSchema(inspection, schema, "inspection"));
});

test("workspace listing accepts symlinks and IDs require canonical UUID text", () => {
  assert.doesNotThrow(() =>
    assertJsonSchema(
      {
        root: "/tmp/project-2",
        entries: [
          {
            path: "notes-link",
            name: "notes-link",
            kind: "symlink",
            bytes: 0,
            editable: false,
            reconstructable: false,
          },
        ],
      },
      schema,
      "workspaceListing",
    ),
  );

  assert.throws(() =>
    assertJsonSchema(
      {
        root: "/tmp/project-2",
        folderbase_id: "folderbase_-",
        protocol_version: "0.5.0",
        manifest_sha256: "a".repeat(64),
        root_instance_sha256: "b".repeat(64),
      },
      schema,
      "attestation",
    ),
  );
});

test("error validation rejects undeclared fields because the v1 envelope is closed", () => {
  assert.doesNotThrow(() =>
    assertJsonSchema(
      { error: { code: "invalid_root", message: "missing" } },
      schema,
      "error",
    ),
  );
  assert.throws(() =>
    assertJsonSchema(
      { error: { code: "invalid_root", message: "missing", details: {} } },
      schema,
      "error",
    ),
  );
});

test("protocol checks select exactly one valid or invalid result branch", () => {
  assert.doesNotThrow(() =>
    assertJsonSchema(
      {
        artifact: "folderbase-version",
        valid: true,
        profile: "0.5",
        canonical_digest: "a".repeat(64),
      },
      schema,
      "protocolCheck",
    ),
  );
  assert.doesNotThrow(() =>
    assertJsonSchema(
      {
        artifact: "chunk-manifest",
        valid: false,
        error: { code: "invalid_artifact", message: "invalid" },
      },
      schema,
      "protocolCheck",
    ),
  );
});

test("upgrade plan and result have stable reviewed-digest shapes", () => {
  const base = {
    root: "/tmp/project-2",
    folderbase_id: "folderbase_019f9b75-4f42-7f65-a012-2bfecdd8c475",
    from_protocol_version: "0.1.0",
    to_protocol_version: "0.5.0",
    changed_paths: [".folderbase/manifest.json"],
  };
  assert.doesNotThrow(() =>
    assertJsonSchema(
      {
        ...base,
        plan_digest: { algorithm: "sha256", digest: "a".repeat(64) },
      },
      schema,
      "upgradePlan",
    ),
  );
  assert.doesNotThrow(() =>
    assertJsonSchema(
      {
        ...base,
        applied_plan_digest: { algorithm: "sha256", digest: "a".repeat(64) },
      },
      schema,
      "upgradeResult",
    ),
  );
});

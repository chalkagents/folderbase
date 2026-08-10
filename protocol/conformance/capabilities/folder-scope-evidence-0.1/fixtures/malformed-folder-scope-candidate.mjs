#!/usr/bin/env node

const [family] = process.argv.slice(2);

if (family === "protocol") {
  process.stdout.write(`${JSON.stringify({
    format: "folderbase-compatibility-contract-v1",
    contract_version: "1.0.0",
    cli_json: "folderbase-cli-json-v1",
    capabilities: [{
      name: "folderbase.folder-scope-evidence",
      version: "0.1.0",
      stability: "stable",
    }],
  })}\n`);
} else {
  process.stdout.write(`${JSON.stringify({
    format: "folderbase-folder-scope-evidence-v1",
    folderbase_id: "folderbase_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    selected_path: ".FOLDERBASE",
    event_id: `folder_scope_event_${"a".repeat(64)}`,
    device_sequence: 1,
    opaque_binding_proof: `fb_scope_binding_v1_${"b".repeat(64)}`,
    nested_boundaries: [],
  })}\n`);
}

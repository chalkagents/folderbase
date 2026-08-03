#!/usr/bin/env node

const descriptor = {
  format: "folderbase-compatibility-contract-v1",
  contract_version: "1.0.0",
  cli_json: "folderbase-cli-json-v1",
  protocol_profiles: {
    root_manifest: ["0.5.0"],
    folderbase_version: ["0.4", "0.5"],
    chunk_manifest: ["folderbase-chunk-manifest-v1"],
  },
  capabilities: [
    {
      name: "folderbase.version-cli-json",
      version: "0.1.0",
      stability: "stable",
    },
  ],
};

if (process.argv.slice(2).join(" ") === "protocol contract --json") {
  process.stdout.write(`${JSON.stringify(descriptor)}\n`);
} else {
  process.stderr.write("fixture implements discovery only\n");
  process.exitCode = 2;
}

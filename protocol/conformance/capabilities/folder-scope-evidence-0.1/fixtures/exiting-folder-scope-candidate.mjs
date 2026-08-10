#!/usr/bin/env node

import { spawn } from "node:child_process";

const marker = process.env.FOLDERBASE_FOLDER_SCOPE_DESCENDANT_MARKER;
if (!marker) throw new Error("missing descendant marker");

const descendant = spawn(
  process.execPath,
  [
    "-e",
    "setTimeout(() => require('node:fs').writeFileSync(process.argv[1], 'escaped\\n'), 1000)",
    marker,
  ],
  { stdio: "ignore", windowsHide: true },
);
descendant.unref();

if (process.argv.slice(2).join(" ") === "protocol contract --json") {
  process.stdout.write(`${JSON.stringify({
    capabilities: [{ name: "folderbase.folder-scope-evidence", version: "0.1.0" }],
  })}\n`);
} else {
  process.stderr.write("operation unavailable\n");
  process.exitCode = 2;
}

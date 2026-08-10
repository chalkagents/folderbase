#!/usr/bin/env node

import { spawn } from "node:child_process";

const marker = process.env.FOLDERBASE_FOLDER_SCOPE_DESCENDANT_MARKER;
if (!marker) throw new Error("missing descendant marker");

spawn(
  process.execPath,
  [
    "-e",
    "setTimeout(() => require('node:fs').writeFileSync(process.argv[1], 'escaped\\n'), 1000)",
    marker,
  ],
  { stdio: "ignore", windowsHide: true },
);

await new Promise(() => {});

#!/usr/bin/env node

import { spawn } from "node:child_process";
import { writeFileSync } from "node:fs";

if (process.argv[2] === "--grandchild") {
  process.on("SIGTERM", () => {});
  setInterval(() => {}, 1_000);
} else {
  const grandchild = spawn(process.execPath, [process.argv[1], "--grandchild"], {
    stdio: "ignore",
  });
  if (process.env.FOLDERBASE_TEMPLATE_CONFORMANCE_PID_FILE) {
    writeFileSync(
      process.env.FOLDERBASE_TEMPLATE_CONFORMANCE_PID_FILE,
      `${process.pid}\n${grandchild.pid}\n`,
    );
  }
  process.on("SIGTERM", () => {});
  setInterval(() => {}, 1_000);
}

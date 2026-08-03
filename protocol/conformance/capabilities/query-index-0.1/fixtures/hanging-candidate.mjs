#!/usr/bin/env node

import { writeFileSync } from "node:fs";

if (process.env.FOLDERBASE_QUERY_CONFORMANCE_PID_FILE) {
  writeFileSync(process.env.FOLDERBASE_QUERY_CONFORMANCE_PID_FILE, `${process.pid}\n`);
}
process.on("SIGTERM", () => {});
setInterval(() => {}, 1_000);

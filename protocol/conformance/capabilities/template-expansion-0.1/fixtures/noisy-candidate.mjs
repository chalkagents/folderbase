#!/usr/bin/env node

import { writeFileSync } from "node:fs";

if (process.env.FOLDERBASE_TEMPLATE_CONFORMANCE_PID_FILE) {
  writeFileSync(process.env.FOLDERBASE_TEMPLATE_CONFORMANCE_PID_FILE, `${process.pid}\n`);
}
for (;;) process.stdout.write("x".repeat(65_536));

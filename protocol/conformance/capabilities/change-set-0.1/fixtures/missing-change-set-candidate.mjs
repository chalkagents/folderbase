#!/usr/bin/env node

process.stderr.write(`${JSON.stringify({
  format: "folderbase-change-set-error-v1",
  error: {
    code: "change_set_operational_error",
    message: "fixture deliberately does not implement Folderbase Change Sets",
  },
})}\n`);
process.exitCode = 2;

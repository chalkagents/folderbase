#!/usr/bin/env node

process.stderr.write(`${JSON.stringify({
  format: "folderbase-root-reconstruction-error-v1",
  error: {
    code: "invalid_invocation",
    message: "root reconstruction capability is not implemented",
  },
})}\n`);
process.exitCode = 2;

#!/usr/bin/env node

process.stderr.write(`${JSON.stringify({
  format: "folderbase-folder-scope-evidence-error-v1",
  error: {
    code: "invalid_invocation",
    message: "folder-scope evidence is unavailable",
  },
})}\n`);
process.exitCode = 2;

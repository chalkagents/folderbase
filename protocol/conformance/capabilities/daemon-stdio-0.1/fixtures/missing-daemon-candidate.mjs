#!/usr/bin/env node

process.stderr.write(`${JSON.stringify({
  format: "folderbase-daemon-terminal-error-v1",
  error: {
    code: "invalid_daemon_invocation",
    message: "daemon capability is not implemented",
  },
})}\n`);
process.exitCode = 2;

#!/usr/bin/env node

import { pathToFileURL } from "node:url";

const NAME = /^[a-z0-9]+(?:-[a-z0-9]+)*$/u;
const VERSION = /^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?$/u;
const SHA256 = /^[0-9a-f]{64}$/u;

export function decideCratePublication(input) {
  const { crateName, version, localChecksum, published } = input;
  if (!NAME.test(crateName)) throw new Error(`invalid crate name: ${crateName}`);
  if (!VERSION.test(version)) throw new Error(`invalid crate version: ${version}`);
  if (!SHA256.test(localChecksum)) throw new Error("invalid local crate checksum");
  if (published === null) return { skipPublish: false };
  if (!published || typeof published !== "object" || Array.isArray(published)) {
    throw new Error("invalid published crate metadata");
  }
  if (published.version !== version) {
    throw new Error(`${crateName} registry version does not match ${version}`);
  }
  if (published.yanked === true) {
    throw new Error(`${crateName}@${version} is yanked`);
  }
  if (published.checksum !== localChecksum) {
    throw new Error(`${crateName}@${version} checksum does not match local bytes`);
  }
  return { skipPublish: true };
}

async function readStandardInput() {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  return Buffer.concat(chunks).toString("utf8");
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    process.stdout.write(`${JSON.stringify(
      decideCratePublication(JSON.parse(await readStandardInput())),
    )}\n`);
  } catch (error) {
    process.stderr.write(`folderbase crate publication policy: ${error.message}\n`);
    process.exitCode = 1;
  }
}

#!/usr/bin/env node

import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const repositoryRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const vectorRoot = join(
  repositoryRoot,
  "protocol",
  "conformance",
  "folderbase-version",
);
const reference = join(vectorRoot, "reference-digest.mjs");

for (const stem of ["minimal-restorable-v1", "fidelity-and-lifecycle-v1"]) {
  const json = join(vectorRoot, "valid", `${stem}.json`);
  const expected = readFileSync(
    join(vectorRoot, "valid", `${stem}.sha256`),
    "utf8",
  ).trim();
  const observed = execFileSync(process.execPath, [reference, json], {
    encoding: "utf8",
  }).trim();
  if (observed !== expected) {
    throw new Error(`${stem} digest mismatch: ${observed} != ${expected}`);
  }
  console.log(`Folderbase Version ${stem} ${observed}`);
}

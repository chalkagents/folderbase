#!/usr/bin/env node

import { createHash } from "node:crypto";
import { execFileSync, spawnSync } from "node:child_process";
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const repositoryRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const vectorRoot = join(
  repositoryRoot,
  "protocol",
  "conformance",
  "folderbase-version-0.5",
);
const reference = join(vectorRoot, "reference-digest.mjs");

function stemsWithExactSidecars(directory) {
  const names = readdirSync(directory).sort();
  const jsonStems = names
    .filter((name) => name.endsWith(".json"))
    .map((name) => name.slice(0, -".json".length));
  const sidecarStems = names
    .filter((name) => name.endsWith(".sha256"))
    .map((name) => name.slice(0, -".sha256".length));
  if (JSON.stringify(jsonStems) !== JSON.stringify(sidecarStems)) {
    throw new Error(`JSON/sidecar mismatch in ${directory}`);
  }
  return jsonStems;
}

const versionValidRoot = join(vectorRoot, "valid");
for (const stem of stemsWithExactSidecars(versionValidRoot)) {
  const json = join(versionValidRoot, `${stem}.json`);
  const expected = readFileSync(
    join(versionValidRoot, `${stem}.sha256`),
    "utf8",
  ).trim();
  const observed = execFileSync(process.execPath, [reference, json], {
    encoding: "utf8",
  }).trim();
  if (observed !== expected) {
    throw new Error(`${stem} canonical digest mismatch: ${observed} != ${expected}`);
  }
  console.log(`Folderbase Version 0.5 ${stem} ${observed}`);
}

const rootManifestValidRoot = join(vectorRoot, "root-manifest", "valid");
for (const stem of stemsWithExactSidecars(rootManifestValidRoot)) {
  const exactBytes = readFileSync(
    join(rootManifestValidRoot, `${stem}.json`),
  );
  const expected = readFileSync(
    join(rootManifestValidRoot, `${stem}.sha256`),
    "utf8",
  ).trim();
  const observed = createHash("sha256").update(exactBytes).digest("hex");
  if (observed !== expected) {
    throw new Error(
      `${stem} exact root-manifest digest mismatch: ${observed} != ${expected}`,
    );
  }
  console.log(`Folderbase root manifest 0.5 ${stem} ${observed}`);
}

const rejectedProfile = spawnSync(
  process.execPath,
  [
    reference,
    join(vectorRoot, "invalid", "protocol-version-0.4.json"),
  ],
  { encoding: "utf8" },
);
if (rejectedProfile.status === 0) {
  throw new Error("protocol 0.5 reference encoder accepted a 0.4 envelope");
}

#!/usr/bin/env node

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const repositoryRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const vectorRoot = join(
  repositoryRoot,
  "protocol",
  "conformance",
  "reorganization",
  "plan",
  "valid",
);
const plan = JSON.parse(
  readFileSync(join(vectorRoot, "project-cleanup-v1.json"), "utf8"),
);
const expected = readFileSync(
  join(vectorRoot, "project-cleanup-v1.sha256"),
  "utf8",
).trim();

const compareUtf8 = (left, right) =>
  Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"));
const comparePath = (left, right) =>
  compareUtf8(left.path.normalize("NFC"), right.path.normalize("NFC"));

plan.analysis_scope.nested_boundaries.sort(comparePath);
plan.analysis_scope.operation_closure.sort(comparePath);
plan.analysis_scope.declared_entries.sort(comparePath);
plan.template_references?.sort(compareUtf8);

const canonicalJson = (value) => {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(",")}]`;
  }
  return `{${Object.keys(value)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
    .join(",")}}`;
};

const digest = (domain, value) =>
  createHash("sha256")
    .update(Buffer.from(`${domain}\0`, "utf8"))
    .update(Buffer.from(canonicalJson(value), "utf8"))
    .digest("hex");

const scopeDigest = digest(
  "folderbase-reorganization-analysis-scope-v1",
  plan.analysis_scope,
);
if (scopeDigest !== plan.analysis_scope_digest) {
  throw new Error(
    `analysis-scope digest mismatch: ${scopeDigest} != ${plan.analysis_scope_digest}`,
  );
}

const { plan_digest: storedPlanDigest, ...planWithoutDigest } = plan;
const planDigest = digest(
  "folderbase-reorganization-plan-v1",
  planWithoutDigest,
);
if (planDigest !== storedPlanDigest || planDigest !== expected) {
  throw new Error(
    `plan digest mismatch: ${planDigest} != ${storedPlanDigest} != ${expected}`,
  );
}

console.log(`reorganization scope ${scopeDigest}`);
console.log(`reorganization plan  ${planDigest}`);

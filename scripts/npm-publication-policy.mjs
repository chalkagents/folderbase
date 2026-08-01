#!/usr/bin/env node

import { pathToFileURL } from "node:url";

const SEMVER =
  /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;

function parseSemver(version) {
  const match = version.match(SEMVER);
  if (!match) {
    throw new Error(`invalid semantic version: ${version}`);
  }
  return {
    core: match.slice(1, 4).map(Number),
    prerelease: match[4]?.split(".") ?? [],
  };
}

function compareIdentifier(left, right) {
  const leftNumeric = /^(0|[1-9]\d*)$/.test(left);
  const rightNumeric = /^(0|[1-9]\d*)$/.test(right);
  if (leftNumeric && rightNumeric) {
    return Number(left) - Number(right);
  }
  if (leftNumeric !== rightNumeric) {
    return leftNumeric ? -1 : 1;
  }
  return left.localeCompare(right);
}

function compareSemver(leftVersion, rightVersion) {
  const left = parseSemver(leftVersion);
  const right = parseSemver(rightVersion);
  for (let index = 0; index < left.core.length; index += 1) {
    if (left.core[index] !== right.core[index]) {
      return left.core[index] - right.core[index];
    }
  }
  if (left.prerelease.length === 0 || right.prerelease.length === 0) {
    if (left.prerelease.length === right.prerelease.length) return 0;
    return left.prerelease.length === 0 ? 1 : -1;
  }
  const length = Math.max(left.prerelease.length, right.prerelease.length);
  for (let index = 0; index < length; index += 1) {
    if (left.prerelease[index] === undefined) return -1;
    if (right.prerelease[index] === undefined) return 1;
    const comparison = compareIdentifier(
      left.prerelease[index],
      right.prerelease[index],
    );
    if (comparison !== 0) return comparison;
  }
  return 0;
}

function backfillTagFor(packageVersion) {
  return `folderbase-backfill-${packageVersion.replace(/[^0-9A-Za-z-]/g, "-")}`;
}

export function decideNpmPublication(input) {
  const {
    packageVersion,
    channel,
    localIntegrity,
    publishedVersion,
    publishedIntegrity,
    distTags,
  } = input;
  const parsed = parseSemver(packageVersion);
  if (!["latest", "next"].includes(channel)) {
    throw new Error(`unsupported npm publication channel: ${channel}`);
  }
  if (parsed.prerelease.length > 0 && distTags.latest === packageVersion) {
    throw new Error(`prerelease ${packageVersion} cannot occupy latest`);
  }

  if (publishedVersion !== null) {
    if (publishedVersion !== packageVersion) {
      throw new Error("published version does not match the exact release");
    }
    if (!publishedIntegrity || publishedIntegrity !== localIntegrity) {
      throw new Error("published package integrity does not match local bytes");
    }
    const backfillTag = backfillTagFor(packageVersion);
    const cleanupTag = distTags[backfillTag] === packageVersion ? backfillTag : null;
    return { skipPublish: true, publishTag: null, cleanupTag };
  }

  const selectedVersion = distTags[channel];
  if (!selectedVersion) {
    return { skipPublish: false, publishTag: channel, cleanupTag: null };
  }
  const comparison = compareSemver(packageVersion, selectedVersion);
  if (comparison === 0) {
    throw new Error(
      `registry state is inconsistent: ${channel} points to absent ${packageVersion}`,
    );
  }
  if (comparison > 0) {
    return { skipPublish: false, publishTag: channel, cleanupTag: null };
  }

  const cleanupTag = backfillTagFor(packageVersion);
  return { skipPublish: false, publishTag: cleanupTag, cleanupTag };
}

async function readStandardInput() {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  return Buffer.concat(chunks).toString("utf8");
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const decision = decideNpmPublication(
      JSON.parse(await readStandardInput()),
    );
    process.stdout.write(`${JSON.stringify(decision)}\n`);
  } catch (error) {
    console.error(`folderbase npm publication policy: ${error.message}`);
    process.exitCode = 1;
  }
}

import assert from "node:assert/strict";
import test from "node:test";

import { decideNpmPublication } from "../npm-publication-policy.mjs";

const integrity = "sha512-local";

test("an exact stable rerun stays idempotent after latest advances", () => {
  assert.deepEqual(
    decideNpmPublication({
      packageVersion: "0.4.0",
      channel: "latest",
      localIntegrity: integrity,
      publishedVersion: "0.4.0",
      publishedIntegrity: integrity,
      distTags: { latest: "0.6.0" },
    }),
    { skipPublish: true, publishTag: null, cleanupTag: null },
  );
});

test("an exact rerun cleans up a temporary tag left by an interrupted backfill", () => {
  assert.deepEqual(
    decideNpmPublication({
      packageVersion: "0.4.0",
      channel: "latest",
      localIntegrity: integrity,
      publishedVersion: "0.4.0",
      publishedIntegrity: integrity,
      distTags: {
        latest: "0.6.0",
        "folderbase-backfill-0-4-0": "0.4.0",
      },
    }),
    {
      skipPublish: true,
      publishTag: null,
      cleanupTag: "folderbase-backfill-0-4-0",
    },
  );
});

test("an exact prerelease rerun stays idempotent after next advances", () => {
  assert.deepEqual(
    decideNpmPublication({
      packageVersion: "0.5.0-rc.1",
      channel: "next",
      localIntegrity: integrity,
      publishedVersion: "0.5.0-rc.1",
      publishedIntegrity: integrity,
      distTags: { latest: "0.4.0", next: "0.5.0-rc.2" },
    }),
    { skipPublish: true, publishTag: null, cleanupTag: null },
  );
});

test("an unpublished newer stable version advances latest", () => {
  assert.deepEqual(
    decideNpmPublication({
      packageVersion: "0.6.0",
      channel: "latest",
      localIntegrity: integrity,
      publishedVersion: null,
      publishedIntegrity: null,
      distTags: { latest: "0.5.1" },
    }),
    { skipPublish: false, publishTag: "latest", cleanupTag: null },
  );
});

test("an unpublished older stable version cannot roll latest backward", () => {
  assert.deepEqual(
    decideNpmPublication({
      packageVersion: "0.4.0",
      channel: "latest",
      localIntegrity: integrity,
      publishedVersion: null,
      publishedIntegrity: null,
      distTags: { latest: "0.6.0" },
    }),
    {
      skipPublish: false,
      publishTag: "folderbase-backfill-0-4-0",
      cleanupTag: "folderbase-backfill-0-4-0",
    },
  );
});

test("semver prerelease ordering advances next without touching latest", () => {
  assert.deepEqual(
    decideNpmPublication({
      packageVersion: "0.5.0-rc.10",
      channel: "next",
      localIntegrity: integrity,
      publishedVersion: null,
      publishedIntegrity: null,
      distTags: { latest: "0.4.0", next: "0.5.0-rc.2" },
    }),
    { skipPublish: false, publishTag: "next", cleanupTag: null },
  );
});

test("a prerelease can never occupy latest", () => {
  assert.throws(
    () =>
      decideNpmPublication({
        packageVersion: "0.5.0-rc.1",
        channel: "next",
        localIntegrity: integrity,
        publishedVersion: "0.5.0-rc.1",
        publishedIntegrity: integrity,
        distTags: { latest: "0.5.0-rc.1", next: "0.5.0-rc.1" },
      }),
    /prerelease .* cannot occupy latest/,
  );
});

test("an exact rerun rejects different immutable npm bytes", () => {
  assert.throws(
    () =>
      decideNpmPublication({
        packageVersion: "0.4.0",
        channel: "latest",
        localIntegrity: integrity,
        publishedVersion: "0.4.0",
        publishedIntegrity: "sha512-different",
        distTags: { latest: "0.4.0" },
      }),
    /integrity does not match/,
  );
});

test("an absent exact version cannot already own its channel", () => {
  assert.throws(
    () =>
      decideNpmPublication({
        packageVersion: "0.4.0",
        channel: "latest",
        localIntegrity: integrity,
        publishedVersion: null,
        publishedIntegrity: null,
        distTags: { latest: "0.4.0" },
      }),
    /registry state is inconsistent/,
  );
});

import assert from "node:assert/strict";
import test from "node:test";

import {
  classifyRelease,
  decideNpmPublication,
} from "../npm-publication-policy.mjs";

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
      githubLatestVersion: "0.6.0",
    }),
    {
      skipPublish: true,
      publishTag: null,
      cleanupTag: null,
      advanceChannel: false,
      advanceGithubLatest: false,
    },
  );
});

test("an exact stable rerun may retain the channel it already owns", () => {
  assert.deepEqual(
    decideNpmPublication({
      packageVersion: "0.4.0",
      channel: "latest",
      localIntegrity: integrity,
      publishedVersion: "0.4.0",
      publishedIntegrity: integrity,
      distTags: { latest: "0.4.0" },
      githubLatestVersion: "0.4.0",
    }),
    {
      skipPublish: true,
      publishTag: null,
      cleanupTag: null,
      advanceChannel: true,
      advanceGithubLatest: true,
    },
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
      githubLatestVersion: "0.6.0",
    }),
    {
      skipPublish: true,
      publishTag: null,
      cleanupTag: "folderbase-backfill-0-4-0",
      advanceChannel: false,
      advanceGithubLatest: false,
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
      githubLatestVersion: "0.4.0",
    }),
    {
      skipPublish: true,
      publishTag: null,
      cleanupTag: null,
      advanceChannel: false,
      advanceGithubLatest: false,
    },
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
      githubLatestVersion: "0.5.1",
    }),
    {
      skipPublish: false,
      publishTag: "latest",
      cleanupTag: null,
      advanceChannel: true,
      advanceGithubLatest: true,
    },
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
      githubLatestVersion: "0.6.0",
    }),
    {
      skipPublish: false,
      publishTag: "folderbase-backfill-0-4-0",
      cleanupTag: "folderbase-backfill-0-4-0",
      advanceChannel: false,
      advanceGithubLatest: false,
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
      githubLatestVersion: "0.4.0",
    }),
    {
      skipPublish: false,
      publishTag: "next",
      cleanupTag: null,
      advanceChannel: true,
      advanceGithubLatest: false,
    },
  );
});

test("semver prerelease identifiers use ASCII ordering", () => {
  assert.deepEqual(
    decideNpmPublication({
      packageVersion: "0.5.0-Ba",
      channel: "next",
      localIntegrity: integrity,
      publishedVersion: null,
      publishedIntegrity: null,
      distTags: { latest: "0.4.0", next: "0.5.0-a" },
      githubLatestVersion: "0.4.0",
    }),
    {
      skipPublish: false,
      publishTag: "folderbase-backfill-0-5-0-Ba",
      cleanupTag: "folderbase-backfill-0-5-0-Ba",
      advanceChannel: false,
      advanceGithubLatest: false,
    },
  );
});

test("semver compares arbitrary-length numeric prerelease identifiers exactly", () => {
  assert.deepEqual(
    decideNpmPublication({
      packageVersion: "0.5.0-rc.9007199254740993",
      channel: "next",
      localIntegrity: integrity,
      publishedVersion: null,
      publishedIntegrity: null,
      distTags: { latest: "0.4.0", next: "0.5.0-rc.9007199254740992" },
      githubLatestVersion: "0.4.0",
    }),
    {
      skipPublish: false,
      publishTag: "next",
      cleanupTag: null,
      advanceChannel: true,
      advanceGithubLatest: false,
    },
  );
});

test("semver compares arbitrary-length core identifiers exactly", () => {
  assert.deepEqual(
    decideNpmPublication({
      packageVersion: "9007199254740993.0.0",
      channel: "latest",
      localIntegrity: integrity,
      publishedVersion: null,
      publishedIntegrity: null,
      distTags: { latest: "9007199254740992.0.0" },
      githubLatestVersion: "9007199254740992.0.0",
    }),
    {
      skipPublish: false,
      publishTag: "latest",
      cleanupTag: null,
      advanceChannel: true,
      advanceGithubLatest: true,
    },
  );
});

test("semver rejects numeric prerelease identifiers with leading zeroes", () => {
  assert.throws(
    () =>
      decideNpmPublication({
        packageVersion: "0.5.0-rc.01",
        channel: "next",
        localIntegrity: integrity,
        publishedVersion: null,
        publishedIntegrity: null,
        distTags: { latest: "0.4.0", next: "0.5.0-rc.1" },
      }),
    /invalid semantic version/,
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

test("stable build metadata stays on stable release channels", () => {
  assert.deepEqual(classifyRelease("1.2.3+build-x"), {
    channel: "latest",
    githubPrerelease: false,
  });
});

test("prerelease classification ignores hyphens in build metadata", () => {
  assert.deepEqual(classifyRelease("1.2.3-rc.1+build-x"), {
    channel: "next",
    githubPrerelease: true,
  });
});

test("publication rejects a channel that disagrees with parsed SemVer", () => {
  assert.throws(
    () =>
      decideNpmPublication({
        packageVersion: "1.2.3+build-x",
        channel: "next",
        localIntegrity: integrity,
        publishedVersion: null,
        publishedIntegrity: null,
        distTags: { latest: "1.2.2" },
        githubLatestVersion: "1.2.2",
      }),
    /must use latest/,
  );
});

test("npm and GitHub advance independently after a partial publication", () => {
  assert.deepEqual(
    decideNpmPublication({
      packageVersion: "0.5.0",
      channel: "latest",
      localIntegrity: integrity,
      publishedVersion: null,
      publishedIntegrity: null,
      distTags: { latest: "0.4.0" },
      githubLatestVersion: "0.6.0",
    }),
    {
      skipPublish: false,
      publishTag: "latest",
      cleanupTag: null,
      advanceChannel: true,
      advanceGithubLatest: false,
    },
  );
});

test("GitHub may advance while npm preserves a newer channel", () => {
  assert.deepEqual(
    decideNpmPublication({
      packageVersion: "0.6.0",
      channel: "latest",
      localIntegrity: integrity,
      publishedVersion: null,
      publishedIntegrity: null,
      distTags: { latest: "0.7.0" },
      githubLatestVersion: "0.5.0",
    }),
    {
      skipPublish: false,
      publishTag: "folderbase-backfill-0-6-0",
      cleanupTag: "folderbase-backfill-0-6-0",
      advanceChannel: false,
      advanceGithubLatest: true,
    },
  );
});

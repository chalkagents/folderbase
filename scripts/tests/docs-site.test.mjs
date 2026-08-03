import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { classifyChanges } from "../ci/classify-changes.mjs";

const repositoryRoot = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const docsRoot = join(repositoryRoot, "apps", "docs");

function read(relativePath) {
  return readFileSync(join(repositoryRoot, relativePath), "utf8");
}

function workflowJob(source, jobName) {
  const start = source.indexOf(`\n  ${jobName}:\n`);
  assert.notEqual(start, -1, `missing workflow job: ${jobName}`);
  const remaining = source.slice(start + 1);
  const next = remaining.slice(1).search(/\n  [a-z][a-z0-9-]*:\n/u);
  return next === -1 ? remaining : remaining.slice(0, next + 1);
}

test("docs changes run only the docs verification lane", () => {
  assert.deepEqual(
    classifyChanges(["apps/docs/content/docs/getting-started/quickstart.mdx"]),
    {
      docs: true,
      install: false,
      npm: false,
      platform: false,
      rust: false,
    },
  );
});

test("full-confidence runs include the docs verification lane", () => {
  assert.equal(classifyChanges([], { full: true }).docs, true);
});

test("the protected aggregate requires successful docs verification when applicable", () => {
  const source = read(".github/workflows/ci.yml");
  const docs = workflowJob(source, "docs");
  const required = workflowJob(source, "required");

  assert.match(docs, /if: needs\.plan\.outputs\.docs == 'true'/);
  assert.match(docs, /npm ci --prefix apps\/docs/);
  assert.match(docs, /npm test --prefix apps\/docs/);
  assert.match(required, /needs: \[plan, docs, npm-cli, rust, package-install, core-platforms\]/);
  assert.match(required, /DOCS_REQUIRED: \$\{\{ needs\.plan\.outputs\.docs \}\}/);
  assert.match(required, /DOCS_RESULT: \$\{\{ needs\.docs\.result \}\}/);
});

test("Vercel Git deployments are enabled only for main", () => {
  const config = JSON.parse(readFileSync(join(docsRoot, "vercel.json"), "utf8"));
  const packageManifest = JSON.parse(
    readFileSync(join(docsRoot, "package.json"), "utf8"),
  );

  assert.equal(config.git, undefined);
  assert.equal(config.ignoreCommand, "node scripts/ignore-non-main-deploy.mjs");
  assert.equal(config.installCommand, "npm ci");
  assert.equal(packageManifest.engines?.node, "24.x");
  assert.match(packageManifest.packageManager ?? "", /^npm@\d+\.\d+\.\d+$/u);
  assert.match(packageManifest.devDependencies?.["@types/node"] ?? "", /^24\./u);

  const ignoreScript = join(docsRoot, "scripts", "ignore-non-main-deploy.mjs");
  const runIgnore = (gitRef) =>
    spawnSync(process.execPath, [ignoreScript], {
      env: {
        ...process.env,
        ...(gitRef === undefined ? {} : { VERCEL_GIT_COMMIT_REF: gitRef }),
      },
    });

  assert.equal(runIgnore("codex/preview").status, 0, "preview should be ignored");
  assert.equal(runIgnore("main").status, 1, "main should build");
  assert.equal(runIgnore(undefined).status, 1, "manual deploy should build");
});

test("published docs describe the released native 0.5 contract", () => {
  const content = readFileSync(
    join(docsRoot, "content", "docs", "getting-started", "quickstart.mdx"),
    "utf8",
  );
  const index = readFileSync(
    join(docsRoot, "content", "docs", "index.mdx"),
    "utf8",
  );
  const allDocs = [
    "content/docs/getting-started/quickstart.mdx",
    "content/docs/guides/agents.mdx",
    "content/docs/reference/cli-json-v1.mdx",
    "content/docs/reference/cli.mdx",
  ]
    .map((path) => readFileSync(join(docsRoot, path), "utf8"))
    .join("\n");

  assert.match(content, /creates only `.folderbase\/manifest\.json` by default/);
  assert.match(content, /--expected-plan-digest/);
  assert.match(index, /init \. --expected-plan-digest DIGEST_FROM_DRY_RUN --json/);
  assert.doesNotMatch(allDocs, /--help-json/);
});

test("install docs cover every verified 0.5 distribution channel", () => {
  const install = read("apps/docs/content/docs/getting-started/install.mdx");
  const release = read("apps/docs/content/docs/releases/0.5.mdx");

  for (const page of [install, release]) {
    assert.match(page, /npx --yes @folderbase\/cli@0\.5\.0 --version/u);
    assert.match(
      page,
      /cargo install folderbase-cli --version 0\.5\.0 --locked/u,
    );
    assert.match(page, /brew install chalkagents\/tap\/folderbase/u);
    assert.match(
      page,
      /github\.com\/chalkagents\/folderbase\/releases\/tag\/v0\.5\.0/u,
    );
  }
});

test("released templates, local versions, and public conformance have runnable guides", () => {
  const guidesMeta = JSON.parse(
    readFileSync(join(docsRoot, "content", "docs", "guides", "meta.json"), "utf8"),
  );
  const referenceMeta = JSON.parse(
    readFileSync(join(docsRoot, "content", "docs", "reference", "meta.json"), "utf8"),
  );

  for (const guide of ["templates", "versioning"]) {
    assert(guidesMeta.pages.includes(guide), `guides navigation omits ${guide}`);
    assert.match(
      readFileSync(join(docsRoot, "content", "docs", "guides", `${guide}.mdx`), "utf8"),
      /```bash/u,
    );
  }

  assert(referenceMeta.pages.includes("conformance"));
  assert.match(
    readFileSync(
      join(docsRoot, "content", "docs", "reference", "conformance.mdx"),
      "utf8",
    ),
    /protocol\/conformance\/cli-json-v1\/run\.mjs/u,
  );

  const templates = readFileSync(
    join(docsRoot, "content", "docs", "guides", "templates.mdx"),
    "utf8",
  );
  assert.equal((templates.match(/--name "Launch project"/gu) ?? []).length, 2);
  assert.match(templates, /templates capability is experimental/u);

  for (const guide of ["migrate", "versioning"]) {
    assert.match(
      readFileSync(join(docsRoot, "content", "docs", "guides", `${guide}.mdx`), "utf8"),
      /experimental/u,
    );
  }

  const cli = readFileSync(
    join(docsRoot, "content", "docs", "reference", "cli.mdx"),
    "utf8",
  );
  assert.match(cli, /\| `migrate` \| Experimental JSON \|/u);
  assert.match(cli, /\| `version` \| Experimental JSON \|/u);
});

test("the query capability has runnable guide, wire reference, and honest release notes", () => {
  const guidesMeta = JSON.parse(
    read("apps/docs/content/docs/guides/meta.json"),
  );
  const referenceMeta = JSON.parse(
    read("apps/docs/content/docs/reference/meta.json"),
  );
  const releasesMeta = JSON.parse(
    read("apps/docs/content/docs/releases/meta.json"),
  );
  const guide = read("apps/docs/content/docs/guides/querying.mdx");
  const reference = read("apps/docs/content/docs/reference/query-index.mdx");
  const release = read("apps/docs/content/docs/releases/next.mdx");
  const cli = read("apps/docs/content/docs/reference/cli.mdx");
  const conformance = read("apps/docs/content/docs/reference/conformance.mdx");

  assert(guidesMeta.pages.includes("querying"));
  assert(referenceMeta.pages.includes("query-index"));
  assert(releasesMeta.pages.includes("next"));

  for (const page of [guide, reference, release]) {
    assert.match(page, /folderbase\.query-index@0\.1\.0/u);
  }
  assert.match(guide, /folderbase query run \. --json/u);
  assert.match(guide, /folderbase query explain \. --json/u);
  assert.match(guide, /folderbase index status \. --json/u);
  assert.match(guide, /folderbase index rebuild \. --json/u);
  assert.doesNotMatch(guide, /\bfbv1_/u);
  assert.match(
    guide,
    /"folderbase_version_id": "fbversion_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"/u,
  );
  assert.match(reference, /folderbase-query-request-v1/u);
  assert.match(reference, /query_snapshot_changed/u);
  assert.match(reference, /invalid_query_cursor/u);
  assert.match(reference, /syntax failures/u);
  assert.match(reference, /host output-stream failure/u);
  assert.match(reference, /Exit `1`/u);
  assert.match(reference, /Exit `2`/u);
  assert.match(release, /not part of the immutable Core 0\.5 release/u);
  assert.match(cli, /\| `query` \| Experimental optional capability \|/u);
  assert.match(conformance, /experimental query\/index profile/u);
});

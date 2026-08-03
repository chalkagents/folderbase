import assert from "node:assert/strict";
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

  assert.deepEqual(config.git?.deploymentEnabled, {
    "*": false,
    main: true,
  });
  assert.equal(config.installCommand, "npm ci");
  assert.equal(packageManifest.engines?.node, "24.x");
  assert.match(packageManifest.packageManager ?? "", /^npm@\d+\.\d+\.\d+$/u);
  assert.match(packageManifest.devDependencies?.["@types/node"] ?? "", /^24\./u);
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

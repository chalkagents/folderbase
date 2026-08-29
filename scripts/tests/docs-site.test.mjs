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

test("owner-sync guide preserves the generalized V0/V1 journey and honest delivery boundary", () => {
  const guide = read(
    "apps/docs/content/docs/guides/sync-agent-workspace.mdx",
  );

  assert.match(guide, /## What works today/u);
  assert.match(guide, /## V0: Content & Stories/u);
  assert.match(guide, /## V1: Full personal operating system/u);
  assert.match(guide, /Device A\s+Folderbase Cloud\s+Device B/u);
  assert.match(guide, /PR #192/u);
  assert.match(guide, /PR #196/u);
  assert.match(guide, /PR #200/u);
  assert.match(guide, /issue #197/u);
  assert.match(guide, /issue #205/u);
  assert.match(guide, /issue #207/u);
  assert.match(guide, /PR #204/u);
  assert.match(guide, /PR #215/u);
  assert.match(guide, /PR #218/u);
  assert.match(guide, /PR #219/u);
  assert.match(guide, /PR #220/u);
  assert.match(guide, /issue #211/u);
  assert.match(
    guide,
    /Generalized V0 existing-folder disposable preflight \| Locally verified/u,
  );
  assert.match(
    guide,
    /Private GCP bootstrap project, protected empty state bucket, and exact-revision attestation \| Live and independently verified/u,
  );
  assert.match(
    guide,
    /Native GCS exact-generation provider conformance \| Live proof passed; disposable bucket removed/u,
  );
  assert.match(
    guide,
    /Private Cloud SQL transport, migration, backup, and restore behavioral checkpoint \| Narrow live proof passed; full release gate remains open/u,
  );
  assert.match(
    guide,
    /Native GCS\/PostgreSQL owner-sync composition \| Locally verified; not deployed/u,
  );
  assert.match(
    guide,
    /Cloud SQL authority install plan, apply, and execution recovery \| Locally verified; no live authority Job ran/u,
  );
  assert.match(
    guide,
    /Generalized V0 PostgreSQL\/MinIO one-device local-cell pilot \| Passed twice; source unchanged and disposable authority removed/u,
  );
  assert.match(
    guide,
    /Native App exact owner-sync status and Pause\/Resume projection \| Locally verified; production remains Not connected without a verified session/u,
  );
  assert.match(guide, /exact\s+`Ready` Job and immutable Execution/u);
  assert.match(guide, /No live authority Job ran/u);
  assert.match(guide, /sealed PostgreSQL\/MinIO local cell/u);
  assert.match(guide, /Neither is deployed Folderbase Cloud/u);
  assert.match(guide, /Remote Head advanced from revision 1 to revision 2/u);
  assert.match(guide, /restart returned `AlreadyCurrent`/u);
  assert.match(guide, /These proofs do not deploy the owner-sync data plane/u);
  assert.match(guide, /All cost-bearing Cloud SQL test resources were removed/u);
  assert.match(
    guide,
    /Twelve free network\/API control-plane objects remain under a revision-bound\s+cleanup receipt/u,
  );
  assert.match(guide, /behavioral sub-gate, not the full release gate/u);
  assert.match(guide, /Physical V0 Device A ↔ Device B pilot \| Not yet passed/u);
  assert.match(
    guide,
    /V1 full personal OS with active repositories, mixed files, and large volume \| Not yet passed/u,
  );
  assert.doesNotMatch(guide, /\/Users\/jerel/u);
  assert.doesNotMatch(guide, /Jerel-OS/u);
});

test("published docs describe the released native 0.6 contract", () => {
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

test("install docs cover every verified 0.7.2 distribution channel", () => {
  const install = read("apps/docs/content/docs/getting-started/install.mdx");
  const release = read("apps/docs/content/docs/releases/0.7.2.mdx");

  for (const page of [install, release]) {
    assert.match(page, /npx --yes @folderbase\/cli@0\.7\.2 --version/u);
    assert.match(
      page,
      /cargo install folderbase-cli --version 0\.7\.2 --locked/u,
    );
    assert.match(page, /brew install chalkagents\/tap\/folderbase/u);
    assert.match(
      page,
      /github\.com\/chalkagents\/folderbase\/releases\/tag\/v0\.7\.2/u,
    );
  }
});

test("the incomplete 0.7.0 publication is visibly superseded", () => {
  const release = read("apps/docs/content/docs/releases/0.7.0.mdx");

  assert.match(release, /Do not install or integrate Core 0\.7\.0/u);
  assert.match(release, /\.cargo_vcs_info\.json/u);
  assert.match(release, /Core 0\.7\.1 supersedes 0\.7\.0/u);
  assert.doesNotMatch(release, /npx --yes @folderbase\/cli@0\.7\.0/u);
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
  assert.match(templates, /folderbase\.template-expansion@0\.1\.0/u);
  assert.match(templates, /folderbase template plan \/path\/to\/project --stdin --json/u);
  assert.match(templates, /folderbase template apply \/path\/to\/project/u);
  assert(referenceMeta.pages.includes("template-expansion"));
  assert.match(
    readFileSync(
      join(docsRoot, "content", "docs", "reference", "conformance.mdx"),
      "utf8",
    ),
    /protocol\/conformance\/capabilities\/template-expansion-0\.1\/run\.mjs/u,
  );

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
  const release = read("apps/docs/content/docs/releases/0.6.1.mdx");
  const cli = read("apps/docs/content/docs/reference/cli.mdx");
  const conformance = read("apps/docs/content/docs/reference/conformance.mdx");

  assert(guidesMeta.pages.includes("querying"));
  assert(referenceMeta.pages.includes("query-index"));
  assert(releasesMeta.pages.includes("next"));
  assert(releasesMeta.pages.includes("0.7.2"));
  assert(releasesMeta.pages.includes("0.7.1"));
  assert(releasesMeta.pages.includes("0.7.0"));
  assert(releasesMeta.pages.includes("0.6.1"));

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
  assert.match(release, /Core 0\.6\.1 retains Compatibility Contract v1/u);
  for (const page of [guide, reference, release, cli]) {
    assert.match(page, /Unstable Beta/u);
  }
  assert.match(guide, /does not search inside files/u);
  assert.match(guide, /required for Folderbase sync/u);
  assert.match(cli, /\| `query` \| Unstable Beta optional capability \|/u);
  assert.match(conformance, /experimental query\/index profile/u);
});

test("the stable Change Set capability has a runnable guide, wire reference, and release boundary", () => {
  const guidesMeta = JSON.parse(read("apps/docs/content/docs/guides/meta.json"));
  const referenceMeta = JSON.parse(read("apps/docs/content/docs/reference/meta.json"));
  const guide = read("apps/docs/content/docs/guides/change-sets.mdx");
  const reference = read("apps/docs/content/docs/reference/change-sets.mdx");
  const release = read("apps/docs/content/docs/releases/0.6.1.mdx");
  const cli = read("apps/docs/content/docs/reference/cli.mdx");
  const conformance = read("apps/docs/content/docs/reference/conformance.mdx");

  assert(guidesMeta.pages.includes("change-sets"));
  assert(referenceMeta.pages.includes("change-sets"));
  for (const page of [guide, reference, release, cli, conformance]) {
    assert.match(page, /folderbase\.change-set@0\.1\.0/u);
  }
  assert.match(guide, /change-set checkout/u);
  assert.match(guide, /change-set propose/u);
  assert.match(guide, /change-set assess/u);
  assert.match(guide, /change-set apply/u);
  assert.match(guide, /PDFs, CSVs, SQLite files, videos/u);
  assert.match(reference, /folderbase-change-set-attention-v1/u);
  assert.match(reference, /passed: 10/u);
  assert.match(conformance, /capabilities\/change-set-0\.1\/run\.mjs/u);
  assert.match(release, /Hosted share-link/u);
  assert.match(release, /Cloud Agents remain separate/u);
});

test("the daemon capability has a runnable guide, wire reference, and honest authority model", () => {
  const guidesMeta = JSON.parse(read("apps/docs/content/docs/guides/meta.json"));
  const referenceMeta = JSON.parse(read("apps/docs/content/docs/reference/meta.json"));
  const guide = read("apps/docs/content/docs/guides/daemon-sessions.mdx");
  const reference = read("apps/docs/content/docs/reference/daemon-stdio.mdx");
  const release = read("apps/docs/content/docs/releases/0.6.1.mdx");
  const cli = read("apps/docs/content/docs/reference/cli.mdx");
  const conformance = read("apps/docs/content/docs/reference/conformance.mdx");

  assert(guidesMeta.pages.includes("daemon-sessions"));
  assert(referenceMeta.pages.includes("daemon-stdio"));
  for (const page of [guide, reference, release, cli, conformance]) {
    assert.match(page, /folderbase\.daemon-stdio@0\.1\.0/u);
  }
  assert.match(guide, /daemon serve \/path\/to\/folderbase --stdio-jsonl/u);
  assert.match(guide, /ask Core again/u);
  assert.match(reference, /physical Root Instance/u);
  assert.match(reference, /At most one hint is outstanding/u);
  assert.match(reference, /passed: 10/u);
  assert.match(conformance, /capabilities\/daemon-stdio-0\.1\/run\.mjs/u);
  assert.match(release, /no second scanner, mutation engine, network listener/u);
});

test("Folder Scope evidence has a runnable reference and honest first-share boundary", () => {
  const referenceMeta = JSON.parse(read("apps/docs/content/docs/reference/meta.json"));
  const reference = read("apps/docs/content/docs/reference/folder-scope-evidence.mdx");
  const cli = read("apps/docs/content/docs/reference/cli.mdx");
  const conformance = read("apps/docs/content/docs/reference/conformance.mdx");
  const release = read("apps/docs/content/docs/releases/next.mdx");
  const sdk = read("apps/docs/content/docs/guides/typescript-sdk.mdx");

  assert(referenceMeta.pages.includes("folder-scope-evidence"));
  for (const page of [reference, cli, conformance, release, sdk]) {
    assert.match(page, /folderbase\.folder-scope-evidence@0\.1\.0/u);
  }
  assert.match(reference, /folder-scope observe/u);
  assert.match(reference, /observeFolderScope/u);
  assert.match(reference, /eleven black-box cases/u);
  assert.match(reference, /not authorization/u);
  assert.match(reference, /does not parse or upload file contents/u);
  assert.match(conformance, /capabilities\/folder-scope-evidence-0\.1\/run\.mjs/u);
  assert.match(release, /unreleased work/u);
});

test("the public TypeScript and native process adapter seam is fully documented", () => {
  const guidesMeta = JSON.parse(read("apps/docs/content/docs/guides/meta.json"));
  const referenceMeta = JSON.parse(read("apps/docs/content/docs/reference/meta.json"));
  const guide = read("apps/docs/content/docs/guides/typescript-sdk.mdx");
  const reference = read("apps/docs/content/docs/reference/process-adapters.mdx");
  const release = read("apps/docs/content/docs/releases/0.6.1.mdx");
  const index = read("apps/docs/content/docs/index.mdx");

  assert(guidesMeta.pages.includes("typescript-sdk"));
  assert(referenceMeta.pages.includes("process-adapters"));
  for (const page of [guide, reference, release, index]) {
    assert.match(page, /@folderbase\/sdk/u);
  }
  assert.match(guide, /FolderbaseClient/u);
  assert.match(guide, /startDaemon/u);
  assert.match(guide, /PDFs, CSVs, SQLite databases, videos/u);
  assert.match(reference, /Exit `0`/u);
  assert.match(reference, /Exit `1`/u);
  assert.match(reference, /Exit `2`/u);
  assert.match(reference, /any valid JSON value/u);
  assert.match(reference, /Swift and native apps/u);
  assert.match(reference, /must not read or write `.folderbase/u);
  assert.match(reference, /test-sdk-package\.mjs/u);
});

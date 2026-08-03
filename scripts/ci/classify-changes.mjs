import { appendFileSync, readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

const documentationPath = /(^|\/)(?:[^/]+\.md|[^/]+\.(?:gif|jpe?g|png|svg|webp))$/i;
const npmLauncherPath = /^packages\/npm-cli\//;
const workspaceManifestPath = /^Cargo\.(?:lock|toml)$/;
const ciControlPath = /^(?:\.github\/workflows\/ci\.yml|scripts\/check-ci-policy\.sh|scripts\/ci\/|scripts\/tests\/ci-(?:policy|scope)\.test\.mjs)/;
const nativeInstallPath = /^(?:crates\/folderbase-cli\/|crates\/folderbase-core\/(?:Cargo\.toml$|assets\/)|scripts\/(?:test-extracted-package[^/]*|test-package-install)\.sh$)/;
const npmOnlyPath = /^(?:LICENSE|NOTICE|scripts\/(?:npm-publication-policy|test-npm-cli-package)\.mjs|scripts\/tests\/(?:compatibility-contract|npm-publication-policy|release-scripts)\.test\.mjs)$/;

export function classifyChanges(paths, { full = false } = {}) {
  const npm = full || paths.some(
    (path) =>
      npmLauncherPath.test(path) ||
      workspaceManifestPath.test(path) ||
      ciControlPath.test(path) ||
      npmOnlyPath.test(path),
  );
  const install = full || paths.some(
    (path) =>
      workspaceManifestPath.test(path) ||
      ciControlPath.test(path) ||
      nativeInstallPath.test(path),
  );
  const hasNonDocumentationChange = full || paths.some(
    (path) =>
      !documentationPath.test(path) &&
      !npmLauncherPath.test(path) &&
      !npmOnlyPath.test(path),
  );

  return {
    install,
    npm,
    platform: hasNonDocumentationChange,
    rust: hasNonDocumentationChange,
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  if (!process.env.GITHUB_OUTPUT) {
    throw new Error("GITHUB_OUTPUT is required");
  }

  const paths = readFileSync(0, "utf8")
    .split(/\r?\n/u)
    .filter(Boolean);
  const result = classifyChanges(paths, {
    full: process.argv.includes("--full"),
  });
  const outputs = Object.entries(result)
    .map(([name, value]) => `${name}=${value}`)
    .join("\n");

  appendFileSync(process.env.GITHUB_OUTPUT, `${outputs}\n`);
  process.stdout.write(`${JSON.stringify({ paths, ...result })}\n`);
}

import { appendFileSync, readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

const routineDocumentationPath = /^(?:(?:CODE_OF_CONDUCT|CONTEXT|CONTRIBUTING|README|SECURITY)\.md|docs\/superpowers\/.*\.md|.*\.(?:gif|jpe?g|png|svg|webp))$/i;
const normativeDocumentationPaths = new Set([
  "docs/cli-json-v1.md",
  "docs/compatibility-v1.md",
  "docs/protocol-spec.md",
  "docs/releasing.md",
  "docs/reorganization-protocol.md",
  "docs/template-protocol.md",
]);
const normativeAdrPath = /^docs\/adr\/000(?:3|4|5|6|8|9)-/;
const docsSitePath = /^apps\/docs\//;
const docsSiteControlPath = /^scripts\/tests\/docs-site\.test\.mjs$/;
const npmLauncherPath = /^packages\/npm-cli\//;
const sdkPackagePath = /^(?:packages\/sdk\/|scripts\/test-sdk-package\.mjs$)/;
const workspaceManifestPath = /^Cargo\.(?:lock|toml)$/;
const ciControlPath = /^(?:\.github\/workflows\/ci\.yml|scripts\/check-ci-policy\.sh|scripts\/ci\/|scripts\/tests\/ci-(?:policy|required-results|scope)\.test\.mjs)/;
const nativeInstallPath = /^(?:crates\/folderbase-cli\/|crates\/folderbase-core\/(?:Cargo\.toml$|assets\/)|scripts\/(?:test-extracted-package[^/]*|test-package-install)\.sh$)/;
const npmOnlyPath = /^(?:LICENSE|NOTICE|scripts\/(?:npm-publication-policy|test-npm-cli-package)\.mjs|scripts\/tests\/(?:compatibility-contract|npm-publication-policy|release-scripts)\.test\.mjs)$/;
const coreImplementationPath = /^crates\/folderbase-core\/(?:src|tests)\//;
const protocolContractPath = /^protocol\//;
const releaseControlPath = /^(?:\.github\/workflows\/release-cli\.yml|scripts\/.*release[^/]*\.(?:mjs|sh))$/;

function requiresFullConfidencePath(path) {
  return workspaceManifestPath.test(path) ||
    ciControlPath.test(path) ||
    normativeDocumentationPaths.has(path) ||
    normativeAdrPath.test(path) ||
    protocolContractPath.test(path) ||
    releaseControlPath.test(path);
}

function isKnownPath(path) {
  return requiresFullConfidencePath(path) ||
    routineDocumentationPath.test(path) ||
    docsSitePath.test(path) ||
    docsSiteControlPath.test(path) ||
    npmLauncherPath.test(path) ||
    sdkPackagePath.test(path) ||
    nativeInstallPath.test(path) ||
    npmOnlyPath.test(path) ||
    coreImplementationPath.test(path);
}

export function classifyChanges(paths, { full = false } = {}) {
  const requiresFullConfidence = full || paths.some(
    (path) => requiresFullConfidencePath(path) || !isKnownPath(path),
  );
  const npm = requiresFullConfidence || paths.some(
    (path) =>
      npmLauncherPath.test(path) ||
      sdkPackagePath.test(path) ||
      npmOnlyPath.test(path),
  );
  const install = requiresFullConfidence || paths.some(
    (path) =>
      nativeInstallPath.test(path) || sdkPackagePath.test(path),
  );
  const requiresCoreVerification = requiresFullConfidence || paths.some(
    (path) =>
      coreImplementationPath.test(path) || nativeInstallPath.test(path),
  );

  return {
    docs: requiresFullConfidence || paths.some(
      (path) => docsSitePath.test(path) || docsSiteControlPath.test(path),
    ),
    install,
    npm,
    platform: requiresCoreVerification,
    rust: requiresCoreVerification,
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

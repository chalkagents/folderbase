#!/usr/bin/env node

import { readFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";

const VERSION = /^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const TARGETS = [
  "aarch64-apple-darwin",
  "x86_64-apple-darwin",
  "aarch64-unknown-linux-gnu",
  "x86_64-unknown-linux-gnu",
];

function versionFromTag(tag) {
  if (typeof tag !== "string" || !tag.startsWith("v") || !VERSION.test(tag.slice(1))) {
    throw new Error(`invalid release tag: ${tag}`);
  }
  return tag.slice(1);
}

export function parseChecksums(source, tag) {
  const version = versionFromTag(tag);
  const expected = new Set(
    TARGETS.map((target) => `folderbase-v${version}-${target}`),
  );
  const result = {};
  const lines = source.split(/\r?\n/u).filter(Boolean);
  if (lines.length !== expected.size) {
    throw new Error(`SHA256SUMS must contain exactly ${expected.size} assets`);
  }
  for (const line of lines) {
    const match = line.match(/^([0-9a-f]{64})  (folderbase-v[^/\s]+)$/u);
    if (!match || !SHA256.test(match[1]) || !expected.delete(match[2])) {
      throw new Error(`unexpected SHA256SUMS entry: ${line}`);
    }
    result[match[2]] = match[1];
  }
  if (expected.size !== 0) throw new Error("SHA256SUMS omits a release target");
  return result;
}

export function renderHomebrewFormula({ version, checksums }) {
  if (!VERSION.test(version)) throw new Error(`invalid version: ${version}`);
  const asset = (target) => `folderbase-v${version}-${target}`;
  const checksum = (target) => {
    const digest = checksums[asset(target)];
    if (!SHA256.test(digest ?? "")) throw new Error(`missing checksum for ${target}`);
    return digest;
  };
  const url = (target) =>
    `https://github.com/chalkagents/folderbase/releases/download/v${version}/${asset(target)}`;

  return `class Folderbase < Formula
  desc "Open folder-based database core for agents"
  homepage "https://folderbase.ai"
  version "${version}"
  license "Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "${url("aarch64-apple-darwin")}"
      sha256 "${checksum("aarch64-apple-darwin")}"
    else
      url "${url("x86_64-apple-darwin")}"
      sha256 "${checksum("x86_64-apple-darwin")}"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "${url("aarch64-unknown-linux-gnu")}"
      sha256 "${checksum("aarch64-unknown-linux-gnu")}"
    else
      url "${url("x86_64-unknown-linux-gnu")}"
      sha256 "${checksum("x86_64-unknown-linux-gnu")}"
    end
  end

  def install
    platform = if OS.mac?
      "#{Hardware::CPU.arm? ? "aarch64" : "x86_64"}-apple-darwin"
    else
      "#{Hardware::CPU.arm? ? "aarch64" : "x86_64"}-unknown-linux-gnu"
    end

    bin.install "folderbase-v#{version}-#{platform}" => "folderbase"
  end

  test do
    assert_equal "folderbase #{version}", shell_output("#{bin}/folderbase --version").strip
    assert_match '"contract_version": "1.0.0"', shell_output("#{bin}/folderbase protocol contract --json")

    workspace = testpath/"ordinary-folder"
    workspace.mkpath
    (workspace/"ordinary.txt").write("ordinary file\\n")

    system bin/"folderbase", "init", workspace, "--json"
    assert_path_exists workspace/".folderbase/manifest.json"
    assert_match '"valid": true', shell_output("#{bin}/folderbase validate #{workspace} --json")
  end
end
`;
}

function argumentsFrom(argv) {
  const tagIndex = argv.indexOf("--tag");
  const checksumIndex = argv.indexOf("--checksums");
  if (
    tagIndex === -1 || checksumIndex === -1
    || !argv[tagIndex + 1] || !argv[checksumIndex + 1]
    || argv.length !== 4
  ) {
    throw new Error("usage: render-homebrew-formula.mjs --tag vVERSION --checksums PATH");
  }
  return { tag: argv[tagIndex + 1], path: argv[checksumIndex + 1] };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const inputs = argumentsFrom(process.argv.slice(2));
    const version = versionFromTag(inputs.tag);
    const checksums = parseChecksums(await readFile(inputs.path, "utf8"), inputs.tag);
    process.stdout.write(renderHomebrewFormula({ version, checksums }));
  } catch (error) {
    process.stderr.write(`folderbase Homebrew formula: ${error.message}\n`);
    process.exitCode = 1;
  }
}

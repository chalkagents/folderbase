#!/usr/bin/env node

import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";

if (process.argv.length !== 4) {
  throw new Error("usage: generate-unicode-casefold-v9.mjs TABLES.rs OUTPUT.mjs");
}

const sourcePath = resolve(process.argv[2]);
const outputPath = resolve(process.argv[3]);
const source = await readFile(sourcePath, "utf8");
const sourceSha256 = createHash("sha256").update(source).digest("hex");

function section(name, nextName) {
  const start = source.indexOf(`pub static ${name}`);
  const end = source.indexOf(`pub static ${nextName}`, start);
  if (start === -1 || end === -1) throw new Error(`missing ${name} table`);
  return source.slice(start, end);
}

const mappings = new Map();
for (const match of section("COMMON_TABLE", "FULL_TABLE").matchAll(
  /\('\\u\{([0-9a-f]+)\}', '\\u\{([0-9a-f]+)\}'\)/gu,
)) mappings.set(Number.parseInt(match[1], 16), [Number.parseInt(match[2], 16)]);

const full = section("FULL_TABLE", "SIMPLE_TABLE");
for (const line of full.split("\n")) {
  const codepoints = [...line.matchAll(/'\\u\{([0-9a-f]+)\}'/gu)]
    .map((match) => Number.parseInt(match[1], 16));
  if (codepoints.length >= 3) mappings.set(codepoints[0], codepoints.slice(1));
}

const rows = [...mappings]
  .sort(([left], [right]) => left - right)
  .map(([input, output]) => `  [0x${input.toString(16)}, [${output.map((value) => `0x${value.toString(16)}`).join(", ")}]],`)
  .join("\n");
const generated = `// Generated from unicode-casefold 0.2.0 (Unicode 9.0.0).\n// Source: https://docs.rs/crate/unicode-casefold/0.2.0/source/\n// crates.io checksum: b7f66b1c8f8caa2ab31dc6d3f35386f16efdab89668f93411e565ac368908e8f\n// Source SHA-256 (src/tables.rs): ${sourceSha256}\n// Copyright Chris Wong and unicode-casefold contributors.\n// Licensed under MIT OR Apache-2.0; see THIRD_PARTY_NOTICES.md beside this file.\n// This modified/derived checked-in module is self-contained. Regeneration is\n// optional and uses generate-unicode-casefold-v9.mjs; do not edit by hand.\n\nexport const UNICODE_CASEFOLD_VERSION = Object.freeze([9, 0, 0]);\nexport const FULL_DEFAULT_CASE_FOLD_V9 = new Map([\n${rows}\n]);\n`;
await writeFile(outputPath, generated);

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const caseName = process.argv[2];
const supported = new Set([
  "aggregate-split",
  "component-byte-limit",
  "path-byte-limit",
  "depth-limit",
]);
if (!supported.has(caseName)) {
  throw new Error(
    `usage: node generate-runtime-limit-vector.mjs ${[...supported].join("|")}`,
  );
}

const here = dirname(fileURLToPath(import.meta.url));
const base = JSON.parse(
  readFileSync(join(here, "../valid/minimal-restorable-v1.json"), "utf8"),
);
base.version_id = "fbversion_0198ee40-a111-7aaa-8000-000000000030";

function directory(path, suffix) {
  return {
    path,
    object_id: `obj_0198ee40-b222-7bbb-8000-${suffix
      .toString(16)
      .padStart(12, "0")}`,
    lifecycle: "live",
    kind: "directory",
  };
}

function sortBindings() {
  base.bindings.sort((left, right) =>
    Buffer.compare(Buffer.from(left.path), Buffer.from(right.path)),
  );
}

switch (caseName) {
  case "aggregate-split":
    for (let index = 0; index < 8_191; index += 1) {
      base.bindings.push(directory(`b${index.toString().padStart(5, "0")}`, 0x10_000 + index));
    }
    base.tombstones = Array.from({ length: 8_192 }, (_, index) => ({
      path: `t${index.toString().padStart(5, "0")}`,
      object_id: `obj_0198ee40-b222-7bbb-8000-${(0x20_000 + index)
        .toString(16)
        .padStart(12, "0")}`,
      lifecycle: "deleted",
      deleted_kind: "directory",
      last_object_version_id: null,
    }));
    break;
  case "component-byte-limit":
    base.bindings.push(directory("é".repeat(128), 0x502));
    break;
  case "path-byte-limit": {
    const components = Array.from({ length: 17 }, () => "é".repeat(120));
    components[components.length - 1] += "x";
    base.bindings.push(directory(components.join("/"), 0x504));
    break;
  }
  case "depth-limit":
    base.bindings.push(directory(Array.from({ length: 129 }, () => "d").join("/"), 0x505));
    break;
}

sortBindings();
process.stdout.write(`${JSON.stringify(base, null, 2)}\n`);

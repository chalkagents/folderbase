import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const repositoryRoot = join(
  dirname(fileURLToPath(import.meta.url)),
  "..",
  "..",
);

test(
  "the released 0.5 distribution is verified from its immutable tag",
  { timeout: 30_000 },
  () => {
    const result = spawnSync(
      process.execPath,
      [
        join(
          repositoryRoot,
          "scripts",
          "verify-folderbase-version-0.5-distribution.mjs",
        ),
      ],
      {
        cwd: repositoryRoot,
        encoding: "utf8",
      },
    );

    assert.equal(
      result.status,
      0,
      [result.stdout, result.stderr].filter(Boolean).join("\n"),
    );
    assert.match(
      result.stdout,
      /Folderbase protocol 0\.5 released distribution verified:/,
    );
  },
);

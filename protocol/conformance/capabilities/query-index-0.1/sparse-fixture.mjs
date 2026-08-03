import assert from "node:assert/strict";

export const SPARSE_FIXTURE_MAX_ALLOCATED_BYTES = 16n * 1024n * 1024n;

export function markSparseFileForLogicalSizing(
  path,
  platform = process.platform,
  execute = () => ({ status: 0 }),
) {
  if (platform !== "win32") return;
  const result = execute("fsutil", ["sparse", "setflag", path], {
    encoding: "utf8",
    windowsHide: true,
  });
  assert.equal(
    result.status,
    0,
    `failed to mark the Windows conformance fixture sparse: ${result.stderr ?? result.error ?? "unknown fsutil failure"}`,
  );
}

export function assertSparseFixture(metadata, expectedBytes, platform = process.platform) {
  assert.equal(metadata.size, BigInt(expectedBytes));

  // Node exposes NTFS `blocks`, but it is not the POSIX 512-byte allocation
  // count and may equal a sparse file's logical length. Windows therefore
  // proves the exact logical fixture size; POSIX hosts prove allocation too.
  if (platform === "win32") return;

  assert.equal(
    typeof metadata.blocks,
    "bigint",
    "non-Windows hosts must expose sparse allocation blocks",
  );
  assert.ok(
    metadata.blocks * 512n <= SPARSE_FIXTURE_MAX_ALLOCATED_BYTES,
    "the 10 GiB fixture must remain sparsely allocated below 16 MiB",
  );
}

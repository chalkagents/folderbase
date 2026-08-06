# Root reconstruction capability implementation plan

Status: R1–R4 released in Core 0.7.1; ADR-0016 accepted 2026-08-06

## Outcome

From one public reconstruction package containing an exact retained
`folderbase-version-v1`, canonical manifests, and chunks, a compatible
`folderbase` executable reconstructs one absent ordinary Folderbase root. The
result works like a normal local folder, opens through Core with the selected
Version as Local Head, preserves retained Tombstone restore, and never depends
on private Folderbase Platform code.

## Merge sequence

### R1 — freeze schemas, fixtures, and RED runner

- Add the capability registry entry, package/request/result/attention/error
  schemas, public fixture generator, and implementation-neutral runner.
- Cover mixed file types, retained Tombstone closure, exact package pins,
  malformed input, no-clobber, and deterministic crash seams.
- Keep the reference CLI unadvertised so the new suite fails for the intended
  missing capability rather than weakening capability discovery.

Exit: the public runner is independently runnable and RED against v0.6.1.

### R2 — deepen Core around a reconstruction plan

- Add one `root_reconstruction` module that owns bounded package decode,
  Version/reference closure validation, deterministic planning, and typed
  results.
- Reuse `FolderbaseVersion`, canonical Chunk Manifest validation, transfer
  verification, portable path rules, root attestation, and local immutable
  object/version writers. Do not duplicate scanners or Platform records.
- Unit-test closure mismatches, including the current missing-Tombstone case
  and an unchanged move whose one Object Version reference has both live-file
  and retained-Tombstone roles.

Exit: pure plan and verification tests are GREEN; no destination publication
exists yet.

### R3 — journaled staging and directory no-replace publication

- Create capability-rooted private staging, exact operation journals, durable
  completion records, and platform-specific atomic no-replace directory
  publication.
- Preserve every supported binding kind and local database record required for
  follow-up capture and Tombstone restore.
- Add deterministic process-loss seams before staging, after object verify,
  before publish, after publish, and before completion output.
- Preflight the filesystem durability contract and fail before staging on any
  platform or filesystem where both file and directory-entry persistence
  cannot be proven.

Exit: focused Core tests prove no partial visible root, no clobber, exact retry,
and convergence on supported Linux, macOS, and Windows filesystems; unsupported
durability semantics fail before staging or publication.

### R4 — CLI, SDK, and independent conformance

- Wire the exact process contract without a shell and add the supervised
  `@folderbase/sdk` helper.
- Run the public black-box runner against the reference executable and a small
  independent fixture verifier.
- Advertise `folderbase.root-reconstruction@0.1.0` only after every profile
  passes.

Exit: a clean consumer can discover and invoke the capability without reading
`.folderbase` internals.

### R5 — Platform closure and local-cell clean-device restore

- Extend managed Version registration to retain every Tombstone last-Object-
  Version reference while preserving exact actor/sponsor/root fences.
- Add durable Root Reconstruction Session and operation-owned private-stage
  reachability pins to physical-generation accounting. Collection must fail
  closed while either pin is live, across restart and collection races.
- Build packages only from one authorized, retained Root Reconstruction
  Session and download immutable chunks directly from the local S3-compatible
  cell.
- Consume only supervised Core completion evidence before Device Cursor
  advancement.

Exit: PostgreSQL 16 plus MinIO reconstructs the real mixed-file fixture on a
clean device byte-for-byte, restores a retained deleted file, survives process
restart and a concurrent collection attempt, retains session/stage-reachable
bytes until trusted completion, and advances only the qualifying Device cursor.

## Required local gates per slice

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features --locked
node protocol/conformance/cli-json-v1/run.mjs --implementation ./target/debug/folderbase
node protocol/conformance/capabilities/run.mjs --implementation ./target/debug/folderbase
node --test protocol/conformance/capabilities/run.test.mjs scripts/tests/capability-contract.test.mjs
scripts/check-ci-policy.sh
scripts/check-public-eclipse.sh
scripts/test-package-install.sh
```

GitHub-hosted Actions are optional evidence while account quota is unavailable;
the same path-scoped gates must pass locally and be recorded with exact commit
and fixture hashes before merge.

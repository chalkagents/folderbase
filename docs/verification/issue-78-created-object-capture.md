# Issue 78: created Object identity through Change Set capture

## Scope and status

Local repair candidate based on `5ac6eecd93b5e84940942ad62317020b081a22bb`.
This change does not publish a release, change a portable record or public API,
or claim a hosted service. Product expansion is separate from this correction.

## Failure and correction

A clean Change Set can create a new ordinary file. The proposal already gives
that file a stable Object ID. Applying the proposal publishes its bytes, but
the subsequent general-purpose capture previously assigned another new ID.
History finalization then failed because the proposed Object was absent from
the captured identity set.

The capture path used by Change Set apply now retains Core's proposed creation
IDs before its existing durable assignment journal is written. The assignment
checks also cover resumed capture transactions. General capture still assigns
fresh IDs to unrelated new files, and existing Object lineage remains checked
against the verified parent. No capture schema is extended.

The implementation builds an index of proposed paths, then walks capture
assignments; it does not scan the entire workspace separately for each delta.

## Public executable coverage

The Change Set suite now has thirteen scenarios. New coverage includes:

- added-only work and preservation of its exact Object ID in history;
- a second fresh checkout that renames and edits the created file;
- creation plus modification, rename, deletion, new directories, binary bytes,
  and an empty file in one proposal;
- creation interrupted after the journal, first visible mutation, and history
  Head publication; and
- idempotent replay without additional immutable Versions.

The original added-only case was run against unmodified main first and failed
with the exact omitted-Object operational error from issue 78.

### Development verification

- Workspace regression suite: 1,106 passed, zero failed, three ignored across
  43 suites. This run preceded the equivalent private lookup optimization.
- Final optimized CLI: all thirteen Change Set scenarios passed, including
  second-session identity and crash/replay coverage.
- Final optimized CLI: the local loop and legacy-pending characterization below
  passed.
- Conformance/registry runner self-tests: 20 passed.
- Final formatting, clippy with warnings denied, CI policy, public naming
  policy, and diff whitespace checks passed.

These are local development checks. A published release still needs its
complete checks on the selected immutable candidate and supported platforms.

## Reproduce the local product loop

From this checkout:

```sh
cargo build --package folderbase-cli --locked
node scripts/verify-local-agent-loop.mjs --implementation ./target/debug/folderbase
```

The script creates a disposable fixture, prints its location, and leaves a
`report.json` beside the source, scoped checkouts, and staging data. It proves:

1. Initialize existing files in place.
2. Give a local simulated agent only the `shared` folder.
3. Modify a brief and create a new report.
4. Assess, apply, and replay the proposal.
5. Continue the created report in a second fresh session with the same ID.
6. Restore its original bytes to a new path and reject an overwrite.
7. Verify that a private sibling remains unchanged.

This uses synthetic local scope IDs and the caller's filesystem authority.
It does not simulate cloud authentication or an operating-system sandbox.
The edits are deterministic fixture operations, not a claim of a live model run.

## Existing failed 0.7.2 transactions

This candidate repairs new transactions. It does **not** migrate a pending
transaction whose wrong-identity capture was already published by 0.7.2.

The official macOS arm64 0.7.2 binary was checked against its release SHA-256:

```text
526b34d3dd86b98197779e0d7d80a30cd426b09e465c5ca2ee2fbf1b3246e1b6
```

With that binary, an added-only proposal assesses clean, apply exits 2, and the
new file nevertheless exists in the ordinary source folder. Retrying the same
pending proposal with this candidate still exits 2; the proposed ordinary
bytes remain unchanged. This confirms the September 8 issue comment's narrower
observation and supersedes the issue body's assertion of no visible mutation.

To characterize the same boundary with a previously downloaded binary:

```sh
node scripts/verify-local-agent-loop.mjs \
  --implementation ./target/debug/folderbase \
  --legacy-implementation /absolute/path/to/folderbase-v0.7.2-aarch64-apple-darwin
```

Keep an affected old root, its metadata, and its proposal/staging intact.
Deleting engine-owned records is not a supported recovery procedure. A safe
migration for those pending transactions needs a separate, reviewed recovery
contract before any claim of automatic upgrade repair.

## Remaining product boundaries

- Query is currently an experimental metadata inventory, not SQL or queries
  inside JSON, CSV, documents, or database files.
- The CLI exposes per-file history and recovery; full-root reconstruction uses
  a verified package whose producer is currently a Rust API.
- The low-level checkout request expects scope IDs/revision evidence. A simpler
  local application entry point is a product/API design question, not part of
  this correctness patch.
- Recoverable publication does not make several ordinary filesystem writes
  simultaneously invisible to external readers.
- This fixture does not establish application-consistent capture of live
  databases, production reliability, customer demand, or cloud readiness.

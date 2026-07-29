# FB-41F byte-verified sealing and Local Head evidence

Date: 2026-07-30

Status: implementation evidence for the second ADR-0005 slice. ADR-0005 remains
Proposed.

## Red

The first commit added the public capture contract before implementation:

```text
17b29f3404ee98e701dbbee849f84f5d589d1f69
test(core): define durable Folderbase capture contract
```

The focused test failed to compile with twelve errors for the absent
`seal_capture`, sealed-version reader, result type, and typed state-change
surface:

```text
cargo test -p folderbase-core --test folderbase_seal
error[E0599]: no method named `seal_capture`
error[E0599]: no method named `read_version`
error[E0599]: no variant named `CaptureStateChanged`
```

The final standards review added a second explicit RED commit:

```text
bc4950333d90b3f560d5395ebe767a06525c88a1
test(core): expose final FB-41F sealing bounds
```

At that exact commit, the focused unit target failed to compile because the
bounded source-reader argument and bounded preflight seam did not yet exist:

```text
error[E0599]: no method named `seal_capture_with_hook_and_limits`
error[E0061]: this method takes 3 arguments but 4 arguments were supplied
```

The corresponding GREEN implementation is:

```text
010cf10c4fb5be0f9f1159f7bfa0771dd8542655
fix(core): bound FB-41F sealing before publication
```

The read-only Windows follow-up preserved one more RED/GREEN pair:

```text
52e82656db4f576067d97a083523ba66ecbe0445
test(core): require read-only Windows version inspection

d96cdaba2f059008292f32a9945db0430195788b
fix(core): separate read-only Folderbase state handles
```

At the RED commit, the focused state test failed to compile because
`open_existing_read_only` did not exist. The GREEN implementation gives
verification and mutation distinct retained capability modes, refuses mutation
through the read-only mode, and uses only `GENERIC_READ` for Windows
`read_version`. A Windows-only integration regression holds root and state
directory handles that share reads but deny write access while verifying a
complete sealed Folderbase Version.

## Green behavior

The implementation proves:

- genesis and update Folderbase Versions with exact parent linkage;
- stable Object ID reuse only from a verified prior Local Head binding;
- fail-closed reuse when physical-identity evidence is missing, including
  replacement after Head but before derived identity projection;
- Unix device/inode and Windows volume plus 128-bit File ID continuity from
  opened no-follow handles;
- new IDs persisted in a durable transaction before immutable object writes;
- exact active-journal cardinality and prior-lineage validation, with bounded
  streaming JSON encoding under the same declared writer/restart byte bound;
- preflight encoding of the complete future Folderbase Version before the
  journal or any immutable object is published;
- content reads stop after one byte beyond the exact planned length, remove
  staging, and report the concurrent source change without consuming a growing
  file to EOF;
- Local Head anchoring of the complete capture-journal digest, with
  post-Head journal-observation tamper refusal;
- exact committed parent and timestamp validation before recovery may project
  identity evidence;
- exact bytes for PDF, video, CSV, SQLite, Git packs, office-shaped, binary, and
  unknown files without format interpretation;
- directory, symlink target, empty-directory, and executable fidelity;
- a practical 8 MiB capture fixture plus the separate metadata-only 10 GiB
  planning fixture;
- required markers, ordered exclusions, nested boundaries, and
  `.folderbase/**` non-capture;
- concurrent/stale metadata rejection without Local Head movement;
- no-op and crash retry convergence on the exact assigned Folderbase Version;
- append-only blob, Object Version, and complete Folderbase Version
  verification before Local Head compare-and-replace;
- capability-confined journal, blob, Object Version, Folderbase Version,
  derived projection, identity, and Head publication;
- one capture-specific physical-identity projection, without a second
  path-identity representation that could diverge;
- a retained-parent swap regression proving an outside symlink receives no
  state writes;
- a seal-prelude regression proving no lock or state publication occurs before
  the retained state capability is open and the plan is re-attested;
- shared Windows reparse-point rejection for root, state, workspace, and seal
  mutation paths, plus native Windows directory-junction and writable
  directory-flush regressions;
- least-privilege read-only state and version verification that does not request
  Windows directory write authority;
- an exclusive cross-platform transaction file-lock contention test;
- fresh-process recovery at journal, object-write, Folderbase-Version,
  Head-replace, and cleanup checkpoints;
- no lost prior Head during update recovery;
- stale-intent cleanup while retaining only safe content-addressed or immutable
  orphans;
- explicit no-write refusal when a deletion requires an unimplemented
  Tombstone.

Focused gates:

```text
cargo test -p folderbase-core --test folderbase_seal
6 passed; 0 failed on macOS; 7 tests are selected on Windows

cargo test -p folderbase-core --lib folderbase_seal::tests::
13 passed; 0 failed

cargo test -p folderbase-core --lib folderbase_state::tests::
3 passed; 0 failed on macOS

cargo test -p folderbase-core --lib local_versions::tests::transaction_lock_is_exclusive_across_independent_handles
1 passed; 0 failed

cargo check -p folderbase-core --target x86_64-pc-windows-msvc
passed

cargo clippy --workspace --all-targets -- -D warnings
passed
```

The Windows target has four state tests: read-only inspection, bounded source
streaming, junction refusal, and writable-capability publication/flush. Its
read-only version integration regression is also selected there. Their runtime
result is owned by the checked-in `windows-latest` CI job.

Full local workspace gate:

```text
cargo test --workspace
passed
```

## Truth boundary

This evidence does not claim Tombstone production, same-path recreation,
kind-replacement capture, complete restore/no-clobber reconstruction, restore
crash recovery, filesystem or database snapshot coordination, Remote Head,
sync, sharing, authorization, Cloud durability, or hosted deployment. Those
remain required before ADR-0005 can be Accepted.

The local cross-target library check proves Windows code compiles, while the
checked-in `windows-latest` CI matrix owns runtime proof for Windows File IDs,
exclusive locking, Head replacement, and crash recovery. A local macOS host
cannot execute that Windows binary.

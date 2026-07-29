# TB-33 byte-verified sealing and Local Head evidence

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

## Green behavior

The implementation proves:

- genesis and update Folderbase Versions with exact parent linkage;
- stable Object ID reuse only from a verified prior Local Head binding;
- fail-closed reuse when physical-identity evidence is missing, including
  replacement after Head but before derived identity projection;
- Unix device/inode and Windows volume plus 128-bit File ID continuity from
  opened no-follow handles;
- new IDs persisted in a durable transaction before immutable object writes;
- exact active-journal cardinality and prior-lineage validation, plus one
  declared writer/restart byte bound;
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
- a retained-parent swap regression proving an outside symlink receives no
  state writes;
- a seal-prelude regression proving no lock or state publication occurs before
  the retained state capability is open and the plan is re-attested;
- shared Windows reparse-point rejection for root, state, workspace, and seal
  mutation paths, plus a native Windows directory-junction regression;
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
6 passed; 0 failed

cargo test -p folderbase-core --lib folderbase_seal::tests::
12 passed; 0 failed

cargo test -p folderbase-core --lib folderbase_state::tests::
1 passed; 0 failed

cargo test -p folderbase-core --lib local_versions::tests::transaction_lock_is_exclusive_across_independent_handles
1 passed; 0 failed

cargo check -p folderbase-core --target x86_64-pc-windows-msvc
passed

cargo clippy --workspace --all-targets -- -D warnings
passed
```

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

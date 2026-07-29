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
- new IDs persisted in a durable transaction before immutable object writes;
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
5 passed; 0 failed

cargo test -p folderbase-core folderbase_seal::tests
4 passed; 0 failed

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

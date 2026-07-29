# TB-33 metadata-only capture planning verification

This evidence covers only phases 1–3 of the proposed capture transaction:
controlled Folderbase Version encoding, read-only store/open and Capture Plan
inventory, and ordered ignore-policy planning.

## Exact base

The work started from the public Core v0.4.0 tag target:

```text
7160017612c9f557803c74031f1715c516935f6c
```

After implementation, the branch was rebased onto the proof-only `origin/main`
commit `7f873d1c4fef43d9fb9a1a1385a2f5c314119b75`. That commit records the public
Core v0.4.0 proof and does not change the product baseline.

## RED evidence

Each public seam failed before its implementation:

```text
folderbase_version_conformance:
  no method named `encode_bounded` found for `FolderbaseVersion`

folderbase_capture open/plan:
  no `FolderbaseVersionStore`, `CapturePlan`, or `CaptureEntryKind`

ordered ignore planning:
  UnsafePortablePath("dist/deep/CON")
  (the default-excluded directory was incorrectly descended)

nested-boundary/opaque-format planning:
  no typed capture exclusion kind or reason

10 GiB metadata/object bound:
  no `CapturePlanLimitKind` or `InventoryLimitExceeded`

optional Local Head:
  expected an observed current head, found `None`

hard-link/FIFO fidelity:
  hard-linked regular files were incorrectly emitted as ordinary entries

symlink fidelity:
  no exact-target accessor or unsafe-target error

malformed nested marker:
  UnsafePortablePath("Clients/Malformed/CON")
  (planning descended past an invalid child entry marker)

symlink root:
  `FolderbaseVersionStore::open` accepted the symlink target after canonicalizing
  before root attestation

crate-private producer:
  no sibling-accessible constructors for `RootManifest`, `PathBinding`, or the
  closed `FolderbaseVersionParts`
```

The initial RED command was also repeated after a clean generated-target failure
caused by a full disk. The repeated run reached Rust compilation and failed on
the missing API, separating product RED from environmental pressure.

## GREEN evidence

Focused public tests currently prove:

```text
cargo test --package folderbase-core --test folderbase_version_conformance --locked
  14 passed

cargo test --package folderbase-core --lib folderbase_version_producer_tests --locked
  1 passed

cargo test --package folderbase-core --lib capability_tests --locked
  1 passed

cargo test --package folderbase-core --test folderbase_capture --locked
  15 passed on macOS
  plus Linux-only non-UTF-8 and case-collision coverage in hosted CI
```

The capture suite proves:

- exact root attestation, no writes, and optional Local Head binding;
- rejection of a caller-supplied symlink root before canonicalization;
- capability-relative Local Head reads that reject an intermediate state
  symlink;
- direct sibling-module construction of every v1 producer record shape without
  raw deserialization, followed by complete validation and bounded encoding;
- ordered Core defaults plus user negation and required-marker override;
- streaming, root-relative no-follow traversal that classifies ignored
  directories before opening them and rechecks opened directory identities;
- no descent into a definitively ignored or nested Folderbase directory,
  including a malformed nested entry marker paired with nested state;
- opaque metadata handling for PDF, video, CSV, SQLite, Git pack, and unknown
  regular files;
- a content-unreadable 10 GiB sparse file is planned by length alone;
- per-object, path-depth, and aggregate-record bounds;
- exact safe symlink targets and rejection of escape targets;
- typed nested-boundary, hard-link, FIFO, and other special-node exclusions;
- fail-closed portable paths, including Linux non-UTF-8 and case collisions; and
- a closed Local Head from another physical root is rejected.

The complete local quality gate also passes:

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --locked
cargo test --workspace --all-features --locked
scripts/test-package-install.sh
scripts/check-ci-policy.sh
scripts/check-public-eclipse.sh
node scripts/verify-reorganization-digest-vector.mjs
node scripts/verify-folderbase-version-digest-vectors.mjs
node scripts/verify-folderbase-version-distribution.mjs
```

The packaged Core archive contains the capture implementation, public test, and
fixture; both extracted packages build and test outside the checkout, and the
installed CLI initializes a Folderbase.

The Core library cross-checks for `x86_64-pc-windows-msvc`. Cross-checking the
integration-test binary itself from macOS stops in the unrelated `aws-lc-sys`
development dependency because the host has no Windows SDK headers. Hosted CI
therefore runs the exact public capture test natively on both Windows and macOS;
Linux runs it as part of the full workspace gate.

No evidence in this document claims sealing, Local Head mutation, restore, crash
recovery, snapshot atomicity, database consistency, sync, sharing,
authorization, or Cloud.

# FB-41F exact no-clobber Tombstone restore

This evidence covers the first explicit restore operation for productive
Folderbase Version Tombstones. The public seam is:

```rust
FolderbaseVersionStore::restore_tombstone(portable_path)
```

The CLI seam is:

```text
folderbase version restore-tombstone ROOT PORTABLE_PATH --json
```

## Transition base

The branch starts from accepted capture/Tombstone merge:

```text
70a999b345ae46deba062c89dac5078ab1a5a1c0
feat(core): seal productive tombstones safely (#27)
```

No second object, version, or content store was introduced. Restore consumes
the existing immutable `LocalVersionStore` Object Version record and SHA-256
blob named by the current Head Tombstone.

## RED evidence

- `b1ee74f` required exact ordinary-file bytes, executable fidelity, original
  Object ID/Object Version, immutable deletion history, and a new Local Head.
  It failed to compile because `restore_tombstone` did not exist.
- `869b443` required retry convergence across journal, stage, target
  publication, version, Head, projection, and cleanup checkpoints. It failed to
  compile because no restore checkpoint/recovery seam existed.
- `c2f288c` required a fresh-process CLI JSON round trip. It failed because
  `restore-tombstone` was an unrecognized subcommand.
- `f5561df` required active-journal exclusion, tamper refusal, bounded and
  hostile ancestry handling, and root confinement. The nested-Folderbase
  regression failed because restore initially crossed a newly created child
  boundary.
- `20ecf87` strengthened journal tamper coverage by changing only executable
  fidelity and recomputing the target digest. It failed because recovery had
  not yet re-derived fidelity from verified ancestry.
- `7ee012e` required case-folded `.folderbase/manifest.json` aliases to remain
  nested restore boundaries on case-sensitive filesystems. The pure
  case-folding seam failed to compile before the boundary matcher existed.
- `baffd20` required final retained-stage identity, byte/fidelity, nested
  boundary, and physical-root attachment revalidation. It failed to compile
  because the final verification seam did not exist.
- `a7b429c` converted the first fixed-head review into regressions for
  same-byte replacement, in-place mutation, post-Head rollback, independently
  rewritten journal assignment, a nearer candidate hiding a deeper cycle,
  late nested-boundary closure, and copied replacement roots.
- `be97f9c` converted the second fixed-head review into regressions for two
  convergent-edge cycle shapes and a coordinated committed journal, Head, and
  valid-target rewrite.
- `28a6fdb` used an isolated restrictive-umask child process to prove that
  create-time mode bits alone did not preserve executable restore fidelity.
- `4ef4fa5` extended committed recovery tamper to rewrite the journal's prior
  Head transaction digest, every dependent deterministic assignment, the valid
  target Version, retained stage, and current Head. The prior implementation
  accepted that coordinated rewrite.
- `e7bf984` required post-Head projection to keep using retained capabilities
  and to roll Head back if projection failed. The prior implementation could
  leave the new Head visible after projection failure.
- `b24614c` required an in-place edit of the transaction-owned published target
  to preserve the new workspace bytes while relinquishing restore ownership.
  The prior implementation left durable restore intent blocking capture.
- `62df4cb`, `b497099`, and `af4b4b6` required successful transaction-directory
  retirement and restartable cleanup whose durable receipt survives active
  journal retirement. The prior implementation leaked transaction directories
  or could lose the final cleanup obligation.
- `773955f` required captured and restore-derived Heads to carry different,
  closed authority meanings while released v1 capture Heads still recover. The
  old wire used one ambiguous `transaction_sha256` field for both meanings.

## GREEN behavior

- `04dc017` restores exact opaque bytes and v1 executable fidelity, reactivates
  the same Object ID and Object Version, creates one full-state child version,
  removes only the selected Tombstone, and advances Local Head after complete
  verification.
- `1bf3942` adds a bounded durable restore journal, retained private stage,
  same-inode retry proof, and seven-checkpoint crash convergence.
- `7fc2646` exposes the fresh-process CLI and stable JSON result.
- `9109526` covers same-byte foreign competitors, every occupied leaf kind,
  corrupt/missing immutable state, newest deletion generation, carried
  Tombstones, multiple Tombstones, capture/restore exclusion, bounded,
  ambiguous, and cyclic ancestry, symlink-parent swaps, and new nested
  Folderbase boundaries.
- `8158080` binds pending journal fidelity back to the current verified
  Tombstone and nearest verified live ancestor before staging.
- `c807298` discovers nested state and manifest components capability-relatively
  with ASCII case folding and refuses ambiguous aliases.
- `9f6d7f6` and `bd5fc2b` retain and compare exact stage/destination and
  physical-root identities, stream-verify bytes and fidelity, and recheck
  case-folded nested boundaries without cross-target warnings.
- `981e22a` derives transaction and target Version identity from verified
  immutable authority, validates the complete reachable ancestry DAG, performs
  live publication proofs immediately before and after Head CAS, and restores
  the prior Head on the retained root capability before reporting a
  post-Head conflict.
- `d338982` builds the complete bounded ancestry adjacency graph, validates it
  independently with an iterative acyclic pass, and re-derives full restore
  authority in both prior-Head and committed-Head recovery branches.
- `9841f2d` explicitly applies Unix restore-stage permissions through the open
  capability after creation, before sync and verification.
- `c476afc` atomically pre-binds the verified parent Head to a
  domain-separated digest of surviving root and Version authority before the
  restore journal exists. Both restore execution branches and rollback require
  the rederived parent/target Head authorities; capture journal binding remains
  unchanged.
- `1755a57` confines projection to the retained state capability and restores
  the prior Head when post-Head projection cannot be proven.
- `2805ce7` distinguishes a transaction-owned unchanged target from an in-place
  user or agent edit, preserves edited workspace bytes, and retires only the
  transaction's ownership and private stage.
- `329e8d7`, `d47e0c0`, and `e28108f` durably retire successful private
  transaction directories through a singleton cleanup receipt. Receipt-only
  recovery re-derives the exact target and converges, and capture remains
  excluded until final receipt retirement.
- `4b620b5` writes `folderbase-local-head-v2` with the closed
  `capture_transaction_v1` or `version_derived_v1` authority. It independently
  verifies version-derived authority, rejects unknown or mismatched
  discriminators, and reads released v1 `transaction_sha256` only as capture
  authority before CAS normalization under the transaction lock.

The transaction is same-path and no-clobber. A preexisting regular file,
directory, symlink, or dangling symlink is unchanged. Matching bytes are not
ownership evidence. Recovery accepts an already published target only when it
is the exact same filesystem object as the retained private stage.

The current verified Head must contain an exact regular-file Tombstone. A
bounded, cycle-detecting ancestor DAG search selects the nearest live binding
with the same path, Object ID, and Object Version. Competing nearest bindings
must agree exactly, including executable fidelity. Missing, corrupt,
ambiguous, cyclic, or over-limit lineage fails before restore publication.
A nearer candidate cannot hide a deeper reachable cycle; a legitimate
convergent DAG is accepted.
Committed-Head recovery performs the same parent, Tombstone, binding,
assignment, and exact-child derivation as first execution; a coordinated
journal, Head, and installed-target rewrite is not recovery authority.
The journal's copy of the prior Head transaction digest is not authority
either. Restore first binds the verified parent Head to an independently
derivable digest, and target-Head recovery rejects any replacement value even
when every journal-dependent ID and digest was recomputed consistently.

The mutable journal is not assignment authority. Transaction and target
Version IDs are deterministic domain-separated derivations of the verified
Head, Tombstone, binding, Folderbase, and physical root, while the timestamp is
re-derived from the verified parent. Final target identity, content, fidelity,
root attachment, and nested-boundary proofs run immediately before and after
Head CAS. Post-Head failure rolls the retained root back to its prior Head and
never reports restore success. Projection uses the already-retained state
capability. Cleanup records its obligation durably before removing the retained
stage and per-transaction directory, retains that receipt through active-journal
retirement, and resumes from either active intent or the singleton receipt after
restart. If the published transaction-owned file is edited in place, Core
preserves the edit, relinquishes its restore ownership, and permits the ordinary
next capture.

## Gates

The frozen implementation passed:

```text
cargo fmt --all -- --check
git diff --check

cargo test --workspace --all-features --locked
596 passed; 3 ignored

cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
passed

RUSTDOCFLAGS="-D warnings" \
  cargo doc --workspace --all-features --no-deps --locked
passed

RUSTFLAGS="-D warnings" \
  cargo check -p folderbase-core \
  --target x86_64-pc-windows-msvc --locked --all-features
passed

RUSTFLAGS="-D warnings" \
  cargo check -p folderbase-core \
  --target aarch64-unknown-linux-gnu --locked --all-features
passed

bash scripts/test-package-install.sh
passed; Core packaged 55 files, CLI packaged 10 files, extracted package
tests passed, and the fresh release install reported folderbase 0.4.0

bash scripts/check-ci-policy.sh
passed

bash scripts/check-public-eclipse.sh
passed

node scripts/verify-folderbase-version-distribution.mjs
passed; 32 files

node scripts/verify-folderbase-version-digest-vectors.mjs
passed

node scripts/verify-reorganization-digest-vector.mjs
passed
```

The Windows and Linux commands are compile checks. Runtime proof on those
platforms remains owned by the repository CI matrix.

## Claims and nonclaims

This slice claims exact no-clobber restore only for a current-Head
regular-file Tombstone whose nearest verified live ancestor preserves the v1
binding. It preserves opaque bytes and the v1 executable boolean. It does not
claim complete POSIX mode, ACL, xattr, Finder metadata, database snapshot
coordination, directory restore, symlink restore, arbitrary-destination
checkout, Remote Head, sync, sharing, authorization, Cloud durability, or
hosted deployment.

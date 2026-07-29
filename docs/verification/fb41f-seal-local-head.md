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

The independent threat review preserved three final bounded-read RED/GREEN
pairs:

```text
3a13020ef36953244fa5215c311715fa25e06d01
test(core): expose unbounded repeat capture reads

d520356d63a80e2b0d9bea395b7d2236f98b6cfd
fix(core): bound repeat capture verification

1b6f49220ffe53694c87a5d98f255a0d81f81442
test(core): expose unbounded blob verification

da219cc09105b3468ffac3f2d1ac56063182719d
fix(core): bound immutable blob verification

f327c0ff049b55f36046efbfc7f2e981c4f4cc42
test(core): expose unbounded exact state verification

d75d5389ae9dffb8bd2f02a3680e386b190e94ff
fix(core): bound exact state verification
```

The first RED proved that prior-Head/no-op verification did not expose its
regular-file byte-read seam. The GREEN path now applies the approved length plus
one limit before deciding that live state matches Local Head. The second RED
required a deterministic growth seam after immutable-blob metadata inspection.
The GREEN verifier now reads at most the referenced bytes plus one and rejects
growth immediately, including during read-only `read_version` reference
verification. The third RED exposed the same post-metadata growth window in
exact mutable-state verification. Its GREEN verifier caps allocation and reads
at the expected state-record length plus one before accepting exact bytes.

The first hosted platform matrix then preserved two platform-specific
RED/GREEN pairs:

```text
c9a2342a810afd1b6086496626d4ae357b0d97cf
test(core): expose Linux O_PATH flush failure

21ed18047f7e109c7cdce62c2d0928bc6fa985e6
fix(core): fsync Linux state through retained capability

3809827b2a3f4a7e68aeb783fce9cb94fffd55ba
test(core): expose recursive capture stack overflow

a157261dc19e64f08ac2073515afca3b452a65b5
fix(core): traverse capture depth with heap frames
```

Linux Rust gate run `30491758063` exposed `EBADF` while flushing
`.folderbase/locks`: `cap-primitives` uses `O_PATH` for retained no-follow Linux
directory capabilities, but `fsync` cannot operate on an `O_PATH` descriptor.
The GREEN implementation opens `"."` relative to that retained capability with
read/no-follow authority, verifies the reopened directory has the same physical
identity, and flushes it without ambient path traversal.

Windows job `90711058447` exposed a native stack overflow in the existing
129-component depth-refusal regression. A deterministic 256 KiB test thread
reproduced the same abort locally at the RED commit. The GREEN planner retains
the same streaming depth-first ordering and post-child identity verification,
but stores directory iterators and capabilities in explicit heap frames, so the
129th component returns the typed portable-depth refusal on constant native
stack.

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
- new-capture and prior-Head/no-op content reads stop after one byte beyond the
  exact planned length, remove staging where applicable, and report the
  concurrent source change without consuming a growing file to EOF;
- immutable-blob verification, including read-only Folderbase Version
  inspection, stops after one byte beyond the referenced length;
- exact mutable-state publication verification stops after one byte beyond the
  expected record length without allocating from a growing stream;
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
- capability-relative Linux directory flushing through an ordinary descriptor
  verified against the retained no-follow `O_PATH` directory identity;
- constant-native-stack capture traversal with the same 128-component portable
  depth limit, streaming DFS behavior, and child-identity recheck;
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
14 passed; 0 failed

cargo test -p folderbase-core --lib folderbase_state::tests::
5 passed; 0 failed on macOS

cargo test -p folderbase-core --test folderbase_capture
16 passed; 0 failed on macOS

cargo test -p folderbase-core --lib local_versions::tests::transaction_lock_is_exclusive_across_independent_handles
1 passed; 0 failed

cargo check -p folderbase-core --lib --target aarch64-unknown-linux-gnu
passed

cargo check -p folderbase-core --target x86_64-pc-windows-msvc
passed

cargo clippy --workspace --all-targets -- -D warnings
passed
```

The Windows target has six state tests: read-only inspection, bounded source
streaming, bounded immutable-blob verification, bounded exact-state
verification, junction refusal, and writable-capability publication/flush. Its
read-only version integration regression is also selected there. Their runtime
result is owned by the checked-in `windows-latest` CI job.

The Linux target has six state tests, including the retained-parent confinement
regression and the native `O_PATH` directory creation/publication/flush
regression. Its runtime result is owned by the checked-in Linux Rust quality
gate.

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

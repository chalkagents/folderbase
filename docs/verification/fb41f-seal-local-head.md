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

## Productive Tombstone Phase A

Phase A froze the product decision that snapshot capture uses exact path plus
supported kind as logical Knowledge Object continuity. Physical identity is
race evidence and a future move hint, not sole cross-capture logical identity
authority. This keeps atomic-save editors usable while requiring durable
deletion evidence before a same-path/same-kind recreation receives a new
Object ID.

The genuine RED/GREEN pairs are:

```text
a154410 test(core): require productive deletion tombstones
e4ac4c1 feat(core): seal absent bindings as tombstones

8a981b2 test(core): require atomic-save identity continuity
fbf7539 feat(core): preserve same-kind path continuity

3b64d2b test(core): bind executable fidelity to object versions
d2b3600 fix(core): version executable fidelity changes

3ff51f8 test(core): require productive kind replacement
7b99c6d feat(core): tombstone supported kind replacement

f510555 test(core): refuse hidden prior bindings
02a78e3 fix(core): refuse hidden prior bindings

df4296e test(core): bound capture journal entry aggregate
8783a05 fix(core): bound capture journal entry aggregate

57ecf06 test(core): preserve legacy capture journal digest
bb05fdb fix(core): preserve legacy empty journal encoding

ca20008 test(core): preserve intent across scope refusal
ef26b2c fix(core): refuse scope change before intent cleanup
```

The first RED observed `TombstonesRequired` for an ordinary captured absence.
Its GREEN transaction carries the complete sorted target Tombstone set, seals
it into the immutable Folderbase Version, and advances Local Head only after
referenced Object Versions verify. The atomic-save REDs observed the same old
refusal for a provably distinct replacement and for missing derived physical
identity. GREEN preserves the Object ID at the same exact path and supported
kind; changed bytes or executable fidelity receive a new Object Version.

The kind-replacement RED observed the old refusal for both regular-to-directory
and directory-to-regular changes. GREEN assigns a new Object ID while retaining
the prior Object as a Tombstone. The scope-safety RED introduced a typed
`PriorBindingHidden` contract; GREEN refuses new ignore, nested-Folderbase, and
unsupported-node hiding before capture-journal or Head mutation. The aggregate
RED proved that a journal could separately fit the assignment and Tombstone
caps while exceeding the one Folderbase Version entry limit. GREEN checks their
sum before accepting the journal.

The compatibility RED installed legacy pre-Tombstone-field journal bytes after
Head replacement and anchored their exact digest in Local Head. Deserializing
the missing field to an empty collection and then serializing the new field
broke recovery. GREEN keeps the field optional on decode and omits it on encode
when empty, preserving the exact legacy digest while non-empty Tombstone target
sets remain explicit.

The interrupted-scope RED left a durable update intent, then introduced each of
an ignore rule, a nested Folderbase boundary, and an unsupported hard-link
replacement that hid a prior binding. The typed refusal occurred only after the
old implementation removed the intent. GREEN verifies the current prior and
refuses the scope change before stale-intent cleanup. The journal remains
byte-identical, Local Head remains unchanged, and restoring the exact approved
ignore-case plan converges on the originally assigned Folderbase Version.

Three additional commits are explicitly regression coverage, not claimed REDs:

```text
f236e85 test(core): cover newest tombstone lifecycle
c334e31 test(core): cover tombstone crash convergence
a13d32f test(core): reject tombstone journal tamper
```

The generic projection introduced by the first GREEN already made
delete→recreate→delete retain only the newest deleted Object for one exact path.
The recovery regression proves the exact Tombstone-bearing target converges
after interruption at journal, object-write, Folderbase-Version, Head-replace,
and cleanup checkpoints. The tamper regression proves an active journal cannot
substitute a different target Tombstone for the one derived from the verified
parent and approved plan.

## Green behavior

The implementation proves:

- genesis and update Folderbase Versions with exact parent linkage;
- same-path/same-supported-kind logical Object ID continuity only from a
  verified prior Local Head binding, including atomic-save replacement;
- changed content or executable fidelity creates a new Object Version under the
  same logical Object ID;
- captured absence creates a durable Tombstone, while supported-kind
  replacement creates prior Tombstone plus new live Object ID;
- delete→recreate→delete retains only the newest deleted Object for one exact
  path, and captured absence is durable evidence that recreation is new;
- physical identity from Unix device/inode or Windows volume plus 128-bit File
  ID remains exact-read race evidence and derived local state rather than sole
  cross-capture logical identity authority;
- missing or stale derived physical identity is rebuilt without splitting a
  same-path/same-kind Knowledge Object;
- new IDs persisted in a durable transaction before immutable object writes;
- complete sorted target Tombstones persisted in that transaction and matched
  to the verified parent, approved plan, and committed immutable version;
- exact active-journal assignment-plus-Tombstone aggregate and prior-lineage
  validation, with bounded streaming JSON encoding under the same declared
  writer/restart byte bound;
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
- fail-closed refusal before journal or Head mutation when ignore policy, a
  nested Folderbase, or an unsupported exclusion hides a prior live binding;
- byte-identical preservation of an existing durable capture intent and its
  Local Head across that typed scope refusal;
- post-Head recovery of legacy capture journals that predate the optional
  Tombstone target field;
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
  Head-replace, and cleanup checkpoints for both live updates and Tombstones;
- no lost prior Head during update recovery;
- stale-intent cleanup while retaining only safe content-addressed or immutable
  orphans;
- active-journal Tombstone tamper refusal without moving the prior Head.

## Hosted Linux replacement-fixture hardening

PR #26 run `30492952060`, Linux job `90715021561`, exposed a deterministic
test-fixture ambiguity in
`replacement_after_head_and_before_identity_projection_requires_a_tombstone`.
The `HeadReplaced` hook ran and replaced `active.bin`, but the fixture closed
the removed file before recreating the path. Linux immediately reused its
device/inode, so the alleged replacement had the same physical identity and the
then-current test could not prove that two filesystem objects had existed. No
process-global fault injector exists: each seal owns its callback closure.

The test-only RED commit is:

```text
db03f05 test(core): expose Linux replacement identity alias
```

It synchronizes eight independent Folderbase Roots, verifies each per-call hook
observes exactly one Head replacement, and requires the two open-file
fingerprints to differ. The native Linux stress loop was RED in all 20 runs,
with the exact device/inode alias printed by the failing assertion.

The GREEN commit is:

```text
ce80793 fix(core): retain replaced file during seal fault test
```

The fixture now retains the removed file handle until the replacement handle
and fingerprint exist. The two objects therefore coexist and Linux cannot
recycle the removed inode while constructing the fault. The native Linux
eight-worker test was GREEN in all 20 runs, the original hosted test passed,
and all 15 seal unit tests passed together with eight test threads.

Phase A later superseded the old cross-capture expectation while retaining the
deterministic fixture: a same-path/same-kind replacement is logical continuity
by default even when its physical identity differs. A captured absence is
durable deletion evidence and makes later recreation new. Delete-and-recreate
entirely between captures needs a future App event journal or explicit Core
operation to override that atomic-save-friendly default.

Focused gates:

```text
cargo test -p folderbase-core --test folderbase_seal
12 passed; 0 failed on macOS; the Windows-only read-authority regression replaces
the Unix-only fidelity regression in the native Windows selection

cargo test -p folderbase-core --lib folderbase_seal::tests::
22 passed; 0 failed

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

cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
passed

scripts/test-package-install.sh
passed; extracted Core and CLI packages are self-contained and the installed
binary reports folderbase 0.4.0
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
CARGO_INCREMENTAL=0 RUSTFLAGS='-C debuginfo=0' \
  cargo test --workspace --all-features --locked -- --test-threads=1
passed
```

## Truth boundary

This evidence proves productive captured-absence Tombstones, same-path/same-kind
logical continuity, and supported-kind replacement capture. It does not claim
durable App filesystem-event intake or an explicit Core deletion operation for
delete-and-recreate entirely between captures, cross-path move detection,
complete restore/no-clobber reconstruction, restore crash recovery, filesystem
or database snapshot coordination, Remote Head, sync, sharing, authorization,
Cloud durability, or hosted deployment. Those remain required before ADR-0005
can be Accepted.

The local cross-target library check proves Windows code compiles, while the
checked-in `windows-latest` CI matrix owns runtime proof for Windows File IDs,
exclusive locking, Head replacement, and crash recovery. A local macOS host
cannot execute that Windows binary.

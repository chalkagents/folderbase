# Execute migrations through one durable transaction module

Status: Proposed

## Context

Folderbase migrations already have approved plans, durable results, recovery,
rollback, a shared local transaction lock, and root-relative filesystem helpers.
The execution surface nevertheless exposes separate apply, result-reopen,
recover, and rollback paths. Their implementations can update a mutable plan,
mutable journal, ordinary leaves, snapshots, and protocol records through
different call graphs. As structural operations grow, callers and tests must
understand too much of that sequencing.

That is a shallow module. The public interface should express the user's intent
while one implementation owns compilation, crash recovery, conflict
classification, legacy dispatch, and platform-specific filesystem behavior.
This concentrates safety knowledge at one seam and makes the same interface the
test surface for the CLI, App, humans, and agents.

The transaction also needs an exact claim. Folderbase can serialize cooperating
writers with its local transaction lock and can use atomic filesystem operations
for individual names. It cannot portably make a multi-leaf migration invisible,
or provide compare-and-swap for a pathname against an editor, shell command,
sync client, or other writer that ignores that lock. A safe design must preserve
bytes and report conflicts across those visible windows rather than describe
them as an atomic portable transaction.

ADR-0002 defines Reorganization Plan semantics and ADR-0003 defines exact-root
attestation. This decision refines the migration application, recovery, and
rollback architecture shared by additive migrations and Reorganization Plans.
It does not change who may approve a plan or turn a migration record into
authorization.

## Decision

### One external execution seam

Core will expose one method on the `MigrationExecution` module:

```text
MigrationExecution::run(
  RootClaim::Current { display_root },
  command
) -> MigrationOutcome | FolderbaseError

MigrationCommand
  = Apply { migration_id, approval_digest }
  | Recover { migration_id }
  | Rollback { migration_id }
```

`root` names the exact Folderbase Root supplied by the caller. `Apply` consumes
an identifier and approval digest bound to one immutable plan. The released
`apply_migration` convenience adapter may carry its already-open
`ApprovedMigration` through the compatibility-only approval-carrying root-claim
variant; new callers use `RootClaim::Current`. `Recover` resumes the direction
already recorded by durable state; it does not silently choose apply or rollback
from current workspace contents. `Rollback` durably records rollback intent
before executing an inverse transition.

The outcome distinguishes at least applied, rolled back, recovery required, and
conflicted states. A conflict is data, not a generic I/O error. It identifies the
transaction, durable execution direction, operation index, affected relative
paths, expected fact, observed fact, durable phase, and any private preserved
artifact the user may need. The invoked command and durable direction are not
always the same: `Recover` can resume either an apply or rollback direction.
Errors remain for unsafe roots, corrupt or unsupported state, invalid commands
for the durable state, unavailable required filesystem behavior, and ordinary
I/O failures.

Existing Rust convenience functions, CLI verbs, and the process-JSON bridge
become adapters at this seam. They may retain released shapes for compatibility,
but they do not own independent execution implementations. Planning, approval,
preview, and rejection remain separate because they do not execute an approved
mutation program.

`Apply` first checks for an existing transaction-v1 execution record. If one
exists, Core reopens that immutable program, verifies the caller's approval
digest and retained root identity against it, and resumes it even when the
mutable plan projection already says `conflicted`. It does not require a
conflicted projection to become `approved` again. Only when no execution record
exists may `Apply` reopen an approved plan and compile a new program. This makes
an unchanged public Apply retry return the same semantic conflict without
appending a duplicate generation.

This makes `MigrationExecution` a deep module: callers learn one method and
three commands, while the implementation owns all execution sequencing and
recovery invariants.

### Immutable internal mutation program

Before the first ordinary-leaf mutation, `Apply` reopens and validates the exact
approved plan under the shared transaction lock, rechecks its declared scope,
and compiles it into one private, data-only `MutationProgramV1`. The program is
not a public portable plan, wire contract, permission token, or extension seam.
It is an immutable execution artifact internal to the migration module.
Revalidation includes typed ignore-policy syntax and capture-size bounds after
the durable plan is reopened, so a rewritten approved plan cannot bypass those
checks before transaction state is born.

The closed and bounded program binds:

- its `folderbase-mutation-program-v1` format and transaction identity;
- the approved plan and approval digests;
- the Folderbase identity, manifest digest, device-local physical-root
  authority, path/case profile, and admitted filesystem durability profile;
- every ordered leaf transition and the exact relative parents it may open;
- each expected pre-state, staged post-state, and rollback fact, including
  entry kind, byte length, SHA-256, required portable fidelity, and expected
  presence or absence;
- exact nested-boundary and policy facts relevant to those paths;
- private stage, original-byte snapshot, and claim names derived from the
  transaction and operation identities; and
- the complete bounded set of protocol records the transition must publish and
  verify.

Higher-level operations such as an adapter update or policy change are compiled
to their exact resulting bytes before execution. The executor never asks a
mutable plan, template, agent response, callback, or ambient path to decide the
next mutation. Any operation or filesystem fact that cannot be represented
exactly by `MutationProgramV1` is unsupported before the first ordinary
mutation.

The program is bounded-encoded, synchronized, installed append-only with
no-clobber semantics, reopened through the retained state capability, and
verified before the first journal state is published. A domain-separated
SHA-256 of its exact admitted bytes identifies it. Recovery accepts only that
exact program digest; it never recompiles an active transaction from a newer
plan or current workspace.

### Checksummed durable state machine

New execution state uses the private
`folderbase-migration-transaction-v1` format. The implementation records
immutable, monotonically numbered journal generations instead of repeatedly
trusting one mutable progress document. Each bounded generation binds the
transaction and program digests, generation number, previous-generation
checksum, requested direction, state-machine phase, operation cursor, any
in-flight leaf transition, completed apply and inverse receipts, durable
apply-abort receipts, and conflict evidence.

Each generation has a domain-separated SHA-256 over its controlled encoding
with the checksum field excluded. Recovery verifies the complete chain from its
initial generation. A gap, checksum mismatch, duplicate number, fork from one
predecessor, unknown field, unknown phase, out-of-bound record, or disagreement
with the immutable program fails closed. Checksums detect corruption,
truncation, and inconsistent local state; they are not signatures and do not
authenticate against a same-user actor who can rewrite the entire private
state. Adding apply-abort receipts is an additive encoding extension: a
generation with no abort receipt preserves the exact canonical bytes and
checksum domain of the released transaction-v1 generation. The new field is
serialized and enters the controlled checksum encoding only when the generation
contains an abort receipt.

The state machine durably records intent before a leaf transition, then records
completion only after the visible and private postconditions verify. Its
directions and terminal states are:

```text
prepared -> applying -> applied
                    \-> conflicted

prepared | applying | applied | conflicted
  -> rollback_requested -> rolling_back -> rolled_back
                                      \-> conflicted
```

A crash at any edge leaves enough exact evidence to classify the leaf as not
started, claimed, published, modified, completed, or conflicted. `Recover`
performs only the restart-safe transition implied by that durable direction.
Repeating any command is idempotent when the exact durable postcondition already
exists. An incompatible command returns a typed state mismatch without changing
ordinary content.

Before rollback can mutate its first ordinary leaf, Core durably records
rollback direction and preflights the retained parent and nested-boundary facts
for every remaining inverse step. A conflict in any later-to-execute step
therefore stops the whole rollback attempt before an earlier inverse step
removes or restores ordinary content. Restart repeats this read-only preflight
against the current journal cursor before the next inverse mutation.

Rollback may be requested while a conflicted apply transition remains
in-flight. Core does not clear that operation from the journal merely because
an inverse attempt returned. It first normalizes the interrupted leaf to the
exact step-specific abort postcondition, persists a canonical private
`folderbase-private-abort-work-v1` receipt that binds the operation, visible
post-identity, and complete private claim facts, and then reopens and verifies
that receipt. Only afterward may a new journal generation add an apply-abort
receipt containing the private receipt's SHA-256 and clear the in-flight
operation. Recovery accepts a private receipt ahead of its journal generation
only when all recorded visible and private facts still match; a journaled abort
requires that exact private receipt and claim set. Missing, additional,
different-kind, aliased, or changed evidence fails closed before another
generation is written.

Move abort claims are transient execution authority, not permanent ownership of
the restored workspace path. After Core exact-restores the source, it retires
the rollback claim first and the source claim second, verifies the source at
its immutable program identity, and persists an empty-claim abort receipt.
Before that receipt is journaled, recovery still proves the live source; after
journalization, the receipt is immutable history and ordinary user edits or
replacement of the restored source do not invalidate terminal recovery. The
immutable Move snapshot remains the independent byte evidence.

The same ownership boundary applies to every terminal rollback receipt:
`rolled_back` history continues to verify its canonical program, journal,
private receipts, and immutable blobs, but it no longer requires an ordinary
pathname to remain absent or unchanged. A user may recreate or edit any
released path without making terminal recovery invalid. Releasing that
pathname does not weaken private history: when rollback retained a removed
directory as a private claim, terminal recovery continues to exact-verify the
claim's physical identity, device, fidelity, and emptiness.

The shared Folderbase transaction lease covers format dispatch, program and
journal validation, leaf execution, protocol-record publication, and terminal
verification. One active migration, capture, restore, or protocol upgrade may
mutate a root at a time when those writers honor the lease. An active intent
from another transaction returns recovery required; it is never automatically
discarded.

### Retain exact root authority

Every command opens the exact caller-supplied root without following a symlink
or Windows reparse point. It retains one no-follow root capability for the
complete run. Through that capability it retains or reopens `.folderbase`,
manifest, migration-state, transaction, journal, and lock entries and verifies
their required identities. It acquires the lock relative to that retained state
authority and then revalidates the exact retained-root authority before
creating, repairing, or publishing transaction state. After that authority is
bound, the caller-supplied pathname is diagnostic only; a later rename or
replacement of that ambient pathname never transfers authority to the new
occupant.

All program, journal, claim, stage, snapshot, protocol, and workspace access is
relative to retained no-follow capabilities. Existing path ancestors are
reopened without following links and checked against the active path/case
profile and nested-Folderbase rules. The implementation never resumes by
canonicalizing a journal's stored absolute path, searching an ancestor, or
opening a replacement `.folderbase` by ambient pathname.

Additive source-topology validation follows the same rule. After acquiring the
shared lease and before the first mutation, Core enumerates ordinary files,
nested Folderbase boundaries, and expanded reconstructable trees through the
retained root capability. It never re-walks the caller's display pathname to
decide what the approved transaction may publish.

Before and after each externally visible transition Core:

1. verifies the retained root handle against the program's root identity,
   without requiring the old ambient display pathname to remain attached;
2. reopens `.folderbase` relative to that retained root and requires the exact
   recorded state identity;
3. verifies journal-phase-derived manifest and policy facts;
4. requires the selected parent chain to remain attached beneath the retained
   root with exact identities and boundary facts, while mutations use the
   retained parent capability; and
5. verifies each affected leaf's expected presence or absence, kind, identity
   where applicable, content, fidelity, and link topology.

If the ambient root pathname is renamed or replaced, Core does not reopen,
read, or mutate the replacement. It may continue through the same retained
physical root while that authority remains internally valid, even if the root
is now reachable under another name or only through the retained capability.
If the retained state, selected parent chain, boundary, or leaf facts no longer
match the durable program and journal phase, Core stops with a recoverable
conflict. A pathname replacement can therefore make private state harder to
find from the old display name, but it cannot redirect the current execution
into a different Folderbase.

This follows ADR-0005's cooperative-namespace model. ADR-0003 attestation binds
the initial exact root; it does not turn the caller's display pathname into an
ongoing authority lease.

On Windows, the exact root and every retained state or workspace directory,
manifest, journal, stage, claim, snapshot, and affected leaf are rejected when
`FILE_ATTRIBUTE_REPARSE_POINT` is set, regardless of reparse tag. Junctions,
symbolic links, cloud placeholders implemented as reparse points, and unknown
reparse kinds are unsupported by transaction v1.

Windows portable fidelity maps the read-only file attribute to `read_only`.
Regular files have no portable executable bit and therefore observe
`executable: false`; directories are inherently traversable and observe
`executable: true`. Core never synthesizes Unix mode bits on Windows. When an
exact retained directory needs `FILE_WRITE_ATTRIBUTES`, Core reopens that same
object with `ReOpenFile`, revalidates that it is a non-reparse directory, and
closes the elevated handle after the leaf operation. No-replace rename is
different: child directory capabilities are initially opened with the closed
union of `FILE_TRAVERSE` and `FILE_READ_ATTRIBUTES` documented for the
destination `RootDirectory`, with delete sharing enabled. For a cross-directory
rename, that retained destination capability is passed directly to
`NtSetInformationFile`. For a same-directory rename, Core compares the
physical identities of the retained source and destination parents and passes
`RootDirectory = NULL` with the simple destination name, as required by the
kernel rename contract. Core uses the native handle-relative call because the
Win32 wrapper resolves a NULL-root simple name against process current working
directory. Core does not try to widen or ambiently reopen a directory while
publishing. Source leaves request `DELETE`,
`FILE_READ_ATTRIBUTES`, and `SYNCHRONIZE`. The rename buffer uses the complete
`FILE_RENAME_INFO` structure size plus the filename bytes. Core never recovers
rights by reopening `.` or an ambient pathname.

### Claim and publish one leaf at a time

The internal filesystem adapter executes a small set of typed leaf transitions.
It never implements replacement as an unchecked rename over the visible leaf.
For a destructive transition it:

1. revalidates the expected parent and no-follow leaf;
2. writes and synchronizes the exact new bytes and an independent rollback
   snapshot before removing any visible original;
3. writes a durable `claim_intent` generation;
4. atomically moves the expected original to its private no-clobber claim name;
   a create leaves absence unclaimed and relies on the no-clobber publication
   below;
5. revalidates the claimed identity, bytes, kind, and fidelity;
6. publishes the staged result into the now-absent visible name with an atomic
   no-clobber primitive;
7. synchronizes and revalidates the published leaf and relevant parents; and
8. writes the completed transition receipt.

Moves claim the source before publishing the destination. Creates publish only
into an absent leaf. Rollback applies the corresponding inverse leaf program
through the same claim-and-publish rules. A transaction-created regular file is
removed only when its exact identity, digest, length, and fidelity remain
unchanged. A created directory is removed only when it is still the exact
transaction-created directory and empty. Recursive cleanup of an ordinary
directory is never a transaction-v1 operation.

If a writer changes the leaf before the claim, preconditions fail and the
writer's content remains visible. If a writer creates the name between claim
and publish, no-clobber publication fails and Core retains both the private
claim and the competing visible content. If a writer edits or replaces a
published result before verification, recovery, or rollback, Core preserves
that content and records a conflict instead of restoring over it. Cleanup
removes only an exact transaction-owned private artifact after its durable
obligation has ended; an unknown, changed, or aliased artifact is retained and
reported.

The same rule applies to deterministic private staging names. A fully
synchronized stage whose exact content, identity, fidelity, and link topology
still prove the pending transaction publication may resume after a process
exit. A partial, replaced, malformed, or otherwise unprovable stage is retained
and reported; recovery never treats the reserved filename alone as proof of
ownership. Before a recoverable private claim reaches a hook or crash edge,
Core synchronizes a canonical ownership record that binds the exact staged
physical identity, device, digest, length, and portable fidelity to the pending
program claim. Restart requires both that durable record and the exact leaf it
names; equal bytes on a different inode or fidelity-only changes fail closed.
The final claim retains the same ownership record until its transaction
obligation ends. Legacy final-plus-stage hard-link checkpoints are retired only
after both names are proven to reference the same exact two-link publication.

Conflict records include a retained no-follow fingerprint of the affected
ordinary leaves. Repeating an unchanged conflict returns the existing record
without extending the journal; a changed workspace fact may append one new
record. Apply-direction conflicts identify the exact private claim that
preserves the displaced original. Rollback conflicts for Replace and Move
identify the immutable program-bound rollback snapshot rather than a claim
whose bytes may have changed through a visible hard link.

Original bytes and rollback snapshots remain private while rollback is
supported. An interrupted or conflicted transition must always leave every
observed non-transaction byte either at an exact visible path or in a named,
durable private artifact. Folderbase does not resolve a conflict by selecting
one side, overwriting a competing leaf, or deleting an unrecognized entry.

Directories needed as parents are created as individually journaled leaves.
Symlinks, hard-link arrangements whose exact authority cannot be bounded,
special files, case-only renames, cross-device leaf moves, and other
unrepresentable shapes fail before their destructive transition.

### Concurrency claim

The transaction lock is a real seam for cooperating Folderbase writers. Apps
and agents using Core receive deterministic serialization, durable recovery,
and idempotent retries. Humans may continue to use ordinary editors and file
tools; their changes are never treated as permission for the migration and are
never silently overwritten.

The claim-and-publish sequence is intentionally visible. There may be a period
after an original name is claimed and before its replacement is published.
File watchers, sync tools, and uncoordinated writers can observe or act in that
period. A migration touching several leaves can expose completed earlier leaves
before later leaves finish.

Folderbase therefore does not promise:

- an invisible or all-or-nothing multi-path filesystem transaction;
- a portable atomic compare-and-swap of arbitrary existing pathnames;
- exclusion of an editor, shell, sync client, or malicious same-user process
  that ignores the transaction lease; or
- conflict-free completion merely because preflight succeeded.

It does promise for admitted filesystems and supported leaf kinds that each
transition is restart-classifiable, no-clobber publication never overwrites a
competing name, known preexisting bytes have durable rollback evidence before
their visible name is claimed, and every unresolved race returns an explicit
conflict without discarding either known side.

### Private state and durability

Transaction-v1 state lives in a dedicated
`.folderbase/migrations/<migration-id>/transaction-v1/` directory beneath the
migration's existing private state. Program, journal, lock, stage, claim,
snapshot, and receipt names inside that directory are closed and
operation-derived. Reopen bounds both entry counts and file sizes and rejects
unknown entries, aliases, symlinks, directories in file positions, regular
files in directory positions, and ambiguous coexistence of a legacy active
result with transaction-v1 active state.

On Unix, every transaction-v1 private directory is created and reopened with
exact mode `0700`; every private regular file and lock uses exact mode `0600`.
Core applies those modes explicitly rather than depending on umask and fails
closed when any owner, group, or other permission bit differs. A staged
workspace result receives its program-bound visible fidelity only immediately
before publication; its private copy remains private.

Windows does not reinterpret Unix mode bits as an ACL guarantee. Transaction
state remains beneath the existing current-user local-state trust seam, Core
does not broaden inherited access, and every open is no-follow with the
reparse-point rejection above. This is protection from accidental exposure and
pathname redirection, not a security boundary against another process running
as the same user.

Before publishing `prepared`, Core admits the exact filesystem behavior needed
by every program transition: stable no-follow handle identity, same-filesystem
atomic rename and no-clobber installation for the affected names, bounded
regular-file I/O, file synchronization, and the platform's documented
directory-entry persistence primitive. Unsupported operations, cross-device
transitions, filesystem responses that cannot establish these properties, and
unknown durability profiles return `UnsupportedMigrationFilesystem`. Core does
not fall back to copy-delete or overwrite semantics.

Every new private or visible file is synchronized before publication. On Unix,
the implementation synchronizes the real parent directory descriptors after
claim, publication, journal generation, and cleanup. On Windows, it flushes
writable file handles and uses same-volume atomic name operations, but does not
claim a POSIX directory-`fsync` equivalent; power-loss persistence of directory
entries follows documented platform/filesystem behavior. That admitted
platform difference is part of the outcome's durability profile, not hidden
behind a generic “durable” claim.

A platform or filesystem is supported only after native tests demonstrate the
required identity, no-follow, no-clobber, rename, flush, reopen, and
crash-recovery behavior. If a required primitive reports unsupported behavior
at runtime, the transaction stops with its last durable intent and preserved
artifacts; it never substitutes weaker semantics.

### Legacy journals and transaction-v1 adoption

Released migration directories and their `result.json` journals remain
readable. `MigrationExecution::run` dispatches them through a private legacy
adapter that preserves their exact admitted bytes, states, recovery rules, and
error behavior. An active legacy `applying` or `rolling_back` journal is
recovered in place by that adapter. It is never normalized, re-encoded, or
partially translated into `MutationProgramV1`, because doing so could lose the
meaning of an in-flight operation.

New `Apply` commands always create transaction-v1 state before their first
ordinary mutation. An approved legacy plan with no active result may be compiled
into a new `MutationProgramV1` only after its released plan decoder, approval
digest, root authority, and all current preconditions verify. Once
transaction-v1 `prepared` exists, that transaction never falls back to the
legacy executor.

`Recover` and `Rollback` select the implementation from durable format identity,
not crate version or a caller flag. Legacy and transaction-v1 active state for
the same migration ID, an unknown format, or an ambiguous partial format fails
closed without ordinary mutation. Terminal legacy results remain reopenable and
rollback-capable for as long as their released contract requires.

`MigrationResult::reopen`, `MigrationResult::recover`, and the CLI
`reopen`/`rollback` adapters use that same format classifier. They do not assume
that a new migration has `result.json`. Transaction-v1 results are projected
from the exact program and current journal phase; released `result.json` is
decoded only by the legacy adapter. Terminal plan state is likewise a
projection of the immutable program and journal. Updating it verifies the
program-bound approval digest but does not re-traverse newly introduced
ordinary nested boundaries, because the conflict that introduced the boundary
must still be durably projectable as `conflicted`.

This compatibility is an internal adapter, not a second external interface.
All new callers and tests use `MigrationExecution::run`.

## Consequences

Callers gain leverage from one command interface, and maintainers gain locality:
the facts required for safe execution live in one immutable program and one
state machine. Crash tests and concurrency tests exercise the same seam used by
the CLI and App.

The implementation and private state become larger. Replacement and move
operations need extra local bytes for exact stages and rollback snapshots.
Multi-leaf changes are visibly progressive, conflicts can require human
resolution, private rollback evidence may remain after a successful apply, and
some mounts or special filesystem shapes will be rejected. Those costs are
preferable to hidden overwrite, lossy recovery, or an inaccurate portability
claim.

## Rejected alternatives

**Keep separate public apply, recover, and rollback implementations.** This
spreads state-machine knowledge across callers and makes compatibility,
durability, and conflict behavior diverge.

**Expose `MutationProgramV1` as a public plan format.** It contains
device-local authority, private paths, and platform execution facts. Making it
portable would enlarge the interface and confuse execution evidence with
approval or permission.

**Rely on the transaction lock alone.** The lease coordinates Folderbase-aware
writers but cannot prevent ordinary human and agent tools from changing the
folder.

**Replace a leaf with an overwrite rename after checking its digest.** The
check and rename are not a portable compare-and-swap. A competing writer can
lose content between them.

**Promise an invisible portable compare-and-swap transaction.** Portable
filesystems do not provide one primitive that atomically checks arbitrary
bytes, replaces multiple names, publishes protocol records, and excludes
uncoordinated writers.

**Copy and delete when atomic claim or publication is unavailable.** A crash or
writer race could leave neither exact side authoritative. Transaction v1 fails
closed on that filesystem instead.

**Upgrade active legacy journals in place.** An in-flight released journal may
encode progress that has no lossless transaction-v1 state. Recovery must honor
the original implementation.

## Acceptance

This decision becomes Accepted when:

- `MigrationExecution::run` is the only external execution implementation and
  released convenience functions plus CLI/process commands are adapters to it;
- new applies persist one immutable, bounded, digest-bound
  `MutationProgramV1` and only transaction-v1 journal generations can advance
  it;
- checksum corruption, truncation, chain gaps, forks, unknown state, format
  coexistence, and program disagreement all fail closed;
- crash tests at every apply, recovery, rollback, claim, publish, journal,
  protocol-record, and cleanup checkpoint converge or return an exact conflict;
- concurrent-writer tests cover a change before claim, creation between claim
  and publish, in-place edit after publication, replacement before rollback,
  nonempty created directories, and changes outside the affected paths;
- every conflict fixture proves that all competing and preexisting bytes remain
  either visible or in identified private state;
- exact-root, state replacement, nested-boundary, case-alias, symlink, Windows
  reparse-point, insecure Unix mode, cross-device, and unsupported-filesystem
  fixtures fail without redirected or weaker mutation;
- native Linux, macOS, and Windows tests demonstrate their admitted identity,
  atomic-name, synchronization, and restart behavior without overstating the
  Windows directory-persistence claim;
- released applying, rolling-back, verified, conflicted, and rolled-back journal
  fixtures retain their exact recovery and rollback behavior while every new
  apply adopts transaction v1; and
- human and agent acceptance journeys stop on explicit conflicts, invoke
  recovery intentionally, and never need direct access to the internal program
  or journal.

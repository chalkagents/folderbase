# ADR-0019: Associate device-local evidence with external scope identities

## Status

Proposed

Proposed: 2026-08-16

Founder confirmation required before implementation.

## Context

Accepted ADR 0018 gives each Device a private append-only exact-folder evidence
journal. Its binding survives a locally proven rename but is not portable.
Another Device creates its own evidence and an authenticated control plane
reconciles it to the durable Folder Scope.

After first allocation, an App needs to recover the opaque external scope ID.
Path recovery would make presentation authority. Repeating allocation after
every restart would misuse a first-allocation artifact. App-private storage
would create a competing lifecycle beside Core's evidence journal.

Core must not treat an external ID as local identity or authorization. It may
only associate that opaque label with the local binding it already proved.

Related decisions and tracking:

- proposed Platform ADR 0034;
- [folderbase#76](https://github.com/chalkagents/folderbase/issues/76); and
- [folderbase-platform#165](https://github.com/chalkagents/folderbase-platform/issues/165).

## Proposed decision

Core should expose an optional versioned capability for **Device-local external
scope associations**. It owns a private profile beneath:

```text
.folderbase/local/folder-scope-associations-v1/
```

The profile binds one ADR-0018 selected-folder binding and evidence authority
to a bounded external authority namespace and opaque external scope ID. It is
non-authoritative metadata: never a grant, credential, Cloud verifier,
filesystem identity ingredient, or permission decision.

Core-managed Folderbase Versions, root packages, portable export,
synchronization object sets, new-Device reconstruction/restore, managed copy,
and permission-scoped projections structurally exclude the profile. An
unmanaged Finder, `cp`, or raw backup can physically copy private bytes, but
root/Device attestation treats them as inert and refuses them as source-Device
identity.

## Separate allocation from recipient policy

The external control plane allocates a Folder Scope before any Recipient Grant.
Core records only allocation/reconciliation identity, never recipient,
permission, expiry, materialization, locator, or grant revision.

Before Cloud, Core appends a pending operation bound to:

- exact evidence authority and selected-folder binding;
- exact ADR-0018 evidence event;
- authority namespace;
- operation purpose: first allocation or Device reconciliation;
- for reconciliation only, the exact owner-selected external scope ID;
- one Core-generated opaque operation ID; and
- Owner Device context supplied as opaque non-secret association input.

The trusted observer pairs that operation with an exact immutable Folderbase
Version/object closure whose bytes are durably verified before Cloud publishes
membership. Cloud allocation/reconciliation and authenticated receipt lookup
use that immutable identity. They do not require recipient policy. Core records
the returned external scope ID, verified Version reference, and opaque receipt
digest; the App handles grants separately.

## Public process contract

The capability version, operations, result schemas, bounds, and errors close
together before implementation. It needs these narrow operations:

1. **Prepare allocation or reconciliation** appends pending state before any
   external request and returns the operation plus original evidence. A
   reconciliation operation also binds the exact owner-selected target scope.
   Exact replay returns it.
2. **Recover pending** returns that original purpose, target, and evidence even
   if newer ADR-0018 events exist after content or Local Head changes.
3. **Resolve** revalidates root and selection, then returns external scope ID,
   local generation and record digest, plus one disposition: pending, exact
   unchanged, content refresh required, relocation required, boundary
   unresolved, absent, stale, retired, or abandoned.
4. **Record** converts the exact pending generation to active using the matching
   external allocation or Device-reconciliation receipt, including its verified
   Version/object-closure reference. Changed values are a no-clobber conflict.
5. **Abandon pending** appends terminal state only from an exact Cloud
   terminal-not-committed receipt and compare-and-swap against
   `(binding, namespace, purpose, target if any, operation ID, pending
   generation, pending record digest)`.
6. **Transition active** appends content-confirmed, relocated, stale, retired,
   abandoned, or successor state by compare-and-swap against exact active
   `(binding, namespace, external scope ID, generation, record digest)`.

Delayed receipts, stale approvals, target changes, and concurrent transitions
conflict. Exact replay returns the existing generation. Apps/SDKs never inspect
private files or copy Core validation.

Cloud owns one durable state machine for every pending external operation:
`open`, `committed`, or `terminal_not_committed`. Authenticated lookup returns
the exact committed receipt or state. Atomic cancel-if-uncommitted creates or
advances a durable terminal fence; after that fence, a delayed request cannot
commit. Core appends `abandoned` only from that exact terminal receipt. If the
original evidence is no longer current, the App fences and abandons the old
operation before preparing a successor. It never guesses from a missing
response, resubmits stale evidence as current, or races a delayed request.

Operation identity fences attempts; it does not define scope uniqueness. Under
an authenticated Owner Device, Cloud enforces one durable scope mapping for the
stable `(authority namespace, evidence authority, selected-folder binding)`
across operation IDs and evidence events. A new allocation operation for an
already committed binding returns the existing exact scope receipt, or an
explicit retired/conflict disposition; it never allocates another scope.

## Evidence dispositions

Resolve compares the current ADR-0018 event to the association's last externally
confirmed event:

- exact path, Local Head, visible inventory, and nested boundaries means
  `unchanged`;
- inventory or Local Head advancement means `content_refresh_required`;
- a Core-proven same-binding path change means `relocation_required`;
- selected/root replacement or identity ambiguity fails closed; and
- added, removed, replaced, or crossed nested Folderbase remains
  `boundary_unresolved` under ADR 0018.

Content and relocation evidence can advance an association only after the
observer has durably verified the exact immutable Version/object closure, Cloud
has committed membership, and Core receives the external receipt for an
exact-generation CAS. Metadata never publishes ahead of bytes. Zero observer
work is valid only for `unchanged`.

Ordinary ADR-0018 observation continues to refuse nested-boundary change. This
capability does not resolve or reinterpret that security-boundary change. The
App may restore the prior boundary or retire the association/share. Any future
owner-approved boundary-resolution operation requires its own founder-confirmed
ADR, public contract, Cloud membership semantics, and recovery proof.

## Private profile and loss detection

The profile is a closed append-only chain:

- every record commits to previous record digest, evidence authority, local
  generation, operation, lifecycle, and typed external receipt digest;
- exact active `(binding, namespace)` pairs are unique;
- one durable head identifies the committed record;
- one exact orphan is recoverable after record write before head advance;
- gaps, duplicate generations, unknown files, changed bytes, or authority
  mismatch fail closed;
- strings and records are bounded before allocation; and
- each epoch is capped at 4,096 records and 16 MiB.

Before the first profile write, Core creates its own independently versioned
sibling authority record at:

```text
.folderbase/local/folder-scope-association-authority-v1.json
```

That record binds association genesis, current epoch and head outside the
association journal directory. It references the existing current ADR-0018
event but never writes to, migrates, or changes the semantics of the accepted
ADR-0018 journal/authority. Deleting the association profile beside its
authority, or deleting/replacing its authority beside committed profile state,
fails closed rather than appearing never-created. Loss of all Device-local
Core evidence requires the ordinary new-Device/reinstall reconciliation path.
If both association-owned files disappear while ADR-0018 evidence survives,
Core may report local `absent`, but authenticated Cloud allocation recovery by
the stable binding must return the existing scope or a retired/conflict result.
It must never create a second scope, including after a newer evidence event.

Capacity reserves one rollover transition. Explicit owner recovery seals the
epoch's cumulative terminal digest into the association authority, then
atomically starts a new association epoch bound to the existing current
ADR-0018 evidence event and external receipt. It does not create or alter an
ADR-0018 event. The association authority retains a cumulative prior-history
digest, not unbounded detail. Interrupted rollover recovers one exact old/new
epoch state; ambiguity fails closed. Ordinary user files remain usable when
association recovery is blocked.

## Same Device, lifecycle, and another Device

An unchanged same-Device restart resolves the active association. Content or
Local Head advancement requires an observer refresh before grant mutation. A
proven rename requires relocation evidence. Core CAS-records the corresponding
external receipt.

Another Device never adopts copied association state. The authenticated owner
explicitly selects the intended external scope before Core prepares a distinct
reconciliation operation bound to that target and fresh ADR-0018 evidence. The
observer durably verifies exact Version/object closure; Cloud authenticates the
owner and verifies current closure, boundaries, and lifecycle; Core records the
matching Device-reconciliation receipt. Restart recovers the same target-bound
operation. Ambiguity or target change modifies nothing.

## Repair and retirement

History is never silently overwritten or deleted. Receipt-bound Cloud
lifecycle effects and locally approved repair both CAS the exact active
generation/digest. Local repair may append `abandoned` for erroneous
non-authoritative metadata, but it cannot change external scope or grant and
does not free Cloud's durable binding uniqueness. Pending abandonment uses the
separate exact terminal-receipt CAS above.
A successor requires terminal prior state and fresh evidence/receipt.

## Security consequences

- External IDs remain labels attached to proven local identity.
- No credential, bearer, observer capability, raw physical identity, complete
  object inventory, recipient, or permission is persisted.
- Raw copied bytes grant nothing and fail local attestation as identity.
- Local misuse can cause recoverable local denial but never external access;
  preserved generations make repair reviewable.
- Platform must pin an immutable released capability before use.

## Rejected alternatives

- Portable association identity.
- Path-derived or content-similarity recovery.
- Repeated first allocation after restart.
- Recipient-policy replay to recover allocation.
- App-private mapping or direct `.folderbase/local` writes.
- Mutable overwrite, silent deletion, or unbounded append-only detail.

## Acceptance gates

- founder accepts or rejects this ADR and Platform ADR 0034 before
  implementation;
- public red-green conformance proves allocation and target-bound reconciliation
  prepare/recover/record/pending-abandon/resolve/active-CAS transition,
  later-event pending recovery, Cloud open/committed/terminal fencing, exact
  replay, no-clobber, process
  restart, stale/concurrent transition, content advancement, verified bytes
  before membership, rename, boundary refusal/retirement, replacement, repair,
  tamper, genesis/profile loss, at-cap rollover, rollover crash, and
  cross-platform behavior;
- loss of both association-owned files while ADR-0018 evidence survives,
  including after a newer evidence event, recovers the existing Cloud scope or
  a retired/conflict disposition and never duplicates it;
- Version/export/reconstruction/sync/projection/managed-copy tests exclude the
  profile, while raw-copy tests include inert bytes and prove attestation refusal;
- another-Device tests require fresh ADR-0018 evidence and authenticated
  reconciliation;
- SDKs and docs consume only typed public results; and
- release artifacts pass public conformance and source-integrity gates before
  Platform pins them.

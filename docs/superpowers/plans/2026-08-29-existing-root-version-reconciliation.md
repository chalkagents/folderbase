# Existing-root Version reconciliation implementation plan

Status: decision-gated

Decision: proposed ADR 0020 and
[folderbase#88](https://github.com/chalkagents/folderbase/issues/88)

## Outcome

Exact Core applies one verified direct-descendant Folderbase Version package to
one existing managed ordinary root without overwriting uncaptured local work.
The same operation is crash-safe, replay-safe, bounded-memory, and independently
conformant through the stable process interface proposed in ADR 0020.

This is the next deep local seam required by Platform's accepted two-device
owner-sync plan. It does not implement Cloud selection, transfer, Cursor
authority, divergent merge, or App behavior.

## Public seam requiring founder confirmation before RED

```text
capability: folderbase.version-reconciliation@0.1.0

folderbase version reconcile ROOT PACKAGE --stdin --json
```

The request binds one operation ID, expected current Local Head Version, exact
target Version, and exact package-index SHA-256. The command returns only one
typed success, attention, or bounded operational error. Core owns every step
between exact current-root capture and verified target Local Head publication.

No test or implementation begins until the founder confirms this seam and the
fast-forward-only Version 0.1 boundary on issue #88 or in an immutable linked
decision record.

## Slice 1 — public RED package

Create the optional-capability package, schemas, fixture builder, and
independent runner first.

RED proves the current released executable cannot:

- advertise `folderbase.version-reconciliation@0.1.0`;
- decode the exact request or emit its result/attention formats;
- apply one direct-descendant Version to an existing root; or
- replay a lost success without another visible mutation.

The first fixture is a small managed root with Markdown, opaque bytes, an empty
directory, a safe symlink, one excluded entry, and a direct-child target Version
that updates one file and adds another.

Exit proof: the independent runner fails solely because the new capability is
absent.

## Slice 2 — exact package and ancestry preflight

RED:

- wrong Folderbase, target, package digest, canonical Version digest, manifest,
  chunk, Tombstone association, or reference closure;
- target with zero, different, duplicate, or malformed parents;
- request expected-current mismatch;
- changed root identity, nested boundary, path alias, unsafe symlink, or special
  node; and
- uncaptured local edit after request preparation.

GREEN:

- reuse the accepted root-reconstruction package decoder and validators;
- retain one no-follow physical-root capability;
- capture the current root through the normal Local Version module;
- require current Version exactly equals expected current and target directly
  names it as a parent; and
- produce an opaque Core-owned mutation plan without touching ordinary paths.

Exit proof: every invalid or divergent case returns typed attention/error and a
descriptor-based before/after snapshot proves zero mutation.

## Slice 3 — crash-safe exact managed delta

RED:

- add, update, move, delete, executable, symlink, empty-directory, opaque-file,
  Git-working-tree, exclusion, and Tombstone cases;
- failure before and after each visible mutation;
- local writer races immediately before and during apply;
- insufficient space and unsupported durability behavior; and
- root rename/replacement and same-path ABA during the operation.

GREEN:

- derive the delta only from exact base and target Versions;
- stage and durably verify every replacement before the first mutation;
- journal all forward-recovery evidence under the retained root capability;
- apply the complete managed delta atomically from Core's transaction module;
- preserve entries both Versions classify as excluded;
- import target immutable Version/Object state; and
- publish the exact target as Local Head only after the ordinary tree is
  durably complete.

Exit proof: every crash recovers to exact base or exact target, never a mixture,
and no out-of-delta entry changes.

## Slice 4 — verification, replay, and public process adapter

RED:

- process loss after Local Head publication and after completion-record write;
- lost success output;
- exact replay with package present or already durably consumed;
- changed-input replay and operation-ID reuse; and
- target-looking visible bytes without the exact Core completion evidence.

GREEN:

- reopen through public Core validation after mutation;
- prove root attestation, Local Head, target Version, and immutable object
  associations agree;
- persist one exact completion record;
- return the prior result on exact replay without another Version or mutation;
  and
- advertise the capability only when the complete black-box suite passes.

Exit proof: source archive, npm, native, and Cargo candidates pass the same
implementation-neutral conformance suite.

## Slice 5 — Platform alternating two-Device tracer

After a released Core version carries the stable capability, Platform consumes
it behind the existing owner-sync coordinator/background-service interface:

1. logical MacBook publishes V1 and logical Mac mini clean-restores V1;
2. mini captures and publishes V2 with parent V1;
3. MacBook downloads V2, exact Core reconciles V1 to V2, then Cloud records its
   Cursor;
4. MacBook captures and publishes V3 with parent V2;
5. mini downloads V3, exact Core reconciles V2 to V3, then Cloud records its
   Cursor; and
6. both roots, Local Heads, Remote Head, immutable bytes, and Cursors agree.

Lost response, restart, late revocation, corrupt transfer, changed root, and a
local edit racing apply remain mandatory. `UpToDate` is impossible before exact
Core success and Cursor completion.

Exit proof: the one-way hosted bootstrap becomes an alternating logical
two-Device fast-forward tracer without adding a second App, Platform, or Cloud
mutation authority.

## Subsequent divergent reconciliation gate

The accepted product outcome also requires concurrent/offline edits,
different-object convergence, overlapping Markdown and opaque conflicts,
move/edit, delete/edit, path collisions, and unrelated safe work continuing.
ADR 0020 Version 0.1 intentionally returns divergence attention without
mutation. A separately confirmed extension must preserve every base and input,
produce real merge ancestry, and expose object-scoped conflict evidence before
the physical bidirectional V0 can pass.

## Verification

- focused Rust library tests at the new public capability seam;
- independent black-box conformance from a clean source archive;
- fixed-memory synthetic multi-gigabyte package;
- Linux, macOS, and Windows filesystem cases where supported;
- exact process exit/output/timeout bounds;
- format, Clippy, package, native, npm, and complete repository gates; and
- independent specification and repository-standards review before release.

## Strict nonclaims

Until every slice is green and the capability is released, no document may
claim existing-root remote apply, bidirectional sync, conflict handling, live
GCP, physical V0, App Connect, or V1 completion.


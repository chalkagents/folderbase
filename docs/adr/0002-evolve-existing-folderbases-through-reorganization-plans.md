# Evolve existing Folderbases through digest-bound Reorganization Plans

Status: Proposed

An existing Folderbase must be able to expand and reorganize repeatedly without
turning templates into permanent schemas or letting an agent perform an opaque
batch of filesystem mutations. Folderbase Core will therefore extend its
recoverable Migration Protocol with a public, data-only Reorganization Plan.
Organization Skills may guide analysis and propose a plan, while Core validates its
portable state transitions, application, recovery, and rollback. The invoking App
or service remains responsible for actor authority and approval policy.

## Decision

A Reorganization Plan is a versioned portable record for changing the structure of
an already initialized Folderbase. It reuses the existing migration lifecycle:

```text
analyze
  -> ask consequential questions
  -> propose
  -> preview
  -> approve
  -> apply
  -> reopen or recover
  -> optionally roll back
```

Core `0.3.0` will define two data-only records:

- a revisable `folderbase-reorganization-draft-v1` stored under the migration
  record for the work while required questions remain unanswered; and
- a sealed `folderbase-reorganization-plan-v1` created from a complete draft.

A Draft is inert and cannot be approved or applied. It records analysis, typed
questions, answered and unanswered states, proposed rationale, and the declared
read/affected paths. After every required question is answered, Core seals one
immutable Plan. A changed answer or analysis creates a new Draft and Plan generation;
an approved Plan is never mutated in place.

The first Plan contract will bind:

- one exact `reorg_<lowercase hyphenated UUID>` identity shared by its Draft and
  sealed Plan;
- the Folderbase identity and protocol version;
- an explicit portable Analysis Scope and its digest;
- the nested-boundary and ignore/policy snapshot used during analysis;
- typed consequential questions, typed answers, and concise rationale;
- ordered typed operations and their source/destination preconditions;
- the exact base identity and version of every tracked Knowledge Object affected;
- the expected absence or digest of every path created or replaced; and
- one canonical plan digest covering all of the above.

The Analysis Scope has two explicit parts.

Core derives a mandatory operation closure containing:

- the active `.folderbase/manifest.json` digest, its exact
  `policies.structural_changes` value, and the relevant ignore-policy fact;
- every source, destination, and destination-parent path used by an operation;
- the ancestor directories needed to prove those paths remain inside the same root;
  and
- nested-Folderbase markers at or below every traversal prefix required by an
  operation.

The caller separately declares every additional relative path whose name, kind,
content, identity, or absence informed its analysis. Core validates those declared
facts but cannot attest that an external agent disclosed every file it read.
Organization Skills must declare their analysis reads; a trusted remote workspace
sidecar should record them automatically where the harness exposes that evidence.
Undeclared reasoning provenance is never presented as Core-verified.

Each entry uses portable facts only: canonical relative path, expected presence or
absence, entry kind, content SHA-256 and byte count or immutable Object Version when
content matters, stable Object ID when tracked, and required directory existence.
Inodes, device identifiers, timestamps, filesystem-native IDs, and other
materialization-specific metadata never enter the public digest.

The Plan binds the active Core path/case profile. Traversal uses root-relative
no-follow handles. `reorganization-v1` refuses a symlink source, destination, or
ancestor and does not operate on a symlink entry. Unicode-normalization or
case-folding aliases collide according to that profile. Case-only renames are
rejected in v1 rather than relying on materialization-specific temporary names.

Any relevant addition, removal, move, kind change, policy change,
nested-boundary change, or content change inside the declared scope makes the Plan
stale before its first write. Unrelated activity outside the scope does not. A
whole-inventory fingerprint may be reported as non-authoritative analysis evidence
but never becomes a hidden apply precondition.

### Initial operations

The first Reorganization Plan may use these generic operations:

- create a directory when absent;
- create a bounded UTF-8 file when absent;
- replace a bounded UTF-8 file only with an exact expected-content precondition;
- update an already-defined managed agent-adapter block from a marker-free body;
- move or rename an ordinary file;
- move a tracked Knowledge Object while preserving its Object ID and version
  history;
- mark an Object canonical or superseded, archive it, or add a relationship
  through the already-defined Object Protocol operations.

Large and binary files remain opaque bytes. A plan may move them without loading
them into model context or claiming format-aware understanding.

The managed-agent-block operation is not a whole-file text replacement. Its
`managed_block` value must omit all `<!-- folderbase:` marker syntax, including
obsolete noncanonical wrappers. Application delegates to the existing adapter
merge contract, which adds the canonical
`<!-- folderbase:begin -->` and `<!-- folderbase:end -->` markers and preserves
all user-owned text around the one managed block. Its Reorganization record bound
counts Unicode code points like the public schema; the older Migration adapter
operation keeps its existing UTF-8 byte bound.

The first contract does not delete filesystem content. A user or agent may use the
operating system Trash separately, and a later deletion contract may add explicit
human-in-the-loop semantics. Archiving a Knowledge Object changes lifecycle state;
it is not deletion.

Directories are created explicitly rather than inferred from a move destination.
Directory moves remain outside the first slice because their identity, descendant,
case-collision, nested-boundary, and rollback semantics need separate conformance
cases.

### Templates and organization policy

Templates remain optional starting or additive guidance. A Reorganization Plan may
cite template provenance or suggestions in its rationale, but divergence from a
template is valid and no plan may claim that an existing Folderbase must conform to
one.

Core contains no model prompt or organization policy. An Organization Skill may,
when useful:

- notice related drafts or proposal versions;
- recommend one Canonical Narrative while preserving source evidence;
- write unresolved consequential questions for the App to ask;
- propose new structure, moves, and narrative edits; and
- explain why a plan better serves the user.

Those recommendations become mutations only after they are encoded as valid Core
operations and transition under the Folderbase structural-change policy. Core
validates the Plan digest and transition record; the local App or hosted service
authorizes the actor and decides whether policy requires a human approval or permits
a sponsored automatic transition. Questions, answers, and rationale are inert data
and never executable instructions.

### Identity, boundaries, and authority

A tracked move must commit or recover the filesystem rename, Object ID/path record,
local-version journal, and rollback evidence together so stable identity and history
survive. Moving a path must never create a new identity merely because its pathname
changed.

Nested Folderbases remain independent boundaries. Analysis may report their marker
and relative location, but a parent Reorganization Plan cannot read, move, create,
replace, or infer descendants within them.

A Reorganization Plan carries no permission. Local ownership, a hosted grant, or an
Agent Session authorizes who may request and approve work; Core validates only the
portable plan and filesystem boundary. Links, paths, relationships, template
provenance, and plan possession never grant authority. Remote-agent work produces a
candidate Change Set against its pinned base; Cloud authorization and Remote Head
compare-and-swap remain required before canonical publication.

### Application and recovery

An approval transition binds the canonical plan digest, not a mutable pathname or
UI object. Apply recomputes the Analysis Scope and every operation precondition
before writing. A preflight mismatch returns a stale-plan result with zero protocol
or ordinary-file mutations.

After the durable journal records that apply began, Core immediately revalidates
each operation through root-relative no-follow handles and uses atomic no-clobber
installation where the filesystem supports it. A competing change after preflight
is an apply conflict, not a zero-mutation stale result: Core stops, preserves every
competing byte, retains recoverable partial state, and reports the exact operation
that must be recovered or rolled back.

Application uses the existing durable migration journal. Every operation must be
restart-safe, and recovery or rollback must preserve ordinary bytes, stable object
identity, nested boundaries, and a truthful record of what completed.

Rollback follows exact postconditions:

- remove a file created by the Plan only if its bytes remain unchanged;
- remove a created directory only if it remains empty;
- restore replaced UTF-8 bytes only if current bytes still equal the Plan-applied
  digest;
- reverse an ordinary move only if the destination retains the expected identity
  and bytes and the source remains absent;
- reverse a tracked move only by restoring the filesystem path, Object ID/path
  record, and journal together; and
- reverse relationship or lifecycle state only when the current record digest
  still equals the exact Plan-applied result.

Otherwise Core preserves every side and returns a rollback conflict without
overwriting user work. A verified completion record is written only after all
operations and protocol records verify.

The records extend the Migration Protocol through a closed
`reorganization-v1` plan profile. Older clients must recognize the unknown profile
as unsupported and refuse mutation. The installed CLI and process-JSON bridge will
expose the same records rather than inventing App-specific organization commands.

## Rejected alternatives

**Let agents reorganize with ordinary shell commands only.** This remains useful for
routine edits but cannot provide one reviewable proposal, stale-scope detection,
tracked identity preservation, or batch recovery.

**Make templates continuing schemas.** This would turn useful starting guidance
into a rigid taxonomy and make mature Folderbases invalid when life or projects
change.

**Put reorganization policy in Core.** Core must validate portable facts and
operations, not decide how a person's company, client, career, or project should be
organized.

**Define a second App or Cloud plan format.** That would split local and remote
agent behavior from the open database contract and make recovery dependent on the
commercial product.

**Include deletion in the first version.** The additional authority, Trash,
retention, synchronization, and conflict semantics would make the adoption path
less understandable without being required for safe additive reorganization.

## Technical acceptance

This decision remains Proposed until the public repository contains:

- versioned Draft and Plan JSON Schemas with closed profile identifiers, canonical
  digest vectors, and unsupported-profile behavior;
- positive and negative conformance cases for questions, answers, rationale,
  explicit-scope staleness, portable guard inputs, nested boundaries, directory
  creation, bounded UTF-8 create/replace, large opaque moves, tracked moves,
  normalization/case collisions, symlink and case-only-rename refusal, preflight
  stale versus journaled apply conflict, no deletion, and rollback conflicts;
- restart, recovery, rollback, and byte/identity preservation tests;
- a stable CLI/process-JSON proposal seam; and
- an App and Organization Skill acceptance journey using the same records.

Implementation should deepen the existing migration module rather than create a
parallel reorganization state machine. Core `0.3.0` first publishes the inert
Draft/Plan data contract, bounded decoding, validation, sealing, and canonical
digests; filesystem analysis, apply, recovery, and rollback remain later slices
under this same decision.

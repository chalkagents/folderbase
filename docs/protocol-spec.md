# Folderbase protocol specification

Status: Draft through protocol 0.5

Audience: Client implementers, agent-harness authors, and protocol reviewers

## Purpose

The Folderbase protocol makes an ordinary filesystem tree a portable,
agent-readable folderbase without making recovery dependent on the Folderbase
application or cloud.

Version 0.1 defines:

- folderbase discovery
- the canonical folderbase entry
- stable folderbase and object identity
- agent bootstrap adapters
- ignore and lifecycle policy
- object metadata and relationships
- activity and migration records
- validation
- workspace composition
- the checkout and change-set seam used by future remote sessions

It does not define the cloud transport, billing, hosted authentication, model
provider, or user interface.

## Design constraints

### Filesystem native

Users and agents must be able to read and edit current content with ordinary
filesystem tools. A folderbase continues to behave like an ordinary project folder;
the protocol does not impose a permanent internal directory layout.

### Portable

The folderbase must remain understandable when copied to another machine without a
Folderbase installation.

### Additive

Initializing a folderbase adds protocol state. It does not rewrite existing content
or agent instructions without an approved migration.

### Evolvable organization

A folderbase may expand and reorganize repeatedly as its purpose and contents
change. Templates and organization skills provide guidance, not continuing
schema authority. Routine within-folderbase changes use ordinary filesystem
operations; higher-risk structural or boundary changes use previewable,
recoverable plans.

### Stable identity

Folderbase and knowledge-object identities do not depend on names or paths.

### Explicit authority

Relationships and physical nesting never grant permission. A folderbase root is an
atomic ownership and governance boundary. A hosted scoped grant may expose less
than the folderbase, but it never grants access to the remaining folderbase or to related
folderbases.

### Recoverable change

Migrations and remote work are represented as previewable operations against a
known base state.

## Terminology

Canonical definitions live in [`../CONTEXT.md`](../CONTEXT.md).

## Folderbase discovery

Discovery is profile-specific. A protocol 0.1 or 0.2 directory is a Folderbase
root when it contains both:

```text
FOLDERBASE.md
.folderbase/manifest.json
```

For a native protocol 0.5 directory, an exact regular
`.folderbase/manifest.json` with the supported `protocol_version: "0.5.0"`
establishes the root when that directory is opened and attested.
`FOLDERBASE.md`, `.folderbase/summary.md`,
`.folderbase/questions.jsonl`, adapter files, a folder name, and cloud
registration do not establish a root. Clients must not infer Folderbase status
from any of those hints.

When traversing a filesystem, a client stops applying a parent Folderbase's
policy when it observes another exact nested manifest marker. The nested tree
is an independent opaque boundary, not an inherited subfolder.

A parent traversal that observes any exact regular, no-follow
`.folderbase/manifest.json` stops at that directory and records one opaque
nested boundary. It does not read or decode the nested manifest through the
parent, even when the bytes are malformed or unsupported. Only an operation
that explicitly opens that nested root decodes and attests its manifest; that
operation fails closed if the root is invalid. This prevents malformed private
state from being exposed through the parent without making the parent an
authority over nested profile validity.

The shared classifier has three outcomes:

- an exact `.folderbase` directory containing an exact regular, no-follow
  `manifest.json` is the opaque boundary above, regardless of its bytes;
- an ASCII-case alias of either marker, a symlink or non-directory
  `.folderbase`, or a symlink or non-regular `manifest.json` is an unsafe
  filesystem shape, not Folderbase authority; and
- markerless `.folderbase` state, summary, question context, adapters, and
  other context are inert and establish no boundary.

Read-only analysis may report an unsafe shape as an `Unchecked` quarantine
(`unchecked` on the wire) and omit its descendants. That conservative omission
grants no authority.

Materialization, mutation, transfer, and restore seams reject unsafe shapes
instead of treating them as either ordinary content or a valid nested root.

Creating a nested folderbase also closes the parent boundary retroactively for
tracked paths beneath it. Parent history may retain immutable bytes for
recovery, but parent read, journal, and restore interfaces must not expose
those records while the nested boundary exists. Moving that history into the
new folderbase requires an explicit, reviewed transfer rather than implicit
inheritance.

## Required layout

The legacy 0.1/0.2 profile requires:

```text
Folderbase Root/
├── FOLDERBASE.md
├── .folderbaseignore
└── .folderbase/
    ├── manifest.json
    ├── objects/
    ├── activity/
    ├── decisions/
    ├── migrations/
    ├── policies/
    └── changesets/
```

Agent-specific bootstrap files are recommended but optional:

```text
AGENTS.md
CLAUDE.md
```

Empty protocol directories may be omitted from a portable export. Their
absence does not invalidate the folderbase.

A native 0.5 root requires only:

```text
Folderbase Root/
└── .folderbase/
    └── manifest.json
```

Root `FOLDERBASE.md` is fully ordinary optional user content in 0.5. Root
`.folderbaseignore` is optional and user-owned, but it controls capture policy:
clients bound its input, force-capture it when present, and change it only
through typed policy-aware flows. Optional `.folderbase/summary.md` and
`.folderbase/questions.jsonl` files are the named engine-owned hint formats.
Their absence is normal, and their presence does not expand authority or the
portable Version surface. Any other `.folderbase/**` content remains private
and inert but is not assigned one of those named hint formats.

`.folderbase/local/` is reserved for device-local runtime state such as
filesystem path-identity bindings. Clients must exclude that directory from
cloud synchronization and portable exports regardless of `.folderbaseignore`.
Its contents are never canonical folderbase history and must be rebuilt from
verified local observations on each device.

## Folderbase entry

For protocol 0.1 and 0.2, `FOLDERBASE.md` is the canonical human- and
agent-readable entry point. It must be valid Markdown and should remain concise
enough to enter an agent context without summarization.

It must contain:

1. folderbase name
2. purpose
3. current state
4. navigation
5. operating rules
6. unresolved work

Recommended shape:

```md
# Folderbase

## Purpose

Build file storage infrastructure that remains understandable to agents across
time.

## Current state

The 0.1 reference implementation is running locally and remains pre-release.

## Navigate

- `docs/product-prd.md` — product requirements
- `docs/protocol-spec.md` — on-disk contract
- `Decisions/` — current and superseded decisions

## Operating rules

- Read this file before changing the folderbase.
- Preserve ordinary file compatibility.
- Propose structural migrations before moving canonical knowledge.

## Unresolved work

- Validate the first Project Folderbase against the Client Company 2 migration case.
```

`FOLDERBASE.md` is not a transcript, generated dump, or complete index. It points to
deeper knowledge.

Protocol 0.5 has no mandatory narrative entry and no `folderbase.entry`
authority field. If a root `FOLDERBASE.md` exists, it is ordinary user content:
it may be text or opaque bytes, may be ignored from capture, and grants no
special permission. Optional `.folderbase/summary.md` and
`.folderbase/questions.jsonl` files may summarize or ask about the ordinary tree,
but they are non-authoritative hints. They never establish discovery, approve a
mutation, authorize sharing, or enter ordinary Folderbase Version bindings.
Other `.folderbase/**` content remains private and inert without becoming a
named narrative or question format.

Stored object paths must be matched using the canonical filesystem spelling.
On a case-insensitive filesystem, a legacy record such as `notes.md` and the
materialized path `Notes.md` identify one object, not two. Ambiguous aliases
must fail closed rather than create a second object identity.

## Folderbase manifest

`.folderbase/manifest.json` is the machine-readable root record.

Example:

```json
{
  "$schema": "https://folderbase.ai/protocol/0.1/folderbase.schema.json",
  "protocol_version": "0.1.0",
  "folderbase": {
    "id": "folderbase_019f9b75-0b22-7a18-8f40-3f29f1438b62",
    "name": "Folderbase",
    "kind": "project",
    "status": "active",
    "created_at": "2026-07-25T10:00:00Z",
    "entry": "FOLDERBASE.md"
  },
  "adapters": [
    {
      "agent": "codex",
      "path": "AGENTS.md"
    },
    {
      "agent": "claude",
      "path": "CLAUDE.md"
    }
  ],
  "policies": {
    "availability": "keep_local",
    "structural_changes": "approve",
    "archive": "approve",
    "cloud_sync": "disabled"
  }
}
```

### Required manifest fields

| Field | Meaning |
|---|---|
| `protocol_version` | Semantic protocol version used by the folderbase |
| `folderbase.id` | Stable globally unique identifier prefixed with `folderbase_` |
| `folderbase.name` | Human-readable name |
| `folderbase.kind` | Current semantic kind; independent of template lineage |
| `folderbase.status` | `active`, `paused`, or `archived` |
| `folderbase.created_at` | RFC 3339 creation time |
| `folderbase.entry` | Relative path to the canonical folderbase entry |
| `policies.availability` | `keep_local`, `managed`, or `cloud_only` |
| `policies.structural_changes` | `suggest`, `approve`, or `autonomous` |
| `policies.archive` | `manual`, `approve`, or `automatic` |
| `policies.cloud_sync` | `disabled` or `enabled` |

Unknown fields must be preserved by clients that rewrite the manifest.

Protocol 0.5 uses the separate
`protocol/schemas/0.5/folderbase.schema.json` profile. It removes
`folderbase.entry` from the required shape and requires the embedded
`policies.capture_ignore` record:

```json
{
  "$schema": "https://folderbase.ai/protocol/0.5/folderbase.schema.json",
  "protocol_version": "0.5.0",
  "folderbase": {
    "id": "folderbase_019f9b75-0b22-7a18-8f40-3f29f1438b62",
    "name": "Folderbase",
    "kind": "project",
    "status": "active",
    "created_at": "2026-07-30T00:00:00Z"
  },
  "adapters": [],
  "policies": {
    "availability": "keep_local",
    "structural_changes": "approve",
    "archive": "manual",
    "cloud_sync": "disabled",
    "capture_ignore": {
      "format": "folderbase-capture-ignore-v1",
      "rules": []
    }
  }
}
```

The capture record is closed: it contains exactly `format` and `rules`.
`format` is `folderbase-capture-ignore-v1`; `rules` contains at most 1,024
ordered nonempty strings, each at most 4,096 UTF-8 bytes and containing no NUL.
JSON Schema expresses the corresponding 4,096-character ceiling; runtimes must
also enforce the UTF-8 byte ceiling.

The optional top-level `folderbase_protocol_upgrade` record is the closed,
Core-owned recovery receipt for a legacy-to-0.5 manifest activation. It binds
the legacy protocol version, reviewed plan SHA-256, and SHA-256 of the activated
manifest with the receipt removed. It provides integrity and lost-ack recovery
only and grants no mutation, sharing, or hosted authority. Compatible clients
must preserve an unknown top-level `protocol_upgrade` extension without
interpreting it as this receipt.

### Folderbase kinds

Version 0.1 reserves:

- `person`
- `organization`
- `engagement`
- `project`
- `customer`
- `temporary`
- `custom`

Kinds select starting templates and recommendations. They do not change the
permission invariant, prohibit expansion, or require a folderbase to preserve the
template's suggested layout.

## Initialization approval binding

Initialization is additive, but a reviewed dry-run can still become stale
before apply. The reference Core therefore emits an opaque SHA-256 plan digest
and accepts that digest when applying an approved initialization.

The digest commits to:

- the canonical destination, physical filesystem root identity, and exact
  initialization request
- exact template identity, semantic package digest, and typed answers
- planned directories and protocol writes, with manifest fields interpreted
  as Core semantics
- existing-path and template preconditions
- visible destination paths and kinds for ordinary files, directories,
  symlinks, and nested-folderbase boundaries
- the canonical reconstructable-directory policy and explicit collapsed Git
  metadata boundaries

Generated Folderbase IDs and timestamps are excluded, so repeated dry-runs
over unchanged semantic state produce the same digest. Preserved ordinary-file
contents and sizes are not read or committed because initialization never
writes those files. Descendants of a nested Folderbase, recognized
reconstructable tree, or `.git` metadata boundary are not traversed; the
boundary path and kind are committed instead.

The CLI creates one Core plan. An apply carrying an expected digest compares it
to that exact plan and then performs one bounded metadata-only destination
inventory before its first write. A digest mismatch, destination membership or
kind change, boundary change, traversal-limit refusal, or planned-target
collision creates no protocol files. The successful result returns the digest
that was applied. Clients treat this digest as opaque and must not reproduce or
normalize the Core's canonicalization.

Initialization inventory traversal is bounded to 50,000 entries, 64 levels,
4,096 encoded bytes per relative path, 16 MiB of canonical inventory input,
2,000,000 path-component visits, and 2,000,000 directory-entry observations.
Budget accounting happens before names are retained in memory and also covers
nested-boundary probes. Traversal uses a root directory capability and opens
child directories without following symlinks. Large ordinary files are
metadata-only and therefore require no content hydration.

The preflight is optimistic concurrency, not atomic filesystem isolation.
Races after preflight are contained by no-follow parent capabilities and
per-write no-clobber installation. A competing path is preserved and apply
fails rather than overwriting it.

## Templates and organization guidance

A template is optional, versioned starting guidance. It may propose:

- initialization questions
- an initial folderbase entry and navigation
- folders or files that are useful for the kind of folderbase
- policies, ignore patterns, and agent adapters
- later additive suggestions

Template provenance records where a folderbase started. It is not a conformance
claim about the folderbase's current folder structure.

Template Protocol 0.2 packages are transparent JSON data conforming to
`protocol/schemas/0.2/template.schema.json`. A package declares its stable ID,
semantic version, suggested folderbase kind, questions, additive artifacts, and
supported upgrade edges. It cannot declare executable hooks, commands,
membership, permissions, grants, or shares. Artifact targets must be safe
relative paths, must be unique under case-folding, and use only
`create_if_missing`; a template therefore cannot overwrite an existing user
file.

Protocol 0.2 manifests may record optional `folderbase.template_provenance` with the
template ID, version, and application time. A folderbase without provenance remains
valid. The current `folderbase.kind` and directory layout are not constrained by a
template's suggested kind or artifacts, so a folderbase may expand and reorganize
without pretending to be a new template instance.

`folderbase.template_provenance` is the immutable Template Origin; clients must not
overwrite it when later guidance is applied. Each later verified additive
application appends an immutable Template Application record under
`.folderbase/template-applications/`. The latest verified application for the
same template ID is the comparison point for another expansion; if none
exists, clients compare against the origin version. These records are
provenance, not layout-conformance or authorization claims.

Reference Template Origin records include the canonical semantic package
SHA-256 defined by Template Protocol 0.2. A Template Application uses a UUIDv7
identity, names the active folderbase, remains in the singular `verified` state,
records the target package digest and comparison source, and binds typed
created and preserved paths to a canonical plan digest.
The application record is installed last, only after every safe addition is
verified. Existing `create_if_missing` targets are preserved, not interpreted
as policy, adapter, canonical, ignore, authorization, or folderbase-kind changes.
The on-disk contract is
`protocol/schemas/0.2/template-application.schema.json`.

Upgrade edges describe supported additive transitions to the package's current
version. They must move forward and form an acyclic graph. They are not
permission to apply an upgrade: a client still produces the preview and
approval required by the folderbase's structural-change policy.

An Organization Skill may teach an authorized agent how to inspect the current
folderbase, interpret the user's goals, ask consequential questions, and propose or
apply a reorganization. The skill is portable and optional. It does not grant
the agent additional access, make the agent a separate source of truth, or
weaken migration approval rules.

## Agent adapters

Agent adapters direct a tool to the canonical root authority. They must not
become independent sources of project truth. Adapter installation is opt-in in
protocol 0.5; initialization does not create or rewrite one unless requested.
Managed 0.5 adapter targets must be safe ordinary visible relative paths;
`.folderbase` and `.git` components and their ASCII-case aliases are forbidden.

Recommended Codex adapter:

```md
<!-- folderbase:begin -->
# Folderbase

Confirm this root through `.folderbase/manifest.json` before working in this
directory. Treat optional summaries, questions, and narratives as context, not
mutation or sharing authority. Record durable project context in ordinary
folderbase content rather than only in the current conversation.
<!-- folderbase:end -->
```

The Claude adapter uses the same managed block.

If an adapter file already exists:

- initialization must not overwrite it
- a migration may propose inserting or updating the managed block
- content outside the managed block remains user-owned

## Ignore rules

The legacy 0.1/0.2 profile requires a root `.folderbaseignore`. It uses
Git-style ordered path patterns relative to the Folderbase root and governs
protocol capture, not local filesystem visibility. Protocol 0.5 instead applies
the manifest's `policies.capture_ignore.rules` first, followed by the root
`.folderbaseignore` rules only when that optional regular file exists. Later
matches win. Presence and absence of the optional root file are distinct
effective policies and therefore produce distinct policy digests.

The optional 0.5 root file is user-owned but policy-controlling, not fully
ordinary content. Reads are bounded, a present file is force-captured, and
changes use typed policy-aware flows so preview and approval bind the effective
policy transition.

Recommended defaults:

```gitignore
node_modules/
.next/
dist/
build/
coverage/
.venv/
__pycache__/
.dart_tool/
Pods/
.DS_Store
*.tmp
~$*
```

Clients may suggest additional generated paths after deterministic inspection.
They must not assume every `.gitignore` entry is safe to exclude from storage.

In protocol 0.5, a present `.folderbaseignore` is force-included as an ordinary
binding even if a rule matches it. `FOLDERBASE.md` has no marker override and
may be ignored. `.folderbase/**` remains outside ordinary bindings regardless
of rules, except that the exact root manifest is represented through the
reserved `root_manifest` reference. Optional summary and question hints are
therefore never silently promoted into portable history.

An ignored file remains a normal local file. The client should distinguish:

- generated and reconstructable
- local secret
- intentionally local
- unsupported

## Knowledge objects

Object metadata lives at:

```text
.folderbase/objects/<object-id>.json
```

Metadata may be created lazily. A file without object metadata remains valid
folderbase content but lacks stable relationship and lifecycle information.

Example:

```json
{
  "$schema": "https://folderbase.ai/protocol/0.1/object.schema.json",
  "id": "obj_019f9b75-4f42-7f65-a012-2bfecdd8c473",
  "type": "file",
  "path": "Deliverables/Architecture.md",
  "media_type": "text/markdown",
  "content": {
    "algorithm": "sha256",
    "digest": "4d5b2d..."
  },
  "lifecycle": {
    "status": "canonical"
  },
  "provenance": {
    "created_at": "2026-07-25T10:05:00Z",
    "source": "local"
  },
  "relationships": [
    {
      "type": "implements",
      "target": "obj_019f9b75-6ed2-71cc-a7a7-22d3c38b3b55"
    }
  ]
}
```

### Object requirements

- `id` is stable across path changes.
- `path` is relative to the folderbase root and represents current materialization.
- content hashes identify bytes, not object identity.
- two objects may have identical content.
- lifecycle status is one of `draft`, `canonical`, `superseded`, `archived`,
  or `deleted`.
- a superseded object should reference its replacement.

Version 0.1 does not prescribe a semantic ontology. Relationship types are
lowercase strings. Common reserved types include:

- `depends_on`
- `implements`
- `derived_from`
- `supersedes`
- `references`
- `approved_by`
- `belongs_to`

## Decisions

Structured decision records live under `.folderbase/decisions/`. A Project
Folderbase template may also expose a visible `Decisions/` folder for authored
decision documents.

Minimum record:

```json
{
  "id": "decision_019f9b76-11be-75c3-8bb9-53bca3859128",
  "title": "Use filesystem-native folderbases",
  "status": "accepted",
  "decided_at": "2026-07-25T10:10:00Z",
  "summary": "Current content remains readable as ordinary files.",
  "supersedes": null,
  "related_objects": []
}
```

Decision status is `proposed`, `accepted`, `superseded`, or `rejected`.

## Activity

Activity is append-only newline-delimited JSON, partitioned by UTC date:

```text
.folderbase/activity/2026-07-25.ndjson
```

Example event:

```json
{
  "id": "event_019f9b76-6615-7608-9424-f8d0fcc4c099",
  "at": "2026-07-25T10:20:00Z",
  "actor": {
    "type": "member",
    "id": "local"
  },
  "channel": {
    "type": "agent_session",
    "name": "codex"
  },
  "action": "object.updated",
  "object_id": "obj_019f9b75-4f42-7f65-a012-2bfecdd8c473",
  "reason": "Updated the architecture after founder review."
}
```

In version 0.1, a local agent acts through the member's authority. Agent or tool
information is optional provenance, not an independent permission identity.

## Migration

A migration is a state machine:

```text
analyzing → questions → proposed → approved → applying → verified
                                      └──────→ rejected
                            applying → rolled_back
```

Not every change to folder organization is a migration. A human or authorized
agent may reorganize content within one folderbase through ordinary file operations,
subject to the folderbase's change policy and normal versioning. The product may
present a **Reorganize Folderbase** workflow that uses the same operation and
recovery primitives for batch changes.

A migration is required when adopting an unmanaged folder or when a proposed
change creates, removes, merges, or transfers folderbase boundaries, ownership,
membership, retention, or lifecycle. An Organization Skill may recommend such
a migration, but it cannot approve one on the user's behalf.

Migration plans live at:

```text
.folderbase/migrations/<migration-id>/plan.json
```

A plan contains:

- source inventory digest
- an approval-bound source-topology snapshot, excluding only explicit
  destination roots and protocol state
- base folderbase version
- questions and recorded answers
- proposed folderbases and permission boundaries
- operations
- exclusions
- expected local and cloud storage impact
- rollback information

When an unmanaged folder has more than 32 assignment scopes, an analyzer may
replace per-scope questions with versioned **Migration Assignment Groups**.
Each group declares its literal, sorted members and a coverage digest that
binds the grouping rule, source root, content kind, member path, and whether
the member is a regular file or a collapsed reconstructable tree. One default
destination applies to every literal member; an optional exception can replace
that destination for one exact member. Prefixes and descendants never inherit
an assignment implicitly, and grouping never creates a permission boundary or
grant. Any rule, membership, default, or exception change invalidates the
approval and requires review.

If a member is an explicitly included reconstructable tree, planning records
the exact expanded descendant set. Apply must re-expand and compare that set
before changing plan state, creating a journal, or creating a destination.
Added or removed descendants, new nested folderbases, and new secret-shaped content
make the approved plan stale.

Allowed operation types:

- `create_folderbase`
- `create_folder`
- `create_object`
- `move_object`
- `copy_object`
- `mark_canonical`
- `mark_superseded`
- `archive_object`
- `add_relationship`
- `update_adapter`
- `update_policy`

Destructive deletion is not a migration operation in version 0.1.

Before applying structural operations, a client must:

1. verify the source inventory has not changed unexpectedly
2. create a recoverable base snapshot
3. obtain approval unless policy explicitly permits the operation

Before an additive apply, the client must also revalidate the complete
analyzer-visible source topology and every current nested-folderbase ancestor before
creating a journal or destination. Before rollback, it must revalidate every
created path and refuse any nested boundary that was not materialized by the
approved migration. These checks happen before the migration state changes or
any path is removed.
4. record each completed operation
5. verify the resulting content

## Workspace composition

A workspace descriptor may compose several folderbases:

```text
Client Company 2/
├── WORKSPACE.md
└── .folderbase-workspace.json
```

Example:

```json
{
  "$schema": "https://folderbase.ai/protocol/0.1/workspace.schema.json",
  "protocol_version": "0.1.0",
  "id": "workspace_019f9b77-8dd4-7c28-8d21-1d89cd4da891",
  "name": "Client Company 2",
  "folderbases": [
    {
      "folderbase_id": "folderbase_019f9b77-a003-785a-b7c8-195f45a0c985",
      "label": "Security Remediation",
      "path": "Security Remediation"
    },
    {
      "folderbase_id": "folderbase_019f9b77-bfb8-74da-8d39-5a524b56235e",
      "label": "Commercial",
      "path": "Commercial"
    }
  ]
}
```

The descriptor is navigation, not authorization. A client shows only folderbases the
current member can independently access. Failure to access one folderbase must not
grant, leak, or delete anything from another.

Hosted sharing is outside protocol version 0.1. A hosted service may grant a
folder, object, or view without granting the complete source folderbase. Such a
grant must name its scope explicitly and must not be inferred from this
descriptor or from filesystem nesting.

## Hosted materialization invariants

A hosted Live Folder locator is navigation, not authority. The authenticated
recipient grant owns Can View or Can Work and a separate, default-off Can
Materialize capability. The recipient's devices and sponsored Agent Sessions
inherit that grant ceiling without acquiring independent grant authority.

Generic Live Folder materialization is present-tense: one actor may receive a
short-lived ticket only for one exact current object version in the authorized
projection. Redeeming the ticket creates one durable Transfer Session that
preserves the actor, recipient grant, capability revision, Folder Scope
revision, intent, object, version, digest, and size bounds while a resumable
transfer proceeds. Transfer or ticket state alone never establishes local
availability or Agent-readiness.

Provider locations and storage keys are not portable identifiers and never
grant access. A hosted service resolves them internally and authorizes only
bounded transfer operations. Checkout hydration and historical recovery use
separate authorization flows; a caller cannot turn an arbitrary historical
version identifier into Live Folder materialization authority.

## Device-local root identity

`root_instance_sha256` is device-local integrity and recovery evidence, not a
portable Folderbase identity or permission grant. Unix uses the released
`folderbase-physical-root-instance-v1` domain over `unix`, big-endian `u64`
device, and big-endian `u64` inode. Those bytes remain unchanged.

Released Windows records used the same V1 domain over `windows`, big-endian
`u32` volume serial, and big-endian `u64` file index. New Windows attestations
use `folderbase-physical-root-instance-v2` over `windows`, the complete
big-endian `u64` volume serial, and all 16 bytes of
`FILE_ID_INFO.FileId.Identifier`. Both values are queried from one retained
no-follow root handle. The digest domain selects the encoding; the public
attestation receipt remains the same five-field record.

On Windows, Core may admit an exact released V1 digest for a durable record
when it matches the released digest computed from the retained root. Admission
preserves the exact recorded value. Active capture and restore journals, their
deterministic derivations, rollback, cleanup, completion, and authority receipts
are never normalized or rewritten. Only mutable Local Head may move to the
current V2 root under the transaction lock, after the named immutable Version
and digest verify and no pending recovery remains, or as the normal next Head
CAS. Capture-transaction authority keeps the SHA-256 of the exact journal
bytes; version-derived authority is recomputed for the current root. Once a
Head records V2, a different full identity is rejected even if the two roots
would have collided under V1 truncation.

First-upgrade admission of a released Windows V1 record is necessarily trust on
first use within trusted local `.folderbase`. V1 cannot manufacture the upper
identity bits it never recorded, so a copied, self-consistent legacy record on
a rare root with the same truncated tuple is not distinguishable from same-root
legacy state. That compatibility fact grants no portable, actor, sharing, or
Cloud authority. Mutable Head moves to V2 at the safe boundary above; immutable
legacy transaction evidence remains explicitly legacy through retirement.

## Canonical Folderbase Version 0.4

`folderbase-version-v1` is the portable bounded full state of one Folderbase
boundary. It uses the distinct `fbversion_` identity namespace; the existing
`version_` namespace remains the Object Version for one immutable Knowledge Object
representation. Neither identity is a chunk-manifest digest.

The closed record contains the exact Folderbase and Folderbase Version identities,
parents, creation time, pinned portable-path policy, one reserved exact
`.folderbase/manifest.json` Object Version reference, sorted live Path Bindings,
sorted Tombstones, and sorted typed exclusions. The containing Folderbase Version
itself establishes the deletion generation for every Tombstone, so Tombstones do
not repeat the containing ID or digest.

Every protocol 0.4 restorable full state contains `.folderbaseignore` and
`FOLDERBASE.md` as live regular-file Path Bindings. Both are required 0.4
protocol files, not optional template output. The 0.4 schema rejects fewer than
two bindings; 0.4 semantic validation proves the exact required paths and
kinds.

Regular files are opaque exact bytes plus executable fidelity. Symlinks retain an
exact UTF-8 target and are never followed; only lexically contained targets that
avoid protocol state and nested boundaries conform. Directories are explicit,
including empty directories. Hard links, FIFOs, sockets, block devices, character
devices, and other special nodes are typed unsupported exclusions in v1 and must
never disappear silently.

Paths preserve their exact UTF-8 spelling. The v1 policy rejects traversal,
absolute and drive paths, backslashes, NUL, Windows-reserved or trailing-dot/space
components, protocol self-capture, excessive size/depth/count, and exact, NFC, or
full-default-case-fold collisions. Names are never silently normalized or renamed.
A nested Folderbase contributes one boundary exclusion and no parent-version
binding may enter it. Nested-boundary exclusions cannot overlap. Windows DOS device
rejection includes the superscript-digit `COM¹`–`COM³` and `LPT¹`–`LPT³` spellings
recognized by Windows, including names with extensions.

The record is at most 64 MiB and 16,384 aggregate entries. A 10 GiB file therefore
appears as bounded metadata, but a producer may seal no Folderbase Version until
the exact included Object Version references and bytes have been verified. Core's
0.4 module decodes, validates, digests, looks up, and performs controlled bounded
encoding of a sealed record. It also produces a deterministic typed diff that
distinguishes stable-ID moves, same-path recreation, deletion/Tombstone evidence,
fidelity updates, exclusions, and root-manifest changes. A moved Object that also
changes version or metadata produces both `Moved` and `Updated`. The public type
cannot be constructed through raw Serde deserialization; the bounded private wire
decoder and validated crate-private producer boundary are the only construction
paths. Core can now produce an inert metadata-only Capture Plan and consume that
exact plan in a byte-verified, journaled local sealing transaction, as specified
below. Remote publication remains a later transaction.

The full Folderbase Version is independent restore state. It is never exposed as a
Folder Scope share projection because doing so could disclose paths outside the
grant. A separate projection artifact will bind only authorized content.

The repository/tag source archive is the normative cross-language protocol
distribution. The `folderbase-core` Cargo package contains the Rust runtime module,
but intentionally does not duplicate the workspace-level schema, fixtures, or
reference encoder. The released manifest at
`protocol/releases/0.4/folderbase-version-v1.json` declares the exact
source-release surface. ADR-0004 is Accepted, and CI rejects either a non-released
status or a remaining candidate manifest.

## Folderbase Version protocol 0.5 delta

Protocol 0.5 retains the closed `folderbase-version-v1` envelope, portable-path
policy, bounds, semantic validation, and canonical digest encoding from 0.4.
The `protocol_version` literal changes from `0.4` to `0.5`; because that string
is the first encoded field after the v1 digest domain, otherwise identical 0.4
and 0.5 records have distinct digests.

The only root-file binding delta is deliberate. A 0.5 Version may have zero
bindings. Root `FOLDERBASE.md` and `.folderbaseignore` are optional bindings
when present; neither is required to restore the exact 0.5 authority because
`root_manifest` represents `.folderbase/manifest.json`. `FOLDERBASE.md` is
fully ordinary. `.folderbaseignore` is user-owned but policy-controlling,
bounded, force-captured, and changed only through typed policy-aware flows.
Ordinary `.folderbase/**` bindings remain forbidden, including the named
optional `.folderbase/summary.md` and `.folderbase/questions.jsonl` hints.

The immutable 0.4 release inventory, conformance bytes, reference encoder, and
verifier semantics do not change. Protocol 0.5 has a separate candidate schema,
conformance tree, reference encoder, member-hashed inventory, release-manifest
sidecar, and verifier under `protocol/releases/0.5/`. ADR-0006 records the
accepted ordinary-folder and optional-narrative transition. Repository CI and
package-install validation run both 0.5 verifiers while retaining the frozen
0.4 digest and distribution gates.

### Proposed local capture, sealing, and Local Head

The first producer-side FB-41F slice remains Proposed in ADR-0005. A
`FolderbaseVersionStore` can open one attested physical root and return an opaque,
bounded `CapturePlan` containing filesystem metadata only. The plan binds the
physical root, effective ordered ignore policy, and optional device-local head.
It is inert and is not a Folderbase Version.

`.folderbase/` is trusted engine-owned local state, analogous to `.git/`.
Local Core guarantees bounded and closed decoding, torn-state recovery,
ordinary race and substitution refusal, and no-clobber workspace mutation. Its
digests and stable filesystem identities are integrity and linearization
evidence; they are not signatures. Deliberate coordinated forgery of every
related `.folderbase/` record by a process running as the same user is outside
the local Core threat model. Cloud grants and hosted Live Folder authority are
separately authenticated and cannot be obtained from local metadata.

Core reads the manifest, optional `.folderbaseignore`, optional
`.folderbase/local/head.json`, and bounded retained restore-authority receipts
needed to interpret a 0.5 root, but does not request data access to ordinary
files or their retained private links while planning. Unix planning compares
no-follow directory metadata; Windows uses zero-data-access, no-follow metadata
handles. PDFs, videos, CSV, SQLite, Git packs, and unknown files are all opaque
regular files. Nested Folderbases, hard links, and special nodes are typed
exclusions; symlinks are not followed.

For protocol 0.5, Core applies manifest engine rules first, then the optional
root `.folderbaseignore` rules. A present `.folderbaseignore` is captured;
`FOLDERBASE.md` may be ignored. For 0.4 compatibility capture, both required
root files retain their marker override. `.folderbase/**` cannot enter the
ordinary inventory under either profile. Definitively excluded directories are
classified before they are opened. Root-relative no-follow directory
capabilities prevent ambient-path escape, opened directory identities are
rechecked, and streamed traversal enforces the aggregate bound without
retaining an unbounded directory listing. The capture inventory uses the v1
portable-path, Unicode collision, depth, entry-count, and object-size limits.

`FolderbaseVersionStore::seal_capture(plan)` first revalidates the complete plan,
then durably journals every new stable Object ID, candidate Object Version ID,
Folderbase Version ID, parent, timestamp, expected Local Head, and the complete
sorted target Tombstone set. The journal bounds assignments and Tombstones as
one Folderbase Version entry aggregate.

The same exact path and same supported kind continue one logical Knowledge
Object by default, including atomic-save replacement. Changed content or
executable fidelity creates a new Object Version under that Object ID. A prior
live path absent from the capture creates a Tombstone; a supported-kind
replacement creates a Tombstone for the old Object plus a new live Object ID.
Tombstones carry forward with newest-deleted-Object-per-exact-path semantics.
Recreation after a captured absence therefore receives a new Object ID.

Physical identity is exact-read race evidence and a future move hint, not sole
cross-capture logical identity authority. Unix observations use device/inode;
Windows observations use the volume serial and complete 128-bit File ID from
the opened no-follow handle. Missing or different physical identity causes full
verification and derived-evidence refresh without splitting same-path,
same-kind logical identity. A delete-and-recreate entirely between captures is
continuity unless a prior Tombstone, a future App filesystem-event journal, or
a future explicit Core deletion operation supplies durable deletion evidence.
All ordinary regular files are read as exact opaque bytes through root-relative
no-follow capabilities and checked against planned metadata and physical
identity before and after the read.

A prior live path newly hidden by ignore policy, a nested Folderbase boundary,
or a typed unsupported-node exclusion is refused before capture-journal or
Local Head mutation. Unobserved content is never silently interpreted as
deleted content.

Core installs content-addressed blobs and immutable Object Version records through
the existing `LocalVersionStore`. It then constructs the one canonical
Folderbase Version through the crate-private verified-producer seam, encodes it
with the bounded encoder, publishes it append-only, and independently verifies
every referenced durable record. A shared capability-confined state publisher
stages, flushes, publishes, verifies, replaces, and removes capture state
relative to retained no-follow directory handles. It rejects symlink/junction
parent swaps; a detached write cannot advance visible Head. Local Head advances
only after those checks, through a compare-and-replace under a cross-platform
exclusive device-local file lock. New Local Heads use
`folderbase-local-head-v2` with one closed authority discriminator:
`capture_transaction_v1` binds the SHA-256 digest of the complete capture
journal, while `version_derived_v1` binds a domain-separated digest of the
Folderbase ID, physical-root instance, Version ID, and Version digest. Released
`folderbase-local-head-v1.transaction_sha256` records are read only with their
original capture-transaction meaning and are compare-and-swapped to v2 under
the transaction lock after restore activity is ruled out. They are never
silently reinterpreted as version-derived authority. Recovery after Head
publication refuses any journal mutation and requires the committed version's
exact parents and timestamp to match the anchored capture intent before
projecting identity evidence.
When a durable Head or active journal carries an admitted released Windows V1
root, the journal's plan digest is reproduced with that exact recorded root.
Recovery never hashes a current-root normalization in place of the recorded
pre-Head or post-Head authority. A released-root Head is rebound only after its
immutable Version verifies and pending capture work is retired, unless the
normal next Head CAS already writes the current root.

The closed v2 wire shape is:

```json
{
  "format": "folderbase-local-head-v2",
  "folderbase_id": "folderbase_...",
  "root_instance_sha256": "<64 lowercase hex>",
  "version_id": "fbversion_...",
  "version_sha256": "<64 lowercase hex>",
  "authority": {
    "kind": "capture_transaction_v1",
    "sha256": "<64 lowercase hex>"
  }
}
```

The `kind` value is exactly `capture_transaction_v1` or
`version_derived_v1`. Unknown top-level fields, unknown authority fields,
unknown authority kinds, malformed digests, and a `version_derived_v1` digest
that does not equal the canonical domain-separated derivation are invalid.
`capture_transaction_v1.sha256` is SHA-256 of the exact durable capture-journal
bytes. `version_derived_v1.sha256` is SHA-256 of the compact UTF-8 JSON encoding
of this object in the displayed field order:

```json
{
  "format": "folderbase-local-head-authority-v1",
  "folderbase_id": "folderbase_...",
  "root_instance_sha256": "<64 lowercase hex>",
  "version_id": "fbversion_...",
  "version_sha256": "<64 lowercase hex>"
}
```

Released v1 non-genesis capture journals stored the prior authority as
`expected_head.transaction_sha256`. The bounded active-journal reader accepts
that exact closed nested wire and its exact released assignment shape as capture
authority, converts it to
`capture_transaction_v1` only in memory, and separately retains SHA-256 of the
exact journal bytes that were read. Pre-Head execution and committed-Head
recovery both bind and compare that retained byte digest; normalized typed
serialization is never substituted for a digest already named by a released
Head. Current-only assignment fields cannot be smuggled through the released
decoder under a flat released Head.

Sealing opens the existing retained state capability and re-attests the inert
plan before any lock, layout, recovery, or capture publication. Capture-specific
blob, Object Version, Folderbase Version, projection, identity, journal, and Head
operations reuse that capability rather than re-entering through ambient paths.
Mutating root openers reject Windows junctions and all other reparse points.

The active journal's writer and restart reader share one explicit bound.
Assignment and Tombstone aggregate cardinality, every planned
path/kind/observation, reused Object ID, prior Object Version, root-manifest
lineage, expected Head, and the complete sorted target Tombstone set are matched
to the approved plan and verified parent before object writes.
For each regular source with retained restore links, metadata-only planning and
the journal also commit the expected live link count and a canonical sorted set
of exact authority receipt paths and byte digests, retained stage paths, and
publication identities. Missing fields in released journals normalize only to
one live link and an empty authority set and remain absent when serialized, so
their original Head-anchored SHA-256 is preserved. The released decoder uses a
closed historical assignment type; a current-only link commitment is an unknown
field rather than a compatibility alias. Default-only plans retain the v1
plan-digest domain when Head is absent or capture-transaction-derived. That v1
encoder reproduces the released flat
`current_head.transaction_sha256` representation byte-for-byte. A
version-derived Head or any authority-bearing entry uses the typed v2
plan-digest domain. Core re-enumerates and revalidates that exact set from the
retained source handle immediately before and after its bounded byte read.
Added links and same-count authority-set swaps are concurrent state changes.
When a bounded active journal decodes through the released-v1 wire, recovery
preserves that wire kind, exact raw byte length, and exact raw SHA-256.
Preflight applies the byte bound to those raw bytes and validates the released
closed schema plus normalized transaction semantics; it does not apply the same
wire bound to a larger typed reserialization that is never persisted. Current
and newly assigned journals remain bounded through the current encoder. JSON
whitespace accepted by the released decoder remains part of its raw authority:
the exact maximum is accepted, one byte over is refused, and truncated JSON is
never normalized into a transaction.
The journal makes every persistence boundary retryable with the exact assigned
IDs and preserves the prior Head until the complete next version is durable.

`FolderbaseVersionStore::restore_tombstone(path)` restores only a regular-file
Tombstone selected from the current verified Local Head. It searches the
bounded ancestor DAG for the nearest verified live binding with the exact
path, Object ID, and Object Version. That binding supplies the authoritative
opaque-byte digest, length, and executable fidelity. Missing, ambiguous,
cyclic, corrupt, or over-limit ancestry is refused.

Restore uses a separate bounded journal under the shared local transaction
lock. Capture and restore refuse each other's active intent. The journal binds
the expected Head, selected Tombstone, recovered live binding, target version,
timestamp, and digest. Target and transaction IDs are deterministic
domain-separated derivations of the verified parent authority; the timestamp
is re-derived from that parent, so rewriting the mutable journal alone is
refused under the trusted-local-state boundary. Deliberate coordinated forgery
of every related trusted local record is not a cryptographic guarantee. A
private copied stage retains transaction ownership
while Core hard-links it into the absent same-path destination. Existing
regular files, directories, symlinks, and dangling symlinks are never replaced;
even identical foreign bytes are refused. Retry may accept the destination
only when it has the exact retained-stage filesystem identity. Core validates
the complete bounded reachable ancestry DAG before accepting the nearest
candidate, so a binding cannot mask a deeper cycle and a legitimate
convergent DAG remains accepted. Cycle validation runs over the complete
bounded adjacency graph independently of global traversal deduplication.

Workspace publication and every multi-step restore observation retain a
no-follow parent-directory capability, its physical identity, the validated
leaf, and the attested Folderbase Root. Core freshly reopens that parent from
the root and compares its exact identity before mutation and after mutation,
hooks, authority retention, and completion proof. Ancestor replacement
therefore cannot redirect publication or produce a false success.

On POSIX systems this guarantee is scoped to the retained capability and
coordinated Folderbase namespace. An uncoordinated same-user rename may move the
exact opened directory after an attachment proof; if it races after hard-link
publication, the moved directory may contain that exact transaction-owned
link. Core does not claim global pathname confinement and does not unlink
through a replacement pathname. It retains journal, stage, and cleanup evidence
and fails closed. Windows parent capabilities deny delete sharing while held,
so the equivalent directory rename is blocked.

Publication topology is exact. A missing destination is eligible only when the
private stage has one link. An existing destination is resumable only when it
is the same filesystem object as the stage and that object has exactly the two
expected links. A missing destination with any extra link returns typed
`RestoreNamespaceRepairRequired` before another hard link is created. Recovery
continues after the user either returns the moved parent to the intended path or
inspects and explicitly removes the operation-owned orphan. A future managed
workspace may provide a stronger platform-specific namespace mutation
invariant; v1 does not depend on it.

The resulting full-state Folderbase Version preserves the root manifest,
exclusions, every unrelated live binding, and every unrelated Tombstone,
removes only the selected Tombstone, restores the original Object ID and Object
Version, and names the deletion Head as its sole parent. The target file and
every immutable reference verify before Local Head changes. Immediately before
and after the Local Head CAS, Core re-attests the physical root, case-folded
nested boundaries, retained-stage/destination identity, exact bytes, length,
and executable fidelity. A post-Head failure durably restores the prior Head
on the retained root capability before reporting conflict. Journal, stage,
target, version, Head, projection, and cleanup boundaries are recoverable.
Both prior-Head execution and committed-Head recovery re-derive the selected
Tombstone, live binding, deterministic assignment, and exact child Version
from the verified expected parent. After all read-only eligibility checks and
before journal publication, Core atomically rebinds the verified parent Local
Head to `folderbase-local-head-authority-v1`, a digest of the attested
Folderbase ID, physical-root instance, parent Version ID, and parent Version
digest. The rebound parent and restore-produced Heads are v2 records with
`version_derived_v1` authority. Committed recovery rejects a journal-supplied
prior Head digest that cannot be rederived after the prior Head is gone.
For an admitted released-root restore, every transaction and target
derivation uses `transaction.root_instance_sha256`, not the current
attestation. Target and rollback Heads retain that recorded root until cleanup
retires pending state; cleanup, completion, and authority records remain exact
immutable compatibility evidence. Core then independently verifies the
installed Version and atomically rebinds only Local Head to the current root.
Post-Head projection remains confined to the retained state capability, and
projection failure restores the exact prior Head. An in-place edit of the
transaction-owned published target preserves the user's bytes. Cleanup
publishes a durable closed v2 singleton receipt with `committed`, `modified`, or
`committed_modified` disposition before retiring mutable intent. Every
disposition rederives the exact deterministic transaction from the immutable
parent, Tombstone, and ancestor binding, and the receipt binds the durable
device-local identity of the published inode. Core retains the
transaction-unique private stage as an authority link and never automatically
renames or unlinks it. The private pathname, visible pathname, publication
identity, and committed byte/mode fidelity are re-proved before and after both
cleanup hook boundaries. A missing or replaced authority link leaves recovery
pending and can never return restored success.

A late same-inode edit after target Head publication transitions to
`committed_modified`; cleanup preserves the edit and retains exact private
authority without reporting restored success. Modified cleanup does not require
owned user bytes to remain different from sealed bytes. The pending receipt
survives active-journal retirement, blocks capture, and drives restartable
convergence. Successful committed cleanup atomically replaces one bounded
device-local completion v2 receipt before retiring the pending receipt.
Completion evidence never blocks capture. It recovers an idempotent terminal
result only while the exact target Head and installed Version remain current
and the authority receipt, retained stage, and workspace path still prove the
recorded published identity, sealed bytes, and executable fidelity. Capture
accepts the resulting hard-linked workspace file only when its link count is
one visible link plus the exact count of validated Folderbase authorities for
that path and identity; any ordinary extra hard link remains excluded.
Authorities are capped at 4096 and new restore fails with typed maintenance
required at the cap. There is no automatic authority garbage collection in
this version. Unix identity is device plus inode while the retained link keeps
that inode live; Windows uses volume serial plus the complete 128-bit
`FILE_ID_INFO` identifier. Missing, foreign, changed, or stale state produces
no restored-success result. Unix staging explicitly applies its final `0700`
or `0600` permissions after creation, independently of process umask.
All cleanup hooks and mutable-state operations precede one final success
linearization proof. A transaction-locked released-root Local Head rebind also
precedes that proof. Final and terminal verification admit exactly one complete
recorded-root target Head with independently derived recorded-root authority or
one complete current-root rebound Head with independently derived current-root
authority. They compare the full Folderbase ID, root digest, Version ID,
Version digest, and authority rather than a root-free Head summary. The
transaction, completion, and retained authority records keep their exact
recorded-root bytes. Immediately before returning `Restored`, Core revalidates
those bytes, the exact target Version and permitted Head, retained stage and
visible destination identity, content digest and length, and executable mode.
No hook or filesystem mutation follows that proof.
Directory and symlink Tombstone reconstruction remain outside v1 restore.

This remains Proposed. Productive captured-absence and supported-kind
replacement Tombstones and exact ordinary-file no-clobber restore are
implemented, including crash convergence. Durable App filesystem-event or
explicit Core deletion evidence, cross-path moves, directory/symlink restore,
database snapshot coordination, Remote Head publication, sync, sharing,
authorization, and Cloud behavior remain out of scope.

## Checkout

A checkout is an isolated materialization at a known folderbase version.

Checkout metadata records:

- checkout ID
- source folderbase or view IDs
- base version
- included object IDs
- excluded paths and reasons
- creation time
- intended permission mode

The checkout contains normal files and the relevant folderbase entry and adapters.

## Change sets

A change set describes one declarative final-state delta produced against a
checkout:

```json
{
  "id": "changeset_019f9b78-5db7-79d8-88ad-dda3a34cfbd4",
  "checkout_id": "checkout_019f9b78-4811-7d2e-993e-308bc2378d74",
  "base_version": "version_019f9b77-fdfa-78fb-8ca5-4ff25e6cc4b1",
  "operations": [
    {
      "type": "move",
      "object_id": "obj_019f9b75-4f42-7f65-a012-2bfecdd8c473",
      "base_version_id": "version_019f9b77-fdfa-78fb-8ca5-4ff25e6cc4b2",
      "relative_path": "draft.md",
      "destination_relative_path": "approved.md"
    }
  ],
  "status": "proposed"
}
```

Change-set status is `proposed`, `approved`, `applying`, `applied`,
`conflicted`, or `rejected`.

Protocol 0.1 accepts 1–64 typed `create`, `update`, `move`, and `delete`
operations. One object may appear at most once. Create and update carry a new
immutable content version; move and delete do not. A move changes working path
without changing object or content-version identity. A delete records a
recoverable tombstone.

A publisher must detect divergence from the pinned object bases and validate
the complete proposed namespace before applying. Publication is atomic: every
authorized, non-conflicting operation becomes one Folderbase Version, or none
does. Can Work is standing approval for conflict-free work inside the current
Live Folder grant. Conflicts or authorization loss preserve the complete
candidate Change Set for review; they never expose a partially applied folder.
Candidate storage keys are server-derived and are not accepted from callers.

## Availability

Protocol state distinguishes:

- `local_complete`
- `session_ready`
- `remote_ready`
- `incomplete`
- `archived`

Sync completion alone does not imply agent-readiness. A client must verify
materialized content and required dependencies before reporting
`local_complete` or `session_ready`.

`keep_local` means the client must request eager materialization and must not
initiate eviction. If the operating system cannot guarantee the policy, the
client must report the folderbase as not guaranteed Agent-ready.

## Archive

Archive is a verified lifecycle transition:

1. upload and verify current content
2. verify required version history
3. record archive policy and time
4. transition folderbase or object status
5. remove local bytes only after verification
6. retain metadata and restoration information

An archived object must report its remote size and expected restore size.

## Validation

A version 0.1 validator checks:

- required discovery files exist
- manifest JSON is valid
- protocol version is supported
- folderbase ID and required fields are present
- entry and adapter paths remain inside the root
- object IDs are unique
- object paths resolve or have an allowed non-materialized state
- content digests match when requested
- relationship targets are valid or explicitly external
- migrations and change sets have valid state transitions

Validation must not modify a folderbase. Repair is a separate explicit operation.

A native 0.5 validator instead requires the exact root manifest, rejects
unsupported live protocol versions, validates the closed embedded
`capture_ignore` record and its runtime UTF-8 byte bounds, and does not require
`FOLDERBASE.md` or `.folderbaseignore`. A present `FOLDERBASE.md` is ordinary
content. A present `.folderbaseignore` is bounded policy input and a
force-captured binding under the 0.5 capture semantics.
Optional summary and question hints never satisfy a missing manifest or grant
authority.

## Protocol compatibility

The protocol uses semantic versioning:

- patch: compatible clarification or optional field
- minor: backward-compatible capability
- major: incompatible representation or invariant

Clients must:

- reject unsupported major versions
- keep version 0.1 folderbases readable when adding 0.2 template support
- preserve unknown fields
- warn about unsupported optional capabilities
- avoid rewriting records they cannot safely round-trip

## Open artifacts

The protocol project will publish:

- JSON Schemas
- Markdown templates
- reference CLI
- conformance fixtures
- migration fixtures
- change-set fixtures
- compatibility tests

Hosted sync and account services may remain proprietary while implementing this
open contract.

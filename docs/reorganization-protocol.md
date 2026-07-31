# Reorganization Protocol 0.3

Folderbase Core 0.3 defines the portable, inert records used to propose how an
existing Folderbase should evolve. It does not define organization policy,
authorization, filesystem analysis, apply, recovery, or rollback in this first
slice.

## Records

`folderbase-reorganization-draft-v1` is revisable data. It may contain unanswered
consequential questions and cannot be approved or applied.

`folderbase-reorganization-plan-v1` is produced only by sealing a valid Draft whose
required questions are answered. It adds:

- `analysis_scope_digest`, binding the exact portable facts used by analysis; and
- `plan_digest`, binding the complete sealed proposal except the digest field
  itself.

Both records use `protocol_version: "0.3.0"`. Unknown protocol, record, path, or
operation profiles are refused rather than interpreted optimistically.
Their shared record identity is exactly `reorg_<lowercase hyphenated UUID>`;
Draft and Plan schemas reference the same definition, and sealing preserves it.

## Analysis scope

The scope separates:

- Core's exact `operation_closure`, derived from every source, destination,
  destination parent, ancestor, and precondition encoded by the ordered
  operations; and
- caller-declared `declared_entries` whose path, presence, identity, or bytes
  informed the proposal beyond that closure.

The active `.folderbase/manifest.json` digest, its exact
`policies.structural_changes` value, the `.folderbaseignore` fact, and every known
nested Folderbase boundary are bound separately. A parent plan cannot declare or
operate on a nested Folderbase or any descendant.

Portable facts use relative slash-separated paths. Files bind lowercase SHA-256 and
byte count; tracked objects bind stable Object ID and immutable Version ID. Files of
every format remain opaque. For example, a 10 GB video is represented by metadata
and may be moved without placing its bytes in a model context.

## Operations

The v1 operation vocabulary is closed:

- `create_directory`
- `create_utf8_file`
- `replace_utf8_file`
- `update_managed_agent_block`
- `move_file`
- `move_tracked_object`
- `mark_canonical`
- `mark_superseded`
- `archive_object`
- `add_relationship`

There is no delete or directory-move operation. Created paths and move destinations
must be absent. Text creation and replacement are bounded; an opaque file move
binds metadata without embedding content. Case-only renames are refused. Paths are
NFC-normalized for collision detection, and the selected path profile additionally
controls Unicode case folding.

Generic create, replace, and move operations cannot enter `.folderbase` or
`.git` or replace adapters or the policy-controlling `.folderbaseignore`.
Protocol 0.5 `FOLDERBASE.md` is fully ordinary and is not a protected marker, so
generic operations may address it under the normal structural-change policy.
Managed adapter updates are limited to the matching root `AGENTS.md` or
`CLAUDE.md`. Their `managed_block` payload is only the marker-free body—not a
whole adapter file and not a pre-wrapped block. Any `<!-- folderbase:` marker
syntax in that body is refused, including obsolete noncanonical wrappers.
Application uses the established `<!-- folderbase:begin -->` and
`<!-- folderbase:end -->` markers to replace or append that block while
preserving all surrounding user-owned text. The four typed Object operations
are the only v1 seam into `.folderbase/objects/<obj_UUID>.json`; they bind the
real `obj_<UUID>` Object ID, `version_<UUID>` base Version ID, and exact record
digest. Relationship types follow the Object Protocol lowercase-token grammar.
The contract does not invent revision counters absent from Object Protocol 0.1.

Templates may be cited as provenance, but are optional guidance. They never become
continuing layout authority. Drafts and Plans contain no grants, roles, approval
state, actor authority, executable hooks, or model prompts. An App or hosted service
must authorize any later transition.

## Bounds

Core reads at most 8 MiB plus one sentinel byte before refusing an encoded record.
Direct in-memory validation, sealing, and digest entry points enforce the same
aggregate encoded limit through bounded streaming serialization before cloning or
canonicalizing a record. Core also bounds questions, operations, scope entries,
paths, and embedded UTF-8.
String and path `maxLength` values count Unicode code points, matching JSON Schema;
the encoded-record cap separately bounds bytes and memory.
That rule includes a Reorganization operation's marker-free `managed_block`.
The older Migration Protocol adapter operation retains its released UTF-8 byte
limit; the two versioned records do not reinterpret one another.
Canonical integer fields are limited to `9007199254740991`, the exact common range
for JSON implementations.

## Canonical digests

Digest input is the validated typed record serialized as compact canonical JSON:

- object keys are sorted lexicographically (all v1 field names are ASCII);
- array order is preserved;
- set-like `nested_boundaries`, `operation_closure`, and `declared_entries` are
  sorted by ascending NFC-normalized path UTF-8 bytes (equivalent to Unicode
  scalar lexicographic order), and `template_references` are sorted by ascending
  stored UTF-8 bytes, while question, option, and operation order remains
  meaningful;
- optional empty fields omitted by the typed contract remain omitted;
- strings use standard JSON escaping and UTF-8;
- booleans and nulls use their JSON spelling; schema-valid decimal or exponent
forms of mathematical integers are parsed from their arbitrary-precision
  lexical spelling, decode exactly, normalize mathematical negative zero to zero,
  and re-encode as shortest base-10 integers;
  and
- floating-point numbers are not part of the contract.

The analysis-scope digest is:

```text
SHA-256(
  UTF-8("folderbase-reorganization-analysis-scope-v1") || 0x00 ||
  canonical_json(analysis_scope)
)
```

The plan digest is:

```text
SHA-256(
  UTF-8("folderbase-reorganization-plan-v1") || 0x00 ||
  canonical_json(plan_without_plan_digest)
)
```

`protocol/conformance/reorganization/plan/valid/project-cleanup-v1.sha256` was
calculated independently with Node.js `crypto` over that contract. Implementations
must match it byte for byte. Re-run the independent implementation with:

```sh
node scripts/verify-reorganization-digest-vector.mjs
```

## Schemas and conformance

- `protocol/schemas/0.3/reorganization-draft.schema.json`
- `protocol/schemas/0.3/reorganization-plan.schema.json`
- `protocol/conformance/reorganization/`

The Plan schema references shared definitions by the absolute `$id` of the Draft
schema, including the exact `reorg_<UUID>` and `folderbase_<UUID>` identity
grammars. Validators should register both public schemas before compiling the
Plan schema. Schema validation checks record shape; Core validation additionally
checks operation closure, question/option uniqueness, path-profile aliases,
reserved paths, nested boundaries, real Core identities, and both digests.

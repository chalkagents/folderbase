# Template Protocol 0.2

Status: Frozen for the folder-to-folderbase vertical slice

Templates are optional, versioned starting guidance. They help initialize or
extend an ordinary folder without turning the resulting folderbase into a permanent
template instance.

## Package contract

A template package is one JSON document with:

- `protocol_version`: compatible Template Protocol 0.2 version
- `id`: stable package lineage
- `version`: semantic package version
- `suggested_folderbase_kind`: initialization recommendation, not authority
- `questions`: data-only prompts an interface may ask, with an optional
  `answer_type` of `text` (the default) or `boolean`
- `artifacts`: directories or text files installed only when absent
- `upgrade_edges`: supported additive transitions to this package version

Package and upgrade versions are valid Semantic Versions. Package IDs use the
lowercase `[a-z0-9][a-z0-9._-]*` form, and names and question prompts contain
non-whitespace text.

Packages may carry `x-` extension fields. The package and every artifact remain
inspectable data. Executable hooks, scripts, commands, permissions, members,
grants, and shares are invalid.

## Artifact safety

Every target is a slash-separated path relative to the destination folderbase.
Absolute paths, drive-prefixed paths, backslashes, empty segments, and `.` or
`..` traversal are invalid. Targets must be unique under full, non-Turkic
Unicode case-folding.

The only installation mode is `create_if_missing`. A client must preview the
result, preserve existing files, and resolve any collision through the user's
structural-change policy. A template never supplies permission to overwrite.
The reference renderer returns absent targets as immutable planned additions
and reports already-present targets separately as `existing_paths`; it performs
no writes. A destination root, artifact target, or existing ancestor that is a
symlink is refused rather than followed.

Text artifact `content` may interpolate declared question answers through the
explicit `${question-id}` form. Substitution is deterministic and
non-recursive: placeholder-like text inside an answer is preserved literally.
Rendering fails when a placeholder is undeclared, an answer is missing or has
the wrong type, or a target is unsafe. Template packages cannot read other
files while rendering.

Starter packages may declare the conventional optional `folderbase_name` question
and use `${folderbase_name}` in `FOLDERBASE.md`. The reference initializer supplies its
resolved manifest display name automatically and rejects a caller-provided
answer that differs, so the human/agent entry and manifest cannot silently
diverge. A caller using the lower-level renderer directly must provide that
answer when rendering an absent artifact that references it. New folderbase display
names are trimmed and must be nonblank, single-line text of at most 120
characters; control characters and Unicode line or paragraph separators are
refused before either manifest or Markdown rendering.

## Provenance, not conformance

Protocol 0.2 folderbases may record:

```json
{
  "folderbase": {
    "template_provenance": {
      "id": "folderbase.project",
      "version": "0.2.0",
      "applied_at": "2026-07-26T00:00:00Z",
      "package_digest": {
        "algorithm": "sha256",
        "digest": "..."
      }
    }
  }
}
```

The field is optional. It records where a folderbase started, not its required
folder layout or current kind. An Organization Skill may later guide an
authorized agent to expand or reorganize the ordinary files. The folderbase remains
valid when its user-defined layout diverges from the package.

The reference initializer records the canonical semantic package digest so a
later same-version package with different guidance fails closed. The digest is
SHA-256 over Canonical Template JSON: the fully validated typed package with
protocol defaults materialized, optional typed fields represented as `null`,
object keys ordered by their UTF-8 bytes, array order preserved, no
insignificant whitespace, JSON strings escaped by the JSON grammar, and JSON
integers written in minimal decimal form. Floating values use Ryu's shortest
round-trippable IEEE-754 representation while retaining `.0` for an integral
floating token. Source whitespace and object-member order therefore do not
change package identity. The authoritative cross-client vector is
`protocol/conformance/template/valid/digest-vector-0.2.0.{json,sha256}`.
Existing 0.2 folderbases whose origin predates package digests remain readable, but
require an explicit provenance migration before template expansion.

## Additive application history

An expansion planner derives its comparison point from the latest verified
Template Application for the target template ID, falling back to immutable
Template Origin. Callers provide only the destination folderbase, target package,
and typed answers; they cannot select an earlier comparison package.

Protocol 0.2 templates express only `create_if_missing` guidance. Existing
targets—including `FOLDERBASE.md`, adapters, and `.folderbaseignore`—are preserved
regardless of whether the target package suggests different bytes. A template
cannot express a policy update, canonical replacement, adapter rewrite,
authorization change, or current folderbase-kind change. A downgrade, different
lineage, or undeclared transition is previewed as structural and cannot use the
additive applier. `suggested_folderbase_kind` remains initialization guidance only.

After every absent target is installed with no-clobber semantics and verified,
the reference applier appends a `state: verified` record under
`.folderbase/template-applications/`. The record conforms to
`protocol/schemas/0.2/template-application.schema.json` and binds:

- a UUIDv7 application ID and the active folderbase ID
- target template ID, version, and canonical semantic package SHA-256
- comparison source, version, and prior application ID when applicable
- typed created paths with text byte counts and content digests
- typed preserved targets
- the canonical approved plan digest, self-verifying record digest, and
  application time

The plan digest contains no absolute destination path or raw answers. It binds
the active manifest digest, history snapshot, comparison, target package,
sorted additions, preserved preconditions, and structural codes. Manifest or
history changes invalidate a stale plan before any write. A crash may leave
safe additions without a record, but never a false verified record; a retry
treats those paths as preserved.

## Upgrade graph

Every edge moves from an earlier semantic version to the package's current
version. Cycles, backward edges, and edges to unsupported intermediate
destinations are invalid. Declaring an edge does not apply it; clients still
need a previewable plan and any approval required by the folderbase.

## Compatibility

Template support does not invalidate Protocol 0.1 folderbases. Clients must retain
the 0.1 schema, keep unknown manifest fields readable, and treat missing
template provenance as normal.

Conformance artifacts live under `protocol/conformance/`; the Rust acceptance
suite is `crates/folderbase-core/tests/template_conformance.rs`.

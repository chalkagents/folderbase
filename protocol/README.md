# Folderbase open protocol artifacts

These artifacts implement the portable, filesystem-native contract described in
[`../docs/protocol-spec.md`](../docs/protocol-spec.md). They are intentionally
independent of the Folderbase application and hosted services.

## Artifact locations

- `schemas/0.1/folderbase.schema.json` validates `.folderbase/manifest.json`.
- `schemas/0.1/object.schema.json` validates records in
  `.folderbase/objects/`.
- `schemas/0.1/workspace.schema.json` validates
  `.folderbase-workspace.json`.
- `schemas/0.1/migration.schema.json` validates migration `plan.json` files.
- `schemas/0.1/change-set.schema.json` validates proposed checkout change sets.
- `schemas/0.2/folderbase.schema.json` adds optional, non-locking template
  provenance while preserving unknown manifest fields.
- `schemas/0.2/template.schema.json` validates transparent Template Protocol
  0.2 packages.
- `schemas/0.3/chunk-manifest.schema.json` validates the canonical,
  provider-neutral `folderbase-chunk-manifest-v1` transfer plan.
- `schemas/0.3/reorganization-{draft,plan}.schema.json` validate the inert,
  closed-profile Reorganization Protocol 0.3 records. The Plan schema references
  definitions in the Draft schema by its public `$id`; register both with a
  validator.
- `schemas/0.4/folderbase-version.schema.json` validates the closed,
  provider-neutral `folderbase-version-v1` bounded full-state artifact.
- `conformance/` contains valid and invalid compatibility fixtures.
- `conformance/chunk-manifest/` fixes the valid and invalid manifest shapes;
  its independently generated `.sha256` sidecars fix cross-client canonical
  binary digests for small and greater-than-32-bit identities.
- `conformance/template/valid/digest-vector-0.2.0.{json,sha256}` fixes the
  cross-client canonical package-digest contract.
- `conformance/reorganization/` covers valid Drafts and Plans, every v1
  operation kind, schema negatives, semantic negatives, and the independently
  calculated canonical Plan digest.
- `conformance/folderbase-version/` fixes valid fidelity/lifecycle state,
  schema and semantic negatives, Unicode collision policy, and independently
  generated canonical-digest sidecars.
- `templates/0.2/project/template.json` is the built-in data-only
  Project package.
- `templates/project/` is the additive starting point for a new Project
  Folderbase.
- `../fixtures/client-company-2-shaped-unmanaged/` is a small synthetic inspection
  fixture.

All schemas use JSON Schema Draft 2020-12. Version 0.1 records require the
documented identifiers, states, policies, and path-safety invariants. Every
object schema deliberately uses `additionalProperties: true`: compatible
clients must preserve fields they do not understand when rewriting a record.

Protocol paths are slash-separated paths relative to their folderbase or workspace
root. Schema validation rejects absolute paths, Windows drive prefixes,
backslashes, empty path segments, and `.` or `..` traversal segments. Runtime
implementations must additionally resolve paths against the root and reject
symlink escapes; JSON Schema cannot safely inspect the filesystem.

Template package targets are additionally unique under case-folding, and
upgrade graphs must be forward-only, acyclic, and terminate at the package
version. Those cross-record rules are covered by the Rust conformance suite.
Templates may create missing directories or text files only; they cannot
execute code, overwrite user files, or declare authority.

Reorganization Drafts and Plans are likewise data only and carry no authority.
Templates are optional provenance, not continuing layout requirements. The v1
operation set contains no deletion, treats large and binary files as opaque
movable bytes, and refuses paths at or below nested Folderbase boundaries. See
[`../docs/reorganization-protocol.md`](../docs/reorganization-protocol.md).
Question answers are typed as text or boolean. Dynamic text uses only explicit,
non-recursive `${question-id}` substitutions; renderers never evaluate code or
read other package-relative or filesystem paths.

Chunk Manifest v1 intentionally rejects unknown fields. Semantic conformance
also validates ordered, contiguous descriptors, exact object length, profile
bounds, the 1 TiB lossless JSON-integer ceiling, and empty-object identity
because JSON Schema cannot compare all of those values across array entries.

Folderbase Version v1 also rejects unknown fields. It preserves exact UTF-8 path
spellings while rejecting exact, NFC, and full-default-case-fold collisions.
Regular files are opaque bytes with executable fidelity, symlinks are recorded
without being followed, empty directories are explicit, Tombstones retain
deletions, and hard links or special nodes are typed exclusions rather than silent
loss. `.folderbase/manifest.json` is represented only by the reserved
`root_manifest` Object Version reference; every ordinary `.folderbase/**` binding
is rejected. `FOLDERBASE.md` and root `.folderbaseignore` remain ordinary visible
bindings.

The full-state artifact is an independent restore contract, not a scoped share
projection, authorization record, hosted-presence receipt, or chunk transfer plan.
A separate future projection artifact must contain only the paths authorized for
one Folder Scope.

`FOLDERBASE.md` and `.folderbaseignore` are both required live regular-file
bindings in every restorable Folderbase Version. The source repository/tag is the
normative cross-language protocol bundle. The `folderbase-core` crate is the Rust
runtime implementation and intentionally does not duplicate workspace-level
schemas, fixtures, or the independent reference encoder. The closed released
manifest is `releases/0.4/folderbase-version-v1.json`; CI verifies its `released`
status and exact declared surface before testing Cargo packages. The verifier also
rejects a remaining candidate manifest, so a tag cannot publish an ambiguous
protocol surface.

## Using the Project template

Copy the contents of `templates/project/` into a folder through an
approved initialization plan. Before installing the manifest, replace every
`${...}` token in `.folderbase/manifest.template.json`, then save the result as
`.folderbase/manifest.json`. Generate a new Folderbase ID for every initialized
folder; never ship the literal placeholder as an identity.

`AGENTS.md` and `CLAUDE.md` contain only the managed bootstrap block described
by the protocol. If either file already exists, initialization must preserve
it and propose insertion of the block instead of overwriting the file.

## Fixture safety

The Client Company 2-shaped fixture is not copied from the live Client Company 2 workspace. It uses
invented names and tiny text payloads, contains no credentials, customer
records, source code, media, contracts, or confidential content, and is safe to
commit. Secret-shaped content is labeled fake in both its filename-adjacent
content and the fixture README.

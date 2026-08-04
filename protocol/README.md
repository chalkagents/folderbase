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
- `schemas/0.1/change-set.schema.json` is the unchanged legacy Change Set
  prototype; it is not the optional Change Set capability.
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
- `schemas/0.5/folderbase.schema.json` validates the native protocol 0.5 root
  manifest, including the closed embedded capture-ignore policy.
- `schemas/0.5/folderbase-version.schema.json` validates the protocol 0.5
  profile of the same closed, provider-neutral Version v1 envelope.
- `schemas/capabilities/change-set/0.1/change-set.schema.json` defines the
  unadvertised scoped checkout and immutable Change Set 0.1 capability.
- `conformance/` contains valid and invalid compatibility fixtures.
- `compatibility/v1/contract.json` is the machine-readable stable Core
  compatibility inventory.
- `schemas/cli/1/folderbase-cli-json.schema.json` defines the stable CLI JSON
  result and error documents.
- `conformance/cli-json-v1/run.mjs` runs the complete black-box contract against
  any compatible executable without loading Rust.
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
  generated canonical-digest sidecars for the immutable protocol 0.4 release.
- `conformance/folderbase-version-0.5/` is the separate protocol 0.5 corpus. It
  fixes markerless and optional-root-file Version states, strict root-manifest
  capture policy, invalid delta cases, canonical Version digests, and exact
  root-manifest byte digests.
- `conformance/capabilities/change-set-0.1/` is the independently runnable RED
  suite for scoped projections, opaque staged bytes, three-way assessment,
  atomic apply, crash recovery, and replay.
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

Folderbase Version v1 rejects unknown fields. It preserves exact UTF-8 path
spellings while rejecting exact, NFC, and full-default-case-fold collisions.
Regular files are opaque bytes with executable fidelity, symlinks are recorded
without being followed, empty directories are explicit, Tombstones retain
deletions, and hard links or special nodes are typed exclusions rather than silent
loss. `.folderbase/manifest.json` is represented only by the reserved
`root_manifest` Object Version reference; every ordinary `.folderbase/**` binding
is rejected. Root `FOLDERBASE.md` is fully ordinary when present.
`.folderbaseignore` is an optional user-owned policy input in 0.5 and is
force-captured as a visible binding when present.

The full-state artifact is an independent restore contract, not a scoped share
projection, authorization record, hosted-presence receipt, or chunk transfer
plan. The separately versioned Change Set capability defines a projection
artifact containing only the paths authorized for one Folder Scope; that
artifact never reinterprets the full-state Version.

The required root-file bindings are profile-specific. Protocol 0.4 requires
`FOLDERBASE.md` and `.folderbaseignore` as live regular-file bindings. Protocol
0.5 changes that requirement: either file may be absent. `FOLDERBASE.md` is
fully ordinary. `.folderbaseignore` remains bounded, policy-controlling,
force-captured, and changed only through typed policy-aware flows. A native 0.5
Version may therefore have zero bindings. The Version format and canonical
binary encoding remain v1; the literal `protocol_version` (`0.4` or `0.5`)
enters that encoding and keeps the digest namespaces distinct.

Optional `.folderbase/summary.md` and `.folderbase/questions.jsonl` are the
named non-authoritative hint formats. They do not establish a boundary, grant
mutation or sharing authority, or enter ordinary Version bindings under the
`.folderbase/**` self-capture ban. Other `.folderbase/**` content remains
private and inert without becoming a named hint format. Parent traversal treats
any exact regular, no-follow nested manifest marker as an opaque boundary and
does not decode it through the parent. Markerless state/context is inert.
ASCII-case aliases and symlink or wrong-type state/manifest markers are unsafe
shapes, not authority. Analysis may quarantine them as `Unchecked`
(`unchecked` on the wire) and omit descendants; materializing, mutating,
transfer, and restore seams reject them.

The source repository/tag is the normative cross-language protocol bundle. The
`folderbase-core` crate is the Rust runtime implementation and intentionally
does not duplicate workspace-level schemas, fixtures, or independent reference
encoders. The immutable released 0.4 manifest remains
`releases/0.4/folderbase-version-v1.json`. The separately hashed released 0.5
inventory is `releases/0.5/folderbase-version-v1.json`. That inventory binds the
released schemas, fixtures, independent digest encoders, implementing Rust
sources, Rust conformance test, package metadata, package proof scripts, and CI
gates as one exact source surface. The verifier deterministically walks both
complete Rust crate trees and seals their sources, embedded assets, tests,
manifests, and legal files together with the workspace `Cargo.toml` and
`Cargo.lock`. A new unsealed runtime or package input therefore fails the exact
closure gate. The extracted-package proof compares every packaged Rust source
and embedded asset with the sealed checkout bytes. The Rust conformance test
decodes both valid 0.5 Version vectors and compares each runtime digest with its
independently generated `.sha256` sidecar. The release manifest is not a member
of its own inventory; its external `.sha256` sidecar remains the non-circular
root proof. The 0.5 release verifier does not reinterpret or mutate any 0.4
release or conformance bytes. The
accepted profile decision is
`../docs/adr/0006-version-ordinary-folder-roots-and-optional-narratives.md`.

## Using the Project template

`templates/project/` is explicit additive template input, not the native 0.5
default. Native 0.5 initialization creates only `.folderbase/manifest.json`
unless the user selects additional template artifacts or adapters. A selected
template is applied through an approved initialization plan. Before installing
its manifest, replace every `${...}` token in
`.folderbase/manifest.template.json`, then save the result as
`.folderbase/manifest.json`. Generate a new Folderbase ID for every initialized
folder; never ship the literal placeholder as an identity.

Root `FOLDERBASE.md` remains fully ordinary optional content, while an optional
user-owned `.folderbaseignore` remains typed capture-policy input. `AGENTS.md`
and `CLAUDE.md` adapters are opt-in. If an adapter is requested and its file
already exists, initialization must preserve it and propose insertion of the
managed block instead of overwriting the file.

## Fixture safety

The Client Company 2-shaped fixture is not copied from the live Client Company 2 workspace. It uses
invented names and tiny text payloads, contains no credentials, customer
records, source code, media, contracts, or confidential content, and is safe to
commit. Secret-shaped content is labeled fake in both its filename-adjacent
content and the fixture README.

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
- `conformance/` contains valid and invalid compatibility fixtures.
- `conformance/template/valid/digest-vector-0.2.0.{json,sha256}` fixes the
  cross-client canonical package-digest contract.
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
Question answers are typed as text or boolean. Dynamic text uses only explicit,
non-recursive `${question-id}` substitutions; renderers never evaluate code or
read other package-relative or filesystem paths.

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

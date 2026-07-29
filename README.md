# Folderbase

**A folder-based database for agents.**

Folderbase turns an ordinary folder into a structured, versioned workspace that
humans and agents can understand and operate across sessions. Files remain
normal files. A small `.folderbase/` directory adds the durable identity,
protocol records, history, and policy needed to treat the folder as a database.

Folderbase is the open database core beneath
[Folderbase Cloud](https://folderbase.ai), in the same way that PostgreSQL is
the open database beneath managed platforms. The core works locally and does
not require a Folderbase account.

## Design principles

- **Folders stay folders.** Existing repositories, documents, media, PDFs,
  databases, and other file types keep their ordinary paths and native tools.
- **Agents are first-class users.** `FOLDERBASE.md`, `AGENTS.md`, and
  `CLAUDE.md` provide direct local entry points without requiring an MCP server.
- **Structure is guidance, not a cage.** Templates initialize useful structure
  and can expand over time. Reorganization is explicit, previewable, and
  reversible.
- **Local work is complete work.** Keep-local workspaces remain fully usable
  offline. Cloud availability never silently evicts active files.
- **Sharing is explicit authority.** Folder scopes can be granted to humans or
  agent sessions; nesting and relationships never imply access.
- **Changes preserve evidence.** Local versions, resumable content transfer,
  conflict preservation, and migration rollback protect ongoing work.

## What is included

- `folderbase-core`: Rust library for inspection, initialization, validation,
  templates, migration, local versions, workspace operations, sharing policy,
  canonical bounded-memory transfer planning/source streaming, canonical
  Folderbase Version validation/digests, and sync primitives
- `folderbase`: reference command-line interface
- versioned JSON Schemas and conformance fixtures
- built-in person, organization, customer, engagement, project, temporary, and
  custom templates
- an unmanaged, mixed-file project fixture used for end-to-end migration tests

The commercial desktop app, managed sync service, web workspace, and cloud
agent runtime live in the separate Folderbase Platform repository.

## Install

Folderbase currently requires Rust 1.96 or newer.

```sh
cargo install --path crates/folderbase-cli --locked
folderbase --version
```

Once the first crates.io release is published:

```sh
cargo install folderbase-cli --locked
```

## Turn a folder into a Folderbase

Inspect first. Inspection reads metadata and boundaries without changing the
folder:

```sh
folderbase inspect /path/to/project --json
```

Preview the additive initialization:

```sh
folderbase init /path/to/project --dry-run --json
```

The JSON plan includes a stable Core-owned `plan_digest`. To bind approval to
the exact reviewed request, template, protocol writes, boundaries, and visible
destination state, apply with that digest:

```sh
folderbase init /path/to/project \
  --expected-plan-digest DIGEST_FROM_DRY_RUN \
  --json
folderbase validate /path/to/project --json
```

The CLI asks Core for one plan. Apply carries the opaque digest from that plan;
Core compares it and performs a bounded, metadata-only preflight immediately
before its first write. The digest includes the physical filesystem identity of
the reviewed root, so replacing a folder with a same-path, same-shape folder in
another process is stale. New paths, kind changes, boundary changes, or planned
target collisions also return a typed stale-plan error with no protocol writes.
Content edits to ordinary preserved files do not create approval churn because
Core never writes those files. `folderbase init /path/to/project` remains
available for direct, single-step initialization.

This is optimistic concurrency, not atomic filesystem isolation. A race after
preflight is contained by root-capability traversal, no-follow parent opens,
and per-write no-clobber installation; competing bytes are preserved and the
operation fails rather than overwriting them.

Initialization leaves the original files in place and adds the Folderbase
protocol surface:

```text
project/
├── .folderbase/
│   └── manifest.json
├── .folderbaseignore
├── FOLDERBASE.md
└── …your existing files
```

For a disorganized or multi-boundary folder, use the migration workflow. It
analyzes the folder, asks bounded questions, produces a reviewable plan, and
does not apply it unless explicitly approved:

```sh
folderbase migrate /path/to/project --destination Organized
```

## Work with files

The workspace interface lists ordinary files while keeping protocol state,
repository internals, and reconstructable dependency trees out of agent
context:

```sh
folderbase workspace list /path/to/project --json
folderbase workspace read /path/to/project FOLDERBASE.md --json
```

Text saves use an expected SHA-256 so stale agent sessions cannot silently
overwrite newer work:

```sh
printf '%s' "$UPDATED_TEXT" | folderbase workspace save \
  /path/to/project FOLDERBASE.md \
  --expected-sha256 "$LOADED_SHA256" \
  --stdin \
  --json
```

Binary and very large files remain part of the workspace. Agents can inspect
their metadata first; transformations operate with streaming and
content-addressed chunks rather than loading entire files into model context.
Core opens a transfer source by immutable `VersionId`, never by the mutable
workspace path. The source binds a canonical manifest to that exact
content-addressed blob and emits a verification receipt only after an exact
chunk range has been streamed and checked.

## Protocol

- [Domain language](CONTEXT.md)
- [Protocol specification](docs/protocol-spec.md)
- [Template protocol](docs/template-protocol.md)
- [Reorganization Protocol 0.3](docs/reorganization-protocol.md)
- [Proposed Reorganization Plan decision](docs/adr/0002-evolve-existing-folderbases-through-reorganization-plans.md)
- [Schemas, templates, and conformance vectors](protocol/README.md)
- [Accepted canonical streaming-transfer decision](docs/adr/0001-stream-immutable-versions-through-canonical-manifests.md)
- [Proposed bounded full-state Folderbase Version decision](docs/adr/0004-seal-portable-folderbase-versions-as-bounded-full-state.md)

Protocol `0.x` and crate `0.x` releases are pre-stable. Wire and filesystem
contracts may change between minor versions until 1.0.

## Development

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features --locked
bash scripts/check-public-eclipse.sh
bash scripts/test-package-install.sh
```

See [CONTRIBUTING.md](CONTRIBUTING.md) and
[SECURITY.md](SECURITY.md) before submitting changes or reporting a
vulnerability.

## License

Licensed under the [Apache License 2.0](LICENSE).

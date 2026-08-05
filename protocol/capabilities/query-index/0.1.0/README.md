# Folderbase query/index capability 0.1.0

This package is a separately advertised optional capability. It does not add a
command to Compatibility Contract v1 or a definition to Folderbase CLI JSON v1.

Product maturity: **Unstable Beta**. The machine-readable registry continues to
use the protocol value `"stability": "experimental"`. Integrators must discover
and pin this exact capability version. Query/index is a metadata-only inventory
and filtering surface; it does not search file contents and is not required for
sync, Cloud storage, sharing, or ordinary workspace access.

The package entry in `capability.json` is deliberately the same closed shape
accepted by the optional-capability registry introduced by ADR-0010. The
post-0.5 reference CLI copies that exact entry into its registry only after
passing the complete suite. The immutable 0.5 executable correctly does not
advertise this later capability.

Normative surfaces:

- query/index decision: `docs/adr/0011-query-folderbases-through-rebuildable-private-indexes.md`;
- public JSON Schema: `protocol/schemas/capabilities/query-index/0.1/query-index.schema.json`;
- request digest vectors and mixed-file fixtures:
  `protocol/conformance/capabilities/query-index-0.1/`; and
- independent runner: `protocol/conformance/capabilities/query-index-0.1/run.mjs`.

The process contract has one physical delivery carve-out: when a host output
stream is unavailable, implementations exit 2 and report best-effort without
panicking, but cannot guarantee a typed document on that unusable stream.

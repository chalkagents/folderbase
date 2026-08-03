# Folderbase query/index capability 0.1.0

This package is a separately advertised optional capability. It does not add a
command to Compatibility Contract v1 or a definition to Folderbase CLI JSON v1.

The package entry in `capability.json` is deliberately the same closed shape
accepted by the optional-capability registry introduced by ADR-0010. A registry
may copy that entry once an implementation advertises and passes the complete
suite. Until then the released 0.5 executable correctly does not advertise it.

Normative surfaces:

- query/index decision: `docs/adr/0011-query-folderbases-through-rebuildable-private-indexes.md`;
- public JSON Schema: `protocol/schemas/capabilities/query-index/0.1/query-index.schema.json`;
- request digest vectors and mixed-file fixtures:
  `protocol/conformance/capabilities/query-index-0.1/`; and
- independent runner: `protocol/conformance/capabilities/query-index-0.1/run.mjs`.

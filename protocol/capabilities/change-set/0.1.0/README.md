# Folderbase Change Set capability 0.1.0

This is the unadvertised contract package for
`folderbase.change-set@0.1.0`. It owns least-authority checkout projection,
immutable before/after proposals, three-way assessment, and atomic publication
as one optional capability.

The package is marked stable because an implementation that eventually
advertises it promises the exact 0.1 process and record contract. Its presence
in this source tree is not an advertisement. Do not add it to either capability
registry until the candidate executable passes the complete public suite.

Normative surfaces:

- [ADR-0012](../../../../docs/adr/0012-materialize-scoped-projections-and-merge-immutable-change-sets.md);
- [public JSON Schema](../../../schemas/capabilities/change-set/0.1/change-set.schema.json);
- [RED fixture suite](../../../conformance/capabilities/change-set-0.1/); and
- [independent runner](../../../conformance/capabilities/change-set-0.1/run.mjs).

The unrelated `protocol/schemas/0.1/change-set.schema.json` is a legacy
prototype. It is not a prior version of this capability and remains unchanged.

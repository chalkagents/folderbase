# Folderbase template-expansion capability 0.1.0

This optional capability stabilizes only two bounded, machine-readable
operations:

```text
folderbase template plan ROOT --stdin --json
folderbase template apply ROOT --expected-plan-digest SHA256 --stdin --json
```

Standard input is one `folderbase-template-expansion-request-v1` document. It
contains one exact data-only Template Protocol 0.2 package and the typed answers
needed to render it. The package is never located through an ambient registry.

Planning is read-only. Applying acquires the Folderbase shared transaction
lease, re-plans against the retained root capability, compares the new digest
with the approved digest, and only then installs absent paths with no-clobber
semantics. Existing paths are preserved. Replaying an applied package is a
no-op. Downgrades, lineage changes, and undeclared transitions are returned as
`reorganization_required`; this capability never performs them.

Built-in catalogs, latest-version selection, interactive prompting, and
`init --template` are implementation conveniences. They are not part of this
compatibility profile.

The public schema is
`protocol/schemas/capabilities/template-expansion/0.1/template-expansion.schema.json`.
The independent black-box suite is
`protocol/conformance/capabilities/template-expansion-0.1/run.mjs`.

Implementations must not advertise this capability until that suite passes in
full.

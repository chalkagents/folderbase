# Folderbase folder-scope-evidence capability 0.1.0

This stable optional capability asks exact Core to produce bounded, durable
device-local continuity evidence for one selected ordinary folder:

```text
folderbase folder-scope observe ROOT SELECTED_PATH --json
```

`ROOT` is an explicitly supplied, attested Folderbase Root. `SELECTED_PATH` is
a safe root-relative ordinary directory. Success contains no absolute path,
Cloud credential, permission grant, observer capability, file contents, or
unrelated object metadata. The opaque binding proof is continuity evidence; it
is not a Folder Scope ID or authorization credential.

The operation uses Core's exact metadata inventory, current Local Head, held
physical identities, a Core-generated non-reusable private binding nonce, exact
nested-root attestations, and a bounded private journal. Repeated observations
are idempotent. A proven rename preserves the opaque binding proof. Root,
selected-folder, or nested-root replacement, stale Local Head, nested
Folderbase boundary changes, unsafe symlinks, unsupported nodes, and journal
tampering fail closed without changing ordinary workspace files.

This one-shot process command is the universal mutation seam. Capability
discovery is available through `folderbase protocol contract --json`. Daemon
0.1 remains a query/hint session and does not proxy this private-journal
mutation.

Normative surfaces:

- [ADR-0018](../../../../docs/adr/0018-journal-exact-folder-scope-evidence-under-core-authority.md);
- [public JSON Schema](../../../schemas/capabilities/folder-scope-evidence/0.1/folder-scope-evidence.schema.json); and
- [independent runner](../../../conformance/capabilities/folder-scope-evidence-0.1/run.mjs).

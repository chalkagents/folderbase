# Folderbase protocol 0.5 conformance

This tree is independent from the frozen protocol 0.4 conformance distribution.
It contains two related fixture groups:

- `valid/` and `invalid/` exercise the `folderbase-version-v1` envelope against
  `protocol/schemas/0.5/folderbase-version.schema.json`.
- `root-manifest/valid/` and `root-manifest/invalid/` exercise native 0.5 root
  manifests against `protocol/schemas/0.5/folderbase.schema.json`.

Protocol 0.5 keeps the Version v1 structural envelope and digest algorithm.
The literal `protocol_version` value changes to `0.5` and is still encoded into
the canonical digest, so a 0.4 envelope and a 0.5 envelope cannot have the same
digest merely because the remaining fields match.

Unlike protocol 0.4, a protocol 0.5 Version may have zero bindings. Root
`FOLDERBASE.md` is a fully ordinary optional binding. Root
`.folderbaseignore` is optional and user-owned, but remains bounded,
policy-controlling, force-captured, and changed through typed policy-aware
flows. Files below `.folderbase/**`, including the named optional
`.folderbase/summary.md` and `.folderbase/questions.jsonl` hints, remain outside
ordinary Version bindings. Those hints do not establish a Folderbase boundary
or grant mutation, sharing, or checkout authority. Other `.folderbase/**`
content remains private and inert without becoming a named hint format.

Each valid Version fixture has a `.sha256` sidecar containing its canonical
Folderbase Version digest, as produced by `reference-digest.mjs`. Each valid
root-manifest fixture has a `.sha256` sidecar containing the SHA-256 digest of
its exact bytes. The separately inventoried released distribution verifies
both kinds.

The root-manifest negatives cover an unsupported live protocol; missing and
invalid Folderbase description and policy fields; malformed adapters; unsafe
dot, NUL, drive, traversal, `.folderbase`, and `.git` adapter targets (including
case aliases); missing or unknown capture-policy members; wrong format and rule
types; empty and NUL rules; and a runtime-only UTF-8 byte overflow. The overflow
is exactly 4,096 Unicode characters but 8,192 UTF-8 bytes: it satisfies JSON
Schema's character count and is intentionally rejected by the runtime byte
bound.

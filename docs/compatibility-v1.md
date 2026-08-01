# Folderbase Compatibility Contract v1

This document is the human-readable contract implemented by
[`../protocol/compatibility/v1/contract.json`](../protocol/compatibility/v1/contract.json).
The machine-readable file owns inventories and exact names; this document owns
their compatibility meaning.

## Stability promise

An implementation claiming Compatibility Contract v1 must:

1. preserve ordinary workspace files and every byte of a portable record it
   does not intentionally replace through a supported operation;
2. accept every valid and reject every invalid public conformance fixture;
3. produce the published canonical digest for every fixture with a sidecar;
4. implement the stable Folderbase CLI JSON v1 commands; and
5. pass the public black-box conformance runner.

A contract-compatible release may add optional object fields, new commands,
new error codes, and new separately named protocol profiles. It may not remove
or rename required v1 fields, change their types or meanings, reuse an
identifier for another entity, reinterpret an existing profile, or change the
meaning of exit status `0`, `1`, or `2`.

## `.folderbase` record classes

### Portable and normative

- `.folderbase/manifest.json`
- `.folderbase/versions/folderbase/*.json`
- their referenced content identities and canonical digests

These records are independently implementable. Native root manifests use exact
profile `0.5.0`. Folderbase Version v1 supports exact profiles `0.4` and `0.5`.
Chunk manifests use exact format `folderbase-chunk-manifest-v1`.

### Extension-preserving

Object, template, template-application, and reorganization records are public
data formats but are not required for the minimal v1 implementation claim.
Implementations that rewrite them must preserve fields they do not understand
where the applicable schema permits extensions.

### Engine-owned durable state

Transactions, local journals, locks, restore receipts, history-transfer state,
migrations, and local object-version storage are implementation records. The
machine contract lists the paths Core currently writes. Every unclassified
record below `.folderbase/` is engine-owned by default, so a future Core record
cannot accidentally become a portable compatibility promise. Another
implementation must not guess at or partially mutate engine-owned state. It
must preserve it and refuse takeover when it represents nonterminal work. The
writer must provide upgrade recovery for its own durable state. A specifically
listed engine-owned path takes precedence over a broader extension-preserving
pattern.

### Rebuildable projections and optional hints

Indexes may be rebuilt from normative records. `.folderbase/summary.md` and
`.folderbase/questions.jsonl` are optional, non-authoritative hints. Neither
grants access, establishes a nested boundary, or replaces the root manifest.

## Identifiers

- Folderbase: `folderbase_<canonical-lowercase-uuid>`
- Knowledge Object: `obj_<canonical-lowercase-uuid>`
- Object Version: `version_<canonical-lowercase-uuid>`
- Folderbase Version: `fbversion_<canonical-lowercase-uuid>`

Identifiers are opaque and durable. They survive path moves and device or
Cloud transport. UUID payloads do not imply ordering, recency, permission, or
authenticity. Canonical SHA-256 digests are separate content identities and are
never interchangeable with Version IDs.

## Upgrade behavior

Core supports explicit legacy root-manifest `0.1`/`0.2` to native `0.5.0`
upgrade. The upgrade preserves the Folderbase ID, ordinary bytes, and unknown
non-reserved manifest extensions. Apply requires the exact reviewed plan digest
and refuses changed preconditions or nonterminal work. Repeating a completed
upgrade is safe. Automatic upgrades and downgrades are not supported.

## CLI and conformance

The stable process contract is documented in
[`cli-json-v1.md`](cli-json-v1.md). Discover it from a binary:

```sh
folderbase protocol contract --json
```

Run the implementation-neutral suite from a source release:

```sh
node protocol/conformance/cli-json-v1/run.mjs \
  --implementation /path/to/folderbase
```

The runner exercises 96 portable protocol fixtures and 10 process/filesystem
behaviors. A successful report has `failed: 0` and exits `0`.

Every CLI document is checked against the public JSON Schema. The behavior
assertions also verify the required semantics while tolerating additive fields,
as the v1 evolution rules require.

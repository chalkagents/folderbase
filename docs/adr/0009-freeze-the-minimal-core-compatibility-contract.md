# ADR-0009: Freeze the minimal Core compatibility contract

## Status

Accepted

## Context

Folderbase Core is intended to be the open database beneath Folderbase App and
Cloud. That claim is useful only if an independent implementation can read the
same folders, preserve the same durable identities, validate the same portable
records, and integrate through a stable process interface.

The repository already contained strong schemas, fixtures, bounded decoders,
and canonical digest vectors. It did not say which `.folderbase/**` records
were portable, which command JSON shapes were stable, or how a non-Rust team
could prove compatibility. Treating every pre-1.0 feature as stable would freeze
too much unfinished surface. Treating every 0.x artifact as breakable would
make Core unsuitable as shared infrastructure.

## Decision

Folderbase publishes **Compatibility Contract v1** independently of the Cargo
package major version. The contract freezes only the deliberately small public
surface in [`../compatibility-v1.md`](../compatibility-v1.md) and
[`../../protocol/compatibility/v1/contract.json`](../../protocol/compatibility/v1/contract.json).

Portable records are:

- `.folderbase/manifest.json` under exact native profile `0.5.0`;
- Folderbase Version v1 records under profiles `0.4` and `0.5`; and
- Chunk Manifest `folderbase-chunk-manifest-v1` records and canonical digests.

Stable identifiers are opaque durable strings in their documented namespaces.
Consumers may compare and persist them but must not infer time, ordering, or
authority from UUID payloads.

Engine-owned transactions, local journals, locks, recovery receipts, and local
indexes are not cross-implementation layouts. An implementation must preserve
unknown engine-owned state and refuse unsafe takeover while work is nonterminal.
The implementation that wrote durable recovery state remains responsible for
recovering or retiring it during an upgrade.

Folderbase CLI JSON v1 is the universal process integration seam. It keeps the
existing command-specific result objects rather than wrapping every result:
callers already know which command they invoked, and the flat attestation
receipt is an intentionally minimal public artifact. Required fields and their
types are stable; additive object fields are compatible. Operational errors use
one closed error envelope. `folderbase protocol contract --json` provides
runtime discovery.

The public conformance runner invokes only a candidate executable, its standard
streams, and ordinary filesystem effects. It does not load Rust or use the Rust
implementation as an oracle. A Go or TypeScript implementation can therefore
run the same suite.

Protocol profile support is explicit, not inferred from SemVer. A client must
not assume that a record marked `0.5.1` is accepted merely because it supports
`0.5.0`. A compatible release may advertise a separately named profile, but it
must not reinterpret an existing profile or imply support from SemVer alone.

Root upgrades are never silent. Supported upgrades use a read-only plan, a
reviewed digest, stale-state revalidation, and explicit apply. Downgrades are
unsupported.

## Consequences

- Cargo releases may remain below 1.0 while Compatibility Contract v1 stays
  stable.
- Breaking a v1 portable record, identifier rule, required CLI field, exit
  meaning, or conformance expectation requires a new compatibility contract.
- Experimental migration, transformation, template, reorganization, sharing,
  sync, Cloud, and Cloud Agent surfaces can continue to evolve.
- Release publication must run the public suite against the exact binary before
  publishing GitHub assets, npm, crates.io, or Homebrew metadata.
- A common top-level JSON envelope is deferred. It may be introduced only as an
  explicitly selected later interface rather than silently changing v1.

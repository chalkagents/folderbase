# ADR-0011: Query Folderbases through rebuildable private indexes

## Status

Accepted

## Context

Folderbase must behave like a database without replacing ordinary folders with
an engine-owned store. Core already has one bounded, metadata-only live
observation: `FolderbaseVersionStore::plan_capture()`. It also has immutable
Folderbase Versions for exact historical state. Building query on `workspace
list`, or adding a third filesystem scanner, would create conflicting ignore,
nested-boundary, file-reading, and race semantics.

Query is post-0.5 work. It must not expand Compatibility Contract v1, CLI JSON
v1, or the immutable 0.5 release closure merely by existing in the repository.

## Decision

### Capability boundary

Query and its private index are the separately advertised experimental
capability `folderbase.query-index@0.1.0`. Its schemas and independent
black-box runner are under `protocol/schemas/capabilities/query-index/0.1/`
and `protocol/conformance/capabilities/query-index-0.1/`. Implementations that
advertise only Compatibility Contract v1 remain conformant without it. A
candidate must not advertise this capability until its complete runner passes.

### Exact observation scopes

`live` scope is exactly the existing `CapturePlan` observation set: entries,
typed exclusions, ignored paths, root attestation, effective ignore-policy
digest, and optional Local Head observed by `plan_capture()`. Query does not
invoke `workspace list` and does not walk the root through another scanner.
All ordinary formats are opaque. Markdown, repositories, PDFs, CSV, SQLite,
office files, videos, sparse 10 GiB files, and unknown formats are distinguished
only by filesystem kind and metadata; query never opens or hashes their bytes.

`historical` scope is exactly one verified immutable Folderbase Version named
by `folderbase_version_id`. It is not a range, a moving Head, or an implicit
"latest" lookup. Bindings produce `live` rows and Tombstones produce `deleted`
rows. The first capability version exposes only those two lifecycle values.

A live result may carry an Object ID or Object Version ID only when the
optional verified Local Head proves the same portable path and compatible kind.
Otherwise those fields are `null`. An historical result takes identity only
from the selected Version. Query never guesses identity from path, inode, file
ID, extension, content sniffing, or a stale index.

Nested Folderbases are one opaque `nested_folderbase` boundary row with no
object identity or byte count. Parent query never decodes the nested manifest
and never emits a descendant. Ignored paths and unsupported nodes are
explainable exclusions, not silently reintroduced rows.

### Filters and deterministic ordering

The bounded v1 request supports exact portable paths, component-aware path
prefixes, filesystem kinds, byte range, `live`/`deleted` lifecycle, Object IDs,
and Object Version IDs. Different filter families intersect with AND. Repeated
values inside one family combine with OR. A prefix `data` matches `data` and
`data/report.csv`, never `database.md`. Relationship and semantic-lifecycle
filters are deferred until their authoritative Object-record projection is
separately accepted; extensions must not infer them from filenames or prose.

Rows use ascending raw UTF-8 portable-path byte order. Because Folderbase
Version portability already rejects exact, NFC, and case-fold collisions, this
is stable without normalizing the displayed spelling. Exclusions use the same
ordering. Page limits are bounded. Pages of size 1, 2, or N must concatenate to
the same ordered logical result without skips or duplicates.

The normalized request fills every filter family, deduplicates and byte-sorts
set values, normalizes absent byte bounds to `null`, and omits the cursor. Its
domain-separated SHA-256 is `folderbase-query-request-v1\0` followed by the
canonical compact JSON bytes. Public vectors fix this digest across languages.

### Snapshot-safe cursors

Cursors are opaque values. Their implementation-private payload binds the exact
Folderbase Root identity, normalized request digest, observation generation,
and final portable-path sort key. It may additionally authenticate that
binding. Callers may persist and round-trip a cursor but cannot inspect it for
authority or ordering.

The live observation generation binds root instance, manifest and effective
ignore policy, optional Local Head, and the complete capture-plan metadata
observation. The historical generation binds the exact root, Version ID, and
verified Version digest. If a live workspace changes after a page, continuation
returns the typed, retryable attention `query_snapshot_changed`; it never mixes
rows from two generations. The caller restarts without a cursor. An immutable
historical Version cannot legitimately change; missing or invalid bytes are an
operational error.

### Disposable index

Ordinary files and portable records remain authoritative. A missing or stale
index falls back to the same bounded in-memory projection of the selected
observation scope. Query, explain, and index status are read-only. Only explicit
`index rebuild` may replace the engine-owned namespace
`.folderbase/local/query-index-v1/**`. It uses the exact same observation and
normalization rules, publishes no portable record, never writes an ordinary
path, and never touches another `.folderbase/local/**` namespace.

Index generations bind root identity, manifest and ignore policy, Local Head,
and observation generation. Index bytes are bounded, private, disposable, and
excluded from capture. Deleting them changes performance only. A rebuild is a
derived-state transaction, not Folderbase history and not permission or share
authority.

### Process surface

The capability freezes these machine-readable invocations:

- `folderbase query run ROOT --json`, with one query request on standard input;
- `folderbase query explain ROOT --json`, with the same request shape;
- `folderbase index status ROOT --json`; and
- `folderbase index rebuild ROOT --json`.

Successful commands exit 0 with one JSON document on stdout and empty stderr.
`query_snapshot_changed` exits 1 with the capability attention document.
Invocation and operational failures exit 2 with empty stdout and one typed
capability error on stderr. These are optional-capability JSON documents, not
new definitions or commands in Folderbase CLI JSON v1.

Query never grants access, evaluates share policy, or crosses the authority of
the root opened by the caller. It never mutates ordinary files or portable
records. Cloud query, SQL, embeddings, relationships, semantic lifecycle,
content extraction, and content search are outside this decision.

## Consequences

- Core has one live traversal and one nested-boundary policy instead of three.
- Large and binary assets are useful to agents immediately through metadata
  without becoming content-loading hazards.
- Pagination fails clearly on live change instead of returning a plausible but
  internally inconsistent result.
- The App, remote agents, Go implementations, and TypeScript implementations
  can share an independently testable process contract.
- Query may be slower with no index; correctness and adoption do not depend on
  private derived state.
- Relationship queries require a later ADR and capability revision rather than
  a compatible-looking but unauthoritative guess.

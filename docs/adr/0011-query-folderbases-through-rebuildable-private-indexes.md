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

The root `.folderbaseignore` file is optional in protocol 0.5. Its effective
policy digest distinguishes absent from present-empty bytes, applies manifest
engine rules first, and then applies user lines in order. Public vectors cover
escaped leading `!`/`#`, classes and ranges, trailing and escaped spaces,
anchored and unanchored patterns, `**`, directory-only rules, negation,
last-match-wins, and the rule that an ignored parent is pruned before a child
can be re-included.

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

Every request path uses the complete `folderbase-portable-path-v1` policy: no
absolute or drive-prefixed path, backslash, empty/dot/traversal component,
control or Windows-forbidden character, trailing dot or space, case-folded
`.folderbase` component, Windows-reserved stem, component beyond 255 UTF-8
bytes, path beyond 4096 UTF-8 bytes, or depth beyond 128. The Unicode 17 NFC and
Unicode 9 full-default-case-fold collision keys from the Folderbase Version
contract apply. Exact duplicates inside a filter family are deduplicated; two
distinct spellings that collide by NFC or full case fold make the request
invalid. Path and prefix families are validated independently because their
intersection is meaningful.

The independent reference carries checked-in, self-contained Unicode 17.0.0
canonical normalization and Unicode 9.0.0 full-default case-fold tables. It
does not delegate portability to the host ICU version. Table provenance,
license notices, fixed artifact digests, and maintainers' generators live with
the capability runner.

Rows use the total `query_row_key_v1` order. Compare the raw UTF-8 portable-path
bytes first; then lifecycle (`live`, `deleted`); kind (`directory`,
`regular_file`, `symlink`, `nested_folderbase`); nullable Object ID, Object
Version ID, and Folderbase Version ID (null before a present value, present
values by raw UTF-8 bytes); source (`capture_plan`, `folderbase_version`); and
nullable boundary reason by the same null/byte rule. Folderbase Version
portability rejects path aliases but deliberately permits a current binding and
an older Tombstone at the same path after recreation, so path alone is not a
total row key. Exclusions remain ordered by ascending raw UTF-8 path bytes. Page
limits are bounded. Pages of size 1, 2, or N must concatenate to the same
ordered logical result without skips or duplicates.

Run and explain each return at most 1,000 exclusions, preserving the exclusion
path order above. `exclusions_truncated` on a result and `excluded_truncated`
on an explanation are true exactly when more exclusions belonged to the bound
observation. Truncation never changes the observation generation or matched-row
count.

The normalized request fills every filter family, deduplicates and byte-sorts
set values, normalizes absent byte bounds to `null`, and omits the cursor. Its
domain-separated SHA-256 is `folderbase-query-request-v1\0` followed by the
canonical compact JSON bytes. Public vectors fix this digest across languages.

Those JSON bytes have one closed serialization: object members occur in the
schema-defined normalized order (`format`, `scope`, `filters`, `page`, with the
documented order inside each), arrays retain their normalized order, integers
use unsigned base-10 without leading zeroes, and no insignificant whitespace is
present. Strings use JSON double quotes; quote, reverse solidus, and U+0000–001F
use the standard shortest JSON escapes (`\b`, `\f`, `\n`, `\r`, `\t`, or
lowercase `\u00xx`), solidus is not escaped, and all other Unicode scalar values,
including U+2028/U+2029, are their exact UTF-8 bytes. Public vectors cover input
member reordering, duplicate-set removal, Unicode byte order, every escape, and
the maximum bounded integer. There are no implementation-selected map keys in a
normalized request.

### Snapshot-safe cursors

Cursors are opaque values. Their implementation-private payload binds the exact
Folderbase Root identity, normalized request digest, observation generation,
and final complete `query_row_key_v1` sort key. It may additionally authenticate that
binding. Callers may persist and round-trip a cursor but cannot inspect it for
authority or ordering.

The live observation generation binds the attested physical root instance and
Folderbase ID; exact root-manifest bytes and metadata; effective ordered ignore
policy digest; optional verified Local Head bytes and metadata; every Capture
Plan entry's kind, bytes, modified time, readonly/executable bits, device/inode
or platform physical identity, and symlink target; plus sorted ignored and
excluded paths. Index-private state is not part of that observation. If any
bound fact changes after a page, continuation returns the typed, retryable
attention `query_snapshot_changed`; it never mixes rows from two generations.
Replaying a cursor against another root or normalized request is instead an
`invalid_query_cursor` operational error.

The historical generation binds the exact attested root, requested Version ID,
and canonical digest of one bounded, semantically verified Folderbase Version.
A missing Version exits 2 as `query_scope_version_missing`; malformed, identity-
mismatched, schema-invalid, semantically invalid, or otherwise unverifiable
Version bytes exit 2 as `query_scope_version_invalid`. Both use empty stdout and
one typed error document on stderr. An immutable historical Version cannot
legitimately change.

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

Conformance protects ordinary files, ignored descendants, descendants behind a
nested Folderbase, portable protocol records, and pre-existing sibling
namespaces under `.folderbase/local/**` across query, explain, status, and
rebuild. Only the exact query-index namespace may differ after rebuild.
Protection is a complete no-follow tree snapshot: bounded regular files are
hashed, large sparse files use metadata and bounded edge samples, and symlink
targets and stable directory metadata are recorded. Only explicit rebuild may
exclude the exact index namespace from its before/after comparison, with the
single expected mutable parent-directory size/time exception at
`.folderbase/local`. Rebuilt private index state is independently bounded and
may not be a symlink. After publication, query run, explain, and status snapshot
the exact index bytes and metadata and prove they do not mutate it.

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

The public runner resolves one regular candidate executable without a shell,
places every fixture beneath one cleanup-owned temporary parent, and applies a
hard per-command wall-clock and combined stdout/stderr byte bound. It terminates
the candidate process tree with a new process group plus `SIGKILL` on POSIX and
`taskkill /T /F` on Windows. Adversarial fixtures trap SIGTERM, fork a child, or
produce unbounded output and prove every recorded PID is gone afterward. This
is process-tree cleanup, not a security sandbox against deliberate daemon or
kernel escape. The sparse 10 GiB fixture must consume at most 16 MiB where the
host exposes allocation blocks; Windows still proves the exact logical size.

The full capability suite runs on the Linux pull-request lane and on the
existing cost-controlled macOS/Windows platform matrix only after merge,
schedule, or manual full-confidence runs. Pull requests spend no native-platform
runner minutes.

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

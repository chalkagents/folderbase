# Folderbase query/index 0.1 conformance

This dependency-free black-box suite covers the separately advertised
`folderbase.query-index@0.1.0` capability. It invokes only a candidate process,
standard streams, and temporary ordinary filesystem effects. It does not load
Rust or use Folderbase Core as its expected-value oracle.

```sh
node run.mjs --implementation /absolute/path/to/folderbase
```

The runner creates a Folderbase containing repository metadata, Markdown, PDF,
CSV, SQLite, video, a symlink, an ignored tree, one opaque nested Folderbase,
and a sparse 10 GiB video whose bytes are never read. It also installs one exact
Folderbase Version fixture with a Tombstone. Every fixture lives below one
cleanup-owned temporary parent. The runner verifies that the 10 GiB file uses at
most 16 MiB of allocated blocks and removes all state even when setup or the
candidate fails.

The suite proves:

- live scope uses metadata-first rows and never descends ignored or nested trees;
- historical scope selects one exact Version and preserves Object identity and
  `live`/`deleted` lifecycle;
- path prefixes are component-aware and filter families have deterministic
  AND-between-families/OR-within-family semantics;
- request paths obey the complete portable-path byte, depth, reserved-name,
  normalization, case-fold collision, and reserved-state policy;
- fixed request digests cover normalized key order, Unicode byte order,
  duplicates, bounds, and JSON escaping;
- pages of size 1, 2, and N concatenate to the same UTF-8 path-byte ordering;
- missing and invalid exact historical Versions use distinct typed exit-2
  errors with empty stdout;
- explain reports observation source, ordering, content access, and exclusions;
- query, explain, and status do not create an index or alter ordinary,
  portable, ignored, nested-boundary, or sibling-private state;
- explicit rebuild writes only `.folderbase/local/query-index-v1/**`;
- cursors bind the physical root, manifest, effective ignore policy, optional
  Local Head, and complete CapturePlan-like metadata fingerprints; and
- a continued live query returns `query_snapshot_changed` after any bound
  change instead of mixing generations.

Exit 0 with `failed: 0` is the conformance claim. Exit 1 is a complete report
with a behavioral failure, including the expected result for the released 0.5
binary because it does not implement or advertise this post-0.5 capability.
Bad runner arguments exit 2.

Each candidate command has a 30-second wall-clock bound and an 8 MiB bound for
each output stream by default, enforced with SIGKILL. A conformance host may lower or
raise them only within the runner's closed bounds through
`FOLDERBASE_QUERY_CONFORMANCE_COMMAND_TIMEOUT_MS` and
`FOLDERBASE_QUERY_CONFORMANCE_COMMAND_MAX_BYTES`. Hanging and noisy adversarial
fixtures prove both bounds and prove their PIDs are gone after termination.

`reference-request-digest.mjs` is an implementation-independent reference for
the domain-separated normalized-request digest. The checked-in `.sha256`
sidecars are fixed expected values, not values calculated by the candidate.
Canonical serialization is schema-ordered compact JSON, not a host-language map
order; see ADR-0011 and the public JSON/Unicode vectors for the exact rules.

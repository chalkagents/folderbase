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
Folderbase Version fixture with a Tombstone. Temporary state is removed even
when the candidate fails.

The suite proves:

- live scope uses metadata-first rows and never descends ignored or nested trees;
- historical scope selects one exact Version and preserves Object identity and
  `live`/`deleted` lifecycle;
- path prefixes are component-aware and filter families have deterministic
  semantics;
- pages of size 1, 2, and N concatenate to the same UTF-8 path-byte ordering;
- explain reports observation source, ordering, content access, and exclusions;
- query and status do not create an index or alter ordinary files;
- explicit rebuild writes only `.folderbase/local/query-index-v1/**`; and
- a continued live query returns `query_snapshot_changed` after workspace
  change instead of mixing generations.

Exit 0 with `failed: 0` is the conformance claim. Exit 1 is a complete report
with a behavioral failure, including the expected result for the released 0.5
binary because it does not implement or advertise this post-0.5 capability.
Bad runner arguments exit 2.

`reference-request-digest.mjs` is an implementation-independent reference for
the domain-separated normalized-request digest. The checked-in `.sha256`
sidecars are fixed expected values, not values calculated by the candidate.

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

The runner invokes candidates without a shell, bounds each command to 30
seconds and 8 MiB of combined output by default, and hard-terminates the whole
candidate process tree on timeout or output overflow. Conformance hosts may
use the runner's closed, validated timeout and output environment controls for
faster hostile-candidate proofs; those controls do not change capability
semantics.

Template expansion visits only declared artifact targets. A pre-existing text
target larger than 1 MiB is classified from metadata as blocked rather than
opened and hashed; unrelated large or opaque files are never visited.

Parser failures for the `template` command use
`folderbase-template-expansion-error-v1` on stderr with exit code `2`, including
missing or unknown arguments. Successful and attention documents are written
to stdout; operational errors are written to stderr.

The process contract has one physical delivery carve-out: when a host output
stream is unavailable, the CLI still exits `2` and attempts a non-panicking
best-effort diagnostic, but cannot guarantee delivery of typed JSON to that
unusable stream.

Implementations must not advertise this capability until that suite passes in
full.

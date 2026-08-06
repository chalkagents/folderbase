# Folderbase root reconstruction 0.1 conformance

This dependency-free black-box suite specifies
`folderbase.root-reconstruction@0.1.0` through only a candidate process,
standard streams, and ordinary temporary directories. It never imports Rust,
uses private Platform state, or treats another Core implementation as its
expected-value oracle.

Run it with Node.js 22 or newer:

```sh
node protocol/conformance/capabilities/root-reconstruction-0.1/run.mjs \
  --implementation /absolute/path/to/folderbase
```

Exit `0` with `failed: 0` is the complete capability claim. Exit `1` is a
bounded behavioral report. Bad runner arguments or runner failures exit `2`.
The v0.6.1 reference executable is expected to be RED because it does not yet
implement or advertise this later capability.

The generator creates a bounded exact package containing Markdown, CSV, PDF,
DOCX-shaped opaque bytes, immutable SQLite-shaped bytes, media, archive,
unknown binary, executable, Git working-tree state, safe symlink, empty
directory, nested-boundary exclusion, and retained Tombstones. One unchanged
moved file deliberately uses a single package reference whose canonical role
set is `["live_regular_file", "retained_tombstone"]`.

The twelve cases prove the mixed root and retained restore, an exact Version
`0.4` reconstruction whose root manifest reports `0.2.0+reconstruction`, exact
package pin, closed request, changed Version, reference closure, corrupt chunks,
no-follow package shape, destination no-clobber, deterministic restart/replay,
unsupported-filesystem preflight before staging, and rejection of ambient
authority. The legacy success keeps the Folderbase Version protocol distinct
from the exact root-manifest protocol reported by attestation. The preflight
case presents the conformance-only
`FOLDERBASE_ROOT_RECONSTRUCTION_CONFORMANCE_FORCE_UNSUPPORTED_FILESYSTEM=1`
environment control and proves the destination parent remains empty.
Deterministic process loss uses only the
conformance environment variable
`FOLDERBASE_ROOT_RECONSTRUCTION_CONFORMANCE_CRASH_AFTER` with the values
`prepared-journal`, `verified-staging`, `publication`, and
`completion-record`. A conforming test build terminates nonzero immediately
after that durable boundary and before its next externally observable step.

Every candidate process is supervised without a shell. The default command
bound is 30 seconds and 8 MiB of combined output. Conformance hosts may set
positive integer values within the closed maxima through
`FOLDERBASE_ROOT_RECONSTRUCTION_CONFORMANCE_COMMAND_TIMEOUT_MS` (maximum
120000) and `FOLDERBASE_ROOT_RECONSTRUCTION_CONFORMANCE_COMMAND_MAX_BYTES`
(maximum 16777216). POSIX supervision kills the process group; Windows uses
`taskkill /T /F`.

Run the package, schema, selector, generator, and expected-RED self-tests with:

```sh
node --test \
  protocol/conformance/capabilities/root-reconstruction-0.1/suite.test.mjs \
  protocol/conformance/capabilities/run.test.mjs
```

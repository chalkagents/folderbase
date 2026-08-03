# Folderbase Change Set 0.1 conformance

This dependency-free black-box suite specifies the unadvertised
`folderbase.change-set@0.1.0` capability through only a candidate process,
standard streams, ordinary temporary folders, and provider-neutral staging.
It never imports Rust or uses Folderbase Core as its expected-value oracle.

Run it from any checkout with Node.js 22 or newer:

```sh
node protocol/conformance/capabilities/change-set-0.1/run.mjs \
  --implementation /absolute/path/to/folderbase
```

Exit 0 with `failed: 0` is the complete capability claim. Exit 1 is a bounded
report with behavioral failures. Bad runner arguments or runner failures exit
2. The released executable is expected to be RED until the runtime capability
is implemented; the package is intentionally absent from both registries.

The ten public scenarios cover:

- clean scoped work with concurrent private sibling activity;
- one move-plus-edit delta;
- opaque binary bytes and a sparse 64 MiB + 1 byte file;
- delete/edit and create/create conflicts;
- stable-identity rename;
- Unicode/full-case-fold aliases;
- nested Folderbase boundaries;
- a missing trusted projection base; and
- crash-after-prepare, restart recovery, and idempotent replay.

Every checkout is restricted to `shared/**` while a marker under `private/**`
proves that result, receipt, proposal, assessment, attention, and apply output do
not disclose sibling content. Assessment is read-only. Apply and replay must
leave every ordinary out-of-scope entry unchanged.

Changed regular-file bytes are external to the Change Set envelope. The runner
independently verifies the closed staging tree, Chunk Manifest canonical
digests, contiguous ranges, chunk filenames, chunk bytes, object length, and
final object SHA-256. It rejects links, special nodes, aliases, or extra staging
files.

For deterministic crash evidence the runner presents the exact
conformance-only environment variable documented by ADR-0012. A conforming
test build exits nonzero after its prepared journal is durable and before its
first visible ordinary-path mutation. The next normal apply must recover and
publish once; a third identical apply must return `already_applied` without
creating more history.

The self-tests verify the public schema, fixed Change Set digest vector,
scenario inventory, legacy-prototype non-reinterpretation, absent advertisement,
and the expected RED report:

```sh
node --test protocol/conformance/capabilities/change-set-0.1/suite.test.mjs
```

The runner enforces a 30-second and 8 MiB bound for each candidate command.
Hosts may tighten or raise those values only inside the closed ranges through
`FOLDERBASE_CHANGE_SET_CONFORMANCE_COMMAND_TIMEOUT_MS` and
`FOLDERBASE_CHANGE_SET_CONFORMANCE_COMMAND_MAX_BYTES`. POSIX uses a fresh
process group and `SIGKILL`; Windows uses `taskkill /T /F`. This is process-tree
cleanup, not a security sandbox against a deliberately escaping daemon.

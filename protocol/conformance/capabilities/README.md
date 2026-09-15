# Folderbase optional-capability conformance

This dependency-free runner selects independently versioned capability suites
without adding their commands to the Compatibility Contract v1 minimum.

Run every known profile advertised by a candidate:

```sh
node run.mjs --implementation /absolute/path/to/folderbase
```

Require one exact profile:

```sh
node run.mjs \
  --implementation /absolute/path/to/folderbase \
  --capability folderbase.version-cli-json@0.1.0
```

The candidate may be a native executable or a `.js`, `.cjs`, or `.mjs`
implementation. Discovery uses only `protocol contract --json`. Registered
suites invoke only the candidate's process interface and ordinary temporary
filesystem effects.

The registry lists known profiles; an executable advertises only its supported
subset. The development Core candidate advertises root reconstruction on Linux
and macOS release targets. Windows and other targets omit that profile because
the complete publication/replay behavior is unavailable there. The universal
command still returns typed refusals. Explicitly requiring an omitted profile
fails; an unsupported-filesystem refusal is not a passing reconstruction suite.
Eligible targets must still pass Core's runtime destination-filesystem preflight.

Every child process is bounded. Discovery defaults to 15 seconds, each
candidate command within a registered suite defaults to 120 seconds, and a
whole registered suite defaults to 5 minutes. These bounds retain the existing
8 MiB candidate-output and 16 MiB suite-output limits. Slow environments may
set positive integer millisecond values with:

- `FOLDERBASE_CAPABILITY_DISCOVERY_TIMEOUT_MS`
- `FOLDERBASE_CAPABILITY_COMMAND_TIMEOUT_MS`
- `FOLDERBASE_CAPABILITY_SUITE_TIMEOUT_MS`

A timed-out discovery or suite is emitted as a failed JSON report and exits
`1`; it does not change argument/selector errors, which continue to exit `2`.

The runner ignores unknown advertised profiles when no selector is supplied.
It exits `2` for an unknown requested profile, reports a failed case for a
known but unadvertised profile, and reports a failed case when any known
advertisement does not pass its registered suite. A v1 candidate with no
`capabilities` field selects zero suites and remains valid for base v1.

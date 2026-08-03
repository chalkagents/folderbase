# FB-41N.1.1 query/index contract verification

Date: 2026-08-03

Base: `origin/main` at `0fbe405f0d34201e725b22f10389fb8dec47b844`

Scope: ADR, optional-capability package, public schemas, deterministic mixed-file
and historical fixtures, independent request digests, and a black-box runner.
No Rust query/index/API/CLI implementation is included.

## RED — current 0.5 runtime

The runner was executed against an existing current `folderbase 0.5.0` binary:

```sh
node protocol/conformance/capabilities/query-index-0.1/run.mjs \
  --implementation /path/to/current/folderbase
```

Expected and observed report:

```text
capability: folderbase.query-index@0.1.0
passed: 0
failed: 1
case: query-live-mixed-files-metadata-first
message: unrecognized subcommand 'query'
```

The runner exited 1. This is the intentional missing-runtime result for
FB-41N.1.1, not a claim that the capability is implemented or advertised.

## REVIEW RED — adversarial contract gaps

Independent specification and standards review found the first contract runner
did not yet prove invalid historical Version handling, complete filter algebra,
portable-path limits/collisions, full live-generation binding, write confinement,
or child-process termination. New public tests failed before the reference
candidate and runner were changed:

- canonical serializer and portable-path exports were missing;
- the hard-timeout fixture survived the unbounded RED runner;
- the candidate accepted invalid paths and mapped corrupt Versions to a generic
  request error;
- live generation came from a hard-coded path list rather than fixture metadata;
- nested-boundary rows admitted schema-invalid identity and byte shapes; and
- CI did not execute or policy-pin the optional-capability suite.

Each case was made GREEN through the public process surface. The final timeout
test writes the adversarial child PID, requires `ESRCH` after the command bound,
and leaves no hanging/noisy child process.

## GREEN — contract, vectors, runner, and CI policy

```sh
node --test \
  protocol/conformance/capabilities/query-index-0.1/suite.test.mjs \
  protocol/conformance/cli-json-v1/schema.test.mjs \
  scripts/tests/compatibility-contract.test.mjs \
  scripts/tests/ci-policy.test.mjs
```

Result: 57 passed, 0 failed.

The query suite's minimal JavaScript candidate passed all 18 public black-box
cases. They cover the complete deterministic filter algebra; fixed ASCII and
Unicode request digests; every portable-path bound and representative Unicode
17 NFC/Unicode 9 full-fold collision discriminator; typed invalid/missing
historical Versions; root/manifest/ignore/Local Head/metadata cursor binding;
and confinement of ignored, nested, portable, and sibling-private state. The
missing-query candidate exited 1 with the same intentional runtime gap.

The runner creates every fixture below one cleanup-owned parent, verifies the
sparse 10 GiB file occupies no more than 16 MiB, and removes it on every path.
SIGTERM-trapping and noisy candidates are hard-killed within test-selected
bounds, their PIDs are proven absent, and the production defaults remain 30
seconds and 8 MiB per output stream for each candidate command.

```sh
node protocol/conformance/capabilities/query-index-0.1/run.mjs \
  --implementation \
  protocol/conformance/capabilities/query-index-0.1/fixtures/conforming-candidate.mjs
```

Result: 18 passed, 0 failed.

```sh
scripts/check-ci-policy.sh
```

Result: exited 0. The optional capability suite is a distinct npm-lane CI step,
and the policy test proves replacing that exact entrypoint makes policy fail.

```sh
node scripts/verify-folderbase-version-0.5-digest-vectors.mjs
scripts/check-public-eclipse.sh
find protocol/capabilities/query-index \
  protocol/conformance/capabilities/query-index-0.1 \
  protocol/schemas/capabilities/query-index \
  -type f -name '*.json' -print0 | xargs -0 -n1 jq empty
git diff --check
test ! -d target
```

Result: all commands exited 0. The immutable Folderbase Version 0.5 vectors
remain exact, the public terminology gate is clean, every added JSON document
parses, no whitespace errors exist, and this worktree contains no Rust build
artifacts.

The historical fixture also passed the public 0.5 protocol-check surface and
matched its independently calculated digest:

```text
valid: true
profile: 0.5
canonical_digest: 7c494ee4509f8865facdbb10b4ad94b3b59637a5f85149d80d938d1c75cba140
```

## Compatibility proof

- `protocol/compatibility/v1/contract.json` is unchanged.
- `protocol/schemas/cli/1/folderbase-cli-json.schema.json` is unchanged.
- No file in the immutable 0.5 release closure changed.
- The new package entry uses the closed optional-registry shape accepted by
  ADR-0010/FB-41P, but it is not added to base v1 discovery in this slice.
- `apps/docs/**` is unchanged. Public docs should be updated after the runtime
  implementation and advertisement pass the black-box suite.

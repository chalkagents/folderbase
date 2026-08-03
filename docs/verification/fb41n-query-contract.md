# FB-41N.1.1 query/index contract verification

Date: 2026-08-03

Base: `origin/main` at `45b6a34d67ac0147f38cf2388052a63ccbd1a460`

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

## GREEN — contract, vectors, and runner

```sh
node --test \
  protocol/conformance/capabilities/query-index-0.1/suite.test.mjs \
  protocol/conformance/cli-json-v1/schema.test.mjs \
  scripts/tests/compatibility-contract.test.mjs
```

Result: 17 passed, 0 failed.

The query suite's minimal JavaScript candidate passed all nine public black-box
cases. The missing-query candidate exited 1 with the same intentional runtime
gap. The suite creates and removes its temporary root and sparse 10 GiB fixture.

```sh
node protocol/conformance/capabilities/query-index-0.1/run.mjs \
  --implementation \
  protocol/conformance/capabilities/query-index-0.1/fixtures/conforming-candidate.mjs
```

Result: 9 passed, 0 failed.

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

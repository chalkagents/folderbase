# Folderbase public conformance runner

This dependency-free Node.js runner proves Compatibility Contract v1 through a
candidate executable's public process and filesystem interface. It never loads
the Rust crate and does not calculate expected digests with Folderbase Core.
It validates every emitted document against the public CLI JSON v1 Schema,
then checks command semantics while tolerating permitted additive fields.

```sh
node run.mjs --implementation /absolute/path/to/folderbase
```

The executable may be implemented in Rust, Go, TypeScript, or another language.
It must expose the stable commands in `suite.json`. The runner creates only
temporary folders and removes them when complete.

The suite covers:

- native root-manifest `0.5.0` valid and invalid fixtures;
- Folderbase Version v1 profiles `0.4` and `0.5`;
- Chunk Manifest v1 semantics and independent digest sidecars;
- contract discovery;
- ordinary-folder inspection;
- read-only initialization planning and digest-bound apply;
- root attestation and shallow validation;
- workspace list, read, and optimistic save; and
- explicit non-following representation of ordinary symlinks; and
- machine-readable operational errors.

Exit `0` with `failed: 0` is the conformance claim. Exit `1` means at least one
case failed. Missing runner arguments or an unlaunchable implementation are
runner failures and do not constitute a conformance report.

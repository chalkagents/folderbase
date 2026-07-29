# Folderbase Version v1 conformance

These fixtures define the public `folderbase-version-v1` compatibility surface.

- `valid/empty-v1.json` is the smallest independently restorable state and proves
  the dedicated root-manifest reference.
- `valid/fidelity-and-lifecycle-v1.json` covers visible root markers, empty
  directories, a 10 GiB metadata-first opaque executable file, a contained
  symlink, same-path recreation with a new Object ID, stable identity across a
  moved path, directory and file Tombstones, a nested boundary, and typed hard-link
  and FIFO exclusions.
- each valid JSON digest vector has a `.sha256` sidecar produced by
  `reference-digest.mjs`, an implementation independent from the Rust module.
- `invalid/` separates schema closure, exact ordering, NFC and full-case-fold
  collisions, protocol self-capture, nested-boundary containment, symlink escape,
  same-object recreation, and exclusion fidelity failures.

The canonical binary sequence is specified by
[`../../../docs/adr/0004-seal-portable-folderbase-versions-as-bounded-full-state.md`](../../../docs/adr/0004-seal-portable-folderbase-versions-as-bounded-full-state.md).
Regenerate a candidate digest for review with:

```sh
node protocol/conformance/folderbase-version/reference-digest.mjs \
  protocol/conformance/folderbase-version/valid/empty-v1.json
```

The script calculates evidence only. It does not rewrite sidecars, grant authority,
prove hosted bytes, or seal a Folderbase Version from unverified workspace state.

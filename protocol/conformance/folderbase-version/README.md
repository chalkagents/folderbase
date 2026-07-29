# Folderbase Version v1 conformance

These fixtures define the public `folderbase-version-v1` compatibility surface.

- `valid/minimal-restorable-v1.json` is the smallest restorable state: the reserved
  root-manifest reference plus required live regular-file bindings for
  `.folderbaseignore` and `FOLDERBASE.md`.
- `valid/fidelity-and-lifecycle-v1.json` covers visible root markers, empty
  directories, a 10 GiB metadata-first opaque executable file, a contained
  symlink, same-path recreation with a new Object ID, stable identity across a
  moved path, directory and file Tombstones, a nested boundary, and typed hard-link
  and FIFO exclusions.
- each valid JSON digest vector has a `.sha256` sidecar produced by
  `reference-digest.mjs`, an implementation independent from the Rust module.
- `invalid/` separates schema closure and minimum cardinality; exact ordering;
  legacy and table-discriminating NFC/full-case-fold collisions; required marker,
  parent, root-manifest, and Object Version ownership; protocol self-capture;
  overlapping and entered nested boundaries; symlink escape; same-object
  recreation; Windows DOS superscript device names; and exclusion fidelity.
- `invalid/generate-runtime-limit-vector.mjs` produces the intentionally large
  aggregate-split counterexample and schema-valid/runtime-invalid UTF-8 component,
  full-path, and depth counterexamples without committing megabytes of repeated
  JSON.

The Unicode 17 NFC vector uses U+1ACF, whose canonical combining class changed
from unassigned/default in Unicode 16 to 230 in Unicode 17, so its two paths collide
only under the declared normalization tables. The Unicode 9 full-case-fold vector
uses the Osage U+104B0/U+104D8 pair introduced with that table version. These
discriminate the immediately preceding normalization table and pre-9 case-fold
tables respectively. No finite fixture can prove every entry of a Unicode table,
so Core also rejects a build whose dependency-reported table versions are not
exactly 17.0.0 and 9.0.0, and the declared versions enter the canonical digest.

The Rust conformance test additionally proves that the public `FolderbaseVersion`
does not implement raw Serde deserialization and that a moved stable Object with
changed content produces both typed `Moved` and `Updated` changes. Those API
counterexamples cannot be represented by an invalid JSON document.

The canonical binary sequence is specified by
[`../../../docs/adr/0004-seal-portable-folderbase-versions-as-bounded-full-state.md`](../../../docs/adr/0004-seal-portable-folderbase-versions-as-bounded-full-state.md).
Regenerate a candidate digest for review with:

```sh
node protocol/conformance/folderbase-version/reference-digest.mjs \
  protocol/conformance/folderbase-version/valid/minimal-restorable-v1.json
```

The script calculates evidence only. It does not rewrite sidecars, grant authority,
prove hosted bytes, or seal a Folderbase Version from unverified workspace state.

The repository/tag source archive is the normative cross-language distribution.
`protocol/releases/0.4/folderbase-version-v1.candidate.json` enumerates the exact
candidate surface. The Cargo crate contains the Rust runtime implementation only;
it does not silently claim to contain this schema, corpus, or reference encoder.

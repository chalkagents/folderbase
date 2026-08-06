# Folderbase root-reconstruction capability 0.1.0

This stable optional contract reconstructs one exact retained Folderbase
Version into one absent ordinary root:

```text
folderbase reconstruct SOURCE DESTINATION --stdin --json
```

`SOURCE` is one closed, no-follow provider-neutral package. `DESTINATION` is
an absent child of an existing ordinary directory. Standard input is one
closed request that pins the SHA-256 of the exact encoded `SOURCE/index.json`.
The command never discovers authority from the current directory, a share
link, provider identifier, Folder Scope, Cloud record, or ambient
`.folderbase` state.

The Folderbase Version protocol and the root-manifest protocol are distinct.
Version `0.4` reconstructs legacy roots whose exact manifest protocol is a
SemVer-valid `0.1.x` or `0.2.x` value. Version `0.5` reconstructs roots whose
manifest protocol is exactly `0.5.0`. Success reports that exact root-manifest
protocol in `root_attestation.protocol_version`; it never rewrites it as the
Folderbase Version protocol.

The package is stable and known to the public capability selector. The
reference executable must not advertise it until that executable passes the
complete public black-box suite. During the RED implementation tranche, its
absence from the executable's embedded advertisement registry is deliberate.

Normative surfaces:

- [ADR-0016](../../../../docs/adr/0016-reconstruct-exact-folderbase-versions-into-new-roots.md);
- [public JSON Schema](../../../schemas/capabilities/root-reconstruction/0.1/root-reconstruction.schema.json);
- [public fixtures](../../../conformance/capabilities/root-reconstruction-0.1/fixtures/); and
- [independent runner](../../../conformance/capabilities/root-reconstruction-0.1/run.mjs).

The package index maps the root manifest, every live regular file, and every
retained content Tombstone Object Version to canonical Chunk Manifests. Live
symlink content is derived from the Folderbase Version and is not transported
as an external object. A retained Tombstone reference proves the supplied
immutable bytes and local association; Folderbase Version v1 does not itself
authenticate those deleted bytes.

Because Folderbase Version v1 also does not bind deleted regular-file
executable state, `index.json` includes a required, exact path-sorted
`tombstone_fidelity` array. It contains one closed record—path, Object ID,
Object Version ID, and executable bit—for every regular-file Tombstone with a
last Object Version, and no others. The request's exact package-index digest
pins these transport records. They are not canonical Folderbase Version
evidence and never change its digest; the package producer must preserve them
from the immutable association established at capture or registration.

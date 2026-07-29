# Chunk Manifest v1 conformance

The JSON files under `valid/` and `invalid/` are portable protocol fixtures.
Digest sidecars are derived independently of the Rust implementation with
`reference-digest.mjs`, a small Node.js encoder that writes every integer
explicitly in big-endian form.

From the repository root:

```sh
node protocol/conformance/chunk-manifest/reference-digest.mjs \
  protocol/conformance/chunk-manifest/valid/two-chunk-standard-v1.json
node protocol/conformance/chunk-manifest/reference-digest.mjs \
  protocol/conformance/chunk-manifest/valid/large-offset-large-v1.json
```

The large-offset fixture is synthetic metadata, not a multi-gigabyte payload.
It describes 4,362,076,161 bytes and includes a 4,362,076,160-byte offset, so
both identities exceed 32 bits while remaining exact safe JSON integers.

# Version ordinary-folder roots and make narratives optional

Status: Accepted

## Context

Folderbase is intended to preserve an ordinary folder, but the legacy root
contract made two user-visible files carry protocol meaning:
`FOLDERBASE.md` established the boundary and `.folderbaseignore` was mandatory.
That coupling made initialization visibly reshape an existing folder, made a
human narrative part of machine authority, and made it difficult to distinguish
helpful context from permission.

The root manifest already contains the stable Folderbase identity and policies.
Folderbase Version v1 already represents its exact bytes through the reserved
`root_manifest` reference. A new profile can therefore remove the visible-file
requirements without weakening boundary or restore identity, provided the
profile is exact, independently distributed, and does not reinterpret the
released 0.4 Version surface.

## Decision

Protocol 0.5 defines the ordinary-folder root profile.

An exact regular `.folderbase/manifest.json` whose supported
`protocol_version` is exactly `0.5.0` is the root authority. Clients open and
revalidate that file through the exact supplied root; they do not walk to an
ancestor. Parent traversal is deliberately shallower: any exact regular,
no-follow `.folderbase/manifest.json` is an opaque nested boundary, even when
its contents are malformed. The parent does not read or decode those bytes.
Only an operation explicitly opened on that nested root decodes and attests the
manifest, and that operation fails closed if the profile is invalid.

Every traversal surface uses one shared three-way classifier. Exact
case-sensitive `.folderbase` and `manifest.json` components with a directory
state marker and regular no-follow manifest produce the opaque boundary above.
An ASCII-case alias of either component, a symlink or non-directory state
marker, or a symlink or non-regular manifest is an unsafe filesystem shape and
does not acquire protocol authority. A `.folderbase` tree with no exact
manifest, including markerless summary or question context, is inert and
establishes no boundary.

Read-only analysis may quarantine either an exact opaque boundary or an unsafe
shape as `Unchecked` (`unchecked` on the wire) and omit descendants because it
does not attest nested bytes. That result is a conservative observation, not
authority.

Materialization, mutation, transfer, and restore seams accept the exact opaque
boundary as an exclusion but reject unsafe shapes. Operations explicitly
targeting the nested root still require full attestation.

The 0.5 manifest schema requires:

- a canonical Folderbase ID plus nonempty name, supported kind, supported
  status, and RFC 3339 creation time;
- the availability, structural-change, archive, and cloud-sync policies;
- one closed `capture_ignore` record with format
  `folderbase-capture-ignore-v1` and at most 1,024 ordered rules; and
- valid opt-in adapter records when adapters are present.

Each capture rule is a nonempty string with no NUL and at most 4,096 UTF-8
bytes. JSON Schema also fixes the corresponding character ceiling; runtime
admission enforces the byte ceiling. Unknown members inside `capture_ignore`
are rejected.

The optional top-level `folderbase_protocol_upgrade` member is Core's
namespaced, closed recovery receipt for a legacy-to-0.5 manifest activation.
It records the legacy version, approved plan digest, and digest of the activated
manifest with the receipt removed. It is integrity and lost-ack evidence only:
it grants no mutation, sharing, or hosted authority. Core validates it whenever
present. The generic `protocol_upgrade` name is not reserved; it remains an
unknown extension that compatible clients preserve without interpreting.

Adapter creation is opt-in. A managed adapter target must be an ordinary
visible relative path: absolute and drive paths, backslashes, empty segments,
`.` or `..` traversal, NUL, trailing separators, and `.folderbase` or `.git`
components are rejected. The two private component names are compared without
ASCII case sensitivity. Adapter contents point agents back to the exact root
manifest and describe narratives as context, never authority.

Initialization of a native 0.5 root creates only
`.folderbase/manifest.json` by default. It creates an agent adapter only when
requested. It does not implicitly create `FOLDERBASE.md`,
`.folderbaseignore`, `.folderbase/summary.md`, or
`.folderbase/questions.jsonl`.

An untemplated native 0.5 Folderbase may later take its first additive template
application from the explicit comparison source `unmanaged` at version
`0.0.0`. Applying that reviewed plan writes an immutable Template Application
record; that record becomes the comparison lineage for later expansions. The
root manifest is not rewritten to invent a Template Origin. Templates guide and
expand ordinary content but never become permanent layout, kind, permission, or
protocol constraints.

Root `FOLDERBASE.md` is fully ordinary optional content. It carries no syntax,
discovery, mutation, or sharing authority and may be ignored from capture.
Root `.folderbaseignore` is optional and user-owned, but is not fully ordinary:
it controls capture policy, its input is bounded, and it changes only through
typed policy-aware flows. The effective 0.5 ignore policy applies the manifest
engine rules first and the root file second when present. Presence and absence
are different policy inputs. A present `.folderbaseignore` is force-captured as
a binding even if a rule matches it.

Optional `.folderbase/summary.md` and `.folderbase/questions.jsonl` files are
the named engine-owned contextual hint formats. They may help a person or agent
understand the ordinary tree, but they do not:

- establish or extend a Folderbase boundary;
- approve a filesystem mutation;
- grant actor, sharing, hosted, or cloud authority;
- become the canonical user narrative; or
- enter an ordinary Folderbase Version binding.

The existing `.folderbase/**` self-capture ban supplies the last property. The
exact root manifest remains the sole reserved Version reference into that
private tree. Any other `.folderbase/**` content remains private and inert but
is not assigned one of the two named hint formats.

Folderbase Version protocol 0.5 retains the closed
`folderbase-version-v1` envelope, bounds, portable-path policy, and canonical
digest v1 encoding. Its encoded `protocol_version` is `0.5`, and its binding
array may be empty. Optional root `FOLDERBASE.md` and `.folderbaseignore` files
are bindings when present; the former is fully ordinary while the latter
retains the bounded, policy-controlling lifecycle above.

The released protocol 0.4 contract is immutable. A 0.4 Version still requires
both root files as live regular bindings, and its schema, corpus, reference
encoder, release inventory, and verifier semantics do not change. Upgrading a
live root installs an exact 0.5 manifest profile and causes new full-state
Versions to use `protocol_version: "0.5"`; it never rewrites historic 0.4
Versions or their digests. Validators dispatch by the Version's encoded
profile.

Protocol 0.5 is distributed separately as a candidate: a closed member-hashed
inventory, manifest SHA-256 sidecar, separate schemas and conformance tree, and
independent digest and distribution verifiers. Candidate status is not a claim
of release. Its verifier deterministically walks the complete Core and CLI crate
trees and seals their sources, embedded assets, tests, manifests, and legal
files together with the workspace Cargo manifest and lockfile. Any new unsealed
runtime or package input fails the exact closure gate. The release manifest
cannot hash itself; its external SHA-256 sidecar is the non-circular root proof.
Repository CI and package-install validation run both new 0.5 verifiers while
retaining both frozen 0.4 gates, and extracted-package validation compares every
packaged Rust source and embedded asset with the sealed checkout bytes.

## Permission invariant

This profile changes no permission boundary. Root possession, a manifest,
adapter, narrative, summary, question, path relationship, and physical nesting
do not grant mutation, sharing, or hosted access. Those authorities remain in
their explicit approval, grant, and authenticated service contracts.

## Rejected alternatives

**Keep `FOLDERBASE.md` as a mandatory boundary marker.** This continues to make
user-facing prose part of machine authority and prevents a truly ordinary
minimal root.

**Move summary or questions into the manifest.** This would mix mutable
narrative hints into the exact authority record and make harmless prose changes
look like policy changes.

**Capture `.folderbase/summary.md` as ordinary portable content.** This weakens
the private-state boundary and makes generated hints indistinguishable from
user knowledge.

**Redefine protocol 0.4 in place.** Existing digests and released conformance
evidence are immutable. A new encoded profile is the compatible extension.

**Infer authority from an adapter.** Adapters are optional bootstrap text and
cannot substitute for exact manifest attestation or explicit permission.

## Acceptance

The decision is implemented when:

- native initialization and upgrade produce the exact 0.5 manifest profile;
- explicit manifest-only roots attest without visible narratives, while parent
  traversal treats any exact nested manifest marker as an opaque boundary;
- markerless context remains inert, unsafe marker shapes gain no authority,
  read-only analysis may quarantine them as `Unchecked`, and operational seams
  reject them;
- missing or invalid identity, descriptive, policy, capture-ignore, and adapter
  fields fail closed;
- first template adoption records explicit unmanaged `0.0.0` lineage without a
  root-manifest provenance rewrite;
- optional `FOLDERBASE.md`, summary, `questions.jsonl`, and ignore-file
  presence exercise the exact capture and non-authority semantics above;
- markerless and optional-root-file 0.5 Versions validate and digest
  independently;
- the complete 0.5 candidate inventory and SHA sidecars verify;
- repository and package-install CI execute the separate 0.5 gates without
  removing the frozen 0.4 checks; and
- the released 0.4 distribution and conformance gates continue to pass
  byte-for-byte.

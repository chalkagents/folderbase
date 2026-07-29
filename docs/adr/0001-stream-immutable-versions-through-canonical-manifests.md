# Stream immutable versions through canonical manifests

Status: Accepted

## Context

Folderbase Core v0.1.0 can content-define chunks, persist received chunks, and
resume an interrupted transfer. Its convenient APIs still accept and return
complete byte buffers, however, and its serialized manifest does not record the
chunking parameters or define a cross-language manifest digest. Those
limitations make the current surface unsuitable for a multi-gigabyte video, a
remote Agent Session, or a managed data plane that must verify the exact same
artifact as a local device.

The public Core must own the portable content contract. Folderbase Platform may
coordinate authorization, upload operations, and hosted publication, but it
must not invent a second chunking or verification protocol. The first public
seam should solve immutable object transfer without prematurely fixing the
Folderbase Version, Remote Head, compare-and-swap, provider, or sharing wire
contracts.

## Decision

Folderbase Core will expose one bounded-memory transfer path from an exact
immutable `LocalVersionStore` version to an atomically installed, verified
artifact:

```text
LocalVersionStore::open_chunk_transfer(version_id, profile)
  -> ChunkTransferSource

ChunkTransferSource::manifest()
  -> &ChunkManifest

ChunkTransferSource::copy_chunk(index, writer)
  -> VerifiedChunk

ChunkManifest::decode_bounded(reader)
  -> ChunkManifest

ChunkManifest::verify_object(reader)
  -> VerifiedObject

PersistentTransfer::accept_chunk_from(index, reader)
  -> Accepted | AlreadyPresent

PersistentTransfer::materialize_to(root_capability, relative_destination)
  -> VerifiedMaterialization
```

The source-side Core API also provides
`LocalVersionStore::reopen_chunk_transfer(version_id, profile,
expected_manifest_digest)` for interruption recovery. It regenerates the
canonical plan from the exact immutable version and returns no source when the
durable expected digest differs. This prevents a caller from silently resuming
chunk requests against another profile or plan.

Planning always reads the immutable content-addressed blob named by the exact
`LocalVersionRecord`; it never reads the mutable workspace path. Copying a
chunk uses an opaque `ChunkTransferSource` that binds the exact version,
immutable blob, chunking profile, manifest, and manifest digest once. Callers
cannot pair a version with an arbitrary manifest on later chunk reads. Reopening
the source after restart deterministically regenerates the same manifest and
must match the durable manifest digest before resume. Each copy reads only the
descriptor's byte range and verifies the emitted chunk digest and length.

`ChunkManifest::verify_object()` is the provider-neutral whole-object verifier.
It streams an ordered reader, recomputes the content-defined boundaries,
canonical manifest digest, whole-object SHA-256, and exact byte length, and
returns `VerifiedObject` only when all match. A different partition of the same
content is a different plan and is not accepted as the canonical plan selected
for that transfer. Filesystem materialization and hosted verification both use
this method rather than reimplementing the rules.

The public result identities are exact:

- `VerifiedChunk` contains
  `(manifest_digest, chunk_index, chunk_sha256, chunk_bytes)`;
- `VerifiedObject` contains
  `(manifest_format, manifest_digest, object_sha256, object_bytes)`; and
- `VerifiedMaterialization` contains that complete verified-object identity
  plus the installed relative destination.

These values report integrity work performed by the current process. They may
be serialized for diagnostics or a local checkpoint, but are not authorization,
hosted-presence receipts, Folderbase history, or readiness claims. A hosted
service trusts only a result produced inside its current trusted verifier from
the bytes it observed; it never accepts a caller-submitted result as proof.

Source planning and copying use a fixed 64 KiB I/O buffer. Version and object
records are decoded through fixed encoded-size caps, while descriptor state is
bounded by the manifest's public descriptor cap. The source retains open
identities for the Folderbase root, immutable version record, and blob; it
revalidates those identities, the current nested-boundary authority, and the
exact version membership before and after each chunk copy. Replacing the root,
record, blob, or a protected internal directory with a symlink fails closed.
Changing the ordinary workspace file does not change the opened immutable
version.

Receiving streams into a unique private staging file while computing the
expected digest and length. A complete chunk is installed with no-clobber
semantics and an exact retry reports `AlreadyPresent`. A short, long, corrupt,
unknown, or conflicting chunk changes no accepted state.

Materialization streams accepted chunks in manifest order into a unique file
beside the requested destination. It verifies every chunk plus the complete
object SHA-256, byte length, deterministic chunk boundaries, and canonical
manifest digest, synchronizes the new file, and installs it atomically without
overwriting an existing path. Until that installation succeeds, the
destination is absent and the transfer remains resumable. Failure cleanup may
remove only staging files created by that operation. Destination resolution
is relative to an opened `cap_std::fs::Dir`-style root capability supplied by
the caller. Core opens and holds parent filesystem components without
following symlinks, requires an existing directory parent and absent leaf,
synchronizes the parent after installation, and keeps staging state private to
the current user. A bare absolute destination path is not part of this
interface.

The implementation may retain whole-buffer convenience helpers for small local
callers, but the sync engine, hosted verifier, and Core release acceptance tests
will use only the streaming path. Memory use must be bounded by a fixed I/O
buffer and protocol-capped manifest state, not by object or chunk size. The
native App's versioned CLI/FFI streaming bridge is a separate cross-process
decision; this Rust API does not silently redefine its current JSON CLI seam.

## Canonical Chunk Manifest v1

Core 0.3.0 will define
`folderbase-chunk-manifest-v1` as a versioned public artifact with these
semantic fields:

- manifest format identifier
- content-defined chunking algorithm identifier
- minimum, average, and maximum chunk sizes used to plan it
- whole-object SHA-256 and byte length
- ordered descriptors containing index, offset, byte length, and SHA-256

The algorithm remains `folderbase-cdc-v1+sha256`. Core owns two initial
profiles:

- `standard-v1`: 256 KiB minimum, 1 MiB average, and 4 MiB maximum;
- `large-v1`: 4 MiB minimum, 16 MiB average, and 64 MiB maximum.

The profile identifier and exact parameters are part of the manifest rather
than ambient client configuration, so a different valid configuration cannot
masquerade as the same transfer plan. Manifest v1 caps one object at 1 TiB.
The managed planner recommends and defaults to `large-v1` for large objects to
reduce descriptor count; validation intentionally accepts either exact profile
for any conforming object up to 1 TiB and does not define or infer a profile
switch threshold. The large profile's 4 MiB minimum remains within the
262,144-descriptor cap even under worst-case boundary selection. Custom
configurations are not accepted as hosted v1 profiles.

The Rust source planner's current managed policy selects `large-v1` at 1 GiB
and above. That exported implementation threshold is deterministic metadata
policy, may evolve with a future protocol/client release, and does not alter
the validation rule above. Callers can always request either exact v1 profile.

`ChunkManifest::decode_bounded()` rejects an encoded manifest larger than
64 MiB before deserialization. String lengths are schema-bounded before they
become persistent state. `ChunkManifest::validate()` will reject:

- an unknown format or algorithm;
- an unknown profile or parameters that differ from that profile;
- invalid chunking parameters;
- anything other than lowercase 64-character SHA-256 values;
- more than 262,144 chunk descriptors;
- a whole-object length or descriptor offset greater than 1 TiB;
- nonsequential indices, gaps, overlaps, zero-length chunks, or a descriptor
  larger than the declared maximum;
- a nonfinal chunk smaller than the declared minimum;
- a descriptor total that differs from the whole-object length; and
- an empty-object representation other than zero descriptors and the SHA-256
  of the empty byte string.

The maximum allowed chunk size is 64 MiB. Together these limits bound manifest
memory and retry granularity while allowing the default profile to handle the
multi-gigabyte objects required by the first product. Callers also bound each
request's chunk-index batch; a manifest never implies allocating one operation
per descriptor at once.

Every numeric field uses the JSON Schema `integer` type, so exact integral
decimal and exponent forms are valid alongside plain integer tokens.
Deserializers preserve the number token until they have proved its exact
nonnegative integer value and field bound; they reject fractional, nonfinite,
or out-of-range forms without floating-point rounding. Whole-object lengths
and descriptor offsets are no greater than 1 TiB, inside the lossless integer
range of JavaScript and TypeScript clients. These caps plus the 64 MiB chunk
maximum also prove that offset-plus-length arithmetic cannot overflow.

`ChunkManifest::canonical_digest()` will compute SHA-256 over a
domain-separated binary encoding. It begins with the exact ASCII bytes
`folderbase-chunk-manifest-v1` followed by one zero byte. The format is thereby
bound by the domain separator. The remaining sequence is exactly: algorithm
identifier, profile identifier, minimum chunk size, average chunk size,
maximum chunk size, whole-object digest, whole-object length, chunk count, and
then every ordered chunk descriptor. Each identifier is encoded as a four-byte
unsigned big-endian UTF-8 byte length followed by those bytes. Each chunk size
and the whole-object length is an unsigned eight-byte big-endian integer. Each
digest enters as its decoded 32 bytes. Chunk count is an unsigned four-byte
big-endian integer. Each descriptor encodes index as four bytes, offset and
length as eight bytes each, and digest as its decoded 32 bytes. No padding,
terminator, JSON representation, or unknown field enters the digest. The
protocol repository will publish positive and negative conformance vectors
with the JSON Schema before this decision is accepted or Core 0.3.0 is
released.

Manifest v1 rejects unknown JSON fields (`additionalProperties: false`) instead
of excluding potentially meaningful extensions from plan identity. A future
extension requires a new manifest format whose digest semantics cover it.

The manifest digest identifies the transfer plan; it does not grant access,
name a storage location, prove hosted byte presence, or identify a Folderbase
Version.

## File types and database snapshots

Transfer treats each immutable file as opaque bytes. Markdown, office
documents, PDFs, images, audio, video, CSV, archives, Git packfiles, database
files, and unknown binary formats all use the same transport and integrity
checks. A repository remains a directory graph of such files plus Git
semantics; this object-transfer decision does not claim to synchronize or
restore that graph atomically.

An immutable byte capture of a database file may be transferred, but Folderbase
must not describe it as an application-consistent database snapshot unless a
format-aware snapshot adapter created and recorded that provenance. Transfer
integrity and application-level consistency remain separate claims.

## Durability and compatibility

The manifest is portable and provider-neutral. A durable receiver stores it
before accepting chunks and validates both the manifest and every already
installed chunk when reopening after a process or device restart. Transfer
checkpoints and temporary chunks are local runtime state, not canonical
Folderbase history and not authorization.

The receiver implementation fixes these additional v1 details:

1. `transfer_receiver::PersistentTransfer::create()` receives an opened root
   capability, one normal nonempty child-directory name, and the selected
   canonical manifest. It derives the manifest digest rather than accepting a
   redundant expected value. `open()` receives that same capability and child
   name plus the durable expected digest held by the caller. Absolute paths,
   separators, dot components, symlinks, and clobbering an existing child are
   rejected.
2. A checkpoint contains only `manifest.json` and `chunks/`. The canonical
   digest is recomputed from the validated manifest and compared with the
   caller's expected digest on reopen; no second digest file can drift from the
   manifest. On Unix, directories are created and reopened with exact mode
   `0700`, while manifest, chunk, and staging files require exact mode `0600`.
   Reopen fails closed if any owner, group, or other permission bit differs.
3. Chunk receipt reads and hashes the complete retry stream before returning
   either `Accepted` or `AlreadyPresent`. It writes through one private
   lowercase-hyphenated UUIDv7 staging file, synchronizes that file, installs
   with a no-clobber link, and synchronizes the chunks directory. The receiver
   retains the verified staging file identity, proves the no-follow staging
   name still identifies that file immediately before linking, and proves the
   installed destination identifies it before reporting `Accepted`. An
   identity change fails closed without treating a replacement pathname as
   operation-owned cleanup. A short, long, corrupt, unknown, or conflicting
   retry returns no acceptance result and never replaces an installed chunk.
4. Resume enumeration inspects at most the caller's capped page of sequential
   descriptor indices and returns the next descriptor index as its cursor.
   Reopen validates every installed in-manifest chunk. It ignores only regular,
   private staging files with the exact operation-owned UUIDv7 spelling;
   leading-zero chunk aliases, out-of-range chunks, other UUID versions,
   unknown entries, directories, and symlinks fail closed. The ambiguous
   pre-v1 checkpoint shape returns an explicit unsupported-checkpoint error.
5. Source planning and whole-object verification call the same canonical
   content-defined chunk planner. Both use one fixed 64 KiB buffer. The verifier
   reads only the declared object length plus the one byte required to prove
   exact EOF, then checks byte length, whole-object digest, every deterministic
   boundary and chunk digest, and the canonical manifest digest before
   returning `VerifiedObject`.

Checkpoint creation synchronizes the manifest, checkpoint directory, and
caller-supplied parent capability before returning. A failed create may leave
an invalid orphan child for explicit inspection or removal; Core does not
recursively clean an externally named path after failure because concurrent
state may have appeared there. An opened receiver retains the exact checkpoint
and chunks directory capabilities, so replacement names are never followed by
the current process.

This receiver slice deliberately has no destination path or materialization
method. The next materializer slice must independently define and test its
destination-root capability, no-follow parent authority, no-clobber atomic
installation, and parent-directory durability. Receiving verified chunks is
not authority to install them anywhere.

Core 0.3.0 will add the versioned manifest schema and conformance vectors.
Core 0.1.0 through 0.2.1 exposed only the
`chunk_transfer::ChunkManifest` Rust convenience shape; no released CLI, App,
Cloud, or documented user workflow created durable transfer checkpoints. That
legacy type is deprecated as a production transfer contract but retains its
existing small-buffer behavior while callers migrate. It is not
`transfer_manifest::ChunkManifest`, and neither decoder accepts the other
shape. Noncanonical runtime checkpoints are replanned from their immutable
local version instead of receiving a permanent compatibility decoder. Core
0.3.0 fails closed with an explicit unsupported-checkpoint error when it
encounters the ambiguous pre-v1 shape and never emits it.

Future chunk algorithms or manifest encodings receive new identifiers and
conformance vectors. Existing identifiers never change meaning. A receiver may
support multiple versions, but it must fail closed on an unsupported one
rather than reinterpret it.

## Acceptance evidence

Founder direction and the public/private product boundary were confirmed before
implementation. The canonical manifest contract, schema, Rust validator,
conformance vectors, and independent JavaScript digest implementation merged in
PR 13 at commit `67877f00c1efb3af8b244229d7b32e1e6946b7ce`.

Both independent review axes reported no findings after remediation. Hosted PR
CI run `30423502912` and post-merge `main` run `30423673665` passed the Rust
quality gate, including formatting, strict linting, locked workspace tests,
public-surface checks, extracted package verification, offline CLI installation,
and out-of-checkout initialization. At acceptance, this evidence covered the
manifest contract only; the source, receiver, verifier, and capability-rooted
materializer remained separate implementation slices.

The subsequent source slice implements the immutable `LocalVersionStore`
planner and exact chunk-copy seam. It merged in PR 15 at commit
`359d1b8933724ba10e7470cbddd42dc4d0c5a799`. Its acceptance evidence includes
12 source-specific public-seam tests, the independent canonical digest vector,
the complete locked workspace suite, strict formatting and linting, public
eclipse and CI-policy checks, extracted-package verification, and offline CLI
installation. Both independent review axes reported no findings after
remediation. Hosted PR CI run `30430141590` and post-merge `main` run
`30430363260` passed. The receiver, whole-object verifier, and
capability-rooted materializer remain unimplemented by the source slice.

## Explicit deferrals

This decision does not define or advance:

- a hosted Object Version or Folderbase Version;
- a Remote Head, Device Cursor, compare-and-swap commit, or conflict policy;
- authentication, grants, signed upload/download operations, or object-storage
  routing;
- compression, encryption, retention, or cross-Folderbase deduplication;
- Keep Local, Agent-ready, or application-consistent database state; or
- installation into canonical workspace history on a clean device.

A verified materialized artifact is necessary evidence for those later states,
not proof that any of them has been reached.

## Consequences

- The open Core becomes the single transfer contract used locally, in managed
  cloud, and by a trusted Folderbase workspace materializer inside remote-agent
  virtual machines. A model process receives the authorized local workspace,
  not general object-storage credentials.
- Large and arbitrary files no longer require whole-object or whole-chunk
  allocation.
- Exact immutable version identity survives workspace edits made after capture.
- A clean recipient can resume, verify, and install one artifact without
  trusting metadata or provider routing.
- Manifest validation and conformance work increase up-front, but prevent every
  client and cloud adapter from creating a subtly different protocol.

## Rejected alternatives

- Keeping the existing complete-buffer API as the production seam would make
  memory proportional to large objects.
- Reading from the mutable workspace path after planning could transfer bytes
  that do not belong to the selected immutable version.
- Hashing serialized JSON directly would make identity depend on formatting and
  language behavior.
- Omitting chunking parameters would let different plans share one ambiguous
  algorithm label.
- Installing before whole-object verification would expose partial or corrupt
  content as complete.
- Folding Remote Head or cloud authorization into this interface would couple
  the open local database to one managed product and make the first stable seam
  unnecessarily broad.

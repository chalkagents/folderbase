# ADR-0021: Batch capture's immutable directory flushes

## Status

Proposed: 2026-09-15. Development candidate for
[issue #94](https://github.com/chalkagents/folderbase/issues/94); unreleased.

## Context

An initial capture installs many small content blobs and Object Version
records. Each installation flushes its staged file and then the containing
directory. The same two directories are flushed repeatedly before the capture
transaction can publish a complete Folderbase Version. The diagnostic in
issue #94 identifies these flushes as material onboarding cost; it does not
establish a safe optimization or a measured improvement.

## Decision and interface

Use a capture-private immutable publication batch. A `LocalCaptureInstaller`
keeps typed content digests, Version encoding, and exact existing-record
verification in the local Version module. Its state publisher retains exactly
two no-follow directory capabilities and their physical identities:

- `.folderbase/versions/blobs/sha256`;
- `.folderbase/versions/records`.

Existing immediate publication methods reuse the same low-level write,
no-clobber install, and verification helpers. They retain their immediate
directory-flush behavior. `FolderbaseState` gains no hidden durability mode.
The batch owns no accumulating list of records or file contents; it retains
two directory handles plus bounded path and identity metadata. Streaming and
record-size limits remain unchanged.

## Durability order

1. Retain the existing transaction lease, validate the capture plan, and make
   the active intent and exact identity assignments durable as today.
2. Open both immutable parents beneath the retained state capability. Verify
   root/state attachment and retain each parent's physical identity.
3. For each blob or Object Version record, keep every staged-file `sync_all`,
   no-follow operation, no-clobber namespace installation, and exact-byte/hash
   check. Only the repeated containing-directory flush is deferred. Published
   names may be visible but are not yet acknowledged as durable capture work.
4. `finish` checks root/state attachment and reopens both parents through the
   state capability, rejecting any changed parent identity. It flushes the
   retained blob directory, then the retained Version-record directory. It
   flushes **both unconditionally**, including when every installation reused
   an exact existing entry from an interrupted attempt. It repeats attachment
   and parent-identity checks after the flushes. Either flush or identity error
   is returned to the caller. There is no implicit flush or success in `Drop`.
5. `build_and_install_capture` must finish the batch before returning success.
   Only then may its caller reach `ObjectWritesDurable`, install the complete
   Folderbase Version, or change Local Head. Existing full-Version validation,
   final source-plan validation, and Head compare-and-swap remain in order.
6. Mutable Object projections and capture identities still publish with their
   existing immediate durability after Head publication. Cleanup retires the
   active intent only through the existing successful completion path.

## Failure and recovery

An error or interruption before the batch barrier leaves the old Head and the
active intent in place. Some immutable files may already exist. Retrying the
same unchanged plan uses the journal's exact assigned IDs, verifies those files,
and establishes both directory flushes again before advancing. Mismatching
existing bytes fail closed; a visible file is not evidence of successful work.

If the source plan changed, existing recovery may abandon the uncommitted
intent while retaining safe immutable orphans, then assign a new capture.
Batching does not change that policy. After Head publication, existing recovery
verifies the complete Version and finishes projections/identities before
retiring intent. Source, alias, nested-boundary, no-clobber, and root/state
attestation checks remain authoritative throughout.

## Platform meaning and proof limits

On Linux, the existing helper opens the retained directory's `.` with no-follow
semantics, verifies physical identity, and calls `sync_all`. Other Unix targets,
including macOS, clone the retained directory handle and call `sync_all`.
On Windows, the existing directory helper is a no-op because the POSIX
directory-fsync contract is unavailable; staged regular files are still flushed
before publication. This change preserves that platform limitation and does
not claim a new Windows power-loss guarantee or stronger storage-device
semantics than the existing helpers provide.

Fault tests must exercise interruption before the first flush, between flushes,
and after the second flush; failures of each flush; exact retry; source change;
preexisting mismatches; and root/state/retained-parent replacement. Existing
file-write/verification and post-Head recovery checks must remain green.
Process interruption tests establish control flow and replay, not power-loss
durability. The flush-before-Head ordering argument is required separately.

## Excluded work and acceptance

No record format, index, public command, checkout write, or post-Head projection
batch is introduced. Acceptance requires the relevant Core/protocol gates and
a pinned, uninstrumented baseline/candidate comparison with byte, identity,
history, and restore verification. Retain the change only if the measured
benefit justifies this bounded recovery complexity.

# FB-41F exact no-clobber Tombstone restore

This evidence covers the first explicit restore operation for productive
Folderbase Version Tombstones. The public seam is:

```rust
FolderbaseVersionStore::restore_tombstone(portable_path)
```

The CLI seam is:

```text
folderbase version restore-tombstone ROOT PORTABLE_PATH --json
```

## Transition base

The branch starts from accepted capture/Tombstone merge:

```text
70a999b345ae46deba062c89dac5078ab1a5a1c0
feat(core): seal productive tombstones safely (#27)
```

No second object, version, or content store was introduced. Restore consumes
the existing immutable `LocalVersionStore` Object Version record and SHA-256
blob named by the current Head Tombstone.

## RED evidence

- `b1ee74f` required exact ordinary-file bytes, executable fidelity, original
  Object ID/Object Version, immutable deletion history, and a new Local Head.
  It failed to compile because `restore_tombstone` did not exist.
- `869b443` required retry convergence across journal, stage, target
  publication, version, Head, projection, and cleanup checkpoints. It failed to
  compile because no restore checkpoint/recovery seam existed.
- `c2f288c` required a fresh-process CLI JSON round trip. It failed because
  `restore-tombstone` was an unrecognized subcommand.
- `f5561df` required active-journal exclusion, tamper refusal, bounded and
  hostile ancestry handling, and root confinement. The nested-Folderbase
  regression failed because restore initially crossed a newly created child
  boundary.
- `20ecf87` strengthened journal tamper coverage by changing only executable
  fidelity and recomputing the target digest. It failed because recovery had
  not yet re-derived fidelity from verified ancestry.
- `7ee012e` required case-folded `.folderbase/manifest.json` aliases to remain
  nested restore boundaries on case-sensitive filesystems. The pure
  case-folding seam failed to compile before the boundary matcher existed.
- `baffd20` required final retained-stage identity, byte/fidelity, nested
  boundary, and physical-root attachment revalidation. It failed to compile
  because the final verification seam did not exist.
- `a7b429c` converted the first fixed-head review into regressions for
  same-byte replacement, in-place mutation, post-Head rollback, independently
  rewritten journal assignment, a nearer candidate hiding a deeper cycle,
  late nested-boundary closure, and copied replacement roots.
- `be97f9c` converted the second fixed-head review into regressions for two
  convergent-edge cycle shapes and a coordinated committed journal, Head, and
  valid-target rewrite.
- `28a6fdb` used an isolated restrictive-umask child process to prove that
  create-time mode bits alone did not preserve executable restore fidelity.
- `4ef4fa5` extended committed recovery tamper to rewrite the journal's prior
  Head transaction digest, every dependent deterministic assignment, the valid
  target Version, retained stage, and current Head. The prior implementation
  accepted that coordinated rewrite.
- `e7bf984` required post-Head projection to keep using retained capabilities
  and to roll Head back if projection failed. The prior implementation could
  leave the new Head visible after projection failure.
- `b24614c` required an in-place edit of the transaction-owned published target
  to preserve the new workspace bytes while relinquishing restore ownership.
  The prior implementation left durable restore intent blocking capture.
- `62df4cb`, `b497099`, and `af4b4b6` required successful transaction-directory
  retirement and restartable cleanup whose durable receipt survives active
  journal retirement. The prior implementation leaked transaction directories
  or could lose the final cleanup obligation.
- `773955f` required captured and restore-derived Heads to carry different,
  closed authority meanings while released v1 capture Heads still recover. The
  old wire used one ambiguous `transaction_sha256` field for both meanings.
- `5e8be93` denied private-stage unlink after an in-place target edit. The prior
  order retired active intent first, so fresh-process capture saw an unsupported
  multi-link file, omitted the preserved work, and leaked the transaction
  directory.
- `0689861` installed exact released-v1 non-genesis capture-journal bytes whose
  nested expected Head used `transaction_sha256`. Both pre-Head and
  committed-Head recovery initially rejected the old nested wire.
- `5f4b416` reverted a durably modified restore-owned inode to its sealed bytes
  before retry. The old modified cleanup required the bytes to remain changed
  and wedged the pending restore.
- `fcfc92a` coordinated rewrites of active intent and modified cleanup receipt
  to one self-consistent forged transaction. The old recovery retired forged
  state and global intent while stranding the real stage.
- `c74fac1` replaced the visible destination or private stage at the exact
  committed and modified unlink boundary. The old cleanup could delete the
  stage inode's last name or unlink unrelated replacement state.
- `5df80e7` terminated after `CleanupComplete` and required the same public
  restore call to return its exact durable result after fresh-process reopen.
  The old terminal retry returned target-occupied because every result record
  had already been removed.
- `d8d71f6` edited the published same inode immediately after
  `ProjectionDurable`. The committed cleanup receipt then wedged because sealed
  fidelity no longer matched while modified cleanup still required the prior
  Head.
- `8de8573` removed both private links at the cleanup boundary, then made the
  visible publication missing or foreign. The old committed retry reported a
  restored result without proving any workspace publication.
- `8fcb862` moved the deterministic mutation hook after the final stage or
  rescue pathname check. The old pathname unlink deleted a replacement created
  in that exact check-to-mutation window.
- `7c24cda` replaced a completed restore with a distinct inode containing the
  same bytes and executable fidelity. The old completion singleton treated
  content equality as terminal-result authority.
- `86e058e` coordinated a same-byte replacement of both private stage and
  visible destination with one foreign inode. The old cleanup accepted their
  agreement without binding either handle to the receipt identity.
- `db8e465` edited the exact published inode at both cleanup hook boundaries.
  The old cleanup had already consumed fidelity before those hooks and could
  return restored success.
- `f3546d4` edited the published inode after active-intent retirement, after
  completion-receipt durability, and at cleanup completion. Every late hook
  still returned `Restored`.
- `6bb201f` replaced the published inode at those same three late boundaries.
  The old cleanup acknowledged the foreign inode because no proof followed all
  hooks and mutations.
- `98d249d` added an ordinary user hard link at
  `BeforeObjectBytesRead`. Planning had validated the retained restore link,
  but sealing had discarded that topology and returned the unchanged prior
  capture.
- `3d40940` replaced the compatibility fixture's reused current plan digest
  with an independently encoded released-v1 non-genesis digest whose Head has
  the original flat `transaction_sha256` field. Pre-Head retry abandoned the
  released assignment and created a different target Version.
- `0ab155a` lowers the journal limit to the exact compact released-v1 raw byte
  length and proves that its normalized typed representation is larger. The
  old preflight rejected the valid pre-Head journal even though the bounded
  reader had admitted its exact old wire; one byte below the raw length still
  fails.
- `f7eca5b` moves the destination parent after its capability opens and again
  after the publication link is created. The prior implementation published
  into the detached parent in the first race and had no explicit scoped
  namespace contract for the second.
- `913b9f0` retries after the post-link detach. The prior implementation
  attempted another hard link instead of refusing the unresolved
  transaction-owned orphan, allowing recovery topology to grow rather than
  converge.
- `a266099` converts two independent exact-head review findings into three
  deterministic restore regressions. An ordinary edit and a same-byte inode
  replacement at the released-root Head-rebind boundary both produced a false
  `Restored` result. A process termination immediately after rebind CAS made
  the next identical restore return target-occupied even though the immutable
  completion and authority remained valid. The same retry test pins the exact
  embedded legacy transaction and byte-identical completion and authority
  records.

## GREEN behavior

- `04dc017` restores exact opaque bytes and v1 executable fidelity, reactivates
  the same Object ID and Object Version, creates one full-state child version,
  removes only the selected Tombstone, and advances Local Head after complete
  verification.
- `1bf3942` adds a bounded durable restore journal, retained private stage,
  same-inode retry proof, and seven-checkpoint crash convergence.
- `7fc2646` exposes the fresh-process CLI and stable JSON result.
- `9109526` covers same-byte foreign competitors, every occupied leaf kind,
  corrupt/missing immutable state, newest deletion generation, carried
  Tombstones, multiple Tombstones, capture/restore exclusion, bounded,
  ambiguous, and cyclic ancestry, symlink-parent swaps, and new nested
  Folderbase boundaries.
- `8158080` binds pending journal fidelity back to the current verified
  Tombstone and nearest verified live ancestor before staging.
- `c807298` discovers nested state and manifest components capability-relatively
  with ASCII case folding and refuses ambiguous aliases.
- `9f6d7f6` and `bd5fc2b` retain and compare exact stage/destination and
  physical-root identities, stream-verify bytes and fidelity, and recheck
  case-folded nested boundaries without cross-target warnings.
- `981e22a` derives transaction and target Version identity from verified
  immutable authority, validates the complete reachable ancestry DAG, performs
  live publication proofs immediately before and after Head CAS, and restores
  the prior Head on the retained root capability before reporting a
  post-Head conflict.
- `d338982` builds the complete bounded ancestry adjacency graph, validates it
  independently with an iterative acyclic pass, and re-derives full restore
  authority in both prior-Head and committed-Head recovery branches.
- `9841f2d` explicitly applies Unix restore-stage permissions through the open
  capability after creation, before sync and verification.
- `c476afc` atomically pre-binds the verified parent Head to a
  domain-separated digest of surviving root and Version authority before the
  restore journal exists. Both restore execution branches and rollback require
  the rederived parent/target Head authorities; capture journal binding remains
  unchanged.
- `1755a57` confines projection to the retained state capability and restores
  the prior Head when post-Head projection cannot be proven.
- `2805ce7` distinguishes a transaction-owned unchanged target from an in-place
  user or agent edit, preserves edited workspace bytes, and retires only the
  transaction's ownership and private stage.
- `329e8d7`, `d47e0c0`, and `e28108f` durably retire successful private
  transaction directories through a singleton cleanup receipt. Receipt-only
  recovery re-derives the exact target and converges, and capture remains
  excluded until final receipt retirement.
- `4b620b5` writes `folderbase-local-head-v2` with the closed
  `capture_transaction_v1` or `version_derived_v1` authority. It independently
  verifies version-derived authority, rejects unknown or mismatched
  discriminators, and reads released v1 `transaction_sha256` only as capture
  authority before CAS normalization under the transaction lock.
- `de81932` uses one closed cleanup receipt with `committed` or `modified`
  disposition. Modified retirement publishes the receipt before cleanup,
  revalidates the exact shared modified inode, removes only its private hard
  link and empty transaction directory, retires active intent next, and removes
  the receipt last. A fresh retry preserves visible bytes and capture becomes
  eligible only after link count returns to one.
- `b6e40bd` bounded-decodes the exact released non-genesis journal wire, converts
  only its nested authority type, and retains SHA-256 of the original durable
  bytes. Pre-Head execution and committed-Head recovery use that retained digest
  rather than hashing normalized bytes.
- `bfd5ad6` treats a durable modified receipt as the proof that the shared inode
  was edited, then retires its private ownership after exact stage/destination
  identity proof even when the same inode was later reverted.
- `86c8f90` rederives the exact deterministic modified restore transaction from
  the current immutable parent, Tombstone, and ancestor binding before cleanup;
  within trusted local state, coordinated rewrites of those mutable records
  alone have no retirement authority.
- `4ae2ad9` creates and syncs a transaction-owned rescue hard link before stage
  removal, re-proves stage/rescue/destination at the unlink boundary, and
  re-proves rescue/destination afterward. Pre- or post-unlink replacement keeps
  the exact owned bytes and pending cleanup instead of deleting uncertain state.
- `be02fbe` durably replaces one bounded device-local completion receipt before
  retiring pending cleanup. It never blocks capture and introduced bounded
  terminal completion evidence.
- `bc74848` adds a closed `committed_modified` cleanup disposition for a late
  same-inode edit after target Head publication. It preserves the edit, removes
  only proven private ownership, returns no restored success, and unblocks the
  next capture.
- `c2ec39a` binds cleanup v2 to a cross-platform durable device-local inode
  identity. Recovery with no surviving private link succeeds only for the
  recorded visible identity with sealed bytes and executable fidelity; missing
  or foreign state remains pending.
- `cce0b4e` replaces stage and rescue pathname unlink with
  transaction-unique capability-relative quarantine moves. Each moved object is
  identity-verified; replacements remain quarantined, exact restore bytes retain
  a rescue name, and uncertain state is never deleted.
- `32a5212` binds completion v2 to the published inode identity. A terminal
  retry returns its idempotent result only while the exact target Head,
  installed Version, published inode, sealed bytes, and executable fidelity all
  remain current. Identical bytes on a foreign inode are stale evidence.
- `d2aaf52` proved the previous positive crash case after both private names
  were absent. ADR 0005 now supersedes that terminal rule: a retained authority
  link is required.
- `4e3554c` requires the cleanup receipt's publication identity on every
  private and visible handle before mutation and before restored success.
- `3ea91ec` supersedes destructive private-link retirement with one bounded
  retained authority link. Capture validates exact per-path authority receipts
  and admits only `1 + N` links, where `N` is the exact count of validated
  Folderbase authorities. Same-inode edits remain capturable, an extra user
  hard link remains excluded, an old anchor cannot authorize a replacement,
  and the 4096-entry cap fails with typed maintenance required.
- `dbd7336` revalidates the retained authority pathname after both cleanup hook
  boundaries and requires the exact authority receipt and stage for terminal
  completion evidence.
- `f82b1ee` moves every cleanup hook and mutation before one final
  linearization proof. Immediately before any `Restored` result, Core
  revalidates the immutable transaction and target Version, target Head, exact
  completion and authority receipt bytes and paths, retained stage,
  destination identity, sealed bytes and length, and executable mode.
- `73edf47` carries the exact opened-handle link count and canonical sorted
  authority receipt/stage set from CapturePlan into the active journal.
  Sealing re-enumerates and revalidates that exact set immediately before and
  after every ordinary-file byte read. Extra links and same-count authority-set
  swaps fail without moving Head; an authority-bearing journal recovers after a
  fresh-process crash. Released journals keep byte-for-byte encoding and their
  exact Head-anchored SHA-256.
- `48a8957` proves a partial retained authority receipt fails closed during
  metadata-only planning before capture can move Local Head.
- `95e5609` keeps planning metadata-only for unreadable and sparse ordinary
  files: Unix derives identity and link count from no-follow directory
  metadata, Windows uses a zero-data-access metadata handle, and seal-time
  topology checks remain bound to the actual opened content handle.
- `5a7f4ac` gives released-v1 compatibility one exact encoder rather than
  accepting two digests. A plan with no retained authority links and an absent
  or capture-transaction-derived Head reproduces the released flat-Head v1
  digest byte-for-byte. A version-derived Head or authority-bearing plan uses
  typed v2. Genuine old pre-Head and post-Head journals converge on their
  original assigned Version and exact raw journal SHA.
- `375a3ea` preserves the bounded active journal's parsed wire kind and raw
  length. Released-v1 recovery preflights the exact already-bounded raw wire,
  its closed released schema, and all normalized semantic invariants instead
  of rejecting a larger typed reserialization that is never written. Current
  and newly assigned journals still pass the current bounded encoder.
- `2038d92` / `7acf3e0` close the released assignment schema independently of
  the current assignment type. A hybrid flat-Head journal carrying a
  current-only link commitment is rejected rather than bypassing current-wire
  preflight. The same regression preserves the original transaction ID, admits
  valid released JSON plus trailing whitespace at the actual 64 MiB raw bound,
  rejects one byte over and truncated JSON, and retains the separate
  raw-smaller-than-normalized recovery case.
- `35be1ca` locks the second exact authority-set revalidation after the
  `AfterObjectBytesRead` hook: a same-link-count receipt/stage swap fails without
  moving the restored Head.
- `87b6729` / `f1f6c1a` prove and remove the last planning-time content access
  for retained restore links. A restored 10 GiB sparse inode with mode `000`
  remains plannable with its exact authority commitment. Unix/macOS compare
  no-follow metadata identities; Windows uses zero-data-access no-follow
  handles and the complete File ID. Seal-time byte and opened-handle topology
  verification are unchanged.
- `03a9ac5` retains an exact target-parent capability across publication and
  multi-step restore observations, freshly reopens and identity-checks that
  parent before and after every success-relevant boundary, and refuses
  unresolved extra stage links with typed
  `RestoreNamespaceRepairRequired`. A post-link POSIX detach leaves only the
  exact operation-owned orphan, never touches a replacement directory, never
  moves the pre-publication Head, and never grows link topology on retry.
  Returning the moved parent to the intended path makes retry converge.
  Cleanup-time detach likewise preserves the forward Head plus durable recovery
  evidence and completes only after explicit repair. On Windows, the retained
  parent handle denies the equivalent directory rename.
- `5f894bf` performs a complete preliminary restore evidence proof, rebinds the
  released-root Local Head while holding the transaction lock, and then repeats
  the comprehensive proof as the last success-relevant operation. Final and
  terminal verification accept only the full recorded-root Head with
  independently derived recorded authority or the full current-root rebound
  Head with independently derived current authority. Both forms compare root,
  Folderbase ID, Version, digest, and authority exactly while leaving the
  immutable transaction, completion, and retained authority bytes unchanged.

The local threat boundary is intentionally KISS: `.folderbase/` is trusted
engine-owned state analogous to `.git/`. The regressions prove malformed or
partial record refusal, crash recovery, ordinary race and substitution safety,
and no-clobber behavior. They do not claim cryptographic authenticity against a
same-user process that deliberately forges every related local record into one
internally consistent state. Cloud authority is separately authenticated.

The transaction is same-path and no-clobber. A preexisting regular file,
directory, symlink, or dangling symlink is unchanged. Matching bytes are not
ownership evidence. Recovery accepts an already published target only when it
is the exact same filesystem object as the retained private stage.

The namespace claim is deliberately scoped. Core retains the exact workspace
parent identity and freshly reopens it from the attested root around every
publication and success boundary. A replacement path cannot receive the write
or be blessed. POSIX still permits an uncoordinated process to rename the exact
opened parent; the operation-owned hard link can travel with that directory.
Core leaves the durable stage and recovery record in place, refuses a new link
with typed repair-required, and never guesses at pathname deletion. Returning
the moved parent or explicitly removing the inspected orphan allows retry.
Windows blocks the detach while the retained parent handle is open. This slice
does not claim global namespace exclusion against arbitrary concurrent rename.

The current verified Head must contain an exact regular-file Tombstone. A
bounded, cycle-detecting ancestor DAG search selects the nearest live binding
with the same path, Object ID, and Object Version. Competing nearest bindings
must agree exactly, including executable fidelity. Missing, corrupt,
ambiguous, cyclic, or over-limit lineage fails before restore publication.
A nearer candidate cannot hide a deeper reachable cycle; a legitimate
convergent DAG is accepted.
Committed-Head recovery performs the same parent, Tombstone, binding,
assignment, and exact-child derivation as first execution; a coordinated
journal, Head, and installed-target rewrite alone is not recovery authority
under the trusted-local-state boundary.
The journal's copy of the prior Head transaction digest is not authority
either. Restore first binds the verified parent Head to an independently
derivable digest, and target-Head recovery rejects any replacement value even
when every journal-dependent ID and digest was recomputed consistently.

The mutable journal is not assignment authority. Transaction and target
Version IDs are deterministic domain-separated derivations of the verified
Head, Tombstone, binding, Folderbase, and physical root, while the timestamp is
re-derived from the verified parent. Final target identity, content, fidelity,
root attachment, and nested-boundary proofs run immediately before and after
Head CAS. Post-Head failure rolls the retained root back to its prior Head and
never reports restore success. Projection uses the already-retained state
capability. Cleanup records its obligation and published inode identity durably
before retiring mutable intent, rederives immutable cleanup authority, and
retains the transaction-unique stage without rename or unlink. Capture treats
that hard link as Folderbase-owned only when its bounded receipt, exact
workspace path, current stable identity, and private stage all revalidate and
no additional link exists. A separate bounded singleton completion receipt
never blocks capture and survives the terminal return boundary only as
conditional evidence: the exact target Head, installed Version, authority
receipt, retained stage, recorded inode, sealed bytes, and executable fidelity
must all still match. If the published transaction-owned file is edited in
place, Core preserves the edit, reports no false restore success, and permits
the next capture through that narrow authority exception. At 4096 retained
authorities, new Tombstone restore fails closed until a future explicit
maintenance protocol is available; this slice performs no automatic garbage
collection.

## Root identity continuity and migration unlink authority

- `628d219` retains the exact source and destination leaf identities, their
  parent identities, and one shared no-follow root capability through
  structural recovery. Immediately before unlink, Core reopens the exact
  destination parent from that root, reopens the destination parent-relative,
  and compares full identities. POSIX unlinks while child handles remain live.
  Windows releases only the child handles after final proof while retaining
  root and parent capabilities for the cooperative exact-name removal window.
  A deterministic same-byte destination substitution at that final boundary is
  refused and preserved with the journal still in flight.
- `e410460` leaves Unix root-instance V1 unchanged and makes new Windows roots
  use `folderbase-physical-root-instance-v2`, the complete 64-bit volume serial
  plus all 128 `FILE_ID_INFO` bits. Released Windows V1 remains an exact,
  in-memory compatibility authority rather than being redefined.
- Compatibility admission carries the exact recorded root into active capture
  plan digests, restore transaction and target identities, Head authority,
  rollback, cleanup, completion, and retained authority receipts. Immutable
  journals and receipts are never normalized or rewritten.
- Local Head is rebound only under the transaction lock after its immutable
  Version and digest verify and no pending work remains, after recovery retires
  pending work, or through the normal next Head CAS. Capture-transaction
  authority keeps the exact journal SHA; version-derived authority is
  recomputed. Pre-CAS and post-CAS process faults prove the only outcomes are an
  exact old-valid or new-valid Head.
- Restore success performs preliminary validation, the transaction-locked
  rebind, and then one comprehensive final proof. A crash immediately after the
  CAS is idempotently acknowledged on every identical retry from the exact
  current-root Head plus unchanged recorded-root receipts. Ordinary edits and
  same-byte inode substitution around the rebind fail the final proof and
  cannot return `Restored`.
- Released-root capture recovery reproduces the plan digest with the journal's
  recorded root before and after Head publication. Released-root restore
  recovery converges across all 12 post-journal durability boundaries while
  retaining exact cleanup, completion, and authority bytes and digests.
- Fixed vectors independently preserve Unix V1 and distinguish Windows V2
  identities that collided under the released truncation. The native Windows
  integration encoder queries `FILE_ID_INFO` directly rather than calling the
  production identity helper.
- V1 compatibility is explicitly trusted-local TOFU: a released record cannot
  prove upper identity bits it never stored. Once a Head records V2, a
  different full identity is rejected. Neither identity format grants portable
  or Cloud authority.

## Gates

The frozen implementation passed:

```text
cargo fmt --all -- --check
git diff --check

cargo test --workspace --all-features --locked
657 passed; 3 ignored

cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
passed

RUSTDOCFLAGS="-D warnings" \
  cargo doc --workspace --all-features --no-deps --locked
passed

RUSTFLAGS="-D warnings" \
  cargo check -p folderbase-core --lib \
  --target x86_64-pc-windows-msvc --locked --all-features
passed

RUSTFLAGS="-D warnings" \
  cargo check -p folderbase-core --lib \
  --target aarch64-unknown-linux-gnu --locked --all-features
passed

bash scripts/test-package-install.sh
passed; Core packaged 57 files, CLI packaged 10 files, extracted package
tests passed, and the fresh release install reported folderbase 0.4.0

bash scripts/check-ci-policy.sh
passed

bash scripts/check-public-eclipse.sh
passed

node scripts/verify-folderbase-version-distribution.mjs
passed; 32 files

node scripts/verify-folderbase-version-digest-vectors.mjs
passed

node scripts/verify-reorganization-digest-vector.mjs
passed
```

The Windows and Linux commands are compile checks. Runtime proof on those
platforms remains owned by the repository CI matrix.

## Claims and nonclaims

This slice claims exact no-clobber restore only for a current-Head
regular-file Tombstone whose nearest verified live ancestor preserves the v1
binding. It preserves opaque bytes and the v1 executable boolean. It does not
claim complete POSIX mode, ACL, xattr, Finder metadata, database snapshot
coordination, directory restore, symlink restore, arbitrary-destination
checkout, Remote Head, sync, sharing, authorization, Cloud durability, or
hosted deployment.

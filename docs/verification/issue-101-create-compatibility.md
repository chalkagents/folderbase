# Issue #101: creation compatibility boundary

Expected-absent creation is an unreleased experimental operation. A shared
same-build writer lease protects its independently versioned pending intent.
Released older writers do not recognize that intent; this is not a downgrade
fence, and completed creation does not make mixed-version writers supported.

## Observed released-writer behavior

A 30-case macOS arm64 experiment ran the official
[0.7.2 executable](https://github.com/chalkagents/folderbase/releases/tag/v0.7.2)
at six creation phases: durable intent, durable stage, visible link, mutable
projection, durable receipt, and completed cleanup. The five older operations
were unrelated per-file capture/save, whole capture through public checkout,
and selected-file capture/save. The executable matched the release checksum:

`526b34d3dd86b98197779e0d7d80a30cd426b09e465c5ca2ee2fbf1b3246e1b6`

| Observation | Consequence |
| --- | --- |
| Older unrelated capture/save and whole capture succeeded with a pending create. | The new pending namespace does not fence 0.7.2. |
| Older selected capture/save succeeded once the ordinary file was linked. | A current retry can refuse changed identity/content; it cannot promise transparent mixed-writer recovery. |
| After a durable receipt, a later ordinary edit survived original-result replay. | A creation receipt reports historical completion, not current bytes. |
| Older whole capture after completed creation introduced a second selected-path Object claim. | Mixed-version writers remain unsupported after completion. Do not silently repair those duplicate records. |

This experiment used an initial implementation binary with SHA-256
`a5b73b0c9f2d7b8aeda61f1c4a40fd00cbf980e5826925391844cc48947f30ff`.
It establishes the released writer's compatibility limit; it is not a final
candidate release receipt. Final candidate tests separately exercise the
same-build coordinator and identity-preserving capture integration.

## Required final proofs

The creation unit suite interrupts real child processes at the immutable blob,
intent, Version, unpinned/pinned stage, visible publication, projection, journal,
receipt and cleanup joins. Each requested phase must be observably reached.
The stage-copy failure test preserves ambiguous pre-pin artifacts; retry cannot
adopt or delete them merely because bytes match. Existing receipt replay retains
later ordinary edits or deletion while completing exact owned-stage cleanup.

Recreation checks cover three generations with immediate metadata-only history
and CAS before whole capture, exact original-Version recovery, and unchanged
separate retired Object histories. Wrong/missing/copied-authority receipts,
original-Version changes, new pending work and changed receipt inventories
refuse. A current directory binding with older file claimants must be captured
as removed before recreation can proceed. The installed SDK package exercises
the named binary-safe creation helper through the same public workflow.

These are local correctness checks. They do not establish customer demand,
cloud reliability, a multi-file transaction, or a stronger filesystem isolation
guarantee than Core's existing cooperative-writer contract.

# Folderbase folder-scope-evidence 0.1 conformance

Run the independent black-box suite against an executable:

```sh
node protocol/conformance/capabilities/folder-scope-evidence-0.1/run.mjs \
  --implementation /absolute/path/to/folderbase
```

The eleven-case suite uses disposable ordinary folders and the public process
contract. It verifies capability discovery, closed bounded JSON, replay,
multiple-folder selection, non-genesis Local Head progress, stale-observation
refusal, rename continuity, selected and root replacement refusal, exact
nested-boundary identity, cross-platform escaping-link refusal, unsupported
nodes, crash recovery, and the closed aggregate journal namespace.

Two reserved test-only environment seams make otherwise nondeterministic
durability edges reproducible:

- `FOLDERBASE_FOLDER_SCOPE_CONFORMANCE_ADVANCE_HEAD_AFTER_PLAN=1` advances the
  fixture's Local Head after the candidate's first plan; and
- `FOLDERBASE_FOLDER_SCOPE_CONFORMANCE_CRASH_AFTER=event-publication` exits
  after the exact event is durable and before journal Head publication.

They exist only for this disposable conformance runner and are not product
interfaces, sharing authority, or App behavior.

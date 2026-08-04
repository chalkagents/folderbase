# ADR-0013: Run root-pinned query sessions over stdio JSON Lines

## Status

Accepted

## Context

The App, local agents, scripts, and remote VM agents need a long-lived Core
session so they can query one active Folderbase, learn that its ordinary files
changed, and refresh disposable query acceleration without repeatedly inventing
their own watchers or scanners. The same operation must behave on macOS, Linux,
and Windows and must remain usable in a terminal, child process, container, or
ephemeral agent VM.

Core already has the authoritative live observation and historical query
semantics accepted in ADR-0011. It also has root attestation, bounded process
documents, immutable Folderbase Versions, and separately advertised Change Set
mutations. A daemon that implements another filesystem walk, index format,
mutation path, permission system, or network service would become a second
engine and eventually disagree with one-shot Core.

Operating-system filesystem notifications are lossy hints. They may be
duplicated, reordered, coalesced, delayed, or dropped. They cannot prove the
current contents of a Folderbase and must never become portable history.

## Decision

### One deep session module

The daemon is the separately advertised experimental capability
`folderbase.daemon-stdio@0.1.0`. Its external seam is one explicit process
invocation and two closed JSON Lines document families:

- `folderbase daemon serve ROOT --stdio-jsonl`;
- `folderbase-daemon-request-v1`; and
- `folderbase-daemon-message-v1`.

The module owns process lifetime, bounded framing, root pinning, filesystem
notification coalescing, subscriptions, and delegation to the released query
capability. Callers do not configure watcher backends, debounce algorithms,
private index paths, or recovery state. Removing this module would force every
caller to reimplement those behaviors, so the module earns its seam.

The capability package, schema, and independent suite live under:

- `protocol/capabilities/daemon-stdio/0.1.0/`;
- `protocol/schemas/capabilities/daemon-stdio/0.1/`; and
- `protocol/conformance/capabilities/daemon-stdio-0.1/`.

The capability does not expand Compatibility Contract v1, CLI JSON v1, or the
immutable protocol 0.5 release closure. It must not be advertised until its
complete public suite passes.

### Stdio is transport, not authority

Version 0.1 uses newline-delimited UTF-8 JSON over standard input and standard
output. It opens no TCP port, Unix socket, named pipe, launch agent, background
service, or ambient discovery path. The parent process starts one session with
one explicit root and owns its lifetime. Input EOF, a valid shutdown request,
or parent termination ends the session.

The root argument is the authority ceiling. Startup performs exact root
attestation and pins the physical Root Instance and Folderbase ID. Every
operation re-attests before use. Replacing the directory, crossing an alias, or
changing the Folderbase identity fails closed and makes the session terminal.
A legitimate manifest revision inside the same physical root does not by
itself create a new authority boundary; the delegated Core operation validates
the new manifest under its own contract.

The initial message is `ready` and names only the capability selector, daemon
epoch, Folderbase ID, physical Root Instance digest, and display root. It is not
a credential and does not grant authority to another root. A process that
cannot attest the root emits one bounded terminal error on stderr and exits 2
without entering the session.

### Closed request operations

Each input line is exactly one request with a caller-selected request ID and
one operation:

- `query` carries one `folderbase-query-request-v1` document;
- `explain` carries the same query request;
- `index_status` carries no operation payload;
- `refresh` carries no operation payload and explicitly rebuilds only the
  disposable private query index;
- `subscribe` enables coalesced workspace-change hints;
- `unsubscribe` disables those hints; and
- `shutdown` returns an acknowledgement and ends the process.

Unknown fields, unknown operations, duplicate request IDs still in flight,
malformed JSON, non-UTF-8 input, and frames beyond 4 MiB return a typed request
error. One bad bounded frame does not corrupt later framing. An oversized line
is drained through its newline before the error is emitted, with no unbounded
allocation.

Every output line is one `folderbase-daemon-message-v1` document of kind
`ready`, `response`, or `event`, bounded to 8 MiB. A response repeats the exact
request ID and carries status `ok`, `attention`, or `error`. Query, explain,
index status, and refresh delegate through the existing query-capability
adapter; their inner document is the exact closed document that the equivalent
one-shot command would return. The daemon does not reinterpret its fields or
exit taxonomy. Interleaved events never split or corrupt a response line.

Only one request executes at a time in v0.1. This gives deterministic ordering
and prevents competing private-index rebuilds. The parent can cancel any active
operation by terminating the child process; after restart the daemon performs
fresh root attestation and authoritative observation. Version 0.1 does not
claim cooperative mid-operation cancellation.

### Notifications are bounded freshness hints

The Rust adapter uses the stable cross-platform `notify` implementation, but
the watcher library and backend are not part of the portable interface. A
filesystem event may only mark the session dirty. It cannot add, remove, or
change a query row, Version, Object, permission, or portable record.

At most one `workspace_changed` event remains outstanding. Duplicate,
out-of-order, or burst events coalesce into that hint. The event contains the
daemon epoch and one monotonically increasing sequence, but no changed paths,
file bytes, provider locations, credentials, or inferred semantic meaning.
Events caused only by `.folderbase/local/query-index-v1/**` are ignored so an
explicit refresh cannot trigger a self-sustaining loop.

A successful query, explain, index-status, or refresh response acknowledges
only the dirty state observed before that operation began. An event arriving
during the operation remains pending. A subscriber must therefore treat a
response as one verified observation and an event as an instruction to ask
Core again, never as a patch to that observation.

Watcher setup failure, queue overflow, backend rescan flags, or any suspected
event loss emits one coalesced `rescan_required` event. The daemon remains
usable because the next delegated operation obtains authoritative state. A
client that disconnects or restarts receives no replayed event history; it
must issue a new query or refresh after the new `ready` message.

### One-shot equivalence and mutation ownership

For the same attested root and request bytes, a daemon query or explanation
must have the same success, attention, or error meaning and the same inner JSON
document as the equivalent one-shot query capability. A missing, stale,
corrupt, or deleted private index follows ADR-0011: Core falls back to the same
bounded authoritative observation. The daemon stores no authoritative
checkpoint and writes no portable record.

The daemon does not proxy initialization, capture, restore, template,
reorganization, migration, checkout, Change Set, permission, sync, or Cloud
mutations in v0.1. Those operations already have released CLI or capability
interfaces and their own transaction guarantees. A caller runs the appropriate
Core command; the root-pinned daemon observes the resulting filesystem change
as a hint and the next query revalidates it. This keeps one mutation engine and
prevents the session interface from becoming a second CLI.

### Crash, restart, and conformance

Daemon-private runtime state is disposable. A crash may lose subscriptions,
event sequence, and dirty hints, but cannot lose or partially publish ordinary
files, portable records, Folderbase Versions, or query truth because the daemon
owns none of them. Restart creates a new epoch, re-attests the root, and serves
authoritative operations without needing recovery files.

The independent suite starts a regular candidate executable without a shell,
uses only temporary ordinary folders, and proves:

- ready attestation and explicit-root confinement;
- byte-for-byte one-shot equivalence for query, explain, status, and refresh;
- create, edit, move, delete, and burst-event convergence;
- duplicate, reordered, coalesced, and lost-event safety;
- missing, stale, corrupt, and deleted private-index fallback;
- nested Folderbase isolation and physical-root replacement rejection;
- bounded malformed, non-UTF-8, oversized, and noisy frames;
- subscribe, unsubscribe, EOF, shutdown, forced termination, and restart; and
- edits made while the daemon is down becoming visible after restart.

The suite applies finite startup, per-response, output, and process-tree cleanup
bounds on Linux, macOS, and Windows. Watcher timing assertions wait for eventual
hints only; correctness assertions always use an explicit query or refresh and
never depend on event count or order.

## Consequences

- The App and agents get one long-lived, cross-platform freshness interface
  without learning platform watcher details.
- One-shot CLI behavior remains the universal integration baseline and the
  daemon is provably an acceleration/session adapter rather than a second
  engine.
- Ordinary files of every type remain authoritative and local-first.
- Stdio works unchanged in local child processes, containers, and remote agent
  VMs; hosted transport and authentication can wrap it later without changing
  Core query semantics.
- Clients must re-query after hints and reconnect after daemon loss.
- Version 0.1 deliberately omits network listening, background installation,
  mutation proxying, path-level events, cooperative request cancellation,
  Cloud sync, and hosted permissions.

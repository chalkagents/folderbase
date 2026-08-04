# ADR-0014: Integrate through supervised public process contracts

## Status

Accepted

## Context

Folderbase Core is intended to work in native apps, Node services, scripts,
containers, and short-lived remote agent VMs. Compatibility Contract v1 and
the separately advertised query, template, Change Set, and daemon capabilities
already define bounded JSON process interfaces. Reimplementing those semantics
inside every language adapter would create protocol forks, teach integrations
to interpret engine-owned `.folderbase` state, and make a Swift or TypeScript
consumer behave differently from the released executable.

Raw child-process handling is still easy to get wrong. Callers otherwise need
to repeat cancellation, process-tree cleanup, stdin and output bounds, JSON
framing, exit-code classification, capability discovery, and daemon lifecycle
logic. That repetition is adoption friction for both local apps and remote
agents.

## Decision

### The executable remains the universal integration seam

Language adapters invoke an explicit `folderbase` executable without a shell.
They consume only public stdout, stderr, exit codes, CLI JSON documents,
capability discovery, and daemon JSON Lines. They never read, write, infer, or
cache engine-owned `.folderbase` records directly.

An adapter is not an alternative Core implementation. It owns process
supervision and transport ergonomics while Core continues to own filesystem
authority, validation, queries, transactions, recovery, Versions, templates,
and Change Sets. Removing an adapter must leave every operation available
through the documented executable.

### Start with one dependency-light TypeScript package

The first adapter is `@folderbase/sdk`. It is an ESM package with no runtime
dependencies and a Node.js baseline matching `@folderbase/cli`. It provides:

- a bounded one-shot process client;
- typed success, attention, operational-error, malformed-output, spawn, and
  cancellation outcomes;
- helpers for capability discovery, base CLI JSON, query/index, template, and
  Change Set commands;
- one root-pinned daemon session client with serial requests and event
  subscriptions; and
- caller-supplied executable, argument prefix, environment, timeout, and abort
  controls for local binaries, `npx`, containers, and test harnesses.

The adapter preserves each parsed public document as a complete JSON object.
Known discriminants receive useful TypeScript types, while unknown additive
fields remain present at runtime and do not make compatible consumers fail.
Experimental closed capability envelopes may still reject malformed outer
framing according to their own advertised schemas.

The package does not bundle a native binary. A caller may install
`@folderbase/cli`, use a GitHub binary, Cargo, Homebrew, or provide another
conforming implementation. This keeps distribution, compatibility, and
transport independently replaceable.

### Supervision is bounded and fail-closed

One-shot input, stdout, and stderr have small defaults and hard ceilings. A
timeout, abort, malformed JSON document, noisy success stderr, unexpected exit,
or output overflow terminates the complete child process tree and returns a
typed adapter failure. Exit `0` is success, exit `1` is attention, and exit `2`
is an operational error under the public contracts; the adapter does not parse
human messages as authority.

Daemon output is decoded one bounded line at a time. Only one request is active
per session because daemon 0.1 is serial. Request cancellation terminates that
session rather than pretending the daemon supports cooperative mid-operation
cancellation. Events are freshness hints and never patches. EOF, shutdown,
root replacement, malformed framing, and process loss make the session
terminal and reject pending work.

### Native clients use the same seam

Swift and other native clients should launch the released executable with
explicit arguments, bounded pipes, and structured concurrency cancellation.
They first call `protocol contract --json`, select only advertised
capabilities, and treat daemon events as re-query hints. A native app must not
link private Rust internals or interpret `.folderbase` state to gain a second
semantic path.

### Adoption proof is outside the maintainer checkout

The SDK archive is packed, installed into a clean temporary consumer, and run
against an exact candidate executable. Public conformance is exercised through
the adapter transport, and one mixed ordinary-folder journey covers init,
query, template expansion, scoped Change Sets, and daemon restart. Fixtures
also prove attention, malformed output, unknown additive fields, cancellation,
output limits, and process cleanup.

The SDK and clean-consumer proof run inside existing path-scoped CI jobs. They
must not add a permanent cross-platform PR matrix. Exact packaged/native
cross-platform proof remains part of the existing post-merge and release
gates.

## Consequences

- Codex, Claude, remote VMs, Node apps, and the Folderbase App can share one
  public semantic contract.
- The SDK removes process boilerplate without becoming another database
  engine.
- Independent Go, TypeScript, Swift, or other implementations remain possible
  because conformance targets the executable contract, not this SDK.
- Consumers must install or provide a compatible executable separately.
- A daemon request abort ends its session in capability version 0.1.
- Adding another language adapter requires supervision and conformance proof,
  not a new storage or protocol interpretation.

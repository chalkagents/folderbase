# `folderbase.daemon-stdio@0.1.0`

This optional capability defines one root-pinned, long-lived Core session over
newline-delimited JSON on standard input and standard output.

It guarantees:

- exact delegation to the advertised query/index capability;
- one explicit, re-attested Folderbase root per process;
- bounded requests, responses, events, and process lifetime;
- coalesced filesystem-change hints that never become query authority; and
- restart safety with no daemon-owned portable or authoritative state.

It does not define a network daemon, background installation, Cloud transport,
permission grant, sync protocol, or mutation interface.

Run its implementation-neutral suite from a source checkout:

```sh
node protocol/conformance/capabilities/daemon-stdio-0.1/run.mjs \
  --implementation /absolute/path/to/folderbase
```

The candidate must also implement and advertise
`folderbase.query-index@0.1.0` because daemon operation results are the exact
inner documents from that capability.

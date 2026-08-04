# Daemon stdio 0.1 conformance

This dependency-free black-box suite verifies the optional
`folderbase.daemon-stdio@0.1.0` process contract. It treats filesystem events as
lossy hints and proves correctness only through authoritative query/index
responses.

```sh
node protocol/conformance/capabilities/daemon-stdio-0.1/run.mjs \
  --implementation /absolute/path/to/folderbase
```

The report is `folderbase-capability-suite-report-v1`. Passing requires every
case to pass. The suite creates and removes only its own temporary roots.

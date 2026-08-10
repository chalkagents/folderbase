# Folderbase folder-scope-evidence 0.1 conformance

Run the independent black-box suite against an executable:

```sh
node protocol/conformance/capabilities/folder-scope-evidence-0.1/run.mjs \
  --implementation /absolute/path/to/folderbase
```

The suite uses only ordinary temporary folders and the public process contract.
It verifies capability discovery, closed bounded JSON, replay, multiple folder
selection, rename continuity, replacement refusal, nested-boundary isolation,
root replacement, unsafe selection, and mixed opaque file types.

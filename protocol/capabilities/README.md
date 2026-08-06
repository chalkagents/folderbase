# Folderbase capability profiles

Capability profiles let post-0.5 implementations advertise optional command
families without changing the frozen Compatibility Contract v1 minimum or the
published protocol 0.5 release closure.

The v1 registry is [`v1/registry.json`](v1/registry.json). Its schema is
[`../schemas/capabilities/1/registry.schema.json`](../schemas/capabilities/1/registry.schema.json).
Every known entry fixes:

- one exact lowercase capability name;
- one exact semantic version;
- `stable` or `experimental` stability; and
- one implementation-neutral black-box conformance runner.

The registry is canonically ordered by `name@version`. The reference CLI has a
separate embedded advertisement registry and returns only `name`, `version`,
and `stability` in the additive `capabilities` field of `folderbase protocol
contract --json`. A stable public package may become known to the selector
before it is copied into that executable registry. This is the fail-closed RED
state: explicit selection reports that the capability is not advertised, and
the executable must not copy the entry until its public black-box suite passes.

The mandatory `folderbase-cli-json-v1` base suite is not an optional
capability and is never placed in this registry.

An absent field is valid for an unchanged Compatibility v1 implementation and
means it advertises no optional profiles. Unknown advertisements are ignored
unless explicitly requested. A requested known-but-unadvertised profile and a
known advertisement whose suite fails both fail closed.

See [`../conformance/capabilities/`](../conformance/capabilities/) for the
public selector and suites, and
[`../../docs/adr/0010-discover-optional-capabilities-without-expanding-base-v1.md`](../../docs/adr/0010-discover-optional-capabilities-without-expanding-base-v1.md)
for the decision.

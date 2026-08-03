# ADR-0010: Discover optional capabilities without expanding base v1

## Status

Accepted

## Context

Compatibility Contract v1 deliberately freezes a small independently
implementable minimum. Query, template, Change Set, daemon, and later Core
interfaces need their own evolution paths. Adding each new command to the v1
minimum would make a previously conformant Go, TypeScript, or older Rust
implementation fail conformance even when no caller needs the new interface.

Apps and agents must still be able to determine support without parsing help
text, guessing from package SemVer, or optimistically invoking a mutation.
Discovery also needs to distinguish a stable profile from an experimental one
and bind a known advertisement to an independently runnable suite.

## Decision

`folderbase protocol contract --json` may include the additive `capabilities`
array defined by CLI JSON v1. Its absence means that the implementation makes
no optional capability advertisement; absence does not invalidate a base v1
claim.

Each entry contains exactly the machine identity needed for selection:

- `name`: a lowercase dotted capability name;
- `version`: one exact semantic version, never a range; and
- `stability`: `stable` or `experimental`.

Entries are unique and sorted by the literal `name@version` selector. The
implementation-neutral registry at
`protocol/capabilities/v1/registry.json` owns every known name, version,
stability label, and black-box conformance runner. The CLI embeds an exact copy
of that registry so discovery does not depend on a checkout at runtime.

The public capability runner applies these rules:

1. no selector runs every known profile advertised by the candidate;
2. an old v1 candidate with no `capabilities` field selects nothing and passes;
3. an unknown advertised profile is ignored unless a caller requests it;
4. explicitly requesting an unknown profile is a runner error;
5. explicitly requesting a known but unadvertised profile fails closed; and
6. advertising a known profile requires its registered black-box suite to pass.

The mandatory `folderbase-cli-json-v1` interface remains outside optional
capability selection. `folderbase.version-cli-json@0.1.0` is an experimental profile:
its suite proves the advertised behavior, but its shapes do not become part of
the base v1 compatibility promise.

## Consequences

- The v1 minimum command inventory, required fields, profiles, error meanings,
  and exit meanings do not change.
- New capabilities can ship behind exact profiles without making old v1
  implementations nonconformant.
- Stable capability profiles carry their own compatibility promise and suite;
  `stable` does not silently expand base v1.
- Experimental profiles are honestly discoverable and testable without being
  frozen prematurely.
- Clients must tolerate additive capability-entry fields and unknown profiles,
  but must fail closed when a capability they explicitly require is absent.
- Capability registry changes are normative protocol changes and require the
  full verification and released-source closure.

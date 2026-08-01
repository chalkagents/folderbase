# Folderbase CLI JSON v1

Folderbase CLI JSON v1 is the stable integration surface for local agents,
remote VMs, scripts, desktop apps, and third-party implementations.

## Discoverability

```sh
folderbase protocol contract --json
```

The response identifies `folderbase-compatibility-contract-v1`, contract
version `1.0.0`, `folderbase-cli-json-v1`, and the exact supported protocol
profiles. Consumers should fail closed when they require a contract the binary
does not advertise.

## Stable commands

- `inspect PATH --json`
- `attest PATH --json`
- `init PATH --dry-run --json`
- `init PATH --expected-plan-digest DIGEST --json`
- `validate PATH --level shallow --json`
- `protocol contract --json`
- `protocol check chunk-manifest --stdin --json`
- `protocol check folderbase-version --stdin --json`
- `workspace list ROOT --json`
- `workspace read ROOT PATH --json`
- `workspace save ROOT PATH --expected-sha256 DIGEST --stdin --json`

Other command JSON is experimental until a later contract names it.

## Transport rules

Successful and attention-required results emit exactly one JSON document on
stdout and leave stderr empty. Operational failures leave stdout empty and emit
exactly one JSON document on stderr:

```json
{
  "error": {
    "code": "invalid_root",
    "message": "..."
  }
}
```

The error object is closed in v1. Error codes are stable machine identifiers;
messages are explanatory and must not be parsed. Command-line syntax errors are
produced by the argument parser before a command is selected and are outside
CLI JSON v1.

The canonical machine-readable error-code inventory is
`cli_json.error_codes` in the
[`folderbase-compatibility-contract-v1`](../protocol/compatibility/v1/contract.json).
Its current codes fall into these groups:

- root and manifest attestation (`root_*`, `marker_*`, `manifest_*`,
  `invalid_folderbase_id`, protocol profile/receipt codes, and
  `attestation_io`);
- reviewed initialization and upgrade (`plan_*`, `initialization_*`,
  `protocol_upgrade_*`, and `recovery_required`);
- workspace and version safety (`unsafe_path`, `workspace_content_changed`,
  restore/tombstone/transaction codes, and `capture_error`);
- migration and template safety (`migration_*`, `would_overwrite`,
  `unsupported_migration_filesystem`, and template approval codes); and
- generic transport/runtime failures (`invalid_root`, `invalid_record`,
  `io_error`, `json_error`, and `output_serialization`).

Existing code meanings are stable. Later compatible releases may add codes, so
consumers must preserve unknown codes and treat them as operational failures
according to the exit status.

Exit statuses are:

- `0`: the requested operation completed successfully;
- `1`: the command completed with a valid result requiring attention, such as
  a failed validation or rejected conformance artifact; and
- `2`: an operational or domain error prevented a result.

## Schema evolution

The public schema is
[`../protocol/schemas/cli/1/folderbase-cli-json.schema.json`](../protocol/schemas/cli/1/folderbase-cli-json.schema.json).
Result objects are command-specific and unwrapped. Required fields and their
types and meanings are stable. Implementations and consumers must tolerate
additional object fields. Array ordering is significant. Removing, renaming,
or changing a required field is breaking and requires a later selected
interface.

The caller knows which result definition applies because it selected the
command. This keeps v1 small and preserves the flat five-field attestation
receipt.

use std::path::Path;

use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn public_runner_accepts_the_reference_cli_through_only_its_process_interface() {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let runner = repository.join("protocol/conformance/cli-json-v1/run.mjs");
    let implementation = assert_cmd::cargo::cargo_bin!("folderbase");

    Command::new("node")
        .arg(runner)
        .arg("--implementation")
        .arg(implementation)
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "\"format\": \"folderbase-conformance-report-v1\"",
        ))
        .stdout(predicate::str::contains("\"protocol_cases\": 96"))
        .stdout(predicate::str::contains("\"passed\": 108"))
        .stdout(predicate::str::contains("\"failed\": 0"));
}

#[test]
fn capability_runner_executes_every_known_profile_advertised_by_the_reference_cli() {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let runner = repository.join("protocol/conformance/capabilities/run.mjs");
    let implementation = assert_cmd::cargo::cargo_bin!("folderbase");

    Command::new("node")
        .arg(runner)
        .arg("--implementation")
        .arg(implementation)
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "\"format\": \"folderbase-capability-conformance-report-v1\"",
        ))
        .stdout(predicate::str::contains("\"selected\": 1"))
        .stdout(predicate::str::contains("\"passed\": 1"))
        .stdout(predicate::str::contains("\"failed\": 0"));

    Command::new("node")
        .arg(repository.join("protocol/conformance/capabilities/run.mjs"))
        .arg("--implementation")
        .arg(implementation)
        .args(["--capability", "folderbase.version-cli-json@0.1.0"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "\"requested\": [\n    \"folderbase.version-cli-json@0.1.0\"",
        ))
        .stdout(predicate::str::contains("\"failed\": 0"));
}

#[test]
fn query_index_runner_accepts_the_reference_cli_through_only_its_process_interface() {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let runner = repository.join("protocol/conformance/capabilities/query-index-0.1/run.mjs");
    let implementation = assert_cmd::cargo::cargo_bin!("folderbase");

    Command::new("node")
        .arg(runner)
        .arg("--implementation")
        .arg(implementation)
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "\"format\": \"folderbase-capability-suite-report-v1\"",
        ))
        .stdout(predicate::str::contains(
            "\"capability\": \"folderbase.query-index@0.1.0\"",
        ))
        .stdout(predicate::str::contains("\"passed\": 22"))
        .stdout(predicate::str::contains("\"failed\": 0"));
}

use assert_cmd::Command;
use predicates::prelude::*;

fn folderbase() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("folderbase"))
}

const MINIMAL_FOLDERBASE_VERSION: &[u8] =
    include_bytes!("fixtures/protocol/minimal-folderbase-version-0.5.json");
const UNKNOWN_CHUNK_MANIFEST_FORMAT: &[u8] =
    include_bytes!("fixtures/protocol/unknown-chunk-manifest-format.json");

#[test]
fn protocol_contract_discovers_the_stable_machine_interface() {
    folderbase()
        .args(["protocol", "contract", "--json"])
        .assert()
        .success()
        .stderr(predicate::str::is_empty())
        .stdout(predicate::str::contains(
            "\"format\": \"folderbase-compatibility-contract-v1\"",
        ))
        .stdout(predicate::str::contains("\"contract_version\": \"1.0.0\""))
        .stdout(predicate::str::contains(
            "\"cli_json\": \"folderbase-cli-json-v1\"",
        ));
}

#[test]
fn protocol_check_validates_and_digests_a_folderbase_version_from_stdin() {
    folderbase()
        .args([
            "protocol",
            "check",
            "folderbase-version",
            "--stdin",
            "--json",
        ])
        .write_stdin(MINIMAL_FOLDERBASE_VERSION)
        .assert()
        .success()
        .stderr(predicate::str::is_empty())
        .stdout(predicate::str::contains(
            "\"artifact\": \"folderbase-version\"",
        ))
        .stdout(predicate::str::contains("\"valid\": true"))
        .stdout(predicate::str::contains(
            "29c6ae619019c419ea44e8f3bd67f495e5ecb2337b5b1f0f3b14411dafbd99ba",
        ));
}

#[test]
fn protocol_check_reports_an_invalid_chunk_manifest_as_a_json_attention_result() {
    folderbase()
        .args(["protocol", "check", "chunk-manifest", "--stdin", "--json"])
        .write_stdin(UNKNOWN_CHUNK_MANIFEST_FORMAT)
        .assert()
        .code(1)
        .stderr(predicate::str::is_empty())
        .stdout(predicate::str::contains("\"artifact\": \"chunk-manifest\""))
        .stdout(predicate::str::contains("\"valid\": false"))
        .stdout(predicate::str::contains("\"code\": \"invalid_artifact\""));
}

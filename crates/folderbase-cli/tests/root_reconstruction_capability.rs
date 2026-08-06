use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::Value;

const VALID_REQUEST: &str = r#"{"format":"folderbase-root-reconstruction-request-v1","operation_id":"reconstruction_019f0000-0000-7000-8000-000000000001","package_index_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
"#;

#[test]
fn reconstruction_rejects_relative_package_authority() {
    let temporary = tempfile::tempdir().unwrap();
    let assert = Command::new(assert_cmd::cargo::cargo_bin!("folderbase"))
        .arg("reconstruct")
        .arg("relative-source")
        .arg(temporary.path().join("destination"))
        .args(["--stdin", "--json"])
        .write_stdin(VALID_REQUEST)
        .assert()
        .code(2)
        .stdout(predicate::str::is_empty());

    let document: Value = serde_json::from_slice(&assert.get_output().stderr).unwrap();
    assert_eq!(document["error"]["code"], "unsafe_package");
}

#[test]
fn reconstruction_rejects_relative_destination_authority() {
    let temporary = tempfile::tempdir().unwrap();
    let assert = Command::new(assert_cmd::cargo::cargo_bin!("folderbase"))
        .arg("reconstruct")
        .arg(temporary.path().join("source"))
        .arg("relative-destination")
        .args(["--stdin", "--json"])
        .write_stdin(VALID_REQUEST)
        .assert()
        .code(2)
        .stdout(predicate::str::is_empty());

    let document: Value = serde_json::from_slice(&assert.get_output().stderr).unwrap();
    assert_eq!(document["error"]["code"], "unsafe_destination");
}

#[test]
fn reconstruction_requires_the_exact_process_flags() {
    let temporary = tempfile::tempdir().unwrap();
    let assert = Command::new(assert_cmd::cargo::cargo_bin!("folderbase"))
        .arg("reconstruct")
        .arg(temporary.path().join("source"))
        .arg(temporary.path().join("destination"))
        .arg("--stdin")
        .write_stdin(VALID_REQUEST)
        .assert()
        .code(2)
        .stdout(predicate::str::is_empty());

    let document: Value = serde_json::from_slice(&assert.get_output().stderr).unwrap();
    assert_eq!(document["error"]["code"], "invalid_invocation");
}

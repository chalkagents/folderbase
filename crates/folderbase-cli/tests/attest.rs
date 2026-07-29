use std::fs;

use assert_cmd::Command;
use predicates::prelude::*;

const FOLDERBASE_ID: &str = "folderbase_019f9b75-4f42-7f65-a012-2bfecdd8c473";
const MANIFEST_SHA256: &str = "29a1ad6f2d1c5591b35951a39bc38603728527f8be808510f080db1922c3f8be";
const MANIFEST: &[u8] = br#"{
  "protocol_version": "0.2.0+attestation",
  "folderbase": {
    "id": "folderbase_019f9b75-4f42-7f65-a012-2bfecdd8c473"
  }
}
"#;

fn folderbase() -> Command {
    Command::cargo_bin("folderbase").expect("folderbase executable")
}

fn valid_root() -> tempfile::TempDir {
    let root = tempfile::tempdir().expect("root");
    fs::create_dir(root.path().join(".folderbase")).expect("state");
    fs::write(root.path().join(".folderbase/manifest.json"), MANIFEST).expect("manifest");
    fs::write(root.path().join("FOLDERBASE.md"), b"# Folderbase\n").expect("entry");
    root
}

#[test]
fn attest_json_emits_the_flat_public_receipt() {
    let root = valid_root();
    let assertion = folderbase()
        .args([
            "attest",
            root.path().to_str().expect("UTF-8 root"),
            "--json",
        ])
        .assert()
        .success()
        .stderr(predicate::str::is_empty());

    let value: serde_json::Value =
        serde_json::from_slice(&assertion.get_output().stdout).expect("receipt JSON");
    let object = value.as_object().expect("flat JSON object");
    assert_eq!(object.len(), 5);
    assert_eq!(value["root"], root.path().to_string_lossy().as_ref());
    assert_eq!(value["folderbase_id"], FOLDERBASE_ID);
    assert_eq!(value["protocol_version"], "0.2.0+attestation");
    assert_eq!(value["manifest_sha256"], MANIFEST_SHA256);
    assert!(
        value["root_instance_sha256"]
            .as_str()
            .is_some_and(|digest| digest.len() == 64
                && digest
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()))
    );
}

#[test]
fn attest_human_output_names_the_same_evidence() {
    let root = valid_root();

    folderbase()
        .args(["attest", root.path().to_str().expect("UTF-8 root")])
        .assert()
        .success()
        .stderr(predicate::str::is_empty())
        .stdout(predicate::str::contains(format!(
            "Attested Folderbase root: {}",
            root.path().display()
        )))
        .stdout(predicate::str::contains(format!(
            "Folderbase ID: {FOLDERBASE_ID}"
        )))
        .stdout(predicate::str::contains(
            "Protocol version: 0.2.0+attestation",
        ))
        .stdout(predicate::str::contains(format!(
            "Manifest SHA-256: {MANIFEST_SHA256}"
        )))
        .stdout(predicate::str::contains(
            "Physical root instance (folderbase-physical-root-instance-v1): ",
        ));
}

#[test]
fn attest_json_failure_uses_the_stable_envelope_and_exit_two() {
    let ordinary_folder = tempfile::tempdir().expect("ordinary folder");
    let assertion = folderbase()
        .args([
            "attest",
            ordinary_folder.path().to_str().expect("UTF-8 root"),
            "--json",
        ])
        .assert()
        .code(2)
        .stdout(predicate::str::is_empty());

    let value: serde_json::Value =
        serde_json::from_slice(&assertion.get_output().stderr).expect("error JSON");
    assert_eq!(value["error"]["code"], "marker_missing");
    assert_eq!(
        value["error"]["message"],
        "required Folderbase marker is missing: .folderbase"
    );
}

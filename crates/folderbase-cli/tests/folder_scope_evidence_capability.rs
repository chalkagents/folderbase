use std::fs;

use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::Value;

fn folderbase() -> tempfile::TempDir {
    let root = tempfile::tempdir().expect("temporary Folderbase");
    fs::create_dir(root.path().join(".folderbase")).expect("state directory");
    fs::write(
        root.path().join(".folderbase/manifest.json"),
        br#"{"protocol_version":"0.1.0","folderbase":{"id":"folderbase_019fb97e-9c5f-73ca-9bb2-03dc80f94791"}}"#,
    )
    .expect("manifest");
    fs::write(root.path().join(".folderbaseignore"), "").expect("ignore policy");
    fs::write(root.path().join("FOLDERBASE.md"), "# Folderbase\n").expect("entry marker");
    fs::create_dir_all(root.path().join("Client Work/Briefs")).expect("selected folder");
    fs::write(
        root.path().join("Client Work/Briefs/current.md"),
        "current\n",
    )
    .expect("ordinary file");
    root
}

#[test]
fn observe_emits_the_closed_folder_scope_evidence_document() {
    let root = folderbase();
    let assert = Command::new(assert_cmd::cargo::cargo_bin!("folderbase"))
        .args(["folder-scope", "observe"])
        .arg(root.path())
        .arg("Client Work")
        .arg("--json")
        .assert()
        .success()
        .stderr(predicate::str::is_empty());

    let document: Value = serde_json::from_slice(&assert.get_output().stdout).expect("JSON result");
    assert_eq!(document["format"], "folderbase-folder-scope-evidence-v1");
    assert_eq!(document["selected_path"], "Client Work");
    assert_eq!(document["device_sequence"], 1);
    assert_eq!(document["nested_boundaries"], serde_json::json!([]));
    assert!(document.get("root").is_none());
}

#[test]
fn invalid_observe_invocation_uses_the_capability_error_transport() {
    let assert = Command::new(assert_cmd::cargo::cargo_bin!("folderbase"))
        .args(["folder-scope", "observe"])
        .assert()
        .code(2)
        .stdout(predicate::str::is_empty());

    let document: Value = serde_json::from_slice(&assert.get_output().stderr).expect("JSON error");
    assert_eq!(
        document["format"],
        "folderbase-folder-scope-evidence-error-v1"
    );
    assert_eq!(document["error"]["code"], "invalid_invocation");
}

#[test]
fn protocol_discovery_advertises_the_exact_folder_scope_capability() {
    let assert = Command::new(assert_cmd::cargo::cargo_bin!("folderbase"))
        .args(["protocol", "contract", "--json"])
        .assert()
        .success()
        .stderr(predicate::str::is_empty());

    let document: Value = serde_json::from_slice(&assert.get_output().stdout).expect("contract");
    assert!(document["capabilities"].as_array().is_some_and(|profiles| {
        profiles.iter().any(|profile| {
            profile["name"] == "folderbase.folder-scope-evidence"
                && profile["version"] == "0.1.0"
                && profile["stability"] == "stable"
        })
    }));
}

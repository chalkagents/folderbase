use std::path::Path;

use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn public_root_reconstruction_runner_accepts_the_cli_slice() {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let implementation = assert_cmd::cargo::cargo_bin!("folderbase");

    Command::new("node")
        .arg(repository.join("protocol/conformance/capabilities/root-reconstruction-0.1/run.mjs"))
        .arg("--implementation")
        .arg(implementation)
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "\"capability\": \"folderbase.root-reconstruction@0.1.0\"",
        ))
        .stdout(predicate::str::contains("\"passed\": 12"))
        .stdout(predicate::str::contains("\"failed\": 0"));
}

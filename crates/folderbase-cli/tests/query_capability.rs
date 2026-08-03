use assert_cmd::Command;
use predicates::prelude::*;

const MAX_QUERY_REQUEST_BYTES: usize = 4 * 1024 * 1024;

#[cfg(unix)]
#[test]
fn query_index_parser_failures_exit_two_when_stderr_is_closed() {
    let implementation = assert_cmd::cargo::cargo_bin!("folderbase");
    for arguments in [["query", "run", "--json"], ["index", "status", "--json"]] {
        let (closed_stderr, reader) = std::os::unix::net::UnixStream::pair()
            .expect("create a deterministic broken stderr pipe");
        drop(reader);
        let closed_stderr: std::os::fd::OwnedFd = closed_stderr.into();
        let output = std::process::Command::new(implementation)
            .args(arguments)
            .stderr(std::process::Stdio::from(closed_stderr))
            .output()
            .expect("run folderbase with a closed stderr");

        assert_eq!(
            output.status.code(),
            Some(2),
            "{arguments:?} must remain operational when stderr is unavailable"
        );
        assert!(output.stdout.is_empty());
    }
}
const VALID_REQUEST: &str = r#"{
  "format": "folderbase-query-request-v1",
  "scope": {"kind": "live"},
  "page": {"limit": 1}
}"#;

fn folderbase() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("folderbase"))
}

#[test]
fn query_transport_rejects_more_than_four_mib_before_opening_the_root() {
    let input = vec![b' '; MAX_QUERY_REQUEST_BYTES + 1];
    let assertion = folderbase()
        .args(["query", "run", ".", "--json"])
        .write_stdin(input)
        .assert()
        .code(2)
        .stdout(predicate::str::is_empty());

    let error: serde_json::Value =
        serde_json::from_slice(&assertion.get_output().stderr).expect("query error JSON");
    assert_eq!(error["format"], "folderbase-query-error-v1");
    assert_eq!(error["error"]["code"], "invalid_query_request");
    assert!(
        error["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("4194304 bytes"))
    );
}

#[test]
fn query_transport_rejects_a_second_json_value_before_opening_the_root() {
    let assertion = folderbase()
        .args(["query", "explain", ".", "--json"])
        .write_stdin(format!("{VALID_REQUEST}\n{{}}\n"))
        .assert()
        .code(2)
        .stdout(predicate::str::is_empty());

    let error: serde_json::Value =
        serde_json::from_slice(&assertion.get_output().stderr).expect("query error JSON");
    assert_eq!(error["format"], "folderbase-query-error-v1");
    assert_eq!(error["error"]["code"], "invalid_query_request");
}

//! Process adapter for `folderbase.folder-scope-evidence@0.1.0`.

use std::path::PathBuf;

use folderbase_core::{FolderScopeEvidenceError, observe_folder_scope};
use serde::Serialize;

const EXIT_SUCCESS: u8 = 0;
const EXIT_OPERATIONAL_ERROR: u8 = 2;
const MAX_MESSAGE_SCALARS: usize = 4_096;

pub(crate) struct FolderScopeTransport {
    pub(crate) exit_code: u8,
    pub(crate) stdout: Vec<u8>,
    pub(crate) stderr: Vec<u8>,
}

#[derive(Serialize)]
struct ErrorDetail<'a> {
    code: &'a str,
    message: String,
}

#[derive(Serialize)]
struct ErrorDocument<'a> {
    format: &'static str,
    error: ErrorDetail<'a>,
}

pub(crate) fn execute(root: PathBuf, selected_path: PathBuf) -> FolderScopeTransport {
    match observe_folder_scope(root, selected_path) {
        Ok(evidence) => success_transport(&evidence),
        Err(error) => core_error_transport(&error),
    }
}

pub(crate) fn invalid_invocation(message: impl Into<String>) -> FolderScopeTransport {
    error_transport("invalid_invocation", message.into())
}

fn success_transport(value: &impl Serialize) -> FolderScopeTransport {
    match encode_line(value) {
        Ok(stdout) => FolderScopeTransport {
            exit_code: EXIT_SUCCESS,
            stdout,
            stderr: Vec::new(),
        },
        Err(message) => error_transport("output_failed", message),
    }
}

fn core_error_transport(error: &FolderScopeEvidenceError) -> FolderScopeTransport {
    error_transport(error.code(), error.to_string())
}

fn error_transport(code: &str, message: String) -> FolderScopeTransport {
    let document = ErrorDocument {
        format: "folderbase-folder-scope-evidence-error-v1",
        error: ErrorDetail {
            code,
            message: message.chars().take(MAX_MESSAGE_SCALARS).collect(),
        },
    };
    let stderr = encode_line(&document).unwrap_or_else(|_| {
        b"{\"format\":\"folderbase-folder-scope-evidence-error-v1\",\"error\":{\"code\":\"output_failed\",\"message\":\"failed to encode bounded error\"}}\n".to_vec()
    });
    FolderScopeTransport {
        exit_code: EXIT_OPERATIONAL_ERROR,
        stdout: Vec::new(),
        stderr,
    }
}

fn encode_line(value: &impl Serialize) -> Result<Vec<u8>, String> {
    let mut encoded = serde_json::to_vec(value).map_err(|error| error.to_string())?;
    encoded.push(b'\n');
    Ok(encoded)
}

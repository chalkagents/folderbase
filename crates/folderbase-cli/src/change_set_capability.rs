use std::{
    io::{Read, Write},
    path::PathBuf,
};

use folderbase_core::{
    ChangeSetApplyOutcome, ChangeSetAssessmentOutcome, ChangeSetEnvelope, ChangeSetError,
    CheckoutRequest, MAX_CHANGE_SET_BYTES, apply_change_set, assess_change_set,
    checkout_change_set_projection, propose_change_set,
};
use serde::Serialize;

const EXIT_SUCCESS: u8 = 0;
const EXIT_ATTENTION: u8 = 1;
const EXIT_OPERATIONAL_ERROR: u8 = 2;

pub(crate) enum ChangeSetOperation {
    Checkout { root: PathBuf, destination: PathBuf },
    Propose { checkout: PathBuf, staging: PathBuf },
    Assess { root: PathBuf, staging: PathBuf },
    Apply { root: PathBuf, staging: PathBuf },
}

pub(crate) struct ChangeSetTransport {
    pub(crate) exit_code: u8,
    pub(crate) stdout: Vec<u8>,
    pub(crate) stderr: Vec<u8>,
}

pub(crate) fn execute(operation: ChangeSetOperation, stdin: impl Read) -> ChangeSetTransport {
    match operation {
        ChangeSetOperation::Checkout { root, destination } => {
            let request = match read_json_bounded::<CheckoutRequest>(stdin) {
                Ok(request) => request,
                Err(message) => {
                    return error_transport("invalid_checkout_request", message);
                }
            };
            match checkout_change_set_projection(root, destination, request) {
                Ok(result) => success_transport(&result),
                Err(error) => core_error_transport(error),
            }
        }
        ChangeSetOperation::Propose { checkout, staging } => {
            match propose_change_set(checkout, staging) {
                Ok(result) => success_transport(&result),
                Err(error) => core_error_transport(error),
            }
        }
        ChangeSetOperation::Assess { root, staging } => {
            let envelope = match read_json_bounded::<ChangeSetEnvelope>(stdin) {
                Ok(envelope) => envelope,
                Err(message) => return error_transport("invalid_change_set_input", message),
            };
            match assess_change_set(root, staging, envelope) {
                Ok(ChangeSetAssessmentOutcome::Clean(result)) => success_transport(&result),
                Ok(ChangeSetAssessmentOutcome::Attention(result)) => attention_transport(&result),
                Err(error) => core_error_transport(error),
            }
        }
        ChangeSetOperation::Apply { root, staging } => {
            let envelope = match read_json_bounded::<ChangeSetEnvelope>(stdin) {
                Ok(envelope) => envelope,
                Err(message) => return error_transport("invalid_change_set_input", message),
            };
            match apply_change_set(root, staging, envelope) {
                Ok(ChangeSetApplyOutcome::Applied(result)) => success_transport(&result),
                Ok(ChangeSetApplyOutcome::Attention(result)) => attention_transport(&result),
                Err(error) => core_error_transport(error),
            }
        }
    }
}

pub(crate) fn invalid_invocation(message: String) -> ChangeSetTransport {
    error_transport("invalid_change_set_input", message)
}

fn read_json_bounded<T: for<'de> serde::Deserialize<'de>>(
    mut reader: impl Read,
) -> Result<T, String> {
    let mut bytes = Vec::new();
    reader
        .by_ref()
        .take(MAX_CHANGE_SET_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("failed to read stdin: {error}"))?;
    if bytes.len() as u64 > MAX_CHANGE_SET_BYTES {
        return Err("stdin exceeds the 8 MiB Change Set bound".to_owned());
    }
    serde_json::from_slice(&bytes).map_err(|error| format!("stdin is not valid JSON: {error}"))
}

fn success_transport(value: &impl Serialize) -> ChangeSetTransport {
    match encode(value) {
        Ok(stdout) => ChangeSetTransport {
            exit_code: EXIT_SUCCESS,
            stdout,
            stderr: Vec::new(),
        },
        Err(message) => error_transport("change_set_operational_error", message),
    }
}

fn attention_transport(value: &impl Serialize) -> ChangeSetTransport {
    match encode(value) {
        Ok(stdout) => ChangeSetTransport {
            exit_code: EXIT_ATTENTION,
            stdout,
            stderr: Vec::new(),
        },
        Err(message) => error_transport("change_set_operational_error", message),
    }
}

fn core_error_transport(error: ChangeSetError) -> ChangeSetTransport {
    error_transport(error.code(), error.message())
}

fn error_transport(code: &'static str, message: String) -> ChangeSetTransport {
    let value = serde_json::json!({
        "format": "folderbase-change-set-error-v1",
        "error": {
            "code": code,
            "message": message,
        }
    });
    let stderr = encode(&value).unwrap_or_else(|_| {
        b"{\"format\":\"folderbase-change-set-error-v1\",\"error\":{\"code\":\"change_set_operational_error\",\"message\":\"failed to encode error\"}}\n".to_vec()
    });
    ChangeSetTransport {
        exit_code: EXIT_OPERATIONAL_ERROR,
        stdout: Vec::new(),
        stderr,
    }
}

fn encode(value: &impl Serialize) -> Result<Vec<u8>, String> {
    let mut encoded = Vec::new();
    serde_json::to_writer(&mut encoded, value).map_err(|error| error.to_string())?;
    encoded
        .write_all(b"\n")
        .map_err(|error| error.to_string())?;
    if encoded.len() as u64 > MAX_CHANGE_SET_BYTES {
        return Err("encoded Change Set output exceeds 8 MiB".to_owned());
    }
    Ok(encoded)
}

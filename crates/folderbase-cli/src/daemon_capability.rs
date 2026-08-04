//! Root-pinned stdio JSON Lines session for `folderbase.daemon-stdio@0.1.0`.
//!
//! Filesystem notifications are deliberately only dirty hints. Every query or
//! index operation delegates to the existing query capability adapter.

use std::{
    io::{BufRead, Write},
    path::{Component, Path, PathBuf},
    sync::mpsc::{self, Receiver, SyncSender},
    thread,
};

use folderbase_core::{FolderbaseRootAttestation, attest_folderbase_root};
use notify::{Event, RecommendedWatcher, RecursiveMode, Watcher};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::query_capability::{
    IndexOperation, QueryOperation, QueryTransport, execute_index, execute_query,
};

const CAPABILITY: &str = "folderbase.daemon-stdio@0.1.0";
const REQUEST_FORMAT: &str = "folderbase-daemon-request-v1";
const MESSAGE_FORMAT: &str = "folderbase-daemon-message-v1";
const MAX_REQUEST_BYTES: usize = 4 * 1024 * 1024;
const MAX_OUTPUT_BYTES: usize = 8 * 1024 * 1024;
const MAX_MESSAGE_SCALARS: usize = 4_096;
const INPUT_QUEUE_CAPACITY: usize = 8;
const EXIT_SUCCESS: u8 = 0;
const EXIT_OPERATIONAL_ERROR: u8 = 2;

#[derive(Debug)]
enum Input {
    Frame(Frame),
    Eof,
    ReadError(String),
    Fs(Result<Event, notify::Error>),
}

#[derive(Debug)]
enum Frame {
    Bytes(Vec<u8>),
    Oversized,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Operation {
    Query,
    Explain,
    IndexStatus,
    Refresh,
    Subscribe,
    Unsubscribe,
    Shutdown,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    format: String,
    request_id: String,
    operation: Operation,
    document: Option<Value>,
}

#[derive(Serialize)]
struct Ready<'a> {
    format: &'static str,
    kind: &'static str,
    capability: &'static str,
    epoch: &'a str,
    folderbase_id: &'a str,
    root_instance_sha256: &'a str,
    root: String,
}

#[derive(Serialize)]
struct Response<'a> {
    format: &'static str,
    kind: &'static str,
    request_id: Option<&'a str>,
    operation: Option<Operation>,
    status: &'static str,
    document: Value,
}

#[derive(Serialize)]
struct EventMessage<'a> {
    format: &'static str,
    kind: &'static str,
    event: &'a str,
    epoch: &'a str,
    sequence: u64,
}

pub(crate) fn invalid_invocation(message: String) -> u8 {
    write_terminal_error("invalid_daemon_invocation", message)
}

pub(crate) fn serve(root: PathBuf) -> u8 {
    let pinned = match attest_folderbase_root(&root) {
        Ok(attestation) => attestation,
        Err(error) => return write_terminal_error("daemon_root_invalid", error.to_string()),
    };
    let epoch = format!("daemon_{}", Uuid::now_v7());
    let (sender, receiver) = mpsc::sync_channel(INPUT_QUEUE_CAPACITY);
    let mut watcher = match start_watcher(&root, sender.clone()) {
        Ok(watcher) => watcher,
        Err(error) => return write_terminal_error("daemon_watcher_unavailable", error.to_string()),
    };
    let input_thread = start_input_thread(sender);
    let stdout = std::io::stdout();
    let mut output = stdout.lock();
    if write_message(
        &mut output,
        &Ready {
            format: MESSAGE_FORMAT,
            kind: "ready",
            capability: CAPABILITY,
            epoch: &epoch,
            folderbase_id: &pinned.folderbase_id,
            root_instance_sha256: &pinned.root_instance_sha256,
            root: pinned.root.to_string_lossy().into_owned(),
        },
    )
    .is_err()
    {
        return EXIT_OPERATIONAL_ERROR;
    }

    let code = session_loop(&root, &pinned, &epoch, &receiver, &mut output);
    // Release the bounded receiver first so a watcher callback or stdin reader
    // blocked on backpressure cannot delay watcher teardown.
    drop(receiver);
    drop(watcher.unwatch(&root));
    drop(watcher);
    // The reader may still be blocked in a platform stdin call after an
    // explicit shutdown or terminal root change. Dropping its handle lets the
    // process exit immediately; EOF still causes the reader to return on its
    // own. The thread owns no Folderbase state or mutation authority.
    drop(input_thread);
    code
}

fn start_watcher(root: &Path, sender: SyncSender<Input>) -> notify::Result<RecommendedWatcher> {
    let mut watcher = notify::recommended_watcher(move |event| {
        let _ = sender.send(Input::Fs(event));
    })?;
    watcher.watch(root, RecursiveMode::Recursive)?;
    Ok(watcher)
}

fn start_input_thread(sender: SyncSender<Input>) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let stdin = std::io::stdin();
        let mut input = stdin.lock();
        loop {
            match read_frame(&mut input) {
                Ok(Some(frame)) => {
                    if sender.send(Input::Frame(frame)).is_err() {
                        return;
                    }
                }
                Ok(None) => {
                    let _ = sender.send(Input::Eof);
                    return;
                }
                Err(error) => {
                    let _ = sender.send(Input::ReadError(error.to_string()));
                    return;
                }
            }
        }
    })
}

fn session_loop(
    root: &Path,
    pinned: &FolderbaseRootAttestation,
    epoch: &str,
    receiver: &Receiver<Input>,
    output: &mut impl Write,
) -> u8 {
    let mut subscribed = false;
    let mut dirty = false;
    let mut sequence = 0_u64;
    while let Ok(input) = receiver.recv() {
        match input {
            Input::Eof => return EXIT_SUCCESS,
            Input::ReadError(message) => {
                if write_invalid_request(output, &message).is_err() {
                    return EXIT_OPERATIONAL_ERROR;
                }
                return EXIT_OPERATIONAL_ERROR;
            }
            Input::Frame(Frame::Oversized) => {
                if write_invalid_request(output, "daemon request exceeds 4194304 bytes").is_err() {
                    return EXIT_OPERATIONAL_ERROR;
                }
            }
            Input::Frame(Frame::Bytes(bytes)) => {
                let request = match decode_request(&bytes) {
                    Ok(request) => request,
                    Err(message) => {
                        if write_invalid_request(output, &message).is_err() {
                            return EXIT_OPERATIONAL_ERROR;
                        }
                        continue;
                    }
                };
                let root_current = root_matches_pin(root, pinned);
                if !root_current {
                    let response = Response {
                        format: MESSAGE_FORMAT,
                        kind: "response",
                        request_id: Some(&request.request_id),
                        operation: Some(request.operation),
                        status: "error",
                        document: query_error(
                            "query_root_changed",
                            "the physical Folderbase root changed during the daemon session",
                        ),
                    };
                    if write_message(output, &response).is_err() {
                        return EXIT_OPERATIONAL_ERROR;
                    }
                    return EXIT_OPERATIONAL_ERROR;
                }
                let operation = request.operation;
                let response = execute_request(root, &request, &mut subscribed);
                let success = response.status == "ok";
                if write_message(output, &response).is_err() {
                    return EXIT_OPERATIONAL_ERROR;
                }
                if success
                    && matches!(
                        operation,
                        Operation::Query
                            | Operation::Explain
                            | Operation::IndexStatus
                            | Operation::Refresh
                    )
                {
                    dirty = false;
                }
                if operation == Operation::Shutdown {
                    return EXIT_SUCCESS;
                }
            }
            Input::Fs(Ok(event)) => {
                if event_is_private_index_only(root, &event) {
                    continue;
                }
                dirty = match emit_hint_if_needed(
                    output,
                    epoch,
                    &mut sequence,
                    subscribed,
                    dirty,
                    "workspace_changed",
                ) {
                    Ok(dirty) => dirty,
                    Err(_) => return EXIT_OPERATIONAL_ERROR,
                };
            }
            Input::Fs(Err(_)) => {
                dirty = match emit_hint_if_needed(
                    output,
                    epoch,
                    &mut sequence,
                    subscribed,
                    dirty,
                    "rescan_required",
                ) {
                    Ok(dirty) => dirty,
                    Err(_) => return EXIT_OPERATIONAL_ERROR,
                };
            }
        }
    }
    EXIT_SUCCESS
}

fn emit_hint_if_needed(
    output: &mut impl Write,
    epoch: &str,
    sequence: &mut u64,
    subscribed: bool,
    dirty: bool,
    event: &str,
) -> std::io::Result<bool> {
    if dirty {
        return Ok(true);
    }
    if subscribed {
        *sequence = sequence.saturating_add(1);
        write_message(
            output,
            &EventMessage {
                format: MESSAGE_FORMAT,
                kind: "event",
                event,
                epoch,
                sequence: *sequence,
            },
        )?;
    }
    Ok(true)
}

fn execute_request<'a>(root: &Path, request: &'a Request, subscribed: &mut bool) -> Response<'a> {
    let (status, document) = match request.operation {
        Operation::Query | Operation::Explain => {
            let Some(document) = &request.document else {
                return invalid_response(request, "query and explain require document");
            };
            let bytes = match serde_json::to_vec(document) {
                Ok(bytes) => bytes,
                Err(error) => return invalid_response(request, &error.to_string()),
            };
            let operation = if request.operation == Operation::Query {
                QueryOperation::Run
            } else {
                QueryOperation::Explain
            };
            transport_document(execute_query(
                operation,
                root.to_path_buf(),
                bytes.as_slice(),
            ))
        }
        Operation::IndexStatus => {
            transport_document(execute_index(IndexOperation::Status, root.to_path_buf()))
        }
        Operation::Refresh => {
            transport_document(execute_index(IndexOperation::Rebuild, root.to_path_buf()))
        }
        Operation::Subscribe => {
            *subscribed = true;
            (
                "ok",
                json!({
                    "format": "folderbase-daemon-subscription-v1",
                    "subscribed": true,
                }),
            )
        }
        Operation::Unsubscribe => {
            *subscribed = false;
            (
                "ok",
                json!({
                    "format": "folderbase-daemon-subscription-v1",
                    "subscribed": false,
                }),
            )
        }
        Operation::Shutdown => (
            "ok",
            json!({
                "format": "folderbase-daemon-shutdown-v1",
                "status": "shutting_down",
            }),
        ),
    };
    Response {
        format: MESSAGE_FORMAT,
        kind: "response",
        request_id: Some(&request.request_id),
        operation: Some(request.operation),
        status,
        document,
    }
}

fn transport_document(transport: QueryTransport) -> (&'static str, Value) {
    let (status, bytes) = match transport.exit_code {
        0 => ("ok", transport.stdout),
        1 => ("attention", transport.stdout),
        _ => ("error", transport.stderr),
    };
    match serde_json::from_slice(&bytes) {
        Ok(document) => (status, document),
        Err(error) => (
            "error",
            daemon_error(
                "daemon_internal_error",
                &format!("query adapter returned invalid JSON: {error}"),
            ),
        ),
    }
}

fn invalid_response<'a>(request: &'a Request, message: &str) -> Response<'a> {
    Response {
        format: MESSAGE_FORMAT,
        kind: "response",
        request_id: Some(&request.request_id),
        operation: Some(request.operation),
        status: "error",
        document: daemon_error("invalid_daemon_request", message),
    }
}

fn write_invalid_request(output: &mut impl Write, message: &str) -> std::io::Result<()> {
    write_message(
        output,
        &Response {
            format: MESSAGE_FORMAT,
            kind: "response",
            request_id: None,
            operation: None,
            status: "error",
            document: daemon_error("invalid_daemon_request", message),
        },
    )
}

fn daemon_error(code: &str, message: &str) -> Value {
    json!({
        "format": "folderbase-daemon-error-v1",
        "error": {
            "code": code,
            "message": bounded_message(message),
        }
    })
}

fn query_error(code: &str, message: &str) -> Value {
    json!({
        "format": "folderbase-query-error-v1",
        "error": {
            "code": code,
            "message": bounded_message(message),
        }
    })
}

fn decode_request(bytes: &[u8]) -> Result<Request, String> {
    let request: Request = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
    if request.format != REQUEST_FORMAT {
        return Err(format!("request format must be {REQUEST_FORMAT}"));
    }
    if !valid_request_id(&request.request_id) {
        return Err("request_id must contain 1-128 portable identifier bytes".to_owned());
    }
    let needs_document = matches!(request.operation, Operation::Query | Operation::Explain);
    if needs_document != request.document.is_some() {
        return Err(if needs_document {
            "query and explain require document".to_owned()
        } else {
            "this operation does not accept document".to_owned()
        });
    }
    Ok(request)
}

fn valid_request_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
}

fn read_frame(input: &mut impl BufRead) -> std::io::Result<Option<Frame>> {
    let mut bytes = Vec::new();
    let mut oversized = false;
    let mut observed = false;
    loop {
        let available = input.fill_buf()?;
        if available.is_empty() {
            return if observed {
                Ok(Some(if oversized {
                    Frame::Oversized
                } else {
                    Frame::Bytes(bytes)
                }))
            } else {
                Ok(None)
            };
        }
        observed = true;
        let newline = available.iter().position(|byte| *byte == b'\n');
        let take = newline.unwrap_or(available.len());
        if !oversized {
            if bytes.len().saturating_add(take) > MAX_REQUEST_BYTES {
                oversized = true;
                bytes.clear();
            } else {
                bytes.extend_from_slice(&available[..take]);
            }
        }
        let consumed = take + usize::from(newline.is_some());
        input.consume(consumed);
        if newline.is_some() {
            return Ok(Some(if oversized {
                Frame::Oversized
            } else {
                Frame::Bytes(bytes)
            }));
        }
    }
}

fn root_matches_pin(root: &Path, pinned: &FolderbaseRootAttestation) -> bool {
    attest_folderbase_root(root).is_ok_and(|current| {
        current.folderbase_id == pinned.folderbase_id
            && current.root_instance_sha256 == pinned.root_instance_sha256
    })
}

fn event_is_private_index_only(root: &Path, event: &Event) -> bool {
    !event.paths.is_empty()
        && event.paths.iter().all(|path| {
            path.strip_prefix(root)
                .ok()
                .is_some_and(is_private_index_path)
        })
}

fn is_private_index_path(path: &Path) -> bool {
    let mut components = path.components();
    matches!(components.next(), Some(Component::Normal(value)) if value == ".folderbase")
        && matches!(components.next(), Some(Component::Normal(value)) if value == "local")
        && matches!(components.next(), Some(Component::Normal(value)) if value == "query-index-v1")
}

fn write_message(output: &mut impl Write, message: &impl Serialize) -> std::io::Result<()> {
    let mut encoded = serde_json::to_vec(message).map_err(std::io::Error::other)?;
    encoded.push(b'\n');
    if encoded.len() > MAX_OUTPUT_BYTES {
        return Err(std::io::Error::other("daemon output exceeds 8 MiB"));
    }
    output.write_all(&encoded)?;
    output.flush()
}

fn write_terminal_error(code: &str, message: String) -> u8 {
    let value = json!({
        "format": "folderbase-daemon-terminal-error-v1",
        "error": {
            "code": code,
            "message": bounded_message(&message),
        }
    });
    let stderr = std::io::stderr();
    let mut stderr = stderr.lock();
    match serde_json::to_vec(&value)
        .map_err(std::io::Error::other)
        .and_then(|mut bytes| {
            bytes.push(b'\n');
            stderr.write_all(&bytes)?;
            stderr.flush()
        }) {
        Ok(()) => EXIT_OPERATIONAL_ERROR,
        Err(_) => EXIT_OPERATIONAL_ERROR,
    }
}

fn bounded_message(message: &str) -> String {
    message.chars().take(MAX_MESSAGE_SCALARS).collect()
}

#[cfg(test)]
mod tests {
    use std::io::{BufReader, Cursor};

    use super::{Frame, MAX_REQUEST_BYTES, read_frame, valid_request_id};

    #[test]
    fn request_ids_use_one_small_portable_alphabet() {
        assert!(valid_request_id("request-1.alpha:two"));
        assert!(!valid_request_id(""));
        assert!(!valid_request_id("contains space"));
        assert!(!valid_request_id(&"x".repeat(129)));
    }

    #[test]
    fn oversized_frame_is_drained_without_losing_the_next_frame() {
        let mut input = vec![b'x'; MAX_REQUEST_BYTES + 1];
        input.extend_from_slice(b"\n{}\n");
        let mut reader = BufReader::new(Cursor::new(input));
        assert!(matches!(
            read_frame(&mut reader).unwrap(),
            Some(Frame::Oversized)
        ));
        assert!(matches!(
            read_frame(&mut reader).unwrap(),
            Some(Frame::Bytes(bytes)) if bytes == b"{}"
        ));
    }
}

//! Process adapter for the optional `folderbase.query-index@0.1.0` capability.
//!
//! This module owns the capability's closed JSON documents, byte bounds, stream
//! selection, and exit taxonomy. It deliberately does not reuse CLI JSON v1.

use std::{
    borrow::Cow,
    io::Read,
    path::{Path, PathBuf},
};

use folderbase_core::{
    FolderbaseCaptureError, FolderbaseQueryEngine, QueryEntry, QueryEntryKind, QueryError,
    QueryExclusion, QueryExclusionKind, QueryExecution, QueryExplain, QueryIndexRebuildResult,
    QueryIndexState, QueryIndexStatus, QueryLifecycle, QueryRequest, QueryResult, QuerySource,
};
use serde::Serialize;

const EXIT_SUCCESS: u8 = 0;
const EXIT_ATTENTION: u8 = 1;
const EXIT_OPERATIONAL_ERROR: u8 = 2;
const MAX_QUERY_REQUEST_BYTES: u64 = 4 * 1024 * 1024;
const MAX_QUERY_OUTPUT_BYTES: usize = 8 * 1024 * 1024;
const MAX_QUERY_MESSAGE_SCALARS: usize = 4_096;

#[derive(Debug, Clone, Copy)]
pub(crate) enum QueryOperation {
    Run,
    Explain,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum IndexOperation {
    Status,
    Rebuild,
}

pub(crate) struct QueryTransport {
    pub(crate) exit_code: u8,
    pub(crate) stdout: Vec<u8>,
    pub(crate) stderr: Vec<u8>,
}

impl QueryTransport {
    fn success(document: &impl Serialize) -> Self {
        match encode_document(document) {
            Ok(stdout) => Self {
                exit_code: EXIT_SUCCESS,
                stdout,
                stderr: Vec::new(),
            },
            Err(message) => Self::error("query_inventory_limit_exceeded", message),
        }
    }

    fn attention(message: impl Into<String>) -> Self {
        let document = QueryAttentionDocument {
            format: "folderbase-query-attention-v1",
            error: QueryAttentionBody {
                code: "query_snapshot_changed",
                message: bounded_message(message),
                retryable: true,
            },
        };
        Self {
            exit_code: EXIT_ATTENTION,
            stdout: encode_infallible(&document),
            stderr: Vec::new(),
        }
    }

    fn error(code: &'static str, message: impl Into<String>) -> Self {
        let document = QueryErrorDocument {
            format: "folderbase-query-error-v1",
            error: QueryErrorBody {
                code,
                message: bounded_message(message),
            },
        };
        Self {
            exit_code: EXIT_OPERATIONAL_ERROR,
            stdout: Vec::new(),
            stderr: encode_infallible(&document),
        }
    }
}

pub(crate) fn execute_query(
    operation: QueryOperation,
    root: PathBuf,
    input: impl Read,
) -> QueryTransport {
    let request = match read_request(input) {
        Ok(request) => request,
        Err(error) => return query_error_transport(error),
    };
    let engine = match FolderbaseQueryEngine::open(&root) {
        Ok(engine) => engine,
        Err(error) => return query_error_transport(error),
    };
    match operation {
        QueryOperation::Run => match engine.run(&request) {
            Ok(result) => QueryTransport::success(&QueryResultDocument::from(&result)),
            Err(error) => query_error_transport(error),
        },
        QueryOperation::Explain => match engine.explain(&request) {
            Ok(explanation) => QueryTransport::success(&QueryExplainDocument::from(&explanation)),
            Err(error) => query_error_transport(error),
        },
    }
}

pub(crate) fn execute_index(operation: IndexOperation, root: PathBuf) -> QueryTransport {
    let engine = match FolderbaseQueryEngine::open(&root) {
        Ok(engine) => engine,
        Err(error) => return query_error_transport(error),
    };
    match operation {
        IndexOperation::Status => match engine.index_status() {
            Ok(status) => QueryTransport::success(&QueryIndexStatusDocument::from(&status)),
            Err(error) => query_error_transport(error),
        },
        IndexOperation::Rebuild => match engine.rebuild_index() {
            Ok(result) => QueryTransport::success(&QueryIndexRebuildDocument::from(&result)),
            Err(error) => query_error_transport(error),
        },
    }
}

fn read_request(mut input: impl Read) -> Result<QueryRequest, QueryError> {
    let mut bytes = Vec::new();
    input
        .by_ref()
        .take(MAX_QUERY_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| {
            QueryError::InvalidQueryRequest(format!("failed to read query request: {source}"))
        })?;
    if bytes.len() as u64 > MAX_QUERY_REQUEST_BYTES {
        return Err(QueryError::InvalidQueryRequest(format!(
            "query request exceeds {MAX_QUERY_REQUEST_BYTES} bytes"
        )));
    }
    serde_json::from_slice(&bytes)
        .map_err(|source| QueryError::InvalidQueryRequest(source.to_string()))
}

fn encode_document(document: &impl Serialize) -> Result<Vec<u8>, String> {
    let mut encoded = serde_json::to_vec(document)
        .map_err(|source| format!("failed to serialize query capability output: {source}"))?;
    encoded.push(b'\n');
    if encoded.len() > MAX_QUERY_OUTPUT_BYTES {
        return Err(format!(
            "query capability output exceeds {MAX_QUERY_OUTPUT_BYTES} bytes"
        ));
    }
    Ok(encoded)
}

fn encode_infallible(document: &impl Serialize) -> Vec<u8> {
    encode_document(document).expect("bounded query error documents must serialize")
}

fn bounded_message(message: impl Into<String>) -> String {
    message
        .into()
        .chars()
        .take(MAX_QUERY_MESSAGE_SCALARS)
        .collect()
}

fn query_error_transport(error: QueryError) -> QueryTransport {
    if matches!(error, QueryError::QuerySnapshotChanged) {
        return QueryTransport::attention(error.to_string());
    }
    QueryTransport::error(query_error_code(&error), error.to_string())
}

fn query_error_code(error: &QueryError) -> &'static str {
    match error {
        QueryError::InvalidQueryRequest(_) => "invalid_query_request",
        QueryError::InvalidQueryCursor => "invalid_query_cursor",
        QueryError::QuerySnapshotChanged | QueryError::RootAuthorityChanged => "query_root_changed",
        QueryError::IndexRebuildFailed(_) => "query_index_rebuild_failed",
        QueryError::ScopeVersionMissing { .. } => "query_scope_version_missing",
        QueryError::ScopeVersionInvalid { .. } => "query_scope_version_invalid",
        QueryError::Capture(FolderbaseCaptureError::InventoryLimitExceeded { .. }) => {
            "query_inventory_limit_exceeded"
        }
        QueryError::Capture(
            FolderbaseCaptureError::UnsafePortablePath(_)
            | FolderbaseCaptureError::PortablePathCollision { .. },
        ) => "invalid_query_request",
        QueryError::Capture(_) => "query_root_changed",
        _ => "query_root_changed",
    }
}

/// The wire root is informational rather than authority-bearing. As elsewhere
/// in the CLI, non-UTF-8 platform paths use an explicit U+FFFD display form so
/// the closed JSON schema always receives a valid string.
fn wire_root(root: &Path) -> Cow<'_, str> {
    root.to_string_lossy()
}

#[derive(Serialize)]
struct QueryEntryDocument<'a> {
    path: &'a str,
    kind: QueryEntryKind,
    lifecycle: QueryLifecycle,
    bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    executable: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    symlink_target: Option<&'a str>,
    object_id: Option<&'a str>,
    object_version_id: Option<&'a str>,
    folderbase_version_id: Option<&'a str>,
    source: QuerySource,
    #[serde(skip_serializing_if = "Option::is_none")]
    boundary_reason: Option<&'a str>,
}

impl<'a> From<&'a QueryEntry> for QueryEntryDocument<'a> {
    fn from(entry: &'a QueryEntry) -> Self {
        Self {
            path: entry.path(),
            kind: entry.kind(),
            lifecycle: entry.lifecycle(),
            bytes: entry.bytes(),
            executable: entry.executable(),
            symlink_target: entry.symlink_target(),
            object_id: entry.object_id(),
            object_version_id: entry.object_version_id(),
            folderbase_version_id: entry.folderbase_version_id(),
            source: entry.source(),
            boundary_reason: entry.boundary_reason(),
        }
    }
}

#[derive(Serialize)]
struct QueryExclusionDocument<'a> {
    path: &'a str,
    reason: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    kind: Option<QueryExclusionKind>,
}

impl<'a> From<&'a QueryExclusion> for QueryExclusionDocument<'a> {
    fn from(exclusion: &'a QueryExclusion) -> Self {
        Self {
            path: exclusion.path(),
            reason: exclusion.reason(),
            kind: exclusion.kind(),
        }
    }
}

#[derive(Serialize)]
struct QueryPageDocument<'a> {
    limit: usize,
    returned: usize,
    has_more: bool,
    next_cursor: Option<&'a str>,
}

#[derive(Serialize)]
struct QueryResultDocument<'a> {
    format: &'static str,
    root: Cow<'a, str>,
    folderbase_id: &'a str,
    request_sha256: &'a str,
    observation_generation: &'a str,
    execution: QueryExecution,
    entries: Vec<QueryEntryDocument<'a>>,
    exclusions: Vec<QueryExclusionDocument<'a>>,
    exclusions_truncated: bool,
    page: QueryPageDocument<'a>,
}

impl<'a> From<&'a QueryResult> for QueryResultDocument<'a> {
    fn from(result: &'a QueryResult) -> Self {
        Self {
            format: "folderbase-query-result-v1",
            root: wire_root(result.root()),
            folderbase_id: result.folderbase_id(),
            request_sha256: result.request_sha256(),
            observation_generation: result.observation_generation(),
            execution: result.execution(),
            entries: result.entries().iter().map(Into::into).collect(),
            exclusions: result.exclusions().iter().map(Into::into).collect(),
            exclusions_truncated: result.exclusions_truncated(),
            page: QueryPageDocument {
                limit: result.page().limit(),
                returned: result.page().returned(),
                has_more: result.page().has_more(),
                next_cursor: result.page().next_cursor(),
            },
        }
    }
}

#[derive(Serialize)]
struct QueryExplainDocument<'a> {
    format: &'static str,
    root: Cow<'a, str>,
    folderbase_id: &'a str,
    request_sha256: &'a str,
    observation_generation: &'a str,
    normalized_request: &'a serde_json::Value,
    scope_source: QuerySource,
    ordering: &'static str,
    filter_algebra: &'static str,
    ordinary_content_access: &'static str,
    index_strategy: QueryExecution,
    matched: usize,
    excluded: Vec<QueryExclusionDocument<'a>>,
    excluded_truncated: bool,
}

#[derive(Serialize)]
struct QueryIndexStatusDocument<'a> {
    format: &'static str,
    root: Cow<'a, str>,
    folderbase_id: &'a str,
    state: QueryIndexState,
    generation: Option<&'a str>,
    observed_generation: &'a str,
    records: usize,
    storage_path: &'static str,
    disposable: bool,
}

impl<'a> From<&'a QueryIndexStatus> for QueryIndexStatusDocument<'a> {
    fn from(status: &'a QueryIndexStatus) -> Self {
        Self {
            format: "folderbase-query-index-status-v1",
            root: wire_root(status.root()),
            folderbase_id: status.folderbase_id(),
            state: status.state(),
            generation: status.generation(),
            observed_generation: status.observed_generation(),
            records: status.records(),
            storage_path: status.storage_path(),
            disposable: status.disposable(),
        }
    }
}

#[derive(Serialize)]
struct QueryIndexRebuildDocument<'a> {
    format: &'static str,
    root: Cow<'a, str>,
    folderbase_id: &'a str,
    generation: &'a str,
    records: usize,
    exclusions: usize,
    storage_path: &'static str,
    portable_files_changed: bool,
    ordinary_files_changed: bool,
}

impl<'a> From<&'a QueryIndexRebuildResult> for QueryIndexRebuildDocument<'a> {
    fn from(result: &'a QueryIndexRebuildResult) -> Self {
        Self {
            format: "folderbase-query-index-rebuild-result-v1",
            root: wire_root(result.root()),
            folderbase_id: result.folderbase_id(),
            generation: result.generation(),
            records: result.records(),
            exclusions: result.exclusions(),
            storage_path: result.storage_path(),
            portable_files_changed: result.portable_files_changed(),
            ordinary_files_changed: result.ordinary_files_changed(),
        }
    }
}

impl<'a> From<&'a QueryExplain> for QueryExplainDocument<'a> {
    fn from(explanation: &'a QueryExplain) -> Self {
        Self {
            format: "folderbase-query-explain-v1",
            root: wire_root(explanation.root()),
            folderbase_id: explanation.folderbase_id(),
            request_sha256: explanation.request_sha256(),
            observation_generation: explanation.observation_generation(),
            normalized_request: explanation.normalized_request(),
            scope_source: explanation.scope_source(),
            ordering: explanation.ordering(),
            filter_algebra: explanation.filter_algebra(),
            ordinary_content_access: explanation.ordinary_content_access(),
            index_strategy: explanation.index_strategy(),
            matched: explanation.matched(),
            excluded: explanation.excluded().iter().map(Into::into).collect(),
            excluded_truncated: explanation.excluded_truncated(),
        }
    }
}

#[derive(Serialize)]
struct QueryAttentionDocument {
    format: &'static str,
    error: QueryAttentionBody,
}

#[derive(Serialize)]
struct QueryAttentionBody {
    code: &'static str,
    message: String,
    retryable: bool,
}

#[derive(Serialize)]
struct QueryErrorDocument {
    format: &'static str,
    error: QueryErrorBody,
}

#[derive(Serialize)]
struct QueryErrorBody {
    code: &'static str,
    message: String,
}

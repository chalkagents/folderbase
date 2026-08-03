//! Bounded, metadata-only query projection for one Folderbase Root.
//!
//! Live query never owns filesystem traversal. It projects the exact
//! [`crate::CapturePlan`] produced by [`crate::FolderbaseVersionStore`].

use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use unicode_casefold::UnicodeCaseFold;
use unicode_normalization::UnicodeNormalization;
use uuid::Uuid;

use crate::{
    CaptureEntryKind, CaptureExclusionKind, CaptureExclusionReason, CapturePlan,
    FolderbaseCaptureError, FolderbaseVersionStore,
    folderbase_state::FolderbaseState,
    folderbase_version::{
        DeletedKind, ExclusionKind, FolderbaseVersion, MAX_ENCODED_VERSION_BYTES, PathBindingKind,
        validate_capture_path, validate_capture_version_id,
    },
    root_attestation::attest_folderbase_root,
};

const QUERY_REQUEST_FORMAT: &str = "folderbase-query-request-v1";
const MAX_PAGE_LIMIT: usize = 1_000;
const MAX_INDEX_BYTES: u64 = 64 * 1024 * 1024;
const MAX_INDEX_RECORDS: usize = 16_384;
const INDEX_ROOT: &str = ".folderbase/local/query-index-v1";
const INDEX_RECORD: &str = ".folderbase/local/query-index-v1/index.json";
const INDEX_FORMAT: &str = "folderbase-query-private-index-v1";

/// A root-bound handle for read-only query and explicit disposable-index work.
#[derive(Debug)]
pub struct FolderbaseQueryEngine {
    root: PathBuf,
}

/// One bounded query request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueryRequest {
    format: String,
    scope: QueryScope,
    #[serde(default)]
    filters: QueryFilters,
    page: QueryPage,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum QueryScope {
    Live,
    Historical { folderbase_version_id: String },
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct QueryFilters {
    #[serde(default)]
    paths: Vec<String>,
    #[serde(default)]
    path_prefixes: Vec<String>,
    #[serde(default)]
    kinds: Vec<QueryEntryKind>,
    #[serde(default)]
    lifecycles: Vec<QueryLifecycle>,
    #[serde(default)]
    object_ids: Vec<String>,
    #[serde(default)]
    object_version_ids: Vec<String>,
    minimum_bytes: Option<u64>,
    maximum_bytes: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct QueryPage {
    limit: usize,
    #[serde(default)]
    cursor: Option<String>,
}

impl QueryRequest {
    /// Construct one live query with a page limit from 1 through 1000.
    pub fn live(limit: usize) -> Self {
        Self {
            format: QUERY_REQUEST_FORMAT.to_owned(),
            scope: QueryScope::Live,
            filters: QueryFilters::default(),
            page: QueryPage {
                limit,
                cursor: None,
            },
        }
    }
}

/// Source observation from which a query row was projected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuerySource {
    CapturePlan,
    FolderbaseVersion,
}

/// Filesystem kind exposed by query 0.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueryEntryKind {
    Directory,
    NestedFolderbase,
    RegularFile,
    Symlink,
}

/// Lifecycle exposed by query 0.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueryLifecycle {
    Deleted,
    Live,
}

/// How the selected observation was evaluated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueryExecution {
    BoundedScan,
    PrivateIndex,
}

/// One query row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueryEntry {
    path: String,
    kind: QueryEntryKind,
    lifecycle: QueryLifecycle,
    bytes: Option<u64>,
    executable: Option<bool>,
    symlink_target: Option<String>,
    object_id: Option<String>,
    object_version_id: Option<String>,
    folderbase_version_id: Option<String>,
    source: QuerySource,
    boundary_reason: Option<String>,
}

impl QueryEntry {
    pub fn path(&self) -> &str {
        &self.path
    }
    pub fn kind(&self) -> QueryEntryKind {
        self.kind
    }
    pub fn lifecycle(&self) -> QueryLifecycle {
        self.lifecycle
    }
    pub fn bytes(&self) -> Option<u64> {
        self.bytes
    }
    pub fn executable(&self) -> Option<bool> {
        self.executable
    }
    pub fn symlink_target(&self) -> Option<&str> {
        self.symlink_target.as_deref()
    }
    pub fn object_id(&self) -> Option<&str> {
        self.object_id.as_deref()
    }
    pub fn object_version_id(&self) -> Option<&str> {
        self.object_version_id.as_deref()
    }
    pub fn folderbase_version_id(&self) -> Option<&str> {
        self.folderbase_version_id.as_deref()
    }
    pub fn source(&self) -> QuerySource {
        self.source
    }
    pub fn boundary_reason(&self) -> Option<&str> {
        self.boundary_reason.as_deref()
    }
}

/// Optional type attached to an explainable exclusion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueryExclusionKind {
    BlockDevice,
    CharacterDevice,
    Fifo,
    HardLink,
    NestedFolderbase,
    OtherSpecial,
    Socket,
}

/// One path omitted from ordinary query rows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueryExclusion {
    path: String,
    reason: String,
    kind: Option<QueryExclusionKind>,
}

impl QueryExclusion {
    pub fn path(&self) -> &str {
        &self.path
    }
    pub fn reason(&self) -> &str {
        &self.reason
    }
    pub fn kind(&self) -> Option<QueryExclusionKind> {
        self.kind
    }
}

/// Page metadata for a query result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueryPageResult {
    limit: usize,
    returned: usize,
    has_more: bool,
    next_cursor: Option<String>,
}

impl QueryPageResult {
    pub fn limit(&self) -> usize {
        self.limit
    }
    pub fn returned(&self) -> usize {
        self.returned
    }
    pub fn has_more(&self) -> bool {
        self.has_more
    }
    pub fn next_cursor(&self) -> Option<&str> {
        self.next_cursor.as_deref()
    }
}

/// One successful query page.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueryResult {
    root: PathBuf,
    folderbase_id: String,
    request_sha256: String,
    observation_generation: String,
    execution: QueryExecution,
    entries: Vec<QueryEntry>,
    exclusions: Vec<QueryExclusion>,
    exclusions_truncated: bool,
    page: QueryPageResult,
}

/// Read-only state of the disposable private query index.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueryIndexState {
    Absent,
    Fresh,
    Stale,
}

/// Result of inspecting the private index without changing it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryIndexStatus {
    root: PathBuf,
    folderbase_id: String,
    state: QueryIndexState,
    generation: Option<String>,
    observed_generation: String,
    records: usize,
}

impl QueryIndexStatus {
    pub fn root(&self) -> &Path {
        &self.root
    }
    pub fn folderbase_id(&self) -> &str {
        &self.folderbase_id
    }
    pub fn state(&self) -> QueryIndexState {
        self.state
    }
    pub fn generation(&self) -> Option<&str> {
        self.generation.as_deref()
    }
    pub fn observed_generation(&self) -> &str {
        &self.observed_generation
    }
    pub fn records(&self) -> usize {
        self.records
    }
    pub fn storage_path(&self) -> &'static str {
        INDEX_ROOT
    }
    pub fn disposable(&self) -> bool {
        true
    }
}

/// Result of explicitly replacing the disposable private index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryIndexRebuildResult {
    root: PathBuf,
    folderbase_id: String,
    generation: String,
    records: usize,
    exclusions: usize,
}

impl QueryIndexRebuildResult {
    pub fn root(&self) -> &Path {
        &self.root
    }
    pub fn folderbase_id(&self) -> &str {
        &self.folderbase_id
    }
    pub fn generation(&self) -> &str {
        &self.generation
    }
    pub fn records(&self) -> usize {
        self.records
    }
    pub fn exclusions(&self) -> usize {
        self.exclusions
    }
    pub fn storage_path(&self) -> &'static str {
        INDEX_ROOT
    }
    pub fn portable_files_changed(&self) -> bool {
        false
    }
    pub fn ordinary_files_changed(&self) -> bool {
        false
    }
}

/// Read-only explanation of one normalized query plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryExplain {
    root: PathBuf,
    folderbase_id: String,
    request_sha256: String,
    observation_generation: String,
    normalized_request: serde_json::Value,
    scope_source: QuerySource,
    index_strategy: QueryExecution,
    matched: usize,
    excluded: Vec<QueryExclusion>,
}

impl QueryExplain {
    pub fn root(&self) -> &Path {
        &self.root
    }
    pub fn folderbase_id(&self) -> &str {
        &self.folderbase_id
    }
    pub fn request_sha256(&self) -> &str {
        &self.request_sha256
    }
    pub fn observation_generation(&self) -> &str {
        &self.observation_generation
    }
    pub fn normalized_request(&self) -> &serde_json::Value {
        &self.normalized_request
    }
    pub fn scope_source(&self) -> QuerySource {
        self.scope_source
    }
    pub fn ordering(&self) -> &'static str {
        "portable_path_utf8_bytes_ascending"
    }
    pub fn filter_algebra(&self) -> &'static str {
        "families_and_values_or"
    }
    pub fn ordinary_content_access(&self) -> &'static str {
        "metadata_only"
    }
    pub fn index_strategy(&self) -> QueryExecution {
        self.index_strategy
    }
    pub fn matched(&self) -> usize {
        self.matched
    }
    pub fn excluded(&self) -> &[QueryExclusion] {
        &self.excluded
    }
}

impl QueryResult {
    pub fn root(&self) -> &Path {
        &self.root
    }
    pub fn folderbase_id(&self) -> &str {
        &self.folderbase_id
    }
    pub fn request_sha256(&self) -> &str {
        &self.request_sha256
    }
    pub fn observation_generation(&self) -> &str {
        &self.observation_generation
    }
    pub fn execution(&self) -> QueryExecution {
        self.execution
    }
    pub fn entries(&self) -> &[QueryEntry] {
        &self.entries
    }
    pub fn exclusions(&self) -> &[QueryExclusion] {
        &self.exclusions
    }
    pub fn exclusions_truncated(&self) -> bool {
        self.exclusions_truncated
    }
    pub fn page(&self) -> &QueryPageResult {
        &self.page
    }
}

/// Typed failures from query/index Core operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum QueryError {
    #[error("invalid query request: {0}")]
    InvalidQueryRequest(String),
    #[error("invalid query cursor")]
    InvalidQueryCursor,
    #[error("the query observation changed; retry without a cursor")]
    QuerySnapshotChanged,
    #[error("query index rebuild failed: {0}")]
    IndexRebuildFailed(String),
    #[error("the exact historical Folderbase Version is missing: {version_id}")]
    ScopeVersionMissing { version_id: String },
    #[error("the exact historical Folderbase Version is invalid: {version_id}: {message}")]
    ScopeVersionInvalid { version_id: String, message: String },
    #[error(transparent)]
    Capture(#[from] FolderbaseCaptureError),
}

impl FolderbaseQueryEngine {
    /// Open one exact Folderbase Root without writing state.
    pub fn open(root: impl AsRef<Path>) -> Result<Self, QueryError> {
        let store = FolderbaseVersionStore::open(root)?;
        Ok(Self {
            root: store.root_attestation.root,
        })
    }

    /// Run one bounded query against a newly observed scope.
    pub fn run(&self, request: &QueryRequest) -> Result<QueryResult, QueryError> {
        let normalized = normalize_request(request)?;
        let live = matches!(&request.scope, QueryScope::Live);
        let mut observation = match &request.scope {
            QueryScope::Live => observe_live(&self.root)?,
            QueryScope::Historical {
                folderbase_version_id,
            } => observe_historical(&self.root, folderbase_version_id)?,
        };
        let index = live.then(|| read_index(&self.root, &observation));
        let execution = if index
            .as_ref()
            .is_some_and(|index| index.state == QueryIndexState::Fresh)
        {
            let record = index
                .and_then(|index| index.record)
                .expect("fresh index has a verified record");
            observation.entries = record.entries;
            observation.exclusions = record.exclusions;
            QueryExecution::PrivateIndex
        } else {
            QueryExecution::BoundedScan
        };
        let request_sha256 = request_sha256(&normalized)?;
        let after_path = if let Some(cursor) = request.page.cursor.as_deref() {
            let cursor = decode_cursor(cursor)?;
            if cursor.root_instance_sha256 != observation.root_instance_sha256
                || cursor.request_sha256 != request_sha256
            {
                return Err(QueryError::InvalidQueryCursor);
            }
            if cursor.observation_generation != observation.generation {
                return Err(QueryError::QuerySnapshotChanged);
            }
            Some(cursor.last_path)
        } else {
            None
        };
        let entries = observation
            .entries
            .into_iter()
            .filter(|entry| normalized.filters.applies(entry))
            .filter(|entry| {
                after_path
                    .as_ref()
                    .is_none_or(|path| entry.path.as_bytes() > path.as_bytes())
            })
            .collect::<Vec<_>>();
        let returned = entries.len().min(normalized.limit);
        let has_more = returned < entries.len();
        let next_cursor = has_more
            .then(|| {
                encode_cursor(&QueryCursorPayload {
                    root_instance_sha256: observation.root_instance_sha256.clone(),
                    request_sha256: request_sha256.clone(),
                    observation_generation: observation.generation.clone(),
                    last_path: entries[returned - 1].path.clone(),
                })
            })
            .transpose()?;
        Ok(QueryResult {
            root: observation.root,
            folderbase_id: observation.folderbase_id,
            request_sha256,
            observation_generation: observation.generation,
            execution,
            entries: entries.into_iter().take(returned).collect(),
            exclusions: observation.exclusions,
            exclusions_truncated: false,
            page: QueryPageResult {
                limit: normalized.limit,
                returned,
                has_more,
                next_cursor,
            },
        })
    }

    /// Explain one query using the same normalized request and observation.
    pub fn explain(&self, request: &QueryRequest) -> Result<QueryExplain, QueryError> {
        let normalized = normalize_request(request)?;
        let live = matches!(&request.scope, QueryScope::Live);
        let observation = match &request.scope {
            QueryScope::Live => observe_live(&self.root)?,
            QueryScope::Historical {
                folderbase_version_id,
            } => observe_historical(&self.root, folderbase_version_id)?,
        };
        let request_sha256 = request_sha256(&normalized)?;
        if let Some(cursor) = request.page.cursor.as_deref() {
            let cursor = decode_cursor(cursor)?;
            if cursor.root_instance_sha256 != observation.root_instance_sha256
                || cursor.request_sha256 != request_sha256
            {
                return Err(QueryError::InvalidQueryCursor);
            }
            if cursor.observation_generation != observation.generation {
                return Err(QueryError::QuerySnapshotChanged);
            }
        }
        let index_strategy =
            if live && read_index(&self.root, &observation).state == QueryIndexState::Fresh {
                QueryExecution::PrivateIndex
            } else {
                QueryExecution::BoundedScan
            };
        let matched = observation
            .entries
            .iter()
            .filter(|entry| normalized.filters.applies(entry))
            .count();
        let normalized_request = serde_json::to_value(&normalized.value)
            .map_err(|error| QueryError::InvalidQueryRequest(error.to_string()))?;
        Ok(QueryExplain {
            root: observation.root,
            folderbase_id: observation.folderbase_id,
            request_sha256,
            observation_generation: observation.generation,
            normalized_request,
            scope_source: if live {
                QuerySource::CapturePlan
            } else {
                QuerySource::FolderbaseVersion
            },
            index_strategy,
            matched,
            excluded: observation.exclusions,
        })
    }

    /// Inspect disposable-index freshness without writing state.
    pub fn index_status(&self) -> Result<QueryIndexStatus, QueryError> {
        let observation = observe_live(&self.root)?;
        let index = read_index(&self.root, &observation);
        Ok(QueryIndexStatus {
            root: observation.root,
            folderbase_id: observation.folderbase_id,
            state: index.state,
            generation: index.generation,
            observed_generation: observation.generation,
            records: index.records,
        })
    }

    /// Explicitly replace the exact disposable query-index namespace.
    pub fn rebuild_index(&self) -> Result<QueryIndexRebuildResult, QueryError> {
        let observation = observe_live(&self.root)?;
        if observation.entries.len() + observation.exclusions.len() > MAX_INDEX_RECORDS {
            return Err(QueryError::IndexRebuildFailed(
                "derived record count exceeds the private-index bound".to_owned(),
            ));
        }
        let record = PrivateIndexRecord {
            format: INDEX_FORMAT.to_owned(),
            generation: observation.generation.clone(),
            root_instance_sha256: observation.root_instance_sha256.clone(),
            folderbase_id: observation.folderbase_id.clone(),
            entries: observation.entries.clone(),
            exclusions: observation.exclusions.clone(),
        };
        let encoded = serde_json::to_vec(&record)
            .map_err(|error| QueryError::IndexRebuildFailed(error.to_string()))?;
        if encoded.len() as u64 > MAX_INDEX_BYTES {
            return Err(QueryError::IndexRebuildFailed(
                "derived index exceeds 64 MiB".to_owned(),
            ));
        }
        let state = FolderbaseState::open_existing(&self.root)
            .map_err(|error| QueryError::IndexRebuildFailed(error.to_string()))?;
        if let Err(first) = state.ensure_private_dir(Path::new(INDEX_ROOT)) {
            state
                .remove_durable(Path::new(INDEX_ROOT))
                .map_err(|error| QueryError::IndexRebuildFailed(error.to_string()))?;
            state
                .ensure_private_dir(Path::new(INDEX_ROOT))
                .map_err(|error| {
                    QueryError::IndexRebuildFailed(format!("{first}; recovery failed: {error}"))
                })?;
        }
        state
            .replace(Path::new(INDEX_RECORD), &encoded)
            .map_err(|error| QueryError::IndexRebuildFailed(error.to_string()))?;
        let verified = read_index(&self.root, &observation);
        if verified.state != QueryIndexState::Fresh {
            return Err(QueryError::IndexRebuildFailed(
                "published index did not verify against its observation".to_owned(),
            ));
        }
        Ok(QueryIndexRebuildResult {
            root: observation.root,
            folderbase_id: observation.folderbase_id,
            generation: observation.generation,
            records: observation.entries.len(),
            exclusions: observation.exclusions.len(),
        })
    }
}

#[derive(Serialize)]
struct NormalizedQueryRequest<'a> {
    format: &'static str,
    scope: NormalizedQueryScope<'a>,
    filters: NormalizedQueryFilters,
    page: NormalizedQueryPage,
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum NormalizedQueryScope<'a> {
    Live,
    Historical { folderbase_version_id: &'a str },
}

#[derive(Serialize)]
struct NormalizedQueryFilters {
    paths: Vec<String>,
    path_prefixes: Vec<String>,
    kinds: Vec<QueryEntryKind>,
    lifecycles: Vec<QueryLifecycle>,
    object_ids: Vec<String>,
    object_version_ids: Vec<String>,
    minimum_bytes: Option<u64>,
    maximum_bytes: Option<u64>,
}

impl NormalizedQueryFilters {
    fn applies(&self, entry: &QueryEntry) -> bool {
        (self.paths.is_empty() || self.paths.iter().any(|path| path == &entry.path))
            && (self.path_prefixes.is_empty()
                || self.path_prefixes.iter().any(|prefix| {
                    entry.path == *prefix || entry.path.starts_with(&format!("{prefix}/"))
                }))
            && (self.kinds.is_empty() || self.kinds.contains(&entry.kind))
            && (self.lifecycles.is_empty() || self.lifecycles.contains(&entry.lifecycle))
            && (self.object_ids.is_empty()
                || entry
                    .object_id
                    .as_ref()
                    .is_some_and(|value| self.object_ids.contains(value)))
            && (self.object_version_ids.is_empty()
                || entry
                    .object_version_id
                    .as_ref()
                    .is_some_and(|value| self.object_version_ids.contains(value)))
            && self
                .minimum_bytes
                .is_none_or(|minimum| entry.bytes.is_some_and(|bytes| bytes >= minimum))
            && self
                .maximum_bytes
                .is_none_or(|maximum| entry.bytes.is_some_and(|bytes| bytes <= maximum))
    }
}

#[derive(Serialize)]
struct NormalizedQueryPage {
    limit: usize,
}

struct NormalizedRequest<'a> {
    value: NormalizedQueryRequest<'a>,
    filters: NormalizedQueryFilters,
    limit: usize,
}

fn normalize_request(request: &QueryRequest) -> Result<NormalizedRequest<'_>, QueryError> {
    if request.format != QUERY_REQUEST_FORMAT {
        return Err(QueryError::InvalidQueryRequest(
            "unsupported request format".to_owned(),
        ));
    }
    if !(1..=MAX_PAGE_LIMIT).contains(&request.page.limit) {
        return Err(QueryError::InvalidQueryRequest(
            "page limit must be from 1 through 1000".to_owned(),
        ));
    }
    let scope = match &request.scope {
        QueryScope::Live => NormalizedQueryScope::Live,
        QueryScope::Historical {
            folderbase_version_id,
        } => {
            validate_capture_version_id(folderbase_version_id)
                .map_err(|error| QueryError::InvalidQueryRequest(error.to_string()))?;
            NormalizedQueryScope::Historical {
                folderbase_version_id,
            }
        }
    };
    validate_filter_bounds(&request.filters)?;
    let paths = normalize_paths(&request.filters.paths, "paths")?;
    let path_prefixes = normalize_paths(&request.filters.path_prefixes, "path_prefixes")?;
    let kinds = normalize_set(&request.filters.kinds);
    let lifecycles = normalize_set(&request.filters.lifecycles);
    let object_ids = normalize_identifiers(&request.filters.object_ids, "obj_", "object_ids")?;
    let object_version_ids = normalize_identifiers(
        &request.filters.object_version_ids,
        "version_",
        "object_version_ids",
    )?;
    let filters = NormalizedQueryFilters {
        paths,
        path_prefixes,
        kinds,
        lifecycles,
        object_ids,
        object_version_ids,
        minimum_bytes: request.filters.minimum_bytes,
        maximum_bytes: request.filters.maximum_bytes,
    };
    let value = NormalizedQueryRequest {
        format: QUERY_REQUEST_FORMAT,
        scope,
        filters: NormalizedQueryFilters {
            paths: filters.paths.clone(),
            path_prefixes: filters.path_prefixes.clone(),
            kinds: filters.kinds.clone(),
            lifecycles: filters.lifecycles.clone(),
            object_ids: filters.object_ids.clone(),
            object_version_ids: filters.object_version_ids.clone(),
            minimum_bytes: filters.minimum_bytes,
            maximum_bytes: filters.maximum_bytes,
        },
        page: NormalizedQueryPage {
            limit: request.page.limit,
        },
    };
    Ok(NormalizedRequest {
        value,
        filters,
        limit: request.page.limit,
    })
}

fn validate_filter_bounds(filters: &QueryFilters) -> Result<(), QueryError> {
    for (length, maximum, label) in [
        (filters.paths.len(), 256, "paths"),
        (filters.path_prefixes.len(), 256, "path_prefixes"),
        (filters.kinds.len(), 4, "kinds"),
        (filters.lifecycles.len(), 2, "lifecycles"),
        (filters.object_ids.len(), 256, "object_ids"),
        (filters.object_version_ids.len(), 256, "object_version_ids"),
    ] {
        if length > maximum {
            return Err(QueryError::InvalidQueryRequest(format!(
                "{label} exceeds its bounded item limit"
            )));
        }
    }
    if filters.minimum_bytes > filters.maximum_bytes && filters.maximum_bytes.is_some() {
        return Err(QueryError::InvalidQueryRequest(
            "minimum_bytes must not exceed maximum_bytes".to_owned(),
        ));
    }
    if filters
        .minimum_bytes
        .into_iter()
        .chain(filters.maximum_bytes)
        .any(|bytes| bytes > 1_099_511_627_776)
    {
        return Err(QueryError::InvalidQueryRequest(
            "byte filter exceeds 1 TiB".to_owned(),
        ));
    }
    Ok(())
}

fn normalize_paths(values: &[String], label: &str) -> Result<Vec<String>, QueryError> {
    let mut exact = BTreeSet::new();
    let mut nfc = BTreeMap::new();
    let mut folded = BTreeMap::new();
    for path in values {
        validate_capture_path(path)
            .map_err(|error| QueryError::InvalidQueryRequest(error.to_string()))?;
        let nfc_key = path.nfc().collect::<String>();
        let folded_key = nfc_key
            .case_fold()
            .collect::<String>()
            .nfc()
            .collect::<String>();
        for (index, key) in [(&mut nfc, nfc_key), (&mut folded, folded_key)] {
            if index
                .insert(key, path.as_str())
                .is_some_and(|existing| existing != path)
            {
                return Err(QueryError::InvalidQueryRequest(format!(
                    "{label} contains a portable-path collision"
                )));
            }
        }
        exact.insert(path.clone());
    }
    Ok(exact.into_iter().collect())
}

fn normalize_identifiers(
    values: &[String],
    prefix: &str,
    label: &str,
) -> Result<Vec<String>, QueryError> {
    let mut normalized = BTreeSet::new();
    for value in values {
        let uuid = value.strip_prefix(prefix).ok_or_else(|| {
            QueryError::InvalidQueryRequest(format!("{label} contains the wrong namespace"))
        })?;
        let parsed = Uuid::parse_str(uuid).map_err(|_| {
            QueryError::InvalidQueryRequest(format!("{label} contains an invalid UUID"))
        })?;
        if parsed.hyphenated().to_string() != uuid
            || !(1..=8).contains(&(parsed.as_bytes()[6] >> 4))
            || parsed.as_bytes()[8] & 0xc0 != 0x80
        {
            return Err(QueryError::InvalidQueryRequest(format!(
                "{label} contains an unsupported UUID"
            )));
        }
        normalized.insert(value.clone());
    }
    Ok(normalized.into_iter().collect())
}

fn normalize_set<T: Ord + Copy>(values: &[T]) -> Vec<T> {
    values
        .iter()
        .copied()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

struct QueryObservation {
    root: PathBuf,
    root_instance_sha256: String,
    folderbase_id: String,
    generation: String,
    entries: Vec<QueryEntry>,
    exclusions: Vec<QueryExclusion>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivateIndexRecord {
    format: String,
    generation: String,
    root_instance_sha256: String,
    folderbase_id: String,
    entries: Vec<QueryEntry>,
    exclusions: Vec<QueryExclusion>,
}

struct IndexRead {
    state: QueryIndexState,
    generation: Option<String>,
    records: usize,
    record: Option<PrivateIndexRecord>,
}

impl IndexRead {
    fn absent() -> Self {
        Self {
            state: QueryIndexState::Absent,
            generation: None,
            records: 0,
            record: None,
        }
    }

    fn stale(generation: Option<String>, records: usize) -> Self {
        Self {
            state: QueryIndexState::Stale,
            generation,
            records,
            record: None,
        }
    }
}

fn read_index(root: &Path, observation: &QueryObservation) -> IndexRead {
    let state = match FolderbaseState::open_existing_read_only(root) {
        Ok(state) => state,
        Err(_) => return IndexRead::stale(None, 0),
    };
    let encoded = match state.read_bounded_if_present(Path::new(INDEX_RECORD), MAX_INDEX_BYTES) {
        Ok(Some(encoded)) => encoded,
        Ok(None) => return IndexRead::absent(),
        Err(_) => return IndexRead::stale(None, 0),
    };
    let record: PrivateIndexRecord = match serde_json::from_slice(&encoded) {
        Ok(record) => record,
        Err(_) => return IndexRead::stale(None, 0),
    };
    let generation = is_sha256(&record.generation).then(|| record.generation.clone());
    let records = record.entries.len();
    let bounded = record.entries.len() + record.exclusions.len() <= MAX_INDEX_RECORDS;
    let ordered = record
        .entries
        .windows(2)
        .all(|pair| pair[0].path.as_bytes() < pair[1].path.as_bytes())
        && record
            .exclusions
            .windows(2)
            .all(|pair| pair[0].path.as_bytes() < pair[1].path.as_bytes());
    let paths_valid = record
        .entries
        .iter()
        .all(|entry| validate_capture_path(&entry.path).is_ok())
        && record
            .exclusions
            .iter()
            .all(|entry| validate_capture_path(&entry.path).is_ok());
    let equivalent = record.format == INDEX_FORMAT
        && record.generation == observation.generation
        && record.root_instance_sha256 == observation.root_instance_sha256
        && record.folderbase_id == observation.folderbase_id
        && record.entries == observation.entries
        && record.exclusions == observation.exclusions;
    if bounded && ordered && paths_valid && equivalent {
        IndexRead {
            state: QueryIndexState::Fresh,
            generation,
            records,
            record: Some(record),
        }
    } else {
        IndexRead::stale(generation, records.min(MAX_INDEX_RECORDS))
    }
}

fn observe_live(root: &Path) -> Result<QueryObservation, QueryError> {
    let plan = FolderbaseVersionStore::open(root)?.plan_capture()?;
    let generation = live_observation_generation(&plan)?;
    let mut entries = project_live_entries(&plan);
    if let Some(head) = plan.current_local_head()
        && let Ok(version) = read_historical_version(plan.root(), head.version_id())
        && version.folderbase_id() == plan.folderbase_id()
        && version.canonical_digest().ok().as_deref() == Some(head.version_sha256())
    {
        for entry in &mut entries {
            let Some(binding) = version.lookup_binding(&entry.path) else {
                continue;
            };
            let compatible = matches!(
                (entry.kind, binding.kind()),
                (QueryEntryKind::Directory, PathBindingKind::Directory)
                    | (QueryEntryKind::RegularFile, PathBindingKind::RegularFile)
                    | (QueryEntryKind::Symlink, PathBindingKind::Symlink)
            );
            if compatible {
                entry.object_id = Some(binding.object_id().to_owned());
                entry.object_version_id = binding.object_version_id().map(str::to_owned);
            }
        }
    }
    Ok(QueryObservation {
        root: plan.root().to_path_buf(),
        root_instance_sha256: plan.root_instance_sha256().to_owned(),
        folderbase_id: plan.folderbase_id().to_owned(),
        generation,
        entries,
        exclusions: project_live_exclusions(&plan),
    })
}

fn observe_historical(root: &Path, version_id: &str) -> Result<QueryObservation, QueryError> {
    let attestation = attest_folderbase_root(root).map_err(FolderbaseCaptureError::from)?;
    let version = read_historical_version(&attestation.root, version_id)?;
    if version.version_id() != version_id || version.folderbase_id() != attestation.folderbase_id {
        return Err(QueryError::ScopeVersionInvalid {
            version_id: version_id.to_owned(),
            message: "Version identity does not bind the requested Folderbase".to_owned(),
        });
    }
    let canonical_digest =
        version
            .canonical_digest()
            .map_err(|error| QueryError::ScopeVersionInvalid {
                version_id: version_id.to_owned(),
                message: error.to_string(),
            })?;
    let mut entries = version
        .bindings()
        .iter()
        .map(|binding| QueryEntry {
            path: binding.path().to_owned(),
            kind: query_binding_kind(binding.kind()),
            lifecycle: QueryLifecycle::Live,
            bytes: binding.bytes(),
            executable: binding.executable(),
            symlink_target: binding.symlink_target().map(str::to_owned),
            object_id: Some(binding.object_id().to_owned()),
            object_version_id: binding.object_version_id().map(str::to_owned),
            folderbase_version_id: Some(version_id.to_owned()),
            source: QuerySource::FolderbaseVersion,
            boundary_reason: None,
        })
        .collect::<Vec<_>>();
    entries.extend(version.tombstones().iter().map(|tombstone| QueryEntry {
        path: tombstone.path().to_owned(),
        kind: match tombstone.deleted_kind() {
            DeletedKind::Directory => QueryEntryKind::Directory,
            DeletedKind::RegularFile => QueryEntryKind::RegularFile,
            DeletedKind::Symlink => QueryEntryKind::Symlink,
        },
        lifecycle: QueryLifecycle::Deleted,
        bytes: None,
        executable: None,
        symlink_target: None,
        object_id: Some(tombstone.object_id().to_owned()),
        object_version_id: tombstone.last_object_version_id().map(str::to_owned),
        folderbase_version_id: Some(version_id.to_owned()),
        source: QuerySource::FolderbaseVersion,
        boundary_reason: None,
    }));
    entries.extend(
        version
            .exclusions()
            .iter()
            .filter(|exclusion| exclusion.kind() == ExclusionKind::NestedFolderbase)
            .map(|exclusion| QueryEntry {
                path: exclusion.path().to_owned(),
                kind: QueryEntryKind::NestedFolderbase,
                lifecycle: QueryLifecycle::Live,
                bytes: None,
                executable: None,
                symlink_target: None,
                object_id: None,
                object_version_id: None,
                folderbase_version_id: Some(version_id.to_owned()),
                source: QuerySource::FolderbaseVersion,
                boundary_reason: Some("nested-folderbase-boundary".to_owned()),
            }),
    );
    entries.sort_by(|left, right| left.path.as_bytes().cmp(right.path.as_bytes()));
    let exclusions = version
        .exclusions()
        .iter()
        .map(|exclusion| QueryExclusion {
            path: exclusion.path().to_owned(),
            reason: match exclusion.kind() {
                ExclusionKind::NestedFolderbase => "nested-folderbase-boundary",
                _ => "unsupported-v1",
            }
            .to_owned(),
            kind: Some(query_version_exclusion_kind(exclusion.kind())),
        })
        .collect();
    let mut digest = Sha256::new();
    digest.update(b"folderbase-query-historical-observation-v1\0");
    digest.update(attestation.root_instance_sha256.as_bytes());
    digest.update(version_id.as_bytes());
    digest.update(canonical_digest.as_bytes());
    Ok(QueryObservation {
        root: attestation.root,
        root_instance_sha256: attestation.root_instance_sha256,
        folderbase_id: attestation.folderbase_id,
        generation: format!("{:x}", digest.finalize()),
        entries,
        exclusions,
    })
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct QueryCursorPayload {
    root_instance_sha256: String,
    request_sha256: String,
    observation_generation: String,
    last_path: String,
}

fn encode_cursor(payload: &QueryCursorPayload) -> Result<String, QueryError> {
    let bytes = serde_json::to_vec(payload).map_err(|_| QueryError::InvalidQueryCursor)?;
    let mut checksum = Sha256::new();
    checksum.update(b"folderbase-query-cursor-v1\0");
    checksum.update(&bytes);
    let mut encoded = String::with_capacity(5 + bytes.len() * 2 + 64);
    encoded.push_str("fbq1_");
    append_hex(&mut encoded, &bytes);
    append_hex(&mut encoded, &checksum.finalize());
    if encoded.len() > 8_192 {
        return Err(QueryError::InvalidQueryCursor);
    }
    Ok(encoded)
}

fn decode_cursor(cursor: &str) -> Result<QueryCursorPayload, QueryError> {
    let encoded = cursor
        .strip_prefix("fbq1_")
        .ok_or(QueryError::InvalidQueryCursor)?;
    if cursor.len() > 8_192 || encoded.len() < 66 || encoded.len() % 2 != 0 {
        return Err(QueryError::InvalidQueryCursor);
    }
    let (payload, checksum) = encoded.split_at(encoded.len() - 64);
    let bytes = decode_hex(payload)?;
    let expected = decode_hex(checksum)?;
    let mut digest = Sha256::new();
    digest.update(b"folderbase-query-cursor-v1\0");
    digest.update(&bytes);
    if digest.finalize().as_slice() != expected {
        return Err(QueryError::InvalidQueryCursor);
    }
    let payload: QueryCursorPayload =
        serde_json::from_slice(&bytes).map_err(|_| QueryError::InvalidQueryCursor)?;
    if !is_sha256(&payload.root_instance_sha256)
        || !is_sha256(&payload.request_sha256)
        || !is_sha256(&payload.observation_generation)
        || validate_capture_path(&payload.last_path).is_err()
    {
        return Err(QueryError::InvalidQueryCursor);
    }
    Ok(payload)
}

fn append_hex(output: &mut String, bytes: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in bytes {
        output.push(char::from(HEX[(byte >> 4) as usize]));
        output.push(char::from(HEX[(byte & 0xf) as usize]));
    }
}

fn decode_hex(encoded: &str) -> Result<Vec<u8>, QueryError> {
    encoded
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_nibble(pair[0]).ok_or(QueryError::InvalidQueryCursor)?;
            let low = hex_nibble(pair[1]).ok_or(QueryError::InvalidQueryCursor)?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn read_historical_version(root: &Path, version_id: &str) -> Result<FolderbaseVersion, QueryError> {
    validate_capture_version_id(version_id)
        .map_err(|error| QueryError::InvalidQueryRequest(error.to_string()))?;
    let state = FolderbaseState::open_existing_read_only(root).map_err(|error| {
        QueryError::ScopeVersionInvalid {
            version_id: version_id.to_owned(),
            message: error.to_string(),
        }
    })?;
    let relative = Path::new(".folderbase/versions/folderbase").join(format!("{version_id}.json"));
    let encoded = state
        .read_bounded(&relative, MAX_ENCODED_VERSION_BYTES)
        .map_err(|error| QueryError::ScopeVersionInvalid {
            version_id: version_id.to_owned(),
            message: error.to_string(),
        })?
        .ok_or_else(|| QueryError::ScopeVersionMissing {
            version_id: version_id.to_owned(),
        })?;
    FolderbaseVersion::decode_bounded(encoded.as_slice()).map_err(|error| {
        QueryError::ScopeVersionInvalid {
            version_id: version_id.to_owned(),
            message: error.to_string(),
        }
    })
}

fn query_binding_kind(kind: PathBindingKind) -> QueryEntryKind {
    match kind {
        PathBindingKind::Directory => QueryEntryKind::Directory,
        PathBindingKind::RegularFile => QueryEntryKind::RegularFile,
        PathBindingKind::Symlink => QueryEntryKind::Symlink,
    }
}

fn query_version_exclusion_kind(kind: ExclusionKind) -> QueryExclusionKind {
    match kind {
        ExclusionKind::NestedFolderbase => QueryExclusionKind::NestedFolderbase,
        ExclusionKind::HardLink => QueryExclusionKind::HardLink,
        ExclusionKind::Fifo => QueryExclusionKind::Fifo,
        ExclusionKind::Socket => QueryExclusionKind::Socket,
        ExclusionKind::BlockDevice => QueryExclusionKind::BlockDevice,
        ExclusionKind::CharacterDevice => QueryExclusionKind::CharacterDevice,
        ExclusionKind::OtherSpecial => QueryExclusionKind::OtherSpecial,
    }
}

fn project_live_entries(plan: &CapturePlan) -> Vec<QueryEntry> {
    let mut entries = plan
        .entries()
        .iter()
        .map(|entry| QueryEntry {
            path: entry.path().to_owned(),
            kind: match entry.kind() {
                CaptureEntryKind::Directory => QueryEntryKind::Directory,
                CaptureEntryKind::RegularFile => QueryEntryKind::RegularFile,
                CaptureEntryKind::Symlink => QueryEntryKind::Symlink,
            },
            lifecycle: QueryLifecycle::Live,
            bytes: entry.bytes(),
            executable: entry.executable(),
            symlink_target: entry.symlink_target().map(str::to_owned),
            object_id: None,
            object_version_id: None,
            folderbase_version_id: None,
            source: QuerySource::CapturePlan,
            boundary_reason: None,
        })
        .collect::<Vec<_>>();
    entries.extend(plan.exclusions().iter().filter_map(|exclusion| {
        (exclusion.kind() == CaptureExclusionKind::NestedFolderbase).then(|| QueryEntry {
            path: exclusion.path().to_owned(),
            kind: QueryEntryKind::NestedFolderbase,
            lifecycle: QueryLifecycle::Live,
            bytes: None,
            executable: None,
            symlink_target: None,
            object_id: None,
            object_version_id: None,
            folderbase_version_id: None,
            source: QuerySource::CapturePlan,
            boundary_reason: Some("nested-folderbase-boundary".to_owned()),
        })
    }));
    entries.sort_by(|left, right| left.path.as_bytes().cmp(right.path.as_bytes()));
    entries
}

fn project_live_exclusions(plan: &CapturePlan) -> Vec<QueryExclusion> {
    let mut exclusions = plan
        .ignored_paths()
        .iter()
        .map(|ignored| QueryExclusion {
            path: ignored.path().to_owned(),
            reason: "capture-ignore-policy".to_owned(),
            kind: None,
        })
        .collect::<Vec<_>>();
    exclusions.extend(plan.exclusions().iter().map(|exclusion| {
        QueryExclusion {
            path: exclusion.path().to_owned(),
            reason: match exclusion.reason() {
                CaptureExclusionReason::NestedFolderbaseBoundary => "nested-folderbase-boundary",
                CaptureExclusionReason::UnsupportedV1 => "unsupported-v1",
            }
            .to_owned(),
            kind: Some(match exclusion.kind() {
                CaptureExclusionKind::NestedFolderbase => QueryExclusionKind::NestedFolderbase,
                CaptureExclusionKind::HardLink => QueryExclusionKind::HardLink,
                CaptureExclusionKind::Fifo => QueryExclusionKind::Fifo,
                CaptureExclusionKind::Socket => QueryExclusionKind::Socket,
                CaptureExclusionKind::BlockDevice => QueryExclusionKind::BlockDevice,
                CaptureExclusionKind::CharacterDevice => QueryExclusionKind::CharacterDevice,
                CaptureExclusionKind::OtherSpecial => QueryExclusionKind::OtherSpecial,
            }),
        }
    }));
    exclusions.sort_by(|left, right| left.path.as_bytes().cmp(right.path.as_bytes()));
    exclusions
}

fn request_sha256(request: &NormalizedRequest<'_>) -> Result<String, QueryError> {
    let bytes = serde_json::to_vec(&request.value)
        .map_err(|error| QueryError::InvalidQueryRequest(error.to_string()))?;
    let mut digest = Sha256::new();
    digest.update(b"folderbase-query-request-v1\0");
    digest.update(bytes);
    Ok(format!("{:x}", digest.finalize()))
}

fn live_observation_generation(plan: &CapturePlan) -> Result<String, QueryError> {
    #[derive(Serialize)]
    struct Observation<'a> {
        root_instance_sha256: &'a str,
        folderbase_id: &'a str,
        root_manifest_sha256: &'a str,
        root_manifest_bytes: u64,
        ignore_policy_sha256: &'a str,
        local_head: Option<(&'a str, &'a str, &'a str)>,
        entries: Vec<(
            &'a str,
            CaptureEntryKind,
            Option<u64>,
            Option<bool>,
            Option<&'a str>,
            &'a crate::folderbase_capture::CaptureMetadataFingerprint,
        )>,
        exclusions: Vec<(&'a str, CaptureExclusionKind, CaptureExclusionReason)>,
        ignored_paths: Vec<&'a str>,
    }
    let local_head = plan.current_local_head().map(|head| {
        (
            head.version_id(),
            head.version_sha256(),
            head.authority().sha256(),
        )
    });
    let observation = Observation {
        root_instance_sha256: plan.root_instance_sha256(),
        folderbase_id: plan.folderbase_id(),
        root_manifest_sha256: plan.root_manifest_sha256(),
        root_manifest_bytes: plan.root_manifest_bytes(),
        ignore_policy_sha256: plan.ignore_policy_sha256(),
        local_head,
        entries: plan
            .entries()
            .iter()
            .map(|entry| {
                (
                    entry.path(),
                    entry.kind(),
                    entry.bytes(),
                    entry.executable(),
                    entry.symlink_target(),
                    entry.observed(),
                )
            })
            .collect(),
        exclusions: plan
            .exclusions()
            .iter()
            .map(|exclusion| (exclusion.path(), exclusion.kind(), exclusion.reason()))
            .collect(),
        ignored_paths: plan
            .ignored_paths()
            .iter()
            .map(|path| path.path())
            .collect(),
    };
    let bytes = serde_json::to_vec(&observation)
        .map_err(|error| QueryError::InvalidQueryRequest(error.to_string()))?;
    let mut digest = Sha256::new();
    digest.update(b"folderbase-query-live-observation-v1\0");
    digest.update(bytes);
    Ok(format!("{:x}", digest.finalize()))
}

#[cfg(test)]
mod tests {
    use std::{fs, io};

    use tempfile::tempdir;

    use super::{FolderbaseQueryEngine, INDEX_RECORD, QueryIndexState};

    const MANIFEST: &[u8] = br#"{
      "$schema": "https://folderbase.ai/protocol/0.5/folderbase.schema.json",
      "protocol_version": "0.5.0",
      "folderbase": {
        "id": "folderbase_019f9b75-4f42-7f65-a012-2bfecdd8c473",
        "name": "Query failure fixture",
        "kind": "project",
        "status": "active",
        "created_at": "2026-08-04T00:00:00Z"
      },
      "adapters": [],
      "policies": {
        "availability": "keep_local",
        "structural_changes": "approve",
        "archive": "manual",
        "cloud_sync": "disabled",
        "capture_ignore": {"format": "folderbase-capture-ignore-v1", "rules": []}
      }
    }"#;

    #[test]
    fn failure_before_index_publication_preserves_the_previous_generation() {
        let root = tempdir().expect("temporary Folderbase");
        fs::create_dir(root.path().join(".folderbase")).expect("state");
        fs::write(root.path().join(".folderbase/manifest.json"), MANIFEST).expect("manifest");
        fs::write(root.path().join("ordinary.md"), b"ordinary\n").expect("ordinary file");
        let engine = FolderbaseQueryEngine::open(root.path()).expect("query engine");
        engine.rebuild_index().expect("initial index");
        let before = fs::read(root.path().join(INDEX_RECORD)).expect("initial bytes");

        let failure = engine
            .rebuild_index_with_before_publish(|| {
                Err(io::Error::other("injected pre-publication failure"))
            })
            .expect_err("injected rebuild failure");
        assert!(
            failure
                .to_string()
                .contains("injected pre-publication failure")
        );
        assert_eq!(fs::read(root.path().join(INDEX_RECORD)).unwrap(), before);
        assert_eq!(
            engine.index_status().unwrap().state(),
            QueryIndexState::Fresh
        );
    }
}

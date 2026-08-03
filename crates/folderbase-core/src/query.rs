//! Bounded, metadata-only query projection for one Folderbase Root.
//!
//! Live query never owns filesystem traversal. It projects the exact
//! [`crate::CapturePlan`] produced by [`crate::FolderbaseVersionStore`].

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    CaptureEntryKind, CaptureExclusionKind, CaptureExclusionReason, CapturePlan,
    FolderbaseCaptureError, FolderbaseVersionStore,
};

const QUERY_REQUEST_FORMAT: &str = "folderbase-query-request-v1";
const MAX_PAGE_LIMIT: usize = 1_000;

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
    page: QueryPage,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum QueryScope {
    Live,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct QueryPage {
    limit: usize,
}

impl QueryRequest {
    /// Construct one live query with a page limit from 1 through 1000.
    pub fn live(limit: usize) -> Self {
        Self {
            format: QUERY_REQUEST_FORMAT.to_owned(),
            scope: QueryScope::Live,
            page: QueryPage { limit },
        }
    }
}

/// Source observation from which a query row was projected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuerySource {
    CapturePlan,
    FolderbaseVersion,
}

/// Filesystem kind exposed by query 0.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueryEntryKind {
    Directory,
    NestedFolderbase,
    RegularFile,
    Symlink,
}

/// Lifecycle exposed by query 0.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
        validate_request(request)?;
        let plan = FolderbaseVersionStore::open(&self.root)?.plan_capture()?;
        let observation_generation = live_observation_generation(&plan)?;
        let entries = project_live_entries(&plan);
        let exclusions = project_live_exclusions(&plan);
        let returned = entries.len().min(request.page.limit);
        let has_more = returned < entries.len();
        Ok(QueryResult {
            root: plan.root().to_path_buf(),
            folderbase_id: plan.folderbase_id().to_owned(),
            request_sha256: request_sha256(request)?,
            observation_generation,
            execution: QueryExecution::BoundedScan,
            entries: entries.into_iter().take(returned).collect(),
            exclusions,
            exclusions_truncated: false,
            page: QueryPageResult {
                limit: request.page.limit,
                returned,
                has_more,
                next_cursor: None,
            },
        })
    }
}

fn validate_request(request: &QueryRequest) -> Result<(), QueryError> {
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
    Ok(())
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

fn request_sha256(request: &QueryRequest) -> Result<String, QueryError> {
    let bytes = serde_json::to_vec(request)
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

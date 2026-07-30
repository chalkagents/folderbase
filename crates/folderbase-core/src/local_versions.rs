//! Immutable local content versions and the append-only object journal.
//!
//! The journal is the durable history of accepted operations. Object metadata
//! is a current-state projection that can be rebuilt from that history. Version
//! records and content blobs are installed with no-clobber semantics and are
//! never rewritten.

use std::{
    collections::BTreeMap,
    fmt::Write as _,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Component, Path, PathBuf},
};

use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    FolderbaseError, Result,
    folderbase_state::FolderbaseState,
    workspace::{
        canonical_folderbase_root, has_nested_folderbase_marker, is_reserved_workspace_component,
        resolve_existing_workspace_file,
    },
};

const OBJECT_SCHEMA: &str = "https://folderbase.ai/protocol/0.1/object.schema.json";
const OBJECTS_DIRECTORY: &str = ".folderbase/objects";
const VERSION_RECORDS_DIRECTORY: &str = ".folderbase/versions/records";
const BLOBS_DIRECTORY: &str = ".folderbase/versions/blobs/sha256";
const JOURNAL_PATH: &str = ".folderbase/journal/objects.ndjson";
const JOURNAL_QUARANTINE_DIRECTORY: &str = ".folderbase/journal/quarantine";
const TRANSACTIONS_DIRECTORY: &str = ".folderbase/transactions";
const LOCKS_DIRECTORY: &str = ".folderbase/locks";
const TRANSACTION_LOCK_PATH: &str = ".folderbase/locks/transactions.lock";
const COPY_BUFFER_BYTES: usize = 64 * 1024;
const MAX_CAPTURE_PROJECTION_RECORD_BYTES: u64 = 1024 * 1024;
const PATH_IDENTITIES_DIRECTORY: &str = ".folderbase/local/path-identities";
const HISTORY_TRANSFER_INTENTS_DIRECTORY: &str = ".folderbase/history-transfers/intents";
const HISTORY_TRANSFER_OUTGOING_DIRECTORY: &str = ".folderbase/history-transfers/outgoing";
const HISTORY_TRANSFER_INCOMING_DIRECTORY: &str = ".folderbase/history-transfers/incoming";
const HISTORY_TRANSFER_STAGING_DIRECTORY: &str = ".folderbase/history-transfers/staging";

/// A stable object identity that does not depend on the object's current path.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ObjectId(String);

impl ObjectId {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn new() -> Self {
        Self(format!("obj_{}", Uuid::now_v7()))
    }

    fn validate(&self, record_path: &Path) -> Result<()> {
        validate_prefixed_uuid(&self.0, "obj_", record_path)
    }

    pub fn parse(value: impl Into<String>) -> Result<Self> {
        let value = Self(value.into());
        value.validate(Path::new("object-id"))?;
        Ok(value)
    }
}

impl std::fmt::Display for ObjectId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// The identity of one immutable capture of an object's bytes.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct VersionId(String);

impl VersionId {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn new() -> Self {
        Self(format!("version_{}", Uuid::now_v7()))
    }

    fn validate(&self, record_path: &Path) -> Result<()> {
        validate_prefixed_uuid(&self.0, "version_", record_path)
    }

    pub fn parse(value: impl Into<String>) -> Result<Self> {
        let value = Self(value.into());
        value.validate(Path::new("version-id"))?;
        Ok(value)
    }
}

impl std::fmt::Display for VersionId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectLifecycle {
    pub status: String,
    #[serde(flatten)]
    pub extensions: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectProvenance {
    pub created_at: String,
    pub source: String,
    #[serde(flatten)]
    pub extensions: BTreeMap<String, Value>,
}

/// Current materialization metadata for a tracked object.
///
/// Unknown top-level and nested fields survive a read/modify/write cycle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalObjectRecord {
    #[serde(rename = "$schema")]
    pub schema: String,
    pub id: ObjectId,
    #[serde(rename = "type")]
    pub object_type: String,
    pub path: String,
    pub lifecycle: ObjectLifecycle,
    pub provenance: ObjectProvenance,
    pub current_version: VersionId,
    pub versions: Vec<VersionId>,
    #[serde(flatten)]
    pub extensions: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContentDigest {
    pub algorithm: String,
    pub digest: String,
    pub bytes: u64,
}

/// Immutable metadata for one captured version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalVersionRecord {
    pub id: VersionId,
    pub object_id: ObjectId,
    pub content: ContentDigest,
    pub captured_at: String,
    #[serde(flatten)]
    pub extensions: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum JournalAction {
    #[serde(rename = "object.tracked")]
    ObjectTracked,
    #[serde(rename = "object.relocated")]
    ObjectRelocated,
    #[serde(rename = "version.captured")]
    VersionCaptured,
    #[serde(rename = "version.restored")]
    VersionRestored,
}

/// One append-only journal line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectJournalEvent {
    pub id: String,
    pub at: String,
    pub action: JournalAction,
    pub object_id: ObjectId,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version_id: Option<VersionId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<ContentDigest>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CaptureResult {
    pub object: LocalObjectRecord,
    pub version: LocalVersionRecord,
    pub object_created: bool,
    pub version_created: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RestoreResult {
    pub object_id: ObjectId,
    pub version_id: VersionId,
    pub path: PathBuf,
    pub content: ContentDigest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoryTransferState {
    Proposed,
    Approved,
    Applying,
    DestinationVerified,
    SourceReleased,
    Verified,
    Conflicted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryTransferPlan {
    protocol_version: String,
    id: String,
    source_root: PathBuf,
    destination_root: PathBuf,
    source_folderbase_id: String,
    destination_folderbase_id: String,
    source_manifest_sha256: String,
    destination_manifest_sha256: String,
    object: LocalObjectRecord,
    destination_path: String,
    versions: Vec<LocalVersionRecord>,
    state: HistoryTransferState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    approval_digest: Option<String>,
}

impl HistoryTransferPlan {
    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn state(&self) -> HistoryTransferState {
        self.state
    }

    pub fn source_folderbase_id(&self) -> &str {
        &self.source_folderbase_id
    }

    pub fn destination_folderbase_id(&self) -> &str {
        &self.destination_folderbase_id
    }

    pub fn object_id(&self) -> &ObjectId {
        &self.object.id
    }

    pub fn version_ids(&self) -> impl Iterator<Item = &VersionId> {
        self.versions.iter().map(|version| &version.id)
    }
}

#[derive(Debug)]
pub struct ApprovedHistoryTransfer {
    plan: HistoryTransferPlan,
    approval_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryTransferResult {
    pub transfer_id: String,
    pub source_folderbase_id: String,
    pub destination_folderbase_id: String,
    pub object_id: ObjectId,
    pub state: HistoryTransferState,
    pub version_ids: Vec<VersionId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct HistoryTransferReceipt {
    protocol_version: String,
    transfer_id: String,
    source_folderbase_id: String,
    destination_folderbase_id: String,
    object_id: ObjectId,
    approval_digest: String,
    version_ids: Vec<VersionId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HistoryTransferCheckpoint {
    Applying,
    DestinationStaged,
    DestinationVerified,
    SourceReceiptWritten,
    SourceReleased,
    IncomingReceiptWritten,
    DestinationActivated,
    Verified,
}

/// Durable intent for a projection change.
///
/// The immutable blob is installed before this record. Once this record is
/// durable, every remaining step is idempotent: install the immutable version
/// record, replace the derived object projection, append missing journal
/// events, and remove the intent. A later write replays any intent left behind
/// by an interrupted process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PendingTransaction {
    protocol_version: String,
    id: String,
    version: Option<LocalVersionRecord>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    versions: Vec<LocalVersionRecord>,
    object: LocalObjectRecord,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    restore: Option<PendingRestore>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    replacement: Option<PendingReplacement>,
    events: Vec<ObjectJournalEvent>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PendingRestore {
    version_id: VersionId,
    destination: String,
    content: ContentDigest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PendingReplacement {
    destination: String,
    previous_content: ContentDigest,
    content: ContentDigest,
    readonly: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    unix_mode: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    file_identity: Option<FileSystemIdentity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    parent_identity: Option<FileSystemIdentity>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct FileSystemIdentity {
    device: u64,
    inode: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct LocalPathIdentity {
    object_id: ObjectId,
    file_system: FileSystemIdentity,
}

#[derive(Debug, Clone)]
pub(crate) struct VersionedReplaceResult {
    pub object_id: ObjectId,
    pub version_id: VersionId,
    pub previous_content: ContentDigest,
    pub content: ContentDigest,
}

pub(crate) struct StoreTransactionLock {
    file: File,
}

struct FolderbaseIdentity {
    id: String,
    manifest_sha256: String,
}

impl Drop for StoreTransactionLock {
    fn drop(&mut self) {
        let _ = File::unlock(&self.file);
    }
}

/// Filesystem-backed local version storage for one folderbase root.
#[derive(Debug, Clone)]
pub struct LocalVersionStore {
    root: PathBuf,
}

impl LocalVersionStore {
    /// Open a store rooted at an existing directory.
    ///
    /// Storage directories are created lazily by the first accepted write.
    /// Reopening a store that already has a transaction directory replays
    /// durable pending work and repairs an interrupted final journal append.
    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        let store = Self::open_read_only(root)?;
        match fs::symlink_metadata(store.root.join(TRANSACTIONS_DIRECTORY)) {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
                let _lock = store.acquire_transaction_lock()?;
                store.ensure_store_layout()?;
            }
            Ok(_) => {
                return Err(FolderbaseError::UnsafePath(
                    store.root.join(TRANSACTIONS_DIRECTORY),
                ));
            }
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(FolderbaseError::io(
                    store.root.join(TRANSACTIONS_DIRECTORY),
                    source,
                ));
            }
        }
        Ok(store)
    }

    /// Open without replaying or publishing state. Capture sealing uses this
    /// after retaining its own no-follow state capability.
    pub(crate) fn open_read_only(root: impl AsRef<Path>) -> Result<Self> {
        let supplied = root.as_ref();
        let root = canonical_folderbase_root(supplied)?;
        Ok(Self { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub(crate) fn tracked_object_id(
        &self,
        relative_path: impl AsRef<Path>,
    ) -> Result<Option<ObjectId>> {
        let relative_path = safe_content_path(relative_path.as_ref())?;
        self.find_object_by_path(&relative_path)
            .map(|record| record.map(|record| record.id))
    }

    pub fn propose_history_transfer(
        &self,
        destination: &LocalVersionStore,
        source_folderbase_id: &str,
        destination_folderbase_id: &str,
        object_id: &ObjectId,
        destination_path: impl AsRef<Path>,
    ) -> Result<HistoryTransferPlan> {
        let source_identity = read_folderbase_identity(&self.root)?;
        let destination_identity = read_folderbase_identity(&destination.root)?;
        if source_identity.id != source_folderbase_id {
            return Err(invalid_record(
                self.root.join(".folderbase/manifest.json"),
                "explicit source folderbase ID does not match the active manifest",
            ));
        }
        if destination_identity.id != destination_folderbase_id {
            return Err(invalid_record(
                destination.root.join(".folderbase/manifest.json"),
                "explicit destination folderbase ID does not match the active manifest",
            ));
        }
        let nested_root = destination
            .root
            .strip_prefix(&self.root)
            .map_err(|_| FolderbaseError::UnsafePath(destination.root.clone()))?;
        let nested_root = safe_content_path(nested_root)?;
        if !has_nested_folderbase_marker(&destination.root)? {
            return Err(invalid_record(
                &destination.root,
                "history destination must be an active nested folderbase",
            ));
        }
        let destination_path = safe_content_path(destination_path.as_ref())?;
        let object = self.read_object_record_for_transfer(object_id)?;
        if Path::new(&object.path) != nested_root.join(&destination_path) {
            return Err(invalid_record(
                self.object_record_path(object_id),
                "tracked source path does not map to the requested nested-folderbase destination",
            ));
        }
        let (materialized, canonical_destination_path) =
            resolve_existing_workspace_file(&destination.root, &destination_path)?;
        if canonical_destination_path != destination_path {
            return Err(FolderbaseError::UnsafePath(destination_path));
        }

        if read_optional_file_nofollow(&destination.object_record_path(object_id))?.is_some()
            || destination
                .find_object_by_path(&canonical_destination_path)?
                .is_some()
        {
            return Err(FolderbaseError::WouldOverwrite(
                destination.object_record_path(object_id),
            ));
        }

        let mut versions = Vec::with_capacity(object.versions.len());
        for version_id in &object.versions {
            let version = self.read_version_record(version_id)?;
            if version.object_id != object.id {
                return Err(invalid_record(
                    self.version_record_path(version_id),
                    "version belongs to a different object",
                ));
            }
            verify_file_content(&self.blob_path(&version.content.digest), &version.content)?;
            if let Some(bytes) =
                read_optional_file_nofollow(&destination.version_record_path(version_id))?
            {
                let existing: LocalVersionRecord =
                    serde_json::from_slice(&bytes).map_err(|source| {
                        FolderbaseError::json(destination.version_record_path(version_id), source)
                    })?;
                if existing != version {
                    return Err(FolderbaseError::WouldOverwrite(
                        destination.version_record_path(version_id),
                    ));
                }
            }
            versions.push(version);
        }
        let current = versions
            .iter()
            .find(|version| version.id == object.current_version)
            .ok_or_else(|| {
                invalid_record(
                    self.object_record_path(object_id),
                    "current version is absent from transfer history",
                )
            })?;
        verify_file_content(&materialized, &current.content)?;

        let plan = HistoryTransferPlan {
            protocol_version: "0.1.0".to_owned(),
            id: format!("history_transfer_{}", Uuid::now_v7()),
            source_root: self.root.clone(),
            destination_root: destination.root.clone(),
            source_folderbase_id: source_identity.id,
            destination_folderbase_id: destination_identity.id,
            source_manifest_sha256: source_identity.manifest_sha256,
            destination_manifest_sha256: destination_identity.manifest_sha256,
            object,
            destination_path: relative_path_to_string(&destination_path)?,
            versions,
            state: HistoryTransferState::Proposed,
            approval_digest: None,
        };
        ensure_directory_chain(&self.root, Path::new(HISTORY_TRANSFER_INTENTS_DIRECTORY))?;
        write_json_new(&history_transfer_plan_path(&self.root, &plan.id), &plan)?;
        Ok(plan)
    }

    fn read_object_record_for_transfer(&self, object_id: &ObjectId) -> Result<LocalObjectRecord> {
        object_id.validate(&self.object_record_path(object_id))?;
        let path = self.object_record_path(object_id);
        let record: LocalObjectRecord = read_json(&path)?;
        if record.id != *object_id
            || record.versions.is_empty()
            || !record.versions.contains(&record.current_version)
        {
            return Err(invalid_record(
                path,
                "object record is inconsistent for history transfer",
            ));
        }
        safe_content_path(Path::new(&record.path))
            .map_err(|_| invalid_record(path, "object record has an unsafe path"))?;
        Ok(record)
    }

    /// Capture the current bytes of a regular file.
    ///
    /// Repeated captures at the same tracked path reuse the stable object ID.
    /// Capturing unchanged bytes is idempotent and does not append a duplicate
    /// version or journal event.
    pub fn capture_file(&self, relative_path: impl AsRef<Path>) -> Result<CaptureResult> {
        let relative_path = safe_content_path(relative_path.as_ref())?;
        let _lock = self.acquire_transaction_lock()?;
        self.ensure_store_layout()?;
        let (materialized_path, relative_path) =
            resolve_existing_workspace_file(&self.root, &relative_path)?;

        let existing_object = self.find_object_by_path(&relative_path)?;
        let object_created = existing_object.is_none();
        let object_id = existing_object
            .as_ref()
            .map(|record| record.id.clone())
            .unwrap_or_else(ObjectId::new);

        let content = self.install_content_blob(&materialized_path)?;

        if let Some(object) = existing_object.as_ref() {
            let current = self.read_version(&object.current_version)?;
            if current.content == content {
                self.persist_canonical_object_path(object)?;
                self.write_local_file_identity(&object.id, &materialized_path)?;
                return Ok(CaptureResult {
                    object: object.clone(),
                    version: current,
                    object_created: false,
                    version_created: false,
                });
            }
        }

        let captured_at = Utc::now().to_rfc3339();
        let version = LocalVersionRecord {
            id: VersionId::new(),
            object_id: object_id.clone(),
            content: content.clone(),
            captured_at: captured_at.clone(),
            extensions: BTreeMap::new(),
        };

        let path_string = relative_path_to_string(&relative_path)?;
        let object = match existing_object {
            Some(mut record) => {
                record.current_version = version.id.clone();
                record.versions.push(version.id.clone());
                record
            }
            None => LocalObjectRecord {
                schema: OBJECT_SCHEMA.to_owned(),
                id: object_id.clone(),
                object_type: "file".to_owned(),
                path: path_string.clone(),
                lifecycle: ObjectLifecycle {
                    status: "canonical".to_owned(),
                    extensions: BTreeMap::new(),
                },
                provenance: ObjectProvenance {
                    created_at: captured_at.clone(),
                    source: "local".to_owned(),
                    extensions: BTreeMap::new(),
                },
                current_version: version.id.clone(),
                versions: vec![version.id.clone()],
                extensions: BTreeMap::new(),
            },
        };

        let mut events = Vec::with_capacity(if object_created { 2 } else { 1 });
        if object_created {
            events.push(ObjectJournalEvent {
                id: format!("event_{}", Uuid::now_v7()),
                at: captured_at.clone(),
                action: JournalAction::ObjectTracked,
                object_id: object_id.clone(),
                path: path_string.clone(),
                previous_path: None,
                version_id: None,
                content: None,
            });
        }
        events.push(ObjectJournalEvent {
            id: format!("event_{}", Uuid::now_v7()),
            at: captured_at,
            action: JournalAction::VersionCaptured,
            object_id: object_id.clone(),
            path: path_string,
            previous_path: None,
            version_id: Some(version.id.clone()),
            content: Some(content),
        });
        self.commit_transaction(PendingTransaction {
            protocol_version: "0.1.0".to_owned(),
            id: format!("transaction_{}", Uuid::now_v7()),
            version: Some(version.clone()),
            versions: Vec::new(),
            object: object.clone(),
            restore: None,
            replacement: None,
            events,
        })?;

        Ok(CaptureResult {
            object,
            version,
            object_created,
            version_created: true,
        })
    }

    pub(crate) fn replace_file_versioned(
        &self,
        relative_path: impl AsRef<Path>,
        expected: &ContentDigest,
        new_bytes: &[u8],
    ) -> Result<VersionedReplaceResult> {
        let relative_path = safe_content_path(relative_path.as_ref())?;
        let _lock = self.acquire_transaction_lock()?;
        self.ensure_store_layout()?;
        let (materialized_path, relative_path) =
            resolve_existing_workspace_file(&self.root, &relative_path)?;

        let current_file = open_existing_nofollow(&materialized_path)?;
        let metadata = current_file
            .metadata()
            .map_err(|source| FolderbaseError::io(&materialized_path, source))?;
        let parent = materialized_path
            .parent()
            .ok_or_else(|| FolderbaseError::UnsafePath(materialized_path.clone()))?;
        let parent_metadata =
            fs::metadata(parent).map_err(|source| FolderbaseError::io(parent, source))?;
        let current_content = hash_reader(current_file, &materialized_path)?;
        if current_content != *expected {
            return Err(FolderbaseError::WorkspaceContentChanged(relative_path));
        }
        let captured_current = self.install_content_blob(&materialized_path)?;
        if captured_current != current_content {
            return Err(FolderbaseError::WorkspaceContentChanged(relative_path));
        }
        let next_content = self.install_content_bytes(new_bytes)?;

        let existing_object = self.find_object_by_path(&relative_path)?;
        let object_created = existing_object.is_none();
        let object_id = existing_object
            .as_ref()
            .map(|object| object.id.clone())
            .unwrap_or_else(ObjectId::new);
        let at = Utc::now().to_rfc3339();
        let mut pending_versions = Vec::new();

        let previous_version = match existing_object.as_ref() {
            Some(object) => {
                let current = self.read_version(&object.current_version)?;
                if current.content == current_content {
                    current
                } else {
                    let version = LocalVersionRecord {
                        id: VersionId::new(),
                        object_id: object_id.clone(),
                        content: current_content.clone(),
                        captured_at: at.clone(),
                        extensions: BTreeMap::new(),
                    };
                    pending_versions.push(version.clone());
                    version
                }
            }
            None => {
                let version = LocalVersionRecord {
                    id: VersionId::new(),
                    object_id: object_id.clone(),
                    content: current_content.clone(),
                    captured_at: at.clone(),
                    extensions: BTreeMap::new(),
                };
                pending_versions.push(version.clone());
                version
            }
        };

        let next_version = if next_content == current_content {
            previous_version.clone()
        } else {
            let version = LocalVersionRecord {
                id: VersionId::new(),
                object_id: object_id.clone(),
                content: next_content.clone(),
                captured_at: at.clone(),
                extensions: BTreeMap::new(),
            };
            pending_versions.push(version.clone());
            version
        };

        if pending_versions.is_empty() {
            return Ok(VersionedReplaceResult {
                object_id,
                version_id: next_version.id,
                previous_content: current_content,
                content: next_content,
            });
        }

        let path_string = relative_path_to_string(&relative_path)?;
        let mut object = existing_object.unwrap_or_else(|| LocalObjectRecord {
            schema: OBJECT_SCHEMA.to_owned(),
            id: object_id.clone(),
            object_type: "file".to_owned(),
            path: path_string.clone(),
            lifecycle: ObjectLifecycle {
                status: "canonical".to_owned(),
                extensions: BTreeMap::new(),
            },
            provenance: ObjectProvenance {
                created_at: at.clone(),
                source: "local".to_owned(),
                extensions: BTreeMap::new(),
            },
            current_version: previous_version.id.clone(),
            versions: Vec::new(),
            extensions: BTreeMap::new(),
        });
        for version in &pending_versions {
            if !object.versions.contains(&version.id) {
                object.versions.push(version.id.clone());
            }
        }
        object.current_version = next_version.id.clone();

        let mut events = Vec::new();
        if object_created {
            events.push(ObjectJournalEvent {
                id: format!("event_{}", Uuid::now_v7()),
                at: at.clone(),
                action: JournalAction::ObjectTracked,
                object_id: object_id.clone(),
                path: path_string.clone(),
                previous_path: None,
                version_id: None,
                content: None,
            });
        }
        events.extend(pending_versions.iter().map(|version| ObjectJournalEvent {
            id: format!("event_{}", Uuid::now_v7()),
            at: at.clone(),
            action: JournalAction::VersionCaptured,
            object_id: object_id.clone(),
            path: path_string.clone(),
            previous_path: None,
            version_id: Some(version.id.clone()),
            content: Some(version.content.clone()),
        }));

        #[cfg(unix)]
        let unix_mode = {
            use std::os::unix::fs::PermissionsExt;
            Some(metadata.permissions().mode())
        };
        #[cfg(not(unix))]
        let unix_mode = None;

        self.commit_transaction(PendingTransaction {
            protocol_version: "0.1.0".to_owned(),
            id: format!("transaction_{}", Uuid::now_v7()),
            version: None,
            versions: pending_versions,
            object,
            restore: None,
            replacement: (next_content != current_content).then(|| PendingReplacement {
                destination: path_string,
                previous_content: current_content.clone(),
                content: next_content.clone(),
                readonly: metadata.permissions().readonly(),
                unix_mode,
                file_identity: filesystem_identity(&metadata),
                parent_identity: filesystem_identity(&parent_metadata),
            }),
            events,
        })?;

        Ok(VersionedReplaceResult {
            object_id,
            version_id: next_version.id,
            previous_content: current_content,
            content: next_content,
        })
    }

    /// Rebind an object to a file that has already moved on disk.
    ///
    /// This does not move user content. It records the externally completed
    /// path change while preserving object and version identity.
    pub fn record_path_change(
        &self,
        object_id: &ObjectId,
        new_relative_path: impl AsRef<Path>,
    ) -> Result<LocalObjectRecord> {
        let new_relative_path = safe_content_path(new_relative_path.as_ref())?;
        let _lock = self.acquire_transaction_lock()?;
        self.ensure_store_layout()?;
        let (new_materialized_path, new_relative_path) =
            resolve_existing_workspace_file(&self.root, &new_relative_path)?;

        let mut object = self.read_object(object_id)?;
        let new_path = relative_path_to_string(&new_relative_path)?;
        if object.path == new_path {
            return Ok(object);
        }

        let old_relative_path = safe_content_path(Path::new(&object.path))?;
        match resolve_existing_workspace_file(&self.root, &old_relative_path) {
            Ok((old_materialized_path, _)) if old_materialized_path != new_materialized_path => {
                return Err(invalid_record(
                    self.object_record_path(object_id),
                    format!(
                        "tracked path {} still exists; record a path change only after moving it",
                        object.path
                    ),
                ));
            }
            Ok(_) => {}
            Err(FolderbaseError::Io { source, .. })
                if source.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }

        let current_version = self.read_version(&object.current_version)?;
        let expected_identity = self.read_local_file_identity(object_id)?.ok_or_else(|| {
            invalid_record(
                self.path_identity_path(object_id),
                "tracked object has no local file identity; capture it again before relocating",
            )
        })?;
        let destination_file = open_existing_nofollow(&new_materialized_path)?;
        let destination_metadata = destination_file
            .metadata()
            .map_err(|source| FolderbaseError::io(&new_materialized_path, source))?;
        if filesystem_identity(&destination_metadata).as_ref() != Some(&expected_identity) {
            return Err(FolderbaseError::WorkspaceContentChanged(new_relative_path));
        }
        let current_content = hash_reader(destination_file, &new_materialized_path)?;
        if current_content != current_version.content {
            return Err(FolderbaseError::WorkspaceContentChanged(new_relative_path));
        }

        if let Some(other) = self.find_object_by_path(&new_relative_path)?
            && other.id != *object_id
        {
            return Err(invalid_record(
                self.object_record_path(&other.id),
                format!("path {new_path} is already assigned to {}", other.id),
            ));
        }

        let previous_path = std::mem::replace(&mut object.path, new_path.clone());
        self.commit_transaction(PendingTransaction {
            protocol_version: "0.1.0".to_owned(),
            id: format!("transaction_{}", Uuid::now_v7()),
            version: None,
            versions: Vec::new(),
            object: object.clone(),
            restore: None,
            replacement: None,
            events: vec![ObjectJournalEvent {
                id: format!("event_{}", Uuid::now_v7()),
                at: Utc::now().to_rfc3339(),
                action: JournalAction::ObjectRelocated,
                object_id: object_id.clone(),
                path: new_path,
                previous_path: Some(previous_path),
                version_id: Some(object.current_version.clone()),
                content: None,
            }],
        })?;
        Ok(object)
    }

    /// Restore one immutable version to a new relative path.
    ///
    /// Existing destinations are never overwritten. The blob is verified
    /// before and after installation, and the destination never shares an
    /// inode with the immutable blob.
    pub fn restore_version(
        &self,
        version_id: &VersionId,
        destination: impl AsRef<Path>,
    ) -> Result<RestoreResult> {
        let destination = safe_content_path(destination.as_ref())?;
        let _lock = self.acquire_transaction_lock()?;
        self.ensure_store_layout()?;
        let version = self.read_version(version_id)?;
        let blob_path = self.blob_path(&version.content.digest);
        verify_file_content(&blob_path, &version.content)?;

        let (_, destination) = self.prepare_new_destination(&destination)?;
        let path_string = relative_path_to_string(&destination)?;
        let object = self.read_object(&version.object_id)?;
        self.commit_transaction(PendingTransaction {
            protocol_version: "0.1.0".to_owned(),
            id: format!("transaction_{}", Uuid::now_v7()),
            version: None,
            versions: Vec::new(),
            object,
            restore: Some(PendingRestore {
                version_id: version.id.clone(),
                destination: path_string.clone(),
                content: version.content.clone(),
            }),
            replacement: None,
            events: vec![ObjectJournalEvent {
                id: format!("event_{}", Uuid::now_v7()),
                at: Utc::now().to_rfc3339(),
                action: JournalAction::VersionRestored,
                object_id: version.object_id.clone(),
                path: path_string,
                previous_path: None,
                version_id: Some(version.id.clone()),
                content: Some(version.content.clone()),
            }],
        })?;

        Ok(RestoreResult {
            object_id: version.object_id,
            version_id: version.id,
            path: destination,
            content: version.content,
        })
    }

    pub fn read_object(&self, object_id: &ObjectId) -> Result<LocalObjectRecord> {
        let path = self.object_record_path(object_id);
        object_id.validate(&path)?;
        self.deny_if_transferred_out(object_id)?;
        let record: LocalObjectRecord = read_json(&path)?;
        self.validate_object_record(object_id, &record, &path)?;
        Ok(record)
    }

    pub(crate) fn read_capture_object_projection_in(
        &self,
        state: &FolderbaseState,
        object_id: &ObjectId,
    ) -> Result<Option<LocalObjectRecord>> {
        let path = self.object_record_path(object_id);
        object_id.validate(&path)?;
        let Some(bytes) = state.read_bounded(
            &self.object_record_relative_path(object_id),
            MAX_CAPTURE_PROJECTION_RECORD_BYTES,
        )?
        else {
            return Ok(None);
        };
        let record: LocalObjectRecord = serde_json::from_slice(&bytes)
            .map_err(|source| FolderbaseError::json(&path, source))?;
        self.validate_object_record(object_id, &record, &path)?;
        Ok(Some(record))
    }

    fn validate_object_record(
        &self,
        object_id: &ObjectId,
        record: &LocalObjectRecord,
        path: &Path,
    ) -> Result<()> {
        let relative_path = self.validate_object_record_membership(object_id, record, path)?;
        self.ensure_path_within_current_folderbase_boundary(&relative_path)
    }

    fn validate_object_record_membership(
        &self,
        object_id: &ObjectId,
        record: &LocalObjectRecord,
        path: &Path,
    ) -> Result<PathBuf> {
        object_id.validate(path)?;
        record.id.validate(path)?;
        if record.id != *object_id {
            return Err(invalid_record(
                path.to_path_buf(),
                "object ID does not match its filename",
            ));
        }
        let relative_path = safe_content_path(Path::new(&record.path)).map_err(|_| {
            invalid_record(
                path.to_path_buf(),
                "object path is not a safe relative path",
            )
        })?;
        self.ensure_path_within_current_folderbase_boundary(&relative_path)?;
        if record.versions.is_empty() || !record.versions.contains(&record.current_version) {
            return Err(invalid_record(
                path.to_path_buf(),
                "current version is absent from the object version history",
            ));
        }
        Ok(relative_path)
    }

    pub fn read_version(&self, version_id: &VersionId) -> Result<LocalVersionRecord> {
        let record = self.read_version_record(version_id)?;
        let object = self.read_object(&record.object_id)?;
        if !object.versions.contains(version_id) {
            return Err(invalid_record(
                self.version_record_path(version_id),
                "version is absent from its object's version history",
            ));
        }
        Ok(record)
    }

    pub(crate) fn read_version_record(&self, version_id: &VersionId) -> Result<LocalVersionRecord> {
        let path = self.version_record_path(version_id);
        version_id.validate(&path)?;
        let record: LocalVersionRecord = read_json(&path)?;
        self.validate_version_record(version_id, &record, &path)?;
        Ok(record)
    }

    fn validate_version_record(
        &self,
        version_id: &VersionId,
        record: &LocalVersionRecord,
        path: &Path,
    ) -> Result<()> {
        version_id.validate(path)?;
        record.id.validate(path)?;
        record.object_id.validate(path)?;
        if record.id != *version_id {
            return Err(invalid_record(
                path.to_path_buf(),
                "version ID does not match its filename",
            ));
        }
        validate_content_digest(&record.content, path)
    }

    pub(crate) fn validate_chunk_transfer_membership(
        &self,
        version_id: &VersionId,
        version: &LocalVersionRecord,
        object: &LocalObjectRecord,
    ) -> Result<PathBuf> {
        let version_path = self.version_record_path(version_id);
        self.validate_version_record(version_id, version, &version_path)?;
        let object_path = self.object_record_path(&version.object_id);
        let relative_path =
            self.validate_object_record_membership(&version.object_id, object, &object_path)?;
        if !object.versions.contains(version_id) {
            return Err(invalid_record(
                version_path,
                "version is absent from its object's version history",
            ));
        }
        Ok(relative_path)
    }

    /// Read and validate every complete journal line.
    ///
    /// A final unterminated line is included when it is valid JSON. An invalid
    /// unterminated tail is treated as an interrupted append and ignored here;
    /// the next write quarantines it before replaying pending transactions.
    pub fn journal_events(&self) -> Result<Vec<ObjectJournalEvent>> {
        let _lock = self.acquire_transaction_lock()?;
        self.ensure_store_layout()?;
        let path = self.root.join(JOURNAL_PATH);
        let bytes = match read_optional_file_nofollow(&path)? {
            Some(bytes) => bytes,
            None => return Ok(Vec::new()),
        };
        let events = parse_journal_bytes(&path, &bytes, true)?;
        let mut checked_objects = std::collections::BTreeSet::new();
        for event in &events {
            self.ensure_path_within_current_folderbase_boundary(Path::new(&event.path))?;
            if let Some(previous_path) = &event.previous_path {
                self.ensure_path_within_current_folderbase_boundary(Path::new(previous_path))?;
            }
            if checked_objects.insert(event.object_id.clone()) {
                self.read_object(&event.object_id)?;
            }
        }
        Ok(events)
    }

    pub(crate) fn ensure_store_layout(&self) -> Result<()> {
        for relative in [
            OBJECTS_DIRECTORY,
            VERSION_RECORDS_DIRECTORY,
            BLOBS_DIRECTORY,
            ".folderbase/journal",
            JOURNAL_QUARANTINE_DIRECTORY,
            TRANSACTIONS_DIRECTORY,
            LOCKS_DIRECTORY,
            PATH_IDENTITIES_DIRECTORY,
        ] {
            ensure_directory_chain(&self.root, Path::new(relative))?;
        }
        self.repair_incomplete_journal_tail()?;
        self.recover_pending_transactions()?;
        Ok(())
    }

    pub(crate) fn acquire_transaction_lock(&self) -> Result<StoreTransactionLock> {
        let state = FolderbaseState::open(&self.root)?;
        self.acquire_transaction_lock_in(&state)
    }

    pub(crate) fn acquire_transaction_lock_in(
        &self,
        state: &FolderbaseState,
    ) -> Result<StoreTransactionLock> {
        let lock = self.acquire_transaction_lock_in_allowing_protocol_upgrade(state)?;
        if state
            .read_bounded_if_present(
                Path::new(".folderbase/transactions/protocol-upgrades/active.json"),
                16 * 1024 * 1024,
            )?
            .is_some()
        {
            return Err(FolderbaseError::ProtocolUpgradeBlocked(
                "Folderbase protocol upgrade recovery",
            ));
        }
        Ok(lock)
    }

    pub(crate) fn acquire_transaction_lock_in_allowing_protocol_upgrade(
        &self,
        state: &FolderbaseState,
    ) -> Result<StoreTransactionLock> {
        state.ensure_private_dir(Path::new(LOCKS_DIRECTORY))?;
        let lock_path = self.root.join(TRANSACTION_LOCK_PATH);
        match state.publish_new(Path::new(TRANSACTION_LOCK_PATH), b"") {
            Ok(()) | Err(FolderbaseError::WouldOverwrite(_)) => {}
            Err(error) => return Err(error),
        }
        let file = state.open_lock_file(Path::new(TRANSACTION_LOCK_PATH))?;
        File::lock(&file).map_err(|source| FolderbaseError::io(&lock_path, source))?;
        Ok(StoreTransactionLock { file })
    }

    fn prepare_new_destination(&self, relative_path: &Path) -> Result<(PathBuf, PathBuf)> {
        let path = resolve_without_symlinks(&self.root, relative_path, true)?;
        let name = relative_path
            .file_name()
            .ok_or_else(|| FolderbaseError::UnsafePath(relative_path.to_path_buf()))?;
        let parent = path
            .parent()
            .ok_or_else(|| FolderbaseError::UnsafePath(path.clone()))?;
        let canonical_parent = parent
            .canonicalize()
            .map_err(|source| FolderbaseError::io(parent, source))?;
        let canonical_relative_parent = canonical_parent
            .strip_prefix(&self.root)
            .map_err(|_| FolderbaseError::UnsafePath(canonical_parent.clone()))?;
        let canonical_relative = safe_content_path(&canonical_relative_parent.join(name))?;
        let canonical_path = self.root.join(&canonical_relative);
        match fs::symlink_metadata(&canonical_path) {
            Ok(_) => Err(FolderbaseError::WouldOverwrite(canonical_path)),
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                Ok((canonical_path, canonical_relative))
            }
            Err(source) => Err(FolderbaseError::io(canonical_path, source)),
        }
    }

    fn install_content_blob(&self, source: &Path) -> Result<ContentDigest> {
        let mut input = open_existing_nofollow(source)?;
        let source_before = input
            .metadata()
            .map_err(|source_error| FolderbaseError::io(source, source_error))?;
        let blob_directory = self.root.join(BLOBS_DIRECTORY);
        let staged_path = unique_staged_path(&blob_directory, "blob");
        let mut staged = open_new(&staged_path)?;
        let mut hasher = Sha256::new();
        let mut bytes = 0_u64;
        let mut buffer = [0_u8; COPY_BUFFER_BYTES];

        let copy_result = (|| -> Result<()> {
            loop {
                let read = input
                    .read(&mut buffer)
                    .map_err(|source_error| FolderbaseError::io(source, source_error))?;
                if read == 0 {
                    break;
                }
                staged
                    .write_all(&buffer[..read])
                    .map_err(|source_error| FolderbaseError::io(&staged_path, source_error))?;
                hasher.update(&buffer[..read]);
                bytes = bytes.checked_add(read as u64).ok_or_else(|| {
                    invalid_record(source, "content length exceeds supported range")
                })?;
            }
            staged
                .sync_all()
                .map_err(|source_error| FolderbaseError::io(&staged_path, source_error))?;
            Ok(())
        })();
        drop(staged);
        if let Err(error) = copy_result {
            let _ = fs::remove_file(&staged_path);
            return Err(error);
        }

        let source_after_file = match open_existing_nofollow(source) {
            Ok(file) => file,
            Err(error) => {
                let _ = fs::remove_file(&staged_path);
                return Err(error);
            }
        };
        let source_after = source_after_file
            .metadata()
            .map_err(|source_error| FolderbaseError::io(source, source_error))?;
        if source_before.len() != source_after.len()
            || source_before.modified().ok() != source_after.modified().ok()
            || filesystem_identity(&source_before) != filesystem_identity(&source_after)
            || source_after.len() != bytes
        {
            let _ = fs::remove_file(&staged_path);
            return Err(invalid_record(
                source,
                "content changed while the version was being captured",
            ));
        }

        let digest = digest_hex(hasher.finalize().as_slice());
        let content = ContentDigest {
            algorithm: "sha256".to_owned(),
            digest,
            bytes,
        };
        let blob_path = self.blob_path(&content.digest);
        match install_no_clobber(&staged_path, &blob_path) {
            Ok(()) => sync_parent_directory(&blob_path)?,
            Err(source_error) if source_error.kind() == std::io::ErrorKind::AlreadyExists => {
                fs::remove_file(&staged_path)
                    .map_err(|remove_error| FolderbaseError::io(&staged_path, remove_error))?;
                verify_file_content(&blob_path, &content)?;
            }
            Err(source_error) => {
                let _ = fs::remove_file(&staged_path);
                return Err(FolderbaseError::io(blob_path, source_error));
            }
        }
        Ok(content)
    }

    /// Install bytes from a capability-opened ordinary file into the existing
    /// content-addressed blob store.
    ///
    /// The capture producer owns source-identity checks before and after this
    /// call. This method owns only append-only blob installation and
    /// verification.
    pub(crate) fn install_content_reader(
        &self,
        reader: impl Read,
        source_label: &Path,
        maximum_bytes: u64,
    ) -> Result<ContentDigest> {
        let state = FolderbaseState::open(&self.root)?;
        self.install_content_reader_in(&state, reader, source_label, maximum_bytes)
    }

    pub(crate) fn install_content_reader_in(
        &self,
        state: &FolderbaseState,
        reader: impl Read,
        source_label: &Path,
        maximum_bytes: u64,
    ) -> Result<ContentDigest> {
        let published = state.publish_reader_sha256(
            Path::new(BLOBS_DIRECTORY),
            reader,
            source_label,
            maximum_bytes,
        )?;
        Ok(ContentDigest {
            algorithm: "sha256".to_owned(),
            digest: published.digest,
            bytes: published.bytes,
        })
    }

    pub(crate) fn install_content_bytes(&self, bytes: &[u8]) -> Result<ContentDigest> {
        self.install_content_reader(
            std::io::Cursor::new(bytes),
            Path::new("in-memory content"),
            bytes.len() as u64,
        )
    }

    pub(crate) fn install_content_bytes_in(
        &self,
        state: &FolderbaseState,
        bytes: &[u8],
    ) -> Result<ContentDigest> {
        self.install_content_reader_in(
            state,
            std::io::Cursor::new(bytes),
            Path::new("in-memory content"),
            bytes.len() as u64,
        )
    }

    pub(crate) fn install_or_verify_version_record(
        &self,
        record: &LocalVersionRecord,
    ) -> Result<()> {
        let state = FolderbaseState::open(&self.root)?;
        self.install_or_verify_version_record_in(&state, record)
    }

    pub(crate) fn install_or_verify_version_record_in(
        &self,
        state: &FolderbaseState,
        record: &LocalVersionRecord,
    ) -> Result<()> {
        let path = self.version_record_path(&record.id);
        let relative = Path::new(VERSION_RECORDS_DIRECTORY).join(format!("{}.json", record.id));
        let encoded = json_bytes(&path, record)?;
        match state.publish_new(&relative, &encoded) {
            Ok(()) => Ok(()),
            Err(FolderbaseError::WouldOverwrite(_)) => {
                let existing = state
                    .read_bounded(&relative, MAX_CAPTURE_PROJECTION_RECORD_BYTES)?
                    .ok_or_else(|| invalid_record(&path, "immutable version record disappeared"))?;
                if existing == encoded {
                    Ok(())
                } else {
                    Err(invalid_record(
                        path,
                        "immutable version record differs from the pending transaction",
                    ))
                }
            }
            Err(error) => Err(error),
        }
    }

    fn write_object_projection(&self, record: &LocalObjectRecord) -> Result<()> {
        let state = FolderbaseState::open(&self.root)?;
        self.write_object_projection_in(&state, record)
    }

    fn write_object_projection_in(
        &self,
        state: &FolderbaseState,
        record: &LocalObjectRecord,
    ) -> Result<()> {
        let path = self.object_record_path(&record.id);
        let encoded = json_bytes(&path, record)?;
        state.replace(&self.object_record_relative_path(&record.id), &encoded)
    }

    /// Install one derived regular-file object projection after its containing
    /// Folderbase Version has become Local Head.
    pub(crate) fn write_capture_object_projection_in(
        &self,
        state: &FolderbaseState,
        record: &LocalObjectRecord,
    ) -> Result<()> {
        self.validate_object_record_membership(
            &record.id,
            record,
            &self.object_record_path(&record.id),
        )?;
        self.write_object_projection_in(state, record)?;
        Ok(())
    }

    /// Verify a referenced immutable Object Version without consulting a
    /// mutable object projection.
    pub(crate) fn verify_capture_object_version_in(
        &self,
        state: &FolderbaseState,
        object_id: &ObjectId,
        version_id: &VersionId,
        expected: &ContentDigest,
    ) -> Result<LocalVersionRecord> {
        let record = self.read_capture_version_record_in(state, version_id)?;
        if record.object_id != *object_id || record.content != *expected {
            return Err(invalid_record(
                self.version_record_path(version_id),
                "Object Version does not match the sealed Folderbase Version reference",
            ));
        }
        state.verify_sha256_blob(
            Path::new(BLOBS_DIRECTORY),
            &record.content.digest,
            record.content.bytes,
        )?;
        Ok(record)
    }

    pub(crate) fn verify_capture_version_record_in(
        &self,
        state: &FolderbaseState,
        version_id: &VersionId,
        expected: &ContentDigest,
    ) -> Result<LocalVersionRecord> {
        let record = self.read_capture_version_record_in(state, version_id)?;
        if record.content != *expected {
            return Err(invalid_record(
                self.version_record_path(version_id),
                "Object Version bytes do not match the sealed Folderbase Version reference",
            ));
        }
        state.verify_sha256_blob(
            Path::new(BLOBS_DIRECTORY),
            &record.content.digest,
            record.content.bytes,
        )?;
        Ok(record)
    }

    pub(crate) fn verify_capture_record_integrity_in(
        &self,
        state: &FolderbaseState,
        object_id: &ObjectId,
        version_id: &VersionId,
    ) -> Result<LocalVersionRecord> {
        let record = self.read_capture_version_record_in(state, version_id)?;
        if record.object_id != *object_id {
            return Err(invalid_record(
                self.version_record_path(version_id),
                "Object Version belongs to a different stable Object",
            ));
        }
        state.verify_sha256_blob(
            Path::new(BLOBS_DIRECTORY),
            &record.content.digest,
            record.content.bytes,
        )?;
        Ok(record)
    }

    fn read_capture_version_record_in(
        &self,
        state: &FolderbaseState,
        version_id: &VersionId,
    ) -> Result<LocalVersionRecord> {
        let path = self.version_record_path(version_id);
        version_id.validate(&path)?;
        let relative = Path::new(VERSION_RECORDS_DIRECTORY).join(format!("{version_id}.json"));
        let bytes = state
            .read_bounded(&relative, MAX_CAPTURE_PROJECTION_RECORD_BYTES)?
            .ok_or_else(|| FolderbaseError::io(&path, std::io::ErrorKind::NotFound.into()))?;
        let record: LocalVersionRecord = serde_json::from_slice(&bytes)
            .map_err(|source| FolderbaseError::json(&path, source))?;
        self.validate_version_record(version_id, &record, &path)?;
        Ok(record)
    }

    fn install_or_verify_restore(&self, restore: &PendingRestore) -> Result<()> {
        let destination = safe_content_path(Path::new(&restore.destination))?;
        let destination_path = resolve_without_symlinks(&self.root, &destination, true)?;
        let blob_path = self.blob_path(&restore.content.digest);
        verify_file_content(&blob_path, &restore.content)?;

        match fs::symlink_metadata(&destination_path) {
            Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
                verify_file_content(&destination_path, &restore.content)
            }
            Ok(_) => Err(FolderbaseError::WouldOverwrite(destination_path)),
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                copy_verified_new(&blob_path, &destination_path, &restore.content)?;
                verify_file_content(&destination_path, &restore.content)
            }
            Err(source) => Err(FolderbaseError::io(destination_path, source)),
        }
    }

    fn install_or_verify_replacement(&self, replacement: &PendingReplacement) -> Result<()> {
        let destination = safe_content_path(Path::new(&replacement.destination))?;
        let destination_path = resolve_without_symlinks(&self.root, &destination, false)?;
        let metadata = fs::symlink_metadata(&destination_path)
            .map_err(|source| FolderbaseError::io(&destination_path, source))?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(FolderbaseError::UnsafePath(destination_path));
        }
        let parent = destination_path
            .parent()
            .ok_or_else(|| FolderbaseError::UnsafePath(destination_path.clone()))?;
        let parent_metadata =
            fs::metadata(parent).map_err(|source| FolderbaseError::io(parent, source))?;
        if replacement
            .parent_identity
            .as_ref()
            .is_some_and(|expected| {
                filesystem_identity(&parent_metadata).as_ref() != Some(expected)
            })
        {
            return Err(FolderbaseError::WorkspaceContentChanged(destination));
        }

        let current = hash_reader(
            open_existing_nofollow(&destination_path)?,
            &destination_path,
        )?;
        if current == replacement.content {
            return Ok(());
        }
        if current != replacement.previous_content {
            return Err(FolderbaseError::WorkspaceContentChanged(destination));
        }
        if replacement
            .file_identity
            .as_ref()
            .is_some_and(|expected| filesystem_identity(&metadata).as_ref() != Some(expected))
        {
            return Err(FolderbaseError::WorkspaceContentChanged(destination));
        }

        let blob_path = self.blob_path(&replacement.content.digest);
        verify_file_content(&blob_path, &replacement.content)?;
        replace_verified(
            &blob_path,
            &destination_path,
            &replacement.content,
            replacement,
        )?;
        verify_file_content(&destination_path, &replacement.content)
    }

    fn commit_transaction(&self, transaction: PendingTransaction) -> Result<()> {
        validate_pending_transaction(&transaction, Path::new("pending-transaction"))?;
        let path = self.pending_transaction_path(&transaction.id);
        write_json_new(&path, &transaction)?;
        maybe_fail_workspace_checkpoint(&transaction, "intent-durable", &path)?;
        self.replay_transaction(&path, &transaction)
    }

    fn recover_pending_transactions(&self) -> Result<()> {
        let directory = self.root.join(TRANSACTIONS_DIRECTORY);
        let mut paths = fs::read_dir(&directory)
            .map_err(|source| FolderbaseError::io(&directory, source))?
            .map(|entry| {
                entry
                    .map(|entry| entry.path())
                    .map_err(|source| FolderbaseError::io(&directory, source))
            })
            .collect::<Result<Vec<_>>>()?;
        paths.sort();

        for path in paths {
            let metadata =
                fs::symlink_metadata(&path).map_err(|source| FolderbaseError::io(&path, source))?;
            if path.extension().and_then(|value| value.to_str()) != Some("json") {
                continue;
            }
            if !metadata.is_file() || metadata.file_type().is_symlink() {
                return Err(invalid_record(
                    path,
                    "pending transaction is not a regular file",
                ));
            }
            let transaction: PendingTransaction = read_json(&path)?;
            validate_pending_transaction(&transaction, &path)?;
            if self.pending_transaction_path(&transaction.id) != path {
                return Err(invalid_record(
                    path,
                    "pending transaction ID does not match its filename",
                ));
            }
            self.replay_transaction(&path, &transaction)?;
        }
        Ok(())
    }

    fn replay_transaction(&self, path: &Path, transaction: &PendingTransaction) -> Result<()> {
        if transaction.restore.is_none() {
            let recorded_path = Path::new(&transaction.object.path);
            let (materialized_path, canonical_relative) =
                resolve_existing_workspace_file(&self.root, recorded_path)?;
            if relative_path_to_string(&canonical_relative)? != transaction.object.path {
                return Err(invalid_record(
                    path,
                    "pending object path no longer matches the filesystem spelling",
                ));
            }
            if transaction.replacement.is_none() {
                let expected_content = match &transaction.version {
                    Some(version) => version.content.clone(),
                    None => {
                        self.read_version(&transaction.object.current_version)?
                            .content
                    }
                };
                let current_content = hash_reader(
                    open_existing_nofollow(&materialized_path)?,
                    &materialized_path,
                )?;
                if current_content != expected_content {
                    return Err(FolderbaseError::WorkspaceContentChanged(canonical_relative));
                }
            }
        }

        if let Some(version) = &transaction.version {
            let blob_path = self.blob_path(&version.content.digest);
            verify_file_content(&blob_path, &version.content)?;
            self.install_or_verify_version_record(version)?;
        }
        for version in &transaction.versions {
            let blob_path = self.blob_path(&version.content.digest);
            verify_file_content(&blob_path, &version.content)?;
            self.install_or_verify_version_record(version)?;
        }
        maybe_fail_workspace_checkpoint(transaction, "versions-durable", path)?;
        let current = self.read_version_record(&transaction.object.current_version)?;
        if current.object_id != transaction.object.id {
            return Err(invalid_record(
                path,
                "pending projection current version belongs to a different object",
            ));
        }

        if let Some(replacement) = &transaction.replacement {
            self.install_or_verify_replacement(replacement)?;
            maybe_fail_workspace_checkpoint(transaction, "content-replaced", path)?;
            self.write_materialized_object_projection(&transaction.object)?;
            maybe_fail_workspace_checkpoint(transaction, "projection-durable", path)?;
        } else if let Some(restore) = &transaction.restore {
            let restored_version = self.read_version(&restore.version_id)?;
            if restored_version.object_id != transaction.object.id
                || restored_version.content != restore.content
            {
                return Err(invalid_record(
                    path,
                    "pending restore does not match its immutable version",
                ));
            }
            self.install_or_verify_restore(restore)?;
            maybe_fail_workspace_checkpoint(transaction, "restore-published", path)?;
        } else {
            self.write_materialized_object_projection(&transaction.object)?;
        }
        self.append_journal_events(&transaction.events)?;
        maybe_fail_workspace_checkpoint(transaction, "journal-durable", path)?;
        fs::remove_file(path).map_err(|source| FolderbaseError::io(path, source))?;
        sync_parent_directory(path)
    }

    fn append_journal_events(&self, events: &[ObjectJournalEvent]) -> Result<()> {
        let path = self.root.join(JOURNAL_PATH);
        self.repair_incomplete_journal_tail()?;
        let existing = match read_optional_file_nofollow(&path)? {
            Some(bytes) => parse_journal_bytes(&path, &bytes, false)?,
            None => Vec::new(),
        };
        let mut event_ids = existing
            .into_iter()
            .map(|event| event.id)
            .collect::<std::collections::BTreeSet<_>>();

        let mut journal = OpenOptions::new();
        journal.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            journal.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }
        let mut journal = journal
            .open(&path)
            .map_err(|source| FolderbaseError::io(&path, source))?;
        let mut appended = false;
        for event in events {
            validate_journal_event(event, &path, 0)?;
            if !event_ids.insert(event.id.clone()) {
                continue;
            }
            let mut encoded =
                serde_json::to_vec(event).map_err(|source| FolderbaseError::json(&path, source))?;
            encoded.push(b'\n');
            journal
                .write_all(&encoded)
                .map_err(|source| FolderbaseError::io(&path, source))?;
            appended = true;
        }
        if appended {
            journal
                .sync_data()
                .map_err(|source| FolderbaseError::io(&path, source))?;
            sync_parent_directory(&path)?;
        }
        Ok(())
    }

    fn repair_incomplete_journal_tail(&self) -> Result<()> {
        let path = self.root.join(JOURNAL_PATH);
        let bytes = match read_optional_file_nofollow(&path)? {
            Some(bytes) => bytes,
            None => return Ok(()),
        };
        if bytes.is_empty() || bytes.ends_with(b"\n") {
            return Ok(());
        }

        let prefix_length = bytes
            .iter()
            .rposition(|byte| *byte == b'\n')
            .map_or(0, |index| index + 1);
        let tail = &bytes[prefix_length..];
        match serde_json::from_slice::<ObjectJournalEvent>(tail) {
            Ok(event) => {
                validate_journal_event(&event, &path, 0)?;
                let mut repaired = bytes;
                repaired.push(b'\n');
                write_bytes_replace(&path, &repaired)
            }
            Err(_) => {
                let quarantine = self
                    .root
                    .join(JOURNAL_QUARANTINE_DIRECTORY)
                    .join(format!("objects-tail-{}.ndjson", Uuid::now_v7()));
                write_bytes_new(&quarantine, tail)?;
                write_bytes_replace(&path, &bytes[..prefix_length])
            }
        }
    }

    fn pending_transaction_path(&self, transaction_id: &str) -> PathBuf {
        self.root
            .join(TRANSACTIONS_DIRECTORY)
            .join(format!("{transaction_id}.json"))
    }

    fn find_object_by_path(&self, relative_path: &Path) -> Result<Option<LocalObjectRecord>> {
        let directory = self.root.join(OBJECTS_DIRECTORY);
        let requested_path = relative_path_to_string(relative_path)?;
        let entries = match fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(source) => return Err(FolderbaseError::io(directory, source)),
        };
        let mut found = None;
        for entry in entries {
            let entry = entry.map_err(|source| FolderbaseError::io(&directory, source))?;
            let file_type = entry
                .file_type()
                .map_err(|source| FolderbaseError::io(entry.path(), source))?;
            if entry.path().extension().and_then(|value| value.to_str()) != Some("json") {
                continue;
            }
            if !file_type.is_file() || file_type.is_symlink() {
                return Err(invalid_record(
                    entry.path(),
                    "object record is not a regular file",
                ));
            }
            let mut record: LocalObjectRecord = read_json(&entry.path())?;
            record.id.validate(&entry.path())?;
            let stored_path = safe_content_path(Path::new(&record.path)).map_err(|_| {
                invalid_record(entry.path(), "object path is not a safe relative path")
            })?;
            let is_match = if stored_path == relative_path {
                true
            } else {
                match resolve_existing_workspace_file(&self.root, &stored_path) {
                    Ok((_, canonical_path)) => canonical_path == relative_path,
                    Err(FolderbaseError::Io { source, .. })
                        if source.kind() == std::io::ErrorKind::NotFound =>
                    {
                        if paths_equal_ignoring_ascii_case(&stored_path, relative_path) {
                            return Err(invalid_record(
                                entry.path(),
                                "stored object path alias no longer resolves to its canonical file",
                            ));
                        }
                        false
                    }
                    Err(FolderbaseError::UnsafePath(_))
                        if !paths_equal_ignoring_ascii_case(&stored_path, relative_path) =>
                    {
                        false
                    }
                    Err(error) => return Err(error),
                }
            };
            if is_match {
                self.deny_if_transferred_out(&record.id)?;
                if found.is_some() {
                    return Err(invalid_record(
                        &directory,
                        format!("multiple object records claim path {requested_path}"),
                    ));
                }
                record.path.clone_from(&requested_path);
                found = Some(record);
            }
        }
        Ok(found)
    }

    fn persist_canonical_object_path(&self, object: &LocalObjectRecord) -> Result<()> {
        let persisted = self.read_object(&object.id)?;
        if persisted.path == object.path {
            return Ok(());
        }
        let mut expected_persisted = object.clone();
        expected_persisted.path.clone_from(&persisted.path);
        if persisted != expected_persisted {
            return Err(invalid_record(
                self.object_record_path(&object.id),
                "object record changed while canonicalizing its path",
            ));
        }

        self.commit_transaction(PendingTransaction {
            protocol_version: "0.1.0".to_owned(),
            id: format!("transaction_{}", Uuid::now_v7()),
            version: None,
            versions: Vec::new(),
            object: object.clone(),
            restore: None,
            replacement: None,
            events: vec![ObjectJournalEvent {
                id: format!("event_{}", Uuid::now_v7()),
                at: Utc::now().to_rfc3339(),
                action: JournalAction::ObjectRelocated,
                object_id: object.id.clone(),
                path: object.path.clone(),
                previous_path: Some(persisted.path),
                version_id: Some(object.current_version.clone()),
                content: None,
            }],
        })
    }

    fn ensure_path_within_current_folderbase_boundary(&self, relative_path: &Path) -> Result<()> {
        let mut resolved = self.root.clone();
        let mut components = relative_path.components().peekable();
        while let Some(component) = components.next() {
            let Component::Normal(name) = component else {
                return Err(FolderbaseError::UnsafePath(relative_path.to_path_buf()));
            };
            let requested = resolved.join(name);
            // Even when the requested spelling exists, a second
            // case-insensitive alias can point at a newly established nested
            // folderbase. Treat that ambiguity as unsafe instead of allowing a
            // stale stored spelling to select the ordinary sibling.
            let case_folded_child = find_case_folded_child(&resolved, name)?;
            let (path, metadata) = match fs::symlink_metadata(&requested) {
                Ok(metadata) => (requested, metadata),
                Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                    let Some(alias) = case_folded_child else {
                        return Ok(());
                    };
                    let metadata = fs::symlink_metadata(&alias)
                        .map_err(|source| FolderbaseError::io(&alias, source))?;
                    (alias, metadata)
                }
                Err(source) => return Err(FolderbaseError::io(requested, source)),
            };
            if metadata.file_type().is_symlink() {
                return Err(FolderbaseError::UnsafePath(path));
            }
            if metadata.is_dir() && has_nested_folderbase_marker(&path)? {
                return Err(FolderbaseError::UnsafePath(relative_path.to_path_buf()));
            }
            if components.peek().is_some() && !metadata.is_dir() {
                return Err(FolderbaseError::UnsafePath(relative_path.to_path_buf()));
            }
            resolved = path;
        }
        Ok(())
    }

    fn object_record_path(&self, object_id: &ObjectId) -> PathBuf {
        self.root.join(self.object_record_relative_path(object_id))
    }

    fn path_identity_path(&self, object_id: &ObjectId) -> PathBuf {
        self.root
            .join(PATH_IDENTITIES_DIRECTORY)
            .join(format!("{object_id}.json"))
    }

    fn write_materialized_object_projection(&self, object: &LocalObjectRecord) -> Result<()> {
        self.write_object_projection(object)?;
        self.write_local_file_identity(&object.id, &self.root.join(&object.path))
    }

    fn write_local_file_identity(&self, object_id: &ObjectId, path: &Path) -> Result<()> {
        let state = FolderbaseState::open(&self.root)?;
        self.write_local_file_identity_in(&state, object_id, path)
    }

    fn write_local_file_identity_in(
        &self,
        state: &FolderbaseState,
        object_id: &ObjectId,
        path: &Path,
    ) -> Result<()> {
        let file = open_existing_nofollow(path)?;
        let metadata = file
            .metadata()
            .map_err(|source| FolderbaseError::io(path, source))?;
        let Some(file_system) = filesystem_identity(&metadata) else {
            return Ok(());
        };
        let path = self.path_identity_path(object_id);
        let encoded = json_bytes(
            &path,
            &LocalPathIdentity {
                object_id: object_id.clone(),
                file_system,
            },
        )?;
        state.replace(
            &Path::new(PATH_IDENTITIES_DIRECTORY).join(format!("{object_id}.json")),
            &encoded,
        )
    }

    fn read_local_file_identity(&self, object_id: &ObjectId) -> Result<Option<FileSystemIdentity>> {
        let path = self.path_identity_path(object_id);
        let Some(bytes) = read_optional_file_nofollow(&path)? else {
            return Ok(None);
        };
        let binding: LocalPathIdentity = serde_json::from_slice(&bytes)
            .map_err(|source| FolderbaseError::json(&path, source))?;
        if binding.object_id != *object_id {
            return Err(invalid_record(
                path,
                "local path identity belongs to a different object",
            ));
        }
        Ok(Some(binding.file_system))
    }

    fn version_record_path(&self, version_id: &VersionId) -> PathBuf {
        self.root
            .join(self.version_record_relative_path(version_id))
    }

    fn blob_path(&self, digest: &str) -> PathBuf {
        self.root.join(self.blob_relative_path(digest))
    }

    pub(crate) fn version_record_relative_path(&self, version_id: &VersionId) -> PathBuf {
        PathBuf::from(VERSION_RECORDS_DIRECTORY).join(format!("{version_id}.json"))
    }

    pub(crate) fn object_record_relative_path(&self, object_id: &ObjectId) -> PathBuf {
        PathBuf::from(OBJECTS_DIRECTORY).join(format!("{object_id}.json"))
    }

    pub(crate) fn blob_relative_path(&self, digest: &str) -> PathBuf {
        PathBuf::from(BLOBS_DIRECTORY).join(digest)
    }

    fn deny_if_transferred_out(&self, object_id: &ObjectId) -> Result<()> {
        let path = outgoing_history_transfer_path(&self.root, object_id);
        let Some(bytes) = read_optional_file_nofollow(&path)? else {
            return Ok(());
        };
        validate_chunk_transfer_receipt_bytes(
            &bytes,
            &path,
            object_id,
            &read_folderbase_identity(&self.root)?.id,
        )
    }
}

impl HistoryTransferPlan {
    pub fn reopen(source_root: impl AsRef<Path>, transfer_id: &str) -> Result<Self> {
        let source_root = canonical_folderbase_root(source_root.as_ref())?;
        load_history_transfer_plan(&source_root, transfer_id)
    }
}

impl HistoryTransferResult {
    pub fn recover(source_root: impl AsRef<Path>, transfer_id: &str) -> Result<Self> {
        let source_root = canonical_folderbase_root(source_root.as_ref())?;
        let plan = load_history_transfer_plan(&source_root, transfer_id)?;
        match plan.state {
            HistoryTransferState::Approved
            | HistoryTransferState::Applying
            | HistoryTransferState::DestinationVerified
            | HistoryTransferState::SourceReleased => {
                replay_history_transfer_with_hook(plan, |_| {})
            }
            HistoryTransferState::Verified => {
                let destination = LocalVersionStore::open(&plan.destination_root)?;
                verify_history_transfer_ownership_boundaries(&plan)?;
                verify_history_transfer_receipts(&plan)?;
                verify_incoming_history(&destination, &plan)?;
                cleanup_history_transfer_staging(&destination.root, &plan.id)?;
                Ok(history_transfer_result(&plan))
            }
            HistoryTransferState::Proposed | HistoryTransferState::Conflicted => {
                Err(FolderbaseError::InvalidMigrationState {
                    expected: "approved",
                    actual: history_transfer_state_name(plan.state).to_owned(),
                })
            }
        }
    }
}

pub fn approve_history_transfer(plan: HistoryTransferPlan) -> Result<ApprovedHistoryTransfer> {
    if plan.state != HistoryTransferState::Proposed || plan.approval_digest.is_some() {
        return Err(FolderbaseError::InvalidMigrationState {
            expected: "proposed",
            actual: history_transfer_state_name(plan.state).to_owned(),
        });
    }
    let mut stored = load_history_transfer_plan(&plan.source_root, &plan.id)?;
    if stored != plan {
        return Err(FolderbaseError::MigrationApprovalMismatch);
    }
    verify_history_transfer_preconditions(&stored)?;
    let approval_digest = history_transfer_digest(&stored)?;
    stored.state = HistoryTransferState::Approved;
    stored.approval_digest = Some(approval_digest.clone());
    persist_history_transfer_plan(&stored)?;
    Ok(ApprovedHistoryTransfer {
        plan: stored,
        approval_digest,
    })
}

pub fn apply_history_transfer(approved: ApprovedHistoryTransfer) -> Result<HistoryTransferResult> {
    apply_history_transfer_with_hook(approved, |_| {})
}

fn apply_history_transfer_with_hook(
    approved: ApprovedHistoryTransfer,
    checkpoint: impl FnMut(HistoryTransferCheckpoint),
) -> Result<HistoryTransferResult> {
    if history_transfer_digest(&approved.plan)? != approved.approval_digest {
        return Err(FolderbaseError::MigrationApprovalMismatch);
    }
    let stored = load_history_transfer_plan(&approved.plan.source_root, &approved.plan.id)?;
    if stored.state != HistoryTransferState::Approved
        || stored.approval_digest.as_deref() != Some(approved.approval_digest.as_str())
        || stored != approved.plan
    {
        return Err(FolderbaseError::MigrationApprovalMismatch);
    }
    replay_history_transfer_with_hook(stored, checkpoint)
}

fn replay_history_transfer_with_hook(
    mut plan: HistoryTransferPlan,
    mut checkpoint: impl FnMut(HistoryTransferCheckpoint),
) -> Result<HistoryTransferResult> {
    let source = LocalVersionStore::open(&plan.source_root)
        .map_err(|error| mark_released_history_transfer_conflicted(&mut plan, error))?;
    let destination = LocalVersionStore::open(&plan.destination_root)
        .map_err(|error| mark_released_history_transfer_conflicted(&mut plan, error))?;
    if plan.state == HistoryTransferState::SourceReleased {
        verify_released_history_transfer(&destination, &plan)
            .map_err(|error| mark_history_transfer_conflicted(&mut plan, error))?;
    } else {
        verify_history_transfer_preconditions_for_stores(&source, &destination, &plan)?;
    }
    let (_first_lock, _second_lock) = if source.root <= destination.root {
        (
            source.acquire_transaction_lock()?,
            destination.acquire_transaction_lock()?,
        )
    } else {
        (
            destination.acquire_transaction_lock()?,
            source.acquire_transaction_lock()?,
        )
    };

    if plan.state == HistoryTransferState::SourceReleased {
        verify_released_history_transfer(&destination, &plan)
            .map_err(|error| mark_history_transfer_conflicted(&mut plan, error))?;
    } else {
        verify_history_transfer_preconditions_for_stores(&source, &destination, &plan)?;
    }
    if plan.state == HistoryTransferState::Approved {
        plan.state = HistoryTransferState::Applying;
        persist_history_transfer_plan(&plan)?;
        checkpoint(HistoryTransferCheckpoint::Applying);
    }
    if plan.state == HistoryTransferState::Applying {
        stage_history_transfer(&source, &destination, &plan)?;
        verify_staged_history(&destination, &plan)?;
        checkpoint(HistoryTransferCheckpoint::DestinationStaged);
        plan.state = HistoryTransferState::DestinationVerified;
        persist_history_transfer_plan(&plan)?;
        checkpoint(HistoryTransferCheckpoint::DestinationVerified);
    }
    if plan.state == HistoryTransferState::DestinationVerified {
        let release = (|| -> Result<()> {
            verify_staged_history(&destination, &plan)?;
            verify_destination_available_for_transfer(&destination, &plan, false)?;
            ensure_directory_chain(&source.root, Path::new(HISTORY_TRANSFER_OUTGOING_DIRECTORY))?;
            install_or_verify_history_transfer_receipt(
                &outgoing_history_transfer_path(&source.root, &plan.object.id),
                &history_transfer_receipt(&plan)?,
            )
        })();
        if let Err(error) = release {
            return Err(mark_history_transfer_conflicted(&mut plan, error));
        }
        checkpoint(HistoryTransferCheckpoint::SourceReceiptWritten);
        plan.state = HistoryTransferState::SourceReleased;
        persist_history_transfer_plan(&plan)?;
        checkpoint(HistoryTransferCheckpoint::SourceReleased);
    }
    if plan.state == HistoryTransferState::SourceReleased {
        let activation = (|| -> Result<()> {
            verify_history_transfer_ownership_boundaries(&plan)?;
            verify_staged_history(&destination, &plan)?;
            verify_destination_available_for_transfer(&destination, &plan, true)?;
            ensure_directory_chain(
                &destination.root,
                Path::new(HISTORY_TRANSFER_INCOMING_DIRECTORY),
            )?;
            install_or_verify_history_transfer_receipt(
                &incoming_history_transfer_path(&destination.root, &plan.object.id),
                &history_transfer_receipt(&plan)?,
            )?;
            checkpoint(HistoryTransferCheckpoint::IncomingReceiptWritten);
            activate_incoming_history(&destination, &plan)?;
            verify_incoming_history(&destination, &plan)
        })();
        if let Err(error) = activation {
            return Err(mark_history_transfer_conflicted(&mut plan, error));
        }
        checkpoint(HistoryTransferCheckpoint::DestinationActivated);
        plan.state = HistoryTransferState::Verified;
        persist_history_transfer_plan(&plan)?;
        checkpoint(HistoryTransferCheckpoint::Verified);
    }
    if plan.state != HistoryTransferState::Verified {
        return Err(FolderbaseError::InvalidMigrationState {
            expected: "verified",
            actual: history_transfer_state_name(plan.state).to_owned(),
        });
    }
    verify_history_transfer_ownership_boundaries(&plan)?;
    verify_history_transfer_receipts(&plan)?;
    verify_incoming_history(&destination, &plan)?;
    cleanup_history_transfer_staging(&destination.root, &plan.id)?;
    Ok(history_transfer_result(&plan))
}

fn verify_released_history_transfer(
    destination: &LocalVersionStore,
    plan: &HistoryTransferPlan,
) -> Result<()> {
    verify_history_transfer_ownership_boundaries(plan)?;
    verify_staged_history(destination, plan)
}

fn stage_history_transfer(
    source: &LocalVersionStore,
    destination: &LocalVersionStore,
    plan: &HistoryTransferPlan,
) -> Result<()> {
    let staging = history_transfer_staging_root(&destination.root, &plan.id);
    ensure_directory_chain(
        &destination.root,
        &PathBuf::from(HISTORY_TRANSFER_STAGING_DIRECTORY)
            .join(&plan.id)
            .join("objects"),
    )?;
    ensure_directory_chain(
        &destination.root,
        &PathBuf::from(HISTORY_TRANSFER_STAGING_DIRECTORY)
            .join(&plan.id)
            .join("versions/records"),
    )?;
    ensure_directory_chain(
        &destination.root,
        &PathBuf::from(HISTORY_TRANSFER_STAGING_DIRECTORY)
            .join(&plan.id)
            .join("versions/blobs/sha256"),
    )?;
    for version in &plan.versions {
        install_or_verify_content_file(
            &source.blob_path(&version.content.digest),
            &staging
                .join("versions/blobs/sha256")
                .join(&version.content.digest),
            &version.content,
        )?;
        install_or_verify_json(
            &staging
                .join("versions/records")
                .join(format!("{}.json", version.id)),
            version,
        )?;
    }
    let mut object = plan.object.clone();
    object.path.clone_from(&plan.destination_path);
    install_or_verify_json(
        &staging.join("objects").join(format!("{}.json", object.id)),
        &object,
    )
}

fn verify_staged_history(
    destination: &LocalVersionStore,
    plan: &HistoryTransferPlan,
) -> Result<()> {
    let staging = history_transfer_staging_root(&destination.root, &plan.id);
    for version in &plan.versions {
        let path = staging
            .join("versions/records")
            .join(format!("{}.json", version.id));
        let installed: LocalVersionRecord = read_json(&path)?;
        if installed != *version {
            return Err(invalid_record(path, "staged version record changed"));
        }
        verify_file_content(
            &staging
                .join("versions/blobs/sha256")
                .join(&version.content.digest),
            &version.content,
        )?;
    }
    let mut expected = plan.object.clone();
    expected.path.clone_from(&plan.destination_path);
    let path = staging
        .join("objects")
        .join(format!("{}.json", expected.id));
    let installed: LocalObjectRecord = read_json(&path)?;
    if installed != expected {
        return Err(invalid_record(path, "staged object projection changed"));
    }
    Ok(())
}

fn activate_incoming_history(
    destination: &LocalVersionStore,
    plan: &HistoryTransferPlan,
) -> Result<()> {
    destination.ensure_store_layout()?;
    let staging = history_transfer_staging_root(&destination.root, &plan.id);
    for version in &plan.versions {
        install_or_verify_content_file(
            &staging
                .join("versions/blobs/sha256")
                .join(&version.content.digest),
            &destination.blob_path(&version.content.digest),
            &version.content,
        )?;
        destination.install_or_verify_version_record(version)?;
    }
    let object = expected_history_transfer_object(plan);
    let object_path = destination.object_record_path(&object.id);
    match read_optional_file_nofollow(&object_path)? {
        Some(_) => {
            let installed: LocalObjectRecord = read_json(&object_path)?;
            verify_object_preserves_transferred_history(&installed, plan, &object_path)?;
        }
        None => install_or_verify_json(&object_path, &object)?,
    }
    destination.write_local_file_identity(&object.id, &destination.root.join(&object.path))
}

fn verify_incoming_history(
    destination: &LocalVersionStore,
    plan: &HistoryTransferPlan,
) -> Result<()> {
    let object = destination.read_object(&plan.object.id)?;
    verify_object_preserves_transferred_history(
        &object,
        plan,
        &destination.object_record_path(&plan.object.id),
    )?;
    for version in &plan.versions {
        if destination.read_version(&version.id)? != *version {
            return Err(invalid_record(
                destination.version_record_path(&version.id),
                "incoming version does not match the approved transfer",
            ));
        }
        verify_file_content(
            &destination.blob_path(&version.content.digest),
            &version.content,
        )?;
    }
    Ok(())
}

fn expected_history_transfer_object(plan: &HistoryTransferPlan) -> LocalObjectRecord {
    let mut expected = plan.object.clone();
    expected.path.clone_from(&plan.destination_path);
    expected
}

fn verify_object_preserves_transferred_history(
    object: &LocalObjectRecord,
    plan: &HistoryTransferPlan,
    path: &Path,
) -> Result<()> {
    if object.id != plan.object.id
        || object.path != plan.destination_path
        || !object.versions.starts_with(&plan.object.versions)
        || !object.versions.contains(&object.current_version)
    {
        return Err(invalid_record(
            path,
            "incoming object no longer preserves the approved transferred history",
        ));
    }
    Ok(())
}

fn verify_destination_available_for_transfer(
    destination: &LocalVersionStore,
    plan: &HistoryTransferPlan,
    allow_activated_replay: bool,
) -> Result<()> {
    let object_path = destination.object_record_path(&plan.object.id);
    if read_optional_file_nofollow(&object_path)?.is_some() {
        if !allow_activated_replay {
            return Err(FolderbaseError::WouldOverwrite(object_path));
        }
        let object: LocalObjectRecord = read_json(&object_path)?;
        verify_object_preserves_transferred_history(&object, plan, &object_path)?;
    }

    if let Some(claimant) = destination.find_object_by_path(Path::new(&plan.destination_path))? {
        if !allow_activated_replay || claimant.id != plan.object.id {
            return Err(FolderbaseError::WouldOverwrite(
                destination.object_record_path(&claimant.id),
            ));
        }
        verify_object_preserves_transferred_history(
            &claimant,
            plan,
            &destination.object_record_path(&claimant.id),
        )?;
    }

    for version in &plan.versions {
        let version_path = destination.version_record_path(&version.id);
        if read_optional_file_nofollow(&version_path)?.is_some()
            && destination.read_version_record(&version.id)? != *version
        {
            return Err(FolderbaseError::WouldOverwrite(version_path));
        }
        let blob_path = destination.blob_path(&version.content.digest);
        if read_optional_file_nofollow(&blob_path)?.is_some() {
            verify_file_content(&blob_path, &version.content)?;
        }
    }
    Ok(())
}

fn verify_history_transfer_preconditions(plan: &HistoryTransferPlan) -> Result<()> {
    let source = LocalVersionStore::open(&plan.source_root)?;
    let destination = LocalVersionStore::open(&plan.destination_root)?;
    verify_history_transfer_preconditions_for_stores(&source, &destination, plan)
}

fn verify_history_transfer_preconditions_for_stores(
    source: &LocalVersionStore,
    destination: &LocalVersionStore,
    plan: &HistoryTransferPlan,
) -> Result<()> {
    verify_history_transfer_boundary_preconditions(plan)?;
    let source_identity = read_folderbase_identity(&source.root)?;
    let destination_identity = read_folderbase_identity(&destination.root)?;
    if source_identity.id != plan.source_folderbase_id
        || destination_identity.id != plan.destination_folderbase_id
        || source_identity.manifest_sha256 != plan.source_manifest_sha256
        || destination_identity.manifest_sha256 != plan.destination_manifest_sha256
    {
        return Err(FolderbaseError::PlanPreconditionChanged(
            plan.source_root.clone(),
        ));
    }
    if !has_nested_folderbase_marker(&destination.root)? {
        return Err(FolderbaseError::UnsafePath(destination.root.clone()));
    }
    let object = source.read_object_record_for_transfer(&plan.object.id)?;
    if object != plan.object {
        return Err(FolderbaseError::PlanPreconditionChanged(
            source.object_record_path(&plan.object.id),
        ));
    }
    for expected in &plan.versions {
        let version = source.read_version_record(&expected.id)?;
        if version != *expected {
            return Err(FolderbaseError::PlanPreconditionChanged(
                source.version_record_path(&expected.id),
            ));
        }
        verify_file_content(
            &source.blob_path(&expected.content.digest),
            &expected.content,
        )?;
    }
    let current = plan
        .versions
        .iter()
        .find(|version| version.id == plan.object.current_version)
        .ok_or_else(|| {
            invalid_record(
                source.object_record_path(&plan.object.id),
                "current version is absent from approved history",
            )
        })?;
    let (materialized, canonical_path) =
        resolve_existing_workspace_file(&destination.root, Path::new(&plan.destination_path))?;
    if canonical_path != Path::new(&plan.destination_path) {
        return Err(FolderbaseError::UnsafePath(canonical_path));
    }
    verify_file_content(&materialized, &current.content)
}

fn verify_history_transfer_boundary_preconditions(plan: &HistoryTransferPlan) -> Result<()> {
    verify_history_transfer_ownership_boundaries(plan)?;
    let source_identity = read_folderbase_identity(&plan.source_root)?;
    let destination_identity = read_folderbase_identity(&plan.destination_root)?;
    if source_identity.manifest_sha256 != plan.source_manifest_sha256
        || destination_identity.manifest_sha256 != plan.destination_manifest_sha256
    {
        return Err(FolderbaseError::PlanPreconditionChanged(
            plan.source_root.clone(),
        ));
    }
    let current = plan
        .versions
        .iter()
        .find(|version| version.id == plan.object.current_version)
        .ok_or_else(|| {
            invalid_record(
                history_transfer_plan_path(&plan.source_root, &plan.id),
                "current version is absent from approved history",
            )
        })?;
    let (materialized, canonical_path) =
        resolve_existing_workspace_file(&plan.destination_root, Path::new(&plan.destination_path))?;
    if canonical_path != Path::new(&plan.destination_path) {
        return Err(FolderbaseError::UnsafePath(canonical_path));
    }
    verify_file_content(&materialized, &current.content)
}

fn verify_history_transfer_ownership_boundaries(plan: &HistoryTransferPlan) -> Result<()> {
    validate_history_transfer_plan(
        plan,
        &history_transfer_plan_path(&plan.source_root, &plan.id),
    )?;
    let source_identity = read_folderbase_identity(&plan.source_root)?;
    let destination_identity = read_folderbase_identity(&plan.destination_root)?;
    if source_identity.id != plan.source_folderbase_id
        || destination_identity.id != plan.destination_folderbase_id
    {
        return Err(FolderbaseError::PlanPreconditionChanged(
            plan.source_root.clone(),
        ));
    }
    if !has_nested_folderbase_marker(&plan.destination_root)? {
        return Err(FolderbaseError::UnsafePath(plan.destination_root.clone()));
    }
    let nested_root = plan
        .destination_root
        .strip_prefix(&plan.source_root)
        .map_err(|_| FolderbaseError::UnsafePath(plan.destination_root.clone()))?;
    if Path::new(&plan.object.path)
        != safe_content_path(nested_root)?.join(Path::new(&plan.destination_path))
    {
        return Err(invalid_record(
            history_transfer_plan_path(&plan.source_root, &plan.id),
            "approved source and destination paths no longer map to one materialized object",
        ));
    }
    Ok(())
}

fn verify_history_transfer_receipts(plan: &HistoryTransferPlan) -> Result<()> {
    let expected = history_transfer_receipt(plan)?;
    for path in [
        outgoing_history_transfer_path(&plan.source_root, &plan.object.id),
        incoming_history_transfer_path(&plan.destination_root, &plan.object.id),
    ] {
        let installed: HistoryTransferReceipt = read_json(&path)?;
        validate_history_transfer_receipt(&installed, &path)?;
        if installed != expected {
            return Err(invalid_record(
                path,
                "history-transfer receipt does not match the approved transfer",
            ));
        }
    }
    Ok(())
}

fn load_history_transfer_plan(root: &Path, transfer_id: &str) -> Result<HistoryTransferPlan> {
    validate_prefixed_uuid(transfer_id, "history_transfer_", root)?;
    let path = history_transfer_plan_path(root, transfer_id);
    let plan: HistoryTransferPlan = read_json(&path)?;
    validate_history_transfer_plan(&plan, &path)?;
    if plan.id != transfer_id || plan.source_root != root {
        return Err(invalid_record(
            path,
            "history-transfer plan ID or source root is inconsistent",
        ));
    }
    Ok(plan)
}

fn validate_history_transfer_plan(plan: &HistoryTransferPlan, path: &Path) -> Result<()> {
    if plan.protocol_version != "0.1.0"
        || plan.source_root == plan.destination_root
        || plan
            .destination_root
            .strip_prefix(&plan.source_root)
            .is_err()
        || plan.object.versions.is_empty()
        || plan.object.versions.len() != plan.versions.len()
        || plan
            .object
            .versions
            .iter()
            .zip(&plan.versions)
            .any(|(id, version)| id != &version.id || version.object_id != plan.object.id)
        || !plan.object.versions.contains(&plan.object.current_version)
        || safe_content_path(Path::new(&plan.destination_path)).is_err()
    {
        return Err(invalid_record(
            path,
            "history-transfer plan metadata is inconsistent",
        ));
    }
    validate_prefixed_uuid(&plan.id, "history_transfer_", path)?;
    validate_prefixed_uuid(&plan.source_folderbase_id, "folderbase_", path)?;
    validate_prefixed_uuid(&plan.destination_folderbase_id, "folderbase_", path)?;
    let approval_is_consistent = match plan.state {
        HistoryTransferState::Proposed => plan.approval_digest.is_none(),
        HistoryTransferState::Approved
        | HistoryTransferState::Applying
        | HistoryTransferState::DestinationVerified
        | HistoryTransferState::SourceReleased
        | HistoryTransferState::Verified
        | HistoryTransferState::Conflicted => plan.approval_digest.is_some(),
    };
    if !approval_is_consistent {
        return Err(invalid_record(
            path,
            "history-transfer approval metadata is inconsistent with its state",
        ));
    }
    if let Some(approval_digest) = &plan.approval_digest
        && history_transfer_digest(plan)? != *approval_digest
    {
        return Err(FolderbaseError::MigrationApprovalMismatch);
    }
    Ok(())
}

fn history_transfer_digest(plan: &HistoryTransferPlan) -> Result<String> {
    let bytes = serde_json::to_vec(&(
        &plan.protocol_version,
        &plan.id,
        &plan.source_root,
        &plan.destination_root,
        &plan.source_folderbase_id,
        &plan.destination_folderbase_id,
        &plan.source_manifest_sha256,
        &plan.destination_manifest_sha256,
        &plan.object,
        &plan.destination_path,
        &plan.versions,
        HistoryTransferState::Approved,
    ))
    .map_err(|source| FolderbaseError::json(&plan.source_root, source))?;
    Ok(digest_hex(Sha256::digest(&bytes).as_slice()))
}

fn persist_history_transfer_plan(plan: &HistoryTransferPlan) -> Result<()> {
    write_json_replace(
        &history_transfer_plan_path(&plan.source_root, &plan.id),
        plan,
    )
}

fn history_transfer_receipt(plan: &HistoryTransferPlan) -> Result<HistoryTransferReceipt> {
    Ok(HistoryTransferReceipt {
        protocol_version: "0.1.0".to_owned(),
        transfer_id: plan.id.clone(),
        source_folderbase_id: plan.source_folderbase_id.clone(),
        destination_folderbase_id: plan.destination_folderbase_id.clone(),
        object_id: plan.object.id.clone(),
        approval_digest: plan
            .approval_digest
            .clone()
            .ok_or(FolderbaseError::MigrationApprovalMismatch)?,
        version_ids: plan.object.versions.clone(),
    })
}

fn validate_history_transfer_receipt(receipt: &HistoryTransferReceipt, path: &Path) -> Result<()> {
    if receipt.protocol_version != "0.1.0" || receipt.version_ids.is_empty() {
        return Err(invalid_record(
            path,
            "history-transfer receipt metadata is inconsistent",
        ));
    }
    validate_prefixed_uuid(&receipt.transfer_id, "history_transfer_", path)?;
    validate_prefixed_uuid(&receipt.source_folderbase_id, "folderbase_", path)?;
    validate_prefixed_uuid(&receipt.destination_folderbase_id, "folderbase_", path)?;
    receipt.object_id.validate(path)?;
    for version_id in &receipt.version_ids {
        version_id.validate(path)?;
    }
    Ok(())
}

fn install_or_verify_history_transfer_receipt(
    path: &Path,
    receipt: &HistoryTransferReceipt,
) -> Result<()> {
    validate_history_transfer_receipt(receipt, path)?;
    install_or_verify_json(path, receipt)
}

fn install_or_verify_content_file(
    source: &Path,
    destination: &Path,
    expected: &ContentDigest,
) -> Result<()> {
    match read_optional_file_nofollow(destination)? {
        Some(_) => verify_file_content(destination, expected),
        None => copy_verified_new(source, destination, expected),
    }
}

fn install_or_verify_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let expected = json_bytes(path, value)?;
    match read_optional_file_nofollow(path)? {
        Some(existing) if existing == expected => Ok(()),
        Some(_) => Err(FolderbaseError::WouldOverwrite(path.to_path_buf())),
        None => write_bytes_new(path, &expected),
    }
}

fn history_transfer_result(plan: &HistoryTransferPlan) -> HistoryTransferResult {
    HistoryTransferResult {
        transfer_id: plan.id.clone(),
        source_folderbase_id: plan.source_folderbase_id.clone(),
        destination_folderbase_id: plan.destination_folderbase_id.clone(),
        object_id: plan.object.id.clone(),
        state: plan.state,
        version_ids: plan.object.versions.clone(),
    }
}

fn history_transfer_state_name(state: HistoryTransferState) -> &'static str {
    match state {
        HistoryTransferState::Proposed => "proposed",
        HistoryTransferState::Approved => "approved",
        HistoryTransferState::Applying => "applying",
        HistoryTransferState::DestinationVerified => "destination_verified",
        HistoryTransferState::SourceReleased => "source_released",
        HistoryTransferState::Verified => "verified",
        HistoryTransferState::Conflicted => "conflicted",
    }
}

fn history_transfer_staging_root(root: &Path, transfer_id: &str) -> PathBuf {
    root.join(HISTORY_TRANSFER_STAGING_DIRECTORY)
        .join(transfer_id)
}

fn outgoing_history_transfer_path(root: &Path, object_id: &ObjectId) -> PathBuf {
    root.join(HISTORY_TRANSFER_OUTGOING_DIRECTORY)
        .join(format!("{object_id}.json"))
}

fn incoming_history_transfer_path(root: &Path, object_id: &ObjectId) -> PathBuf {
    root.join(HISTORY_TRANSFER_INCOMING_DIRECTORY)
        .join(format!("{object_id}.json"))
}

fn cleanup_history_transfer_staging(root: &Path, transfer_id: &str) -> Result<()> {
    let staging = history_transfer_staging_root(root, transfer_id);
    match fs::remove_dir_all(&staging) {
        Ok(()) => sync_parent_directory(&staging),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(FolderbaseError::io(staging, source)),
    }
}

fn mark_history_transfer_conflicted(
    plan: &mut HistoryTransferPlan,
    error: FolderbaseError,
) -> FolderbaseError {
    plan.state = HistoryTransferState::Conflicted;
    match persist_history_transfer_plan(plan) {
        Ok(()) => error,
        Err(persistence_error) => persistence_error,
    }
}

fn mark_released_history_transfer_conflicted(
    plan: &mut HistoryTransferPlan,
    error: FolderbaseError,
) -> FolderbaseError {
    if plan.state == HistoryTransferState::SourceReleased {
        mark_history_transfer_conflicted(plan, error)
    } else {
        error
    }
}

fn validate_pending_transaction(transaction: &PendingTransaction, path: &Path) -> Result<()> {
    if transaction.protocol_version != "0.1.0"
        || !transaction.id.starts_with("transaction_")
        || Uuid::parse_str(
            transaction
                .id
                .strip_prefix("transaction_")
                .unwrap_or_default(),
        )
        .is_err()
        || transaction.events.is_empty()
    {
        return Err(invalid_record(
            path,
            "pending transaction has an invalid protocol version, ID, or empty event list",
        ));
    }

    transaction.object.id.validate(path)?;
    safe_content_path(Path::new(&transaction.object.path))
        .map_err(|_| invalid_record(path, "pending transaction has an unsafe object path"))?;
    if transaction.object.versions.is_empty()
        || !transaction
            .object
            .versions
            .contains(&transaction.object.current_version)
    {
        return Err(invalid_record(
            path,
            "pending transaction projection has an invalid version history",
        ));
    }

    if let Some(version) = &transaction.version {
        version.id.validate(path)?;
        version.object_id.validate(path)?;
        validate_content_digest(&version.content, path)?;
        if version.object_id != transaction.object.id
            || version.id != transaction.object.current_version
            || !transaction.object.versions.contains(&version.id)
        {
            return Err(invalid_record(
                path,
                "pending version does not match the object projection",
            ));
        }
    }

    for version in &transaction.versions {
        version.id.validate(path)?;
        version.object_id.validate(path)?;
        validate_content_digest(&version.content, path)?;
        if version.object_id != transaction.object.id
            || !transaction.object.versions.contains(&version.id)
        {
            return Err(invalid_record(
                path,
                "pending version does not match the object projection",
            ));
        }
    }

    if let Some(replacement) = &transaction.replacement {
        validate_content_digest(&replacement.previous_content, path)?;
        validate_content_digest(&replacement.content, path)?;
        safe_content_path(Path::new(&replacement.destination))
            .map_err(|_| invalid_record(path, "pending replacement has an unsafe destination"))?;
        let current = transaction
            .versions
            .iter()
            .chain(transaction.version.iter())
            .find(|version| version.id == transaction.object.current_version);
        if transaction.restore.is_some()
            || replacement.destination != transaction.object.path
            || replacement.previous_content == replacement.content
            || current.map(|version| &version.content) != Some(&replacement.content)
        {
            return Err(invalid_record(
                path,
                "pending replacement does not match the object projection",
            ));
        }
    }

    if let Some(restore) = &transaction.restore {
        restore.version_id.validate(path)?;
        validate_content_digest(&restore.content, path)?;
        safe_content_path(Path::new(&restore.destination))
            .map_err(|_| invalid_record(path, "pending restore has an unsafe destination"))?;
        if transaction.version.is_some()
            || !transaction.versions.is_empty()
            || transaction.replacement.is_some()
            || transaction.events.len() != 1
        {
            return Err(invalid_record(
                path,
                "pending restore must contain one restore event and no new version",
            ));
        }
        let event = &transaction.events[0];
        if event.action != JournalAction::VersionRestored
            || event.version_id.as_ref() != Some(&restore.version_id)
            || event.content.as_ref() != Some(&restore.content)
            || event.path != restore.destination
            || event.previous_path.is_some()
        {
            return Err(invalid_record(
                path,
                "pending restore does not match its restore event",
            ));
        }
    }

    for event in &transaction.events {
        validate_journal_event(event, path, 0)?;
        if event.object_id != transaction.object.id {
            return Err(invalid_record(
                path,
                "pending journal event belongs to a different object",
            ));
        }
    }
    Ok(())
}

fn maybe_fail_workspace_checkpoint(
    transaction: &PendingTransaction,
    checkpoint: &str,
    _path: &Path,
) -> Result<()> {
    let applies_to_workspace_save = transaction.replacement.is_some();
    let applies_to_restore = transaction.restore.is_some() && checkpoint == "restore-published";
    if !applies_to_workspace_save && !applies_to_restore {
        return Ok(());
    }
    #[cfg(debug_assertions)]
    if std::env::var("FOLDERBASE_TEST_FAIL_AFTER_WORKSPACE_CHECKPOINT").as_deref() == Ok(checkpoint)
    {
        return Err(FolderbaseError::io(
            _path,
            std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                format!("simulated interruption after {checkpoint}"),
            ),
        ));
    }
    Ok(())
}

fn parse_journal_bytes(
    path: &Path,
    bytes: &[u8],
    tolerate_incomplete_tail: bool,
) -> Result<Vec<ObjectJournalEvent>> {
    let mut events = Vec::new();
    let mut start = 0;
    let mut line_number = 1;

    for (index, byte) in bytes.iter().enumerate() {
        if *byte != b'\n' {
            continue;
        }
        let line = &bytes[start..index];
        if line.is_empty() {
            return Err(invalid_record(
                path,
                format!("journal line {line_number} is empty"),
            ));
        }
        let event: ObjectJournalEvent =
            serde_json::from_slice(line).map_err(|source| FolderbaseError::Json {
                path: path.to_path_buf(),
                source,
            })?;
        validate_journal_event(&event, path, line_number)?;
        events.push(event);
        start = index + 1;
        line_number += 1;
    }

    if start < bytes.len() {
        match serde_json::from_slice::<ObjectJournalEvent>(&bytes[start..]) {
            Ok(event) => {
                validate_journal_event(&event, path, line_number)?;
                events.push(event);
            }
            Err(_) if tolerate_incomplete_tail => {}
            Err(source) => {
                return Err(FolderbaseError::Json {
                    path: path.to_path_buf(),
                    source,
                });
            }
        }
    }
    Ok(events)
}

fn validate_journal_event(event: &ObjectJournalEvent, path: &Path, line: usize) -> Result<()> {
    if !event.id.starts_with("event_")
        || Uuid::parse_str(event.id.strip_prefix("event_").unwrap_or_default()).is_err()
    {
        return Err(invalid_record(
            path,
            journal_message(line, "has an invalid event ID"),
        ));
    }
    event.object_id.validate(path)?;
    if let Some(version_id) = &event.version_id {
        version_id.validate(path)?;
    }
    safe_content_path(Path::new(&event.path))
        .map_err(|_| invalid_record(path, journal_message(line, "has an unsafe content path")))?;
    if let Some(previous_path) = &event.previous_path {
        safe_content_path(Path::new(previous_path)).map_err(|_| {
            invalid_record(path, journal_message(line, "has an unsafe previous path"))
        })?;
    }
    if let Some(content) = &event.content {
        validate_content_digest(content, path)?;
    }
    Ok(())
}

fn journal_message(line: usize, message: &str) -> String {
    if line == 0 {
        format!("journal event {message}")
    } else {
        format!("journal line {line} {message}")
    }
}

pub(crate) fn safe_content_path(path: &Path) -> Result<PathBuf> {
    if path.as_os_str().is_empty() || path.is_absolute() || path.to_str().is_none() {
        return Err(FolderbaseError::UnsafePath(path.to_path_buf()));
    }

    let mut normalized = PathBuf::new();
    for component in path.components() {
        let Component::Normal(name) = component else {
            return Err(FolderbaseError::UnsafePath(path.to_path_buf()));
        };
        if is_reserved_workspace_component(name) {
            return Err(FolderbaseError::UnsafePath(path.to_path_buf()));
        }
        normalized.push(name);
    }
    if normalized.as_os_str().is_empty() {
        return Err(FolderbaseError::UnsafePath(path.to_path_buf()));
    }
    Ok(normalized)
}

fn relative_path_to_string(path: &Path) -> Result<String> {
    let safe = safe_content_path(path)?;
    safe.to_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| FolderbaseError::UnsafePath(path.to_path_buf()))
}

fn paths_equal_ignoring_ascii_case(left: &Path, right: &Path) -> bool {
    left.to_str()
        .zip(right.to_str())
        .is_some_and(|(left, right)| left.eq_ignore_ascii_case(right))
}

fn find_case_folded_child(parent: &Path, expected: &std::ffi::OsStr) -> Result<Option<PathBuf>> {
    let expected = expected
        .to_str()
        .ok_or_else(|| FolderbaseError::UnsafePath(parent.join(expected)))?;
    let entries = fs::read_dir(parent).map_err(|source| FolderbaseError::io(parent, source))?;
    let mut found = None;
    for entry in entries {
        let entry = entry.map_err(|source| FolderbaseError::io(parent, source))?;
        if entry
            .file_name()
            .to_str()
            .is_some_and(|name| name.eq_ignore_ascii_case(expected))
        {
            if found.is_some() {
                return Err(FolderbaseError::UnsafePath(parent.join(expected)));
            }
            found = Some(entry.path());
        }
    }
    Ok(found)
}

fn resolve_without_symlinks(
    root: &Path,
    relative_path: &Path,
    create_parents: bool,
) -> Result<PathBuf> {
    let relative_path = safe_content_path(relative_path)?;
    let mut resolved = root.to_path_buf();
    let parent = relative_path.parent().unwrap_or_else(|| Path::new(""));
    for component in parent.components() {
        let Component::Normal(component) = component else {
            return Err(FolderbaseError::UnsafePath(relative_path));
        };
        resolved.push(component);
        match fs::symlink_metadata(&resolved) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                return Err(FolderbaseError::UnsafePath(resolved));
            }
            Ok(_) => {}
            Err(source) if create_parents && source.kind() == std::io::ErrorKind::NotFound => {
                create_directory_durable(&resolved)?;
            }
            Err(source) => return Err(FolderbaseError::io(&resolved, source)),
        }
        if has_nested_folderbase_marker(&resolved)? {
            return Err(FolderbaseError::UnsafePath(relative_path));
        }
    }
    Ok(root.join(relative_path))
}

fn ensure_directory_chain(root: &Path, relative_path: &Path) -> Result<()> {
    let mut current = root.to_path_buf();
    for component in relative_path.components() {
        let Component::Normal(component) = component else {
            return Err(FolderbaseError::UnsafePath(relative_path.to_path_buf()));
        };
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                return Err(FolderbaseError::UnsafePath(current));
            }
            Ok(_) => {}
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                match create_private_directory_durable(&current) {
                    Ok(()) => {}
                    Err(FolderbaseError::Io { source, .. })
                        if source.kind() == std::io::ErrorKind::AlreadyExists =>
                    {
                        let metadata = fs::symlink_metadata(&current)
                            .map_err(|source| FolderbaseError::io(&current, source))?;
                        if metadata.file_type().is_symlink() || !metadata.is_dir() {
                            return Err(FolderbaseError::UnsafePath(current));
                        }
                    }
                    Err(error) => return Err(error),
                }
            }
            Err(source) => return Err(FolderbaseError::io(&current, source)),
        }
    }
    Ok(())
}

fn validate_prefixed_uuid(value: &str, prefix: &str, record_path: &Path) -> Result<()> {
    let Some(uuid) = value.strip_prefix(prefix) else {
        return Err(invalid_record(
            record_path,
            format!("identifier must start with {prefix}"),
        ));
    };
    Uuid::parse_str(uuid)
        .map(|_| ())
        .map_err(|_| invalid_record(record_path, "identifier suffix is not a UUID"))
}

fn read_folderbase_identity(root: &Path) -> Result<FolderbaseIdentity> {
    let path = root.join(".folderbase/manifest.json");
    let bytes = read_optional_file_nofollow(&path)?
        .ok_or_else(|| FolderbaseError::io(&path, std::io::ErrorKind::NotFound.into()))?;
    let id = folderbase_id_from_manifest_bytes(&bytes, &path)?;
    Ok(FolderbaseIdentity {
        id,
        manifest_sha256: digest_hex(Sha256::digest(&bytes).as_slice()),
    })
}

pub(crate) fn folderbase_id_from_manifest_bytes(bytes: &[u8], path: &Path) -> Result<String> {
    let manifest: Value =
        serde_json::from_slice(bytes).map_err(|source| FolderbaseError::json(path, source))?;
    let id = manifest
        .get("folderbase")
        .and_then(|folderbase| folderbase.get("id"))
        .and_then(Value::as_str)
        .ok_or_else(|| invalid_record(path, "manifest is missing folderbase.id"))?
        .to_owned();
    validate_prefixed_uuid(&id, "folderbase_", path)?;
    Ok(id)
}

pub(crate) fn validate_chunk_transfer_receipt_bytes(
    bytes: &[u8],
    path: &Path,
    object_id: &ObjectId,
    source_folderbase_id: &str,
) -> Result<()> {
    let receipt: HistoryTransferReceipt =
        serde_json::from_slice(bytes).map_err(|source| FolderbaseError::json(path, source))?;
    validate_history_transfer_receipt(&receipt, path)?;
    if receipt.object_id != *object_id || receipt.source_folderbase_id != source_folderbase_id {
        return Err(invalid_record(
            path,
            "outgoing history-transfer receipt does not match this folderbase or object",
        ));
    }
    Err(invalid_record(
        path,
        format!(
            "object history transferred to folderbase {}",
            receipt.destination_folderbase_id
        ),
    ))
}

fn history_transfer_plan_path(root: &Path, transfer_id: &str) -> PathBuf {
    root.join(HISTORY_TRANSFER_INTENTS_DIRECTORY)
        .join(format!("{transfer_id}.json"))
}

fn validate_content_digest(content: &ContentDigest, record_path: &Path) -> Result<()> {
    if content.algorithm != "sha256"
        || content.digest.len() != 64
        || !content
            .digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid_record(
            record_path,
            "content digest is not a lowercase SHA-256 digest",
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn filesystem_identity(metadata: &fs::Metadata) -> Option<FileSystemIdentity> {
    use std::os::unix::fs::MetadataExt;

    Some(FileSystemIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

#[cfg(not(unix))]
fn filesystem_identity(_metadata: &fs::Metadata) -> Option<FileSystemIdentity> {
    None
}

fn verify_file_content(path: &Path, expected: &ContentDigest) -> Result<()> {
    validate_content_digest(expected, path)?;
    let file = open_existing_nofollow(path)?;
    let actual = hash_reader(file, path)?;
    if actual != *expected {
        return Err(invalid_record(
            path,
            format!(
                "content integrity mismatch: expected {} bytes with digest {}, found {} bytes with digest {}",
                expected.bytes, expected.digest, actual.bytes, actual.digest
            ),
        ));
    }
    Ok(())
}

fn hash_reader(mut reader: impl Read, path: &Path) -> Result<ContentDigest> {
    let mut hasher = Sha256::new();
    let mut bytes = 0_u64;
    let mut buffer = [0_u8; COPY_BUFFER_BYTES];
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|source| FolderbaseError::io(path, source))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        bytes = bytes
            .checked_add(read as u64)
            .ok_or_else(|| invalid_record(path, "content length exceeds supported range"))?;
    }
    Ok(ContentDigest {
        algorithm: "sha256".to_owned(),
        digest: digest_hex(hasher.finalize().as_slice()),
        bytes,
    })
}

fn copy_verified_new(source: &Path, destination: &Path, expected: &ContentDigest) -> Result<()> {
    let parent = destination
        .parent()
        .ok_or_else(|| FolderbaseError::UnsafePath(destination.to_path_buf()))?;
    let mut input = open_existing_nofollow(source)?;
    let staged_path = unique_staged_path(parent, "restore");
    let mut staged = open_new(&staged_path)?;
    let mut hasher = Sha256::new();
    let mut bytes = 0_u64;
    let mut buffer = [0_u8; COPY_BUFFER_BYTES];

    let copy_result = (|| -> Result<()> {
        loop {
            let read = input
                .read(&mut buffer)
                .map_err(|source_error| FolderbaseError::io(source, source_error))?;
            if read == 0 {
                break;
            }
            staged
                .write_all(&buffer[..read])
                .map_err(|source_error| FolderbaseError::io(&staged_path, source_error))?;
            hasher.update(&buffer[..read]);
            bytes = bytes
                .checked_add(read as u64)
                .ok_or_else(|| invalid_record(source, "content length exceeds supported range"))?;
        }
        staged
            .sync_all()
            .map_err(|source_error| FolderbaseError::io(&staged_path, source_error))?;
        Ok(())
    })();
    drop(staged);
    if let Err(error) = copy_result {
        let _ = fs::remove_file(&staged_path);
        return Err(error);
    }

    let copied = ContentDigest {
        algorithm: "sha256".to_owned(),
        digest: digest_hex(hasher.finalize().as_slice()),
        bytes,
    };
    if copied != *expected {
        let _ = fs::remove_file(&staged_path);
        return Err(invalid_record(
            source,
            "blob changed while it was being restored",
        ));
    }
    match install_no_clobber(&staged_path, destination) {
        Ok(()) => sync_parent_directory(destination),
        Err(source_error) => {
            let _ = fs::remove_file(&staged_path);
            if source_error.kind() == std::io::ErrorKind::AlreadyExists {
                Err(FolderbaseError::WouldOverwrite(destination.to_path_buf()))
            } else {
                Err(FolderbaseError::io(destination, source_error))
            }
        }
    }
}

fn replace_verified(
    source: &Path,
    destination: &Path,
    expected: &ContentDigest,
    replacement: &PendingReplacement,
) -> Result<()> {
    let parent = destination
        .parent()
        .ok_or_else(|| FolderbaseError::UnsafePath(destination.to_path_buf()))?;
    let parent_file = open_directory_nofollow(parent)?;
    let parent_identity = filesystem_identity(
        &parent_file
            .metadata()
            .map_err(|source_error| FolderbaseError::io(parent, source_error))?,
    );
    if replacement
        .parent_identity
        .as_ref()
        .is_some_and(|expected| parent_identity.as_ref() != Some(expected))
    {
        return Err(FolderbaseError::WorkspaceContentChanged(PathBuf::from(
            &replacement.destination,
        )));
    }
    let destination_file = open_existing_nofollow(destination)?;
    let destination_identity = filesystem_identity(
        &destination_file
            .metadata()
            .map_err(|source_error| FolderbaseError::io(destination, source_error))?,
    );
    if replacement
        .file_identity
        .as_ref()
        .is_some_and(|expected| destination_identity.as_ref() != Some(expected))
    {
        return Err(FolderbaseError::WorkspaceContentChanged(PathBuf::from(
            &replacement.destination,
        )));
    }
    let mut input = open_existing_nofollow(source)?;
    let staged_path = unique_staged_path(parent, "workspace-save");
    let mut staged = open_new(&staged_path)?;
    let mut hasher = Sha256::new();
    let mut bytes = 0_u64;
    let mut buffer = [0_u8; COPY_BUFFER_BYTES];

    let copy_result = (|| -> Result<()> {
        loop {
            let read = input
                .read(&mut buffer)
                .map_err(|source_error| FolderbaseError::io(source, source_error))?;
            if read == 0 {
                break;
            }
            staged
                .write_all(&buffer[..read])
                .map_err(|source_error| FolderbaseError::io(&staged_path, source_error))?;
            hasher.update(&buffer[..read]);
            bytes = bytes
                .checked_add(read as u64)
                .ok_or_else(|| invalid_record(source, "content length exceeds supported range"))?;
        }

        #[cfg(unix)]
        if let Some(mode) = replacement.unix_mode {
            use std::os::unix::fs::PermissionsExt;
            staged
                .set_permissions(fs::Permissions::from_mode(mode))
                .map_err(|source_error| FolderbaseError::io(&staged_path, source_error))?;
        }
        #[cfg(not(unix))]
        {
            let mut permissions = staged
                .metadata()
                .map_err(|source_error| FolderbaseError::io(&staged_path, source_error))?
                .permissions();
            permissions.set_readonly(replacement.readonly);
            staged
                .set_permissions(permissions)
                .map_err(|source_error| FolderbaseError::io(&staged_path, source_error))?;
        }

        copy_ordinary_file_metadata(&destination_file, &staged, destination)?;
        staged
            .sync_all()
            .map_err(|source_error| FolderbaseError::io(&staged_path, source_error))?;
        Ok(())
    })();
    drop(staged);
    if let Err(error) = copy_result {
        let _ = fs::remove_file(&staged_path);
        return Err(error);
    }

    let copied = ContentDigest {
        algorithm: "sha256".to_owned(),
        digest: digest_hex(hasher.finalize().as_slice()),
        bytes,
    };
    if copied != *expected {
        let _ = fs::remove_file(&staged_path);
        return Err(invalid_record(
            source,
            "blob changed while workspace content was being staged",
        ));
    }

    let final_check = (|| -> Result<()> {
        let current_parent_identity = filesystem_identity(
            &fs::metadata(parent)
                .map_err(|source_error| FolderbaseError::io(parent, source_error))?,
        );
        if current_parent_identity != parent_identity {
            return Err(FolderbaseError::WorkspaceContentChanged(PathBuf::from(
                &replacement.destination,
            )));
        }

        let current_file = open_existing_nofollow(destination)?;
        let current_identity = filesystem_identity(
            &current_file
                .metadata()
                .map_err(|source_error| FolderbaseError::io(destination, source_error))?,
        );
        if current_identity != destination_identity {
            return Err(FolderbaseError::WorkspaceContentChanged(PathBuf::from(
                &replacement.destination,
            )));
        }
        let current_content = hash_reader(current_file, destination)?;
        if current_content != replacement.previous_content {
            return Err(FolderbaseError::WorkspaceContentChanged(PathBuf::from(
                &replacement.destination,
            )));
        }
        Ok(())
    })();
    if let Err(error) = final_check {
        let _ = fs::remove_file(&staged_path);
        return Err(error);
    }

    // POSIX rename is atomic but is not an atomic compare-and-swap. The
    // identity and digest check above is intentionally adjacent to the
    // replace; File Provider/NSFileCoordinator is still required to close the
    // final check-to-rename window against an uncooperative external writer.
    fs::rename(&staged_path, destination).map_err(|source_error| {
        let _ = fs::remove_file(&staged_path);
        FolderbaseError::io(destination, source_error)
    })?;
    sync_parent_directory(destination)?;
    verify_file_content(destination, expected)
}

fn open_existing_nofollow(path: &Path) -> Result<File> {
    let path_metadata =
        fs::symlink_metadata(path).map_err(|source| FolderbaseError::io(path, source))?;
    if path_metadata.file_type().is_symlink() || !path_metadata.is_file() {
        return Err(FolderbaseError::UnsafePath(path.to_path_buf()));
    }

    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let file = options
        .open(path)
        .map_err(|source| FolderbaseError::io(path, source))?;
    let opened_metadata = file
        .metadata()
        .map_err(|source| FolderbaseError::io(path, source))?;
    if !opened_metadata.is_file()
        || filesystem_identity(&path_metadata) != filesystem_identity(&opened_metadata)
    {
        return Err(FolderbaseError::UnsafePath(path.to_path_buf()));
    }
    Ok(file)
}

fn read_optional_file_nofollow(path: &Path) -> Result<Option<Vec<u8>>> {
    let mut file = match open_existing_nofollow(path) {
        Ok(file) => file,
        Err(FolderbaseError::Io { source, .. })
            if source.kind() == std::io::ErrorKind::NotFound =>
        {
            return Ok(None);
        }
        Err(error) => return Err(error),
    };
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|source| FolderbaseError::io(path, source))?;
    Ok(Some(bytes))
}

fn open_directory_nofollow(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW);
    }
    let file = options
        .open(path)
        .map_err(|source| FolderbaseError::io(path, source))?;
    if !file
        .metadata()
        .map_err(|source| FolderbaseError::io(path, source))?
        .is_dir()
    {
        return Err(FolderbaseError::UnsafePath(path.to_path_buf()));
    }
    Ok(file)
}

#[cfg(target_os = "macos")]
fn copy_ordinary_file_metadata(source: &File, destination: &File, path: &Path) -> Result<()> {
    use std::os::fd::AsRawFd;

    // Keep Finder metadata, extended attributes, and ACLs when atomically
    // replacing ordinary user content. COPYFILE_STAT is intentionally omitted:
    // an accepted edit must receive a new modification time.
    let flags = libc::COPYFILE_ACL | libc::COPYFILE_XATTR;
    if unsafe {
        libc::fcopyfile(
            source.as_raw_fd(),
            destination.as_raw_fd(),
            std::ptr::null_mut(),
            flags,
        )
    } != 0
    {
        return Err(FolderbaseError::io(path, std::io::Error::last_os_error()));
    }
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn copy_ordinary_file_metadata(_source: &File, _destination: &File, _path: &Path) -> Result<()> {
    Ok(())
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    let bytes = read_optional_file_nofollow(path)?.ok_or_else(|| {
        FolderbaseError::io(path, std::io::Error::from(std::io::ErrorKind::NotFound))
    })?;
    serde_json::from_slice(&bytes).map_err(|source| FolderbaseError::json(path, source))
}

fn write_json_new(path: &Path, value: &impl Serialize) -> Result<()> {
    let bytes = json_bytes(path, value)?;
    write_bytes_new(path, &bytes)
}

fn write_json_replace(path: &Path, value: &impl Serialize) -> Result<()> {
    let bytes = json_bytes(path, value)?;
    write_bytes_replace(path, &bytes)
}

fn write_bytes_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| FolderbaseError::UnsafePath(path.to_path_buf()))?;
    let staged_path = unique_staged_path(parent, "record");
    write_staged(&staged_path, bytes)?;
    match install_no_clobber(&staged_path, path) {
        Ok(()) => sync_parent_directory(path),
        Err(source) => {
            let _ = fs::remove_file(&staged_path);
            if source.kind() == std::io::ErrorKind::AlreadyExists {
                Err(FolderbaseError::WouldOverwrite(path.to_path_buf()))
            } else {
                Err(FolderbaseError::io(path, source))
            }
        }
    }
}

fn write_bytes_replace(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| FolderbaseError::UnsafePath(path.to_path_buf()))?;
    let staged_path = unique_staged_path(parent, "projection");
    write_staged(&staged_path, bytes)?;
    fs::rename(&staged_path, path).map_err(|source| {
        let _ = fs::remove_file(&staged_path);
        FolderbaseError::io(path, source)
    })?;
    sync_parent_directory(path)
}

fn json_bytes(path: &Path, value: &impl Serialize) -> Result<Vec<u8>> {
    let mut bytes =
        serde_json::to_vec_pretty(value).map_err(|source| FolderbaseError::json(path, source))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn write_staged(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = open_new(path)?;
    let result = file.write_all(bytes).and_then(|()| file.sync_all());
    drop(file);
    if let Err(source) = result {
        let _ = fs::remove_file(path);
        return Err(FolderbaseError::io(path, source));
    }
    Ok(())
}

fn open_new(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    options
        .open(path)
        .map_err(|source| FolderbaseError::io(path, source))
}

fn create_private_directory_durable(path: &Path) -> Result<()> {
    let builder = fs::DirBuilder::new();
    #[cfg(unix)]
    let builder = {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = builder;
        builder.mode(0o700);
        builder
    };
    builder
        .create(path)
        .map_err(|source| FolderbaseError::io(path, source))?;
    sync_parent_directory(path)
}

fn create_directory_durable(path: &Path) -> Result<()> {
    fs::create_dir(path).map_err(|source| FolderbaseError::io(path, source))?;
    sync_parent_directory(path)
}

/// Install a staged file without ever replacing an existing destination.
fn install_no_clobber(staged: &Path, destination: &Path) -> std::io::Result<()> {
    fs::hard_link(staged, destination)?;
    fs::remove_file(staged)
}

fn unique_staged_path(directory: &Path, label: &str) -> PathBuf {
    directory.join(format!(".{label}-{}.tmp", Uuid::now_v7()))
}

#[cfg(unix)]
fn sync_parent_directory(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| FolderbaseError::UnsafePath(path.to_path_buf()))?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| FolderbaseError::io(parent, source))
}

#[cfg(not(unix))]
fn sync_parent_directory(_path: &Path) -> Result<()> {
    Ok(())
}

fn digest_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

fn invalid_record(path: impl Into<PathBuf>, message: impl Into<String>) -> FolderbaseError {
    FolderbaseError::InvalidRecord {
        path: path.into(),
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs::OpenOptions,
        panic::{AssertUnwindSafe, catch_unwind},
    };

    use tempfile::TempDir;

    use super::*;
    use crate::{
        FolderbaseKind, InitializationOptions,
        initialization::{initialize, plan_initialization},
    };

    #[test]
    fn transaction_lock_is_exclusive_across_independent_handles() {
        let fixture = tempfile::tempdir().expect("temporary lock store");
        fs::create_dir_all(fixture.path().join(LOCKS_DIRECTORY)).expect("lock directory");
        let path = fixture.path().join(TRANSACTION_LOCK_PATH);
        let first = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .expect("first handle");
        let second = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .expect("second handle");
        File::lock(&first).expect("first exclusive lock");
        assert!(matches!(
            File::try_lock(&second).expect_err("second handle must contend"),
            std::fs::TryLockError::WouldBlock
        ));
        File::unlock(&first).expect("unlock");
        File::lock(&second).expect("second handle acquires after release");
        File::unlock(&second).expect("final unlock");
    }

    #[test]
    fn every_history_transfer_checkpoint_reopens_and_recovers() {
        for fault in [
            HistoryTransferCheckpoint::Applying,
            HistoryTransferCheckpoint::DestinationStaged,
            HistoryTransferCheckpoint::DestinationVerified,
            HistoryTransferCheckpoint::SourceReceiptWritten,
            HistoryTransferCheckpoint::SourceReleased,
            HistoryTransferCheckpoint::IncomingReceiptWritten,
            HistoryTransferCheckpoint::DestinationActivated,
            HistoryTransferCheckpoint::Verified,
        ] {
            let (fixture, parent_store, child_store, parent_id, child_id, object_id) =
                history_transfer_fixture();
            let plan = parent_store
                .propose_history_transfer(
                    &child_store,
                    &parent_id,
                    &child_id,
                    &object_id,
                    "private.txt",
                )
                .unwrap();
            let transfer_id = plan.id().to_owned();
            let approved = approve_history_transfer(plan).unwrap();

            let interrupted = catch_unwind(AssertUnwindSafe(|| {
                apply_history_transfer_with_hook(approved, |checkpoint| {
                    if checkpoint == fault {
                        panic!("simulated process termination");
                    }
                })
            }));
            assert!(interrupted.is_err());
            if fault == HistoryTransferCheckpoint::IncomingReceiptWritten {
                assert!(incoming_history_transfer_path(child_store.root(), &object_id).exists());
                assert!(child_store.read_object(&object_id).is_err());
            }

            let recovered = HistoryTransferResult::recover(fixture.path(), &transfer_id).unwrap();
            assert_eq!(recovered.state, HistoryTransferState::Verified);
            assert_eq!(recovered.object_id, object_id);
            assert_eq!(
                child_store.read_object(&object_id).unwrap().path,
                "private.txt"
            );
            assert!(parent_store.read_object(&object_id).is_err());
            assert_eq!(
                HistoryTransferResult::recover(fixture.path(), &transfer_id)
                    .unwrap()
                    .state,
                HistoryTransferState::Verified
            );
            assert!(!history_transfer_staging_root(child_store.root(), &transfer_id).exists());
        }
    }

    #[test]
    fn source_released_recovery_preserves_workspace_and_manifest_changes() {
        let (fixture, parent_store, child_store, parent_id, child_id, object_id) =
            history_transfer_fixture();
        let plan = parent_store
            .propose_history_transfer(
                &child_store,
                &parent_id,
                &child_id,
                &object_id,
                "private.txt",
            )
            .unwrap();
        let transfer_id = plan.id().to_owned();
        let approved = approve_history_transfer(plan).unwrap();
        let interrupted = catch_unwind(AssertUnwindSafe(|| {
            apply_history_transfer_with_hook(approved, |checkpoint| {
                if checkpoint == HistoryTransferCheckpoint::SourceReleased {
                    panic!("simulated process termination");
                }
            })
        }));
        assert!(interrupted.is_err());

        fs::write(
            fixture.path().join("Client/private.txt"),
            "user edit after source release\n",
        )
        .unwrap();
        for manifest in [
            fixture.path().join(".folderbase/manifest.json"),
            fixture.path().join("Client/.folderbase/manifest.json"),
        ] {
            let mut bytes = fs::read(&manifest).unwrap();
            bytes.push(b'\n');
            fs::write(manifest, bytes).unwrap();
        }

        let recovered = HistoryTransferResult::recover(fixture.path(), &transfer_id).unwrap();

        assert_eq!(recovered.state, HistoryTransferState::Verified);
        assert_eq!(
            fs::read(fixture.path().join("Client/private.txt")).unwrap(),
            b"user edit after source release\n"
        );
        assert_eq!(child_store.read_object(&object_id).unwrap().id, object_id);
        assert!(parent_store.read_object(&object_id).is_err());
    }

    #[test]
    fn source_released_destination_capture_enters_durable_conflict() {
        let (fixture, parent_store, child_store, parent_id, child_id, object_id) =
            history_transfer_fixture();
        let plan = parent_store
            .propose_history_transfer(
                &child_store,
                &parent_id,
                &child_id,
                &object_id,
                "private.txt",
            )
            .unwrap();
        let transfer_id = plan.id().to_owned();
        let approved = approve_history_transfer(plan).unwrap();
        let interrupted = catch_unwind(AssertUnwindSafe(|| {
            apply_history_transfer_with_hook(approved, |checkpoint| {
                if checkpoint == HistoryTransferCheckpoint::SourceReleased {
                    panic!("simulated process termination");
                }
            })
        }));
        assert!(interrupted.is_err());

        fs::write(
            fixture.path().join("Client/private.txt"),
            "captured child edit\n",
        )
        .unwrap();
        let child_capture = child_store.capture_file("private.txt").unwrap();
        let error = HistoryTransferResult::recover(fixture.path(), &transfer_id).unwrap_err();

        assert!(matches!(error, FolderbaseError::WouldOverwrite(_)));
        assert_eq!(
            HistoryTransferPlan::reopen(fixture.path(), &transfer_id)
                .unwrap()
                .state,
            HistoryTransferState::Conflicted
        );
        assert_eq!(
            child_store
                .read_object(&child_capture.object.id)
                .unwrap()
                .id,
            child_capture.object.id
        );
        assert_eq!(
            fs::read(fixture.path().join("Client/private.txt")).unwrap(),
            b"captured child edit\n"
        );
    }

    #[test]
    fn source_released_staging_tamper_enters_durable_conflict() {
        let (fixture, parent_store, child_store, parent_id, child_id, object_id) =
            history_transfer_fixture();
        let plan = parent_store
            .propose_history_transfer(
                &child_store,
                &parent_id,
                &child_id,
                &object_id,
                "private.txt",
            )
            .unwrap();
        let transfer_id = plan.id().to_owned();
        let approved = approve_history_transfer(plan).unwrap();
        let interrupted = catch_unwind(AssertUnwindSafe(|| {
            apply_history_transfer_with_hook(approved, |checkpoint| {
                if checkpoint == HistoryTransferCheckpoint::SourceReleased {
                    panic!("simulated process termination");
                }
            })
        }));
        assert!(interrupted.is_err());

        let staged_object = history_transfer_staging_root(child_store.root(), &transfer_id)
            .join("objects")
            .join(format!("{object_id}.json"));
        fs::write(staged_object, b"{}\n").unwrap();

        assert!(HistoryTransferResult::recover(fixture.path(), &transfer_id).is_err());
        assert_eq!(
            HistoryTransferPlan::reopen(fixture.path(), &transfer_id)
                .unwrap()
                .state,
            HistoryTransferState::Conflicted
        );
        assert!(parent_store.read_object(&object_id).is_err());
        assert!(child_store.read_object(&object_id).is_err());
    }

    #[test]
    fn verified_recovery_reports_staging_cleanup_failure_and_retries() {
        let (fixture, parent_store, child_store, parent_id, child_id, object_id) =
            history_transfer_fixture();
        let plan = parent_store
            .propose_history_transfer(
                &child_store,
                &parent_id,
                &child_id,
                &object_id,
                "private.txt",
            )
            .unwrap();
        let transfer_id = plan.id().to_owned();
        apply_history_transfer(approve_history_transfer(plan).unwrap()).unwrap();
        let staging = history_transfer_staging_root(child_store.root(), &transfer_id);
        fs::write(&staging, b"not a removable staging directory").unwrap();

        let cleanup_error =
            HistoryTransferResult::recover(fixture.path(), &transfer_id).unwrap_err();

        assert!(matches!(cleanup_error, FolderbaseError::Io { .. }));
        assert!(staging.is_file());
        assert_eq!(
            HistoryTransferPlan::reopen(fixture.path(), &transfer_id)
                .unwrap()
                .state,
            HistoryTransferState::Verified
        );
        fs::remove_file(&staging).unwrap();
        assert_eq!(
            HistoryTransferResult::recover(fixture.path(), &transfer_id)
                .unwrap()
                .state,
            HistoryTransferState::Verified
        );
    }

    fn history_transfer_fixture() -> (
        TempDir,
        LocalVersionStore,
        LocalVersionStore,
        String,
        String,
        ObjectId,
    ) {
        let fixture = tempfile::tempdir().unwrap();
        let parent = initialize(
            &plan_initialization(
                fixture.path(),
                InitializationOptions {
                    name: Some("Parent".to_owned()),
                    kind: FolderbaseKind::Organization,
                    create_agent_adapters: false,
                },
            )
            .unwrap(),
        )
        .unwrap();
        fs::create_dir(fixture.path().join("Client")).unwrap();
        fs::write(fixture.path().join("Client/private.txt"), "history\n").unwrap();
        let parent_store = LocalVersionStore::open(fixture.path()).unwrap();
        let captured = parent_store.capture_file("Client/private.txt").unwrap();

        let child_fixture = tempfile::tempdir().unwrap();
        let child = initialize(
            &plan_initialization(
                child_fixture.path(),
                InitializationOptions {
                    name: Some("Child".to_owned()),
                    kind: FolderbaseKind::Project,
                    create_agent_adapters: false,
                },
            )
            .unwrap(),
        )
        .unwrap();
        fs::create_dir_all(fixture.path().join("Client/.folderbase")).unwrap();
        fs::copy(
            child_fixture.path().join(".folderbase/manifest.json"),
            fixture.path().join("Client/.folderbase/manifest.json"),
        )
        .unwrap();
        let child_store = LocalVersionStore::open(fixture.path().join("Client")).unwrap();
        (
            fixture,
            parent_store,
            child_store,
            parent.folderbase_id,
            child.folderbase_id,
            captured.object.id,
        )
    }
}

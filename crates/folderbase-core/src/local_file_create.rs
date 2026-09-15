//! One expected-absent file, with a separate intent and durable retry receipt.

use super::*;
use crate::root_attestation::{RootAttestationError, attest_folderbase_root};

pub const MAX_WORKSPACE_CREATE_BYTES: usize = 8 * 1024 * 1024;
pub(super) const ACTIVE_CREATE_PATH: &str = ".folderbase/transactions/workspace-create/active.json";
const CREATE_DIRECTORY: &str = ".folderbase/transactions/workspace-create";
const RECEIPTS_DIRECTORY: &str = ".folderbase/local/workspace-create/receipts";
const MAX_PREPARED_STAGES: usize = 4;
const MAX_INTENT_BYTES: u64 = 64 * 1024;
const MAX_OBJECTS: usize = 16_384;
const MAX_READ_BYTES: u64 = 64 * 1024 * 1024;
const INTENT_FORMAT: &str = "folderbase-workspace-create-intent-v1";
const RECEIPT_FORMAT: &str = "folderbase-workspace-create-receipt-v1";

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum WorkspaceCreateError {
    #[error(transparent)]
    Core(#[from] FolderbaseError),
    #[error(transparent)]
    Root(#[from] RootAttestationError),
    #[error("operation ID must be a canonical lowercase hyphenated UUID")]
    InvalidOperationId,
    #[error("create content exceeds the {MAX_WORKSPACE_CREATE_BYTES} byte limit")]
    ContentTooLarge,
    #[error("unclaimed create stage limit reached; retained artifacts require inspection")]
    RetainedStageLimit,
    #[error("create destination is occupied or already claimed: {0}")]
    DestinationOccupied(String),
    #[error("operation ID was already used for a different create request")]
    OperationConflict,
    #[error("workspace create requires recovery of other work: {0}")]
    RecoveryRequired(String),
    #[error("workspace create does not yet support roots with migration metadata")]
    MigrationStateUnsupported,
    #[error("workspace create root or transaction authority changed")]
    AuthorityChanged,
}

impl WorkspaceCreateError {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Core(_) => "workspace_create_state_invalid",
            Self::Root(_) => "workspace_create_root_invalid",
            Self::InvalidOperationId => "workspace_create_invalid_operation_id",
            Self::ContentTooLarge => "workspace_create_content_too_large",
            Self::RetainedStageLimit => "workspace_create_retained_stage_limit",
            Self::DestinationOccupied(_) => "workspace_create_destination_occupied",
            Self::OperationConflict => "workspace_create_operation_conflict",
            Self::RecoveryRequired(_) => "workspace_create_recovery_required",
            Self::MigrationStateUnsupported => "workspace_create_migration_state_unsupported",
            Self::AuthorityChanged => "workspace_create_authority_changed",
        }
    }
}

type CreateResult<T> = std::result::Result<T, WorkspaceCreateError>;

/// Historical result of one accepted create. Replay never asserts current
/// ordinary bytes and never recreates a subsequently removed destination.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceCreateResult {
    pub format: String,
    pub operation_id: String,
    pub path: String,
    pub object_id: ObjectId,
    pub version_id: VersionId,
    pub content: ContentDigest,
    pub created_at: String,
    pub replayed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    operation_id: String,
    path: String,
    #[serde(deserialize_with = "deserialize_closed_digest")]
    content: ContentDigest,
}

fn deserialize_closed_digest<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<ContentDigest, D::Error> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ClosedDigest {
        algorithm: String,
        digest: String,
        bytes: u64,
    }
    let value = ClosedDigest::deserialize(deserializer)?;
    Ok(ContentDigest {
        algorithm: value.algorithm,
        digest: value.digest,
        bytes: value.bytes,
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Intent {
    format: String,
    request: Request,
    folderbase_id: String,
    root_instance_sha256: String,
    manifest_sha256: String,
    state_identity_sha256: String,
    parent_identity_sha256: String,
    object_id: ObjectId,
    version_id: VersionId,
    tracked_event_id: String,
    captured_event_id: String,
    created_at: String,
    stage: Option<OwnedStage>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnedStage {
    name: String,
    identity_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    format: String,
    intent: Intent,
    outcome: Outcome,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Outcome {
    Created,
    Conflicted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Checkpoint {
    BlobDurable,
    IntentDurable,
    VersionDurable,
    StageUnpinned,
    StageDurable,
    FileLinked,
    FileDurable,
    ProjectionDurable,
    JournalStaged,
    JournalDurable,
    ReceiptDurable,
    StageQuarantined,
    StageRetired,
    IntentRetired,
}

impl Checkpoint {
    #[cfg(debug_assertions)]
    fn name(self) -> &'static str {
        match self {
            Self::BlobDurable => "blob-durable",
            Self::IntentDurable => "intent-durable",
            Self::VersionDurable => "version-durable",
            Self::StageUnpinned => "stage-unpinned",
            Self::StageDurable => "stage-durable",
            Self::FileLinked => "file-linked",
            Self::FileDurable => "file-durable",
            Self::ProjectionDurable => "projection-durable",
            Self::JournalStaged => "journal-staged",
            Self::JournalDurable => "journal-durable",
            Self::ReceiptDurable => "receipt-durable",
            Self::StageQuarantined => "stage-quarantined",
            Self::StageRetired => "stage-retired",
            Self::IntentRetired => "intent-retired",
        }
    }
}

impl Intent {
    fn stage_directory(&self) -> PathBuf {
        Path::new(CREATE_DIRECTORY)
            .join("stages")
            .join(&self.request.operation_id)
    }

    fn stage(&self) -> PathBuf {
        self.stage_directory().join(
            &self
                .stage
                .as_ref()
                .expect("stage is pinned before use")
                .name,
        )
    }

    fn version(&self) -> LocalVersionRecord {
        LocalVersionRecord {
            id: self.version_id.clone(),
            object_id: self.object_id.clone(),
            content: self.request.content.clone(),
            captured_at: self.created_at.clone(),
            extensions: BTreeMap::from([(VERSION_EXECUTABLE_FIELD.to_owned(), Value::Bool(false))]),
        }
    }

    fn object(&self) -> Result<LocalObjectRecord> {
        Ok(LocalObjectRecord {
            schema: OBJECT_SCHEMA.to_owned(),
            id: self.object_id.clone(),
            object_type: "file".to_owned(),
            path: relative_path_to_string(Path::new(&self.request.path))?,
            lifecycle: ObjectLifecycle {
                status: "canonical".to_owned(),
                extensions: BTreeMap::new(),
            },
            provenance: ObjectProvenance {
                created_at: self.created_at.clone(),
                source: "local".to_owned(),
                extensions: BTreeMap::new(),
            },
            current_version: self.version_id.clone(),
            versions: vec![self.version_id.clone()],
            extensions: BTreeMap::new(),
        })
    }

    fn events(&self) -> Result<Vec<ObjectJournalEvent>> {
        let path = self.object()?.path;
        Ok(vec![
            ObjectJournalEvent {
                id: self.tracked_event_id.clone(),
                at: self.created_at.clone(),
                action: JournalAction::ObjectTracked,
                object_id: self.object_id.clone(),
                path: path.clone(),
                previous_path: None,
                version_id: None,
                content: None,
            },
            ObjectJournalEvent {
                id: self.captured_event_id.clone(),
                at: self.created_at.clone(),
                action: JournalAction::VersionCaptured,
                object_id: self.object_id.clone(),
                path,
                previous_path: None,
                version_id: Some(self.version_id.clone()),
                content: Some(self.request.content.clone()),
            },
        ])
    }

    fn result(&self, replayed: bool) -> WorkspaceCreateResult {
        WorkspaceCreateResult {
            format: "folderbase-workspace-create-result-v1".to_owned(),
            operation_id: self.request.operation_id.clone(),
            path: self.request.path.clone(),
            object_id: self.object_id.clone(),
            version_id: self.version_id.clone(),
            content: self.request.content.clone(),
            created_at: self.created_at.clone(),
            replayed,
        }
    }

    fn validate(&self) -> CreateResult<()> {
        let path = Path::new(ACTIVE_CREATE_PATH);
        validate_operation_id(&self.request.operation_id)?;
        if self.format != INTENT_FORMAT
            || portable_path(Path::new(&self.request.path))? != self.request.path
        {
            return Err(invalid_record(path, "invalid create intent format or path").into());
        }
        validate_content_digest(&self.request.content, path)?;
        if self.request.content.bytes > MAX_WORKSPACE_CREATE_BYTES as u64 {
            return Err(WorkspaceCreateError::ContentTooLarge);
        }
        self.object_id.validate(path)?;
        self.version_id.validate(path)?;
        validate_prefixed_uuid(&self.folderbase_id, "folderbase_", path)?;
        for value in [
            &self.root_instance_sha256,
            &self.manifest_sha256,
            &self.state_identity_sha256,
            &self.parent_identity_sha256,
        ]
        .into_iter()
        .chain(self.stage.iter().map(|stage| &stage.identity_sha256))
        {
            if value.len() != 64
                || !value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return Err(invalid_record(path, "invalid create authority digest").into());
            }
        }
        if let Some(stage) = &self.stage {
            validate_operation_id(&stage.name)?;
        }
        chrono::DateTime::parse_from_rfc3339(&self.created_at)
            .map_err(|_| invalid_record(path, "invalid create timestamp"))?;
        let events = self.events()?;
        if self.tracked_event_id == self.captured_event_id {
            return Err(invalid_record(path, "duplicate create event ID").into());
        }
        for event in events {
            validate_journal_event(&event, path, 0)?;
        }
        Ok(())
    }
}

fn validate_operation_id(id: &str) -> CreateResult<()> {
    if Uuid::parse_str(id).is_ok_and(|parsed| parsed.hyphenated().to_string() == id) {
        Ok(())
    } else {
        Err(WorkspaceCreateError::InvalidOperationId)
    }
}

fn portable_path(path: &Path) -> Result<String> {
    let path = safe_content_path(path)?;
    refuse_generic_workspace_mutation_path(&path)?;
    path.components()
        .map(|component| {
            component
                .as_os_str()
                .to_str()
                .map(str::to_owned)
                .ok_or_else(|| FolderbaseError::UnsafePath(path.clone()))
        })
        .collect::<Result<Vec<_>>>()
        .map(|parts| parts.join("/"))
}

fn receipt_path(operation_id: &str) -> PathBuf {
    Path::new(RECEIPTS_DIRECTORY).join(format!("{operation_id}.json"))
}

fn read_record<T: serde::de::DeserializeOwned>(
    state: &FolderbaseState,
    path: &Path,
) -> Result<Option<T>> {
    state
        .read_bounded_if_present(path, MAX_INTENT_BYTES)?
        .map(|bytes| {
            serde_json::from_slice(&bytes).map_err(|source| FolderbaseError::json(path, source))
        })
        .transpose()
}

fn publish_exact(state: &FolderbaseState, path: &Path, value: &impl Serialize) -> Result<()> {
    let bytes = json_bytes(path, value)?;
    match state.publish_new(path, &bytes) {
        Ok(()) => Ok(()),
        Err(FolderbaseError::WouldOverwrite(_))
            if state.read_bounded(path, MAX_INTENT_BYTES)?.as_deref() == Some(bytes.as_slice()) =>
        {
            state.sync_private_regular_and_parent(path)
        }
        Err(error) => Err(error),
    }
}

fn verify_authority(
    root: &Path,
    state: &FolderbaseState,
    intent: &Intent,
    completed: bool,
) -> CreateResult<()> {
    state.verify_still_attached()?;
    let current = attest_folderbase_root(root)?;
    if state.state_identity_sha256()? != intent.state_identity_sha256
        || (!completed
            && state.create_parent_identity_sha256(Path::new(&intent.request.path))?
                != intent.parent_identity_sha256)
        || current.folderbase_id != intent.folderbase_id
        || current.root_instance_sha256 != intent.root_instance_sha256
        || (!completed && current.manifest_sha256 != intent.manifest_sha256)
    {
        return Err(WorkspaceCreateError::AuthorityChanged);
    }
    Ok(())
}

/// Historical creation provenance, never an assertion about current file bytes.
/// Only the closed receipt reader below constructs this private proof.
pub(super) struct CreatedObjectClaim {
    intent: Intent,
    receipt: PathBuf,
    encoded: Vec<u8>,
    names: Vec<std::ffi::OsString>,
}

impl CreatedObjectClaim {
    pub(super) fn object_id(&self) -> &ObjectId {
        &self.intent.object_id
    }

    pub(super) fn version(&self) -> LocalVersionRecord {
        self.intent.version()
    }

    pub(super) fn verify(&self, root: &Path, state: &FolderbaseState) -> Result<()> {
        let mut names =
            state.private_directory_names_if_present(Path::new(RECEIPTS_DIRECTORY), MAX_OBJECTS)?;
        names.sort();
        if names != self.names
            || path_ownership::read_metadata(state, &self.receipt, MAX_INTENT_BYTES)?.as_ref()
                != Some(&self.encoded)
            || path_ownership::read_metadata(
                state,
                Path::new(ACTIVE_CREATE_PATH),
                MAX_INTENT_BYTES,
            )?
            .is_some()
        {
            return Err(invalid_record(
                &self.receipt,
                "completed create ownership evidence changed",
            ));
        }
        verify_authority(root, state, &self.intent, true)
            .map_err(|error| invalid_record(&self.receipt, error.to_string()))
    }
}

pub(super) fn completed_object_claim<E: From<FolderbaseError>>(
    root: &Path,
    state: &FolderbaseState,
    selected: &Path,
    object: &LocalObjectRecord,
    mut read: impl FnMut(&Path, u64) -> std::result::Result<Option<Vec<u8>>, E>,
) -> std::result::Result<CreatedObjectClaim, E> {
    let invalid = || {
        invalid_record(
            selected,
            "unbound Object has no valid completed create ownership receipt",
        )
    };
    if read(Path::new(ACTIVE_CREATE_PATH), MAX_INTENT_BYTES)?.is_some() {
        return Err(invalid().into());
    }
    let mut names =
        state.private_directory_names_if_present(Path::new(RECEIPTS_DIRECTORY), MAX_OBJECTS)?;
    names.sort();
    let mut total = 0usize;
    let mut found = None;
    for name in &names {
        let path = Path::new(RECEIPTS_DIRECTORY).join(name);
        let encoded = read(&path, MAX_INTENT_BYTES)?.ok_or_else(invalid)?;
        total = total.checked_add(encoded.len()).ok_or_else(invalid)?;
        if total > MAX_READ_BYTES as usize {
            return Err(
                invalid_record(&path, "completed create receipt inventory exceeds 64 MiB").into(),
            );
        }
        let receipt: Receipt = serde_json::from_slice(&encoded)
            .map_err(|error| FolderbaseError::json(&path, error))?;
        receipt
            .intent
            .validate()
            .map_err(|error| invalid_record(&path, error.to_string()))?;
        if receipt.format != RECEIPT_FORMAT
            || receipt.intent.stage.is_none()
            || receipt_path(&receipt.intent.request.operation_id) != path
        {
            return Err(invalid_record(&path, "invalid completed create receipt inventory").into());
        }
        if receipt.intent.object_id != object.id {
            continue;
        }
        if found.is_some()
            || receipt.outcome != Outcome::Created
            || Path::new(&receipt.intent.request.path) != selected
            || !object.versions.contains(&receipt.intent.version_id)
        {
            return Err(invalid().into());
        }
        verify_authority(root, state, &receipt.intent, true)
            .map_err(|error| invalid_record(&path, error.to_string()))?;
        let version_path = Path::new(VERSION_RECORDS_DIRECTORY)
            .join(format!("{}.json", receipt.intent.version_id));
        let version_bytes =
            read(&version_path, MAX_CAPTURE_PROJECTION_RECORD_BYTES)?.ok_or_else(invalid)?;
        let version: LocalVersionRecord = serde_json::from_slice(&version_bytes)
            .map_err(|error| FolderbaseError::json(&version_path, error))?;
        if version != receipt.intent.version() {
            return Err(invalid_record(
                &version_path,
                "original create Version differs from its receipt",
            )
            .into());
        }
        found = Some(CreatedObjectClaim {
            intent: receipt.intent,
            receipt: path,
            encoded,
            names: names.clone(),
        });
    }
    let proof = found.ok_or_else(invalid)?;
    proof.verify(root, state)?;
    Ok(proof)
}

/// Create one absent, non-executable regular file under an existing safe parent.
///
/// Requires a canonical operation UUID persisted by the caller, an initialized
/// root and same-build cooperative writers. An exact completed retry returns
/// the original result without touching later edits or deletion. Other pending
/// work and migration metadata are refused rather than implicitly recovered.
pub fn create_workspace_file(
    root: impl AsRef<Path>,
    path: impl AsRef<Path>,
    operation_id: &str,
    bytes: &[u8],
) -> CreateResult<WorkspaceCreateResult> {
    create_with_checkpoint(
        root.as_ref(),
        path.as_ref(),
        operation_id,
        bytes,
        |_phase| {
            // Debug-only process-interruption seam; no release behavior.
            #[cfg(debug_assertions)]
            if std::env::var("FOLDERBASE_TEST_EXIT_AFTER_CREATE_CHECKPOINT").as_deref()
                == Ok(_phase.name())
            {
                std::process::exit(86);
            }
            Ok(())
        },
    )
}

fn create_with_checkpoint(
    root: &Path,
    path: &Path,
    operation_id: &str,
    bytes: &[u8],
    mut checkpoint: impl FnMut(Checkpoint) -> CreateResult<()>,
) -> CreateResult<WorkspaceCreateResult> {
    validate_operation_id(operation_id)?;
    if bytes.len() > MAX_WORKSPACE_CREATE_BYTES {
        return Err(WorkspaceCreateError::ContentTooLarge);
    }
    let request = Request {
        operation_id: operation_id.to_owned(),
        path: portable_path(path)?,
        content: ContentDigest {
            algorithm: "sha256".to_owned(),
            digest: digest_hex(&Sha256::digest(bytes)),
            bytes: bytes.len() as u64,
        },
    };
    let local = LocalVersionStore::open_read_only(root)?;
    let root = local.root();
    let attestation = attest_folderbase_root(root)?;
    let state = FolderbaseState::open(root)?;
    let _lock = LocalVersionStore::acquire_transaction_lock_file_for_create(root, &state)?;
    state.verify_still_attached()?;
    let mut active: Option<Intent> = read_record(&state, Path::new(ACTIVE_CREATE_PATH))?;
    if let Some(intent) = &active {
        intent.validate()?;
    }
    let receipt_path = receipt_path(operation_id);
    if let Some(receipt) = read_record::<Receipt>(&state, &receipt_path)? {
        receipt.intent.validate()?;
        if receipt.format != RECEIPT_FORMAT || receipt.intent.stage.is_none() {
            return Err(invalid_record(&receipt_path, "invalid create receipt").into());
        }
        if receipt.intent.request != request {
            return Err(WorkspaceCreateError::OperationConflict);
        }
        verify_authority(root, &state, &receipt.intent, true)?;
        state.sync_private_regular_and_parent(&receipt_path)?;
        if let Some(intent) = active.filter(|intent| intent.request.operation_id == operation_id) {
            if intent != receipt.intent {
                return Err(invalid_record(
                    ACTIVE_CREATE_PATH,
                    "create receipt differs from active intent",
                )
                .into());
            }
            finish_cleanup(&state, &intent, &mut checkpoint)?;
        }
        return outcome_result(&receipt, true);
    }
    if active
        .as_ref()
        .is_some_and(|intent| intent.request != request)
    {
        return Err(
            if active
                .as_ref()
                .is_some_and(|intent| intent.request.operation_id == operation_id)
            {
                WorkspaceCreateError::OperationConflict
            } else {
                WorkspaceCreateError::RecoveryRequired("another workspace create".to_owned())
            },
        );
    }
    ensure_other_work_idle(&state)?;
    if active.is_none() {
        let parent_identity_sha256 =
            state.create_parent_identity_sha256(Path::new(&request.path))?;
        if !state.workspace_path_is_absent(Path::new(&request.path))? {
            return Err(WorkspaceCreateError::DestinationOccupied(request.path));
        }
        verify_claimants(&local, &state, &request.path, None)?;
        LocalVersionStore::prepare_store_layout_in(&state)?;
        state.ensure_private_dir(Path::new(CREATE_DIRECTORY))?;
        state.ensure_private_dir(Path::new(RECEIPTS_DIRECTORY))?;
        if local.install_content_bytes_in(&state, bytes)? != request.content {
            return Err(invalid_record(CREATE_DIRECTORY, "create blob digest differs").into());
        }
        checkpoint(Checkpoint::BlobDurable)?;
        let intent = Intent {
            format: INTENT_FORMAT.to_owned(),
            request,
            folderbase_id: attestation.folderbase_id,
            root_instance_sha256: attestation.root_instance_sha256,
            manifest_sha256: attestation.manifest_sha256,
            state_identity_sha256: state.state_identity_sha256()?,
            parent_identity_sha256,
            object_id: ObjectId::new(),
            version_id: VersionId::new(),
            tracked_event_id: format!("event_{}", Uuid::now_v7()),
            captured_event_id: format!("event_{}", Uuid::now_v7()),
            created_at: Utc::now().to_rfc3339(),
            stage: None,
        };
        intent.validate()?;
        verify_authority(root, &state, &intent, false)?;
        publish_exact(&state, Path::new(ACTIVE_CREATE_PATH), &intent)?;
        checkpoint(Checkpoint::IntentDurable)?;
        active = Some(intent);
    }
    let mut intent = active.expect("active create was prepared");
    verify_authority(root, &state, &intent, false)?;
    verify_claimants(&local, &state, &intent.request.path, Some(&intent))?;
    let version = intent.version();
    local.validate_version_record(
        &version.id,
        &version,
        &local.version_record_path(&version.id),
    )?;
    state.verify_sha256_blob(
        Path::new(BLOBS_DIRECTORY),
        &version.content.digest,
        version.content.bytes,
    )?;
    local.install_or_verify_version_record_in(&state, &version)?;
    state.sync_private_regular_and_parent(&local.blob_relative_path(&version.content.digest))?;
    state.sync_private_regular_and_parent(&local.version_record_relative_path(&version.id))?;
    checkpoint(Checkpoint::VersionDurable)?;
    if let Some(expected) = &intent.stage {
        if state.private_regular_identity_sha256(&intent.stage())? != expected.identity_sha256 {
            return Err(invalid_record(intent.stage(), "create stage identity changed").into());
        }
    } else {
        state.ensure_private_dir(&intent.stage_directory())?;
        let prepared =
            state.private_directory_names(&intent.stage_directory(), MAX_PREPARED_STAGES + 1)?;
        if prepared.len() >= MAX_PREPARED_STAGES {
            return Err(WorkspaceCreateError::RetainedStageLimit);
        }
        // Never infer ownership of a pre-pin crash artifact from its bytes.
        let name = Uuid::now_v7().hyphenated().to_string();
        if prepared.iter().any(|entry| entry.to_str() == Some(&name)) {
            return Err(invalid_record(
                intent.stage_directory(),
                "new create stage name is occupied",
            )
            .into());
        }
        let path = intent.stage_directory().join(&name);
        let identity_sha256 = state.stage_create_blob(
            &local.blob_relative_path(&version.content.digest),
            &path,
            &version.content.digest,
            version.content.bytes,
        )?;
        checkpoint(Checkpoint::StageUnpinned)?;
        intent.stage = Some(OwnedStage {
            name,
            identity_sha256,
        });
        state.replace(
            Path::new(ACTIVE_CREATE_PATH),
            &json_bytes(Path::new(ACTIVE_CREATE_PATH), &intent)?,
        )?;
    }
    checkpoint(Checkpoint::StageDurable)?;
    verify_authority(root, &state, &intent, false)?;
    verify_claimants(&local, &state, &intent.request.path, Some(&intent))?;
    // The callback is a narrow test seam; preserve the error until the helper
    // completes its immediate post-link durability work.
    let mut callback_error = None;
    let publication = state.publish_workspace_restore_with_hook(
        &intent.stage(),
        Path::new(&intent.request.path),
        &version.content.digest,
        version.content.bytes,
        false,
        |linked| {
            if linked {
                callback_error = checkpoint(Checkpoint::FileLinked).err();
            }
        },
    );
    if let Some(error) = callback_error {
        return Err(error);
    }
    if let Err(FolderbaseError::WouldOverwrite(_)) = publication {
        let receipt = Receipt {
            format: RECEIPT_FORMAT.to_owned(),
            intent,
            outcome: Outcome::Conflicted,
        };
        publish_exact(&state, &receipt_path, &receipt)?;
        checkpoint(Checkpoint::ReceiptDurable)?;
        finish_cleanup(&state, &receipt.intent, &mut checkpoint)?;
        return outcome_result(&receipt, false);
    }
    publication?;
    checkpoint(Checkpoint::FileDurable)?;
    verify_authority(root, &state, &intent, false)?;
    state.verify_workspace_restore(
        &intent.stage(),
        Path::new(&intent.request.path),
        &version.content.digest,
        version.content.bytes,
        false,
    )?;
    verify_claimants(&local, &state, &intent.request.path, Some(&intent))?;
    let object = intent.object()?;
    publish_exact(
        &state,
        &local.object_record_relative_path(&object.id),
        &object,
    )?;
    local.write_local_file_identity_in(&state, &object.id, &root.join(&object.path))?;
    checkpoint(Checkpoint::ProjectionDurable)?;
    let events = intent.events()?;
    append_creation_events(&state, &events, &mut checkpoint)?;
    checkpoint(Checkpoint::JournalDurable)?;
    state.verify_workspace_restore(
        &intent.stage(),
        Path::new(&intent.request.path),
        &version.content.digest,
        version.content.bytes,
        false,
    )?;
    verify_authority(root, &state, &intent, false)?;
    let receipt = Receipt {
        format: RECEIPT_FORMAT.to_owned(),
        intent,
        outcome: Outcome::Created,
    };
    publish_exact(&state, &receipt_path, &receipt)?;
    checkpoint(Checkpoint::ReceiptDurable)?;
    finish_cleanup(&state, &receipt.intent, &mut checkpoint)?;
    outcome_result(&receipt, false)
}

fn finish_cleanup(
    state: &FolderbaseState,
    intent: &Intent,
    checkpoint: &mut impl FnMut(Checkpoint) -> CreateResult<()>,
) -> CreateResult<()> {
    let identity = &intent
        .stage
        .as_ref()
        .ok_or_else(|| {
            invalid_record(ACTIVE_CREATE_PATH, "completed create has no stage identity")
        })?
        .identity_sha256;
    state.retire_private_regular_stage_with_hook(&intent.stage(), identity, || {
        checkpoint(Checkpoint::StageQuarantined)
            .map_err(|error| invalid_record(intent.stage(), error.to_string()))
    })?;
    checkpoint(Checkpoint::StageRetired)?;
    state.remove_durable(Path::new(ACTIVE_CREATE_PATH))?;
    checkpoint(Checkpoint::IntentRetired)
}

fn outcome_result(receipt: &Receipt, replayed: bool) -> CreateResult<WorkspaceCreateResult> {
    match receipt.outcome {
        Outcome::Created => Ok(receipt.intent.result(replayed)),
        Outcome::Conflicted => Err(WorkspaceCreateError::DestinationOccupied(
            receipt.intent.request.path.clone(),
        )),
    }
}

fn ensure_other_work_idle(state: &FolderbaseState) -> CreateResult<()> {
    for path in [
        ".folderbase/transactions/protocol-upgrades/active.json",
        ".folderbase/transactions/folderbase-version-captures/active.json",
        ".folderbase/transactions/folderbase-version-restores/active.json",
        ".folderbase/transactions/folderbase-version-restores/cleanup.json",
        ".folderbase/reorganizations/active.json",
        ".folderbase/transactions/change-set/active.json",
    ] {
        if state
            .read_bounded_if_present(Path::new(path), MAX_READ_BYTES)?
            .is_some()
        {
            return Err(WorkspaceCreateError::RecoveryRequired(path.to_owned()));
        }
    }
    for name in
        state.private_directory_names_if_present(Path::new(TRANSACTIONS_DIRECTORY), MAX_OBJECTS)?
    {
        if name.to_str().is_none_or(|name| name.ends_with(".json")) {
            return Err(WorkspaceCreateError::RecoveryRequired(
                "local version transaction".to_owned(),
            ));
        }
    }
    if !state
        .private_directory_names_if_present(Path::new(".folderbase/migrations"), MAX_OBJECTS)?
        .is_empty()
    {
        return Err(WorkspaceCreateError::MigrationStateUnsupported);
    }
    if !state
        .private_directory_names_if_present(
            Path::new(HISTORY_TRANSFER_STAGING_DIRECTORY),
            MAX_OBJECTS,
        )?
        .is_empty()
    {
        return Err(WorkspaceCreateError::RecoveryRequired(
            "history transfer staging".to_owned(),
        ));
    }
    let mut transfer_bytes = 0_u64;
    for name in state.private_directory_names_if_present(
        Path::new(HISTORY_TRANSFER_INTENTS_DIRECTORY),
        MAX_OBJECTS,
    )? {
        let path = Path::new(HISTORY_TRANSFER_INTENTS_DIRECTORY).join(name);
        let encoded = state
            .read_bounded_if_present(&path, MAX_INTENT_BYTES)?
            .ok_or_else(|| invalid_record(&path, "history transfer disappeared"))?;
        transfer_bytes += encoded.len() as u64;
        if transfer_bytes > MAX_READ_BYTES {
            return Err(invalid_record(&path, "create transfer metadata limit exceeded").into());
        }
        let plan: HistoryTransferPlan = serde_json::from_slice(&encoded)
            .map_err(|error| FolderbaseError::json(&path, error))?;
        validate_history_transfer_plan(&plan, &path)?;
        if path.file_stem().and_then(|name| name.to_str()) != Some(plan.id.as_str()) {
            return Err(invalid_record(path, "history transfer ID differs from filename").into());
        }
        if matches!(
            plan.state,
            HistoryTransferState::Approved
                | HistoryTransferState::Applying
                | HistoryTransferState::DestinationVerified
                | HistoryTransferState::SourceReleased
        ) {
            return Err(WorkspaceCreateError::RecoveryRequired(
                "history transfer".to_owned(),
            ));
        }
    }
    verify_journal(state)
}

fn verify_journal(state: &FolderbaseState) -> CreateResult<()> {
    let path = Path::new(JOURNAL_PATH);
    if let Some(bytes) = state.read_bounded_if_present(path, MAX_READ_BYTES)? {
        let events = parse_journal_bytes(path, &bytes, false)?;
        let mut seen = BTreeMap::new();
        for event in &events {
            if let Some(prior) = seen.insert(&event.id, event)
                && prior != event
            {
                return Err(
                    invalid_record(path, "journal has conflicting duplicate event IDs").into(),
                );
            }
        }
    }
    Ok(())
}

/// Preserve the strict, bounded journal byte prefix. This create-only append
/// uses retained durable replacement, including replay with no missing events,
/// so creation never produces an in-place torn tail or skips the retry barrier.
fn append_creation_events(
    state: &FolderbaseState,
    intended: &[ObjectJournalEvent],
    checkpoint: &mut impl FnMut(Checkpoint) -> CreateResult<()>,
) -> CreateResult<()> {
    let path = Path::new(JOURNAL_PATH);
    let mut bytes = state
        .read_bounded_if_present(path, MAX_READ_BYTES)?
        .unwrap_or_default();
    let existing = parse_journal_bytes(path, &bytes, false)?;
    let mut ids = BTreeMap::new();
    for event in &existing {
        if let Some(prior) = ids.insert(event.id.as_str(), event)
            && prior != event
        {
            return Err(invalid_record(path, "journal has conflicting duplicate event IDs").into());
        }
    }
    for event in intended {
        validate_journal_event(event, path, 0)?;
        if let Some(prior) = ids.get(event.id.as_str()) {
            if **prior != *event {
                return Err(invalid_record(
                    path,
                    "create journal event ID was reused with different metadata",
                )
                .into());
            }
            continue;
        }
        if !bytes.is_empty() && !bytes.ends_with(b"\n") {
            bytes.push(b'\n');
        }
        serde_json::to_writer(&mut bytes, event)
            .map_err(|error| FolderbaseError::json(path, error))?;
        bytes.push(b'\n');
        if bytes.len() as u64 > MAX_READ_BYTES {
            return Err(invalid_record(path, "create journal byte limit exceeded").into());
        }
    }
    state.replace_with_before_publish(path, &bytes, || {
        checkpoint(Checkpoint::JournalStaged).map_err(std::io::Error::other)
    })?;
    Ok(())
}

fn verify_claimants(
    local: &LocalVersionStore,
    state: &FolderbaseState,
    selected: &str,
    allowed: Option<&Intent>,
) -> CreateResult<()> {
    let mut total = 0_u64;
    let mut observations = BTreeMap::new();
    let mut selected_records = Vec::new();
    let mut paths = WorkspacePathLookup::new(local.root())?;
    let mut names =
        state.private_directory_names_if_present(Path::new(OBJECTS_DIRECTORY), MAX_OBJECTS)?;
    names.sort();
    for name in &names {
        if name.to_str().is_none_or(|name| !name.ends_with(".json")) {
            continue;
        }
        let path = Path::new(OBJECTS_DIRECTORY).join(name);
        let bytes = state
            .read_bounded(&path, MAX_CAPTURE_PROJECTION_RECORD_BYTES)?
            .ok_or_else(|| invalid_record(&path, "Object record disappeared"))?;
        total += bytes.len() as u64;
        if total > MAX_READ_BYTES {
            return Err(
                invalid_record(OBJECTS_DIRECTORY, "create Object metadata limit exceeded").into(),
            );
        }
        observations.insert(
            path.clone(),
            (MAX_CAPTURE_PROJECTION_RECORD_BYTES, Some(bytes.clone())),
        );
        let record: LocalObjectRecord = serde_json::from_slice(&bytes)
            .map_err(|source| FolderbaseError::json(&path, source))?;
        record.id.validate(&path)?;
        if local.object_record_relative_path(&record.id) != path {
            return Err(invalid_record(path, "Object ID differs from filename").into());
        }
        let stored = safe_content_path(Path::new(&record.path))?;
        if allowed.is_some_and(|intent| record.id == intent.object_id) {
            if record != allowed.expect("checked intent").object()? {
                return Err(invalid_record(path, "create Object projection changed").into());
            }
        } else if object_path_matches(&mut paths, &stored, Path::new(selected), &path)? {
            selected_records.push((path, record));
        }
    }
    paths.finish()?;
    if !selected_records.is_empty() {
        let mut read = |path: &Path, maximum| {
            let bytes = path_ownership::read_metadata(state, path, maximum)?;
            if let Some((_, expected)) = observations.get(path) {
                if expected != &bytes {
                    return Err(invalid_record(path, "create ownership metadata changed"));
                }
            } else {
                total += bytes.as_ref().map_or(0, |bytes| bytes.len() as u64);
                if total > MAX_READ_BYTES {
                    return Err(invalid_record(
                        path,
                        "create ownership metadata exceeds 64 MiB",
                    ));
                }
                observations.insert(path.to_path_buf(), (maximum, bytes.clone()));
            }
            Ok::<_, FolderbaseError>(bytes)
        };
        let current = path_ownership::current_version(local.root(), state, &mut read)?;
        if current
            .bindings()
            .iter()
            .any(|binding| Path::new(binding.path()) == Path::new(selected))
        {
            return Err(WorkspaceCreateError::DestinationOccupied(
                selected.to_owned(),
            ));
        }
        let history = path_ownership::OwnershipHistory::load_with_export_anchor(
            state,
            current,
            &selected_records
                .iter()
                .map(|(_, object)| (PathBuf::from(selected), object.id.clone()))
                .collect::<Vec<_>>(),
            false,
            &mut read,
        )?;
        let folderbase_id = &history.current.folderbase_id();
        let mut versions = 0usize;
        for (path, record) in &selected_records {
            let last = history
                .retired(Path::new(selected), &record.id)
                .ok_or_else(|| WorkspaceCreateError::DestinationOccupied(selected.to_owned()))?;
            if Path::new(&record.path) != Path::new(selected)
                || record.schema != OBJECT_SCHEMA
                || record.object_type != "file"
                || !matches!(record.lifecycle.status.as_str(), "canonical" | "deleted")
                || !record.versions.iter().any(|id| id.as_str() == last)
            {
                return Err(invalid_record(
                    path,
                    "create refuses an invalid or aliased retired Object claim",
                )
                .into());
            }
            local.validate_object_record_membership(&record.id, record, path)?;
            let mut ids = std::collections::BTreeSet::new();
            for id in &record.versions {
                versions += 1;
                if versions > MAX_OBJECTS || !ids.insert(id) {
                    return Err(invalid_record(
                        path,
                        "retired Version list exceeds its bound or contains duplicates",
                    )
                    .into());
                }
                let version_path = local.version_record_relative_path(id);
                let encoded = read(&version_path, MAX_CAPTURE_PROJECTION_RECORD_BYTES)?
                    .ok_or_else(|| invalid_record(&version_path, "retired Version is missing"))?;
                let version: LocalVersionRecord = serde_json::from_slice(&encoded)
                    .map_err(|error| FolderbaseError::json(&version_path, error))?;
                local.validate_version_record(id, &version, &version_path)?;
                if version.object_id != record.id {
                    return Err(invalid_record(
                        &version_path,
                        "retired Version belongs to another Object",
                    )
                    .into());
                }
                if id == &record.current_version {
                    state.verify_sha256_blob(
                        Path::new(BLOBS_DIRECTORY),
                        &version.content.digest,
                        version.content.bytes,
                    )?;
                }
            }
            let outgoing =
                Path::new(HISTORY_TRANSFER_OUTGOING_DIRECTORY).join(format!("{}.json", record.id));
            if let Some(bytes) = read(&outgoing, MAX_CAPTURE_PROJECTION_RECORD_BYTES)? {
                validate_chunk_transfer_receipt_bytes(
                    &bytes,
                    &outgoing,
                    &record.id,
                    folderbase_id,
                )?;
            }
            let incoming =
                Path::new(HISTORY_TRANSFER_INCOMING_DIRECTORY).join(format!("{}.json", record.id));
            if let Some(bytes) = read(&incoming, MAX_CAPTURE_PROJECTION_RECORD_BYTES)? {
                let receipt: HistoryTransferReceipt = serde_json::from_slice(&bytes)
                    .map_err(|error| FolderbaseError::json(&incoming, error))?;
                validate_history_transfer_receipt(&receipt, &incoming)?;
                if receipt.object_id != record.id
                    || receipt.destination_folderbase_id != *folderbase_id
                    || !receipt
                        .version_ids
                        .iter()
                        .all(|id| record.versions.contains(id))
                {
                    return Err(invalid_record(
                        &incoming,
                        "retired Object transfer receipt disagrees",
                    )
                    .into());
                }
            }
        }
    }
    for (path, (maximum, expected)) in observations {
        if path_ownership::read_metadata(state, &path, maximum)? != expected {
            return Err(invalid_record(
                path,
                "create ownership metadata changed before publication",
            )
            .into());
        }
    }
    let mut final_names =
        state.private_directory_names_if_present(Path::new(OBJECTS_DIRECTORY), MAX_OBJECTS)?;
    final_names.sort();
    if final_names != names {
        return Err(invalid_record(OBJECTS_DIRECTORY, "create Object names changed").into());
    }
    state.verify_still_attached()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        InitializationOptions, initialize, plan_initialization, read_file_history,
        save_workspace_text,
    };
    use tempfile::{TempDir, tempdir};

    fn fixture() -> TempDir {
        let root = tempdir().unwrap();
        initialize(&plan_initialization(root.path(), InitializationOptions::default()).unwrap())
            .unwrap();
        fs::create_dir(root.path().join("tasks")).unwrap();
        fs::write(root.path().join("untouched.txt"), b"outside create").unwrap();
        root
    }

    fn id() -> String {
        Uuid::now_v7().to_string()
    }

    #[test]
    fn recreated_files_have_immediate_separate_history_and_cas_before_capture() {
        let root = fixture();
        let full = crate::FolderbaseVersionStore::open(root.path()).unwrap();
        let local = LocalVersionStore::open(root.path()).unwrap();
        let mut retired = Vec::new();
        let mut identities = std::collections::BTreeSet::new();
        for cycle in 0..3 {
            let content = format!("generation {cycle}");
            let created =
                create_workspace_file(root.path(), "tasks/task.txt", &id(), content.as_bytes())
                    .unwrap();
            assert!(identities.insert(created.object_id.clone()));
            let history = read_file_history(root.path(), "tasks/task.txt").unwrap();
            assert_eq!(history.object_id, Some(created.object_id.clone()));
            assert_eq!(history.versions.len(), 1);
            assert_eq!(history.versions[0].id, created.version_id);
            let edited = format!("app edit {cycle}");
            save_workspace_text(
                root.path(),
                "tasks/task.txt",
                &created.content.digest,
                &edited,
            )
            .unwrap();
            let before_capture = read_file_history(root.path(), "tasks/task.txt").unwrap();
            assert_eq!(before_capture.object_id, history.object_id);
            assert_eq!(before_capture.versions.len(), 2);
            full.seal_capture(full.plan_capture().unwrap()).unwrap();
            let captured = read_file_history(root.path(), "tasks/task.txt").unwrap();
            assert_eq!(captured.object_id, history.object_id);
            assert_eq!(&captured.versions[..2], &before_capture.versions);
            for (object_path, bytes) in &retired {
                assert_eq!(fs::read(object_path).unwrap(), *bytes);
            }
            local
                .restore_version(&created.version_id, format!("tasks/recovered-{cycle}.txt"))
                .unwrap();
            assert_eq!(
                fs::read(root.path().join(format!("tasks/recovered-{cycle}.txt"))).unwrap(),
                content.as_bytes()
            );
            fs::remove_file(root.path().join("tasks/task.txt")).unwrap();
            full.seal_capture(full.plan_capture().unwrap()).unwrap();
            let object_path = local.object_record_path(&created.object_id);
            retired.push((object_path.clone(), fs::read(object_path).unwrap()));
        }
    }

    fn recreate_before_capture() -> (TempDir, WorkspaceCreateResult) {
        let root = fixture();
        create_workspace_file(root.path(), "tasks/task.txt", &id(), b"old").unwrap();
        let full = crate::FolderbaseVersionStore::open(root.path()).unwrap();
        full.seal_capture(full.plan_capture().unwrap()).unwrap();
        fs::remove_file(root.path().join("tasks/task.txt")).unwrap();
        full.seal_capture(full.plan_capture().unwrap()).unwrap();
        let created = create_workspace_file(root.path(), "tasks/task.txt", &id(), b"new").unwrap();
        (root, created)
    }

    #[test]
    fn recreated_ownership_refuses_wrong_tampered_missing_and_copied_receipts() {
        for field in [
            "path", "object", "version", "content", "root", "state", "outcome", "stage", "missing",
            "copied",
        ] {
            let (root, created) = recreate_before_capture();
            let path = root.path().join(receipt_path(&created.operation_id));
            let mut receipt: Receipt = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
            match field {
                "path" => receipt.intent.request.path = "tasks/other.txt".into(),
                "object" => receipt.intent.object_id = ObjectId::new(),
                "version" => receipt.intent.version_id = VersionId::new(),
                "content" => receipt.intent.request.content.digest = "0".repeat(64),
                "root" => receipt.intent.root_instance_sha256 = "0".repeat(64),
                "state" => receipt.intent.state_identity_sha256 = "0".repeat(64),
                "outcome" => receipt.outcome = Outcome::Conflicted,
                "stage" => receipt.intent.stage = None,
                "missing" => {}
                "copied" => {
                    let (foreign, foreign_created) = recreate_before_capture();
                    let foreign_receipt: Receipt = serde_json::from_slice(
                        &fs::read(
                            foreign
                                .path()
                                .join(receipt_path(&foreign_created.operation_id)),
                        )
                        .unwrap(),
                    )
                    .unwrap();
                    receipt.intent.root_instance_sha256 =
                        foreign_receipt.intent.root_instance_sha256;
                    receipt.intent.state_identity_sha256 =
                        foreign_receipt.intent.state_identity_sha256;
                }
                _ => unreachable!(),
            }
            if field == "missing" {
                fs::remove_file(&path).unwrap();
            } else {
                fs::write(&path, json_bytes(&path, &receipt).unwrap()).unwrap();
            }
            assert!(
                read_file_history(root.path(), "tasks/task.txt").is_err(),
                "history accepted {field}"
            );
            assert!(
                save_workspace_text(
                    root.path(),
                    "tasks/task.txt",
                    &created.content.digest,
                    "unsafe edit"
                )
                .is_err(),
                "save accepted {field}"
            );
            assert_eq!(
                fs::read(root.path().join("tasks/task.txt")).unwrap(),
                b"new"
            );
        }
    }

    #[test]
    fn recreated_receipt_proves_identity_while_native_bytes_can_change() {
        let (root, created) = recreate_before_capture();
        let original = read_file_history(root.path(), "tasks/task.txt").unwrap();
        fs::write(root.path().join("tasks/task.txt"), b"native edit").unwrap();
        assert_eq!(
            read_file_history(root.path(), "tasks/task.txt").unwrap(),
            original
        );
        let current = crate::read_workspace_text(root.path(), "tasks/task.txt").unwrap();
        save_workspace_text(root.path(), "tasks/task.txt", &current.sha256, "app edit").unwrap();
        let history = read_file_history(root.path(), "tasks/task.txt").unwrap();
        assert_eq!(history.object_id, Some(created.object_id));
        assert_eq!(history.versions.len(), 3);
        assert_eq!(history.versions[0].id, created.version_id);
    }

    #[test]
    fn retired_file_and_stale_live_directory_binding_refuse_creation_until_captured() {
        let root = fixture();
        let old = create_workspace_file(root.path(), "tasks/task.txt", &id(), b"old").unwrap();
        let full = crate::FolderbaseVersionStore::open(root.path()).unwrap();
        full.seal_capture(full.plan_capture().unwrap()).unwrap();
        fs::remove_file(root.path().join("tasks/task.txt")).unwrap();
        fs::create_dir(root.path().join("tasks/task.txt")).unwrap();
        full.seal_capture(full.plan_capture().unwrap()).unwrap();
        fs::remove_dir(root.path().join("tasks/task.txt")).unwrap();
        let object_path = root
            .path()
            .join(format!("{OBJECTS_DIRECTORY}/{}.json", old.object_id));
        let object = fs::read(&object_path).unwrap();
        assert!(matches!(
            create_workspace_file(root.path(), "tasks/task.txt", &id(), b"new"),
            Err(WorkspaceCreateError::DestinationOccupied(_))
        ));
        assert!(!root.path().join("tasks/task.txt").exists());
        assert!(!root.path().join(ACTIVE_CREATE_PATH).exists());
        assert_eq!(fs::read(&object_path).unwrap(), object);
        full.seal_capture(full.plan_capture().unwrap()).unwrap();
        let new = create_workspace_file(root.path(), "tasks/task.txt", &id(), b"new").unwrap();
        assert_ne!(old.object_id, new.object_id);
        assert_eq!(
            read_file_history(root.path(), "tasks/task.txt")
                .unwrap()
                .object_id,
            Some(new.object_id)
        );
        assert_eq!(fs::read(object_path).unwrap(), object);
    }

    #[test]
    fn retired_claim_corruption_at_stage_boundary_refuses_before_visible_creation() {
        let root = fixture();
        let old = create_workspace_file(root.path(), "tasks/task.txt", &id(), b"old").unwrap();
        let full = crate::FolderbaseVersionStore::open(root.path()).unwrap();
        full.seal_capture(full.plan_capture().unwrap()).unwrap();
        fs::remove_file(root.path().join("tasks/task.txt")).unwrap();
        full.seal_capture(full.plan_capture().unwrap()).unwrap();
        let object = root
            .path()
            .join(format!("{OBJECTS_DIRECTORY}/{}.json", old.object_id));
        let mut reached = false;
        let result = create_with_checkpoint(
            root.path(),
            Path::new("tasks/task.txt"),
            &id(),
            b"new",
            |phase| {
                if phase == Checkpoint::StageDurable {
                    reached = true;
                    fs::write(&object, b"damaged metadata").unwrap();
                }
                Ok(())
            },
        );
        assert!(reached);
        assert!(result.is_err());
        assert!(!root.path().join("tasks/task.txt").exists());
        assert_eq!(fs::read(object).unwrap(), b"damaged metadata");
    }

    fn interrupt(phase: Checkpoint) -> CreateResult<()> {
        Err(invalid_record("test-checkpoint", format!("interrupted at {phase:?}")).into())
    }

    fn create_until(root: &Path, operation: &str, phase: Checkpoint) {
        let mut reached = false;
        let result = create_with_checkpoint(
            root,
            Path::new("tasks/new.bin"),
            operation,
            b"created\0bytes\xff",
            |at| {
                if at == phase {
                    reached = true;
                    interrupt(at)
                } else {
                    Ok(())
                }
            },
        );
        assert!(reached, "checkpoint {phase:?} was not reached: {result:?}");
        assert!(result.unwrap_err().to_string().contains("test-checkpoint"));
        assert_eq!(
            fs::read(root.join("untouched.txt")).unwrap(),
            b"outside create"
        );
    }

    #[test]
    fn creates_exact_binary_and_empty_files_with_stable_history_and_receipts() {
        let root = fixture();
        for (path, bytes) in [
            ("tasks/zero.bin", b"".as_slice()),
            ("tasks/日本語.bin", b"\0\xffbinary\r\n".as_slice()),
        ] {
            let operation = id();
            let created = create_workspace_file(root.path(), path, &operation, bytes).unwrap();
            assert_eq!(fs::read(root.path().join(path)).unwrap(), bytes);
            let history = read_file_history(root.path(), path).unwrap();
            assert_eq!(history.object_id.as_ref(), Some(&created.object_id));
            assert_eq!(history.current_version.as_ref(), Some(&created.version_id));
            assert_eq!(history.versions.len(), 1);
            let repeated = create_workspace_file(root.path(), path, &operation, bytes).unwrap();
            assert!(repeated.replayed);
            assert_eq!(
                repeated,
                WorkspaceCreateResult {
                    replayed: true,
                    ..created
                }
            );
            assert!(!root.path().join(ACTIVE_CREATE_PATH).exists());
        }
    }

    #[test]
    fn retries_every_durable_phase_with_original_identity_and_no_duplicate_events() {
        for phase in [
            Checkpoint::IntentDurable,
            Checkpoint::VersionDurable,
            Checkpoint::StageDurable,
            Checkpoint::FileLinked,
            Checkpoint::FileDurable,
            Checkpoint::ProjectionDurable,
            Checkpoint::JournalStaged,
            Checkpoint::JournalDurable,
            Checkpoint::ReceiptDurable,
            Checkpoint::StageQuarantined,
            Checkpoint::StageRetired,
            Checkpoint::IntentRetired,
        ] {
            let root = fixture();
            let operation = id();
            create_until(root.path(), &operation, phase);
            let intent = fs::read(root.path().join(ACTIVE_CREATE_PATH))
                .ok()
                .map(|bytes| serde_json::from_slice::<Intent>(&bytes).unwrap());
            let created = create_workspace_file(
                root.path(),
                "tasks/new.bin",
                &operation,
                b"created\0bytes\xff",
            )
            .unwrap();
            if let Some(intent) = intent {
                assert_eq!(created.object_id, intent.object_id);
                assert_eq!(created.version_id, intent.version_id);
            }
            assert_eq!(
                fs::read(root.path().join("tasks/new.bin")).unwrap(),
                b"created\0bytes\xff"
            );
            let history = read_file_history(root.path(), "tasks/new.bin").unwrap();
            assert_eq!(history.versions.len(), 1, "{phase:?}");
            let events = LocalVersionStore::open(root.path())
                .unwrap()
                .journal_events()
                .unwrap();
            assert_eq!(
                events
                    .iter()
                    .filter(|event| event.object_id == created.object_id)
                    .count(),
                2,
                "{phase:?}"
            );
            assert!(!root.path().join(ACTIVE_CREATE_PATH).exists());
        }
    }

    #[test]
    fn pre_intent_interruption_leaves_only_immutable_orphans_and_no_busy_marker() {
        let root = fixture();
        let operation = id();
        create_until(root.path(), &operation, Checkpoint::BlobDurable);
        assert!(!root.path().join("tasks/new.bin").exists());
        assert!(!root.path().join(ACTIVE_CREATE_PATH).exists());
        assert_eq!(
            fs::read_dir(root.path().join(BLOBS_DIRECTORY))
                .unwrap()
                .count(),
            1
        );
        LocalVersionStore::open(root.path()).unwrap();
        create_workspace_file(
            root.path(),
            "tasks/new.bin",
            &operation,
            b"created\0bytes\xff",
        )
        .unwrap();
    }

    #[test]
    fn unpinned_stages_are_preserved_and_never_reused_by_matching_content() {
        let root = fixture();
        let operation = id();
        create_until(root.path(), &operation, Checkpoint::StageUnpinned);
        let intent: Intent =
            serde_json::from_slice(&fs::read(root.path().join(ACTIVE_CREATE_PATH)).unwrap())
                .unwrap();
        assert!(intent.stage.is_none());
        let directory = root.path().join(intent.stage_directory());
        let orphan = fs::read_dir(&directory)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let before = fs::read(&orphan).unwrap();
        let created =
            create_workspace_file(root.path(), "tasks/new.bin", &operation, &before).unwrap();
        assert_eq!(fs::read(&orphan).unwrap(), before);
        assert_eq!(fs::read(root.path().join("tasks/new.bin")).unwrap(), before);
        let state = FolderbaseState::open(root.path()).unwrap();
        assert!(
            state
                .workspace_restore_identity_sha256(
                    orphan.strip_prefix(root.path()).unwrap(),
                    Path::new("tasks/new.bin")
                )
                .is_err()
        );
        let receipt: Receipt = read_record(&state, &receipt_path(&operation))
            .unwrap()
            .unwrap();
        assert_ne!(receipt.intent.stage().file_name(), orphan.file_name());
        assert_eq!(
            read_file_history(root.path(), "tasks/new.bin")
                .unwrap()
                .object_id,
            Some(created.object_id)
        );
    }

    #[test]
    fn repeated_unpinned_interruptions_are_bounded_without_deleting_artifacts() {
        let root = fixture();
        let operation = id();
        for _ in 0..MAX_PREPARED_STAGES {
            create_until(root.path(), &operation, Checkpoint::StageUnpinned);
        }
        let result = create_workspace_file(
            root.path(),
            "tasks/new.bin",
            &operation,
            b"created\0bytes\xff",
        );
        assert!(result.unwrap_err().to_string().contains("stage limit"));
        let directory = root
            .path()
            .join(CREATE_DIRECTORY)
            .join("stages")
            .join(operation);
        assert_eq!(
            fs::read_dir(directory).unwrap().count(),
            MAX_PREPARED_STAGES
        );
        assert!(!root.path().join("tasks/new.bin").exists());
    }

    #[test]
    fn completed_retry_and_cleanup_preserve_later_native_edits_or_deletion() {
        for remove in [false, true] {
            let root = fixture();
            let operation = id();
            create_until(root.path(), &operation, Checkpoint::ReceiptDurable);
            let destination = root.path().join("tasks/new.bin");
            if remove {
                fs::remove_file(&destination).unwrap();
            } else {
                fs::write(&destination, b"native editor owns this now").unwrap();
            }
            let result = create_workspace_file(
                root.path(),
                "tasks/new.bin",
                &operation,
                b"created\0bytes\xff",
            )
            .unwrap();
            assert!(result.replayed);
            assert!(!root.path().join(ACTIVE_CREATE_PATH).exists());
            if remove {
                assert!(!destination.exists());
            } else {
                assert_eq!(
                    fs::read(destination).unwrap(),
                    b"native editor owns this now"
                );
            }
        }
    }

    #[test]
    fn occupied_targets_and_changed_requests_are_never_overwritten() {
        let root = fixture();
        let operation = id();
        fs::write(root.path().join("tasks/existing.bin"), b"same").unwrap();
        assert!(matches!(
            create_workspace_file(root.path(), "tasks/existing.bin", &operation, b"same"),
            Err(WorkspaceCreateError::DestinationOccupied(_))
        ));
        create_workspace_file(root.path(), "tasks/new.bin", &operation, b"first").unwrap();
        assert!(matches!(
            create_workspace_file(root.path(), "tasks/other.bin", &operation, b"first"),
            Err(WorkspaceCreateError::OperationConflict)
        ));
        assert!(matches!(
            create_workspace_file(root.path(), "tasks/new.bin", &operation, b"other"),
            Err(WorkspaceCreateError::OperationConflict)
        ));
        assert_eq!(
            fs::read(root.path().join("tasks/new.bin")).unwrap(),
            b"first"
        );
    }

    #[test]
    fn competing_target_after_intent_gets_terminal_conflict_and_releases_coordinator() {
        let root = fixture();
        let operation = id();
        create_until(root.path(), &operation, Checkpoint::StageDurable);
        fs::write(root.path().join("tasks/new.bin"), b"created\0bytes\xff").unwrap();
        assert!(matches!(
            create_workspace_file(
                root.path(),
                "tasks/new.bin",
                &operation,
                b"created\0bytes\xff"
            ),
            Err(WorkspaceCreateError::DestinationOccupied(_))
        ));
        assert!(!root.path().join(ACTIVE_CREATE_PATH).exists());
        assert_eq!(
            fs::read(root.path().join("tasks/new.bin")).unwrap(),
            b"created\0bytes\xff"
        );
        assert!(
            read_file_history(root.path(), "tasks/new.bin")
                .unwrap()
                .versions
                .is_empty()
        );
        create_workspace_file(root.path(), "tasks/another.bin", &id(), b"safe").unwrap();
    }

    #[test]
    fn pending_create_blocks_other_writers_and_read_only_history() {
        let root = fixture();
        let operation = id();
        create_until(root.path(), &operation, Checkpoint::StageDurable);
        assert!(matches!(
            LocalVersionStore::open(root.path()),
            Err(FolderbaseError::RecoveryRequired { .. })
        ));
        assert!(matches!(
            read_file_history(root.path(), "untouched.txt"),
            Err(FileHistoryError::RecoveryRequired { .. })
        ));
        assert!(matches!(
            create_workspace_file(root.path(), "tasks/another.bin", &id(), b"safe"),
            Err(WorkspaceCreateError::RecoveryRequired(_))
        ));
        assert_eq!(
            fs::read(root.path().join("untouched.txt")).unwrap(),
            b"outside create"
        );
    }

    #[test]
    fn corrupt_version_refuses_before_file_publication_and_preserves_evidence() {
        let root = fixture();
        let operation = id();
        create_until(root.path(), &operation, Checkpoint::VersionDurable);
        let intent: Intent =
            serde_json::from_slice(&fs::read(root.path().join(ACTIVE_CREATE_PATH)).unwrap())
                .unwrap();
        let record = root
            .path()
            .join(VERSION_RECORDS_DIRECTORY)
            .join(format!("{}.json", intent.version_id));
        fs::write(&record, b"foreign record").unwrap();
        assert!(
            create_workspace_file(
                root.path(),
                "tasks/new.bin",
                &operation,
                b"created\0bytes\xff"
            )
            .is_err()
        );
        assert!(!root.path().join("tasks/new.bin").exists());
        assert_eq!(fs::read(record).unwrap(), b"foreign record");
    }

    #[test]
    fn created_text_supports_cas_and_original_receipt_remains_historical() {
        let root = fixture();
        let operation = id();
        let original =
            create_workspace_file(root.path(), "tasks/note.md", &operation, b"first").unwrap();
        let saved = save_workspace_text(
            root.path(),
            "tasks/note.md",
            &original.content.digest,
            "second",
        )
        .unwrap();
        assert_eq!(saved.object_id, original.object_id);
        let replay =
            create_workspace_file(root.path(), "tasks/note.md", &operation, b"first").unwrap();
        assert_eq!(replay.version_id, original.version_id);
        assert_eq!(
            fs::read(root.path().join("tasks/note.md")).unwrap(),
            b"second"
        );
        assert_eq!(
            read_file_history(root.path(), "tasks/note.md")
                .unwrap()
                .versions
                .len(),
            2
        );
    }
    #[test]
    fn replacement_parent_stage_and_state_refuse_without_mutating_foreign_entries() {
        for changed in ["parent", "stage", "state"] {
            let root = fixture();
            let operation = id();
            create_until(root.path(), &operation, Checkpoint::StageDurable);
            let intent: Intent =
                serde_json::from_slice(&fs::read(root.path().join(ACTIVE_CREATE_PATH)).unwrap())
                    .unwrap();
            let (original, saved) = match changed {
                "parent" => (root.path().join("tasks"), root.path().join("saved-tasks")),
                "state" => (
                    root.path().join(".folderbase"),
                    root.path().join("saved-state"),
                ),
                _ => (
                    root.path().join(intent.stage()),
                    root.path().join("saved-stage"),
                ),
            };
            fs::rename(&original, &saved).unwrap();
            if changed == "stage" {
                fs::write(&original, b"created\0bytes\xff").unwrap();
            } else if changed == "state" {
                copy_tree(&saved, &original);
            } else {
                fs::create_dir(&original).unwrap();
                fs::write(original.join("sentinel"), b"foreign parent").unwrap();
            }
            assert!(
                create_workspace_file(
                    root.path(),
                    "tasks/new.bin",
                    &operation,
                    b"created\0bytes\xff"
                )
                .is_err(),
                "{changed}"
            );
            assert!(!root.path().join("tasks/new.bin").exists());
            assert!(saved.exists());
            if changed == "parent" {
                assert_eq!(
                    fs::read(original.join("sentinel")).unwrap(),
                    b"foreign parent"
                );
            }
            if changed == "stage" {
                assert_eq!(fs::read(original).unwrap(), b"created\0bytes\xff");
            }
        }
    }

    fn copy_tree(source: &Path, destination: &Path) {
        fs::create_dir(destination).unwrap();
        for entry in fs::read_dir(source).unwrap() {
            let entry = entry.unwrap();
            let target = destination.join(entry.file_name());
            if entry.file_type().unwrap().is_dir() {
                copy_tree(&entry.path(), &target);
            } else {
                fs::copy(entry.path(), target).unwrap();
            }
        }
    }

    #[test]
    fn copied_completed_receipt_does_not_authorize_a_different_physical_root() {
        let root = fixture();
        let operation = id();
        create_workspace_file(root.path(), "tasks/new.bin", &operation, b"first").unwrap();
        let owner = tempdir().unwrap();
        let copied = owner.path().join("copy");
        copy_tree(root.path(), &copied);
        assert!(matches!(
            create_workspace_file(&copied, "tasks/new.bin", &operation, b"first"),
            Err(WorkspaceCreateError::AuthorityChanged)
        ));
        assert_eq!(fs::read(copied.join("tasks/new.bin")).unwrap(), b"first");
    }

    #[test]
    fn safe_parent_reserved_path_and_case_alias_refusals_do_not_create_files() {
        let root = fixture();
        fs::write(root.path().join("tasks/Case.txt"), b"existing").unwrap();
        for path in [
            "missing/new",
            "../outside",
            ".folderbase/other",
            ".git/new",
            ".folderbaseignore",
            "tasks/case.txt",
            "TASKS/new",
        ] {
            assert!(
                create_workspace_file(root.path(), path, &id(), b"new").is_err(),
                "{path}"
            );
        }
        let nested = root.path().join("tasks/nested");
        let nested_source = fixture();
        fs::rename(nested_source.path(), &nested).unwrap();
        assert!(create_workspace_file(root.path(), "tasks/nested/new", &id(), b"new").is_err());
        assert_eq!(
            fs::read(root.path().join("tasks/Case.txt")).unwrap(),
            b"existing"
        );
        assert!(!root.path().join("missing").exists());
        assert!(!root.path().join(ACTIVE_CREATE_PATH).exists());
    }

    #[cfg(unix)]
    #[test]
    fn symlink_destination_or_parent_is_never_followed() {
        use std::os::unix::fs::symlink;
        let root = fixture();
        let outside = tempdir().unwrap();
        symlink(outside.path(), root.path().join("linked")).unwrap();
        symlink(
            outside.path().join("absent"),
            root.path().join("tasks/new.bin"),
        )
        .unwrap();
        for path in ["linked/new", "tasks/new.bin"] {
            assert!(create_workspace_file(root.path(), path, &id(), b"new").is_err());
        }
        assert_eq!(fs::read_dir(outside.path()).unwrap().count(), 0);
    }

    #[test]
    fn journal_event_collision_refuses_unchanged() {
        let root = fixture();
        let operation = id();
        create_until(root.path(), &operation, Checkpoint::ProjectionDurable);
        let intent: Intent =
            serde_json::from_slice(&fs::read(root.path().join(ACTIVE_CREATE_PATH)).unwrap())
                .unwrap();
        let mut event = intent.events().unwrap().remove(0);
        event.path = "untouched.txt".to_owned();
        let mut encoded = serde_json::to_vec(&event).unwrap();
        encoded.push(b'\n');
        fs::write(root.path().join(JOURNAL_PATH), &encoded).unwrap();
        assert!(
            create_workspace_file(
                root.path(),
                "tasks/new.bin",
                &operation,
                b"created\0bytes\xff"
            )
            .is_err()
        );
        assert_eq!(fs::read(root.path().join(JOURNAL_PATH)).unwrap(), encoded);
        assert_eq!(
            fs::read(root.path().join("tasks/new.bin")).unwrap(),
            b"created\0bytes\xff"
        );
    }
    #[test]
    fn journal_replacement_preserves_exact_prefix_and_replay_does_not_duplicate_events() {
        let root = fixture();
        let local = LocalVersionStore::open(root.path()).unwrap();
        local.capture_file("untouched.txt").unwrap();
        let path = root.path().join(JOURNAL_PATH);
        let initial = fs::read(&path).unwrap();
        // Valid JSON without a final newline needs a separator, not dropped bytes.
        let prefix = initial.strip_suffix(b"\n").unwrap().to_vec();
        fs::write(&path, &prefix).unwrap();
        let operation = id();
        create_until(root.path(), &operation, Checkpoint::JournalStaged);
        assert_eq!(fs::read(&path).unwrap(), prefix);
        create_until(root.path(), &operation, Checkpoint::JournalDurable);
        let written = fs::read(&path).unwrap();
        assert!(written.starts_with(&prefix));
        let events = parse_journal_bytes(&path, &written, false).unwrap();
        assert_eq!(events.len(), 4);
        let result = create_workspace_file(
            root.path(),
            "tasks/new.bin",
            &operation,
            b"created\0bytes\xff",
        )
        .unwrap();
        assert_eq!(fs::read(&path).unwrap(), written);
        assert_eq!(events[3].version_id.as_ref(), Some(&result.version_id));
        let replay = create_workspace_file(
            root.path(),
            "tasks/new.bin",
            &operation,
            b"created\0bytes\xff",
        )
        .unwrap();
        assert!(replay.replayed);
        assert_eq!(fs::read(&path).unwrap(), written);
    }

    #[test]
    fn partial_journal_and_conflicting_duplicate_ids_are_refused_without_repair() {
        for damage in ["partial", "duplicate"] {
            let root = fixture();
            let local = LocalVersionStore::open(root.path()).unwrap();
            local.capture_file("untouched.txt").unwrap();
            let operation = id();
            create_until(root.path(), &operation, Checkpoint::ProjectionDurable);
            let path = root.path().join(JOURNAL_PATH);
            let mut journal = fs::read(&path).unwrap();
            if damage == "partial" {
                journal.extend_from_slice(b"{\"id\":\"event_partial");
            } else {
                let mut event = parse_journal_bytes(&path, &journal, false)
                    .unwrap()
                    .remove(0);
                event.path = "tasks/another.bin".into();
                journal.extend(serde_json::to_vec(&event).unwrap());
                journal.push(b'\n');
            }
            fs::write(&path, &journal).unwrap();
            let intent = fs::read(root.path().join(ACTIVE_CREATE_PATH)).unwrap();
            assert!(
                create_workspace_file(
                    root.path(),
                    "tasks/new.bin",
                    &operation,
                    b"created\0bytes\xff"
                )
                .is_err(),
                "{damage}"
            );
            assert_eq!(fs::read(&path).unwrap(), journal);
            assert_eq!(
                fs::read(root.path().join(ACTIVE_CREATE_PATH)).unwrap(),
                intent
            );
            assert_eq!(
                fs::read(root.path().join("tasks/new.bin")).unwrap(),
                b"created\0bytes\xff"
            );
            assert!(!root.path().join(receipt_path(&operation)).exists());
            assert_eq!(
                fs::read_dir(root.path().join(JOURNAL_QUARANTINE_DIRECTORY))
                    .unwrap()
                    .count(),
                0
            );
        }
    }

    #[test]
    fn input_bounds_and_malformed_claims_refuse_before_creation_intent() {
        let root = fixture();
        assert!(matches!(
            create_workspace_file(root.path(), "tasks/a.bin", "not-an-id", b""),
            Err(WorkspaceCreateError::InvalidOperationId)
        ));
        assert!(matches!(
            create_workspace_file(
                root.path(),
                "tasks/a.bin",
                &id(),
                &vec![0; MAX_WORKSPACE_CREATE_BYTES + 1]
            ),
            Err(WorkspaceCreateError::ContentTooLarge)
        ));
        assert!(!root.path().join(ACTIVE_CREATE_PATH).exists());
        let local = LocalVersionStore::open(root.path()).unwrap();
        let record = local.capture_file("untouched.txt").unwrap();
        let object_path = local.object_record_path(&record.object.id);
        fs::write(&object_path, b"{malformed}").unwrap();
        assert!(create_workspace_file(root.path(), "tasks/a.bin", &id(), b"").is_err());
        assert_eq!(fs::read(&object_path).unwrap(), b"{malformed}");
        assert!(!root.path().join(ACTIVE_CREATE_PATH).exists());
        assert!(!root.path().join("tasks/a.bin").exists());
    }

    #[test]
    fn process_interruption_child() {
        let Some(root) = std::env::var_os("FOLDERBASE_CREATE_CHILD_ROOT") else {
            return;
        };
        let operation = std::env::var("FOLDERBASE_CREATE_CHILD_OPERATION").unwrap();
        create_workspace_file(
            Path::new(&root),
            "tasks/new.bin",
            &operation,
            b"created\0bytes\xff",
        )
        .unwrap();
        panic!("requested checkpoint was not reached");
    }

    #[cfg(debug_assertions)]
    #[test]
    fn actual_process_exit_at_every_boundary_recovers_the_exact_original_operation() {
        for phase in [
            Checkpoint::BlobDurable,
            Checkpoint::IntentDurable,
            Checkpoint::VersionDurable,
            Checkpoint::StageUnpinned,
            Checkpoint::StageDurable,
            Checkpoint::FileLinked,
            Checkpoint::FileDurable,
            Checkpoint::ProjectionDurable,
            Checkpoint::JournalStaged,
            Checkpoint::JournalDurable,
            Checkpoint::ReceiptDurable,
            Checkpoint::StageQuarantined,
            Checkpoint::StageRetired,
            Checkpoint::IntentRetired,
        ] {
            let root = fixture();
            let operation = id();
            let child = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "local_versions::file_create::tests::process_interruption_child",
                    "--nocapture",
                ])
                .env("FOLDERBASE_CREATE_CHILD_ROOT", root.path())
                .env("FOLDERBASE_CREATE_CHILD_OPERATION", &operation)
                .env("FOLDERBASE_TEST_EXIT_AFTER_CREATE_CHECKPOINT", phase.name())
                .output()
                .unwrap();
            assert_eq!(
                child.status.code(),
                Some(86),
                "{phase:?}: {}",
                String::from_utf8_lossy(&child.stderr)
            );
            let visible = matches!(
                phase,
                Checkpoint::FileLinked
                    | Checkpoint::FileDurable
                    | Checkpoint::ProjectionDurable
                    | Checkpoint::JournalStaged
                    | Checkpoint::JournalDurable
                    | Checkpoint::ReceiptDurable
                    | Checkpoint::StageQuarantined
                    | Checkpoint::StageRetired
                    | Checkpoint::IntentRetired
            );
            assert_eq!(
                root.path().join("tasks/new.bin").exists(),
                visible,
                "{phase:?}"
            );
            assert_eq!(
                root.path().join(ACTIVE_CREATE_PATH).exists(),
                !matches!(phase, Checkpoint::BlobDurable | Checkpoint::IntentRetired),
                "{phase:?}"
            );
            assert_eq!(
                root.path().join(receipt_path(&operation)).exists(),
                matches!(
                    phase,
                    Checkpoint::ReceiptDurable
                        | Checkpoint::StageQuarantined
                        | Checkpoint::StageRetired
                        | Checkpoint::IntentRetired
                ),
                "{phase:?}"
            );
            let before: Option<Intent> = fs::read(root.path().join(ACTIVE_CREATE_PATH))
                .ok()
                .map(|bytes| serde_json::from_slice(&bytes).unwrap());
            assert_eq!(
                fs::read(root.path().join("untouched.txt")).unwrap(),
                b"outside create"
            );
            let result = create_workspace_file(
                root.path(),
                "tasks/new.bin",
                &operation,
                b"created\0bytes\xff",
            )
            .unwrap();
            if let Some(intent) = before {
                assert_eq!(result.object_id, intent.object_id);
                assert_eq!(result.version_id, intent.version_id);
            }
            assert_eq!(
                fs::read(root.path().join("tasks/new.bin")).unwrap(),
                b"created\0bytes\xff"
            );
            assert_eq!(
                read_file_history(root.path(), "tasks/new.bin")
                    .unwrap()
                    .versions
                    .len(),
                1
            );
            assert!(!root.path().join(ACTIVE_CREATE_PATH).exists());
        }
    }
}

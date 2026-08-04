//! Least-authority ordinary-folder checkouts and immutable Change Sets.
//!
//! The public records in this module are the runtime for the optional
//! `folderbase.change-set@0.1.0` capability. A checkout is deliberately not a
//! Folderbase root: it carries one closed projection receipt and ordinary
//! files. Trusted projection-to-Version authority remains private to the
//! source Folderbase.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Component, Path, PathBuf},
};

use chrono::{SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use unicode_casefold::UnicodeCaseFold;
use unicode_normalization::UnicodeNormalization;
use uuid::Uuid;

use crate::{
    FolderbaseVersionStore, LocalVersionStore, PathBindingKind, attest_folderbase_root,
    folderbase_capture::FolderbaseCaptureError,
    folderbase_state::FolderbaseState,
    folderbase_version::{ExclusionKind, FolderbaseVersion, PathBinding, validate_capture_path},
    transfer_manifest::{
        ChunkManifest, LARGE_PROFILE_V1, MAX_OBJECT_BYTES, STANDARD_PROFILE_V1,
        plan_streamed_manifest,
    },
};

pub const MAX_CHANGE_SET_BYTES: u64 = 8 * 1024 * 1024;
pub const MAX_CHANGE_SET_ENTRIES: usize = 16_384;
const MAX_PROJECTION_RECORD_BYTES: u64 = 64 * 1024 * 1024;
const IO_BUFFER_BYTES: usize = 64 * 1024;
const LARGE_PROFILE_THRESHOLD_BYTES: u64 = 1024 * 1024 * 1024;
const PROJECTIONS_DIRECTORY: &str = ".folderbase/change-set/projections";
const CHANGE_SET_IDS_DIRECTORY: &str = ".folderbase/change-set/ids";
const APPLIED_CHANGE_SETS_DIRECTORY: &str = ".folderbase/change-set/applied";
const CHANGE_SET_TRANSACTIONS_DIRECTORY: &str = ".folderbase/transactions/change-set";
const ACTIVE_CHANGE_SET_TRANSACTION: &str = ".folderbase/transactions/change-set/active.json";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuthorizedPath {
    pub path_prefix: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CheckoutRequest {
    pub format: String,
    pub folderbase_id: String,
    pub projection_id: String,
    pub folder_scope_id: String,
    pub scope_revision_sha256: String,
    pub permission: String,
    pub authorized_paths: Vec<AuthorizedPath>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind")]
pub enum ProjectedEntry {
    #[serde(rename = "directory")]
    Directory { path: String, object_id: String },
    #[serde(rename = "regular_file")]
    RegularFile {
        path: String,
        object_id: String,
        object_version_id: String,
        content_sha256: String,
        bytes: u64,
        executable: bool,
    },
    #[serde(rename = "symlink")]
    Symlink {
        path: String,
        object_id: String,
        object_version_id: String,
        target: String,
        target_safety: String,
    },
}

impl ProjectedEntry {
    pub(crate) fn path(&self) -> &str {
        match self {
            Self::Directory { path, .. }
            | Self::RegularFile { path, .. }
            | Self::Symlink { path, .. } => path,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProjectionExclusion {
    pub path: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CheckoutReceipt {
    pub format: String,
    pub checkout_id: String,
    pub folderbase_id: String,
    pub projection_id: String,
    pub folder_scope_id: String,
    pub scope_revision_sha256: String,
    pub permission: String,
    pub authorized_paths: Vec<AuthorizedPath>,
    pub projection_base_sha256: String,
    pub entries: Vec<ProjectedEntry>,
    pub exclusions: Vec<ProjectionExclusion>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CheckoutResult {
    pub format: String,
    pub checkout_id: String,
    pub projection_id: String,
    pub projection_base_sha256: String,
    pub entry_count: usize,
    pub exclusion_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProjectionBaseContent {
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StagedContent {
    pub source: String,
    pub staging_id: String,
    pub chunk_manifest_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum ContentReference {
    ProjectionBase(ProjectionBaseContent),
    Staged(StagedContent),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DeltaDirectory {
    pub path: String,
    pub kind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DeltaRegularFile {
    pub path: String,
    pub kind: String,
    pub object_version_id: String,
    pub content_sha256: String,
    pub bytes: u64,
    pub executable: bool,
    pub content: ContentReference,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DeltaSymlink {
    pub path: String,
    pub kind: String,
    pub object_version_id: String,
    pub target: String,
    pub target_safety: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum DeltaState {
    Directory(DeltaDirectory),
    RegularFile(DeltaRegularFile),
    Symlink(DeltaSymlink),
}

impl DeltaState {
    pub(crate) fn path(&self) -> &str {
        match self {
            Self::Directory(value) => &value.path,
            Self::RegularFile(value) => &value.path,
            Self::Symlink(value) => &value.path,
        }
    }

    fn kind(&self) -> InventoryKind {
        match self {
            Self::Directory(_) => InventoryKind::Directory,
            Self::RegularFile(_) => InventoryKind::RegularFile,
            Self::Symlink(_) => InventoryKind::Symlink,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ObjectDelta {
    pub object_id: String,
    pub before: Option<DeltaState>,
    pub after: Option<DeltaState>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ChangeSetPayload {
    pub format: String,
    pub change_set_id: String,
    pub checkout_id: String,
    pub folderbase_id: String,
    pub projection_id: String,
    pub folder_scope_id: String,
    pub scope_revision_sha256: String,
    pub permission: String,
    pub authorized_paths: Vec<AuthorizedPath>,
    pub projection_base_sha256: String,
    pub created_at: String,
    pub deltas: Vec<ObjectDelta>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ChangeSetEnvelope {
    pub format: String,
    pub change_set_sha256: String,
    pub payload: ChangeSetPayload,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StagingObject {
    pub staging_id: String,
    pub chunk_manifest_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StagingIndex {
    pub format: String,
    pub objects: Vec<StagingObject>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ChangeSetConflict {
    pub code: String,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub other_path: Option<String>,
    pub object_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ChangeSetAssessment {
    pub format: String,
    pub change_set_sha256: String,
    pub status: String,
    pub conflicts: Vec<ChangeSetConflict>,
    pub current_projection_sha256: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ChangeSetAttentionDetail {
    pub code: String,
    pub message: String,
    pub retryable: bool,
    pub conflicts: Vec<ChangeSetConflict>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ChangeSetAttention {
    pub format: String,
    pub change_set_sha256: String,
    pub attention: ChangeSetAttentionDetail,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChangeSetAssessmentOutcome {
    Clean(ChangeSetAssessment),
    Attention(ChangeSetAttention),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ChangeSetApplyResult {
    pub format: String,
    pub change_set_sha256: String,
    pub status: String,
    pub projection_result_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChangeSetApplyOutcome {
    Applied(ChangeSetApplyResult),
    Attention(ChangeSetAttention),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ChangeSetIdBinding {
    format: String,
    change_set_id: String,
    change_set_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ChangeSetApplyJournal {
    format: String,
    change_set_id: String,
    change_set_sha256: String,
    projection_id: String,
    phase: String,
    projection_result_sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct TrustedProjection {
    format: String,
    source_version_id: String,
    source_version_sha256: String,
    receipt: CheckoutReceipt,
}

#[derive(Debug, thiserror::Error)]
pub enum ChangeSetError {
    #[error("{code}: {message}")]
    Invalid { code: &'static str, message: String },
    #[error("{code}: {message}")]
    Operational { code: &'static str, message: String },
}

impl ChangeSetError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Invalid { code, .. } | Self::Operational { code, .. } => code,
        }
    }

    pub fn message(&self) -> String {
        match self {
            Self::Invalid { message, .. } | Self::Operational { message, .. } => message.clone(),
        }
    }
}

pub fn checkout_change_set_projection(
    root: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    request: CheckoutRequest,
) -> Result<CheckoutResult, ChangeSetError> {
    let root = root.as_ref();
    let destination = destination.as_ref();
    validate_checkout_request(&request)?;
    let attestation = attest_folderbase_root(root).map_err(operational)?;
    if attestation.folderbase_id != request.folderbase_id {
        return Err(invalid(
            "invalid_checkout_request",
            "checkout request names a different Folderbase",
        ));
    }
    require_new_destination(destination)?;

    // Pin the exact source state before deriving the scoped projection. This
    // may reuse an unchanged Local Head and never exposes that Head to the
    // checkout.
    let store = FolderbaseVersionStore::open(root).map_err(capture_operational)?;
    let plan = store.plan_capture().map_err(capture_operational)?;
    let sealed = store.seal_capture(plan).map_err(capture_operational)?;
    let version = store
        .read_version(sealed.version_id())
        .map_err(capture_operational)?;

    let mut entries = version
        .bindings()
        .iter()
        .filter(|binding| is_authorized(binding.path(), &request.authorized_paths))
        .map(projected_entry)
        .collect::<Result<Vec<_>, _>>()?;
    entries.sort_by(|left, right| left.path().as_bytes().cmp(right.path().as_bytes()));
    if entries.len() > MAX_CHANGE_SET_ENTRIES {
        return Err(invalid(
            "invalid_checkout_request",
            "scoped checkout exceeds the entry limit",
        ));
    }
    let mut exclusions = version
        .exclusions()
        .iter()
        .filter(|exclusion| is_authorized(exclusion.path(), &request.authorized_paths))
        .map(|exclusion| ProjectionExclusion {
            path: exclusion.path().to_owned(),
            reason: match exclusion.kind() {
                ExclusionKind::NestedFolderbase => "nested-folderbase-boundary",
                _ => "unsupported-v1",
            }
            .to_owned(),
        })
        .collect::<Vec<_>>();
    exclusions.sort_by(|left, right| left.path.as_bytes().cmp(right.path.as_bytes()));

    let projection_base_sha256 = projection_digest(&request, &entries, &exclusions)?;
    let receipt = CheckoutReceipt {
        format: "folderbase-checkout-projection-v1".to_owned(),
        checkout_id: format!("checkout_{}", Uuid::now_v7()),
        folderbase_id: request.folderbase_id.clone(),
        projection_id: request.projection_id.clone(),
        folder_scope_id: request.folder_scope_id.clone(),
        scope_revision_sha256: request.scope_revision_sha256.clone(),
        permission: request.permission.clone(),
        authorized_paths: request.authorized_paths.clone(),
        projection_base_sha256: projection_base_sha256.clone(),
        entries,
        exclusions,
    };

    materialize_checkout(root, destination, &receipt)?;
    let trusted = TrustedProjection {
        format: "folderbase-trusted-projection-v1".to_owned(),
        source_version_id: version.version_id().to_owned(),
        source_version_sha256: sealed.version_sha256().to_owned(),
        receipt: receipt.clone(),
    };
    install_trusted_projection(root, &trusted)?;

    Ok(CheckoutResult {
        format: "folderbase-checkout-result-v1".to_owned(),
        checkout_id: receipt.checkout_id,
        projection_id: receipt.projection_id,
        projection_base_sha256,
        entry_count: receipt.entries.len(),
        exclusion_count: receipt.exclusions.len(),
    })
}

pub fn propose_change_set(
    checkout: impl AsRef<Path>,
    staging: impl AsRef<Path>,
) -> Result<ChangeSetEnvelope, ChangeSetError> {
    let checkout = checkout.as_ref();
    let staging = staging.as_ref();
    let receipt: CheckoutReceipt = read_json_bounded_file(
        &checkout.join(".folderbase/checkout.json"),
        MAX_PROJECTION_RECORD_BYTES,
        "invalid_projection_receipt",
    )?;
    validate_receipt(&receipt)?;
    require_new_destination(staging)?;
    fs::create_dir(staging).map_err(operational)?;
    fs::create_dir(staging.join("manifests")).map_err(operational)?;
    fs::create_dir(staging.join("chunks")).map_err(operational)?;

    let current = inventory_checkout(checkout)?;
    let base = receipt
        .entries
        .iter()
        .map(InventoryEntry::from_projected)
        .collect::<Vec<_>>();
    let matches = match_inventory(&base, &current);
    let mut matched_base = BTreeSet::new();
    let mut matched_current = BTreeSet::new();
    let mut deltas = Vec::new();
    let mut staged_objects = Vec::new();

    for (base_index, current_index) in matches {
        matched_base.insert(base_index);
        matched_current.insert(current_index);
        let before_entry = &base[base_index];
        let after_entry = &current[current_index];
        if before_entry.same_state(after_entry) {
            continue;
        }
        let before = delta_state_from_base(before_entry);
        let after = delta_state_from_current(
            checkout,
            staging,
            after_entry,
            Some(before_entry),
            &mut staged_objects,
        )?;
        deltas.push(ObjectDelta {
            object_id: before_entry
                .object_id
                .clone()
                .ok_or_else(|| operational_message("trusted projection entry omitted Object ID"))?,
            before: Some(before),
            after: Some(after),
        });
    }

    for (index, entry) in base.iter().enumerate() {
        if matched_base.contains(&index) {
            continue;
        }
        deltas.push(ObjectDelta {
            object_id: entry
                .object_id
                .clone()
                .ok_or_else(|| operational_message("trusted projection entry omitted Object ID"))?,
            before: Some(delta_state_from_base(entry)),
            after: None,
        });
    }

    for (index, entry) in current.iter().enumerate() {
        if matched_current.contains(&index) {
            continue;
        }
        let object_id = format!("obj_{}", Uuid::now_v7());
        let after = delta_state_from_current(checkout, staging, entry, None, &mut staged_objects)?;
        deltas.push(ObjectDelta {
            object_id,
            before: None,
            after: Some(after),
        });
    }

    if deltas.is_empty() || deltas.len() > MAX_CHANGE_SET_ENTRIES {
        return Err(invalid(
            "invalid_change_set_input",
            "a Change Set must contain from 1 through 16384 deltas",
        ));
    }
    deltas.sort_by(|left, right| left.object_id.as_bytes().cmp(right.object_id.as_bytes()));
    staged_objects
        .sort_by(|left, right| left.staging_id.as_bytes().cmp(right.staging_id.as_bytes()));
    let index = StagingIndex {
        format: "folderbase-change-set-staging-v1".to_owned(),
        objects: staged_objects,
    };
    create_new_file(
        &staging.join("index.json"),
        &encode_pretty_bounded(&index, MAX_CHANGE_SET_BYTES)?,
    )?;

    let payload = ChangeSetPayload {
        format: "folderbase-change-set-payload-v1".to_owned(),
        change_set_id: format!("changeset_{}", Uuid::now_v7()),
        checkout_id: receipt.checkout_id,
        folderbase_id: receipt.folderbase_id,
        projection_id: receipt.projection_id,
        folder_scope_id: receipt.folder_scope_id,
        scope_revision_sha256: receipt.scope_revision_sha256,
        permission: receipt.permission,
        authorized_paths: receipt.authorized_paths,
        projection_base_sha256: receipt.projection_base_sha256,
        created_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        deltas,
    };
    let change_set_sha256 = change_set_digest(&payload)?;
    let envelope = ChangeSetEnvelope {
        format: "folderbase-change-set-v1".to_owned(),
        change_set_sha256,
        payload,
    };
    let encoded = serde_json::to_vec(&envelope).map_err(operational)?;
    if encoded.len() as u64 > MAX_CHANGE_SET_BYTES {
        return Err(invalid(
            "invalid_change_set_input",
            "Change Set envelope exceeds 8 MiB",
        ));
    }
    Ok(envelope)
}

pub fn assess_change_set(
    root: impl AsRef<Path>,
    staging: impl AsRef<Path>,
    envelope: ChangeSetEnvelope,
) -> Result<ChangeSetAssessmentOutcome, ChangeSetError> {
    let root = root.as_ref();
    let staging = staging.as_ref();
    validate_change_set_envelope(&envelope)?;
    let attestation = attest_folderbase_root(root).map_err(operational)?;
    if attestation.folderbase_id != envelope.payload.folderbase_id {
        return Err(invalid(
            "change_set_root_mismatch",
            "Change Set belongs to a different Folderbase",
        ));
    }

    let Some(trusted) = read_trusted_projection(root, &envelope.payload.projection_id)? else {
        return Ok(ChangeSetAssessmentOutcome::Attention(attention(
            &envelope,
            "change_set_stale_base",
            "trusted projection base is absent; create a fresh checkout",
            true,
            Vec::new(),
        )));
    };
    if !payload_matches_projection(&envelope.payload, &trusted.receipt) {
        return Ok(ChangeSetAssessmentOutcome::Attention(attention(
            &envelope,
            "change_set_authorization_changed",
            "Folder Scope authority no longer matches the checkout",
            false,
            Vec::new(),
        )));
    }
    let version_store = FolderbaseVersionStore::open(root).map_err(capture_operational)?;
    let retained = match version_store.read_version(&trusted.source_version_id) {
        Ok(version) => version,
        Err(_) => {
            return Ok(ChangeSetAssessmentOutcome::Attention(attention(
                &envelope,
                "change_set_stale_base",
                "trusted source Version is no longer retained",
                true,
                Vec::new(),
            )));
        }
    };
    if retained.canonical_digest().map_err(operational)? != trusted.source_version_sha256 {
        return Ok(ChangeSetAssessmentOutcome::Attention(attention(
            &envelope,
            "change_set_stale_base",
            "trusted source Version failed exact verification",
            true,
            Vec::new(),
        )));
    }

    verify_staging(staging, &envelope)?;
    let current = inventory_source_scope(
        root,
        &trusted.receipt.authorized_paths,
        &trusted.receipt.exclusions,
    )?;
    let current_projection_sha256 = scoped_inventory_digest(&current)?;
    let conflicts = assess_conflicts(&envelope, &trusted.receipt, &current);
    if conflicts.is_empty() {
        Ok(ChangeSetAssessmentOutcome::Clean(ChangeSetAssessment {
            format: "folderbase-change-set-assessment-v1".to_owned(),
            change_set_sha256: envelope.change_set_sha256,
            status: "clean".to_owned(),
            conflicts,
            current_projection_sha256,
        }))
    } else {
        Ok(ChangeSetAssessmentOutcome::Attention(attention(
            &envelope,
            "change_set_conflicted",
            "Change Set overlaps current source work",
            false,
            conflicts,
        )))
    }
}

pub fn apply_change_set(
    root: impl AsRef<Path>,
    staging: impl AsRef<Path>,
    envelope: ChangeSetEnvelope,
) -> Result<ChangeSetApplyOutcome, ChangeSetError> {
    let root = root.as_ref();
    let staging = staging.as_ref();
    validate_change_set_envelope(&envelope)?;
    let attestation = attest_folderbase_root(root).map_err(operational)?;
    if attestation.folderbase_id != envelope.payload.folderbase_id {
        return Err(invalid(
            "change_set_root_mismatch",
            "Change Set belongs to a different Folderbase",
        ));
    }

    // Replay is resolved before three-way assessment because the source now
    // intentionally contains the applied after-state rather than the old
    // projection base.
    {
        let replay_state = FolderbaseState::open_existing(root).map_err(operational)?;
        for directory in [
            CHANGE_SET_IDS_DIRECTORY,
            APPLIED_CHANGE_SETS_DIRECTORY,
            CHANGE_SET_TRANSACTIONS_DIRECTORY,
        ] {
            replay_state
                .ensure_private_dir(Path::new(directory))
                .map_err(operational)?;
        }
        let replay_local = LocalVersionStore::open_read_only(root).map_err(operational)?;
        let _replay_lease = replay_local
            .acquire_transaction_lock_in(&replay_state)
            .map_err(operational)?;
        if let Some(completed) = read_completed_apply(&replay_state, &envelope.change_set_sha256)? {
            validate_id_binding(&replay_state, &envelope)?;
            cleanup_completed_change_set(root, &replay_state, &envelope.change_set_sha256)?;
            return Ok(ChangeSetApplyOutcome::Applied(ChangeSetApplyResult {
                status: "already_applied".to_owned(),
                ..completed
            }));
        }
    }

    let trusted_before_apply = read_trusted_projection(root, &envelope.payload.projection_id)?
        .ok_or_else(|| operational_message("trusted projection disappeared before apply"))?;

    let state = FolderbaseState::open_existing(root).map_err(operational)?;
    for directory in [
        CHANGE_SET_IDS_DIRECTORY,
        APPLIED_CHANGE_SETS_DIRECTORY,
        CHANGE_SET_TRANSACTIONS_DIRECTORY,
    ] {
        state
            .ensure_private_dir(Path::new(directory))
            .map_err(operational)?;
    }
    let local = LocalVersionStore::open_read_only(root).map_err(operational)?;
    let lease = local
        .acquire_transaction_lock_in(&state)
        .map_err(operational)?;

    if let Some(completed) = read_completed_apply(&state, &envelope.change_set_sha256)? {
        validate_id_binding(&state, &envelope)?;
        cleanup_completed_change_set(root, &state, &envelope.change_set_sha256)?;
        return Ok(ChangeSetApplyOutcome::Applied(ChangeSetApplyResult {
            status: "already_applied".to_owned(),
            ..completed
        }));
    }
    bind_change_set_id(&state, &envelope)?;

    let active = read_active_apply(&state)?;
    let mut resume_published = false;
    let mut resume_prepared = false;
    if let Some(active) = active {
        if active.change_set_sha256 != envelope.change_set_sha256
            || active.change_set_id != envelope.payload.change_set_id
        {
            return Err(operational_message(
                "another Change Set transaction requires recovery",
            ));
        }
        match active.phase.as_str() {
            "prepared" => {
                if workspace_matches_after(root, &envelope)? {
                    resume_published = true;
                } else if workspace_is_recoverable_transition(root, &envelope)? {
                    resume_prepared = true;
                } else {
                    return Err(operational_message(
                        "interrupted Change Set paths contain unrelated changes",
                    ));
                }
            }
            "published" => {
                if !workspace_matches_after(root, &envelope)? {
                    return Err(operational_message(
                        "published Change Set workspace no longer matches its journal",
                    ));
                }
                resume_published = true;
            }
            _ => {
                return Err(operational_message(
                    "active Change Set journal has an unknown phase",
                ));
            }
        }
    }

    let mut projection_result_sha256 = if resume_published {
        let trusted = read_trusted_projection(root, &envelope.payload.projection_id)?
            .ok_or_else(|| operational_message("trusted projection disappeared during apply"))?;
        let current = inventory_source_scope(
            root,
            &trusted.receipt.authorized_paths,
            &trusted.receipt.exclusions,
        )?;
        scoped_inventory_digest(&current)?
    } else {
        let work = if resume_prepared {
            reopen_prepared_change_set_work(root, &envelope)?
        } else {
            match assess_change_set(root, staging, envelope.clone())? {
                ChangeSetAssessmentOutcome::Attention(attention) => {
                    return Ok(ChangeSetApplyOutcome::Attention(attention));
                }
                ChangeSetAssessmentOutcome::Clean(_) => {}
            }
            let work = prepare_change_set_work(root, staging, &envelope)?;
            let prepared = ChangeSetApplyJournal {
                format: "folderbase-change-set-apply-journal-v1".to_owned(),
                change_set_id: envelope.payload.change_set_id.clone(),
                change_set_sha256: envelope.change_set_sha256.clone(),
                projection_id: envelope.payload.projection_id.clone(),
                phase: "prepared".to_owned(),
                projection_result_sha256: None,
            };
            state
                .replace(
                    Path::new(ACTIVE_CHANGE_SET_TRANSACTION),
                    &encode_pretty_bounded(&prepared, MAX_CHANGE_SET_BYTES)?,
                )
                .map_err(operational)?;

            if std::env::var_os("FOLDERBASE_CHANGE_SET_CONFORMANCE_CRASH_AFTER")
                .is_some_and(|value| value == "prepared-journal")
            {
                std::process::exit(86);
            }
            work
        };

        publish_change_set_work(root, &work, &envelope)?;
        let published = ChangeSetApplyJournal {
            format: "folderbase-change-set-apply-journal-v1".to_owned(),
            change_set_id: envelope.payload.change_set_id.clone(),
            change_set_sha256: envelope.change_set_sha256.clone(),
            projection_id: envelope.payload.projection_id.clone(),
            phase: "published".to_owned(),
            projection_result_sha256: None,
        };
        state
            .replace(
                Path::new(ACTIVE_CHANGE_SET_TRANSACTION),
                &encode_pretty_bounded(&published, MAX_CHANGE_SET_BYTES)?,
            )
            .map_err(operational)?;
        String::new()
    };

    // Keep publication and history in one logical operation. The workspace is
    // still protected by the durable journal while the shared lease is
    // released and the existing capture transaction acquires it.
    drop(lease);
    let store = FolderbaseVersionStore::open(root).map_err(capture_operational)?;
    let plan = store.plan_capture().map_err(capture_operational)?;
    let final_capture = store.seal_capture(plan).map_err(capture_operational)?;
    let history = store
        .finalize_change_set_history(
            &trusted_before_apply.source_version_id,
            final_capture.version_id(),
            &envelope.payload.created_at,
            &envelope.change_set_sha256,
            &envelope.payload.deltas,
        )
        .map_err(capture_operational)?;
    if std::env::var_os("FOLDERBASE_CHANGE_SET_CONFORMANCE_CRASH_AFTER")
        .is_some_and(|value| value == "history-head")
    {
        std::process::exit(89);
    }
    let history_version = store
        .read_version(history.version_id())
        .map_err(capture_operational)?;
    let version_inventory = inventory_version_scope(
        &history_version,
        &trusted_before_apply.receipt.authorized_paths,
        &trusted_before_apply.receipt.exclusions,
    )?;
    let history_projection_sha256 = scoped_inventory_digest(&version_inventory)?;
    if !projection_result_sha256.is_empty() && projection_result_sha256 != history_projection_sha256
    {
        return Err(operational_message(
            "recovered workspace differs from finalized Change Set history",
        ));
    }
    projection_result_sha256 = history_projection_sha256;

    let state = FolderbaseState::open_existing(root).map_err(operational)?;
    let local = LocalVersionStore::open_read_only(root).map_err(operational)?;
    let _lease = local
        .acquire_transaction_lock_in(&state)
        .map_err(operational)?;
    let result = ChangeSetApplyResult {
        format: "folderbase-change-set-apply-result-v1".to_owned(),
        change_set_sha256: envelope.change_set_sha256.clone(),
        status: "applied".to_owned(),
        projection_result_sha256,
    };
    let completion_path = applied_change_set_path(&envelope.change_set_sha256);
    match state.publish_new(
        &completion_path,
        &encode_pretty_bounded(&result, MAX_CHANGE_SET_BYTES)?,
    ) {
        Ok(()) => {}
        Err(crate::FolderbaseError::WouldOverwrite(_)) => {
            let existing = read_completed_apply(&state, &envelope.change_set_sha256)?
                .ok_or_else(|| operational_message("completion receipt disappeared"))?;
            if existing != result {
                return Err(operational_message(
                    "completion receipt names a different Change Set result",
                ));
            }
        }
        Err(error) => return Err(operational(error)),
    }
    cleanup_completed_change_set(root, &state, &envelope.change_set_sha256)?;
    Ok(ChangeSetApplyOutcome::Applied(result))
}

fn bind_change_set_id(
    state: &FolderbaseState,
    envelope: &ChangeSetEnvelope,
) -> Result<(), ChangeSetError> {
    let binding = ChangeSetIdBinding {
        format: "folderbase-change-set-id-binding-v1".to_owned(),
        change_set_id: envelope.payload.change_set_id.clone(),
        change_set_sha256: envelope.change_set_sha256.clone(),
    };
    let path = Path::new(CHANGE_SET_IDS_DIRECTORY)
        .join(format!("{}.json", envelope.payload.change_set_id));
    let encoded = encode_pretty_bounded(&binding, MAX_CHANGE_SET_BYTES)?;
    match state.publish_new(&path, &encoded) {
        Ok(()) => Ok(()),
        Err(crate::FolderbaseError::WouldOverwrite(_)) => {
            let bytes = state
                .read_bounded(&path, MAX_CHANGE_SET_BYTES)
                .map_err(operational)?
                .ok_or_else(|| operational_message("Change Set ID binding disappeared"))?;
            let existing: ChangeSetIdBinding = serde_json::from_slice(&bytes)
                .map_err(|error| invalid("change_set_id_reused", error.to_string()))?;
            if existing == binding {
                Ok(())
            } else {
                Err(invalid(
                    "change_set_id_reused",
                    "Change Set ID already names different bytes",
                ))
            }
        }
        Err(error) => Err(operational(error)),
    }
}

fn validate_id_binding(
    state: &FolderbaseState,
    envelope: &ChangeSetEnvelope,
) -> Result<(), ChangeSetError> {
    let path = Path::new(CHANGE_SET_IDS_DIRECTORY)
        .join(format!("{}.json", envelope.payload.change_set_id));
    let bytes = state
        .read_bounded(&path, MAX_CHANGE_SET_BYTES)
        .map_err(operational)?
        .ok_or_else(|| invalid("change_set_id_reused", "Change Set ID binding is missing"))?;
    let binding: ChangeSetIdBinding = serde_json::from_slice(&bytes)
        .map_err(|error| invalid("change_set_id_reused", error.to_string()))?;
    if binding.change_set_sha256 != envelope.change_set_sha256 {
        return Err(invalid(
            "change_set_id_reused",
            "Change Set ID already names different bytes",
        ));
    }
    Ok(())
}

fn read_active_apply(
    state: &FolderbaseState,
) -> Result<Option<ChangeSetApplyJournal>, ChangeSetError> {
    state
        .read_bounded_if_present(
            Path::new(ACTIVE_CHANGE_SET_TRANSACTION),
            MAX_CHANGE_SET_BYTES,
        )
        .map_err(operational)?
        .map(|bytes| {
            serde_json::from_slice(&bytes)
                .map_err(|error| operational_message(format!("invalid apply journal: {error}")))
        })
        .transpose()
}

fn read_completed_apply(
    state: &FolderbaseState,
    digest: &str,
) -> Result<Option<ChangeSetApplyResult>, ChangeSetError> {
    state
        .read_bounded_if_present(&applied_change_set_path(digest), MAX_CHANGE_SET_BYTES)
        .map_err(operational)?
        .map(|bytes| {
            serde_json::from_slice(&bytes).map_err(|error| {
                operational_message(format!("invalid apply completion receipt: {error}"))
            })
        })
        .transpose()
}

fn applied_change_set_path(digest: &str) -> PathBuf {
    Path::new(APPLIED_CHANGE_SETS_DIRECTORY).join(format!("{digest}.json"))
}

fn cleanup_completed_change_set(
    root: &Path,
    state: &FolderbaseState,
    digest: &str,
) -> Result<(), ChangeSetError> {
    let work = change_set_work_directory(root, digest);
    match fs::symlink_metadata(&work) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
            fs::remove_dir_all(&work).map_err(operational)?;
        }
        Ok(_) => return Err(operational_message("Change Set work path is unsafe")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(operational(error)),
    }
    if read_active_apply(state)?.is_some_and(|active| active.change_set_sha256 == digest) {
        state
            .remove_durable(Path::new(ACTIVE_CHANGE_SET_TRANSACTION))
            .map_err(operational)?;
    }
    Ok(())
}

#[derive(Debug)]
struct PreparedChangeSetWork {
    directory: PathBuf,
    regular_files: BTreeMap<String, PathBuf>,
}

fn change_set_work_directory(root: &Path, digest: &str) -> PathBuf {
    root.join(CHANGE_SET_TRANSACTIONS_DIRECTORY)
        .join(format!("work-{digest}"))
}

fn reopen_prepared_change_set_work(
    root: &Path,
    envelope: &ChangeSetEnvelope,
) -> Result<PreparedChangeSetWork, ChangeSetError> {
    let directory = change_set_work_directory(root, &envelope.change_set_sha256);
    let metadata = fs::symlink_metadata(&directory).map_err(operational)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(operational_message("Change Set prepared work is unsafe"));
    }
    let mut regular_files = BTreeMap::new();
    for delta in &envelope.payload.deltas {
        let Some(DeltaState::RegularFile(after)) = &delta.after else {
            continue;
        };
        let unchanged_move = matches!(after.content, ContentReference::ProjectionBase(_))
            && delta.before.as_ref().is_some_and(|before| {
                before.path() != after.path && before.kind() == InventoryKind::RegularFile
            });
        if unchanged_move {
            continue;
        }
        let prepared = directory.join(&delta.object_id);
        let metadata = fs::symlink_metadata(&prepared).map_err(operational)?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(operational_message(
                "Change Set prepared regular file is unsafe",
            ));
        }
        regular_files.insert(delta.object_id.clone(), prepared);
    }
    Ok(PreparedChangeSetWork {
        directory,
        regular_files,
    })
}

fn prepare_change_set_work(
    root: &Path,
    staging: &Path,
    envelope: &ChangeSetEnvelope,
) -> Result<PreparedChangeSetWork, ChangeSetError> {
    let directory = change_set_work_directory(root, &envelope.change_set_sha256);
    match fs::symlink_metadata(&directory) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
            fs::remove_dir_all(&directory).map_err(operational)?;
        }
        Ok(_) => return Err(operational_message("Change Set work path is unsafe")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(operational(error)),
    }
    fs::create_dir(&directory).map_err(operational)?;
    let mut regular_files = BTreeMap::new();
    for delta in &envelope.payload.deltas {
        let Some(DeltaState::RegularFile(after)) = &delta.after else {
            continue;
        };
        let unchanged_move = matches!(after.content, ContentReference::ProjectionBase(_))
            && delta.before.as_ref().is_some_and(|before| {
                before.path() != after.path && before.kind() == InventoryKind::RegularFile
            });
        if unchanged_move {
            continue;
        }
        let target = directory.join(&delta.object_id);
        match &after.content {
            ContentReference::ProjectionBase(_) => {
                let before = match &delta.before {
                    Some(DeltaState::RegularFile(before)) => before,
                    _ => {
                        return Err(invalid(
                            "invalid_change_set_input",
                            "projection-base bytes have no regular-file before state",
                        ));
                    }
                };
                copy_regular_verified(
                    &resolve_portable(root, &before.path)?,
                    &target,
                    &after.content_sha256,
                    after.bytes,
                    after.executable,
                )?;
            }
            ContentReference::Staged(reference) => {
                materialize_staged_regular(staging, reference, &target, after)?;
            }
        }
        regular_files.insert(delta.object_id.clone(), target);
    }
    sync_directory(&directory)?;
    Ok(PreparedChangeSetWork {
        directory,
        regular_files,
    })
}

fn materialize_staged_regular(
    staging: &Path,
    reference: &StagedContent,
    target: &Path,
    expected: &DeltaRegularFile,
) -> Result<(), ChangeSetError> {
    let manifest_path = staging
        .join("manifests")
        .join(format!("{}.json", reference.chunk_manifest_sha256));
    let manifest = ChunkManifest::decode_bounded(File::open(manifest_path).map_err(operational)?)
        .map_err(|error| invalid("invalid_staging", error.to_string()))?;
    if manifest.object_sha256 != expected.content_sha256
        || manifest.object_bytes != expected.bytes
        || manifest.canonical_digest().map_err(operational)? != reference.chunk_manifest_sha256
    {
        return Err(invalid(
            "invalid_staging",
            "staged object does not match Change Set after-state",
        ));
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    let mut output = options.open(target).map_err(operational)?;
    for chunk in &manifest.chunks {
        let mut input =
            File::open(staging.join("chunks").join(&chunk.sha256)).map_err(operational)?;
        std::io::copy(&mut input, &mut output).map_err(operational)?;
    }
    output.sync_all().map_err(operational)?;
    verify_regular_digest(target, expected.bytes, &expected.content_sha256)?;
    set_executable(target, expected.executable)
}

fn publish_change_set_work(
    root: &Path,
    work: &PreparedChangeSetWork,
    envelope: &ChangeSetEnvelope,
) -> Result<(), ChangeSetError> {
    // Preserve filesystem identity for true moves. Folderbase capture uses
    // that physical continuity to retain the stable Object ID across paths.
    let mut moves = envelope
        .payload
        .deltas
        .iter()
        .filter_map(|delta| match (&delta.before, &delta.after) {
            (Some(before), Some(after))
                if before.path() != after.path() && before.kind() == after.kind() =>
            {
                Some((before.path().to_owned(), after.path().to_owned()))
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    moves.sort_by(|left, right| {
        left.0
            .split('/')
            .count()
            .cmp(&right.0.split('/').count())
            .then_with(|| left.0.as_bytes().cmp(right.0.as_bytes()))
    });
    for (before, after) in &moves {
        let source = resolve_portable(root, before)?;
        let destination = resolve_portable(root, after)?;
        let source_exists = fs::symlink_metadata(&source).is_ok();
        let destination_exists = fs::symlink_metadata(&destination).is_ok();
        match (source_exists, destination_exists) {
            (true, false) => {
                if let Some(parent) = destination.parent() {
                    fs::create_dir_all(parent).map_err(operational)?;
                }
                fs::rename(source, destination).map_err(operational)?;
                crash_after_first_mutation_if_requested();
            }
            (false, true) => {}
            _ => {
                return Err(operational_message(
                    "Change Set move is not in a recoverable state",
                ));
            }
        }
    }
    let moved_from = moves
        .iter()
        .map(|(before, _)| before.as_str())
        .collect::<BTreeSet<_>>();
    let mut removals = envelope
        .payload
        .deltas
        .iter()
        .filter_map(|delta| {
            let before = delta.before.as_ref()?;
            if moved_from.contains(before.path())
                || (delta
                    .after
                    .as_ref()
                    .is_some_and(|after| after.path() == before.path())
                    && matches!(before, DeltaState::Directory(_)))
            {
                None
            } else {
                Some(before.path().to_owned())
            }
        })
        .collect::<Vec<_>>();
    removals.sort_by(|left, right| {
        right
            .split('/')
            .count()
            .cmp(&left.split('/').count())
            .then_with(|| right.as_bytes().cmp(left.as_bytes()))
    });
    for path in removals {
        if remove_workspace_path(&resolve_portable(root, &path)?)? {
            crash_after_first_mutation_if_requested();
        }
    }

    let mut directories = envelope
        .payload
        .deltas
        .iter()
        .filter_map(|delta| match &delta.after {
            Some(DeltaState::Directory(value)) => Some(value.path.clone()),
            _ => None,
        })
        .collect::<Vec<_>>();
    directories.sort_by(|left, right| {
        left.split('/')
            .count()
            .cmp(&right.split('/').count())
            .then_with(|| left.as_bytes().cmp(right.as_bytes()))
    });
    for path in directories {
        let directory = resolve_portable(root, &path)?;
        let existed = fs::symlink_metadata(&directory).is_ok();
        fs::create_dir_all(directory).map_err(operational)?;
        if !existed {
            crash_after_first_mutation_if_requested();
        }
    }

    for delta in &envelope.payload.deltas {
        let Some(after) = &delta.after else {
            continue;
        };
        match after {
            DeltaState::Directory(_) => {}
            DeltaState::RegularFile(value) => {
                let target = resolve_portable(root, &value.path)?;
                let moved = delta.before.as_ref().is_some_and(|before| {
                    before.path() != value.path && before.kind() == InventoryKind::RegularFile
                });
                let bytes_unchanged = matches!(value.content, ContentReference::ProjectionBase(_));
                if moved && bytes_unchanged {
                    verify_regular_digest(&target, value.bytes, &value.content_sha256)?;
                    set_executable(&target, value.executable)?;
                    crash_after_first_mutation_if_requested();
                } else if moved {
                    let source = work.regular_files.get(&delta.object_id).ok_or_else(|| {
                        operational_message("prepared regular-file replacement is missing")
                    })?;
                    mark_in_place_mutation(work, &delta.object_id, &envelope.change_set_sha256)?;
                    overwrite_regular_in_place(
                        source,
                        &target,
                        &value.content_sha256,
                        value.bytes,
                        value.executable,
                    )?;
                    clear_in_place_mutation(work, &delta.object_id)?;
                    crash_after_first_mutation_if_requested();
                } else {
                    let source = work.regular_files.get(&delta.object_id).ok_or_else(|| {
                        operational_message("prepared regular-file replacement is missing")
                    })?;
                    if install_regular_atomic(
                        source,
                        &target,
                        &value.content_sha256,
                        value.bytes,
                        value.executable,
                    )? {
                        crash_after_first_mutation_if_requested();
                    }
                }
            }
            DeltaState::Symlink(value) => {
                if ensure_symlink(root, &value.path, &value.target)? {
                    crash_after_first_mutation_if_requested();
                }
            }
        }
    }
    Ok(())
}

fn in_place_mutation_marker(work: &PreparedChangeSetWork, object_id: &str) -> PathBuf {
    work.directory.join(format!("mutating-{object_id}"))
}

fn mark_in_place_mutation(
    work: &PreparedChangeSetWork,
    object_id: &str,
    change_set_sha256: &str,
) -> Result<(), ChangeSetError> {
    let marker = in_place_mutation_marker(work, object_id);
    let expected = format!("{change_set_sha256}\n");
    match fs::symlink_metadata(&marker) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
            let mut contents = String::new();
            File::open(&marker)
                .and_then(|mut file| file.read_to_string(&mut contents))
                .map_err(operational)?;
            if contents != expected {
                return Err(operational_message(
                    "Change Set in-place recovery marker is invalid",
                ));
            }
        }
        Ok(_) => {
            return Err(operational_message(
                "Change Set in-place recovery marker is unsafe",
            ));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            create_new_file(&marker, expected.as_bytes())?;
            sync_directory(marker.parent().expect("marker has parent"))?;
        }
        Err(error) => return Err(operational(error)),
    }
    Ok(())
}

fn clear_in_place_mutation(
    work: &PreparedChangeSetWork,
    object_id: &str,
) -> Result<(), ChangeSetError> {
    let marker = in_place_mutation_marker(work, object_id);
    match fs::remove_file(&marker) {
        Ok(()) => sync_directory(marker.parent().expect("marker has parent")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(operational(error)),
    }
}

fn overwrite_regular_in_place(
    source: &Path,
    target: &Path,
    expected_sha256: &str,
    expected_bytes: u64,
    executable: bool,
) -> Result<(), ChangeSetError> {
    let metadata = fs::symlink_metadata(target).map_err(operational)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(operational_message("moved regular-file target is unsafe"));
    }
    let mut input = File::open(source).map_err(operational)?;
    let mut output = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(target)
        .map_err(operational)?;
    if std::env::var_os("FOLDERBASE_CHANGE_SET_CONFORMANCE_CRASH_AFTER")
        .is_some_and(|value| value == "in-place-write")
    {
        let mut byte = [0_u8; 1];
        let read = input.read(&mut byte).map_err(operational)?;
        if read > 0 {
            output.write_all(&byte[..read]).map_err(operational)?;
        }
        output.sync_all().map_err(operational)?;
        std::process::exit(88);
    }
    std::io::copy(&mut input, &mut output).map_err(operational)?;
    output.sync_all().map_err(operational)?;
    verify_regular_digest(target, expected_bytes, expected_sha256)?;
    set_executable(target, executable)
}

fn remove_workspace_path(path: &Path) -> Result<bool, ChangeSetError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
            fs::remove_dir(path).map_err(operational)?;
            Ok(true)
        }
        Ok(_) => {
            fs::remove_file(path).map_err(operational)?;
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(operational(error)),
    }
}

fn install_regular_atomic(
    source: &Path,
    target: &Path,
    expected_sha256: &str,
    expected_bytes: u64,
    executable: bool,
) -> Result<bool, ChangeSetError> {
    match fs::symlink_metadata(target) {
        Ok(metadata)
            if metadata.is_file()
                && !metadata.file_type().is_symlink()
                && metadata.len() == expected_bytes
                && is_executable(&metadata) == executable
                && sha256_regular(target, expected_bytes)? == expected_sha256 =>
        {
            return Ok(false);
        }
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
            fs::remove_file(target).map_err(operational)?;
        }
        Ok(_) => {
            return Err(operational_message(
                "Change Set regular-file target is unsafe",
            ));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(operational(error)),
    }
    let parent = target
        .parent()
        .ok_or_else(|| operational_message("regular-file target has no parent"))?;
    fs::create_dir_all(parent).map_err(operational)?;
    let temporary = parent.join(format!(".folderbase-change-set-{}.tmp", Uuid::now_v7()));
    copy_regular_verified(
        source,
        &temporary,
        expected_sha256,
        expected_bytes,
        executable,
    )?;
    fs::rename(&temporary, target).map_err(operational)?;
    Ok(true)
}

fn ensure_symlink(root: &Path, path: &str, expected_target: &str) -> Result<bool, ChangeSetError> {
    let target = resolve_portable(root, path)?;
    match fs::symlink_metadata(&target) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            if fs::read_link(&target)
                .map_err(operational)?
                .to_string_lossy()
                == expected_target
            {
                return Ok(false);
            }
            fs::remove_file(&target).map_err(operational)?;
        }
        Ok(metadata) if metadata.is_file() => {
            fs::remove_file(&target).map_err(operational)?;
        }
        Ok(_) => {
            return Err(operational_message("Change Set symlink target is unsafe"));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(operational(error)),
    }
    materialize_symlink(root, path, expected_target)?;
    Ok(true)
}

fn crash_after_first_mutation_if_requested() {
    if std::env::var_os("FOLDERBASE_CHANGE_SET_CONFORMANCE_CRASH_AFTER")
        .is_some_and(|value| value == "first-mutation")
    {
        std::process::exit(87);
    }
}

fn workspace_is_recoverable_transition(
    root: &Path,
    envelope: &ChangeSetEnvelope,
) -> Result<bool, ChangeSetError> {
    for delta in &envelope.payload.deltas {
        match (&delta.before, &delta.after) {
            (Some(before), Some(after)) if before.path() == after.path() => {
                let path = before.path();
                if path_exists_nofollow(root, path)?
                    && !workspace_state_matches(root, before)?
                    && !workspace_state_matches(root, after)?
                {
                    return Ok(false);
                }
            }
            (Some(before), Some(after)) => {
                let source_matches = workspace_state_matches(root, before)?;
                let source_absent = !path_exists_nofollow(root, before.path())?;
                let destination_absent = !path_exists_nofollow(root, after.path())?;
                let destination_matches_before =
                    workspace_state_matches_at(root, before, after.path())?;
                let destination_matches_after = workspace_state_matches(root, after)?;
                let interrupted_in_place = source_absent
                    && matches!(after, DeltaState::RegularFile(_))
                    && regular_file_exists_nofollow(root, after.path())?
                    && valid_in_place_mutation_marker(root, envelope, &delta.object_id)?;
                let valid = (source_matches && destination_absent)
                    || (source_absent
                        && (destination_matches_before
                            || destination_matches_after
                            || interrupted_in_place));
                if !valid {
                    return Ok(false);
                }
            }
            (Some(before), None) => {
                if path_exists_nofollow(root, before.path())?
                    && !workspace_state_matches(root, before)?
                {
                    return Ok(false);
                }
            }
            (None, Some(after)) => {
                if path_exists_nofollow(root, after.path())?
                    && !workspace_state_matches(root, after)?
                {
                    return Ok(false);
                }
            }
            (None, None) => return Ok(false),
        }
    }
    Ok(true)
}

fn path_exists_nofollow(root: &Path, path: &str) -> Result<bool, ChangeSetError> {
    match fs::symlink_metadata(resolve_portable(root, path)?) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(operational(error)),
    }
}

fn regular_file_exists_nofollow(root: &Path, path: &str) -> Result<bool, ChangeSetError> {
    match fs::symlink_metadata(resolve_portable(root, path)?) {
        Ok(metadata) => Ok(metadata.is_file() && !metadata.file_type().is_symlink()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(operational(error)),
    }
}

fn valid_in_place_mutation_marker(
    root: &Path,
    envelope: &ChangeSetEnvelope,
    object_id: &str,
) -> Result<bool, ChangeSetError> {
    let marker = change_set_work_directory(root, &envelope.change_set_sha256)
        .join(format!("mutating-{object_id}"));
    let metadata = match fs::symlink_metadata(&marker) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(operational(error)),
    };
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 65 {
        return Ok(false);
    }
    let mut contents = String::new();
    File::open(marker)
        .and_then(|mut file| file.read_to_string(&mut contents))
        .map_err(operational)?;
    Ok(contents == format!("{}\n", envelope.change_set_sha256))
}

fn workspace_matches_after(
    root: &Path,
    envelope: &ChangeSetEnvelope,
) -> Result<bool, ChangeSetError> {
    for delta in &envelope.payload.deltas {
        match &delta.after {
            Some(after) if !workspace_state_matches(root, after)? => return Ok(false),
            None => {
                if let Some(before) = &delta.before
                    && fs::symlink_metadata(resolve_portable(root, before.path())?).is_ok()
                {
                    return Ok(false);
                }
            }
            _ => {}
        }
        if let (Some(before), Some(after)) = (&delta.before, &delta.after)
            && before.path() != after.path()
            && fs::symlink_metadata(resolve_portable(root, before.path())?).is_ok()
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn workspace_state_matches(root: &Path, state: &DeltaState) -> Result<bool, ChangeSetError> {
    workspace_state_matches_at(root, state, state.path())
}

fn workspace_state_matches_at(
    root: &Path,
    state: &DeltaState,
    path: &str,
) -> Result<bool, ChangeSetError> {
    let path = resolve_portable(root, path)?;
    let Ok(metadata) = fs::symlink_metadata(&path) else {
        return Ok(false);
    };
    Ok(match state {
        DeltaState::Directory(_) => metadata.is_dir() && !metadata.file_type().is_symlink(),
        DeltaState::RegularFile(value) => {
            metadata.is_file()
                && !metadata.file_type().is_symlink()
                && metadata.len() == value.bytes
                && is_executable(&metadata) == value.executable
                && sha256_regular(&path, value.bytes)? == value.content_sha256
        }
        DeltaState::Symlink(value) => {
            metadata.file_type().is_symlink()
                && fs::read_link(path).map_err(operational)?.to_string_lossy() == value.target
        }
    })
}

fn attention(
    envelope: &ChangeSetEnvelope,
    code: &str,
    message: &str,
    retryable: bool,
    conflicts: Vec<ChangeSetConflict>,
) -> ChangeSetAttention {
    ChangeSetAttention {
        format: "folderbase-change-set-attention-v1".to_owned(),
        change_set_sha256: envelope.change_set_sha256.clone(),
        attention: ChangeSetAttentionDetail {
            code: code.to_owned(),
            message: message.to_owned(),
            retryable,
            conflicts,
        },
    }
}

fn validate_change_set_envelope(envelope: &ChangeSetEnvelope) -> Result<(), ChangeSetError> {
    let payload = &envelope.payload;
    if envelope.format != "folderbase-change-set-v1"
        || payload.format != "folderbase-change-set-payload-v1"
        || !valid_prefixed_uuid(&payload.change_set_id, "changeset_")
        || !valid_prefixed_uuid(&payload.checkout_id, "checkout_")
        || !valid_prefixed_uuid(&payload.folderbase_id, "folderbase_")
        || !valid_prefixed_uuid(&payload.projection_id, "projection_")
        || !valid_prefixed_uuid(&payload.folder_scope_id, "folderscope_")
        || !is_sha256(&payload.scope_revision_sha256)
        || !is_sha256(&payload.projection_base_sha256)
        || payload.permission != "can_work"
        || payload.deltas.is_empty()
        || payload.deltas.len() > MAX_CHANGE_SET_ENTRIES
        || change_set_digest(payload)? != envelope.change_set_sha256
    {
        return Err(invalid(
            "invalid_change_set_input",
            "Change Set envelope violates the closed v1 contract",
        ));
    }
    let request = CheckoutRequest {
        format: "folderbase-checkout-request-v1".to_owned(),
        folderbase_id: payload.folderbase_id.clone(),
        projection_id: payload.projection_id.clone(),
        folder_scope_id: payload.folder_scope_id.clone(),
        scope_revision_sha256: payload.scope_revision_sha256.clone(),
        permission: payload.permission.clone(),
        authorized_paths: payload.authorized_paths.clone(),
    };
    validate_checkout_request(&request)?;
    let mut previous = None;
    let mut final_paths = Vec::new();
    for delta in &payload.deltas {
        if !valid_prefixed_uuid(&delta.object_id, "obj_")
            || previous.is_some_and(|prior: &str| prior.as_bytes() >= delta.object_id.as_bytes())
            || (delta.before.is_none() && delta.after.is_none())
            || delta.before == delta.after
        {
            return Err(invalid(
                "invalid_change_set_input",
                "Change Set deltas are not canonical",
            ));
        }
        previous = Some(delta.object_id.as_str());
        for state in [&delta.before, &delta.after].into_iter().flatten() {
            validate_delta_state(state, &payload.authorized_paths)?;
        }
        if let Some(after) = &delta.after {
            final_paths.push(after.path().to_owned());
            if delta.before.is_none()
                && matches!(
                    after,
                    DeltaState::RegularFile(DeltaRegularFile {
                        content: ContentReference::ProjectionBase(_),
                        ..
                    })
                )
            {
                return Err(invalid(
                    "invalid_change_set_input",
                    "created regular-file bytes must be staged",
                ));
            }
        }
    }
    reject_path_collisions(&final_paths, "invalid_change_set_input")?;
    Ok(())
}

fn validate_delta_state(
    state: &DeltaState,
    authorized: &[AuthorizedPath],
) -> Result<(), ChangeSetError> {
    validate_portable_path(state.path())?;
    if !is_authorized(state.path(), authorized) {
        return Err(invalid(
            "invalid_change_set_input",
            "Change Set path exceeds the authorized Folder Scope",
        ));
    }
    match state {
        DeltaState::Directory(value) if value.kind == "directory" => Ok(()),
        DeltaState::RegularFile(value)
            if value.kind == "regular_file"
                && valid_prefixed_uuid(&value.object_version_id, "version_")
                && is_sha256(&value.content_sha256)
                && value.bytes <= MAX_OBJECT_BYTES =>
        {
            match &value.content {
                ContentReference::ProjectionBase(value) if value.source == "projection_base" => {
                    Ok(())
                }
                ContentReference::Staged(value)
                    if value.source == "staged"
                        && valid_prefixed_uuid(&value.staging_id, "staging_")
                        && is_sha256(&value.chunk_manifest_sha256) =>
                {
                    Ok(())
                }
                _ => Err(invalid(
                    "invalid_change_set_input",
                    "regular-file content reference is invalid",
                )),
            }
        }
        DeltaState::Symlink(value)
            if value.kind == "symlink"
                && valid_prefixed_uuid(&value.object_version_id, "version_")
                && value.target_safety == "relative-within-projection" =>
        {
            validate_safe_symlink_target(&value.path, &value.target)
        }
        _ => Err(invalid(
            "invalid_change_set_input",
            "delta state violates the closed v1 contract",
        )),
    }
}

fn read_trusted_projection(
    root: &Path,
    projection_id: &str,
) -> Result<Option<TrustedProjection>, ChangeSetError> {
    let state = FolderbaseState::open_existing_read_only(root).map_err(operational)?;
    let relative = Path::new(PROJECTIONS_DIRECTORY).join(format!("{projection_id}.json"));
    let Some(bytes) = state
        .read_bounded_if_present(&relative, MAX_PROJECTION_RECORD_BYTES)
        .map_err(operational)?
    else {
        return Ok(None);
    };
    let trusted: TrustedProjection = serde_json::from_slice(&bytes)
        .map_err(|error| invalid("invalid_projection_receipt", error.to_string()))?;
    if trusted.format != "folderbase-trusted-projection-v1"
        || trusted.receipt.projection_id != projection_id
        || !valid_prefixed_uuid(&trusted.source_version_id, "fbversion_")
        || !is_sha256(&trusted.source_version_sha256)
    {
        return Err(invalid(
            "invalid_projection_receipt",
            "trusted projection mapping is invalid",
        ));
    }
    validate_receipt(&trusted.receipt)?;
    Ok(Some(trusted))
}

fn payload_matches_projection(payload: &ChangeSetPayload, receipt: &CheckoutReceipt) -> bool {
    payload.checkout_id == receipt.checkout_id
        && payload.folderbase_id == receipt.folderbase_id
        && payload.projection_id == receipt.projection_id
        && payload.folder_scope_id == receipt.folder_scope_id
        && payload.scope_revision_sha256 == receipt.scope_revision_sha256
        && payload.permission == receipt.permission
        && payload.authorized_paths == receipt.authorized_paths
        && payload.projection_base_sha256 == receipt.projection_base_sha256
}

fn inventory_source_scope(
    root: &Path,
    authorized: &[AuthorizedPath],
    exclusions: &[ProjectionExclusion],
) -> Result<Vec<InventoryEntry>, ChangeSetError> {
    let mut entries = Vec::new();
    let nested = exclusions
        .iter()
        .filter(|exclusion| exclusion.reason == "nested-folderbase-boundary")
        .map(|exclusion| exclusion.path.as_str())
        .collect::<BTreeSet<_>>();
    if authorized.len() == 1 && authorized[0].path_prefix.is_none() {
        inventory_scoped_directory(root, "", &nested, &mut entries)?;
    } else {
        for scope in authorized {
            let prefix = scope.path_prefix.as_deref().expect("non-root scope");
            let path = resolve_portable(root, prefix)?;
            let Ok(metadata) = fs::symlink_metadata(&path) else {
                continue;
            };
            if nested.contains(prefix) {
                continue;
            }
            inventory_scoped_node(root, prefix, &path, &metadata, &nested, &mut entries)?;
        }
    }
    entries.sort_by(|left, right| left.path.as_bytes().cmp(right.path.as_bytes()));
    reject_inventory_collisions(&entries)?;
    Ok(entries)
}

fn inventory_version_scope(
    version: &FolderbaseVersion,
    authorized: &[AuthorizedPath],
    exclusions: &[ProjectionExclusion],
) -> Result<Vec<InventoryEntry>, ChangeSetError> {
    let nested = exclusions
        .iter()
        .filter(|exclusion| exclusion.reason == "nested-folderbase-boundary")
        .map(|exclusion| exclusion.path.as_str())
        .collect::<Vec<_>>();
    let mut entries = version
        .bindings()
        .iter()
        .filter(|binding| is_authorized(binding.path(), authorized))
        .filter(|binding| {
            !nested
                .iter()
                .any(|boundary| is_same_or_descendant(binding.path(), boundary))
        })
        .map(projected_entry)
        .collect::<Result<Vec<_>, _>>()?
        .iter()
        .map(InventoryEntry::from_projected)
        .collect::<Vec<_>>();
    entries.sort_by(|left, right| left.path.as_bytes().cmp(right.path.as_bytes()));
    reject_inventory_collisions(&entries)?;
    Ok(entries)
}

fn inventory_scoped_directory(
    root: &Path,
    prefix: &str,
    nested: &BTreeSet<&str>,
    entries: &mut Vec<InventoryEntry>,
) -> Result<(), ChangeSetError> {
    let directory = if prefix.is_empty() {
        root.to_path_buf()
    } else {
        resolve_portable(root, prefix)?
    };
    let mut children = fs::read_dir(&directory)
        .map_err(operational)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(operational)?;
    children.sort_by(|left, right| {
        left.file_name()
            .as_encoded_bytes()
            .cmp(right.file_name().as_encoded_bytes())
    });
    for child in children {
        let name = child
            .file_name()
            .into_string()
            .map_err(|_| invalid("invalid_change_set_input", "source path is not UTF-8"))?;
        let path = if prefix.is_empty() {
            name
        } else {
            format!("{prefix}/{name}")
        };
        if path == ".folderbase" || nested.contains(path.as_str()) {
            continue;
        }
        let metadata = fs::symlink_metadata(child.path()).map_err(operational)?;
        inventory_scoped_node(root, &path, &child.path(), &metadata, nested, entries)?;
    }
    Ok(())
}

fn inventory_scoped_node(
    root: &Path,
    path: &str,
    absolute: &Path,
    metadata: &fs::Metadata,
    nested: &BTreeSet<&str>,
    entries: &mut Vec<InventoryEntry>,
) -> Result<(), ChangeSetError> {
    validate_portable_path(path)?;
    if entries.len() >= MAX_CHANGE_SET_ENTRIES {
        return Err(invalid(
            "invalid_change_set_input",
            "current scoped inventory exceeds the entry limit",
        ));
    }
    if metadata.is_dir() {
        entries.push(InventoryEntry {
            path: path.to_owned(),
            kind: InventoryKind::Directory,
            object_id: None,
            object_version_id: None,
            content_sha256: None,
            bytes: None,
            executable: None,
            target: None,
        });
        inventory_scoped_directory(root, path, nested, entries)
    } else if metadata.is_file() && !metadata.file_type().is_symlink() {
        entries.push(InventoryEntry {
            path: path.to_owned(),
            kind: InventoryKind::RegularFile,
            object_id: None,
            object_version_id: None,
            content_sha256: Some(sha256_regular(absolute, metadata.len())?),
            bytes: Some(metadata.len()),
            executable: Some(is_executable(metadata)),
            target: None,
        });
        Ok(())
    } else if metadata.file_type().is_symlink() {
        let target = fs::read_link(absolute).map_err(operational)?;
        let target = target
            .to_str()
            .ok_or_else(|| invalid("invalid_change_set_input", "symlink target is not UTF-8"))?;
        validate_safe_symlink_target(path, target)?;
        entries.push(InventoryEntry {
            path: path.to_owned(),
            kind: InventoryKind::Symlink,
            object_id: None,
            object_version_id: None,
            content_sha256: None,
            bytes: None,
            executable: None,
            target: Some(target.to_owned()),
        });
        Ok(())
    } else {
        Err(invalid(
            "invalid_change_set_input",
            format!("unsupported current source node: {path}"),
        ))
    }
}

fn verify_staging(staging: &Path, envelope: &ChangeSetEnvelope) -> Result<(), ChangeSetError> {
    let metadata = fs::symlink_metadata(staging).map_err(operational)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(invalid("invalid_staging", "staging root is unsafe"));
    }
    let index: StagingIndex = read_json_bounded_file(
        &staging.join("index.json"),
        MAX_CHANGE_SET_BYTES,
        "invalid_staging",
    )?;
    if index.format != "folderbase-change-set-staging-v1" {
        return Err(invalid(
            "invalid_staging",
            "staging index format is invalid",
        ));
    }
    let mut expected = Vec::new();
    for delta in &envelope.payload.deltas {
        for state in [&delta.before, &delta.after].into_iter().flatten() {
            if let DeltaState::RegularFile(DeltaRegularFile {
                content: ContentReference::Staged(reference),
                ..
            }) = state
            {
                expected.push(StagingObject {
                    staging_id: reference.staging_id.clone(),
                    chunk_manifest_sha256: reference.chunk_manifest_sha256.clone(),
                });
            }
        }
    }
    expected.sort_by(|left, right| left.staging_id.as_bytes().cmp(right.staging_id.as_bytes()));
    if index.objects != expected {
        return Err(invalid(
            "invalid_staging",
            "staging index does not exactly cover Change Set references",
        ));
    }
    let mut expected_files = BTreeSet::from(["index.json".to_owned()]);
    for object in &index.objects {
        if !valid_prefixed_uuid(&object.staging_id, "staging_")
            || !is_sha256(&object.chunk_manifest_sha256)
        {
            return Err(invalid("invalid_staging", "staging object is invalid"));
        }
        let relative = format!("manifests/{}.json", object.chunk_manifest_sha256);
        expected_files.insert(relative.clone());
        let manifest_path = staging.join(&relative);
        let manifest =
            ChunkManifest::decode_bounded(File::open(&manifest_path).map_err(operational)?)
                .map_err(|error| invalid("invalid_staging", error.to_string()))?;
        if manifest.canonical_digest().map_err(operational)? != object.chunk_manifest_sha256 {
            return Err(invalid("invalid_staging", "chunk manifest digest changed"));
        }
        let mut object_hasher = Sha256::new();
        let mut object_bytes = 0_u64;
        for chunk in &manifest.chunks {
            let chunk_relative = format!("chunks/{}", chunk.sha256);
            expected_files.insert(chunk_relative.clone());
            let chunk_path = staging.join(chunk_relative);
            verify_regular_digest(&chunk_path, chunk.bytes, &chunk.sha256)?;
            let mut file = File::open(&chunk_path).map_err(operational)?;
            let mut buffer = [0_u8; IO_BUFFER_BYTES];
            loop {
                let read = file.read(&mut buffer).map_err(operational)?;
                if read == 0 {
                    break;
                }
                object_hasher.update(&buffer[..read]);
                object_bytes += read as u64;
            }
        }
        if object_bytes != manifest.object_bytes
            || format!("{:x}", object_hasher.finalize()) != manifest.object_sha256
        {
            return Err(invalid("invalid_staging", "staged object digest changed"));
        }
    }
    let actual_files = staging_files(staging)?;
    if actual_files != expected_files {
        return Err(invalid(
            "invalid_staging",
            "staging contains aliases or extra files",
        ));
    }
    Ok(())
}

fn staging_files(staging: &Path) -> Result<BTreeSet<String>, ChangeSetError> {
    fn visit(
        root: &Path,
        directory: &Path,
        files: &mut BTreeSet<String>,
    ) -> Result<(), ChangeSetError> {
        for child in fs::read_dir(directory).map_err(operational)? {
            let child = child.map_err(operational)?;
            let metadata = fs::symlink_metadata(child.path()).map_err(operational)?;
            if metadata.file_type().is_symlink() {
                return Err(invalid("invalid_staging", "staging symlinks are forbidden"));
            }
            if metadata.is_dir() {
                visit(root, &child.path(), files)?;
            } else if metadata.is_file() {
                let relative = child
                    .path()
                    .strip_prefix(root)
                    .map_err(operational)?
                    .components()
                    .map(|component| component.as_os_str().to_string_lossy())
                    .collect::<Vec<_>>()
                    .join("/");
                files.insert(relative);
            } else {
                return Err(invalid(
                    "invalid_staging",
                    "staging special node is forbidden",
                ));
            }
        }
        Ok(())
    }
    let mut files = BTreeSet::new();
    visit(staging, staging, &mut files)?;
    Ok(files)
}

fn assess_conflicts(
    envelope: &ChangeSetEnvelope,
    receipt: &CheckoutReceipt,
    current: &[InventoryEntry],
) -> Vec<ChangeSetConflict> {
    let current_by_path = current
        .iter()
        .map(|entry| (entry.path.as_str(), entry))
        .collect::<BTreeMap<_, _>>();
    let nested = receipt
        .exclusions
        .iter()
        .filter(|exclusion| exclusion.reason == "nested-folderbase-boundary")
        .map(|exclusion| exclusion.path.as_str())
        .collect::<Vec<_>>();
    let mut conflicts = Vec::new();
    for delta in &envelope.payload.deltas {
        let touched = [&delta.before, &delta.after]
            .into_iter()
            .flatten()
            .map(DeltaState::path)
            .collect::<Vec<_>>();
        if let Some(path) = touched.iter().find(|path| {
            nested
                .iter()
                .any(|boundary| is_same_or_descendant(path, boundary))
        }) {
            conflicts.push(ChangeSetConflict {
                code: "nested_boundary".to_owned(),
                path: (*path).to_owned(),
                other_path: None,
                object_id: Some(delta.object_id.clone()),
            });
            continue;
        }
        match (&delta.before, &delta.after) {
            (None, Some(after)) => {
                if current_by_path.contains_key(after.path()) {
                    conflicts.push(conflict("create_create", after.path(), delta, None));
                } else if let Some(alias) = current.iter().find(|entry| {
                    entry.path != after.path()
                        && (collision_key(&entry.path) == collision_key(after.path())
                            || nfc_key(&entry.path) == nfc_key(after.path()))
                }) {
                    conflicts.push(conflict(
                        "path_alias",
                        after.path(),
                        delta,
                        Some(&alias.path),
                    ));
                }
            }
            (Some(before), after) => match current_by_path.get(before.path()) {
                Some(current_entry) => {
                    let base_entry = inventory_from_delta(before);
                    if !base_entry.same_opaque_content_or_metadata(current_entry) {
                        let code = if after.is_none() {
                            "delete_edit"
                        } else if after
                            .as_ref()
                            .is_some_and(|after| after.path() != before.path())
                        {
                            "move_edit"
                        } else {
                            "edit_edit"
                        };
                        conflicts.push(conflict(code, before.path(), delta, None));
                        continue;
                    }
                    if let Some(after) = after
                        && after.path() != before.path()
                    {
                        if current_by_path.contains_key(after.path()) {
                            conflicts.push(conflict(
                                "path_occupied",
                                after.path(),
                                delta,
                                Some(before.path()),
                            ));
                        } else if let Some(alias) = current.iter().find(|entry| {
                            entry.path != before.path()
                                && entry.path != after.path()
                                && (collision_key(&entry.path) == collision_key(after.path())
                                    || nfc_key(&entry.path) == nfc_key(after.path()))
                        }) {
                            conflicts.push(conflict(
                                "path_alias",
                                after.path(),
                                delta,
                                Some(&alias.path),
                            ));
                        }
                    }
                }
                None => {
                    if after.is_some() {
                        conflicts.push(conflict("edit_delete", before.path(), delta, None));
                    }
                }
            },
            (None, None) => unreachable!("validated delta"),
        }
    }
    conflicts.sort_by(|left, right| {
        left.path
            .as_bytes()
            .cmp(right.path.as_bytes())
            .then_with(|| left.code.as_bytes().cmp(right.code.as_bytes()))
    });
    conflicts
}

impl InventoryEntry {
    fn same_opaque_content_or_metadata(&self, other: &Self) -> bool {
        self.kind == other.kind
            && self.content_sha256 == other.content_sha256
            && self.bytes == other.bytes
            && self.executable == other.executable
            && self.target == other.target
    }
}

fn inventory_from_delta(state: &DeltaState) -> InventoryEntry {
    match state {
        DeltaState::Directory(value) => InventoryEntry {
            path: value.path.clone(),
            kind: InventoryKind::Directory,
            object_id: None,
            object_version_id: None,
            content_sha256: None,
            bytes: None,
            executable: None,
            target: None,
        },
        DeltaState::RegularFile(value) => InventoryEntry {
            path: value.path.clone(),
            kind: InventoryKind::RegularFile,
            object_id: None,
            object_version_id: Some(value.object_version_id.clone()),
            content_sha256: Some(value.content_sha256.clone()),
            bytes: Some(value.bytes),
            executable: Some(value.executable),
            target: None,
        },
        DeltaState::Symlink(value) => InventoryEntry {
            path: value.path.clone(),
            kind: InventoryKind::Symlink,
            object_id: None,
            object_version_id: Some(value.object_version_id.clone()),
            content_sha256: None,
            bytes: None,
            executable: None,
            target: Some(value.target.clone()),
        },
    }
}

fn conflict(
    code: &str,
    path: &str,
    delta: &ObjectDelta,
    other_path: Option<&str>,
) -> ChangeSetConflict {
    ChangeSetConflict {
        code: code.to_owned(),
        path: path.to_owned(),
        other_path: other_path.map(ToOwned::to_owned),
        object_id: Some(delta.object_id.clone()),
    }
}

fn scoped_inventory_digest(entries: &[InventoryEntry]) -> Result<String, ChangeSetError> {
    #[derive(Serialize)]
    struct DigestEntry<'a> {
        path: &'a str,
        kind: &'static str,
        content_sha256: Option<&'a str>,
        bytes: Option<u64>,
        executable: Option<bool>,
        target: Option<&'a str>,
    }
    let entries = entries
        .iter()
        .map(|entry| DigestEntry {
            path: &entry.path,
            kind: match entry.kind {
                InventoryKind::Directory => "directory",
                InventoryKind::RegularFile => "regular_file",
                InventoryKind::Symlink => "symlink",
            },
            content_sha256: entry.content_sha256.as_deref(),
            bytes: entry.bytes,
            executable: entry.executable,
            target: entry.target.as_deref(),
        })
        .collect::<Vec<_>>();
    let encoded = serde_json::to_vec(&entries).map_err(operational)?;
    let mut digest = Sha256::new();
    digest.update(b"folderbase-current-projection-v1\0");
    digest.update(encoded);
    Ok(format!("{:x}", digest.finalize()))
}

fn reject_path_collisions(paths: &[String], code: &'static str) -> Result<(), ChangeSetError> {
    let mut exact = BTreeSet::new();
    let mut nfc = BTreeSet::new();
    let mut folded = BTreeSet::new();
    for path in paths {
        if !exact.insert(path.clone())
            || !nfc.insert(nfc_key(path))
            || !folded.insert(collision_key(path))
        {
            return Err(invalid(
                code,
                "paths collide under the portable path policy",
            ));
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InventoryKind {
    Directory,
    RegularFile,
    Symlink,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct InventoryEntry {
    path: String,
    kind: InventoryKind,
    object_id: Option<String>,
    object_version_id: Option<String>,
    content_sha256: Option<String>,
    bytes: Option<u64>,
    executable: Option<bool>,
    target: Option<String>,
}

impl InventoryEntry {
    fn from_projected(entry: &ProjectedEntry) -> Self {
        match entry {
            ProjectedEntry::Directory { path, object_id } => Self {
                path: path.clone(),
                kind: InventoryKind::Directory,
                object_id: Some(object_id.clone()),
                object_version_id: None,
                content_sha256: None,
                bytes: None,
                executable: None,
                target: None,
            },
            ProjectedEntry::RegularFile {
                path,
                object_id,
                object_version_id,
                content_sha256,
                bytes,
                executable,
            } => Self {
                path: path.clone(),
                kind: InventoryKind::RegularFile,
                object_id: Some(object_id.clone()),
                object_version_id: Some(object_version_id.clone()),
                content_sha256: Some(content_sha256.clone()),
                bytes: Some(*bytes),
                executable: Some(*executable),
                target: None,
            },
            ProjectedEntry::Symlink {
                path,
                object_id,
                object_version_id,
                target,
                ..
            } => Self {
                path: path.clone(),
                kind: InventoryKind::Symlink,
                object_id: Some(object_id.clone()),
                object_version_id: Some(object_version_id.clone()),
                content_sha256: None,
                bytes: None,
                executable: None,
                target: Some(target.clone()),
            },
        }
    }

    fn same_state(&self, other: &Self) -> bool {
        self.path == other.path
            && self.kind == other.kind
            && self.content_sha256 == other.content_sha256
            && self.bytes == other.bytes
            && self.executable == other.executable
            && self.target == other.target
    }

    fn same_opaque_content(&self, other: &Self) -> bool {
        self.kind == other.kind
            && match self.kind {
                InventoryKind::Directory => false,
                InventoryKind::RegularFile => {
                    self.content_sha256 == other.content_sha256
                        && self.bytes == other.bytes
                        && self.executable == other.executable
                }
                InventoryKind::Symlink => self.target == other.target,
            }
    }
}

fn inventory_checkout(checkout: &Path) -> Result<Vec<InventoryEntry>, ChangeSetError> {
    let metadata = fs::symlink_metadata(checkout).map_err(operational)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(invalid(
            "invalid_projection_receipt",
            "checkout root is not a no-follow directory",
        ));
    }
    let mut entries = Vec::new();
    inventory_directory(checkout, "", &mut entries)?;
    if entries.len() > MAX_CHANGE_SET_ENTRIES {
        return Err(invalid(
            "invalid_change_set_input",
            "checkout exceeds the Change Set entry limit",
        ));
    }
    entries.sort_by(|left, right| left.path.as_bytes().cmp(right.path.as_bytes()));
    reject_inventory_collisions(&entries)?;
    Ok(entries)
}

fn inventory_directory(
    root: &Path,
    prefix: &str,
    entries: &mut Vec<InventoryEntry>,
) -> Result<(), ChangeSetError> {
    let directory = if prefix.is_empty() {
        root.to_path_buf()
    } else {
        resolve_portable(root, prefix)?
    };
    let mut names = fs::read_dir(&directory)
        .map_err(operational)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(operational)?;
    names.sort_by(|left, right| {
        left.file_name()
            .as_encoded_bytes()
            .cmp(right.file_name().as_encoded_bytes())
    });
    for entry in names {
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| invalid("invalid_change_set_input", "checkout path is not UTF-8"))?;
        let path = if prefix.is_empty() {
            name
        } else {
            format!("{prefix}/{name}")
        };
        if path == ".folderbase" {
            continue;
        }
        validate_portable_path(&path)?;
        let metadata = fs::symlink_metadata(entry.path()).map_err(operational)?;
        if metadata.is_dir() {
            entries.push(InventoryEntry {
                path: path.clone(),
                kind: InventoryKind::Directory,
                object_id: None,
                object_version_id: None,
                content_sha256: None,
                bytes: None,
                executable: None,
                target: None,
            });
            inventory_directory(root, &path, entries)?;
        } else if metadata.is_file() && !metadata.file_type().is_symlink() {
            let digest = sha256_regular(&entry.path(), metadata.len())?;
            entries.push(InventoryEntry {
                path,
                kind: InventoryKind::RegularFile,
                object_id: None,
                object_version_id: None,
                content_sha256: Some(digest),
                bytes: Some(metadata.len()),
                executable: Some(is_executable(&metadata)),
                target: None,
            });
        } else if metadata.file_type().is_symlink() {
            let target = fs::read_link(entry.path()).map_err(operational)?;
            let target = target.to_str().ok_or_else(|| {
                invalid("invalid_change_set_input", "symlink target is not UTF-8")
            })?;
            validate_safe_symlink_target(&path, target)?;
            entries.push(InventoryEntry {
                path,
                kind: InventoryKind::Symlink,
                object_id: None,
                object_version_id: None,
                content_sha256: None,
                bytes: None,
                executable: None,
                target: Some(target.to_owned()),
            });
        } else {
            return Err(invalid(
                "invalid_change_set_input",
                format!("unsupported checkout node: {path}"),
            ));
        }
    }
    Ok(())
}

fn match_inventory(base: &[InventoryEntry], current: &[InventoryEntry]) -> Vec<(usize, usize)> {
    let mut matched_base = BTreeSet::new();
    let mut matched_current = BTreeSet::new();
    let mut result = Vec::new();
    let base_by_path = base
        .iter()
        .enumerate()
        .map(|(index, entry)| (entry.path.as_str(), index))
        .collect::<BTreeMap<_, _>>();
    for (current_index, entry) in current.iter().enumerate() {
        if let Some(base_index) = base_by_path.get(entry.path.as_str()).copied()
            && base[base_index].kind == entry.kind
        {
            matched_base.insert(base_index);
            matched_current.insert(current_index);
            result.push((base_index, current_index));
        }
    }

    // Exact opaque content is a deterministic rename proof.
    for (current_index, entry) in current.iter().enumerate() {
        if matched_current.contains(&current_index) {
            continue;
        }
        let candidates = base
            .iter()
            .enumerate()
            .filter(|(base_index, candidate)| {
                !matched_base.contains(base_index) && candidate.same_opaque_content(entry)
            })
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        if candidates.len() == 1 {
            let base_index = candidates[0];
            matched_base.insert(base_index);
            matched_current.insert(current_index);
            result.push((base_index, current_index));
        }
    }

    // Move-plus-edit has no portable inode in the checkout receipt. Pair only
    // an unambiguous one-to-one remaining file of the same kind; ambiguity is
    // intentionally represented as delete plus create rather than guessed.
    for kind in [InventoryKind::RegularFile, InventoryKind::Symlink] {
        let remaining_base = base
            .iter()
            .enumerate()
            .filter(|(index, entry)| !matched_base.contains(index) && entry.kind == kind)
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        let remaining_current = current
            .iter()
            .enumerate()
            .filter(|(index, entry)| !matched_current.contains(index) && entry.kind == kind)
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        if remaining_base.len() == 1 && remaining_current.len() == 1 {
            matched_base.insert(remaining_base[0]);
            matched_current.insert(remaining_current[0]);
            result.push((remaining_base[0], remaining_current[0]));
        }
    }
    result.sort_unstable();
    result
}

fn delta_state_from_base(entry: &InventoryEntry) -> DeltaState {
    match entry.kind {
        InventoryKind::Directory => DeltaState::Directory(DeltaDirectory {
            path: entry.path.clone(),
            kind: "directory".to_owned(),
        }),
        InventoryKind::RegularFile => DeltaState::RegularFile(DeltaRegularFile {
            path: entry.path.clone(),
            kind: "regular_file".to_owned(),
            object_version_id: entry
                .object_version_id
                .clone()
                .expect("trusted regular file has Object Version"),
            content_sha256: entry
                .content_sha256
                .clone()
                .expect("trusted regular file has digest"),
            bytes: entry.bytes.expect("trusted regular file has length"),
            executable: entry.executable.unwrap_or(false),
            content: ContentReference::ProjectionBase(ProjectionBaseContent {
                source: "projection_base".to_owned(),
            }),
        }),
        InventoryKind::Symlink => DeltaState::Symlink(DeltaSymlink {
            path: entry.path.clone(),
            kind: "symlink".to_owned(),
            object_version_id: entry
                .object_version_id
                .clone()
                .expect("trusted symlink has Object Version"),
            target: entry.target.clone().expect("trusted symlink has target"),
            target_safety: "relative-within-projection".to_owned(),
        }),
    }
}

fn delta_state_from_current(
    checkout: &Path,
    staging: &Path,
    entry: &InventoryEntry,
    base: Option<&InventoryEntry>,
    staged_objects: &mut Vec<StagingObject>,
) -> Result<DeltaState, ChangeSetError> {
    Ok(match entry.kind {
        InventoryKind::Directory => DeltaState::Directory(DeltaDirectory {
            path: entry.path.clone(),
            kind: "directory".to_owned(),
        }),
        InventoryKind::RegularFile => {
            let reuses_base = base.is_some_and(|base| {
                base.content_sha256 == entry.content_sha256
                    && base.bytes == entry.bytes
                    && base.executable == entry.executable
            });
            let object_version_id = if reuses_base {
                base.and_then(|base| base.object_version_id.clone())
                    .expect("base regular file has Object Version")
            } else {
                format!("version_{}", Uuid::now_v7())
            };
            let content = if reuses_base {
                ContentReference::ProjectionBase(ProjectionBaseContent {
                    source: "projection_base".to_owned(),
                })
            } else {
                let staged = stage_regular_file(
                    &resolve_portable(checkout, &entry.path)?,
                    staging,
                    entry.bytes.expect("regular file has byte length"),
                )?;
                staged_objects.push(StagingObject {
                    staging_id: staged.staging_id.clone(),
                    chunk_manifest_sha256: staged.chunk_manifest_sha256.clone(),
                });
                ContentReference::Staged(staged)
            };
            DeltaState::RegularFile(DeltaRegularFile {
                path: entry.path.clone(),
                kind: "regular_file".to_owned(),
                object_version_id,
                content_sha256: entry
                    .content_sha256
                    .clone()
                    .expect("regular file has digest"),
                bytes: entry.bytes.expect("regular file has byte length"),
                executable: entry.executable.unwrap_or(false),
                content,
            })
        }
        InventoryKind::Symlink => {
            let reuses_base = base.is_some_and(|base| base.target == entry.target);
            DeltaState::Symlink(DeltaSymlink {
                path: entry.path.clone(),
                kind: "symlink".to_owned(),
                object_version_id: if reuses_base {
                    base.and_then(|base| base.object_version_id.clone())
                        .expect("base symlink has Object Version")
                } else {
                    format!("version_{}", Uuid::now_v7())
                },
                target: entry.target.clone().expect("symlink has target"),
                target_safety: "relative-within-projection".to_owned(),
            })
        }
    })
}

fn stage_regular_file(
    source: &Path,
    staging: &Path,
    expected_bytes: u64,
) -> Result<StagedContent, ChangeSetError> {
    if expected_bytes > MAX_OBJECT_BYTES {
        return Err(invalid(
            "invalid_change_set_input",
            "regular file exceeds the 1 TiB object limit",
        ));
    }
    let profile = if expected_bytes >= LARGE_PROFILE_THRESHOLD_BYTES {
        LARGE_PROFILE_V1
    } else {
        STANDARD_PROFILE_V1
    };
    let mut file = File::open(source).map_err(operational)?;
    let manifest = plan_streamed_manifest(
        Read::by_ref(&mut file).take(expected_bytes.saturating_add(1)),
        profile,
    )
    .map_err(operational)?;
    if manifest.object_bytes != expected_bytes {
        return Err(invalid(
            "invalid_change_set_input",
            "checkout file changed while staging",
        ));
    }
    let manifest_sha256 = manifest.canonical_digest().map_err(operational)?;
    file.seek(SeekFrom::Start(0)).map_err(operational)?;
    for chunk in &manifest.chunks {
        file.seek(SeekFrom::Start(chunk.offset))
            .map_err(operational)?;
        install_staging_chunk(
            &mut file,
            &staging.join("chunks").join(&chunk.sha256),
            chunk.bytes,
            &chunk.sha256,
        )?;
    }
    let manifest_bytes = serde_json::to_vec(&manifest).map_err(operational)?;
    create_new_file(
        &staging
            .join("manifests")
            .join(format!("{manifest_sha256}.json")),
        &manifest_bytes,
    )?;
    Ok(StagedContent {
        source: "staged".to_owned(),
        staging_id: format!("staging_{}", Uuid::now_v7()),
        chunk_manifest_sha256: manifest_sha256,
    })
}

fn install_staging_chunk(
    source: &mut File,
    target: &Path,
    expected_bytes: u64,
    expected_sha256: &str,
) -> Result<(), ChangeSetError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    let mut target_file = match options.open(target) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            verify_regular_digest(target, expected_bytes, expected_sha256)?;
            return Ok(());
        }
        Err(error) => return Err(operational(error)),
    };
    let mut remaining = expected_bytes;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; IO_BUFFER_BYTES];
    while remaining > 0 {
        let wanted = usize::try_from(remaining.min(buffer.len() as u64))
            .expect("bounded I/O length fits usize");
        let read = source.read(&mut buffer[..wanted]).map_err(operational)?;
        if read == 0 {
            return Err(invalid(
                "invalid_change_set_input",
                "checkout file shortened while staging",
            ));
        }
        hasher.update(&buffer[..read]);
        target_file
            .write_all(&buffer[..read])
            .map_err(operational)?;
        remaining -= read as u64;
    }
    target_file.sync_all().map_err(operational)?;
    if format!("{:x}", hasher.finalize()) != expected_sha256 {
        return Err(invalid(
            "invalid_change_set_input",
            "checkout file changed while staging",
        ));
    }
    Ok(())
}

fn change_set_digest(payload: &ChangeSetPayload) -> Result<String, ChangeSetError> {
    let encoded = serde_json::to_vec(payload).map_err(operational)?;
    let mut digest = Sha256::new();
    digest.update(b"folderbase-change-set-v1\0");
    digest.update(encoded);
    Ok(format!("{:x}", digest.finalize()))
}

fn validate_receipt(receipt: &CheckoutReceipt) -> Result<(), ChangeSetError> {
    if receipt.format != "folderbase-checkout-projection-v1"
        || !valid_prefixed_uuid(&receipt.checkout_id, "checkout_")
        || !valid_prefixed_uuid(&receipt.folderbase_id, "folderbase_")
        || !valid_prefixed_uuid(&receipt.projection_id, "projection_")
        || !valid_prefixed_uuid(&receipt.folder_scope_id, "folderscope_")
        || !is_sha256(&receipt.scope_revision_sha256)
        || !is_sha256(&receipt.projection_base_sha256)
        || receipt.permission != "can_work"
        || receipt.entries.len() > MAX_CHANGE_SET_ENTRIES
        || receipt.exclusions.len() > MAX_CHANGE_SET_ENTRIES
    {
        return Err(invalid(
            "invalid_projection_receipt",
            "checkout receipt violates the closed v1 contract",
        ));
    }
    let request = CheckoutRequest {
        format: "folderbase-checkout-request-v1".to_owned(),
        folderbase_id: receipt.folderbase_id.clone(),
        projection_id: receipt.projection_id.clone(),
        folder_scope_id: receipt.folder_scope_id.clone(),
        scope_revision_sha256: receipt.scope_revision_sha256.clone(),
        permission: receipt.permission.clone(),
        authorized_paths: receipt.authorized_paths.clone(),
    };
    validate_checkout_request(&request)?;
    if projection_digest(&request, &receipt.entries, &receipt.exclusions)?
        != receipt.projection_base_sha256
    {
        return Err(invalid(
            "invalid_projection_receipt",
            "checkout receipt digest does not match its scoped contents",
        ));
    }
    Ok(())
}

fn read_json_bounded_file<T: for<'de> Deserialize<'de>>(
    path: &Path,
    maximum_bytes: u64,
    code: &'static str,
) -> Result<T, ChangeSetError> {
    let metadata = fs::symlink_metadata(path).map_err(operational)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > maximum_bytes {
        return Err(invalid(code, "JSON record is unsafe or exceeds its bound"));
    }
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(operational)?
        .take(maximum_bytes + 1)
        .read_to_end(&mut bytes)
        .map_err(operational)?;
    if bytes.len() as u64 > maximum_bytes {
        return Err(invalid(code, "JSON record exceeds its bound"));
    }
    serde_json::from_slice(&bytes).map_err(|error| invalid(code, error.to_string()))
}

fn sha256_regular(path: &Path, expected_bytes: u64) -> Result<String, ChangeSetError> {
    let mut file = File::open(path).map_err(operational)?;
    let mut hasher = Sha256::new();
    let mut observed = 0_u64;
    let mut buffer = [0_u8; IO_BUFFER_BYTES];
    loop {
        let read = file.read(&mut buffer).map_err(operational)?;
        if read == 0 {
            break;
        }
        observed = observed
            .checked_add(read as u64)
            .ok_or_else(|| invalid("invalid_change_set_input", "file length overflowed"))?;
        if observed > expected_bytes {
            return Err(invalid(
                "invalid_change_set_input",
                "checkout file grew during observation",
            ));
        }
        hasher.update(&buffer[..read]);
    }
    if observed != expected_bytes {
        return Err(invalid(
            "invalid_change_set_input",
            "checkout file changed during observation",
        ));
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn verify_regular_digest(
    path: &Path,
    expected_bytes: u64,
    expected_sha256: &str,
) -> Result<(), ChangeSetError> {
    let metadata = fs::symlink_metadata(path).map_err(operational)?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() != expected_bytes
        || sha256_regular(path, expected_bytes)? != expected_sha256
    {
        return Err(invalid(
            "invalid_staging",
            "staged chunk failed verification",
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn is_executable(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn is_executable(_metadata: &fs::Metadata) -> bool {
    false
}

fn validate_safe_symlink_target(path: &str, target: &str) -> Result<(), ChangeSetError> {
    if target.is_empty() || target.contains('\\') || Path::new(target).is_absolute() {
        return Err(invalid(
            "invalid_change_set_input",
            format!("unsafe symlink target at {path}"),
        ));
    }
    let mut depth = path.split('/').count().saturating_sub(1) as isize;
    for component in target.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                depth -= 1;
                if depth < 0 {
                    return Err(invalid(
                        "invalid_change_set_input",
                        format!("symlink escapes checkout at {path}"),
                    ));
                }
            }
            _ => depth += 1,
        }
    }
    Ok(())
}

fn reject_inventory_collisions(entries: &[InventoryEntry]) -> Result<(), ChangeSetError> {
    let mut exact = BTreeSet::new();
    let mut nfc = BTreeSet::new();
    let mut folded = BTreeSet::new();
    for entry in entries {
        if !exact.insert(entry.path.clone())
            || !nfc.insert(nfc_key(&entry.path))
            || !folded.insert(collision_key(&entry.path))
        {
            return Err(invalid(
                "invalid_change_set_input",
                "checkout paths collide under the portable path policy",
            ));
        }
    }
    Ok(())
}

fn projected_entry(binding: &PathBinding) -> Result<ProjectedEntry, ChangeSetError> {
    Ok(match binding.kind() {
        PathBindingKind::Directory => ProjectedEntry::Directory {
            path: binding.path().to_owned(),
            object_id: binding.object_id().to_owned(),
        },
        PathBindingKind::RegularFile => ProjectedEntry::RegularFile {
            path: binding.path().to_owned(),
            object_id: binding.object_id().to_owned(),
            object_version_id: binding
                .object_version_id()
                .ok_or_else(|| operational_message("regular binding omitted Object Version"))?
                .to_owned(),
            content_sha256: binding
                .content_sha256()
                .ok_or_else(|| operational_message("regular binding omitted content digest"))?
                .to_owned(),
            bytes: binding
                .bytes()
                .ok_or_else(|| operational_message("regular binding omitted byte length"))?,
            executable: binding.executable().unwrap_or(false),
        },
        PathBindingKind::Symlink => ProjectedEntry::Symlink {
            path: binding.path().to_owned(),
            object_id: binding.object_id().to_owned(),
            object_version_id: binding
                .object_version_id()
                .ok_or_else(|| operational_message("symlink binding omitted Object Version"))?
                .to_owned(),
            target: binding
                .symlink_target()
                .ok_or_else(|| operational_message("symlink binding omitted target"))?
                .to_owned(),
            target_safety: "relative-within-projection".to_owned(),
        },
    })
}

#[derive(Serialize)]
struct ProjectionDigest<'a> {
    format: &'static str,
    folderbase_id: &'a str,
    projection_id: &'a str,
    folder_scope_id: &'a str,
    scope_revision_sha256: &'a str,
    permission: &'a str,
    authorized_paths: &'a [AuthorizedPath],
    entries: &'a [ProjectedEntry],
    exclusions: &'a [ProjectionExclusion],
}

fn projection_digest(
    request: &CheckoutRequest,
    entries: &[ProjectedEntry],
    exclusions: &[ProjectionExclusion],
) -> Result<String, ChangeSetError> {
    let encoded = serde_json::to_vec(&ProjectionDigest {
        format: "folderbase-projection-base-v1",
        folderbase_id: &request.folderbase_id,
        projection_id: &request.projection_id,
        folder_scope_id: &request.folder_scope_id,
        scope_revision_sha256: &request.scope_revision_sha256,
        permission: &request.permission,
        authorized_paths: &request.authorized_paths,
        entries,
        exclusions,
    })
    .map_err(operational)?;
    let mut digest = Sha256::new();
    digest.update(b"folderbase-projection-base-v1\0");
    digest.update(encoded);
    Ok(format!("{:x}", digest.finalize()))
}

fn materialize_checkout(
    root: &Path,
    destination: &Path,
    receipt: &CheckoutReceipt,
) -> Result<(), ChangeSetError> {
    fs::create_dir(destination).map_err(operational)?;
    fs::create_dir(destination.join(".folderbase")).map_err(operational)?;

    for entry in &receipt.entries {
        if matches!(entry, ProjectedEntry::Directory { .. }) {
            fs::create_dir_all(resolve_portable(destination, entry.path())?)
                .map_err(operational)?;
        }
    }
    for entry in &receipt.entries {
        match entry {
            ProjectedEntry::Directory { .. } => {}
            ProjectedEntry::RegularFile {
                path,
                content_sha256,
                bytes,
                executable,
                ..
            } => {
                let source = resolve_portable(root, path)?;
                let target = resolve_portable(destination, path)?;
                if let Some(parent) = target.parent() {
                    fs::create_dir_all(parent).map_err(operational)?;
                }
                copy_regular_verified(&source, &target, content_sha256, *bytes, *executable)?;
            }
            ProjectedEntry::Symlink { path, target, .. } => {
                materialize_symlink(destination, path, target)?;
            }
        }
    }

    let encoded = encode_pretty_bounded(receipt, MAX_PROJECTION_RECORD_BYTES)?;
    create_new_file(&destination.join(".folderbase/checkout.json"), &encoded)?;
    Ok(())
}

fn install_trusted_projection(
    root: &Path,
    trusted: &TrustedProjection,
) -> Result<(), ChangeSetError> {
    let state = FolderbaseState::open_existing(root).map_err(operational)?;
    state
        .ensure_private_dir(Path::new(PROJECTIONS_DIRECTORY))
        .map_err(operational)?;
    let relative =
        Path::new(PROJECTIONS_DIRECTORY).join(format!("{}.json", trusted.receipt.projection_id));
    let encoded = encode_pretty_bounded(trusted, MAX_PROJECTION_RECORD_BYTES)?;
    state.publish_new(&relative, &encoded).map_err(operational)
}

fn validate_checkout_request(request: &CheckoutRequest) -> Result<(), ChangeSetError> {
    if request.format != "folderbase-checkout-request-v1"
        || request.permission != "can_work"
        || !valid_prefixed_uuid(&request.folderbase_id, "folderbase_")
        || !valid_prefixed_uuid(&request.projection_id, "projection_")
        || !valid_prefixed_uuid(&request.folder_scope_id, "folderscope_")
        || !is_sha256(&request.scope_revision_sha256)
        || request.authorized_paths.is_empty()
        || request.authorized_paths.len() > 256
    {
        return Err(invalid(
            "invalid_checkout_request",
            "checkout request violates the closed v1 contract",
        ));
    }
    let mut previous: Option<&str> = None;
    for path in &request.authorized_paths {
        if let Some(prefix) = path.path_prefix.as_deref() {
            validate_portable_path(prefix)?;
            if prefix == ".folderbase" || prefix.starts_with(".folderbase/") {
                return Err(invalid(
                    "invalid_checkout_request",
                    "protocol state cannot be authorized as ordinary content",
                ));
            }
            if previous.is_some_and(|prior| prior.as_bytes() >= prefix.as_bytes()) {
                return Err(invalid(
                    "invalid_checkout_request",
                    "authorized paths must be strictly byte-sorted",
                ));
            }
            previous = Some(prefix);
        } else if request.authorized_paths.len() != 1 {
            return Err(invalid(
                "invalid_checkout_request",
                "complete-root authority cannot overlap another prefix",
            ));
        }
    }
    for (index, left) in request.authorized_paths.iter().enumerate() {
        for right in request.authorized_paths.iter().skip(index + 1) {
            let (Some(left), Some(right)) =
                (left.path_prefix.as_deref(), right.path_prefix.as_deref())
            else {
                continue;
            };
            if is_same_or_descendant(right, left)
                || collision_key(left) == collision_key(right)
                || nfc_key(left) == nfc_key(right)
            {
                return Err(invalid(
                    "invalid_checkout_request",
                    "authorized paths overlap or collide",
                ));
            }
        }
    }
    Ok(())
}

fn is_authorized(path: &str, authorized: &[AuthorizedPath]) -> bool {
    authorized.iter().any(|scope| {
        scope
            .path_prefix
            .as_deref()
            .is_none_or(|prefix| is_same_or_descendant(path, prefix))
    }) && path != ".folderbase"
        && !path.starts_with(".folderbase/")
}

fn is_same_or_descendant(path: &str, prefix: &str) -> bool {
    path == prefix
        || path
            .strip_prefix(prefix)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

fn require_new_destination(destination: &Path) -> Result<(), ChangeSetError> {
    if destination.as_os_str().is_empty() || destination.exists() {
        return Err(invalid(
            "invalid_checkout_request",
            "checkout destination must be new and absent",
        ));
    }
    let parent = destination.parent().ok_or_else(|| {
        invalid(
            "invalid_checkout_request",
            "checkout destination has no parent",
        )
    })?;
    let metadata = fs::symlink_metadata(parent).map_err(operational)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(invalid(
            "invalid_checkout_request",
            "checkout parent must be a no-follow directory",
        ));
    }
    Ok(())
}

fn copy_regular_verified(
    source: &Path,
    target: &Path,
    expected_sha256: &str,
    expected_bytes: u64,
    executable: bool,
) -> Result<(), ChangeSetError> {
    let source_metadata = fs::symlink_metadata(source).map_err(operational)?;
    if !source_metadata.is_file()
        || source_metadata.file_type().is_symlink()
        || source_metadata.len() != expected_bytes
    {
        return Err(operational_message(
            "source changed before checkout materialization",
        ));
    }
    let mut input = File::open(source).map_err(operational)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    let mut output = options.open(target).map_err(operational)?;
    let mut hasher = Sha256::new();
    let mut observed = 0_u64;
    let mut buffer = [0_u8; IO_BUFFER_BYTES];
    loop {
        let read = input.read(&mut buffer).map_err(operational)?;
        if read == 0 {
            break;
        }
        observed = observed
            .checked_add(read as u64)
            .ok_or_else(|| operational_message("source byte length overflowed"))?;
        if observed > expected_bytes {
            return Err(operational_message(
                "source grew during checkout materialization",
            ));
        }
        hasher.update(&buffer[..read]);
        output.write_all(&buffer[..read]).map_err(operational)?;
    }
    output.sync_all().map_err(operational)?;
    if observed != expected_bytes || format!("{:x}", hasher.finalize()) != expected_sha256 {
        return Err(operational_message(
            "source changed during checkout materialization",
        ));
    }
    set_executable(target, executable)?;
    Ok(())
}

#[cfg(unix)]
fn set_executable(path: &Path, executable: bool) -> Result<(), ChangeSetError> {
    use std::os::unix::fs::PermissionsExt;
    let mode = if executable { 0o700 } else { 0o600 };
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(operational)
}

#[cfg(not(unix))]
fn set_executable(_path: &Path, _executable: bool) -> Result<(), ChangeSetError> {
    Ok(())
}

#[cfg(unix)]
fn materialize_symlink(destination: &Path, path: &str, target: &str) -> Result<(), ChangeSetError> {
    use std::os::unix::fs::symlink;
    let link = resolve_portable(destination, path)?;
    if let Some(parent) = link.parent() {
        fs::create_dir_all(parent).map_err(operational)?;
    }
    symlink(target, link).map_err(operational)
}

#[cfg(windows)]
fn materialize_symlink(destination: &Path, path: &str, target: &str) -> Result<(), ChangeSetError> {
    use std::os::windows::fs::symlink_file;
    let link = resolve_portable(destination, path)?;
    if let Some(parent) = link.parent() {
        fs::create_dir_all(parent).map_err(operational)?;
    }
    symlink_file(target, link).map_err(operational)
}

fn create_new_file(path: &Path, bytes: &[u8]) -> Result<(), ChangeSetError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    let mut file = options.open(path).map_err(operational)?;
    file.write_all(bytes).map_err(operational)?;
    file.sync_all().map_err(operational)
}

#[cfg(not(windows))]
fn sync_directory(path: &Path) -> Result<(), ChangeSetError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(operational)
}

#[cfg(windows)]
fn sync_directory(_path: &Path) -> Result<(), ChangeSetError> {
    Ok(())
}

fn encode_pretty_bounded(value: &impl Serialize, maximum: u64) -> Result<Vec<u8>, ChangeSetError> {
    let mut encoded = serde_json::to_vec_pretty(value).map_err(operational)?;
    encoded.push(b'\n');
    if encoded.len() as u64 > maximum {
        return Err(operational_message(
            "encoded Change Set record exceeds its bound",
        ));
    }
    Ok(encoded)
}

fn resolve_portable(root: &Path, path: &str) -> Result<PathBuf, ChangeSetError> {
    validate_portable_path(path)?;
    let mut resolved = root.to_path_buf();
    for component in Path::new(path).components() {
        let Component::Normal(component) = component else {
            return Err(invalid(
                "invalid_projection_receipt",
                "path is not portable",
            ));
        };
        resolved.push(component);
    }
    Ok(resolved)
}

fn validate_portable_path(path: &str) -> Result<(), ChangeSetError> {
    validate_capture_path(path)
        .map_err(|_| invalid("invalid_projection_receipt", "path is not portable"))
}

fn collision_key(path: &str) -> String {
    path.chars().case_fold().collect::<String>().nfc().collect()
}

fn nfc_key(path: &str) -> String {
    path.nfc().collect()
}

fn valid_prefixed_uuid(value: &str, prefix: &str) -> bool {
    value
        .strip_prefix(prefix)
        .and_then(|suffix| Uuid::parse_str(suffix).ok())
        .is_some()
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn invalid(code: &'static str, message: impl Into<String>) -> ChangeSetError {
    ChangeSetError::Invalid {
        code,
        message: message.into(),
    }
}

fn operational(error: impl std::fmt::Display) -> ChangeSetError {
    ChangeSetError::Operational {
        code: "change_set_operational_error",
        message: error.to_string(),
    }
}

fn operational_message(message: impl Into<String>) -> ChangeSetError {
    ChangeSetError::Operational {
        code: "change_set_operational_error",
        message: message.into(),
    }
}

fn capture_operational(error: FolderbaseCaptureError) -> ChangeSetError {
    operational(error)
}

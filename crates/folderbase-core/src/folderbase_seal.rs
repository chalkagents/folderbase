//! Durable, byte-verified Folderbase Version capture and device-local Head.
//!
//! Capture journals IDs before installing immutable records. The Folderbase
//! Version remains the only full-state manifest; mutable object projections and
//! Local Head are derived, recoverable local state.

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fs::{File, OpenOptions},
    io::{Read, Write},
    ops::Deref,
    path::{Component, Path, PathBuf},
};

use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt};
use cap_std::fs::{Dir, OpenOptions as CapOpenOptions};
use chrono::{SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    FolderbaseError,
    folderbase_capture::{
        CaptureEntryKind, CaptureExclusionKind, CaptureExclusionReason, CaptureLocalHead,
        CaptureMetadataFingerprint, CapturePlan, CapturePlanEntry, FolderbaseCaptureError,
        FolderbaseVersionStore, LocalHeadAuthority, capture_entry_fingerprint,
        restore_authority_count, version_derived_local_head_sha256,
    },
    folderbase_restore_authority::{
        MAX_RESTORE_AUTHORITIES, MAX_RESTORE_AUTHORITY_BYTES, RESTORE_AUTHORITY_FORMAT_V1,
        RestoreAuthorityRecord, restore_authority_record_path,
    },
    folderbase_state::FolderbaseState,
    folderbase_version::{
        DeletedKind, Exclusion, ExclusionKind, ExclusionReason, FolderbaseVersion,
        FolderbaseVersionEntries, FolderbaseVersionParts, MAX_ENCODED_VERSION_BYTES, PathBinding,
        PathBindingKind, RootManifest, Tombstone, validate_capture_version_id,
    },
    local_versions::{
        ContentDigest, LocalObjectRecord, LocalVersionRecord, LocalVersionStore, ObjectId,
        ObjectLifecycle, ObjectProvenance, VersionId, safe_content_path,
    },
    root_attestation::{attest_folderbase_root, metadata_is_link_or_reparse},
};

#[cfg(test)]
use crate::folderbase_restore_authority::RESTORE_AUTHORITY_FILENAME;

const CAPTURE_TRANSACTION_FORMAT_V1: &str = "folderbase-capture-transaction-v1";
const CAPTURE_TRANSACTIONS_DIRECTORY: &str = ".folderbase/transactions/folderbase-version-captures";
const ACTIVE_CAPTURE_TRANSACTION_PATH: &str =
    ".folderbase/transactions/folderbase-version-captures/active.json";
const RESTORE_TRANSACTION_FORMAT_V1: &str = "folderbase-tombstone-restore-v1";
const RESTORE_TRANSACTIONS_DIRECTORY: &str = ".folderbase/transactions/folderbase-version-restores";
const ACTIVE_RESTORE_TRANSACTION_PATH: &str =
    ".folderbase/transactions/folderbase-version-restores/active.json";
const RESTORE_CLEANUP_RECOVERY_PATH: &str =
    ".folderbase/transactions/folderbase-version-restores/cleanup.json";
const RESTORE_CLEANUP_RECOVERY_FORMAT_V2: &str = "folderbase-restore-cleanup-v2";
const RESTORE_COMPLETION_PATH: &str = ".folderbase/local/completed-restore.json";
const RESTORE_COMPLETION_FORMAT_V2: &str = "folderbase-restore-completion-v2";
const FOLDERBASE_VERSIONS_DIRECTORY: &str = ".folderbase/versions/folderbase";
const CAPTURE_IDENTITIES_DIRECTORY: &str = ".folderbase/local/capture-identities";
const LOCAL_HEAD_PATH: &str = ".folderbase/local/head.json";
const IO_BUFFER_BYTES: usize = 64 * 1024;
const MAX_CAPTURE_TRANSACTION_BYTES: u64 = MAX_ENCODED_VERSION_BYTES;

/// Result of sealing or converging on one durable device-local Folderbase Version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedCapture {
    version_id: String,
    version_sha256: String,
    created: bool,
}

/// Result of restoring the exact bytes named by one current-Head Tombstone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RestoredTombstone {
    path: PathBuf,
    object_id: String,
    object_version_id: String,
    version_id: String,
    version_sha256: String,
    created: bool,
}

impl RestoredTombstone {
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn object_id(&self) -> &str {
        &self.object_id
    }

    pub fn object_version_id(&self) -> &str {
        &self.object_version_id
    }

    pub fn version_id(&self) -> &str {
        &self.version_id
    }

    pub fn version_sha256(&self) -> &str {
        &self.version_sha256
    }

    pub fn created(&self) -> bool {
        self.created
    }
}

impl SealedCapture {
    pub fn version_id(&self) -> &str {
        &self.version_id
    }

    pub fn version_sha256(&self) -> &str {
        &self.version_sha256
    }

    /// Whether this call advanced Local Head to a newly sealed version.
    pub fn created(&self) -> bool {
        self.created
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CaptureCheckpoint {
    StateCapabilityOpen,
    BeforeObjectBytesRead(String),
    JournalDurable,
    ObjectWritesDurable,
    VersionDurable,
    HeadReplaced,
    CleanupComplete,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum RestoreCheckpoint {
    JournalDurable,
    StageDurable,
    TargetPublished,
    VersionDurable,
    HeadReplaced,
    PublicationVerified,
    ProjectionDurable,
    CleanupRecoveryDurable,
    BeforeStageRetirement,
    AfterStageRetirement,
    CleanupIntentRetired,
    CompletionDurable,
    CleanupComplete,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct JournalHead {
    version_id: String,
    version_sha256: String,
    authority: LocalHeadAuthority,
}

impl From<&CaptureLocalHead> for JournalHead {
    fn from(value: &CaptureLocalHead) -> Self {
        Self {
            version_id: value.version_id().to_owned(),
            version_sha256: value.version_sha256().to_owned(),
            authority: value.authority().clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CaptureAssignment {
    path: String,
    kind: CaptureEntryKind,
    object_id: String,
    candidate_object_version_id: Option<String>,
    prior_object_version_id: Option<String>,
    reused_object: bool,
    observed: CaptureMetadataFingerprint,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CaptureTransaction {
    format: String,
    transaction_id: String,
    folderbase_id: String,
    root_instance_sha256: String,
    plan_sha256: String,
    expected_head: Option<JournalHead>,
    target_version_id: String,
    created_at: String,
    root_manifest_object_id: String,
    root_manifest_candidate_version_id: String,
    prior_root_manifest_version_id: Option<String>,
    assignments: Vec<CaptureAssignment>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    target_tombstones: Vec<Tombstone>,
}

#[derive(Debug)]
struct ActiveCaptureTransaction {
    transaction: CaptureTransaction,
    authority_sha256: String,
}

impl Deref for ActiveCaptureTransaction {
    type Target = CaptureTransaction;

    fn deref(&self) -> &Self::Target {
        &self.transaction
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleasedV1JournalHead {
    version_id: String,
    version_sha256: String,
    transaction_sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleasedV1CaptureTransaction {
    format: String,
    transaction_id: String,
    folderbase_id: String,
    root_instance_sha256: String,
    plan_sha256: String,
    expected_head: Option<ReleasedV1JournalHead>,
    target_version_id: String,
    created_at: String,
    root_manifest_object_id: String,
    root_manifest_candidate_version_id: String,
    prior_root_manifest_version_id: Option<String>,
    assignments: Vec<CaptureAssignment>,
    #[serde(default)]
    target_tombstones: Vec<Tombstone>,
}

impl From<ReleasedV1CaptureTransaction> for CaptureTransaction {
    fn from(value: ReleasedV1CaptureTransaction) -> Self {
        Self {
            format: value.format,
            transaction_id: value.transaction_id,
            folderbase_id: value.folderbase_id,
            root_instance_sha256: value.root_instance_sha256,
            plan_sha256: value.plan_sha256,
            expected_head: value.expected_head.map(|head| JournalHead {
                version_id: head.version_id,
                version_sha256: head.version_sha256,
                authority: LocalHeadAuthority::CaptureTransactionV1 {
                    sha256: head.transaction_sha256,
                },
            }),
            target_version_id: value.target_version_id,
            created_at: value.created_at,
            root_manifest_object_id: value.root_manifest_object_id,
            root_manifest_candidate_version_id: value.root_manifest_candidate_version_id,
            prior_root_manifest_version_id: value.prior_root_manifest_version_id,
            assignments: value.assignments,
            target_tombstones: value.target_tombstones,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RestoreTransaction {
    format: String,
    transaction_id: String,
    folderbase_id: String,
    root_instance_sha256: String,
    expected_head: JournalHead,
    target_version_id: String,
    target_version_sha256: String,
    created_at: String,
    path: String,
    tombstone: Tombstone,
    binding: PathBinding,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RestoreCleanupDisposition {
    Committed,
    Modified,
    CommittedModified,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RestoreCleanupOutcome {
    Restored,
    WorkspaceModified,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RestoreCleanupRecovery {
    format: String,
    disposition: RestoreCleanupDisposition,
    transaction: RestoreTransaction,
    published_identity_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RestoreCompletionReceipt {
    format: String,
    transaction: RestoreTransaction,
    published_identity_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
struct LocalHeadRecord {
    format: String,
    folderbase_id: String,
    root_instance_sha256: String,
    version_id: String,
    version_sha256: String,
    authority: LocalHeadAuthority,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum LocalHeadRecordWire {
    V2(LocalHeadRecordV2Wire),
    V1(LocalHeadRecordV1Wire),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalHeadRecordV2Wire {
    format: String,
    folderbase_id: String,
    root_instance_sha256: String,
    version_id: String,
    version_sha256: String,
    authority: LocalHeadAuthority,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalHeadRecordV1Wire {
    format: String,
    folderbase_id: String,
    root_instance_sha256: String,
    version_id: String,
    version_sha256: String,
    transaction_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CaptureIdentityRecord {
    format: String,
    object_id: String,
    kind: CaptureEntryKind,
    observed: CaptureMetadataFingerprint,
}

struct BuiltCapture {
    version: FolderbaseVersion,
    version_sha256: String,
    regular_projections: Vec<LocalObjectRecord>,
}

impl FolderbaseVersionStore {
    /// Verify every included byte, install immutable records append-only, and
    /// advance this device's Local Head only after all references verify.
    pub fn seal_capture(&self, plan: CapturePlan) -> Result<SealedCapture, FolderbaseCaptureError> {
        self.seal_capture_with_hook(plan, |_| {})
    }

    /// Read one complete append-only Folderbase Version and verify every
    /// referenced local Object Version and content blob.
    pub fn read_version(
        &self,
        version_id: &str,
    ) -> Result<FolderbaseVersion, FolderbaseCaptureError> {
        let local = LocalVersionStore::open_read_only(&self.root_attestation.root)?;
        let state = FolderbaseState::open_existing_read_only(&self.root_attestation.root)?;
        read_and_verify_folderbase_version(self, &local, &state, version_id)
    }

    /// Restore the exact ordinary-file bytes named by a Tombstone in the
    /// current verified Local Head.
    ///
    /// Restore is same-path and no-clobber. It creates one new full-state
    /// Folderbase Version and advances Local Head only after the file and all
    /// immutable references verify.
    pub fn restore_tombstone(
        &self,
        portable_path: &str,
    ) -> Result<RestoredTombstone, FolderbaseCaptureError> {
        self.restore_tombstone_with_hook_and_authority_limit(
            portable_path,
            |_| {},
            MAX_RESTORE_AUTHORITIES,
        )
    }

    #[cfg(test)]
    fn restore_tombstone_with_hook(
        &self,
        portable_path: &str,
        checkpoint: impl FnMut(&RestoreCheckpoint),
    ) -> Result<RestoredTombstone, FolderbaseCaptureError> {
        self.restore_tombstone_with_hook_and_authority_limit(
            portable_path,
            checkpoint,
            MAX_RESTORE_AUTHORITIES,
        )
    }

    fn restore_tombstone_with_hook_and_authority_limit(
        &self,
        portable_path: &str,
        mut checkpoint: impl FnMut(&RestoreCheckpoint),
        maximum_restore_authorities: usize,
    ) -> Result<RestoredTombstone, FolderbaseCaptureError> {
        let path = safe_content_path(Path::new(portable_path))?;
        let path_string = path
            .to_str()
            .expect("safe content paths are UTF-8")
            .to_owned();
        verify_restore_root_instance(self)?;
        let local = LocalVersionStore::open_read_only(&self.root_attestation.root)?;
        let state = FolderbaseState::open_existing(&self.root_attestation.root)?;
        let _lock = local.acquire_transaction_lock_in(&state)?;
        verify_restore_root_instance(self)?;
        state.verify_still_attached()?;
        state.ensure_private_dir(Path::new(RESTORE_TRANSACTIONS_DIRECTORY))?;
        state.ensure_private_dir(Path::new(FOLDERBASE_VERSIONS_DIRECTORY))?;
        ensure_no_active_capture(&state)?;

        let active = read_active_restore_transaction(&state)?;
        if let Some(recovery) = read_restore_cleanup_recovery(&state)? {
            if recovery.transaction.path != path_string {
                return Err(FolderbaseCaptureError::ConflictingTransaction(
                    "a different Tombstone restore cleanup is pending",
                ));
            }
            if active
                .as_ref()
                .is_some_and(|active| active != &recovery.transaction)
            {
                return Err(FolderbaseCaptureError::InvalidRestoreTransaction(
                    "active restore and cleanup recovery name different transactions".to_owned(),
                ));
            }
            return match recovery.disposition {
                RestoreCleanupDisposition::Committed => finish_restore_cleanup_recovery(
                    self,
                    &local,
                    &state,
                    &recovery.transaction,
                    &recovery.published_identity_sha256,
                    &mut checkpoint,
                ),
                RestoreCleanupDisposition::Modified => {
                    finish_modified_restore_cleanup_recovery(
                        self,
                        &local,
                        &state,
                        &recovery.transaction,
                        &recovery.published_identity_sha256,
                        &mut checkpoint,
                    )?;
                    Err(FolderbaseCaptureError::RestoreTargetOccupied(path))
                }
                RestoreCleanupDisposition::CommittedModified => {
                    finish_committed_modified_restore_cleanup_recovery(
                        self,
                        &local,
                        &state,
                        &recovery.transaction,
                        &recovery.published_identity_sha256,
                        &mut checkpoint,
                    )?;
                    Err(FolderbaseCaptureError::RestoreTargetOccupied(path))
                }
            };
        }
        if active.is_none()
            && let Some(completion) = read_restore_completion_receipt(&state)?
            && completion.transaction.path == path_string
            && let Some(restored) = completed_restore_result(
                self,
                &local,
                &state,
                &completion.transaction,
                &completion.published_identity_sha256,
            )?
        {
            return Ok(restored);
        }
        let transaction = match active {
            Some(transaction) => {
                validate_restore_transaction(self, &transaction)?;
                if transaction.path != path_string {
                    return Err(FolderbaseCaptureError::ConflictingTransaction(
                        "a different Tombstone restore is pending",
                    ));
                }
                transaction
            }
            None => {
                if !state.workspace_path_is_absent(&path)? {
                    return Err(FolderbaseCaptureError::RestoreTargetOccupied(path));
                }
                if restore_authority_count(&self.root_attestation, maximum_restore_authorities)?
                    >= maximum_restore_authorities
                {
                    return Err(
                        FolderbaseCaptureError::RestoreAuthorityMaintenanceRequired {
                            maximum: maximum_restore_authorities,
                        },
                    );
                }
                let mut head =
                    read_head_record(&state)?.ok_or(FolderbaseCaptureError::MissingLocalHead)?;
                if head.folderbase_id != self.root_attestation.folderbase_id
                    || head.root_instance_sha256 != self.root_attestation.root_instance_sha256
                {
                    return Err(FolderbaseCaptureError::InvalidLocalHead(
                        "Local Head belongs to a different Folderbase Root".to_owned(),
                    ));
                }
                let current =
                    read_and_verify_folderbase_version(self, &local, &state, &head.version_id)?;
                if current.canonical_digest()? != head.version_sha256 {
                    return Err(FolderbaseCaptureError::InvalidLocalHead(
                        "Local Head digest does not match its Folderbase Version".to_owned(),
                    ));
                }
                let tombstone = current
                    .tombstones()
                    .iter()
                    .find(|tombstone| tombstone.path() == path_string)
                    .cloned()
                    .ok_or_else(|| FolderbaseCaptureError::TombstoneNotFound(path.to_path_buf()))?;
                if tombstone.deleted_kind() != DeletedKind::RegularFile {
                    return Err(FolderbaseCaptureError::UnsupportedTombstoneKind(
                        path.to_path_buf(),
                    ));
                }
                let binding = find_restore_binding(self, &local, &state, &current, &tombstone)?;
                let restore_authority_sha256 =
                    local_head_authority_sha256(self, &head.version_id, &head.version_sha256)?;
                let restore_authority = LocalHeadAuthority::VersionDerivedV1 {
                    sha256: restore_authority_sha256,
                };
                if head.authority != restore_authority {
                    let rebound = LocalHeadRecord {
                        format: "folderbase-local-head-v2".to_owned(),
                        authority: restore_authority,
                        ..head.clone()
                    };
                    compare_and_swap_exact_local_head(&state, &head, &rebound)?;
                    head = rebound;
                }
                let transaction =
                    build_restore_transaction(self, &head, &current, tombstone, binding)?;
                write_active_restore_transaction(&state, &transaction)?;
                checkpoint(&RestoreCheckpoint::JournalDurable);
                transaction
            }
        };

        let result =
            execute_restore_transaction(self, &local, &state, &transaction, &mut checkpoint);
        if result.is_err() {
            retire_modified_restore(self, &local, &state, &transaction, &mut checkpoint)?;
        }
        result
    }

    fn seal_capture_with_hook(
        &self,
        plan: CapturePlan,
        checkpoint: impl FnMut(&CaptureCheckpoint),
    ) -> Result<SealedCapture, FolderbaseCaptureError> {
        self.seal_capture_with_hook_and_limits(
            plan,
            checkpoint,
            MAX_CAPTURE_TRANSACTION_BYTES,
            MAX_ENCODED_VERSION_BYTES,
        )
    }

    fn seal_capture_with_hook_and_limits(
        &self,
        plan: CapturePlan,
        mut checkpoint: impl FnMut(&CaptureCheckpoint),
        maximum_transaction_bytes: u64,
        maximum_version_bytes: u64,
    ) -> Result<SealedCapture, FolderbaseCaptureError> {
        if plan.root() != self.root_attestation.root
            || plan.folderbase_id() != self.root_attestation.folderbase_id
            || plan.root_instance_sha256() != self.root_attestation.root_instance_sha256
        {
            return Err(FolderbaseCaptureError::PlanStoreMismatch);
        }

        let local = LocalVersionStore::open_read_only(&self.root_attestation.root)?;
        let state = FolderbaseState::open_existing(&self.root_attestation.root)?;
        checkpoint(&CaptureCheckpoint::StateCapabilityOpen);

        let current_plan = self.plan_capture()?;
        ensure_same_plan(&plan, &current_plan)?;
        state.verify_still_attached()?;

        let _lock = local.acquire_transaction_lock_in(&state)?;
        for relative in [
            ".folderbase/objects",
            ".folderbase/versions/records",
            ".folderbase/versions/blobs/sha256",
        ] {
            state.ensure_private_dir(Path::new(relative))?;
        }
        state.ensure_private_dir(Path::new(CAPTURE_TRANSACTIONS_DIRECTORY))?;
        state.ensure_private_dir(Path::new(RESTORE_TRANSACTIONS_DIRECTORY))?;
        ensure_no_active_restore(&state)?;
        state.ensure_private_dir(Path::new(FOLDERBASE_VERSIONS_DIRECTORY))?;
        state.ensure_private_dir(Path::new(CAPTURE_IDENTITIES_DIRECTORY))?;
        normalize_legacy_local_head(&state)?;

        let current_plan = self.plan_capture()?;
        ensure_same_plan(&plan, &current_plan)?;
        let plan_sha256 = capture_plan_sha256(&plan)?;
        let current_head = current_plan.current_local_head().map(JournalHead::from);
        let mut active = read_active_transaction(&state)?;

        if let Some(transaction) = active.as_ref() {
            validate_transaction(self, transaction)?;
            let target_head = current_head
                .as_ref()
                .filter(|head| head.version_id == transaction.target_version_id);
            if let Some(head) = target_head {
                if head.authority
                    != (LocalHeadAuthority::CaptureTransactionV1 {
                        sha256: transaction.authority_sha256.clone(),
                    })
                {
                    return Err(FolderbaseCaptureError::InvalidCaptureTransaction(
                        "active journal digest does not match Local Head".to_owned(),
                    ));
                }
                let version = read_and_verify_folderbase_version(
                    self,
                    &local,
                    &state,
                    &transaction.target_version_id,
                )?;
                if version.canonical_digest()? != head.version_sha256 {
                    return Err(FolderbaseCaptureError::InvalidCaptureTransaction(
                        "Local Head target digest does not match its complete Folderbase Version"
                            .to_owned(),
                    ));
                }
                let transaction_prior = load_transaction_prior(
                    self,
                    &local,
                    &state,
                    transaction.expected_head.as_ref(),
                )?;
                validate_committed_transaction(transaction, &version, transaction_prior.as_ref())?;
                finish_committed_transaction(self, &local, &state, transaction)?;
                remove_active_transaction(&state)?;
                checkpoint(&CaptureCheckpoint::CleanupComplete);
                active = None;
            } else if transaction.expected_head != current_head {
                return Err(FolderbaseCaptureError::LocalHeadChanged);
            } else if transaction.plan_sha256 != plan_sha256 {
                let prior = load_prior_head(self, &local, &state, plan.current_local_head())?;
                ensure_prior_bindings_observable(&plan, prior.as_ref())?;
                // The old Head still owns authority. Immutable records already
                // installed by the abandoned attempt remain safe orphans;
                // removing only the active intent permits a fresh assignment.
                remove_active_transaction(&state)?;
                active = None;
            }
        }

        let prior = load_prior_head(self, &local, &state, plan.current_local_head())?;
        ensure_prior_bindings_observable(&plan, prior.as_ref())?;
        if active.is_none()
            && live_state_matches_prior(
                self,
                &plan,
                &local,
                &state,
                prior.as_ref(),
                &mut checkpoint,
            )?
        {
            let head = plan
                .current_local_head()
                .expect("matched prior requires Head");
            return Ok(SealedCapture {
                version_id: head.version_id().to_owned(),
                version_sha256: head.version_sha256().to_owned(),
                created: false,
            });
        }

        let transaction = match active {
            Some(transaction) => transaction,
            None => {
                let transaction = assign_capture_transaction(&plan, &plan_sha256, prior.as_ref())?;
                preflight_capture_envelopes(
                    &plan,
                    &transaction,
                    maximum_transaction_bytes,
                    maximum_version_bytes,
                )?;
                let authority_sha256 = write_active_transaction_with_limit(
                    &state,
                    &transaction,
                    maximum_transaction_bytes,
                )?;
                checkpoint(&CaptureCheckpoint::JournalDurable);
                ActiveCaptureTransaction {
                    transaction,
                    authority_sha256,
                }
            }
        };

        if transaction.plan_sha256 != plan_sha256
            || transaction.expected_head != plan.current_local_head().map(JournalHead::from)
        {
            return Err(FolderbaseCaptureError::InvalidCaptureTransaction(
                "active intent does not match the approved CapturePlan".to_owned(),
            ));
        }
        validate_transaction_against_plan(&plan, &transaction, prior.as_ref())?;
        preflight_capture_envelopes(
            &plan,
            &transaction,
            maximum_transaction_bytes,
            maximum_version_bytes,
        )?;

        let built = build_and_install_capture(
            self,
            &plan,
            &local,
            &state,
            &transaction,
            prior.as_ref(),
            &mut checkpoint,
        )?;
        checkpoint(&CaptureCheckpoint::ObjectWritesDurable);
        install_folderbase_version(&state, &built.version, &built.version_sha256)?;
        let installed =
            read_and_verify_folderbase_version(self, &local, &state, built.version.version_id())?;
        if installed.canonical_digest()? != built.version_sha256 {
            return Err(FolderbaseCaptureError::InvalidCaptureTransaction(
                "installed Folderbase Version digest changed".to_owned(),
            ));
        }
        checkpoint(&CaptureCheckpoint::VersionDurable);

        let final_plan = self.plan_capture()?;
        ensure_same_plan(&plan, &final_plan)?;
        compare_and_swap_local_head(
            &state,
            plan.current_local_head(),
            &LocalHeadRecord {
                format: "folderbase-local-head-v2".to_owned(),
                folderbase_id: self.root_attestation.folderbase_id.clone(),
                root_instance_sha256: self.root_attestation.root_instance_sha256.clone(),
                version_id: built.version.version_id().to_owned(),
                version_sha256: built.version_sha256.clone(),
                authority: LocalHeadAuthority::CaptureTransactionV1 {
                    sha256: transaction.authority_sha256.clone(),
                },
            },
        )?;
        checkpoint(&CaptureCheckpoint::HeadReplaced);

        for projection in &built.regular_projections {
            local.write_capture_object_projection_in(&state, projection)?;
        }
        write_capture_identities(&state, &transaction)?;
        remove_active_transaction(&state)?;
        checkpoint(&CaptureCheckpoint::CleanupComplete);

        Ok(SealedCapture {
            version_id: built.version.version_id().to_owned(),
            version_sha256: built.version_sha256,
            created: true,
        })
    }
}

fn build_restore_transaction(
    store: &FolderbaseVersionStore,
    head: &LocalHeadRecord,
    current: &FolderbaseVersion,
    tombstone: Tombstone,
    binding: PathBinding,
) -> Result<RestoreTransaction, FolderbaseCaptureError> {
    let (transaction_id, target_version_id, created_at) =
        assigned_restore_identity(store, head, current, &tombstone, &binding)?;
    let target = restored_version(
        store,
        current,
        &target_version_id,
        &created_at,
        &tombstone,
        &binding,
    )?;
    let transaction = RestoreTransaction {
        format: RESTORE_TRANSACTION_FORMAT_V1.to_owned(),
        transaction_id,
        folderbase_id: store.root_attestation.folderbase_id.clone(),
        root_instance_sha256: store.root_attestation.root_instance_sha256.clone(),
        expected_head: JournalHead::from(head),
        target_version_id,
        target_version_sha256: target.canonical_digest()?,
        created_at,
        path: tombstone.path().to_owned(),
        tombstone,
        binding,
    };
    validate_restore_transaction(store, &transaction)?;
    // Bound all serialized intent before any journal or workspace mutation.
    let _ = encode_restore_transaction(&transaction)?;
    Ok(transaction)
}

fn assigned_restore_identity(
    store: &FolderbaseVersionStore,
    head: &LocalHeadRecord,
    current: &FolderbaseVersion,
    tombstone: &Tombstone,
    binding: &PathBinding,
) -> Result<(String, String, String), FolderbaseCaptureError> {
    #[derive(Serialize)]
    struct RestoreAuthority<'a> {
        format: &'static str,
        folderbase_id: &'a str,
        root_instance_sha256: &'a str,
        expected_head: JournalHead,
        tombstone: &'a Tombstone,
        binding: &'a PathBinding,
    }

    let authority = serde_json::to_vec(&RestoreAuthority {
        format: "folderbase-tombstone-restore-authority-v1",
        folderbase_id: &store.root_attestation.folderbase_id,
        root_instance_sha256: &store.root_attestation.root_instance_sha256,
        expected_head: JournalHead::from(head),
        tombstone,
        binding,
    })
    .map_err(|source| {
        FolderbaseCaptureError::InvalidRestoreTransaction(format!(
            "restore authority encoding failed: {source}"
        ))
    })?;
    let assigned_uuid = |domain: &[u8]| {
        let mut digest = Sha256::new();
        digest.update(domain);
        digest.update(&authority);
        let digest = digest.finalize();
        let mut bytes = [0_u8; 16];
        bytes.copy_from_slice(&digest[..16]);
        bytes[6] = (bytes[6] & 0x0f) | 0x80;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        Uuid::from_bytes(bytes).hyphenated().to_string()
    };
    Ok((
        format!("fbrestore_{}", assigned_uuid(b"transaction")),
        format!("fbversion_{}", assigned_uuid(b"version")),
        current.created_at().to_owned(),
    ))
}

fn restored_version(
    store: &FolderbaseVersionStore,
    current: &FolderbaseVersion,
    target_version_id: &str,
    created_at: &str,
    tombstone: &Tombstone,
    binding: &PathBinding,
) -> Result<FolderbaseVersion, FolderbaseCaptureError> {
    if current.folderbase_id() != store.root_attestation.folderbase_id {
        return Err(FolderbaseCaptureError::InvalidRestoreTransaction(
            "restore parent belongs to a different Folderbase".to_owned(),
        ));
    }
    let mut bindings = current.bindings().to_vec();
    bindings.push(binding.clone());
    bindings.sort_by(|left, right| left.path().as_bytes().cmp(right.path().as_bytes()));
    let tombstones = current
        .tombstones()
        .iter()
        .filter(|candidate| **candidate != *tombstone)
        .cloned()
        .collect();
    let entries = FolderbaseVersionEntries::from_verified_producer(
        bindings,
        tombstones,
        current.exclusions().to_vec(),
    );
    Ok(FolderbaseVersion::from_verified_parts(
        FolderbaseVersionParts::portable_v1_from_verified_producer(
            store.root_attestation.folderbase_id.clone(),
            target_version_id.to_owned(),
            vec![current.version_id().to_owned()],
            created_at.to_owned(),
            current.root_manifest().clone(),
            entries,
        ),
    )?)
}

fn find_restore_binding(
    store: &FolderbaseVersionStore,
    local: &LocalVersionStore,
    state: &FolderbaseState,
    current: &FolderbaseVersion,
    tombstone: &Tombstone,
) -> Result<PathBinding, FolderbaseCaptureError> {
    find_restore_binding_with_limit(
        store,
        local,
        state,
        current,
        tombstone,
        crate::folderbase_version::MAX_VERSION_ENTRIES,
    )
}

fn find_restore_binding_with_limit(
    store: &FolderbaseVersionStore,
    local: &LocalVersionStore,
    state: &FolderbaseState,
    current: &FolderbaseVersion,
    tombstone: &Tombstone,
    maximum_ancestors: usize,
) -> Result<PathBinding, FolderbaseCaptureError> {
    let expected_version = tombstone.last_object_version_id().ok_or_else(|| {
        FolderbaseCaptureError::InvalidRestoreAncestry(
            "regular-file Tombstone omitted its Object Version".to_owned(),
        )
    })?;
    let mut queue = VecDeque::new();
    for parent in current.parents() {
        queue.push_back((parent.clone(), 1_usize));
    }
    let mut expanded = BTreeSet::new();
    let mut adjacency =
        BTreeMap::from([(current.version_id().to_owned(), current.parents().to_vec())]);
    let mut visited = 0_usize;
    let mut candidates = Vec::new();
    let mut candidate_depth = None;
    while let Some((version_id, depth)) = queue.pop_front() {
        if !expanded.insert(version_id.clone()) {
            continue;
        }
        visited += 1;
        if visited > maximum_ancestors {
            return Err(FolderbaseCaptureError::InvalidRestoreAncestry(
                "ancestor search exceeded the bounded version limit".to_owned(),
            ));
        }
        let version = read_and_verify_folderbase_version(store, local, state, &version_id)
            .map_err(|error| {
                FolderbaseCaptureError::InvalidRestoreAncestry(format!(
                    "ancestor {version_id} could not be verified: {error}"
                ))
            })?;
        adjacency.insert(version_id.clone(), version.parents().to_vec());
        if let Some(binding) = version.lookup_binding(tombstone.path())
            && binding.kind() == PathBindingKind::RegularFile
            && binding.object_id() == tombstone.object_id()
            && binding.object_version_id() == Some(expected_version)
            && candidate_depth.is_none_or(|candidate_depth| candidate_depth == depth)
        {
            candidate_depth.get_or_insert(depth);
            candidates.push(binding.clone());
        }
        for parent in version.parents() {
            queue.push_back((parent.clone(), depth + 1));
        }
    }
    ensure_restore_ancestry_acyclic(&adjacency)?;
    if !candidates.is_empty() {
        return unique_restore_candidate(candidates, tombstone);
    }
    Err(FolderbaseCaptureError::InvalidRestoreAncestry(format!(
        "no verified live ancestor preserves exact fidelity for {}",
        tombstone.path()
    )))
}

fn ensure_restore_ancestry_acyclic(
    adjacency: &BTreeMap<String, Vec<String>>,
) -> Result<(), FolderbaseCaptureError> {
    let mut incoming = adjacency
        .keys()
        .map(|version_id| (version_id.clone(), 0_usize))
        .collect::<BTreeMap<_, _>>();
    for parents in adjacency.values() {
        for parent in parents {
            let Some(count) = incoming.get_mut(parent) else {
                return Err(FolderbaseCaptureError::InvalidRestoreAncestry(format!(
                    "ancestor graph omitted reachable version {parent}"
                )));
            };
            *count = count.saturating_add(1);
        }
    }
    let mut ready = incoming
        .iter()
        .filter_map(|(version_id, count)| (*count == 0).then_some(version_id.clone()))
        .collect::<VecDeque<_>>();
    let mut removed = 0_usize;
    while let Some(version_id) = ready.pop_front() {
        removed += 1;
        for parent in adjacency
            .get(&version_id)
            .expect("ready versions came from adjacency")
        {
            let count = incoming
                .get_mut(parent)
                .expect("all reachable parents are in adjacency");
            *count -= 1;
            if *count == 0 {
                ready.push_back(parent.clone());
            }
        }
    }
    if removed != adjacency.len() {
        return Err(FolderbaseCaptureError::InvalidRestoreAncestry(
            "ancestor graph contains a cycle".to_owned(),
        ));
    }
    Ok(())
}

fn unique_restore_candidate(
    candidates: Vec<PathBinding>,
    tombstone: &Tombstone,
) -> Result<PathBinding, FolderbaseCaptureError> {
    let first = candidates
        .first()
        .expect("candidate set is known non-empty")
        .clone();
    if candidates.iter().any(|candidate| candidate != &first) {
        return Err(FolderbaseCaptureError::InvalidRestoreAncestry(format!(
            "nearest ancestors disagree about fidelity for {}",
            tombstone.path()
        )));
    }
    Ok(first)
}

fn execute_restore_transaction(
    store: &FolderbaseVersionStore,
    local: &LocalVersionStore,
    state: &FolderbaseState,
    transaction: &RestoreTransaction,
    checkpoint: &mut impl FnMut(&RestoreCheckpoint),
) -> Result<RestoredTombstone, FolderbaseCaptureError> {
    verify_restore_root_instance(store)?;
    state.verify_still_attached()?;
    validate_restore_transaction(store, transaction)?;
    let current_head = read_head_record(state)?.ok_or(FolderbaseCaptureError::MissingLocalHead)?;
    if current_head.folderbase_id != store.root_attestation.folderbase_id
        || current_head.root_instance_sha256 != store.root_attestation.root_instance_sha256
    {
        return Err(FolderbaseCaptureError::InvalidLocalHead(
            "Local Head belongs to a different Folderbase Root".to_owned(),
        ));
    }
    let current_summary = JournalHead::from(&current_head);
    let target_summary = JournalHead {
        version_id: transaction.target_version_id.clone(),
        version_sha256: transaction.target_version_sha256.clone(),
        authority: LocalHeadAuthority::VersionDerivedV1 {
            sha256: local_head_authority_sha256(
                store,
                &transaction.target_version_id,
                &transaction.target_version_sha256,
            )?,
        },
    };
    let target = derive_authoritative_restore_target(store, local, state, transaction)?;
    let created = if current_summary == target_summary {
        let installed = read_and_verify_folderbase_version(
            store,
            local,
            state,
            &transaction.target_version_id,
        )?;
        if installed.canonical_digest()? != transaction.target_version_sha256 {
            return Err(FolderbaseCaptureError::InvalidRestoreTransaction(
                "committed target digest changed".to_owned(),
            ));
        }
        if let Err(error) =
            finish_restore_materialization(store, local, state, transaction, checkpoint)
        {
            rollback_restore_head(store, state, transaction)?;
            return Err(error);
        }
        false
    } else if current_summary == transaction.expected_head {
        stage_and_publish_restore(state, transaction, checkpoint)?;
        install_folderbase_version(state, &target, &transaction.target_version_sha256)?;
        let installed = read_and_verify_folderbase_version(
            store,
            local,
            state,
            &transaction.target_version_id,
        )?;
        if installed.canonical_digest()? != transaction.target_version_sha256 {
            return Err(FolderbaseCaptureError::InvalidRestoreTransaction(
                "installed restore version failed verification".to_owned(),
            ));
        }
        checkpoint(&RestoreCheckpoint::VersionDurable);
        verify_restore_publication(store, state, transaction)?;
        compare_and_swap_restore_head(
            state,
            &transaction.expected_head,
            &LocalHeadRecord {
                format: "folderbase-local-head-v2".to_owned(),
                folderbase_id: transaction.folderbase_id.clone(),
                root_instance_sha256: transaction.root_instance_sha256.clone(),
                version_id: transaction.target_version_id.clone(),
                version_sha256: transaction.target_version_sha256.clone(),
                authority: LocalHeadAuthority::VersionDerivedV1 {
                    sha256: local_head_authority_sha256(
                        store,
                        &transaction.target_version_id,
                        &transaction.target_version_sha256,
                    )?,
                },
            },
        )?;
        checkpoint(&RestoreCheckpoint::HeadReplaced);
        if let Err(error) = verify_restore_publication(store, state, transaction) {
            rollback_restore_head(store, state, transaction)?;
            return Err(error);
        }
        checkpoint(&RestoreCheckpoint::PublicationVerified);
        if let Err(error) = finish_restore_projection(store, local, state, transaction)
            .and_then(|()| verify_restore_publication(store, state, transaction))
        {
            rollback_restore_head(store, state, transaction)?;
            return Err(error);
        }
        checkpoint(&RestoreCheckpoint::ProjectionDurable);
        true
    } else {
        return Err(FolderbaseCaptureError::LocalHeadChanged);
    };

    if finish_restore_cleanup(state, transaction, checkpoint)?
        == RestoreCleanupOutcome::WorkspaceModified
    {
        return Err(FolderbaseCaptureError::RestoreTargetOccupied(
            PathBuf::from(&transaction.path),
        ));
    }
    checkpoint(&RestoreCheckpoint::CleanupComplete);
    Ok(restored_tombstone(transaction, created))
}

fn restored_tombstone(transaction: &RestoreTransaction, created: bool) -> RestoredTombstone {
    RestoredTombstone {
        path: PathBuf::from(&transaction.path),
        object_id: transaction.binding.object_id().to_owned(),
        object_version_id: transaction
            .binding
            .object_version_id()
            .expect("validated regular binding")
            .to_owned(),
        version_id: transaction.target_version_id.clone(),
        version_sha256: transaction.target_version_sha256.clone(),
        created,
    }
}

fn finish_restore_cleanup_recovery(
    store: &FolderbaseVersionStore,
    local: &LocalVersionStore,
    state: &FolderbaseState,
    transaction: &RestoreTransaction,
    published_identity_sha256: &str,
    checkpoint: &mut impl FnMut(&RestoreCheckpoint),
) -> Result<RestoredTombstone, FolderbaseCaptureError> {
    validate_restore_transaction(store, transaction)?;
    let target = derive_authoritative_restore_target(store, local, state, transaction)?;
    if target.canonical_digest()? != transaction.target_version_sha256 {
        return Err(FolderbaseCaptureError::InvalidRestoreTransaction(
            "cleanup recovery target digest changed".to_owned(),
        ));
    }
    let target_head = JournalHead {
        version_id: transaction.target_version_id.clone(),
        version_sha256: transaction.target_version_sha256.clone(),
        authority: LocalHeadAuthority::VersionDerivedV1 {
            sha256: local_head_authority_sha256(
                store,
                &transaction.target_version_id,
                &transaction.target_version_sha256,
            )?,
        },
    };
    let current_head = read_head_record(state)?.ok_or(FolderbaseCaptureError::MissingLocalHead)?;
    if JournalHead::from(&current_head) != target_head {
        return Err(FolderbaseCaptureError::LocalHeadChanged);
    }
    let installed =
        read_and_verify_folderbase_version(store, local, state, &transaction.target_version_id)?;
    if installed.canonical_digest()? != transaction.target_version_sha256 {
        return Err(FolderbaseCaptureError::InvalidRestoreTransaction(
            "cleanup recovery installed version changed".to_owned(),
        ));
    }

    if finish_restore_cleanup_with_identity(
        state,
        transaction,
        published_identity_sha256,
        checkpoint,
    )? == RestoreCleanupOutcome::WorkspaceModified
    {
        return Err(FolderbaseCaptureError::RestoreTargetOccupied(
            PathBuf::from(&transaction.path),
        ));
    }
    checkpoint(&RestoreCheckpoint::CleanupComplete);
    Ok(restored_tombstone(transaction, false))
}

fn finish_restore_cleanup(
    state: &FolderbaseState,
    transaction: &RestoreTransaction,
    checkpoint: &mut impl FnMut(&RestoreCheckpoint),
) -> Result<RestoreCleanupOutcome, FolderbaseCaptureError> {
    let published_identity_sha256 = state.workspace_restore_identity_sha256(
        &restore_stage_path(transaction),
        Path::new(&transaction.path),
    )?;
    finish_restore_cleanup_with_identity(state, transaction, &published_identity_sha256, checkpoint)
}

fn finish_restore_cleanup_with_identity(
    state: &FolderbaseState,
    transaction: &RestoreTransaction,
    published_identity_sha256: &str,
    checkpoint: &mut impl FnMut(&RestoreCheckpoint),
) -> Result<RestoreCleanupOutcome, FolderbaseCaptureError> {
    let committed = RestoreCleanupRecovery {
        format: RESTORE_CLEANUP_RECOVERY_FORMAT_V2.to_owned(),
        disposition: RestoreCleanupDisposition::Committed,
        transaction: transaction.clone(),
        published_identity_sha256: published_identity_sha256.to_owned(),
    };
    write_restore_cleanup_recovery(state, &committed)?;
    checkpoint(&RestoreCheckpoint::CleanupRecoveryDurable);
    let digest = transaction
        .binding
        .content_sha256()
        .expect("validated regular binding");
    let bytes = transaction
        .binding
        .bytes()
        .expect("validated regular binding");
    let executable = transaction
        .binding
        .executable()
        .expect("validated regular binding");
    let retirement = state.retain_workspace_restore_authority_with_hook(
        &restore_stage_path(transaction),
        Path::new(&transaction.path),
        published_identity_sha256,
        Some((digest, bytes, executable)),
        |stage_removed| {
            checkpoint(if stage_removed {
                &RestoreCheckpoint::AfterStageRetirement
            } else {
                &RestoreCheckpoint::BeforeStageRetirement
            });
        },
    );
    if let Err(error) = retirement {
        let modified_observation = state.workspace_restore_was_modified_in_place(
            &restore_stage_path(transaction),
            Path::new(&transaction.path),
            digest,
            bytes,
            executable,
        );
        if matches!(modified_observation, Ok(true)) {
            let modified = RestoreCleanupRecovery {
                format: RESTORE_CLEANUP_RECOVERY_FORMAT_V2.to_owned(),
                disposition: RestoreCleanupDisposition::CommittedModified,
                transaction: transaction.clone(),
                published_identity_sha256: published_identity_sha256.to_owned(),
            };
            replace_restore_cleanup_recovery(state, &committed, &modified)?;
            finish_committed_modified_restore_cleanup_recovery_stage(
                state,
                transaction,
                published_identity_sha256,
                checkpoint,
            )?;
            return Ok(RestoreCleanupOutcome::WorkspaceModified);
        }
        return Err(error.into());
    }
    write_restore_authority_record(state, transaction, published_identity_sha256)?;
    remove_active_restore_transaction(state)?;
    checkpoint(&RestoreCheckpoint::CleanupIntentRetired);
    write_restore_completion_receipt(state, transaction, published_identity_sha256)?;
    checkpoint(&RestoreCheckpoint::CompletionDurable);
    remove_restore_cleanup_recovery(state)?;
    Ok(RestoreCleanupOutcome::Restored)
}

fn derive_authoritative_restore_target(
    store: &FolderbaseVersionStore,
    local: &LocalVersionStore,
    state: &FolderbaseState,
    transaction: &RestoreTransaction,
) -> Result<FolderbaseVersion, FolderbaseCaptureError> {
    let parent = read_and_verify_folderbase_version(
        store,
        local,
        state,
        &transaction.expected_head.version_id,
    )?;
    if parent.canonical_digest()? != transaction.expected_head.version_sha256 {
        return Err(FolderbaseCaptureError::InvalidRestoreTransaction(
            "restore parent digest changed".to_owned(),
        ));
    }
    if transaction.expected_head.authority
        != (LocalHeadAuthority::VersionDerivedV1 {
            sha256: local_head_authority_sha256(
                store,
                &transaction.expected_head.version_id,
                &transaction.expected_head.version_sha256,
            )?,
        })
    {
        return Err(FolderbaseCaptureError::InvalidRestoreTransaction(
            "restore parent Head authority is not independently derivable".to_owned(),
        ));
    }
    let parent_tombstone = parent
        .tombstones()
        .iter()
        .find(|tombstone| tombstone.path() == transaction.path)
        .ok_or_else(|| {
            FolderbaseCaptureError::InvalidRestoreTransaction(
                "restore parent no longer contains the selected Tombstone".to_owned(),
            )
        })?;
    if parent_tombstone != &transaction.tombstone {
        return Err(FolderbaseCaptureError::InvalidRestoreTransaction(
            "restore journal Tombstone differs from the verified parent".to_owned(),
        ));
    }
    let authoritative = find_restore_binding(store, local, state, &parent, parent_tombstone)?;
    if authoritative != transaction.binding {
        return Err(FolderbaseCaptureError::InvalidRestoreTransaction(
            "restore journal fidelity differs from verified ancestry".to_owned(),
        ));
    }
    let parent_head = LocalHeadRecord {
        format: "folderbase-local-head-v2".to_owned(),
        folderbase_id: transaction.folderbase_id.clone(),
        root_instance_sha256: transaction.root_instance_sha256.clone(),
        version_id: transaction.expected_head.version_id.clone(),
        version_sha256: transaction.expected_head.version_sha256.clone(),
        authority: transaction.expected_head.authority.clone(),
    };
    let (transaction_id, target_version_id, created_at) = assigned_restore_identity(
        store,
        &parent_head,
        &parent,
        parent_tombstone,
        &authoritative,
    )?;
    if transaction.transaction_id != transaction_id
        || transaction.target_version_id != target_version_id
        || transaction.created_at != created_at
    {
        return Err(FolderbaseCaptureError::InvalidRestoreTransaction(
            "restore assignment differs from verified immutable authority".to_owned(),
        ));
    }
    let target = restored_version(
        store,
        &parent,
        &transaction.target_version_id,
        &transaction.created_at,
        &transaction.tombstone,
        &transaction.binding,
    )?;
    if target.canonical_digest()? != transaction.target_version_sha256 {
        return Err(FolderbaseCaptureError::InvalidRestoreTransaction(
            "restore target no longer matches its durable journal".to_owned(),
        ));
    }
    Ok(target)
}

fn verify_restore_root_instance(
    store: &FolderbaseVersionStore,
) -> Result<(), FolderbaseCaptureError> {
    let observed = attest_folderbase_root(&store.root_attestation.root)
        .map_err(|_| FolderbaseCaptureError::PlanStoreMismatch)?;
    if observed.folderbase_id != store.root_attestation.folderbase_id
        || observed.protocol_version != store.root_attestation.protocol_version
        || observed.manifest_sha256 != store.root_attestation.manifest_sha256
        || observed.root_instance_sha256 != store.root_attestation.root_instance_sha256
    {
        return Err(FolderbaseCaptureError::PlanStoreMismatch);
    }
    Ok(())
}

fn verify_restore_publication(
    store: &FolderbaseVersionStore,
    state: &FolderbaseState,
    transaction: &RestoreTransaction,
) -> Result<(), FolderbaseCaptureError> {
    verify_restore_root_instance(store)?;
    state.verify_still_attached()?;
    let digest = transaction
        .binding
        .content_sha256()
        .expect("validated regular binding");
    let bytes = transaction
        .binding
        .bytes()
        .expect("validated regular binding");
    let executable = transaction
        .binding
        .executable()
        .expect("validated regular binding");
    state
        .verify_workspace_restore(
            &restore_stage_path(transaction),
            Path::new(&transaction.path),
            digest,
            bytes,
            executable,
        )
        .map_err(|error| match error {
            FolderbaseError::WouldOverwrite(path) => {
                FolderbaseCaptureError::RestoreTargetOccupied(path)
            }
            error => FolderbaseCaptureError::LocalStore(error),
        })
}

fn retire_modified_restore(
    store: &FolderbaseVersionStore,
    local: &LocalVersionStore,
    state: &FolderbaseState,
    transaction: &RestoreTransaction,
    checkpoint: &mut impl FnMut(&RestoreCheckpoint),
) -> Result<bool, FolderbaseCaptureError> {
    let digest = transaction
        .binding
        .content_sha256()
        .expect("validated regular binding");
    let bytes = transaction
        .binding
        .bytes()
        .expect("validated regular binding");
    let executable = transaction
        .binding
        .executable()
        .expect("validated regular binding");
    if !matches!(
        state.workspace_restore_was_modified_in_place(
            &restore_stage_path(transaction),
            Path::new(&transaction.path),
            digest,
            bytes,
            executable,
        ),
        Ok(true)
    ) {
        return Ok(false);
    }
    let Some(current_head) = read_head_record(state)? else {
        return Ok(false);
    };
    if JournalHead::from(&current_head) != transaction.expected_head {
        return Ok(false);
    }

    let published_identity_sha256 = state.workspace_restore_identity_sha256(
        &restore_stage_path(transaction),
        Path::new(&transaction.path),
    )?;
    write_restore_cleanup_recovery(
        state,
        &RestoreCleanupRecovery {
            format: RESTORE_CLEANUP_RECOVERY_FORMAT_V2.to_owned(),
            disposition: RestoreCleanupDisposition::Modified,
            transaction: transaction.clone(),
            published_identity_sha256: published_identity_sha256.clone(),
        },
    )?;
    checkpoint(&RestoreCheckpoint::CleanupRecoveryDurable);
    finish_modified_restore_cleanup_recovery(
        store,
        local,
        state,
        transaction,
        &published_identity_sha256,
        checkpoint,
    )?;
    Ok(true)
}

fn finish_modified_restore_cleanup_recovery(
    store: &FolderbaseVersionStore,
    local: &LocalVersionStore,
    state: &FolderbaseState,
    transaction: &RestoreTransaction,
    published_identity_sha256: &str,
    checkpoint: &mut impl FnMut(&RestoreCheckpoint),
) -> Result<(), FolderbaseCaptureError> {
    rederive_authoritative_modified_restore_transaction(store, local, state, transaction)?;
    state.retain_workspace_restore_authority_with_hook(
        &restore_stage_path(transaction),
        Path::new(&transaction.path),
        published_identity_sha256,
        None,
        |stage_removed| {
            checkpoint(if stage_removed {
                &RestoreCheckpoint::AfterStageRetirement
            } else {
                &RestoreCheckpoint::BeforeStageRetirement
            });
        },
    )?;
    write_restore_authority_record(state, transaction, published_identity_sha256)?;
    remove_active_restore_transaction(state)?;
    remove_restore_cleanup_recovery(state)
}

fn finish_committed_modified_restore_cleanup_recovery(
    store: &FolderbaseVersionStore,
    local: &LocalVersionStore,
    state: &FolderbaseState,
    transaction: &RestoreTransaction,
    published_identity_sha256: &str,
    checkpoint: &mut impl FnMut(&RestoreCheckpoint),
) -> Result<(), FolderbaseCaptureError> {
    validate_restore_transaction(store, transaction)?;
    let target = derive_authoritative_restore_target(store, local, state, transaction)?;
    if target.canonical_digest()? != transaction.target_version_sha256 {
        return Err(FolderbaseCaptureError::InvalidRestoreTransaction(
            "committed-modified cleanup target digest changed".to_owned(),
        ));
    }
    let target_head = JournalHead {
        version_id: transaction.target_version_id.clone(),
        version_sha256: transaction.target_version_sha256.clone(),
        authority: LocalHeadAuthority::VersionDerivedV1 {
            sha256: local_head_authority_sha256(
                store,
                &transaction.target_version_id,
                &transaction.target_version_sha256,
            )?,
        },
    };
    let current_head = read_head_record(state)?.ok_or(FolderbaseCaptureError::MissingLocalHead)?;
    if JournalHead::from(&current_head) != target_head {
        return Err(FolderbaseCaptureError::LocalHeadChanged);
    }
    let installed =
        read_and_verify_folderbase_version(store, local, state, &transaction.target_version_id)?;
    if installed.canonical_digest()? != transaction.target_version_sha256 {
        return Err(FolderbaseCaptureError::InvalidRestoreTransaction(
            "committed-modified cleanup installed version changed".to_owned(),
        ));
    }
    finish_committed_modified_restore_cleanup_recovery_stage(
        state,
        transaction,
        published_identity_sha256,
        checkpoint,
    )
}

fn finish_committed_modified_restore_cleanup_recovery_stage(
    state: &FolderbaseState,
    transaction: &RestoreTransaction,
    published_identity_sha256: &str,
    checkpoint: &mut impl FnMut(&RestoreCheckpoint),
) -> Result<(), FolderbaseCaptureError> {
    state.retain_workspace_restore_authority_with_hook(
        &restore_stage_path(transaction),
        Path::new(&transaction.path),
        published_identity_sha256,
        None,
        |stage_removed| {
            checkpoint(if stage_removed {
                &RestoreCheckpoint::AfterStageRetirement
            } else {
                &RestoreCheckpoint::BeforeStageRetirement
            });
        },
    )?;
    write_restore_authority_record(state, transaction, published_identity_sha256)?;
    remove_active_restore_transaction(state)?;
    remove_restore_cleanup_recovery(state)
}

fn rederive_authoritative_modified_restore_transaction(
    store: &FolderbaseVersionStore,
    local: &LocalVersionStore,
    state: &FolderbaseState,
    transaction: &RestoreTransaction,
) -> Result<(), FolderbaseCaptureError> {
    let current_head = read_head_record(state)?.ok_or(FolderbaseCaptureError::MissingLocalHead)?;
    if JournalHead::from(&current_head) != transaction.expected_head {
        return Err(FolderbaseCaptureError::LocalHeadChanged);
    }
    rederive_authoritative_restore_transaction(store, local, state, transaction)
}

fn rederive_authoritative_restore_transaction(
    store: &FolderbaseVersionStore,
    local: &LocalVersionStore,
    state: &FolderbaseState,
    transaction: &RestoreTransaction,
) -> Result<(), FolderbaseCaptureError> {
    validate_restore_transaction(store, transaction)?;
    let current = read_and_verify_folderbase_version(
        store,
        local,
        state,
        &transaction.expected_head.version_id,
    )?;
    if current.canonical_digest()? != transaction.expected_head.version_sha256 {
        return Err(FolderbaseCaptureError::InvalidRestoreTransaction(
            "modified cleanup parent digest changed".to_owned(),
        ));
    }
    let tombstone = current
        .tombstones()
        .iter()
        .find(|candidate| candidate.path() == transaction.path)
        .cloned()
        .ok_or_else(|| {
            FolderbaseCaptureError::InvalidRestoreTransaction(
                "modified cleanup path is not a current Tombstone".to_owned(),
            )
        })?;
    let binding = find_restore_binding(store, local, state, &current, &tombstone)?;
    let authoritative = build_restore_transaction(
        store,
        &LocalHeadRecord {
            format: "folderbase-local-head-v2".to_owned(),
            folderbase_id: transaction.folderbase_id.clone(),
            root_instance_sha256: transaction.root_instance_sha256.clone(),
            version_id: transaction.expected_head.version_id.clone(),
            version_sha256: transaction.expected_head.version_sha256.clone(),
            authority: transaction.expected_head.authority.clone(),
        },
        &current,
        tombstone,
        binding,
    )?;
    if authoritative != *transaction {
        return Err(FolderbaseCaptureError::InvalidRestoreTransaction(
            "restore transaction does not match immutable restore authority".to_owned(),
        ));
    }
    Ok(())
}

fn completed_restore_result(
    store: &FolderbaseVersionStore,
    local: &LocalVersionStore,
    state: &FolderbaseState,
    transaction: &RestoreTransaction,
    published_identity_sha256: &str,
) -> Result<Option<RestoredTombstone>, FolderbaseCaptureError> {
    validate_restore_transaction(store, transaction)?;
    let current_head = read_head_record(state)?.ok_or(FolderbaseCaptureError::MissingLocalHead)?;
    let target_head = JournalHead {
        version_id: transaction.target_version_id.clone(),
        version_sha256: transaction.target_version_sha256.clone(),
        authority: LocalHeadAuthority::VersionDerivedV1 {
            sha256: local_head_authority_sha256(
                store,
                &transaction.target_version_id,
                &transaction.target_version_sha256,
            )?,
        },
    };
    if JournalHead::from(&current_head) != target_head {
        return Ok(None);
    }
    rederive_authoritative_restore_transaction(store, local, state, transaction)?;
    let installed =
        read_and_verify_folderbase_version(store, local, state, &transaction.target_version_id)?;
    if installed.canonical_digest()? != transaction.target_version_sha256 {
        return Err(FolderbaseCaptureError::InvalidRestoreTransaction(
            "completed restore version digest changed".to_owned(),
        ));
    }

    let path = Path::new(&transaction.path);
    let digest = transaction
        .binding
        .content_sha256()
        .expect("validated regular binding");
    let bytes = transaction
        .binding
        .bytes()
        .expect("validated regular binding");
    let executable = transaction
        .binding
        .executable()
        .expect("validated regular binding");
    let expected_authority = restore_authority_record(transaction, published_identity_sha256);
    let authority_path = restore_authority_record_path(&transaction.transaction_id);
    let authority = state
        .read_bounded(&authority_path, MAX_RESTORE_AUTHORITY_BYTES)?
        .and_then(|encoded| serde_json::from_slice::<RestoreAuthorityRecord>(&encoded).ok());
    let retained_identity =
        state.workspace_restore_identity_sha256(&restore_stage_path(transaction), path);
    if authority.as_ref() != Some(&expected_authority)
        || !matches!(
            retained_identity,
            Ok(observed) if observed == published_identity_sha256
        )
    {
        return Ok(None);
    }
    if state
        .verify_workspace_regular_file_identity_and_fidelity(
            path,
            published_identity_sha256,
            digest,
            bytes,
            executable,
        )
        .is_err()
    {
        return Ok(None);
    }
    Ok(Some(restored_tombstone(transaction, false)))
}

fn rollback_restore_head(
    store: &FolderbaseVersionStore,
    state: &FolderbaseState,
    transaction: &RestoreTransaction,
) -> Result<(), FolderbaseCaptureError> {
    let target = JournalHead {
        version_id: transaction.target_version_id.clone(),
        version_sha256: transaction.target_version_sha256.clone(),
        authority: LocalHeadAuthority::VersionDerivedV1 {
            sha256: local_head_authority_sha256(
                store,
                &transaction.target_version_id,
                &transaction.target_version_sha256,
            )?,
        },
    };
    let prior = LocalHeadRecord {
        format: "folderbase-local-head-v2".to_owned(),
        folderbase_id: transaction.folderbase_id.clone(),
        root_instance_sha256: transaction.root_instance_sha256.clone(),
        version_id: transaction.expected_head.version_id.clone(),
        version_sha256: transaction.expected_head.version_sha256.clone(),
        authority: transaction.expected_head.authority.clone(),
    };
    // Rollback deliberately uses the already-retained state capability rather
    // than the ambient root path. If that path was swapped after the forward
    // CAS, the exact original root still has to regain its prior Head while
    // the replacement path remains untouched.
    let current = read_head_record(state)?.ok_or(FolderbaseCaptureError::LocalHeadChanged)?;
    if JournalHead::from(&current) != target {
        return Err(FolderbaseCaptureError::LocalHeadChanged);
    }
    state.replace(Path::new(LOCAL_HEAD_PATH), &json_bytes(&prior)?)?;
    if read_head_record(state)?.as_ref() != Some(&prior) {
        return Err(FolderbaseCaptureError::InvalidRestoreTransaction(
            "Local Head rollback did not verify".to_owned(),
        ));
    }
    Ok(())
}

fn finish_restore_materialization(
    store: &FolderbaseVersionStore,
    local: &LocalVersionStore,
    state: &FolderbaseState,
    transaction: &RestoreTransaction,
    checkpoint: &mut impl FnMut(&RestoreCheckpoint),
) -> Result<(), FolderbaseCaptureError> {
    stage_and_publish_restore(state, transaction, checkpoint)?;
    let installed =
        read_and_verify_folderbase_version(store, local, state, &transaction.target_version_id)?;
    if installed.canonical_digest()? != transaction.target_version_sha256 {
        return Err(FolderbaseCaptureError::InvalidRestoreTransaction(
            "committed restore version failed verification".to_owned(),
        ));
    }
    checkpoint(&RestoreCheckpoint::VersionDurable);
    checkpoint(&RestoreCheckpoint::HeadReplaced);
    verify_restore_publication(store, state, transaction)?;
    checkpoint(&RestoreCheckpoint::PublicationVerified);
    finish_restore_projection(store, local, state, transaction)?;
    verify_restore_publication(store, state, transaction)?;
    checkpoint(&RestoreCheckpoint::ProjectionDurable);
    Ok(())
}

fn stage_and_publish_restore(
    state: &FolderbaseState,
    transaction: &RestoreTransaction,
    checkpoint: &mut impl FnMut(&RestoreCheckpoint),
) -> Result<(), FolderbaseCaptureError> {
    let transaction_directory =
        Path::new(RESTORE_TRANSACTIONS_DIRECTORY).join(&transaction.transaction_id);
    state.ensure_private_dir(&transaction_directory)?;
    let stage = restore_stage_path(transaction);
    let digest = transaction
        .binding
        .content_sha256()
        .expect("validated regular binding");
    let bytes = transaction
        .binding
        .bytes()
        .expect("validated regular binding");
    let executable = transaction
        .binding
        .executable()
        .expect("validated regular binding");
    let source = Path::new(".folderbase/versions/blobs/sha256").join(digest);
    state.stage_restore_blob(&source, &stage, digest, bytes, executable)?;
    checkpoint(&RestoreCheckpoint::StageDurable);
    let result = state
        .publish_workspace_restore(
            &stage,
            Path::new(&transaction.path),
            digest,
            bytes,
            executable,
        )
        .map(|_| ())
        .map_err(|error| match error {
            FolderbaseError::WouldOverwrite(path) => {
                FolderbaseCaptureError::RestoreTargetOccupied(path)
            }
            error => FolderbaseCaptureError::LocalStore(error),
        });
    if result.is_ok() {
        checkpoint(&RestoreCheckpoint::TargetPublished);
    }
    result
}

fn finish_restore_projection(
    store: &FolderbaseVersionStore,
    local: &LocalVersionStore,
    state: &FolderbaseState,
    transaction: &RestoreTransaction,
) -> Result<(), FolderbaseCaptureError> {
    let file = state.open_workspace_regular_file(Path::new(&transaction.path))?;
    let observed =
        fingerprint_std_file(&file, &store.root_attestation.root.join(&transaction.path))?;
    let assignment = CaptureAssignment {
        path: transaction.path.clone(),
        kind: CaptureEntryKind::RegularFile,
        object_id: transaction.binding.object_id().to_owned(),
        candidate_object_version_id: transaction.binding.object_version_id().map(str::to_owned),
        prior_object_version_id: transaction.binding.object_version_id().map(str::to_owned),
        reused_object: true,
        observed,
    };
    let version_id = VersionId::parse(
        transaction
            .binding
            .object_version_id()
            .expect("validated regular binding")
            .to_owned(),
    )?;
    if can_project_legacy_object(&transaction.path) {
        let projection = regular_projection(
            local,
            state,
            &assignment,
            &version_id,
            Some(version_id.as_str()),
            &transaction.created_at,
        )?;
        local.write_capture_object_projection_in(state, &projection)?;
    }
    let identity = CaptureIdentityRecord {
        format: "folderbase-capture-identity-v1".to_owned(),
        object_id: assignment.object_id,
        kind: assignment.kind,
        observed: assignment.observed,
    };
    state.replace(
        &capture_identity_relative_path(transaction.binding.object_id()),
        &json_bytes(&identity)?,
    )?;
    Ok(())
}

fn restore_stage_path(transaction: &RestoreTransaction) -> PathBuf {
    restore_transaction_directory(transaction).join("content")
}

fn restore_transaction_directory(transaction: &RestoreTransaction) -> PathBuf {
    Path::new(RESTORE_TRANSACTIONS_DIRECTORY).join(&transaction.transaction_id)
}

impl From<&LocalHeadRecord> for JournalHead {
    fn from(value: &LocalHeadRecord) -> Self {
        Self {
            version_id: value.version_id.clone(),
            version_sha256: value.version_sha256.clone(),
            authority: value.authority.clone(),
        }
    }
}

#[derive(Serialize)]
struct PlanDigest<'a> {
    format: &'static str,
    folderbase_id: &'a str,
    root_instance_sha256: &'a str,
    root_manifest_sha256: &'a str,
    root_manifest_bytes: u64,
    ignore_policy_sha256: &'a str,
    current_head: Option<JournalHead>,
    entries: Vec<PlanDigestEntry<'a>>,
    exclusions: Vec<PlanDigestExclusion<'a>>,
    ignored_paths: Vec<&'a str>,
}

#[derive(Serialize)]
struct PlanDigestEntry<'a> {
    path: &'a str,
    kind: CaptureEntryKind,
    bytes: Option<u64>,
    executable: Option<bool>,
    symlink_target: Option<&'a str>,
    observed: &'a CaptureMetadataFingerprint,
}

#[derive(Serialize)]
struct PlanDigestExclusion<'a> {
    path: &'a str,
    kind: CaptureExclusionKind,
    reason: CaptureExclusionReason,
}

fn capture_plan_sha256(plan: &CapturePlan) -> Result<String, FolderbaseCaptureError> {
    let digest = PlanDigest {
        format: "folderbase-capture-plan-digest-v1",
        folderbase_id: plan.folderbase_id(),
        root_instance_sha256: plan.root_instance_sha256(),
        root_manifest_sha256: plan.root_manifest_sha256(),
        root_manifest_bytes: plan.root_manifest_bytes(),
        ignore_policy_sha256: plan.ignore_policy_sha256(),
        current_head: plan.current_local_head().map(JournalHead::from),
        entries: plan
            .entries()
            .iter()
            .map(|entry| PlanDigestEntry {
                path: entry.path(),
                kind: entry.kind(),
                bytes: entry.bytes(),
                executable: entry.executable(),
                symlink_target: entry.symlink_target(),
                observed: entry.observed(),
            })
            .collect(),
        exclusions: plan
            .exclusions()
            .iter()
            .map(|exclusion| PlanDigestExclusion {
                path: exclusion.path(),
                kind: exclusion.kind(),
                reason: exclusion.reason(),
            })
            .collect(),
        ignored_paths: plan
            .ignored_paths()
            .iter()
            .map(|path| path.path())
            .collect(),
    };
    let encoded = serde_json::to_vec(&digest).map_err(|source| {
        FolderbaseCaptureError::InvalidCaptureTransaction(format!(
            "CapturePlan digest encoding failed: {source}"
        ))
    })?;
    Ok(format!("{:x}", Sha256::digest(encoded)))
}

fn local_head_authority_sha256(
    store: &FolderbaseVersionStore,
    version_id: &str,
    version_sha256: &str,
) -> Result<String, FolderbaseCaptureError> {
    version_derived_local_head_sha256(
        &store.root_attestation.folderbase_id,
        &store.root_attestation.root_instance_sha256,
        version_id,
        version_sha256,
    )
}

#[cfg(test)]
fn capture_transaction_sha256(
    transaction: &CaptureTransaction,
) -> Result<String, FolderbaseCaptureError> {
    Ok(format!("{:x}", Sha256::digest(json_bytes(transaction)?)))
}

fn ensure_same_plan(
    expected: &CapturePlan,
    actual: &CapturePlan,
) -> Result<(), FolderbaseCaptureError> {
    if expected.root() != actual.root()
        || expected.folderbase_id() != actual.folderbase_id()
        || expected.root_instance_sha256() != actual.root_instance_sha256()
    {
        return Err(FolderbaseCaptureError::PlanStoreMismatch);
    }
    if expected.current_local_head() != actual.current_local_head() {
        return Err(FolderbaseCaptureError::LocalHeadChanged);
    }
    if expected.root_manifest_sha256() != actual.root_manifest_sha256()
        || expected.root_manifest_bytes() != actual.root_manifest_bytes()
    {
        return Err(FolderbaseCaptureError::CaptureStateChanged(PathBuf::from(
            ".folderbase/manifest.json",
        )));
    }
    if expected.ignore_policy_sha256() != actual.ignore_policy_sha256() {
        return Err(FolderbaseCaptureError::CaptureStateChanged(PathBuf::from(
            ".folderbaseignore",
        )));
    }
    for (left, right) in expected.entries().iter().zip(actual.entries()) {
        if left.path() != right.path()
            || left.kind() != right.kind()
            || left.bytes() != right.bytes()
            || left.executable() != right.executable()
            || left.symlink_target() != right.symlink_target()
            || left.observed() != right.observed()
        {
            return Err(FolderbaseCaptureError::CaptureStateChanged(PathBuf::from(
                if left.path() <= right.path() {
                    left.path()
                } else {
                    right.path()
                },
            )));
        }
    }
    if expected.entries().len() != actual.entries().len() {
        let path = expected
            .entries()
            .iter()
            .zip(actual.entries())
            .find_map(|(left, right)| (left.path() != right.path()).then_some(left.path()))
            .or_else(|| expected.entries().last().map(CapturePlanEntry::path))
            .or_else(|| actual.entries().last().map(CapturePlanEntry::path))
            .unwrap_or(".");
        return Err(FolderbaseCaptureError::CaptureStateChanged(PathBuf::from(
            path,
        )));
    }
    let same_exclusions = expected.exclusions().len() == actual.exclusions().len()
        && expected
            .exclusions()
            .iter()
            .zip(actual.exclusions())
            .all(|(left, right)| {
                left.path() == right.path()
                    && left.kind() == right.kind()
                    && left.reason() == right.reason()
            });
    if !same_exclusions {
        let path = expected
            .exclusions()
            .first()
            .map(|value| value.path())
            .or_else(|| actual.exclusions().first().map(|value| value.path()))
            .unwrap_or(".");
        return Err(FolderbaseCaptureError::CaptureStateChanged(PathBuf::from(
            path,
        )));
    }
    let same_ignored = expected.ignored_paths().len() == actual.ignored_paths().len()
        && expected
            .ignored_paths()
            .iter()
            .zip(actual.ignored_paths())
            .all(|(left, right)| left.path() == right.path());
    if !same_ignored {
        let path = expected
            .ignored_paths()
            .first()
            .map(|value| value.path())
            .or_else(|| actual.ignored_paths().first().map(|value| value.path()))
            .unwrap_or(".");
        return Err(FolderbaseCaptureError::CaptureStateChanged(PathBuf::from(
            path,
        )));
    }
    Ok(())
}

fn assign_capture_transaction(
    plan: &CapturePlan,
    plan_sha256: &str,
    prior: Option<&FolderbaseVersion>,
) -> Result<CaptureTransaction, FolderbaseCaptureError> {
    let prior_bindings = prior
        .map(|version| {
            version
                .bindings()
                .iter()
                .map(|binding| (binding.path(), binding))
                .collect::<BTreeMap<_, _>>()
        })
        .unwrap_or_default();
    let mut assignments = Vec::with_capacity(plan.entries().len());
    for entry in plan.entries() {
        let prior_binding = prior_bindings.get(entry.path()).copied();
        let reused_object =
            prior_binding.is_some_and(|binding| binding.kind() == path_binding_kind(entry.kind()));
        let object_id = prior_binding
            .filter(|_| reused_object)
            .map(|binding| binding.object_id().to_owned())
            .unwrap_or_else(|| ObjectId::new().to_string());
        let candidate_object_version_id =
            (entry.kind() != CaptureEntryKind::Directory).then(|| VersionId::new().to_string());
        let prior_object_version_id = prior_binding
            .filter(|_| reused_object)
            .and_then(|binding| binding.object_version_id())
            .map(str::to_owned);
        assignments.push(CaptureAssignment {
            path: entry.path().to_owned(),
            kind: entry.kind(),
            object_id,
            candidate_object_version_id,
            prior_object_version_id,
            reused_object,
            observed: entry.observed().clone(),
        });
    }

    let target_tombstones = project_target_tombstones(prior, &assignments);
    Ok(CaptureTransaction {
        format: CAPTURE_TRANSACTION_FORMAT_V1.to_owned(),
        transaction_id: format!("fbcapture_{}", Uuid::now_v7()),
        folderbase_id: plan.folderbase_id().to_owned(),
        root_instance_sha256: plan.root_instance_sha256().to_owned(),
        plan_sha256: plan_sha256.to_owned(),
        expected_head: plan.current_local_head().map(JournalHead::from),
        target_version_id: format!("fbversion_{}", Uuid::now_v7()),
        created_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        root_manifest_object_id: ObjectId::new().to_string(),
        root_manifest_candidate_version_id: VersionId::new().to_string(),
        prior_root_manifest_version_id: prior
            .map(|version| version.root_manifest().object_version_id().to_owned()),
        assignments,
        target_tombstones,
    })
}

fn ensure_prior_bindings_observable(
    plan: &CapturePlan,
    prior: Option<&FolderbaseVersion>,
) -> Result<(), FolderbaseCaptureError> {
    let Some(prior) = prior else {
        return Ok(());
    };
    let live_paths = plan
        .entries()
        .iter()
        .map(|entry| entry.path())
        .collect::<std::collections::BTreeSet<_>>();
    for binding in prior.bindings() {
        if live_paths.contains(binding.path()) {
            continue;
        }
        let hidden_by_ignore = plan
            .ignored_paths()
            .iter()
            .any(|ignored| path_is_same_or_descendant_of(binding.path(), ignored.path()));
        let hidden_by_exclusion = plan.exclusions().iter().any(|exclusion| {
            binding.path() == exclusion.path()
                || (exclusion.kind() == CaptureExclusionKind::NestedFolderbase
                    && path_is_same_or_descendant_of(binding.path(), exclusion.path()))
        });
        if hidden_by_ignore || hidden_by_exclusion {
            return Err(FolderbaseCaptureError::PriorBindingHidden(PathBuf::from(
                binding.path(),
            )));
        }
    }
    Ok(())
}

fn path_is_same_or_descendant_of(path: &str, ancestor: &str) -> bool {
    path == ancestor
        || path
            .strip_prefix(ancestor)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

fn project_target_tombstones(
    prior: Option<&FolderbaseVersion>,
    assignments: &[CaptureAssignment],
) -> Vec<Tombstone> {
    let Some(prior) = prior else {
        return Vec::new();
    };
    let assignments = assignments
        .iter()
        .map(|assignment| (assignment.path.as_str(), assignment))
        .collect::<BTreeMap<_, _>>();
    let mut by_path = prior
        .tombstones()
        .iter()
        .cloned()
        .map(|tombstone| (tombstone.path().to_owned(), tombstone))
        .collect::<BTreeMap<_, _>>();
    for binding in prior.bindings() {
        let continued = assignments.get(binding.path()).is_some_and(|assignment| {
            assignment.reused_object && assignment.object_id == binding.object_id()
        });
        if continued {
            continue;
        }
        by_path.insert(
            binding.path().to_owned(),
            Tombstone::from_verified_producer(
                binding.path(),
                binding.object_id(),
                deleted_kind(binding.kind()),
                binding.object_version_id().map(str::to_owned),
            ),
        );
    }
    by_path.into_values().collect()
}

fn deleted_kind(kind: PathBindingKind) -> DeletedKind {
    match kind {
        PathBindingKind::Directory => DeletedKind::Directory,
        PathBindingKind::RegularFile => DeletedKind::RegularFile,
        PathBindingKind::Symlink => DeletedKind::Symlink,
    }
}

fn path_binding_kind(kind: CaptureEntryKind) -> PathBindingKind {
    match kind {
        CaptureEntryKind::Directory => PathBindingKind::Directory,
        CaptureEntryKind::RegularFile => PathBindingKind::RegularFile,
        CaptureEntryKind::Symlink => PathBindingKind::Symlink,
    }
}

fn identity_allows_reuse(
    state: &FolderbaseState,
    root: &Path,
    object_id: &str,
    entry: &CapturePlanEntry,
) -> Result<bool, FolderbaseCaptureError> {
    let relative = capture_identity_relative_path(object_id);
    let path = root.join(&relative);
    let Some(encoded) = state.read_bounded(&relative, 64 * 1024)? else {
        return Ok(false);
    };
    let record: CaptureIdentityRecord = serde_json::from_slice(&encoded).map_err(|source| {
        FolderbaseCaptureError::InvalidPriorLocalHead(format!(
            "capture identity {} is invalid: {source}",
            path.display()
        ))
    })?;
    if record.format != "folderbase-capture-identity-v1"
        || record.object_id != object_id
        || record.kind != entry.kind()
    {
        return Err(FolderbaseCaptureError::InvalidPriorLocalHead(format!(
            "capture identity {} does not match its binding",
            path.display()
        )));
    }
    match (
        record.observed.physical_identity.as_deref(),
        entry.observed().physical_identity.as_deref(),
    ) {
        (Some(previous), Some(current)) => return Ok(previous == current),
        (Some(_), None) | (None, Some(_)) => return Ok(false),
        (None, None) => {}
    }
    match (
        (record.observed.device, record.observed.inode),
        (entry.observed().device, entry.observed().inode),
    ) {
        ((Some(old_device), Some(old_inode)), (Some(device), Some(inode))) => {
            Ok(old_device == device && old_inode == inode)
        }
        _ => Ok(false),
    }
}

fn load_prior_head(
    store: &FolderbaseVersionStore,
    local: &LocalVersionStore,
    state: &FolderbaseState,
    head: Option<&CaptureLocalHead>,
) -> Result<Option<FolderbaseVersion>, FolderbaseCaptureError> {
    let Some(head) = head else {
        return Ok(None);
    };
    let version = read_and_verify_folderbase_version(store, local, state, head.version_id())
        .map_err(|error| FolderbaseCaptureError::InvalidPriorLocalHead(error.to_string()))?;
    let digest = version
        .canonical_digest()
        .map_err(|error| FolderbaseCaptureError::InvalidPriorLocalHead(error.to_string()))?;
    if digest != head.version_sha256() {
        return Err(FolderbaseCaptureError::InvalidPriorLocalHead(
            "Local Head digest does not match the complete Folderbase Version".to_owned(),
        ));
    }
    Ok(Some(version))
}

fn load_transaction_prior(
    store: &FolderbaseVersionStore,
    local: &LocalVersionStore,
    state: &FolderbaseState,
    head: Option<&JournalHead>,
) -> Result<Option<FolderbaseVersion>, FolderbaseCaptureError> {
    let Some(head) = head else {
        return Ok(None);
    };
    let version = read_and_verify_folderbase_version(store, local, state, &head.version_id)
        .map_err(|error| FolderbaseCaptureError::InvalidPriorLocalHead(error.to_string()))?;
    if version.canonical_digest()? != head.version_sha256 {
        return Err(FolderbaseCaptureError::InvalidPriorLocalHead(
            "transaction parent digest does not match its complete Folderbase Version".to_owned(),
        ));
    }
    Ok(Some(version))
}

fn live_state_matches_prior(
    store: &FolderbaseVersionStore,
    plan: &CapturePlan,
    local: &LocalVersionStore,
    state: &FolderbaseState,
    prior: Option<&FolderbaseVersion>,
    checkpoint: &mut impl FnMut(&CaptureCheckpoint),
) -> Result<bool, FolderbaseCaptureError> {
    let Some(prior) = prior else {
        return Ok(false);
    };
    if prior.folderbase_id() != plan.folderbase_id()
        || prior.root_manifest().content_sha256() != plan.root_manifest_sha256()
        || prior.root_manifest().bytes() != plan.root_manifest_bytes()
        || prior.bindings().len() != plan.entries().len()
        || prior.exclusions().len() != plan.exclusions().len()
    {
        return Ok(false);
    }
    for (entry, binding) in plan.entries().iter().zip(prior.bindings()) {
        if entry.path() != binding.path()
            || path_binding_kind(entry.kind()) != binding.kind()
            || !identity_allows_reuse(
                state,
                &store.root_attestation.root,
                binding.object_id(),
                entry,
            )?
        {
            return Ok(false);
        }
        match entry.kind() {
            CaptureEntryKind::Directory => {}
            CaptureEntryKind::RegularFile => {
                let content = hash_regular_entry(
                    &store.root_attestation.root,
                    entry,
                    None::<(&LocalVersionStore, &FolderbaseState)>,
                    || {
                        checkpoint(&CaptureCheckpoint::BeforeObjectBytesRead(
                            entry.path().to_owned(),
                        ));
                    },
                )?;
                if binding.content_sha256() != Some(content.digest.as_str())
                    || binding.bytes() != Some(content.bytes)
                    || binding.executable() != entry.executable()
                {
                    return Ok(false);
                }
                let object_id = ObjectId::parse(binding.object_id().to_owned())?;
                let version_id = VersionId::parse(binding.object_version_id().unwrap().to_owned())?;
                local.verify_capture_object_version_in(state, &object_id, &version_id, &content)?;
            }
            CaptureEntryKind::Symlink => {
                verify_symlink_entry(&store.root_attestation.root, entry)?;
                if binding.symlink_target() != entry.symlink_target() {
                    return Ok(false);
                }
                let target = entry.symlink_target().expect("planned symlink target");
                let content = content_digest(target.as_bytes());
                let object_id = ObjectId::parse(binding.object_id().to_owned())?;
                let version_id = VersionId::parse(binding.object_version_id().unwrap().to_owned())?;
                local.verify_capture_object_version_in(state, &object_id, &version_id, &content)?;
            }
        }
    }
    for (planned, sealed) in plan.exclusions().iter().zip(prior.exclusions()) {
        if planned.path() != sealed.path()
            || exclusion_kind(planned.kind()) != sealed.kind()
            || exclusion_reason(planned.reason()) != sealed.reason()
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn preflight_capture_envelopes(
    plan: &CapturePlan,
    transaction: &CaptureTransaction,
    maximum_transaction_bytes: u64,
    maximum_version_bytes: u64,
) -> Result<(), FolderbaseCaptureError> {
    encode_active_transaction(transaction, maximum_transaction_bytes)?;

    if transaction.assignments.len() != plan.entries().len() {
        return Err(FolderbaseCaptureError::InvalidCaptureTransaction(
            "journal assignment cardinality does not match the CapturePlan".to_owned(),
        ));
    }

    let placeholder_sha256 = "0".repeat(64);
    let mut bindings = Vec::with_capacity(plan.entries().len());
    for (entry, assignment) in plan.entries().iter().zip(&transaction.assignments) {
        if assignment.path != entry.path() || assignment.kind != entry.kind() {
            return Err(FolderbaseCaptureError::InvalidCaptureTransaction(
                "journal assignment does not match the CapturePlan".to_owned(),
            ));
        }
        let binding = match entry.kind() {
            CaptureEntryKind::Directory => PathBinding::directory_from_verified_producer(
                entry.path(),
                assignment.object_id.clone(),
            ),
            CaptureEntryKind::RegularFile => PathBinding::regular_file_from_verified_producer(
                entry.path(),
                assignment.object_id.clone(),
                assigned_object_version_id(assignment)?,
                placeholder_sha256.clone(),
                entry.bytes().ok_or_else(|| {
                    FolderbaseCaptureError::InvalidCaptureTransaction(format!(
                        "regular CapturePlan entry has no byte length: {}",
                        entry.path()
                    ))
                })?,
                entry.executable().unwrap_or(false),
            ),
            CaptureEntryKind::Symlink => PathBinding::symlink_from_verified_producer(
                entry.path(),
                assignment.object_id.clone(),
                assigned_object_version_id(assignment)?,
                entry.symlink_target().ok_or_else(|| {
                    FolderbaseCaptureError::InvalidCaptureTransaction(format!(
                        "symlink CapturePlan entry has no target: {}",
                        entry.path()
                    ))
                })?,
            ),
        };
        bindings.push(binding);
    }

    let exclusions = plan
        .exclusions()
        .iter()
        .map(|exclusion| {
            Exclusion::from_verified_producer(
                exclusion.path(),
                exclusion_kind(exclusion.kind()),
                exclusion_reason(exclusion.reason()),
            )
        })
        .collect();
    let tombstones = transaction.target_tombstones.clone();
    let parts = FolderbaseVersionParts::portable_v1_from_verified_producer(
        plan.folderbase_id(),
        transaction.target_version_id.clone(),
        plan.current_local_head()
            .map(|head| vec![head.version_id().to_owned()])
            .unwrap_or_default(),
        transaction.created_at.clone(),
        RootManifest::from_verified_producer(
            assigned_root_manifest_version_id(transaction),
            plan.root_manifest_sha256(),
            plan.root_manifest_bytes(),
        ),
        FolderbaseVersionEntries::from_verified_producer(bindings, tombstones, exclusions),
    );
    let version = FolderbaseVersion::from_verified_parts(parts)?;
    let mut encoded = BoundedJsonWriter::new(maximum_version_bytes);
    let result = version.encode_bounded(&mut encoded);
    if encoded.exceeded {
        return Err(FolderbaseCaptureError::InvalidCaptureTransaction(
            "future Folderbase Version envelope exceeds its bounded record limit".to_owned(),
        ));
    }
    result.map_err(|source| {
        FolderbaseCaptureError::InvalidCaptureTransaction(format!(
            "future Folderbase Version envelope could not be encoded: {source}"
        ))
    })?;
    Ok(())
}

fn assigned_object_version_id(
    assignment: &CaptureAssignment,
) -> Result<String, FolderbaseCaptureError> {
    assignment
        .prior_object_version_id
        .clone()
        .or_else(|| assignment.candidate_object_version_id.clone())
        .ok_or_else(|| {
            FolderbaseCaptureError::InvalidCaptureTransaction(format!(
                "Object Version assignment is missing for {}",
                assignment.path
            ))
        })
}

fn assigned_root_manifest_version_id(transaction: &CaptureTransaction) -> String {
    transaction
        .prior_root_manifest_version_id
        .clone()
        .unwrap_or_else(|| transaction.root_manifest_candidate_version_id.clone())
}

fn build_and_install_capture(
    store: &FolderbaseVersionStore,
    plan: &CapturePlan,
    local: &LocalVersionStore,
    state: &FolderbaseState,
    transaction: &CaptureTransaction,
    prior: Option<&FolderbaseVersion>,
    checkpoint: &mut impl FnMut(&CaptureCheckpoint),
) -> Result<BuiltCapture, FolderbaseCaptureError> {
    let prior_bindings = prior
        .map(|version| {
            version
                .bindings()
                .iter()
                .map(|binding| (binding.path(), binding))
                .collect::<BTreeMap<_, _>>()
        })
        .unwrap_or_default();
    let root_content = capture_root_manifest(store, plan, local, state, || {
        checkpoint(&CaptureCheckpoint::BeforeObjectBytesRead(
            ".folderbase/manifest.json".to_owned(),
        ));
    })?;
    let root_object_version_id = if prior.is_some_and(|version| {
        version.root_manifest().content_sha256() == root_content.digest
            && version.root_manifest().bytes() == root_content.bytes
    }) {
        let version_id = VersionId::parse(
            transaction
                .prior_root_manifest_version_id
                .clone()
                .ok_or_else(|| {
                    FolderbaseCaptureError::InvalidCaptureTransaction(
                        "prior root manifest assignment is missing".to_owned(),
                    )
                })?,
        )?;
        local.verify_capture_version_record_in(state, &version_id, &root_content)?;
        version_id
    } else {
        install_object_version(
            local,
            state,
            &transaction.root_manifest_object_id,
            &transaction.root_manifest_candidate_version_id,
            &root_content,
            &transaction.created_at,
        )?
    };

    let mut bindings = Vec::with_capacity(plan.entries().len());
    let mut regular_projections = Vec::new();
    for (entry, assignment) in plan.entries().iter().zip(&transaction.assignments) {
        if assignment.path != entry.path()
            || assignment.kind != entry.kind()
            || assignment.observed != *entry.observed()
        {
            return Err(FolderbaseCaptureError::InvalidCaptureTransaction(
                "journal assignment does not match CapturePlan metadata".to_owned(),
            ));
        }
        match entry.kind() {
            CaptureEntryKind::Directory => {
                bindings.push(PathBinding::directory_from_verified_producer(
                    entry.path(),
                    assignment.object_id.clone(),
                ));
            }
            CaptureEntryKind::RegularFile => {
                let content = hash_regular_entry(
                    &store.root_attestation.root,
                    entry,
                    Some((local, state)),
                    || {
                        checkpoint(&CaptureCheckpoint::BeforeObjectBytesRead(
                            entry.path().to_owned(),
                        ));
                    },
                )?;
                let prior_binding = prior_bindings.get(entry.path()).copied();
                let object_version_id = if prior_binding.is_some_and(|binding| {
                    binding.object_id() == assignment.object_id
                        && binding.content_sha256() == Some(content.digest.as_str())
                        && binding.bytes() == Some(content.bytes)
                        && binding.executable() == entry.executable()
                }) {
                    let version_id = VersionId::parse(
                        assignment.prior_object_version_id.clone().ok_or_else(|| {
                            FolderbaseCaptureError::InvalidCaptureTransaction(format!(
                                "prior Object Version is missing for {}",
                                entry.path()
                            ))
                        })?,
                    )?;
                    let object_id = ObjectId::parse(assignment.object_id.clone())?;
                    local.verify_capture_object_version_in(
                        state,
                        &object_id,
                        &version_id,
                        &content,
                    )?;
                    version_id
                } else {
                    install_object_version(
                        local,
                        state,
                        &assignment.object_id,
                        assignment
                            .candidate_object_version_id
                            .as_deref()
                            .expect("regular assignment has Object Version"),
                        &content,
                        &transaction.created_at,
                    )?
                };
                bindings.push(PathBinding::regular_file_from_verified_producer(
                    entry.path(),
                    assignment.object_id.clone(),
                    object_version_id.to_string(),
                    content.digest.clone(),
                    content.bytes,
                    entry.executable().unwrap_or(false),
                ));
                if can_project_legacy_object(entry.path()) {
                    regular_projections.push(regular_projection(
                        local,
                        state,
                        assignment,
                        &object_version_id,
                        prior_binding.and_then(|binding| binding.object_version_id()),
                        &transaction.created_at,
                    )?);
                }
            }
            CaptureEntryKind::Symlink => {
                verify_symlink_entry(&store.root_attestation.root, entry)?;
                let target = entry.symlink_target().expect("planned symlink");
                let content = local.install_content_bytes_in(state, target.as_bytes())?;
                let prior_binding = prior_bindings.get(entry.path()).copied();
                let object_version_id = if prior_binding.is_some_and(|binding| {
                    binding.object_id() == assignment.object_id
                        && binding.symlink_target() == Some(target)
                }) {
                    let version_id = VersionId::parse(
                        assignment.prior_object_version_id.clone().ok_or_else(|| {
                            FolderbaseCaptureError::InvalidCaptureTransaction(format!(
                                "prior symlink Object Version is missing for {}",
                                entry.path()
                            ))
                        })?,
                    )?;
                    let object_id = ObjectId::parse(assignment.object_id.clone())?;
                    local.verify_capture_object_version_in(
                        state,
                        &object_id,
                        &version_id,
                        &content,
                    )?;
                    version_id
                } else {
                    install_object_version(
                        local,
                        state,
                        &assignment.object_id,
                        assignment
                            .candidate_object_version_id
                            .as_deref()
                            .expect("symlink assignment has Object Version"),
                        &content,
                        &transaction.created_at,
                    )?
                };
                bindings.push(PathBinding::symlink_from_verified_producer(
                    entry.path(),
                    assignment.object_id.clone(),
                    object_version_id.to_string(),
                    target,
                ));
            }
        }
    }

    let exclusions = plan
        .exclusions()
        .iter()
        .map(|exclusion| {
            Exclusion::from_verified_producer(
                exclusion.path(),
                exclusion_kind(exclusion.kind()),
                exclusion_reason(exclusion.reason()),
            )
        })
        .collect();
    let tombstones = transaction.target_tombstones.clone();
    let parts = FolderbaseVersionParts::portable_v1_from_verified_producer(
        plan.folderbase_id(),
        transaction.target_version_id.clone(),
        plan.current_local_head()
            .map(|head| vec![head.version_id().to_owned()])
            .unwrap_or_default(),
        transaction.created_at.clone(),
        RootManifest::from_verified_producer(
            root_object_version_id.to_string(),
            root_content.digest,
            root_content.bytes,
        ),
        FolderbaseVersionEntries::from_verified_producer(bindings, tombstones, exclusions),
    );
    let version = FolderbaseVersion::from_verified_parts(parts)?;
    let version_sha256 = version.canonical_digest()?;
    Ok(BuiltCapture {
        version,
        version_sha256,
        regular_projections,
    })
}

fn capture_root_manifest(
    store: &FolderbaseVersionStore,
    plan: &CapturePlan,
    local: &LocalVersionStore,
    state: &FolderbaseState,
    before_read: impl FnOnce(),
) -> Result<ContentDigest, FolderbaseCaptureError> {
    let relative = Path::new(".folderbase/manifest.json");
    let mut file = open_regular_beneath(&store.root_attestation.root, relative)?;
    let display = store.root_attestation.root.join(relative);
    let before = fingerprint_std_file(&file, &display)?;
    before_read();
    let content = local
        .install_content_reader_in(
            state,
            &mut file,
            &store.root_attestation.root.join(relative),
            plan.root_manifest_bytes(),
        )
        .map_err(|source| bounded_source_error(source, relative))?;
    let after = fingerprint_std_file(&file, &display)?;
    let reopened = open_regular_beneath(&store.root_attestation.root, relative)?;
    let reopened_fingerprint = fingerprint_std_file(&reopened, &display)?;
    if before != after
        || before != reopened_fingerprint
        || content.bytes != plan.root_manifest_bytes()
        || content.digest != plan.root_manifest_sha256()
    {
        return Err(FolderbaseCaptureError::CaptureStateChanged(
            relative.to_path_buf(),
        ));
    }
    Ok(content)
}

fn hash_regular_entry(
    root: &Path,
    entry: &CapturePlanEntry,
    installer: Option<(&LocalVersionStore, &FolderbaseState)>,
    before_read: impl FnOnce(),
) -> Result<ContentDigest, FolderbaseCaptureError> {
    let relative = Path::new(entry.path());
    let display = root.join(relative);
    let mut file = open_regular_beneath(root, relative)?;
    let before = fingerprint_std_file(&file, &display)?;
    if before != *entry.observed() {
        return Err(FolderbaseCaptureError::CaptureStateChanged(
            relative.to_path_buf(),
        ));
    }
    before_read();
    let content = match installer {
        Some((local, state)) => local
            .install_content_reader_in(
                state,
                &mut file,
                &display,
                entry.bytes().expect("planned regular length"),
            )
            .map_err(|source| bounded_source_error(source, relative))?,
        None => hash_reader(
            &mut file,
            &display,
            entry.bytes().expect("planned regular length"),
        )
        .map_err(|source| bounded_source_error(source, relative))?,
    };
    let after = fingerprint_std_file(&file, &display)?;
    let reopened = open_regular_beneath(root, relative)?;
    let reopened_fingerprint = fingerprint_std_file(&reopened, &display)?;
    if after != *entry.observed()
        || reopened_fingerprint != *entry.observed()
        || content.bytes != entry.bytes().expect("planned regular length")
    {
        return Err(FolderbaseCaptureError::CaptureStateChanged(
            relative.to_path_buf(),
        ));
    }
    Ok(content)
}

fn bounded_source_error(error: FolderbaseError, path: &Path) -> FolderbaseCaptureError {
    match error {
        FolderbaseError::InvalidRecord { ref message, .. }
            if message.contains("grew beyond its approved byte length") =>
        {
            FolderbaseCaptureError::CaptureStateChanged(path.to_path_buf())
        }
        error => FolderbaseCaptureError::LocalStore(error),
    }
}

fn fingerprint_std_file(
    file: &File,
    display: &Path,
) -> Result<CaptureMetadataFingerprint, FolderbaseCaptureError> {
    CaptureMetadataFingerprint::from_std_file(file).map_err(|source| FolderbaseCaptureError::Io {
        path: display.to_path_buf(),
        source,
    })
}

fn install_object_version(
    local: &LocalVersionStore,
    state: &FolderbaseState,
    object_id: &str,
    version_id: &str,
    content: &ContentDigest,
    captured_at: &str,
) -> Result<VersionId, FolderbaseCaptureError> {
    let object_id = ObjectId::parse(object_id.to_owned())?;
    let version_id = VersionId::parse(version_id.to_owned())?;
    let record = LocalVersionRecord {
        id: version_id.clone(),
        object_id: object_id.clone(),
        content: content.clone(),
        captured_at: captured_at.to_owned(),
        extensions: BTreeMap::new(),
    };
    local.install_or_verify_version_record_in(state, &record)?;
    local.verify_capture_object_version_in(state, &object_id, &version_id, content)?;
    Ok(version_id)
}

fn regular_projection(
    local: &LocalVersionStore,
    state: &FolderbaseState,
    assignment: &CaptureAssignment,
    current_version: &VersionId,
    prior_version: Option<&str>,
    captured_at: &str,
) -> Result<LocalObjectRecord, FolderbaseCaptureError> {
    let object_id = ObjectId::parse(assignment.object_id.clone())?;
    let existing = local.read_capture_object_projection_in(state, &object_id)?;
    let mut record = existing.unwrap_or_else(|| {
        let mut versions = prior_version
            .map(|value| VersionId::parse(value.to_owned()).expect("verified prior version"))
            .into_iter()
            .collect::<Vec<_>>();
        if !versions.contains(current_version) {
            versions.push(current_version.clone());
        }
        LocalObjectRecord {
            schema: "https://folderbase.ai/protocol/0.1/object.schema.json".to_owned(),
            id: object_id.clone(),
            object_type: "file".to_owned(),
            path: assignment.path.clone(),
            lifecycle: ObjectLifecycle {
                status: "canonical".to_owned(),
                extensions: BTreeMap::new(),
            },
            provenance: ObjectProvenance {
                created_at: captured_at.to_owned(),
                source: "folderbase-version-capture".to_owned(),
                extensions: BTreeMap::new(),
            },
            current_version: current_version.clone(),
            versions,
            extensions: BTreeMap::new(),
        }
    });
    if record.id != object_id {
        return Err(FolderbaseCaptureError::InvalidPriorLocalHead(format!(
            "object projection for {} has the wrong stable ID",
            assignment.path
        )));
    }
    record.path.clone_from(&assignment.path);
    if !record.versions.contains(current_version) {
        record.versions.push(current_version.clone());
    }
    record.current_version = current_version.clone();
    Ok(record)
}

fn can_project_legacy_object(path: &str) -> bool {
    !Path::new(path).components().any(|component| {
        matches!(
            component,
            Component::Normal(name)
                if name.to_str().is_some_and(|name| {
                    name.eq_ignore_ascii_case(".git")
                        || name.eq_ignore_ascii_case(".folderbase")
                })
        )
    })
}

fn verify_symlink_entry(
    root: &Path,
    entry: &CapturePlanEntry,
) -> Result<(), FolderbaseCaptureError> {
    let relative = Path::new(entry.path());
    let (parent, name) = open_parent_beneath(root, relative)?;
    let display = root.join(relative);
    let metadata = parent
        .symlink_metadata(&name)
        .map_err(|source| FolderbaseCaptureError::Io {
            path: display.clone(),
            source,
        })?;
    let target = parent
        .read_link(&name)
        .map_err(|source| FolderbaseCaptureError::Io {
            path: display.clone(),
            source,
        })?;
    let rechecked = parent
        .read_link(&name)
        .map_err(|source| FolderbaseCaptureError::Io {
            path: display,
            source,
        })?;
    if !metadata.file_type().is_symlink()
        || capture_entry_fingerprint(
            &parent,
            &name,
            CaptureEntryKind::Symlink,
            &metadata,
            &root.join(relative),
        )? != *entry.observed()
        || target != rechecked
        || target.to_str() != entry.symlink_target()
    {
        return Err(FolderbaseCaptureError::CaptureStateChanged(
            relative.to_path_buf(),
        ));
    }
    Ok(())
}

fn exclusion_kind(kind: CaptureExclusionKind) -> ExclusionKind {
    match kind {
        CaptureExclusionKind::NestedFolderbase => ExclusionKind::NestedFolderbase,
        CaptureExclusionKind::HardLink => ExclusionKind::HardLink,
        CaptureExclusionKind::Fifo => ExclusionKind::Fifo,
        CaptureExclusionKind::Socket => ExclusionKind::Socket,
        CaptureExclusionKind::BlockDevice => ExclusionKind::BlockDevice,
        CaptureExclusionKind::CharacterDevice => ExclusionKind::CharacterDevice,
        CaptureExclusionKind::OtherSpecial => ExclusionKind::OtherSpecial,
    }
}

fn exclusion_reason(reason: CaptureExclusionReason) -> ExclusionReason {
    match reason {
        CaptureExclusionReason::NestedFolderbaseBoundary => {
            ExclusionReason::NestedFolderbaseBoundary
        }
        CaptureExclusionReason::UnsupportedV1 => ExclusionReason::UnsupportedV1,
    }
}

fn hash_reader(
    mut reader: impl Read,
    path: &Path,
    maximum_bytes: u64,
) -> Result<ContentDigest, FolderbaseError> {
    let mut digest = Sha256::new();
    let mut bytes = 0_u64;
    let mut buffer = [0_u8; IO_BUFFER_BYTES];
    let mut bounded = reader.by_ref().take(maximum_bytes.saturating_add(1));
    loop {
        let read = bounded
            .read(&mut buffer)
            .map_err(|source| FolderbaseError::io(path, source))?;
        if read == 0 {
            break;
        }
        bytes = bytes
            .checked_add(read as u64)
            .ok_or_else(|| FolderbaseError::InvalidRecord {
                path: path.to_path_buf(),
                message: "content length exceeds supported range".to_owned(),
            })?;
        if bytes > maximum_bytes {
            return Err(FolderbaseError::InvalidRecord {
                path: path.to_path_buf(),
                message: "source grew beyond its approved byte length".to_owned(),
            });
        }
        digest.update(&buffer[..read]);
    }
    Ok(ContentDigest {
        algorithm: "sha256".to_owned(),
        digest: format!("{:x}", digest.finalize()),
        bytes,
    })
}

fn content_digest(bytes: &[u8]) -> ContentDigest {
    ContentDigest {
        algorithm: "sha256".to_owned(),
        digest: format!("{:x}", Sha256::digest(bytes)),
        bytes: bytes.len() as u64,
    }
}

fn read_and_verify_folderbase_version(
    store: &FolderbaseVersionStore,
    local: &LocalVersionStore,
    state: &FolderbaseState,
    version_id: &str,
) -> Result<FolderbaseVersion, FolderbaseCaptureError> {
    validate_capture_version_id(version_id)?;
    let relative = folderbase_version_relative_path(version_id);
    let encoded = state
        .read_bounded(&relative, MAX_ENCODED_VERSION_BYTES)?
        .ok_or_else(|| {
            FolderbaseCaptureError::InvalidPriorLocalHead("version is missing".to_owned())
        })?;
    let version = FolderbaseVersion::decode_bounded(encoded.as_slice())?;
    if version.version_id() != version_id
        || version.folderbase_id() != store.root_attestation.folderbase_id
    {
        return Err(FolderbaseCaptureError::InvalidPriorLocalHead(
            "Folderbase Version ID or Folderbase membership does not match its path".to_owned(),
        ));
    }
    verify_version_references(local, state, &version)?;
    Ok(version)
}

fn verify_version_references(
    local: &LocalVersionStore,
    state: &FolderbaseState,
    version: &FolderbaseVersion,
) -> Result<(), FolderbaseCaptureError> {
    let root_content = ContentDigest {
        algorithm: "sha256".to_owned(),
        digest: version.root_manifest().content_sha256().to_owned(),
        bytes: version.root_manifest().bytes(),
    };
    local.verify_capture_version_record_in(
        state,
        &VersionId::parse(version.root_manifest().object_version_id().to_owned())?,
        &root_content,
    )?;
    for binding in version.bindings() {
        match binding.kind() {
            PathBindingKind::Directory => {}
            PathBindingKind::RegularFile => {
                let content = ContentDigest {
                    algorithm: "sha256".to_owned(),
                    digest: binding.content_sha256().expect("regular digest").to_owned(),
                    bytes: binding.bytes().expect("regular bytes"),
                };
                local.verify_capture_object_version_in(
                    state,
                    &ObjectId::parse(binding.object_id().to_owned())?,
                    &VersionId::parse(
                        binding
                            .object_version_id()
                            .expect("regular version")
                            .to_owned(),
                    )?,
                    &content,
                )?;
            }
            PathBindingKind::Symlink => {
                let content =
                    content_digest(binding.symlink_target().expect("symlink target").as_bytes());
                local.verify_capture_object_version_in(
                    state,
                    &ObjectId::parse(binding.object_id().to_owned())?,
                    &VersionId::parse(
                        binding
                            .object_version_id()
                            .expect("symlink version")
                            .to_owned(),
                    )?,
                    &content,
                )?;
            }
        }
    }
    for tombstone in version.tombstones() {
        if let Some(version_id) = tombstone.last_object_version_id() {
            local.verify_capture_record_integrity_in(
                state,
                &ObjectId::parse(tombstone.object_id().to_owned())?,
                &VersionId::parse(version_id.to_owned())?,
            )?;
        }
    }
    Ok(())
}

fn install_folderbase_version(
    state: &FolderbaseState,
    version: &FolderbaseVersion,
    expected_sha256: &str,
) -> Result<(), FolderbaseCaptureError> {
    let mut encoded = Vec::new();
    version.encode_bounded(&mut encoded)?;
    let relative = folderbase_version_relative_path(version.version_id());
    match state.publish_new(&relative, &encoded) {
        Ok(()) => {}
        Err(FolderbaseError::WouldOverwrite(_)) => {
            let existing = state
                .read_bounded(&relative, MAX_ENCODED_VERSION_BYTES)?
                .ok_or_else(|| {
                    FolderbaseCaptureError::InvalidCaptureTransaction(
                        "append-only Folderbase Version disappeared".to_owned(),
                    )
                })?;
            if existing != encoded {
                return Err(FolderbaseCaptureError::InvalidCaptureTransaction(
                    "append-only Folderbase Version ID already names different bytes".to_owned(),
                ));
            }
        }
        Err(error) => return Err(error.into()),
    }
    let installed = FolderbaseVersion::decode_bounded(
        state
            .read_bounded(&relative, MAX_ENCODED_VERSION_BYTES)?
            .ok_or_else(|| {
                FolderbaseCaptureError::InvalidCaptureTransaction(
                    "installed Folderbase Version is missing".to_owned(),
                )
            })?
            .as_slice(),
    )?;
    if installed.canonical_digest()? != expected_sha256 {
        return Err(FolderbaseCaptureError::InvalidCaptureTransaction(
            "installed Folderbase Version failed digest verification".to_owned(),
        ));
    }
    Ok(())
}

fn folderbase_version_relative_path(version_id: &str) -> PathBuf {
    Path::new(FOLDERBASE_VERSIONS_DIRECTORY).join(format!("{version_id}.json"))
}

fn validate_transaction(
    store: &FolderbaseVersionStore,
    transaction: &CaptureTransaction,
) -> Result<(), FolderbaseCaptureError> {
    let aggregate_entries = transaction
        .assignments
        .len()
        .checked_add(transaction.target_tombstones.len())
        .ok_or_else(|| {
            FolderbaseCaptureError::InvalidCaptureTransaction(
                "active journal entry aggregate exceeds the supported range".to_owned(),
            )
        })?;
    if transaction.format != CAPTURE_TRANSACTION_FORMAT_V1
        || !transaction.transaction_id.starts_with("fbcapture_")
        || Uuid::parse_str(
            transaction
                .transaction_id
                .strip_prefix("fbcapture_")
                .unwrap_or_default(),
        )
        .is_err()
        || transaction.folderbase_id != store.root_attestation.folderbase_id
        || transaction.root_instance_sha256 != store.root_attestation.root_instance_sha256
        || transaction.plan_sha256.len() != 64
        || aggregate_entries > crate::folderbase_version::MAX_VERSION_ENTRIES
    {
        return Err(FolderbaseCaptureError::InvalidCaptureTransaction(
            "active journal metadata or entry aggregate is inconsistent".to_owned(),
        ));
    }
    validate_capture_version_id(&transaction.target_version_id)?;
    ObjectId::parse(transaction.root_manifest_object_id.clone())?;
    VersionId::parse(transaction.root_manifest_candidate_version_id.clone())?;
    let mut previous = None;
    for assignment in &transaction.assignments {
        if previous.is_some_and(|value: &str| value.as_bytes() >= assignment.path.as_bytes()) {
            return Err(FolderbaseCaptureError::InvalidCaptureTransaction(
                "journal assignments are not in strict portable-path order".to_owned(),
            ));
        }
        ObjectId::parse(assignment.object_id.clone())?;
        match (
            assignment.kind,
            assignment.candidate_object_version_id.as_deref(),
        ) {
            (CaptureEntryKind::Directory, None) => {}
            (CaptureEntryKind::RegularFile | CaptureEntryKind::Symlink, Some(version_id)) => {
                VersionId::parse(version_id.to_owned())?;
            }
            _ => {
                return Err(FolderbaseCaptureError::InvalidCaptureTransaction(
                    "journal Object Version assignment does not match entry kind".to_owned(),
                ));
            }
        }
        if let Some(version_id) = &assignment.prior_object_version_id {
            VersionId::parse(version_id.clone())?;
        }
        previous = Some(assignment.path.as_str());
    }
    let mut previous = None;
    for tombstone in &transaction.target_tombstones {
        if previous.is_some_and(|value: &str| value.as_bytes() >= tombstone.path().as_bytes()) {
            return Err(FolderbaseCaptureError::InvalidCaptureTransaction(
                "journal Tombstones are not in strict portable-path order".to_owned(),
            ));
        }
        ObjectId::parse(tombstone.object_id().to_owned())?;
        match (tombstone.deleted_kind(), tombstone.last_object_version_id()) {
            (DeletedKind::Directory, None) => {}
            (DeletedKind::RegularFile | DeletedKind::Symlink, Some(version_id)) => {
                VersionId::parse(version_id.to_owned())?;
            }
            _ => {
                return Err(FolderbaseCaptureError::InvalidCaptureTransaction(
                    "journal Tombstone Object Version does not match its deleted kind".to_owned(),
                ));
            }
        }
        previous = Some(tombstone.path());
    }
    Ok(())
}

fn validate_transaction_against_plan(
    plan: &CapturePlan,
    transaction: &CaptureTransaction,
    prior: Option<&FolderbaseVersion>,
) -> Result<(), FolderbaseCaptureError> {
    if transaction.assignments.len() != plan.entries().len() {
        return Err(FolderbaseCaptureError::InvalidCaptureTransaction(
            "journal assignment count does not match the approved CapturePlan".to_owned(),
        ));
    }
    let prior_bindings = prior
        .map(|version| {
            version
                .bindings()
                .iter()
                .map(|binding| (binding.path(), binding))
                .collect::<BTreeMap<_, _>>()
        })
        .unwrap_or_default();
    for (entry, assignment) in plan.entries().iter().zip(&transaction.assignments) {
        if assignment.path != entry.path()
            || assignment.kind != entry.kind()
            || assignment.observed != *entry.observed()
        {
            return Err(FolderbaseCaptureError::InvalidCaptureTransaction(
                "journal assignment does not exactly match the approved CapturePlan".to_owned(),
            ));
        }
        let prior_binding = prior_bindings.get(entry.path()).copied();
        match prior_binding {
            Some(binding)
                if assignment.reused_object
                    && binding.kind() == path_binding_kind(entry.kind())
                    && assignment.object_id == binding.object_id()
                    && assignment.prior_object_version_id.as_deref()
                        == binding.object_version_id() => {}
            Some(binding)
                if !assignment.reused_object
                    && binding.kind() != path_binding_kind(entry.kind())
                    && assignment.object_id != binding.object_id()
                    && assignment.prior_object_version_id.is_none() => {}
            None if !assignment.reused_object && assignment.prior_object_version_id.is_none() => {}
            _ => {
                return Err(FolderbaseCaptureError::InvalidCaptureTransaction(format!(
                    "journal identity lineage does not match the verified parent at {}",
                    entry.path()
                )));
            }
        }
    }
    if transaction.target_tombstones != project_target_tombstones(prior, &transaction.assignments) {
        return Err(FolderbaseCaptureError::InvalidCaptureTransaction(
            "journal Tombstones do not match the verified parent and approved CapturePlan"
                .to_owned(),
        ));
    }
    let expected_prior_root = prior.map(|version| version.root_manifest().object_version_id());
    if transaction.prior_root_manifest_version_id.as_deref() != expected_prior_root {
        return Err(FolderbaseCaptureError::InvalidCaptureTransaction(
            "journal root-manifest lineage does not match the verified parent".to_owned(),
        ));
    }
    Ok(())
}

fn validate_committed_transaction(
    transaction: &CaptureTransaction,
    committed: &FolderbaseVersion,
    prior: Option<&FolderbaseVersion>,
) -> Result<(), FolderbaseCaptureError> {
    let expected_parents = transaction
        .expected_head
        .as_ref()
        .map(|head| vec![head.version_id.clone()])
        .unwrap_or_default();
    if committed.version_id() != transaction.target_version_id
        || committed.bindings().len() != transaction.assignments.len()
        || committed.tombstones() != transaction.target_tombstones
        || committed.parents() != expected_parents
        || committed.created_at() != transaction.created_at
    {
        return Err(FolderbaseCaptureError::InvalidCaptureTransaction(
            "committed Folderbase Version does not match its active journal".to_owned(),
        ));
    }
    let prior_bindings = prior
        .map(|version| {
            version
                .bindings()
                .iter()
                .map(|binding| (binding.path(), binding))
                .collect::<BTreeMap<_, _>>()
        })
        .unwrap_or_default();
    for (binding, assignment) in committed.bindings().iter().zip(&transaction.assignments) {
        if binding.path() != assignment.path
            || binding.kind() != path_binding_kind(assignment.kind)
            || binding.object_id() != assignment.object_id
        {
            return Err(FolderbaseCaptureError::InvalidCaptureTransaction(
                "committed binding does not match its active journal".to_owned(),
            ));
        }
        let expected_version = match (
            prior_bindings.get(binding.path()).copied(),
            assignment.reused_object,
        ) {
            (Some(parent), true)
                if parent.kind() == binding.kind()
                    && parent.object_id() == assignment.object_id
                    && parent.object_version_id()
                        == assignment.prior_object_version_id.as_deref() =>
            {
                if binding.object_version_id() == parent.object_version_id() {
                    assignment.prior_object_version_id.as_deref()
                } else {
                    assignment.candidate_object_version_id.as_deref()
                }
            }
            (Some(parent), false)
                if parent.kind() != binding.kind()
                    && parent.object_id() != assignment.object_id
                    && assignment.prior_object_version_id.is_none() =>
            {
                assignment.candidate_object_version_id.as_deref()
            }
            (None, false) if assignment.prior_object_version_id.is_none() => {
                assignment.candidate_object_version_id.as_deref()
            }
            _ => {
                return Err(FolderbaseCaptureError::InvalidCaptureTransaction(format!(
                    "committed identity lineage does not match the verified parent at {}",
                    binding.path()
                )));
            }
        };
        if binding.object_version_id() != expected_version {
            return Err(FolderbaseCaptureError::InvalidCaptureTransaction(format!(
                "committed Object Version does not match its journal assignment at {}",
                binding.path()
            )));
        }
    }
    let expected_prior_root = prior.map(|version| version.root_manifest().object_version_id());
    if transaction.prior_root_manifest_version_id.as_deref() != expected_prior_root {
        return Err(FolderbaseCaptureError::InvalidCaptureTransaction(
            "committed root-manifest lineage does not match the verified parent".to_owned(),
        ));
    }
    let expected_root_version = if committed.root_manifest().object_version_id()
        == expected_prior_root.unwrap_or_default()
    {
        transaction.prior_root_manifest_version_id.as_deref()
    } else {
        Some(transaction.root_manifest_candidate_version_id.as_str())
    };
    if committed.root_manifest().object_version_id() != expected_root_version.unwrap_or_default() {
        return Err(FolderbaseCaptureError::InvalidCaptureTransaction(
            "committed root-manifest Object Version does not match its journal assignment"
                .to_owned(),
        ));
    }
    Ok(())
}

fn read_active_transaction(
    state: &FolderbaseState,
) -> Result<Option<ActiveCaptureTransaction>, FolderbaseCaptureError> {
    let Some(encoded) = state.read_bounded(
        Path::new(ACTIVE_CAPTURE_TRANSACTION_PATH),
        MAX_CAPTURE_TRANSACTION_BYTES,
    )?
    else {
        return Ok(None);
    };
    let authority_sha256 = format!("{:x}", Sha256::digest(&encoded));
    let transaction = match serde_json::from_slice::<CaptureTransaction>(&encoded) {
        Ok(transaction) => transaction,
        Err(current_error) => {
            match serde_json::from_slice::<ReleasedV1CaptureTransaction>(&encoded) {
                Ok(transaction) => transaction.into(),
                Err(released_error) => {
                    return Err(FolderbaseCaptureError::InvalidCaptureTransaction(format!(
                        "active journal is invalid JSON for current ({current_error}) and released v1 ({released_error}) wire formats"
                    )));
                }
            }
        }
    };
    Ok(Some(ActiveCaptureTransaction {
        transaction,
        authority_sha256,
    }))
}

fn ensure_no_active_capture(state: &FolderbaseState) -> Result<(), FolderbaseCaptureError> {
    if state
        .read_bounded(
            Path::new(ACTIVE_CAPTURE_TRANSACTION_PATH),
            MAX_CAPTURE_TRANSACTION_BYTES,
        )?
        .is_some()
    {
        return Err(FolderbaseCaptureError::ConflictingTransaction(
            "a Folderbase Version capture is pending",
        ));
    }
    Ok(())
}

fn ensure_no_active_restore(state: &FolderbaseState) -> Result<(), FolderbaseCaptureError> {
    if state
        .read_bounded(
            Path::new(ACTIVE_RESTORE_TRANSACTION_PATH),
            MAX_CAPTURE_TRANSACTION_BYTES,
        )?
        .is_some()
        || state
            .read_bounded(
                Path::new(RESTORE_CLEANUP_RECOVERY_PATH),
                MAX_CAPTURE_TRANSACTION_BYTES,
            )?
            .is_some()
    {
        return Err(FolderbaseCaptureError::ConflictingTransaction(
            "a Tombstone restore is pending",
        ));
    }
    Ok(())
}

fn read_active_restore_transaction(
    state: &FolderbaseState,
) -> Result<Option<RestoreTransaction>, FolderbaseCaptureError> {
    let Some(encoded) = state.read_bounded(
        Path::new(ACTIVE_RESTORE_TRANSACTION_PATH),
        MAX_CAPTURE_TRANSACTION_BYTES,
    )?
    else {
        return Ok(None);
    };
    serde_json::from_slice(&encoded)
        .map(Some)
        .map_err(|source| {
            FolderbaseCaptureError::InvalidRestoreTransaction(format!(
                "active restore journal is invalid JSON: {source}"
            ))
        })
}

fn write_active_restore_transaction(
    state: &FolderbaseState,
    transaction: &RestoreTransaction,
) -> Result<(), FolderbaseCaptureError> {
    let encoded = encode_restore_transaction(transaction)?;
    state
        .publish_new(Path::new(ACTIVE_RESTORE_TRANSACTION_PATH), &encoded)
        .map_err(Into::into)
}

fn read_restore_cleanup_recovery(
    state: &FolderbaseState,
) -> Result<Option<RestoreCleanupRecovery>, FolderbaseCaptureError> {
    let relative = Path::new(RESTORE_CLEANUP_RECOVERY_PATH);
    let Some(encoded) = state.read_bounded(relative, MAX_CAPTURE_TRANSACTION_BYTES)? else {
        return Ok(None);
    };
    let recovery: RestoreCleanupRecovery = serde_json::from_slice(&encoded).map_err(|source| {
        FolderbaseCaptureError::InvalidRestoreTransaction(format!(
            "restore cleanup recovery is invalid JSON: {source}"
        ))
    })?;
    if recovery.format != RESTORE_CLEANUP_RECOVERY_FORMAT_V2
        || !is_lowercase_sha256(&recovery.published_identity_sha256)
    {
        return Err(FolderbaseCaptureError::InvalidRestoreTransaction(
            "restore cleanup recovery format or publication identity is invalid".to_owned(),
        ));
    }
    Ok(Some(recovery))
}

fn write_restore_cleanup_recovery(
    state: &FolderbaseState,
    recovery: &RestoreCleanupRecovery,
) -> Result<(), FolderbaseCaptureError> {
    let relative = Path::new(RESTORE_CLEANUP_RECOVERY_PATH);
    let encoded = encode_restore_cleanup_recovery(recovery)?;
    match state.publish_new(relative, &encoded) {
        Ok(()) => Ok(()),
        Err(FolderbaseError::WouldOverwrite(_)) => {
            let existing = state
                .read_bounded(relative, MAX_CAPTURE_TRANSACTION_BYTES)?
                .ok_or_else(|| {
                    FolderbaseCaptureError::InvalidRestoreTransaction(
                        "restore cleanup recovery disappeared".to_owned(),
                    )
                })?;
            if existing != encoded {
                return Err(FolderbaseCaptureError::InvalidRestoreTransaction(
                    "restore cleanup recovery slot names different bytes".to_owned(),
                ));
            }
            Ok(())
        }
        Err(error) => Err(error.into()),
    }
}

fn replace_restore_cleanup_recovery(
    state: &FolderbaseState,
    expected: &RestoreCleanupRecovery,
    target: &RestoreCleanupRecovery,
) -> Result<(), FolderbaseCaptureError> {
    let relative = Path::new(RESTORE_CLEANUP_RECOVERY_PATH);
    let expected = encode_restore_cleanup_recovery(expected)?;
    let target = encode_restore_cleanup_recovery(target)?;
    let current = state
        .read_bounded(relative, MAX_CAPTURE_TRANSACTION_BYTES)?
        .ok_or_else(|| {
            FolderbaseCaptureError::InvalidRestoreTransaction(
                "restore cleanup recovery disappeared before transition".to_owned(),
            )
        })?;
    if current != expected {
        return Err(FolderbaseCaptureError::InvalidRestoreTransaction(
            "restore cleanup recovery changed before transition".to_owned(),
        ));
    }
    state.replace(relative, &target)?;
    if state
        .read_bounded(relative, MAX_CAPTURE_TRANSACTION_BYTES)?
        .as_deref()
        != Some(target.as_slice())
    {
        return Err(FolderbaseCaptureError::InvalidRestoreTransaction(
            "restore cleanup recovery transition did not verify".to_owned(),
        ));
    }
    Ok(())
}

fn encode_restore_cleanup_recovery(
    recovery: &RestoreCleanupRecovery,
) -> Result<Vec<u8>, FolderbaseCaptureError> {
    let mut encoded = serde_json::to_vec_pretty(recovery).map_err(|source| {
        FolderbaseCaptureError::InvalidRestoreTransaction(format!(
            "restore cleanup recovery encoding failed: {source}"
        ))
    })?;
    encoded.push(b'\n');
    if encoded.len() as u64 > MAX_CAPTURE_TRANSACTION_BYTES {
        return Err(FolderbaseCaptureError::InvalidRestoreTransaction(
            "restore cleanup recovery exceeds its bounded record limit".to_owned(),
        ));
    }
    Ok(encoded)
}

fn remove_restore_cleanup_recovery(state: &FolderbaseState) -> Result<(), FolderbaseCaptureError> {
    let relative = Path::new(RESTORE_CLEANUP_RECOVERY_PATH);
    match state.remove_durable(relative) {
        Ok(()) => Ok(()),
        Err(error) => match state.read_bounded(relative, MAX_CAPTURE_TRANSACTION_BYTES) {
            Ok(None) => Ok(()),
            Ok(Some(_)) | Err(_) => Err(error.into()),
        },
    }
}

fn read_restore_completion_receipt(
    state: &FolderbaseState,
) -> Result<Option<RestoreCompletionReceipt>, FolderbaseCaptureError> {
    let relative = Path::new(RESTORE_COMPLETION_PATH);
    let Some(encoded) = state.read_bounded(relative, MAX_CAPTURE_TRANSACTION_BYTES)? else {
        return Ok(None);
    };
    let completion: RestoreCompletionReceipt =
        serde_json::from_slice(&encoded).map_err(|source| {
            FolderbaseCaptureError::InvalidRestoreTransaction(format!(
                "restore completion receipt is invalid JSON: {source}"
            ))
        })?;
    if completion.format != RESTORE_COMPLETION_FORMAT_V2
        || !is_lowercase_sha256(&completion.published_identity_sha256)
    {
        return Err(FolderbaseCaptureError::InvalidRestoreTransaction(
            "restore completion receipt format or publication identity is invalid".to_owned(),
        ));
    }
    Ok(Some(completion))
}

fn write_restore_authority_record(
    state: &FolderbaseState,
    transaction: &RestoreTransaction,
    published_identity_sha256: &str,
) -> Result<(), FolderbaseCaptureError> {
    let record = restore_authority_record(transaction, published_identity_sha256);
    let mut encoded = serde_json::to_vec_pretty(&record).map_err(|source| {
        FolderbaseCaptureError::InvalidRestoreTransaction(format!(
            "restore authority encoding failed: {source}"
        ))
    })?;
    encoded.push(b'\n');
    if encoded.len() as u64 > MAX_RESTORE_AUTHORITY_BYTES {
        return Err(FolderbaseCaptureError::InvalidRestoreTransaction(
            "restore authority exceeds its bounded record limit".to_owned(),
        ));
    }
    let relative = restore_authority_record_path(&transaction.transaction_id);
    match state.publish_new(&relative, &encoded) {
        Ok(()) => Ok(()),
        Err(FolderbaseError::WouldOverwrite(_)) => {
            if state
                .read_bounded(&relative, MAX_RESTORE_AUTHORITY_BYTES)?
                .as_deref()
                == Some(encoded.as_slice())
            {
                Ok(())
            } else {
                Err(FolderbaseCaptureError::InvalidRestoreTransaction(
                    "restore authority slot names different bytes".to_owned(),
                ))
            }
        }
        Err(error) => Err(error.into()),
    }
}

fn restore_authority_record(
    transaction: &RestoreTransaction,
    published_identity_sha256: &str,
) -> RestoreAuthorityRecord {
    RestoreAuthorityRecord {
        format: RESTORE_AUTHORITY_FORMAT_V1.to_owned(),
        folderbase_id: transaction.folderbase_id.clone(),
        root_instance_sha256: transaction.root_instance_sha256.clone(),
        transaction_id: transaction.transaction_id.clone(),
        workspace_path: transaction.path.clone(),
        private_stage_path: restore_stage_path(transaction)
            .to_str()
            .expect("validated restore stage paths are UTF-8")
            .to_owned(),
        published_identity_sha256: published_identity_sha256.to_owned(),
    }
}

fn write_restore_completion_receipt(
    state: &FolderbaseState,
    transaction: &RestoreTransaction,
    published_identity_sha256: &str,
) -> Result<(), FolderbaseCaptureError> {
    let completion = RestoreCompletionReceipt {
        format: RESTORE_COMPLETION_FORMAT_V2.to_owned(),
        transaction: transaction.clone(),
        published_identity_sha256: published_identity_sha256.to_owned(),
    };
    let mut encoded = serde_json::to_vec_pretty(&completion).map_err(|source| {
        FolderbaseCaptureError::InvalidRestoreTransaction(format!(
            "restore completion receipt encoding failed: {source}"
        ))
    })?;
    encoded.push(b'\n');
    if encoded.len() as u64 > MAX_CAPTURE_TRANSACTION_BYTES {
        return Err(FolderbaseCaptureError::InvalidRestoreTransaction(
            "restore completion receipt exceeds its bounded record limit".to_owned(),
        ));
    }
    state
        .replace(Path::new(RESTORE_COMPLETION_PATH), &encoded)
        .map_err(Into::into)
}

fn encode_restore_transaction(
    transaction: &RestoreTransaction,
) -> Result<Vec<u8>, FolderbaseCaptureError> {
    let mut encoded = serde_json::to_vec_pretty(transaction).map_err(|source| {
        FolderbaseCaptureError::InvalidRestoreTransaction(format!(
            "restore journal encoding failed: {source}"
        ))
    })?;
    encoded.push(b'\n');
    if encoded.len() as u64 > MAX_CAPTURE_TRANSACTION_BYTES {
        return Err(FolderbaseCaptureError::InvalidRestoreTransaction(
            "restore journal exceeds its bounded record limit".to_owned(),
        ));
    }
    Ok(encoded)
}

fn remove_active_restore_transaction(
    state: &FolderbaseState,
) -> Result<(), FolderbaseCaptureError> {
    state
        .remove_durable(Path::new(ACTIVE_RESTORE_TRANSACTION_PATH))
        .map_err(Into::into)
}

fn validate_restore_transaction(
    store: &FolderbaseVersionStore,
    transaction: &RestoreTransaction,
) -> Result<(), FolderbaseCaptureError> {
    let safe_path = safe_content_path(Path::new(&transaction.path)).map_err(|_| {
        FolderbaseCaptureError::InvalidRestoreTransaction(
            "restore path is not an ordinary portable content path".to_owned(),
        )
    })?;
    if transaction.format != RESTORE_TRANSACTION_FORMAT_V1
        || transaction.folderbase_id != store.root_attestation.folderbase_id
        || transaction.root_instance_sha256 != store.root_attestation.root_instance_sha256
        || transaction.path != safe_path.to_string_lossy()
        || !transaction.transaction_id.starts_with("fbrestore_")
        || Uuid::parse_str(
            transaction
                .transaction_id
                .strip_prefix("fbrestore_")
                .unwrap_or_default(),
        )
        .is_err()
        || !is_lowercase_sha256(&transaction.expected_head.version_sha256)
        || !is_lowercase_sha256(transaction.expected_head.authority.sha256())
        || !is_lowercase_sha256(&transaction.target_version_sha256)
    {
        return Err(FolderbaseCaptureError::InvalidRestoreTransaction(
            "restore journal identity or digest fields are invalid".to_owned(),
        ));
    }
    validate_capture_version_id(&transaction.expected_head.version_id)?;
    validate_capture_version_id(&transaction.target_version_id)?;
    if transaction.expected_head.version_id == transaction.target_version_id
        || transaction.tombstone.path() != transaction.path
        || transaction.binding.path() != transaction.path
        || transaction.tombstone.deleted_kind() != DeletedKind::RegularFile
        || transaction.binding.kind() != PathBindingKind::RegularFile
        || transaction.tombstone.object_id() != transaction.binding.object_id()
        || transaction.tombstone.last_object_version_id() != transaction.binding.object_version_id()
        || transaction.binding.content_sha256().is_none()
        || transaction.binding.bytes().is_none()
        || transaction.binding.executable().is_none()
    {
        return Err(FolderbaseCaptureError::InvalidRestoreTransaction(
            "restore Tombstone and live binding do not describe one exact ordinary file".to_owned(),
        ));
    }
    ObjectId::parse(transaction.binding.object_id().to_owned())?;
    VersionId::parse(
        transaction
            .binding
            .object_version_id()
            .expect("validated regular binding")
            .to_owned(),
    )?;
    Ok(())
}

fn is_lowercase_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn compare_and_swap_restore_head(
    state: &FolderbaseState,
    expected: &JournalHead,
    target: &LocalHeadRecord,
) -> Result<(), FolderbaseCaptureError> {
    let encoded = json_bytes(target)?;
    state.verify_still_attached()?;
    let current = read_head_record(state)?.ok_or(FolderbaseCaptureError::LocalHeadChanged)?;
    if JournalHead::from(&current) != *expected {
        return Err(FolderbaseCaptureError::LocalHeadChanged);
    }
    state.replace(Path::new(LOCAL_HEAD_PATH), &encoded)?;
    state.verify_still_attached()?;
    if read_head_record(state)?.as_ref() != Some(target) {
        return Err(FolderbaseCaptureError::InvalidRestoreTransaction(
            "Local Head replacement did not verify".to_owned(),
        ));
    }
    Ok(())
}

fn compare_and_swap_exact_local_head(
    state: &FolderbaseState,
    expected: &LocalHeadRecord,
    target: &LocalHeadRecord,
) -> Result<(), FolderbaseCaptureError> {
    let encoded = json_bytes(target)?;
    state.verify_still_attached()?;
    if read_head_record(state)?.as_ref() != Some(expected) {
        return Err(FolderbaseCaptureError::LocalHeadChanged);
    }
    state.replace(Path::new(LOCAL_HEAD_PATH), &encoded)?;
    state.verify_still_attached()?;
    if read_head_record(state)?.as_ref() != Some(target) {
        return Err(FolderbaseCaptureError::InvalidLocalHead(
            "Local Head authority replacement did not verify".to_owned(),
        ));
    }
    Ok(())
}

fn normalize_legacy_local_head(state: &FolderbaseState) -> Result<(), FolderbaseCaptureError> {
    let Some(legacy) = read_head_record(state)? else {
        return Ok(());
    };
    if legacy.format != "folderbase-local-head-v1" {
        return Ok(());
    }
    let normalized = LocalHeadRecord {
        format: "folderbase-local-head-v2".to_owned(),
        ..legacy.clone()
    };
    compare_and_swap_exact_local_head(state, &legacy, &normalized)
}

fn write_active_transaction_with_limit(
    state: &FolderbaseState,
    transaction: &CaptureTransaction,
    maximum_bytes: u64,
) -> Result<String, FolderbaseCaptureError> {
    let encoded = encode_active_transaction(transaction, maximum_bytes)?;
    state
        .publish_new(Path::new(ACTIVE_CAPTURE_TRANSACTION_PATH), &encoded)
        .map_err(FolderbaseCaptureError::from)?;
    Ok(format!("{:x}", Sha256::digest(&encoded)))
}

fn encode_active_transaction(
    transaction: &CaptureTransaction,
    maximum_bytes: u64,
) -> Result<Vec<u8>, FolderbaseCaptureError> {
    let mut encoded = BoundedJsonWriter::new(maximum_bytes);
    let result = serde_json::to_writer_pretty(&mut encoded, transaction);
    if encoded.exceeded {
        return Err(FolderbaseCaptureError::InvalidCaptureTransaction(
            "active journal exceeds its bounded record limit".to_owned(),
        ));
    }
    result.map_err(|source| {
        FolderbaseCaptureError::InvalidCaptureTransaction(format!(
            "capture record encoding failed: {source}"
        ))
    })?;
    encoded.write_all(b"\n").map_err(|_| {
        FolderbaseCaptureError::InvalidCaptureTransaction(
            "active journal exceeds its bounded record limit".to_owned(),
        )
    })?;
    Ok(encoded.bytes)
}

struct BoundedJsonWriter {
    bytes: Vec<u8>,
    maximum_bytes: u64,
    exceeded: bool,
}

impl BoundedJsonWriter {
    fn new(maximum_bytes: u64) -> Self {
        Self {
            bytes: Vec::with_capacity(maximum_bytes.min(64 * 1024) as usize),
            maximum_bytes,
            exceeded: false,
        }
    }
}

impl Write for BoundedJsonWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let Some(next_len) = (self.bytes.len() as u64).checked_add(bytes.len() as u64) else {
            self.exceeded = true;
            return Err(std::io::Error::other("bounded JSON record exceeded"));
        };
        if next_len > self.maximum_bytes {
            self.exceeded = true;
            return Err(std::io::Error::other("bounded JSON record exceeded"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn remove_active_transaction(state: &FolderbaseState) -> Result<(), FolderbaseCaptureError> {
    state
        .remove_durable(Path::new(ACTIVE_CAPTURE_TRANSACTION_PATH))
        .map_err(Into::into)
}

fn compare_and_swap_local_head(
    state: &FolderbaseState,
    expected: Option<&CaptureLocalHead>,
    target: &LocalHeadRecord,
) -> Result<(), FolderbaseCaptureError> {
    let expected = expected.map(JournalHead::from);
    let encoded = json_bytes(target)?;
    state.verify_still_attached()?;
    let current = read_head_record(state)?;
    let current_summary = current.as_ref().map(|head| JournalHead {
        version_id: head.version_id.clone(),
        version_sha256: head.version_sha256.clone(),
        authority: head.authority.clone(),
    });
    if current_summary != expected {
        return Err(FolderbaseCaptureError::LocalHeadChanged);
    }
    state.replace(Path::new(LOCAL_HEAD_PATH), &encoded)?;
    state.verify_still_attached()?;
    if read_head_record(state)?.as_ref() != Some(target) {
        return Err(FolderbaseCaptureError::InvalidCaptureTransaction(
            "Local Head replacement did not verify".to_owned(),
        ));
    }
    Ok(())
}

fn read_head_record(
    state: &FolderbaseState,
) -> Result<Option<LocalHeadRecord>, FolderbaseCaptureError> {
    let Some(encoded) =
        state.read_bounded(Path::new(LOCAL_HEAD_PATH), crate::MAX_LOCAL_HEAD_BYTES)?
    else {
        return Ok(None);
    };
    let wire: LocalHeadRecordWire = serde_json::from_slice(&encoded).map_err(|source| {
        FolderbaseCaptureError::InvalidLocalHead(format!("Local Head JSON is invalid: {source}"))
    })?;
    let head = match wire {
        LocalHeadRecordWire::V2(head) if head.format == "folderbase-local-head-v2" => {
            LocalHeadRecord {
                format: head.format,
                folderbase_id: head.folderbase_id,
                root_instance_sha256: head.root_instance_sha256,
                version_id: head.version_id,
                version_sha256: head.version_sha256,
                authority: head.authority,
            }
        }
        LocalHeadRecordWire::V1(head) if head.format == "folderbase-local-head-v1" => {
            LocalHeadRecord {
                format: head.format,
                folderbase_id: head.folderbase_id,
                root_instance_sha256: head.root_instance_sha256,
                version_id: head.version_id,
                version_sha256: head.version_sha256,
                authority: LocalHeadAuthority::CaptureTransactionV1 {
                    sha256: head.transaction_sha256,
                },
            }
        }
        _ => {
            return Err(FolderbaseCaptureError::InvalidLocalHead(
                "Local Head format is unsupported".to_owned(),
            ));
        }
    };
    if head.version_sha256.len() != 64
        || head.authority.sha256().len() != 64
        || !head
            .version_sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || !head
            .authority
            .sha256()
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(FolderbaseCaptureError::InvalidLocalHead(
            "Local Head fields are invalid".to_owned(),
        ));
    }
    validate_capture_version_id(&head.version_id)?;
    Ok(Some(head))
}

fn finish_committed_transaction(
    store: &FolderbaseVersionStore,
    local: &LocalVersionStore,
    state: &FolderbaseState,
    transaction: &CaptureTransaction,
) -> Result<(), FolderbaseCaptureError> {
    let version =
        read_and_verify_folderbase_version(store, local, state, &transaction.target_version_id)?;
    for assignment in &transaction.assignments {
        let Some(binding) = version.lookup_binding(&assignment.path) else {
            return Err(FolderbaseCaptureError::InvalidCaptureTransaction(format!(
                "committed version has no assignment for {}",
                assignment.path
            )));
        };
        if binding.object_id() != assignment.object_id
            || binding.kind() != path_binding_kind(assignment.kind)
        {
            return Err(FolderbaseCaptureError::InvalidCaptureTransaction(format!(
                "committed binding differs from journal assignment at {}",
                assignment.path
            )));
        }
        if assignment.kind == CaptureEntryKind::RegularFile
            && can_project_legacy_object(&assignment.path)
        {
            let projection = regular_projection(
                local,
                state,
                assignment,
                &VersionId::parse(
                    binding
                        .object_version_id()
                        .expect("regular version")
                        .to_owned(),
                )?,
                assignment.prior_object_version_id.as_deref(),
                &transaction.created_at,
            )?;
            local.write_capture_object_projection_in(state, &projection)?;
        }
    }
    write_capture_identities(state, transaction)
}

fn write_capture_identities(
    state: &FolderbaseState,
    transaction: &CaptureTransaction,
) -> Result<(), FolderbaseCaptureError> {
    for assignment in &transaction.assignments {
        // This records the identity of the bytes that Head sealed, not a claim
        // about whatever currently occupies the path. If the live entry was
        // replaced after Head, the mismatch makes subsequent reuse fail closed.
        let record = CaptureIdentityRecord {
            format: "folderbase-capture-identity-v1".to_owned(),
            object_id: assignment.object_id.clone(),
            kind: assignment.kind,
            observed: assignment.observed.clone(),
        };
        state.replace(
            &capture_identity_relative_path(&assignment.object_id),
            &json_bytes(&record)?,
        )?;
    }
    Ok(())
}

fn capture_identity_relative_path(object_id: &str) -> PathBuf {
    Path::new(CAPTURE_IDENTITIES_DIRECTORY).join(format!("{object_id}.json"))
}

fn open_root_capability(root: &Path) -> Result<Dir, FolderbaseCaptureError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        options.custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE,
            FILE_SHARE_READ, FILE_SHARE_WRITE,
        };

        options
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE);
    }
    let file = options
        .open(root)
        .map_err(|source| FolderbaseCaptureError::Io {
            path: root.to_path_buf(),
            source,
        })?;
    let metadata = file
        .metadata()
        .map_err(|source| FolderbaseCaptureError::Io {
            path: root.to_path_buf(),
            source,
        })?;
    if metadata_is_link_or_reparse(&metadata) || !metadata.is_dir() {
        return Err(FolderbaseCaptureError::PlanStoreMismatch);
    }
    Ok(Dir::from_std_file(file))
}

fn open_parent_beneath(
    root: &Path,
    relative: &Path,
) -> Result<(Dir, std::ffi::OsString), FolderbaseCaptureError> {
    let mut components = relative.components().peekable();
    let mut directory = open_root_capability(root)?;
    let mut traversed = PathBuf::new();
    while let Some(component) = components.next() {
        let Component::Normal(name) = component else {
            return Err(FolderbaseCaptureError::CaptureStateChanged(
                relative.to_path_buf(),
            ));
        };
        if components.peek().is_none() {
            return Ok((directory, name.to_os_string()));
        }
        traversed.push(name);
        directory =
            directory
                .open_dir_nofollow(name)
                .map_err(|source| FolderbaseCaptureError::Io {
                    path: root.join(&traversed),
                    source,
                })?;
    }
    Err(FolderbaseCaptureError::CaptureStateChanged(
        relative.to_path_buf(),
    ))
}

fn open_regular_beneath(root: &Path, relative: &Path) -> Result<File, FolderbaseCaptureError> {
    let (parent, name) = open_parent_beneath(root, relative)?;
    let mut options = CapOpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    let file = parent
        .open_with(&name, &options)
        .map_err(|source| FolderbaseCaptureError::Io {
            path: root.join(relative),
            source,
        })?;
    let metadata = file
        .metadata()
        .map_err(|source| FolderbaseCaptureError::Io {
            path: root.join(relative),
            source,
        })?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(FolderbaseCaptureError::CaptureStateChanged(
            relative.to_path_buf(),
        ));
    }
    Ok(file.into_std())
}

#[cfg(test)]
fn read_regular_beneath(
    root: &Path,
    relative: &Path,
    maximum_bytes: u64,
) -> Result<Option<Vec<u8>>, FolderbaseCaptureError> {
    let mut file = match open_regular_beneath(root, relative) {
        Ok(file) => file,
        Err(FolderbaseCaptureError::Io { source, .. })
            if source.kind() == std::io::ErrorKind::NotFound =>
        {
            return Ok(None);
        }
        Err(error) => return Err(error),
    };
    if file
        .metadata()
        .map_err(|source| FolderbaseCaptureError::Io {
            path: root.join(relative),
            source,
        })?
        .len()
        > maximum_bytes
    {
        return Err(FolderbaseCaptureError::InvalidCaptureTransaction(format!(
            "{} exceeds its bounded record limit",
            relative.display()
        )));
    }
    let mut encoded = Vec::new();
    Read::by_ref(&mut file)
        .take(maximum_bytes + 1)
        .read_to_end(&mut encoded)
        .map_err(|source| FolderbaseCaptureError::Io {
            path: root.join(relative),
            source,
        })?;
    if encoded.len() as u64 > maximum_bytes {
        return Err(FolderbaseCaptureError::InvalidCaptureTransaction(format!(
            "{} exceeds its bounded record limit",
            relative.display()
        )));
    }
    Ok(Some(encoded))
}

fn json_bytes(value: &impl Serialize) -> Result<Vec<u8>, FolderbaseCaptureError> {
    let mut encoded = serde_json::to_vec_pretty(value).map_err(|source| {
        FolderbaseCaptureError::InvalidCaptureTransaction(format!(
            "capture record encoding failed: {source}"
        ))
    })?;
    encoded.push(b'\n');
    Ok(encoded)
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        panic::{AssertUnwindSafe, catch_unwind},
        sync::{Arc, Barrier},
        thread,
    };

    use tempfile::{TempDir, tempdir};

    use super::*;

    const MANIFEST: &[u8] = br#"{
  "protocol_version": "0.4.0",
  "folderbase": {
    "id": "folderbase_019f9b75-4f42-7f65-a012-2bfecdd8c473"
  }
}
"#;

    fn folderbase() -> TempDir {
        let root = tempdir().expect("temporary Folderbase");
        fs::create_dir(root.path().join(".folderbase")).expect("state");
        fs::write(root.path().join(".folderbase/manifest.json"), MANIFEST).expect("manifest");
        fs::write(root.path().join(".folderbaseignore"), "").expect("ignore");
        fs::write(root.path().join("FOLDERBASE.md"), "# Folderbase\n").expect("entry");
        fs::write(root.path().join("active.bin"), b"first opaque bytes").expect("content");
        root
    }

    fn copy_directory(source: &Path, destination: &Path) {
        fs::create_dir_all(destination).expect("create copied directory");
        for entry in fs::read_dir(source).expect("read copied directory") {
            let entry = entry.expect("directory entry");
            let destination = destination.join(entry.file_name());
            if entry.file_type().expect("entry type").is_dir() {
                copy_directory(&entry.path(), &destination);
            } else {
                fs::copy(entry.path(), destination).expect("copy file");
            }
        }
    }

    fn active_transaction(root: &Path) -> Option<CaptureTransaction> {
        read_active_transaction(&FolderbaseState::open(root).expect("state"))
            .expect("active intent")
            .map(|active| active.transaction)
    }

    fn local_head(root: &Path) -> Option<LocalHeadRecord> {
        read_head_record(&FolderbaseState::open(root).expect("state")).expect("Local Head")
    }

    fn install_test_version(root: &Path, version: &FolderbaseVersion) {
        let state = FolderbaseState::open(root).expect("state");
        install_folderbase_version(
            &state,
            version,
            &version.canonical_digest().expect("version digest"),
        )
        .expect("install test version");
    }

    fn point_test_head(root: &Path, version: &FolderbaseVersion) {
        let state = FolderbaseState::open(root).expect("state");
        let store = FolderbaseVersionStore::open(root).expect("store");
        let version_sha256 = version.canonical_digest().expect("version digest");
        state
            .replace(
                Path::new(LOCAL_HEAD_PATH),
                &json_bytes(&LocalHeadRecord {
                    format: "folderbase-local-head-v2".to_owned(),
                    folderbase_id: version.folderbase_id().to_owned(),
                    root_instance_sha256: store.root_attestation.root_instance_sha256.clone(),
                    version_id: version.version_id().to_owned(),
                    version_sha256: version_sha256.clone(),
                    authority: LocalHeadAuthority::VersionDerivedV1 {
                        sha256: local_head_authority_sha256(
                            &store,
                            version.version_id(),
                            &version_sha256,
                        )
                        .expect("Head authority"),
                    },
                })
                .expect("Head bytes"),
            )
            .expect("point test Head");
    }

    #[test]
    fn tombstone_restore_reopens_and_converges_at_every_persistence_checkpoint() {
        for fault in [
            RestoreCheckpoint::JournalDurable,
            RestoreCheckpoint::StageDurable,
            RestoreCheckpoint::TargetPublished,
            RestoreCheckpoint::VersionDurable,
            RestoreCheckpoint::HeadReplaced,
            RestoreCheckpoint::PublicationVerified,
            RestoreCheckpoint::ProjectionDurable,
            RestoreCheckpoint::CleanupRecoveryDurable,
            RestoreCheckpoint::BeforeStageRetirement,
            RestoreCheckpoint::AfterStageRetirement,
            RestoreCheckpoint::CleanupIntentRetired,
            RestoreCheckpoint::CompletionDurable,
            RestoreCheckpoint::CleanupComplete,
        ] {
            let root = folderbase();
            let store = FolderbaseVersionStore::open(root.path()).expect("open");
            store
                .seal_capture(store.plan_capture().expect("genesis"))
                .expect("genesis");
            fs::remove_file(root.path().join("active.bin")).expect("delete");
            let deletion = store
                .seal_capture(store.plan_capture().expect("deletion"))
                .expect("deletion");
            let interrupted = catch_unwind(AssertUnwindSafe(|| {
                store.restore_tombstone_with_hook("active.bin", |checkpoint| {
                    if checkpoint == &fault {
                        panic!("simulated restore termination at {fault:?}");
                    }
                })
            }));
            assert!(interrupted.is_err(), "fault {fault:?}");
            drop(store);

            let reopened = FolderbaseVersionStore::open(root.path()).expect("reopen");
            let retry = reopened
                .restore_tombstone("active.bin")
                .expect("every durable checkpoint must retain an exact retry result");
            assert!(retry.created() || fault >= RestoreCheckpoint::HeadReplaced);
            let restored = reopened
                .read_version(retry.version_id())
                .expect("restored version");
            assert_eq!(restored.parents(), &[deletion.version_id().to_owned()]);
            assert_eq!(
                fs::read(root.path().join("active.bin")).expect("restored bytes"),
                b"first opaque bytes"
            );
            assert!(restored.lookup_binding("active.bin").is_some());
            assert!(
                restored
                    .tombstones()
                    .iter()
                    .all(|tombstone| tombstone.path() != "active.bin")
            );
            assert!(
                read_active_restore_transaction(
                    &FolderbaseState::open(root.path()).expect("state")
                )
                .expect("active restore")
                .is_none()
            );
        }
    }

    #[test]
    fn same_byte_foreign_target_after_staging_is_never_adopted_as_restore_owned() {
        let root = folderbase();
        let store = FolderbaseVersionStore::open(root.path()).expect("open");
        store
            .seal_capture(store.plan_capture().expect("genesis"))
            .expect("genesis");
        fs::remove_file(root.path().join("active.bin")).expect("delete");
        let deletion = store
            .seal_capture(store.plan_capture().expect("deletion"))
            .expect("deletion");

        let error = store
            .restore_tombstone_with_hook("active.bin", |checkpoint| {
                if checkpoint == &RestoreCheckpoint::StageDurable {
                    fs::write(root.path().join("active.bin"), b"first opaque bytes")
                        .expect("same-byte foreign competitor");
                }
            })
            .expect_err("same-byte foreign target must not be transaction-owned");
        assert!(matches!(
            error,
            FolderbaseCaptureError::RestoreTargetOccupied(path)
                if path.ends_with("active.bin")
        ));
        assert_eq!(
            local_head(root.path()).expect("deletion Head").version_id,
            deletion.version_id()
        );
        assert!(
            read_active_restore_transaction(&FolderbaseState::open(root.path()).expect("state"))
                .expect("active restore")
                .is_some(),
            "durable intent and retained stage remain available for diagnosis/retry"
        );
        assert!(matches!(
            FolderbaseVersionStore::open(root.path())
                .expect("reopen")
                .restore_tombstone("active.bin"),
            Err(FolderbaseCaptureError::RestoreTargetOccupied(_))
        ));
        assert_eq!(
            fs::read(root.path().join("active.bin")).expect("foreign bytes preserved"),
            b"first opaque bytes"
        );
    }

    #[test]
    fn capture_and_restore_active_journals_mutually_exclude_each_other() {
        let root = folderbase();
        let store = FolderbaseVersionStore::open(root.path()).expect("open");
        store
            .seal_capture(store.plan_capture().expect("genesis"))
            .expect("genesis");
        fs::remove_file(root.path().join("active.bin")).expect("delete");
        let deletion = store
            .seal_capture(store.plan_capture().expect("deletion"))
            .expect("deletion");
        fs::write(root.path().join("FOLDERBASE.md"), "# changed\n").expect("unrelated update");
        let interrupted = catch_unwind(AssertUnwindSafe(|| {
            store.seal_capture_with_hook(
                store.plan_capture().expect("capture plan"),
                |checkpoint| {
                    if checkpoint == &CaptureCheckpoint::JournalDurable {
                        panic!("leave capture active");
                    }
                },
            )
        }));
        assert!(interrupted.is_err());
        assert!(matches!(
            store.restore_tombstone("active.bin"),
            Err(FolderbaseCaptureError::ConflictingTransaction(message))
                if message.contains("capture")
        ));
        assert_eq!(
            local_head(root.path()).expect("deletion Head").version_id,
            deletion.version_id()
        );

        let root = folderbase();
        let store = FolderbaseVersionStore::open(root.path()).expect("open");
        store
            .seal_capture(store.plan_capture().expect("genesis"))
            .expect("genesis");
        fs::remove_file(root.path().join("active.bin")).expect("delete");
        let deletion = store
            .seal_capture(store.plan_capture().expect("deletion"))
            .expect("deletion");
        let interrupted = catch_unwind(AssertUnwindSafe(|| {
            store.restore_tombstone_with_hook("active.bin", |checkpoint| {
                if checkpoint == &RestoreCheckpoint::JournalDurable {
                    panic!("leave restore active");
                }
            })
        }));
        assert!(interrupted.is_err());
        assert!(matches!(
            store.seal_capture(store.plan_capture().expect("capture plan")),
            Err(FolderbaseCaptureError::ConflictingTransaction(message))
                if message.contains("restore")
        ));
        assert_eq!(
            local_head(root.path()).expect("deletion Head").version_id,
            deletion.version_id()
        );
    }

    #[test]
    fn restore_journal_and_head_tamper_fail_closed_before_workspace_publication() {
        let root = folderbase();
        let store = FolderbaseVersionStore::open(root.path()).expect("open");
        store
            .seal_capture(store.plan_capture().expect("genesis"))
            .expect("genesis");
        fs::remove_file(root.path().join("active.bin")).expect("delete");
        let deletion = store
            .seal_capture(store.plan_capture().expect("deletion"))
            .expect("deletion");
        let interrupted = catch_unwind(AssertUnwindSafe(|| {
            store.restore_tombstone_with_hook("active.bin", |checkpoint| {
                if checkpoint == &RestoreCheckpoint::JournalDurable {
                    panic!("leave restore journal");
                }
            })
        }));
        assert!(interrupted.is_err());
        let state = FolderbaseState::open(root.path()).expect("state");
        let mut transaction = read_active_restore_transaction(&state)
            .expect("journal")
            .expect("active");
        transaction.target_version_sha256 = "0".repeat(64);
        state
            .replace(
                Path::new(ACTIVE_RESTORE_TRANSACTION_PATH),
                &encode_restore_transaction(&transaction).expect("tampered journal"),
            )
            .expect("replace journal");
        assert!(matches!(
            store.restore_tombstone("active.bin"),
            Err(FolderbaseCaptureError::InvalidRestoreTransaction(_))
        ));
        assert!(!root.path().join("active.bin").exists());
        assert_eq!(
            local_head(root.path()).expect("deletion Head").version_id,
            deletion.version_id()
        );

        let root = folderbase();
        let store = FolderbaseVersionStore::open(root.path()).expect("open");
        store
            .seal_capture(store.plan_capture().expect("genesis"))
            .expect("genesis");
        fs::remove_file(root.path().join("active.bin")).expect("delete");
        let deletion = store
            .seal_capture(store.plan_capture().expect("deletion"))
            .expect("deletion");
        let interrupted = catch_unwind(AssertUnwindSafe(|| {
            store.restore_tombstone_with_hook("active.bin", |checkpoint| {
                if checkpoint == &RestoreCheckpoint::JournalDurable {
                    panic!("leave restore journal");
                }
            })
        }));
        assert!(interrupted.is_err());
        let state = FolderbaseState::open(root.path()).expect("state");
        let mut head = read_head_record(&state).expect("Head").expect("Head");
        head.authority = LocalHeadAuthority::CaptureTransactionV1 {
            sha256: "0".repeat(64),
        };
        state
            .replace(
                Path::new(LOCAL_HEAD_PATH),
                &json_bytes(&head).expect("tampered Head"),
            )
            .expect("replace Head");
        assert!(matches!(
            store.restore_tombstone("active.bin"),
            Err(FolderbaseCaptureError::LocalHeadChanged)
        ));
        assert!(!root.path().join("active.bin").exists());
        assert_eq!(head.version_id, deletion.version_id());

        let root = folderbase();
        let store = FolderbaseVersionStore::open(root.path()).expect("open");
        store
            .seal_capture(store.plan_capture().expect("genesis"))
            .expect("genesis");
        fs::remove_file(root.path().join("active.bin")).expect("delete");
        let deletion = store
            .seal_capture(store.plan_capture().expect("deletion"))
            .expect("deletion");
        let interrupted = catch_unwind(AssertUnwindSafe(|| {
            store.restore_tombstone_with_hook("active.bin", |checkpoint| {
                if checkpoint == &RestoreCheckpoint::JournalDurable {
                    panic!("leave restore journal");
                }
            })
        }));
        assert!(interrupted.is_err());
        let state = FolderbaseState::open(root.path()).expect("state");
        let mut transaction = read_active_restore_transaction(&state)
            .expect("journal")
            .expect("active");
        transaction.binding = PathBinding::regular_file_from_verified_producer(
            transaction.binding.path(),
            transaction.binding.object_id(),
            transaction
                .binding
                .object_version_id()
                .expect("Object Version"),
            transaction.binding.content_sha256().expect("digest"),
            transaction.binding.bytes().expect("bytes"),
            !transaction.binding.executable().expect("executable"),
        );
        let parent = store.read_version(deletion.version_id()).expect("parent");
        transaction.target_version_sha256 = restored_version(
            &store,
            &parent,
            &transaction.target_version_id,
            &transaction.created_at,
            &transaction.tombstone,
            &transaction.binding,
        )
        .expect("tampered target")
        .canonical_digest()
        .expect("tampered digest");
        state
            .replace(
                Path::new(ACTIVE_RESTORE_TRANSACTION_PATH),
                &encode_restore_transaction(&transaction).expect("tampered journal"),
            )
            .expect("replace journal");
        assert!(matches!(
            store.restore_tombstone("active.bin"),
            Err(FolderbaseCaptureError::InvalidRestoreTransaction(_))
        ));
        assert!(!root.path().join("active.bin").exists());
        assert_eq!(
            local_head(root.path()).expect("deletion Head").version_id,
            deletion.version_id()
        );

        let root = folderbase();
        let store = FolderbaseVersionStore::open(root.path()).expect("open");
        store
            .seal_capture(store.plan_capture().expect("genesis"))
            .expect("genesis");
        fs::remove_file(root.path().join("active.bin")).expect("delete");
        let deletion = store
            .seal_capture(store.plan_capture().expect("deletion"))
            .expect("deletion");
        let interrupted = catch_unwind(AssertUnwindSafe(|| {
            store.restore_tombstone_with_hook("active.bin", |checkpoint| {
                if checkpoint == &RestoreCheckpoint::JournalDurable {
                    panic!("leave restore journal");
                }
            })
        }));
        assert!(interrupted.is_err());
        let state = FolderbaseState::open(root.path()).expect("state");
        let mut transaction = read_active_restore_transaction(&state)
            .expect("journal")
            .expect("active");
        transaction.target_version_id = format!("fbversion_{}", Uuid::now_v7());
        transaction.created_at = "2035-01-02T03:04:05Z".to_owned();
        let parent = store.read_version(deletion.version_id()).expect("parent");
        transaction.target_version_sha256 = restored_version(
            &store,
            &parent,
            &transaction.target_version_id,
            &transaction.created_at,
            &transaction.tombstone,
            &transaction.binding,
        )
        .expect("rewritten target")
        .canonical_digest()
        .expect("rewritten digest");
        state
            .replace(
                Path::new(ACTIVE_RESTORE_TRANSACTION_PATH),
                &encode_restore_transaction(&transaction).expect("tampered journal"),
            )
            .expect("replace journal");
        assert!(matches!(
            store.restore_tombstone("active.bin"),
            Err(FolderbaseCaptureError::InvalidRestoreTransaction(_))
        ));
        assert!(!root.path().join("active.bin").exists());
        assert_eq!(
            local_head(root.path()).expect("deletion Head").version_id,
            deletion.version_id()
        );
    }

    #[test]
    fn committed_restore_rederives_authority_before_recovery() {
        let root = folderbase();
        let store = FolderbaseVersionStore::open(root.path()).expect("open");
        store
            .seal_capture(store.plan_capture().expect("genesis"))
            .expect("genesis");
        fs::remove_file(root.path().join("active.bin")).expect("delete");
        let deletion = store
            .seal_capture(store.plan_capture().expect("deletion"))
            .expect("deletion");
        let interrupted = catch_unwind(AssertUnwindSafe(|| {
            store.restore_tombstone_with_hook("active.bin", |checkpoint| {
                if checkpoint == &RestoreCheckpoint::HeadReplaced {
                    panic!("leave committed restore intent");
                }
            })
        }));
        assert!(interrupted.is_err());

        let state = FolderbaseState::open(root.path()).expect("state");
        let mut transaction = read_active_restore_transaction(&state)
            .expect("journal")
            .expect("active");
        let parent = store.read_version(deletion.version_id()).expect("parent");
        transaction.expected_head.authority = LocalHeadAuthority::VersionDerivedV1 {
            sha256: "a".repeat(64),
        };
        let forged_parent_head = LocalHeadRecord {
            format: "folderbase-local-head-v2".to_owned(),
            folderbase_id: transaction.folderbase_id.clone(),
            root_instance_sha256: transaction.root_instance_sha256.clone(),
            version_id: transaction.expected_head.version_id.clone(),
            version_sha256: transaction.expected_head.version_sha256.clone(),
            authority: transaction.expected_head.authority.clone(),
        };
        let (transaction_id, target_version_id, created_at) = assigned_restore_identity(
            &store,
            &forged_parent_head,
            &parent,
            &transaction.tombstone,
            &transaction.binding,
        )
        .expect("forge every dependent deterministic assignment");
        transaction.transaction_id = transaction_id;
        transaction.target_version_id = target_version_id;
        transaction.created_at = created_at;
        let forged = restored_version(
            &store,
            &parent,
            &transaction.target_version_id,
            &transaction.created_at,
            &transaction.tombstone,
            &transaction.binding,
        )
        .expect("forged target");
        transaction.target_version_sha256 =
            forged.canonical_digest().expect("forged target digest");
        install_test_version(root.path(), &forged);
        let forged_stage_directory = root
            .path()
            .join(RESTORE_TRANSACTIONS_DIRECTORY)
            .join(&transaction.transaction_id);
        fs::create_dir(&forged_stage_directory).expect("forged transaction directory");
        fs::hard_link(
            root.path().join("active.bin"),
            forged_stage_directory.join("content"),
        )
        .expect("retain the published destination under the forged assignment");
        state
            .replace(
                Path::new(ACTIVE_RESTORE_TRANSACTION_PATH),
                &encode_restore_transaction(&transaction).expect("forged journal"),
            )
            .expect("replace journal");
        state
            .replace(
                Path::new(LOCAL_HEAD_PATH),
                &json_bytes(&LocalHeadRecord {
                    format: "folderbase-local-head-v2".to_owned(),
                    folderbase_id: transaction.folderbase_id.clone(),
                    root_instance_sha256: transaction.root_instance_sha256.clone(),
                    version_id: transaction.target_version_id.clone(),
                    version_sha256: transaction.target_version_sha256.clone(),
                    authority: LocalHeadAuthority::VersionDerivedV1 {
                        sha256: local_head_authority_sha256(
                            &store,
                            &transaction.target_version_id,
                            &transaction.target_version_sha256,
                        )
                        .expect("forged Head authority"),
                    },
                })
                .expect("forged Head"),
            )
            .expect("replace Head");

        assert!(matches!(
            store.restore_tombstone("active.bin"),
            Err(FolderbaseCaptureError::InvalidRestoreTransaction(_))
        ));
    }

    #[test]
    fn restore_ancestor_search_is_bounded_before_any_restore_intent() {
        let root = folderbase();
        let store = FolderbaseVersionStore::open(root.path()).expect("open");
        store
            .seal_capture(store.plan_capture().expect("genesis"))
            .expect("genesis");
        fs::remove_file(root.path().join("active.bin")).expect("delete");
        let deletion = store
            .seal_capture(store.plan_capture().expect("deletion"))
            .expect("deletion");
        let local = LocalVersionStore::open_read_only(root.path()).expect("local");
        let state = FolderbaseState::open_existing(root.path()).expect("state");
        let current =
            read_and_verify_folderbase_version(&store, &local, &state, deletion.version_id())
                .expect("current");
        let tombstone = &current.tombstones()[0];

        assert!(matches!(
            find_restore_binding_with_limit(&store, &local, &state, &current, tombstone, 0),
            Err(FolderbaseCaptureError::InvalidRestoreAncestry(message))
                if message.contains("bounded")
        ));
        assert!(!root.path().join("active.bin").exists());
        assert!(
            read_active_restore_transaction(&state)
                .expect("active restore")
                .is_none()
        );
    }

    #[test]
    fn nearest_ancestor_fidelity_disagreement_is_refused_as_ambiguous() {
        let root = folderbase();
        let store = FolderbaseVersionStore::open(root.path()).expect("open");
        let genesis = store
            .seal_capture(store.plan_capture().expect("genesis"))
            .expect("genesis");
        let genesis_version = store.read_version(genesis.version_id()).expect("genesis");
        let original = genesis_version
            .lookup_binding("active.bin")
            .expect("active")
            .clone();
        let alternate_binding = PathBinding::regular_file_from_verified_producer(
            original.path(),
            original.object_id(),
            original.object_version_id().expect("Object Version"),
            original.content_sha256().expect("digest"),
            original.bytes().expect("bytes"),
            !original.executable().expect("executable"),
        );
        let mut alternate_bindings = genesis_version.bindings().to_vec();
        let index = alternate_bindings
            .iter()
            .position(|binding| binding.path() == "active.bin")
            .expect("active index");
        alternate_bindings[index] = alternate_binding;
        let alternate = FolderbaseVersion::from_verified_parts(
            FolderbaseVersionParts::portable_v1_from_verified_producer(
                genesis_version.folderbase_id(),
                format!("fbversion_{}", Uuid::now_v7()),
                Vec::new(),
                Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
                genesis_version.root_manifest().clone(),
                FolderbaseVersionEntries::from_verified_producer(
                    alternate_bindings,
                    Vec::new(),
                    genesis_version.exclusions().to_vec(),
                ),
            ),
        )
        .expect("alternate");
        install_test_version(root.path(), &alternate);

        fs::remove_file(root.path().join("active.bin")).expect("delete");
        let current = FolderbaseVersion::from_verified_parts(
            FolderbaseVersionParts::portable_v1_from_verified_producer(
                genesis_version.folderbase_id(),
                format!("fbversion_{}", Uuid::now_v7()),
                vec![
                    genesis_version.version_id().to_owned(),
                    alternate.version_id().to_owned(),
                ],
                Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
                genesis_version.root_manifest().clone(),
                FolderbaseVersionEntries::from_verified_producer(
                    genesis_version
                        .bindings()
                        .iter()
                        .filter(|binding| binding.path() != "active.bin")
                        .cloned()
                        .collect(),
                    vec![Tombstone::from_verified_producer(
                        original.path(),
                        original.object_id(),
                        DeletedKind::RegularFile,
                        original.object_version_id().map(str::to_owned),
                    )],
                    genesis_version.exclusions().to_vec(),
                ),
            ),
        )
        .expect("ambiguous current");
        install_test_version(root.path(), &current);
        point_test_head(root.path(), &current);

        assert!(matches!(
            FolderbaseVersionStore::open(root.path())
                .expect("reopen")
                .restore_tombstone("active.bin"),
            Err(FolderbaseCaptureError::InvalidRestoreAncestry(message))
                if message.contains("disagree")
        ));
        assert!(!root.path().join("active.bin").exists());
    }

    #[test]
    fn cyclic_ancestor_graph_is_refused_before_restore_publication() {
        let root = folderbase();
        let store = FolderbaseVersionStore::open(root.path()).expect("open");
        let genesis = store
            .seal_capture(store.plan_capture().expect("genesis"))
            .expect("genesis");
        let genesis_version = store.read_version(genesis.version_id()).expect("genesis");
        let original = genesis_version
            .lookup_binding("active.bin")
            .expect("active")
            .clone();
        fs::remove_file(root.path().join("active.bin")).expect("delete");
        let surviving = genesis_version
            .bindings()
            .iter()
            .filter(|binding| binding.path() != "active.bin")
            .cloned()
            .collect::<Vec<_>>();
        let tombstones = vec![Tombstone::from_verified_producer(
            original.path(),
            original.object_id(),
            DeletedKind::RegularFile,
            original.object_version_id().map(str::to_owned),
        )];
        let first_id = format!("fbversion_{}", Uuid::now_v7());
        let second_id = format!("fbversion_{}", Uuid::now_v7());
        let cycle_version = |version_id: &str, parent: &str| {
            FolderbaseVersion::from_verified_parts(
                FolderbaseVersionParts::portable_v1_from_verified_producer(
                    genesis_version.folderbase_id(),
                    version_id,
                    vec![parent.to_owned()],
                    Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
                    genesis_version.root_manifest().clone(),
                    FolderbaseVersionEntries::from_verified_producer(
                        surviving.clone(),
                        tombstones.clone(),
                        genesis_version.exclusions().to_vec(),
                    ),
                ),
            )
            .expect("cycle member")
        };
        let first = cycle_version(&first_id, &second_id);
        let second = cycle_version(&second_id, &first_id);
        install_test_version(root.path(), &first);
        install_test_version(root.path(), &second);
        let current = FolderbaseVersion::from_verified_parts(
            FolderbaseVersionParts::portable_v1_from_verified_producer(
                genesis_version.folderbase_id(),
                format!("fbversion_{}", Uuid::now_v7()),
                vec![first_id],
                Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
                genesis_version.root_manifest().clone(),
                FolderbaseVersionEntries::from_verified_producer(
                    surviving,
                    tombstones,
                    genesis_version.exclusions().to_vec(),
                ),
            ),
        )
        .expect("current");
        install_test_version(root.path(), &current);
        point_test_head(root.path(), &current);

        assert!(matches!(
            FolderbaseVersionStore::open(root.path())
                .expect("reopen")
                .restore_tombstone("active.bin"),
            Err(FolderbaseCaptureError::InvalidRestoreAncestry(message))
                if message.contains("cycle")
        ));
        assert!(!root.path().join("active.bin").exists());
    }

    #[test]
    fn nearest_candidate_does_not_hide_a_deeper_ancestor_cycle() {
        let root = folderbase();
        let store = FolderbaseVersionStore::open(root.path()).expect("open");
        let genesis = store
            .seal_capture(store.plan_capture().expect("genesis"))
            .expect("genesis");
        let genesis_version = store.read_version(genesis.version_id()).expect("genesis");
        let original = genesis_version
            .lookup_binding("active.bin")
            .expect("active")
            .clone();
        fs::remove_file(root.path().join("active.bin")).expect("delete");
        let surviving = genesis_version
            .bindings()
            .iter()
            .filter(|binding| binding.path() != "active.bin")
            .cloned()
            .collect::<Vec<_>>();
        let tombstones = vec![Tombstone::from_verified_producer(
            original.path(),
            original.object_id(),
            DeletedKind::RegularFile,
            original.object_version_id().map(str::to_owned),
        )];
        let candidate_id = format!("fbversion_{}", Uuid::now_v7());
        let deeper_id = format!("fbversion_{}", Uuid::now_v7());
        let candidate = FolderbaseVersion::from_verified_parts(
            FolderbaseVersionParts::portable_v1_from_verified_producer(
                genesis_version.folderbase_id(),
                &candidate_id,
                vec![deeper_id.clone()],
                genesis_version.created_at(),
                genesis_version.root_manifest().clone(),
                FolderbaseVersionEntries::from_verified_producer(
                    genesis_version.bindings().to_vec(),
                    Vec::new(),
                    genesis_version.exclusions().to_vec(),
                ),
            ),
        )
        .expect("candidate");
        let deeper = FolderbaseVersion::from_verified_parts(
            FolderbaseVersionParts::portable_v1_from_verified_producer(
                genesis_version.folderbase_id(),
                &deeper_id,
                vec![candidate_id.clone()],
                genesis_version.created_at(),
                genesis_version.root_manifest().clone(),
                FolderbaseVersionEntries::from_verified_producer(
                    surviving.clone(),
                    tombstones.clone(),
                    genesis_version.exclusions().to_vec(),
                ),
            ),
        )
        .expect("deeper cycle");
        install_test_version(root.path(), &candidate);
        install_test_version(root.path(), &deeper);
        let current = FolderbaseVersion::from_verified_parts(
            FolderbaseVersionParts::portable_v1_from_verified_producer(
                genesis_version.folderbase_id(),
                format!("fbversion_{}", Uuid::now_v7()),
                vec![candidate_id],
                genesis_version.created_at(),
                genesis_version.root_manifest().clone(),
                FolderbaseVersionEntries::from_verified_producer(
                    surviving,
                    tombstones,
                    genesis_version.exclusions().to_vec(),
                ),
            ),
        )
        .expect("current");
        install_test_version(root.path(), &current);
        point_test_head(root.path(), &current);

        assert!(matches!(
            FolderbaseVersionStore::open(root.path())
                .expect("reopen")
                .restore_tombstone("active.bin"),
            Err(FolderbaseCaptureError::InvalidRestoreAncestry(message))
                if message.contains("cycle")
        ));
        assert!(!root.path().join("active.bin").exists());
    }

    #[test]
    fn convergent_ancestor_dag_restores_from_one_shared_verified_candidate() {
        let root = folderbase();
        let store = FolderbaseVersionStore::open(root.path()).expect("open");
        let genesis = store
            .seal_capture(store.plan_capture().expect("genesis"))
            .expect("genesis");
        let genesis_version = store.read_version(genesis.version_id()).expect("genesis");
        let original = genesis_version
            .lookup_binding("active.bin")
            .expect("active")
            .clone();
        fs::remove_file(root.path().join("active.bin")).expect("delete");
        let surviving = genesis_version
            .bindings()
            .iter()
            .filter(|binding| binding.path() != "active.bin")
            .cloned()
            .collect::<Vec<_>>();
        let tombstones = vec![Tombstone::from_verified_producer(
            original.path(),
            original.object_id(),
            DeletedKind::RegularFile,
            original.object_version_id().map(str::to_owned),
        )];
        let branch = |version_id: String| {
            FolderbaseVersion::from_verified_parts(
                FolderbaseVersionParts::portable_v1_from_verified_producer(
                    genesis_version.folderbase_id(),
                    version_id,
                    vec![genesis_version.version_id().to_owned()],
                    genesis_version.created_at(),
                    genesis_version.root_manifest().clone(),
                    FolderbaseVersionEntries::from_verified_producer(
                        surviving.clone(),
                        tombstones.clone(),
                        genesis_version.exclusions().to_vec(),
                    ),
                ),
            )
            .expect("branch")
        };
        let left = branch(format!("fbversion_{}", Uuid::now_v7()));
        let right = branch(format!("fbversion_{}", Uuid::now_v7()));
        install_test_version(root.path(), &left);
        install_test_version(root.path(), &right);
        let current = FolderbaseVersion::from_verified_parts(
            FolderbaseVersionParts::portable_v1_from_verified_producer(
                genesis_version.folderbase_id(),
                format!("fbversion_{}", Uuid::now_v7()),
                vec![left.version_id().to_owned(), right.version_id().to_owned()],
                genesis_version.created_at(),
                genesis_version.root_manifest().clone(),
                FolderbaseVersionEntries::from_verified_producer(
                    surviving,
                    tombstones,
                    genesis_version.exclusions().to_vec(),
                ),
            ),
        )
        .expect("convergent current");
        install_test_version(root.path(), &current);
        point_test_head(root.path(), &current);

        FolderbaseVersionStore::open(root.path())
            .expect("reopen")
            .restore_tombstone("active.bin")
            .expect("restore through convergent DAG");
        assert_eq!(
            fs::read(root.path().join("active.bin")).expect("restored"),
            b"first opaque bytes"
        );
    }

    #[test]
    fn convergent_edges_cannot_hide_any_reachable_ancestor_cycle() {
        for shape in ["shared-cycle", "cross-branch-cycle"] {
            let root = folderbase();
            let store = FolderbaseVersionStore::open(root.path()).expect("open");
            let genesis = store
                .seal_capture(store.plan_capture().expect("genesis"))
                .expect("genesis");
            let genesis_version = store.read_version(genesis.version_id()).expect("genesis");
            let original = genesis_version
                .lookup_binding("active.bin")
                .expect("active")
                .clone();
            fs::remove_file(root.path().join("active.bin")).expect("delete");
            let surviving = genesis_version
                .bindings()
                .iter()
                .filter(|binding| binding.path() != "active.bin")
                .cloned()
                .collect::<Vec<_>>();
            let tombstones = vec![Tombstone::from_verified_producer(
                original.path(),
                original.object_id(),
                DeletedKind::RegularFile,
                original.object_version_id().map(str::to_owned),
            )];
            let a = format!("fbversion_{}", Uuid::now_v7());
            let b = format!("fbversion_{}", Uuid::now_v7());
            let c = format!("fbversion_{}", Uuid::now_v7());
            let d = format!("fbversion_{}", Uuid::now_v7());
            let definitions = match shape {
                "shared-cycle" => vec![
                    (a.clone(), vec![c.clone()], true),
                    (b.clone(), vec![c.clone()], false),
                    (c.clone(), vec![b.clone()], false),
                ],
                "cross-branch-cycle" => vec![
                    (a.clone(), vec![c.clone()], true),
                    (b.clone(), vec![d.clone()], false),
                    (c.clone(), vec![d.clone()], false),
                    (d.clone(), vec![a.clone()], false),
                ],
                _ => unreachable!(),
            };
            for (version_id, parents, live) in definitions {
                let version = FolderbaseVersion::from_verified_parts(
                    FolderbaseVersionParts::portable_v1_from_verified_producer(
                        genesis_version.folderbase_id(),
                        version_id,
                        parents,
                        genesis_version.created_at(),
                        genesis_version.root_manifest().clone(),
                        FolderbaseVersionEntries::from_verified_producer(
                            if live {
                                genesis_version.bindings().to_vec()
                            } else {
                                surviving.clone()
                            },
                            if live { Vec::new() } else { tombstones.clone() },
                            genesis_version.exclusions().to_vec(),
                        ),
                    ),
                )
                .expect("graph member");
                install_test_version(root.path(), &version);
            }
            let current = FolderbaseVersion::from_verified_parts(
                FolderbaseVersionParts::portable_v1_from_verified_producer(
                    genesis_version.folderbase_id(),
                    format!("fbversion_{}", Uuid::now_v7()),
                    vec![a, b],
                    genesis_version.created_at(),
                    genesis_version.root_manifest().clone(),
                    FolderbaseVersionEntries::from_verified_producer(
                        surviving,
                        tombstones,
                        genesis_version.exclusions().to_vec(),
                    ),
                ),
            )
            .expect("current");
            install_test_version(root.path(), &current);
            point_test_head(root.path(), &current);

            assert!(matches!(
                FolderbaseVersionStore::open(root.path())
                    .expect("reopen")
                    .restore_tombstone("active.bin"),
                Err(FolderbaseCaptureError::InvalidRestoreAncestry(message))
                    if message.contains("cycle")
            ));
        }
    }

    #[test]
    fn restore_revalidates_owned_target_and_boundary_before_and_after_head() {
        for mutation in [
            "same-byte-replacement",
            "in-place",
            "late-boundary",
            "post-head",
            "post-head-in-place",
        ] {
            let root = folderbase();
            let store = FolderbaseVersionStore::open(root.path()).expect("open");
            store
                .seal_capture(store.plan_capture().expect("genesis"))
                .expect("genesis");
            fs::remove_file(root.path().join("active.bin")).expect("delete");
            let deletion = store
                .seal_capture(store.plan_capture().expect("deletion"))
                .expect("deletion");
            let result = store.restore_tombstone_with_hook("active.bin", |checkpoint| {
                if checkpoint == &RestoreCheckpoint::TargetPublished {
                    match mutation {
                        "same-byte-replacement" => {
                            fs::remove_file(root.path().join("active.bin")).expect("unlink target");
                            fs::write(root.path().join("active.bin"), b"first opaque bytes")
                                .expect("replace with same bytes");
                        }
                        "in-place" => {
                            fs::write(root.path().join("active.bin"), b"mutated")
                                .expect("mutate target inode");
                        }
                        "late-boundary" => {
                            fs::create_dir_all(root.path().join(".folderbase-probe")).ok();
                        }
                        _ => {}
                    }
                }
                if mutation == "post-head" && checkpoint == &RestoreCheckpoint::HeadReplaced {
                    fs::remove_file(root.path().join("active.bin"))
                        .expect("unlink committed target");
                    fs::write(root.path().join("active.bin"), b"first opaque bytes")
                        .expect("post-Head same-byte replacement");
                }
                if mutation == "post-head-in-place"
                    && checkpoint == &RestoreCheckpoint::HeadReplaced
                {
                    fs::write(root.path().join("active.bin"), b"post-Head mutation")
                        .expect("post-Head in-place mutation");
                }
            });
            if mutation == "late-boundary" {
                // Root-level content has no ancestor at which to introduce a
                // nested boundary; this case is covered by the nested-path test.
                assert!(result.is_ok());
                continue;
            }
            assert!(result.is_err(), "{mutation} must fail closed");
            assert_eq!(
                local_head(root.path()).expect("deletion Head").version_id,
                deletion.version_id(),
                "{mutation} must not leave the restore Head committed"
            );
        }
    }

    #[test]
    fn in_place_edit_of_published_restore_is_preserved_and_capture_is_unblocked() {
        for fault in [
            RestoreCheckpoint::TargetPublished,
            RestoreCheckpoint::HeadReplaced,
        ] {
            let root = folderbase();
            let store = FolderbaseVersionStore::open(root.path()).expect("open");
            store
                .seal_capture(store.plan_capture().expect("genesis"))
                .expect("genesis");
            fs::remove_file(root.path().join("active.bin")).expect("delete");
            let deletion = store
                .seal_capture(store.plan_capture().expect("deletion"))
                .expect("deletion");
            let user_bytes = format!("user work after {fault:?}");

            store
                .restore_tombstone_with_hook("active.bin", |checkpoint| {
                    if checkpoint == &fault {
                        fs::write(root.path().join("active.bin"), user_bytes.as_bytes())
                            .expect("edit published file in place");
                    }
                })
                .expect_err("an in-place edit must stop the restore");

            assert_eq!(
                fs::read(root.path().join("active.bin")).expect("preserved user work"),
                user_bytes.as_bytes()
            );
            assert_eq!(
                local_head(root.path()).expect("deletion Head").version_id,
                deletion.version_id(),
                "restore must roll back before relinquishing the edited file"
            );

            let captured = store
                .seal_capture(store.plan_capture().expect("capture edited workspace"))
                .expect("the abandoned restore must not block a normal capture");
            let captured_version = store
                .read_version(captured.version_id())
                .expect("captured version");
            assert_eq!(
                captured_version.parents(),
                &[deletion.version_id().to_owned()]
            );
            assert_eq!(
                fs::read(root.path().join("active.bin")).expect("captured user work"),
                user_bytes.as_bytes()
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn modified_restore_cleanup_failure_reopens_and_capture_adopts_preserved_bytes() {
        use std::{
            cell::RefCell,
            os::unix::fs::{MetadataExt, PermissionsExt},
        };

        let root = folderbase();
        let store = FolderbaseVersionStore::open(root.path()).expect("open");
        store
            .seal_capture(store.plan_capture().expect("genesis"))
            .expect("genesis");
        fs::remove_file(root.path().join("active.bin")).expect("delete");
        store
            .seal_capture(store.plan_capture().expect("deletion"))
            .expect("deletion");
        let transaction_directory = RefCell::new(None);
        let user_bytes = b"user work preserved across cleanup failure";

        let cleanup_error = store
            .restore_tombstone_with_hook("active.bin", |checkpoint| {
                if checkpoint == &RestoreCheckpoint::TargetPublished {
                    let transaction = read_active_restore_transaction(
                        &FolderbaseState::open(root.path()).expect("state"),
                    )
                    .expect("restore journal")
                    .expect("active restore");
                    let directory = root
                        .path()
                        .join(restore_transaction_directory(&transaction));
                    transaction_directory.replace(Some(directory.clone()));
                    fs::write(root.path().join("active.bin"), user_bytes)
                        .expect("edit restored target in place");
                    fs::set_permissions(&directory, fs::Permissions::from_mode(0o500))
                        .expect("deny private stage cleanup");
                }
            })
            .expect_err("private-stage cleanup failure must be reported");
        assert!(matches!(
            cleanup_error,
            FolderbaseCaptureError::LocalStore(FolderbaseError::Io { .. })
        ));
        assert_eq!(
            fs::read(root.path().join("active.bin")).expect("preserved workspace bytes"),
            user_bytes
        );
        assert!(
            fs::metadata(root.path().join("active.bin"))
                .expect("preserved workspace metadata")
                .nlink()
                > 1,
            "failed cleanup must leave the visible file linked to its private stage"
        );

        let transaction_directory = transaction_directory
            .into_inner()
            .expect("transaction directory");
        fs::set_permissions(&transaction_directory, fs::Permissions::from_mode(0o700))
            .expect("restore cleanup permissions");
        drop(store);

        let reopened = FolderbaseVersionStore::open(root.path()).expect("fresh-process reopen");
        assert!(matches!(
            reopened.restore_tombstone("active.bin"),
            Err(FolderbaseCaptureError::RestoreTargetOccupied(path))
                if path == Path::new("active.bin")
        ));
        let captured = reopened
            .seal_capture(
                reopened
                    .plan_capture()
                    .expect("capture preserved user work"),
            )
            .expect("completed cleanup must unblock capture");
        let captured_version = reopened
            .read_version(captured.version_id())
            .expect("captured version");
        let binding = captured_version
            .lookup_binding("active.bin")
            .expect("preserved user work must become a live binding");
        assert_eq!(binding.bytes(), Some(user_bytes.len() as u64));
        assert_eq!(
            fs::metadata(root.path().join("active.bin"))
                .expect("captured workspace metadata")
                .nlink(),
            2,
            "capture keeps exactly one validated Folderbase authority link"
        );
        assert!(
            transaction_directory
                .join(RESTORE_AUTHORITY_FILENAME)
                .is_file(),
            "cleanup retry must retain a durable authority receipt"
        );
    }

    #[cfg(unix)]
    #[test]
    fn modified_restore_cleanup_retry_accepts_the_same_owned_inode_reverted_to_sealed_bytes() {
        use std::{cell::RefCell, os::unix::fs::PermissionsExt};

        let root = folderbase();
        let store = FolderbaseVersionStore::open(root.path()).expect("open");
        store
            .seal_capture(store.plan_capture().expect("genesis"))
            .expect("genesis");
        fs::remove_file(root.path().join("active.bin")).expect("delete");
        store
            .seal_capture(store.plan_capture().expect("deletion"))
            .expect("deletion");
        let transaction_directory = RefCell::new(None);

        store
            .restore_tombstone_with_hook("active.bin", |checkpoint| {
                if checkpoint == &RestoreCheckpoint::TargetPublished {
                    let transaction = read_active_restore_transaction(
                        &FolderbaseState::open(root.path()).expect("state"),
                    )
                    .expect("restore journal")
                    .expect("active restore");
                    let directory = root
                        .path()
                        .join(restore_transaction_directory(&transaction));
                    transaction_directory.replace(Some(directory.clone()));
                    fs::write(root.path().join("active.bin"), b"temporary user edit")
                        .expect("edit restored target in place");
                    fs::set_permissions(&directory, fs::Permissions::from_mode(0o500))
                        .expect("deny private stage cleanup");
                }
            })
            .expect_err("private-stage cleanup failure must be reported");

        let transaction_directory = transaction_directory
            .into_inner()
            .expect("transaction directory");
        fs::set_permissions(&transaction_directory, fs::Permissions::from_mode(0o700))
            .expect("restore cleanup permissions");
        fs::write(root.path().join("active.bin"), b"first opaque bytes")
            .expect("revert the same restore-owned inode");
        drop(store);

        let reopened = FolderbaseVersionStore::open(root.path()).expect("fresh-process reopen");
        assert!(matches!(
            reopened.restore_tombstone("active.bin"),
            Err(FolderbaseCaptureError::RestoreTargetOccupied(path))
                if path == Path::new("active.bin")
        ));
        assert!(
            transaction_directory
                .join(RESTORE_AUTHORITY_FILENAME)
                .is_file(),
            "durable modified ownership must become a retained capture authority"
        );
        reopened
            .seal_capture(reopened.plan_capture().expect("capture reverted file"))
            .expect("completed cleanup must leave capture unblocked");
    }

    #[cfg(unix)]
    #[test]
    fn coordinated_modified_receipt_and_active_rewrite_cannot_retire_forged_state() {
        use std::{cell::RefCell, os::unix::fs::PermissionsExt};

        let root = folderbase();
        let store = FolderbaseVersionStore::open(root.path()).expect("open");
        store
            .seal_capture(store.plan_capture().expect("genesis"))
            .expect("genesis");
        fs::remove_file(root.path().join("active.bin")).expect("delete");
        store
            .seal_capture(store.plan_capture().expect("deletion"))
            .expect("deletion");
        let transaction_directory = RefCell::new(None);

        store
            .restore_tombstone_with_hook("active.bin", |checkpoint| {
                if checkpoint == &RestoreCheckpoint::TargetPublished {
                    let transaction = read_active_restore_transaction(
                        &FolderbaseState::open(root.path()).expect("state"),
                    )
                    .expect("restore journal")
                    .expect("active restore");
                    let directory = root
                        .path()
                        .join(restore_transaction_directory(&transaction));
                    transaction_directory.replace(Some(directory.clone()));
                    fs::write(root.path().join("active.bin"), b"user-edited restore")
                        .expect("edit restored target in place");
                    fs::set_permissions(&directory, fs::Permissions::from_mode(0o500))
                        .expect("deny private stage cleanup");
                }
            })
            .expect_err("private-stage cleanup failure must be reported");

        let real_transaction_directory = transaction_directory
            .into_inner()
            .expect("real transaction directory");
        fs::set_permissions(
            &real_transaction_directory,
            fs::Permissions::from_mode(0o700),
        )
        .expect("restore cleanup permissions");
        let state = FolderbaseState::open(root.path()).expect("state");
        let mut forged = read_active_restore_transaction(&state)
            .expect("active restore")
            .expect("durable active restore");
        forged.transaction_id = "fbrestore_00000000-0000-8000-8000-000000000001".to_owned();
        let forged_directory = root.path().join(restore_transaction_directory(&forged));
        fs::create_dir(&forged_directory).expect("forged transaction directory");
        fs::hard_link(
            root.path().join("active.bin"),
            forged_directory.join("content"),
        )
        .expect("forged private link");
        state
            .replace(
                Path::new(ACTIVE_RESTORE_TRANSACTION_PATH),
                &encode_restore_transaction(&forged).expect("forged active bytes"),
            )
            .expect("coordinated active rewrite");
        let forged_identity_sha256 = state
            .workspace_restore_identity_sha256(
                &restore_stage_path(&forged),
                Path::new(&forged.path),
            )
            .expect("forged publication identity");
        state
            .replace(
                Path::new(RESTORE_CLEANUP_RECOVERY_PATH),
                &encode_restore_cleanup_recovery(&RestoreCleanupRecovery {
                    format: RESTORE_CLEANUP_RECOVERY_FORMAT_V2.to_owned(),
                    disposition: RestoreCleanupDisposition::Modified,
                    transaction: forged.clone(),
                    published_identity_sha256: forged_identity_sha256,
                })
                .expect("forged cleanup bytes"),
            )
            .expect("coordinated cleanup rewrite");
        drop(state);
        drop(store);

        let error = FolderbaseVersionStore::open(root.path())
            .expect("fresh-process reopen")
            .restore_tombstone("active.bin")
            .expect_err("mutable journals cannot assign cleanup ownership");
        assert!(matches!(
            error,
            FolderbaseCaptureError::InvalidRestoreTransaction(_)
        ));
        assert!(
            real_transaction_directory.join("content").exists(),
            "forged cleanup must not strand and forget the real private stage"
        );
        assert!(
            forged_directory.join("content").exists(),
            "untrusted forged state must not be deleted"
        );
        assert!(
            root.path().join(ACTIVE_RESTORE_TRANSACTION_PATH).exists(),
            "global restore intent must remain until authority is proven"
        );
    }

    #[cfg(unix)]
    #[test]
    fn cleanup_receipt_identity_rejects_coordinated_same_byte_stage_and_destination_replacement() {
        use std::os::unix::fs::MetadataExt;

        let root = folderbase();
        let store = FolderbaseVersionStore::open(root.path()).expect("open");
        store
            .seal_capture(store.plan_capture().expect("genesis"))
            .expect("genesis");
        fs::remove_file(root.path().join("active.bin")).expect("delete");
        store
            .seal_capture(store.plan_capture().expect("deletion"))
            .expect("deletion");
        let mut foreign_identity = None;

        let result = store.restore_tombstone_with_hook("active.bin", |checkpoint| {
            if checkpoint == &RestoreCheckpoint::CleanupRecoveryDurable {
                let transaction = read_active_restore_transaction(
                    &FolderbaseState::open(root.path()).expect("state"),
                )
                .expect("restore journal")
                .expect("active restore");
                let stage = root.path().join(restore_stage_path(&transaction));
                let destination = root.path().join("active.bin");
                let foreign = root.path().join("same-byte-foreign.bin");
                fs::write(&foreign, b"first opaque bytes").expect("same-byte foreign file");
                let metadata = fs::metadata(&foreign).expect("foreign metadata");
                foreign_identity = Some((metadata.dev(), metadata.ino()));
                fs::remove_file(&stage).expect("replace exact stage");
                fs::remove_file(&destination).expect("replace exact destination");
                fs::hard_link(&foreign, &stage).expect("foreign stage link");
                fs::rename(&foreign, &destination).expect("foreign destination link");
            }
        });

        result.expect_err("receipt identity must reject coordinated foreign hard links");
        let transaction =
            read_active_restore_transaction(&FolderbaseState::open(root.path()).expect("state"))
                .expect("restore journal")
                .expect("retained active restore");
        for path in [
            root.path().join(restore_stage_path(&transaction)),
            root.path().join("active.bin"),
        ] {
            let metadata = fs::metadata(path).expect("foreign replacement preserved");
            assert_eq!(
                (metadata.dev(), metadata.ino()),
                foreign_identity.expect("foreign identity")
            );
        }
        assert!(root.path().join(RESTORE_CLEANUP_RECOVERY_PATH).exists());
    }

    #[cfg(unix)]
    #[derive(Clone, Copy)]
    enum CleanupBoundarySwap {
        Destination,
        Stage,
        Rescue,
    }

    #[cfg(unix)]
    fn assert_cleanup_boundary_swap_fails_closed(
        modified: bool,
        swap: CleanupBoundarySwap,
        after_stage_retirement: bool,
    ) {
        let root = folderbase();
        let store = FolderbaseVersionStore::open(root.path()).expect("open");
        store
            .seal_capture(store.plan_capture().expect("genesis"))
            .expect("genesis");
        fs::remove_file(root.path().join("active.bin")).expect("delete");
        store
            .seal_capture(store.plan_capture().expect("deletion"))
            .expect("deletion");
        let owned_bytes: &[u8] = if modified {
            b"user-edited restore at cleanup boundary"
        } else {
            b"first opaque bytes"
        };
        let competitor = b"unrelated replacement must survive";
        let mut transaction_directory = None;

        let result = store.restore_tombstone_with_hook("active.bin", |checkpoint| {
            if modified && checkpoint == &RestoreCheckpoint::TargetPublished {
                fs::write(root.path().join("active.bin"), owned_bytes)
                    .expect("edit restored target in place");
            }
            let mutation_checkpoint = if after_stage_retirement {
                &RestoreCheckpoint::AfterStageRetirement
            } else {
                &RestoreCheckpoint::BeforeStageRetirement
            };
            if checkpoint == mutation_checkpoint {
                let transaction = read_active_restore_transaction(
                    &FolderbaseState::open(root.path()).expect("state"),
                )
                .expect("restore journal")
                .expect("active restore");
                let directory = root
                    .path()
                    .join(restore_transaction_directory(&transaction));
                transaction_directory = Some(directory.clone());
                let target = match swap {
                    CleanupBoundarySwap::Destination => root.path().join("active.bin"),
                    CleanupBoundarySwap::Stage => directory.join("content"),
                    CleanupBoundarySwap::Rescue => directory.join("content.rescue"),
                };
                if !matches!(swap, CleanupBoundarySwap::Rescue) {
                    fs::remove_file(&target).expect("remove exact cleanup-owned name");
                }
                fs::write(&target, competitor).expect("install unrelated boundary replacement");
            }
        });
        if matches!(swap, CleanupBoundarySwap::Rescue) {
            if modified {
                result.expect_err("the prior same-inode edit still prevents Restored");
            } else {
                result.expect("unused legacy rescue names cannot block a restore");
            }
        } else {
            result.expect_err("an authority-boundary replacement must fail closed");
        }

        let transaction_directory = transaction_directory.expect("transaction directory");
        let replacement_survived = match swap {
            CleanupBoundarySwap::Destination => {
                fs::read(root.path().join("active.bin")).expect("unrelated replacement")
                    == competitor
            }
            CleanupBoundarySwap::Stage | CleanupBoundarySwap::Rescue => {
                fs::read_dir(&transaction_directory)
                    .expect("retained transaction directory")
                    .filter_map(|entry| entry.ok())
                    .filter_map(|entry| fs::read(entry.path()).ok())
                    .any(|bytes| bytes == competitor)
            }
        };
        assert!(
            replacement_survived,
            "cleanup must preserve the boundary replacement under a private quarantine name"
        );
        let uncertain_authority = !matches!(swap, CleanupBoundarySwap::Rescue);
        assert_eq!(
            root.path().join(ACTIVE_RESTORE_TRANSACTION_PATH).exists(),
            uncertain_authority,
            "only an authority-path or destination replacement retains global restore intent"
        );
        assert_eq!(
            root.path().join(RESTORE_CLEANUP_RECOVERY_PATH).exists(),
            uncertain_authority,
            "only an authority-path or destination replacement retains recovery evidence"
        );
        let retained_owned_bytes_in_private_state = fs::read_dir(&transaction_directory)
            .expect("retained transaction directory")
            .filter_map(|entry| entry.ok())
            .filter_map(|entry| fs::read(entry.path()).ok())
            .any(|bytes| bytes == owned_bytes);
        let retained_owned_bytes = retained_owned_bytes_in_private_state
            || fs::read(root.path().join("active.bin")).is_ok_and(|bytes| bytes == owned_bytes);
        assert!(
            retained_owned_bytes,
            "the workspace or retained authority must preserve the exact owned inode bytes"
        );
    }

    #[cfg(unix)]
    #[test]
    fn modified_cleanup_retains_owned_bytes_when_destination_swaps_at_unlink_boundary() {
        assert_cleanup_boundary_swap_fails_closed(true, CleanupBoundarySwap::Destination, false);
    }

    #[cfg(unix)]
    #[test]
    fn modified_cleanup_never_unlinks_a_stage_name_replacement() {
        assert_cleanup_boundary_swap_fails_closed(true, CleanupBoundarySwap::Stage, false);
    }

    #[cfg(unix)]
    #[test]
    fn committed_cleanup_retains_owned_bytes_when_destination_swaps_at_unlink_boundary() {
        assert_cleanup_boundary_swap_fails_closed(false, CleanupBoundarySwap::Destination, false);
    }

    #[cfg(unix)]
    #[test]
    fn committed_cleanup_never_unlinks_a_stage_name_replacement() {
        assert_cleanup_boundary_swap_fails_closed(false, CleanupBoundarySwap::Stage, false);
    }

    #[cfg(unix)]
    #[test]
    fn modified_cleanup_rescue_survives_destination_swap_after_stage_unlink() {
        assert_cleanup_boundary_swap_fails_closed(true, CleanupBoundarySwap::Destination, true);
    }

    #[cfg(unix)]
    #[test]
    fn committed_cleanup_rescue_survives_destination_swap_after_stage_unlink() {
        assert_cleanup_boundary_swap_fails_closed(false, CleanupBoundarySwap::Destination, true);
    }

    #[cfg(unix)]
    #[test]
    fn modified_cleanup_never_unlinks_a_rescue_name_replacement() {
        assert_cleanup_boundary_swap_fails_closed(true, CleanupBoundarySwap::Rescue, true);
    }

    #[cfg(unix)]
    #[test]
    fn committed_cleanup_never_unlinks_a_rescue_name_replacement() {
        assert_cleanup_boundary_swap_fails_closed(false, CleanupBoundarySwap::Rescue, true);
    }

    #[test]
    fn successful_restore_retains_one_private_authority_link() {
        let root = folderbase();
        let store = FolderbaseVersionStore::open(root.path()).expect("open");
        store
            .seal_capture(store.plan_capture().expect("genesis"))
            .expect("genesis");
        fs::remove_file(root.path().join("active.bin")).expect("delete");
        store
            .seal_capture(store.plan_capture().expect("deletion"))
            .expect("deletion");

        let restored = store
            .restore_tombstone("active.bin")
            .expect("successful restore");

        let transaction_entries = fs::read_dir(root.path().join(RESTORE_TRANSACTIONS_DIRECTORY))
            .expect("restore transaction directory")
            .collect::<std::io::Result<Vec<_>>>()
            .expect("transaction entries");
        assert_eq!(transaction_entries.len(), 1);
        let completion =
            read_restore_completion_receipt(&FolderbaseState::open(root.path()).expect("state"))
                .expect("completion receipt")
                .expect("completed restore");
        assert_eq!(
            completion.transaction.target_version_id,
            restored.version_id()
        );
        let retained_stage = root
            .path()
            .join(restore_stage_path(&completion.transaction));
        assert!(retained_stage.is_file());
        assert!(
            root.path()
                .join(restore_authority_record_path(
                    &completion.transaction.transaction_id
                ))
                .is_file()
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            assert_eq!(
                fs::metadata(&retained_stage)
                    .expect("retained authority metadata")
                    .nlink(),
                2
            );
        }
        let plan = store.plan_capture().expect("authority-aware capture plan");
        assert!(
            plan.entries()
                .iter()
                .any(|entry| entry.path() == "active.bin")
        );
        assert!(
            !plan
                .exclusions()
                .iter()
                .any(|entry| entry.path() == "active.bin")
        );
    }

    #[cfg(unix)]
    #[test]
    fn restore_authority_allows_same_inode_edits_but_not_extra_user_hard_links() {
        let root = folderbase();
        let store = FolderbaseVersionStore::open(root.path()).expect("open");
        store
            .seal_capture(store.plan_capture().expect("genesis"))
            .expect("genesis");
        fs::remove_file(root.path().join("active.bin")).expect("delete");
        store
            .seal_capture(store.plan_capture().expect("deletion"))
            .expect("deletion");
        store
            .restore_tombstone("active.bin")
            .expect("successful restore");
        fs::write(root.path().join("active.bin"), b"same-inode user edit").expect("edit");

        let edited_plan = store.plan_capture().expect("edited authority plan");
        assert!(
            edited_plan
                .entries()
                .iter()
                .any(|entry| entry.path() == "active.bin")
        );
        store
            .seal_capture(edited_plan)
            .expect("same-inode edit with one authority link is capturable");

        fs::hard_link(
            root.path().join("active.bin"),
            root.path().join("ordinary-user-link.bin"),
        )
        .expect("ordinary user hard link");
        let linked_plan = store.plan_capture().expect("hard-link exclusion plan");
        for path in ["active.bin", "ordinary-user-link.bin"] {
            assert!(linked_plan.exclusions().iter().any(|exclusion| {
                exclusion.path() == path && exclusion.kind() == CaptureExclusionKind::HardLink
            }));
        }
    }

    #[cfg(unix)]
    #[test]
    fn old_restore_authority_never_authorizes_a_replaced_workspace_inode() {
        let root = folderbase();
        let store = FolderbaseVersionStore::open(root.path()).expect("open");
        store
            .seal_capture(store.plan_capture().expect("genesis"))
            .expect("genesis");
        fs::remove_file(root.path().join("active.bin")).expect("delete");
        store
            .seal_capture(store.plan_capture().expect("deletion"))
            .expect("deletion");
        store
            .restore_tombstone("active.bin")
            .expect("successful restore");

        fs::remove_file(root.path().join("active.bin")).expect("replace restored inode");
        fs::write(root.path().join("active.bin"), b"foreign replacement").expect("replacement");
        fs::hard_link(
            root.path().join("active.bin"),
            root.path().join("foreign-user-link.bin"),
        )
        .expect("foreign hard link");

        let plan = store.plan_capture().expect("replacement plan");
        for path in ["active.bin", "foreign-user-link.bin"] {
            assert!(plan.exclusions().iter().any(|exclusion| {
                exclusion.path() == path && exclusion.kind() == CaptureExclusionKind::HardLink
            }));
        }
    }

    #[test]
    fn restore_authority_limit_fails_closed_with_typed_maintenance_error() {
        let root = folderbase();
        let store = FolderbaseVersionStore::open(root.path()).expect("open");
        store
            .seal_capture(store.plan_capture().expect("genesis"))
            .expect("genesis");
        fs::remove_file(root.path().join("active.bin")).expect("first delete");
        store
            .seal_capture(store.plan_capture().expect("first deletion"))
            .expect("first deletion");
        store
            .restore_tombstone("active.bin")
            .expect("first restore authority");
        fs::remove_file(root.path().join("active.bin")).expect("second delete");
        store
            .seal_capture(store.plan_capture().expect("second deletion"))
            .expect("second deletion");

        assert!(matches!(
            store.restore_tombstone_with_hook_and_authority_limit("active.bin", |_| {}, 1),
            Err(FolderbaseCaptureError::RestoreAuthorityMaintenanceRequired { maximum: 1 })
        ));
        assert!(!root.path().join("active.bin").exists());
    }

    #[test]
    fn retained_authority_never_overwrites_legacy_quarantine_names() {
        let root = folderbase();
        let store = FolderbaseVersionStore::open(root.path()).expect("open");
        store
            .seal_capture(store.plan_capture().expect("genesis"))
            .expect("genesis");
        fs::remove_file(root.path().join("active.bin")).expect("delete");
        store
            .seal_capture(store.plan_capture().expect("deletion"))
            .expect("deletion");
        let foreign = b"foreign quarantine target";
        let mut preserved = Vec::new();

        store
            .restore_tombstone_with_hook("active.bin", |checkpoint| {
                if checkpoint == &RestoreCheckpoint::CleanupRecoveryDurable {
                    let transaction = read_active_restore_transaction(
                        &FolderbaseState::open(root.path()).expect("state"),
                    )
                    .expect("restore journal")
                    .expect("active restore");
                    let stage = root.path().join(restore_stage_path(&transaction));
                    for name in ["content.rescue", "content.folderbase-quarantine"] {
                        let path = stage.with_file_name(name);
                        fs::write(&path, foreign).expect("foreign legacy target");
                        preserved.push(path);
                    }
                }
            })
            .expect("legacy names do not participate in retained authority");

        for path in preserved {
            assert_eq!(fs::read(path).expect("preserved legacy target"), foreign);
        }
    }

    #[test]
    fn completion_receipt_is_a_bounded_singleton_and_never_blocks_capture() {
        let root = folderbase();
        let store = FolderbaseVersionStore::open(root.path()).expect("open");
        store
            .seal_capture(store.plan_capture().expect("genesis"))
            .expect("genesis");
        fs::remove_file(root.path().join("active.bin")).expect("first delete");
        store
            .seal_capture(store.plan_capture().expect("first deletion"))
            .expect("first deletion");
        let first = store
            .restore_tombstone("active.bin")
            .expect("first restore");
        let state = FolderbaseState::open(root.path()).expect("state");
        let first_receipt = read_restore_completion_receipt(&state)
            .expect("first completion receipt")
            .expect("durable first completion");
        assert_eq!(
            first_receipt.transaction.target_version_id,
            first.version_id()
        );
        assert!(
            fs::metadata(root.path().join(RESTORE_COMPLETION_PATH))
                .expect("completion metadata")
                .len()
                <= MAX_CAPTURE_TRANSACTION_BYTES
        );

        let unchanged = store
            .seal_capture(store.plan_capture().expect("unchanged capture"))
            .expect("completion receipt must not block capture");
        assert!(!unchanged.created());
        fs::remove_file(root.path().join("active.bin")).expect("second delete");
        store
            .seal_capture(store.plan_capture().expect("second deletion"))
            .expect("stale completion must not block a later deletion");
        let second = store
            .restore_tombstone("active.bin")
            .expect("second restore");
        let second_receipt = read_restore_completion_receipt(&state)
            .expect("second completion receipt")
            .expect("durable second completion");
        assert_eq!(
            second_receipt.transaction.target_version_id,
            second.version_id()
        );
        assert_ne!(
            second_receipt.transaction.target_version_id,
            first_receipt.transaction.target_version_id,
            "later completion must replace, not append to, the singleton"
        );
    }

    #[test]
    fn completion_receipt_never_blesses_changed_workspace_bytes() {
        let root = folderbase();
        let store = FolderbaseVersionStore::open(root.path()).expect("open");
        store
            .seal_capture(store.plan_capture().expect("genesis"))
            .expect("genesis");
        fs::remove_file(root.path().join("active.bin")).expect("delete");
        store
            .seal_capture(store.plan_capture().expect("deletion"))
            .expect("deletion");
        store
            .restore_tombstone("active.bin")
            .expect("completed restore");
        fs::write(root.path().join("active.bin"), b"later workspace edit")
            .expect("edit completed target");

        assert!(matches!(
            store.restore_tombstone("active.bin"),
            Err(FolderbaseCaptureError::RestoreTargetOccupied(path))
                if path == Path::new("active.bin")
        ));
        store
            .seal_capture(store.plan_capture().expect("edited capture"))
            .expect("advisory completion evidence must not block later work");
    }

    #[cfg(unix)]
    #[test]
    fn completion_receipt_never_blesses_identical_bytes_from_a_foreign_inode() {
        use std::os::unix::fs::MetadataExt;

        let root = folderbase();
        let store = FolderbaseVersionStore::open(root.path()).expect("open");
        store
            .seal_capture(store.plan_capture().expect("genesis"))
            .expect("genesis");
        fs::remove_file(root.path().join("active.bin")).expect("delete");
        store
            .seal_capture(store.plan_capture().expect("deletion"))
            .expect("deletion");
        store
            .restore_tombstone("active.bin")
            .expect("completed restore");

        let restored_metadata =
            fs::metadata(root.path().join("active.bin")).expect("restored metadata");
        fs::write(root.path().join("foreign.bin"), b"first opaque bytes")
            .expect("write identical foreign file");
        let foreign_metadata =
            fs::metadata(root.path().join("foreign.bin")).expect("foreign metadata");
        assert_ne!(
            (restored_metadata.dev(), restored_metadata.ino()),
            (foreign_metadata.dev(), foreign_metadata.ino()),
            "fixture must use a distinct filesystem object"
        );
        fs::remove_file(root.path().join("active.bin")).expect("remove restored inode");
        fs::rename(
            root.path().join("foreign.bin"),
            root.path().join("active.bin"),
        )
        .expect("publish identical-byte foreign inode");

        assert!(matches!(
            store.restore_tombstone("active.bin"),
            Err(FolderbaseCaptureError::RestoreTargetOccupied(path))
                if path == Path::new("active.bin")
        ));
    }

    #[test]
    fn completion_receipt_requires_its_retained_authority_link() {
        let root = folderbase();
        let store = FolderbaseVersionStore::open(root.path()).expect("open");
        store
            .seal_capture(store.plan_capture().expect("genesis"))
            .expect("genesis");
        fs::remove_file(root.path().join("active.bin")).expect("delete");
        store
            .seal_capture(store.plan_capture().expect("deletion"))
            .expect("deletion");
        store
            .restore_tombstone("active.bin")
            .expect("completed restore");
        let completion =
            read_restore_completion_receipt(&FolderbaseState::open(root.path()).expect("state"))
                .expect("completion receipt")
                .expect("completed restore");
        fs::remove_file(
            root.path()
                .join(restore_stage_path(&completion.transaction)),
        )
        .expect("remove retained authority link");

        assert!(matches!(
            store.restore_tombstone("active.bin"),
            Err(FolderbaseCaptureError::RestoreTargetOccupied(path))
                if path == Path::new("active.bin")
        ));
        assert_eq!(
            fs::read(root.path().join("active.bin")).expect("workspace file preserved"),
            b"first opaque bytes"
        );
    }

    #[test]
    fn late_same_inode_edit_after_projection_retires_without_false_restore_success() {
        let root = folderbase();
        let store = FolderbaseVersionStore::open(root.path()).expect("open");
        store
            .seal_capture(store.plan_capture().expect("genesis"))
            .expect("genesis");
        fs::remove_file(root.path().join("active.bin")).expect("delete");
        store
            .seal_capture(store.plan_capture().expect("deletion"))
            .expect("deletion");
        let edited = b"user edit after projection became durable";

        store
            .restore_tombstone_with_hook("active.bin", |checkpoint| {
                if checkpoint == &RestoreCheckpoint::ProjectionDurable {
                    fs::write(root.path().join("active.bin"), edited)
                        .expect("late same-inode edit");
                }
            })
            .expect_err("late edit must prevent restored-success acknowledgement");
        drop(store);

        let reopened = FolderbaseVersionStore::open(root.path()).expect("fresh-process reopen");
        assert!(matches!(
            reopened.restore_tombstone("active.bin"),
            Err(FolderbaseCaptureError::RestoreTargetOccupied(path))
                if path == Path::new("active.bin")
        ));
        assert_eq!(
            fs::read(root.path().join("active.bin")).expect("preserved edit"),
            edited
        );
        let captured = reopened
            .seal_capture(reopened.plan_capture().expect("edited capture"))
            .expect("late edit cleanup must not wedge capture");
        assert!(captured.created());
    }

    fn assert_cleanup_hook_edit_never_returns_restored(checkpoint_to_edit: RestoreCheckpoint) {
        let root = folderbase();
        let store = FolderbaseVersionStore::open(root.path()).expect("open");
        store
            .seal_capture(store.plan_capture().expect("genesis"))
            .expect("genesis");
        fs::remove_file(root.path().join("active.bin")).expect("delete");
        store
            .seal_capture(store.plan_capture().expect("deletion"))
            .expect("deletion");
        let edited = b"user edit during restore cleanup";

        store
            .restore_tombstone_with_hook("active.bin", |checkpoint| {
                if checkpoint == &checkpoint_to_edit {
                    fs::write(root.path().join("active.bin"), edited)
                        .expect("same-inode cleanup edit");
                }
            })
            .expect_err("cleanup edit must prevent restored-success acknowledgement");
        assert_eq!(
            fs::read(root.path().join("active.bin")).expect("preserved cleanup edit"),
            edited
        );
        drop(store);

        let reopened = FolderbaseVersionStore::open(root.path()).expect("fresh-process reopen");
        assert!(matches!(
            reopened.restore_tombstone("active.bin"),
            Err(FolderbaseCaptureError::RestoreTargetOccupied(path))
                if path == Path::new("active.bin")
        ));
        reopened
            .seal_capture(reopened.plan_capture().expect("edited capture"))
            .expect("cleanup edit must remain capturable");
    }

    fn assert_cleanup_hook_substitution_never_returns_restored(
        checkpoint_to_replace: RestoreCheckpoint,
    ) {
        let root = folderbase();
        let store = FolderbaseVersionStore::open(root.path()).expect("open");
        store
            .seal_capture(store.plan_capture().expect("genesis"))
            .expect("genesis");
        fs::remove_file(root.path().join("active.bin")).expect("delete");
        store
            .seal_capture(store.plan_capture().expect("deletion"))
            .expect("deletion");
        let replacement = b"foreign replacement during restore cleanup";

        store
            .restore_tombstone_with_hook("active.bin", |checkpoint| {
                if checkpoint == &checkpoint_to_replace {
                    fs::remove_file(root.path().join("active.bin"))
                        .expect("remove published inode");
                    fs::write(root.path().join("active.bin"), replacement)
                        .expect("install foreign inode");
                }
            })
            .expect_err("cleanup substitution must prevent restored-success acknowledgement");
        assert_eq!(
            fs::read(root.path().join("active.bin")).expect("preserved replacement"),
            replacement
        );
    }

    #[test]
    fn same_inode_edit_before_stage_retirement_never_returns_restored() {
        assert_cleanup_hook_edit_never_returns_restored(RestoreCheckpoint::BeforeStageRetirement);
    }

    #[test]
    fn same_inode_edit_after_stage_retirement_never_returns_restored() {
        assert_cleanup_hook_edit_never_returns_restored(RestoreCheckpoint::AfterStageRetirement);
    }

    #[test]
    fn same_inode_edit_after_cleanup_intent_retirement_never_returns_restored() {
        assert_cleanup_hook_edit_never_returns_restored(RestoreCheckpoint::CleanupIntentRetired);
    }

    #[test]
    fn same_inode_edit_after_completion_durability_never_returns_restored() {
        assert_cleanup_hook_edit_never_returns_restored(RestoreCheckpoint::CompletionDurable);
    }

    #[test]
    fn same_inode_edit_at_cleanup_completion_never_returns_restored() {
        assert_cleanup_hook_edit_never_returns_restored(RestoreCheckpoint::CleanupComplete);
    }

    #[test]
    fn inode_substitution_after_cleanup_intent_retirement_never_returns_restored() {
        assert_cleanup_hook_substitution_never_returns_restored(
            RestoreCheckpoint::CleanupIntentRetired,
        );
    }

    #[test]
    fn inode_substitution_after_completion_durability_never_returns_restored() {
        assert_cleanup_hook_substitution_never_returns_restored(
            RestoreCheckpoint::CompletionDurable,
        );
    }

    #[test]
    fn inode_substitution_at_cleanup_completion_never_returns_restored() {
        assert_cleanup_hook_substitution_never_returns_restored(RestoreCheckpoint::CleanupComplete);
    }

    #[cfg(unix)]
    #[test]
    fn cleanup_failure_reopens_from_durable_recovery_and_converges() {
        use std::{cell::RefCell, os::unix::fs::PermissionsExt};

        let root = folderbase();
        let store = FolderbaseVersionStore::open(root.path()).expect("open");
        store
            .seal_capture(store.plan_capture().expect("genesis"))
            .expect("genesis");
        fs::remove_file(root.path().join("active.bin")).expect("delete");
        store
            .seal_capture(store.plan_capture().expect("deletion"))
            .expect("deletion");
        let transaction_directory = RefCell::new(None);

        let cleanup_error = store
            .restore_tombstone_with_hook("active.bin", |checkpoint| {
                if checkpoint == &RestoreCheckpoint::JournalDurable {
                    let transaction = read_active_restore_transaction(
                        &FolderbaseState::open(root.path()).expect("state"),
                    )
                    .expect("restore journal")
                    .expect("active restore");
                    transaction_directory.replace(Some(
                        root.path()
                            .join(restore_transaction_directory(&transaction)),
                    ));
                }
                if checkpoint == &RestoreCheckpoint::CleanupRecoveryDurable {
                    fs::set_permissions(
                        transaction_directory
                            .borrow()
                            .as_ref()
                            .expect("transaction directory"),
                        fs::Permissions::from_mode(0o500),
                    )
                    .expect("deny stage cleanup");
                }
            })
            .expect_err("stage cleanup failure must be reported");
        assert!(matches!(
            cleanup_error,
            FolderbaseCaptureError::LocalStore(FolderbaseError::Io { .. })
        ));
        let transaction_directory = transaction_directory
            .into_inner()
            .expect("transaction directory");
        fs::set_permissions(&transaction_directory, fs::Permissions::from_mode(0o700))
            .expect("restore cleanup permissions");
        drop(store);

        let reopened = FolderbaseVersionStore::open(root.path()).expect("reopen");
        let restored = reopened
            .restore_tombstone("active.bin")
            .expect("durable cleanup retry");
        assert!(!restored.created());
        assert_eq!(
            fs::read(root.path().join("active.bin")).expect("restored workspace bytes"),
            b"first opaque bytes"
        );
        assert!(
            transaction_directory
                .join(RESTORE_AUTHORITY_FILENAME)
                .is_file(),
            "retry must retain the private authority and its durable receipt"
        );
    }

    #[test]
    fn committed_cleanup_without_private_links_never_blesses_missing_or_foreign_publication() {
        for replacement in ["missing", "foreign"] {
            let root = folderbase();
            let store = FolderbaseVersionStore::open(root.path()).expect("open");
            store
                .seal_capture(store.plan_capture().expect("genesis"))
                .expect("genesis");
            fs::remove_file(root.path().join("active.bin")).expect("delete");
            store
                .seal_capture(store.plan_capture().expect("deletion"))
                .expect("deletion");

            store
                .restore_tombstone_with_hook("active.bin", |checkpoint| {
                    if checkpoint == &RestoreCheckpoint::AfterStageRetirement {
                        let transaction = read_active_restore_transaction(
                            &FolderbaseState::open(root.path()).expect("state"),
                        )
                        .expect("restore journal")
                        .expect("active restore");
                        fs::remove_file(root.path().join(restore_stage_path(&transaction)))
                            .expect("simulate lost retained authority link");
                    }
                })
                .expect_err("missing retained authority must interrupt cleanup");
            if replacement == "missing" {
                fs::remove_file(root.path().join("active.bin")).expect("remove publication");
            } else {
                fs::remove_file(root.path().join("active.bin")).expect("remove publication");
                fs::write(
                    root.path().join("active.bin"),
                    b"foreign workspace replacement",
                )
                .expect("foreign replacement");
            }
            drop(store);

            let reopened = FolderbaseVersionStore::open(root.path()).expect("fresh-process reopen");
            reopened
                .restore_tombstone("active.bin")
                .expect_err("unproven publication must never return Restored");
            assert!(
                root.path().join(ACTIVE_RESTORE_TRANSACTION_PATH).exists(),
                "{replacement}: unproven cleanup must retain active restore intent"
            );
            assert!(
                root.path().join(RESTORE_CLEANUP_RECOVERY_PATH).exists(),
                "{replacement}: unproven cleanup must retain recovery evidence"
            );
        }
    }

    #[test]
    fn committed_cleanup_without_private_links_never_converges_as_restored() {
        let root = folderbase();
        let store = FolderbaseVersionStore::open(root.path()).expect("open");
        store
            .seal_capture(store.plan_capture().expect("genesis"))
            .expect("genesis");
        fs::remove_file(root.path().join("active.bin")).expect("delete");
        store
            .seal_capture(store.plan_capture().expect("deletion"))
            .expect("deletion");

        store
            .restore_tombstone_with_hook("active.bin", |checkpoint| {
                if checkpoint == &RestoreCheckpoint::AfterStageRetirement {
                    let transaction = read_active_restore_transaction(
                        &FolderbaseState::open(root.path()).expect("state"),
                    )
                    .expect("restore journal")
                    .expect("active restore");
                    fs::remove_file(root.path().join(restore_stage_path(&transaction)))
                        .expect("simulate lost retained authority link");
                }
            })
            .expect_err("missing retained authority must interrupt cleanup");
        drop(store);

        FolderbaseVersionStore::open(root.path())
            .expect("fresh-process reopen")
            .restore_tombstone("active.bin")
            .expect_err("publication without its retained authority cannot return Restored");
        assert_eq!(
            fs::read(root.path().join("active.bin")).expect("restored bytes"),
            b"first opaque bytes"
        );
        assert!(root.path().join(ACTIVE_RESTORE_TRANSACTION_PATH).exists());
        assert!(root.path().join(RESTORE_CLEANUP_RECOVERY_PATH).exists());
    }

    #[cfg(unix)]
    #[test]
    fn cleanup_receipt_survives_active_retirement_and_blocks_capture() {
        use std::os::unix::fs::PermissionsExt;

        let root = folderbase();
        let store = FolderbaseVersionStore::open(root.path()).expect("open");
        store
            .seal_capture(store.plan_capture().expect("genesis"))
            .expect("genesis");
        fs::remove_file(root.path().join("active.bin")).expect("delete");
        store
            .seal_capture(store.plan_capture().expect("deletion"))
            .expect("deletion");
        let restore_transactions = root.path().join(RESTORE_TRANSACTIONS_DIRECTORY);

        let cleanup_error = store
            .restore_tombstone_with_hook("active.bin", |checkpoint| {
                if checkpoint == &RestoreCheckpoint::CleanupIntentRetired {
                    fs::set_permissions(&restore_transactions, fs::Permissions::from_mode(0o500))
                        .expect("deny cleanup receipt removal");
                }
            })
            .expect_err("receipt cleanup failure must be reported");
        assert!(matches!(
            cleanup_error,
            FolderbaseCaptureError::LocalStore(FolderbaseError::Io { .. })
        ));
        assert!(matches!(
            store.seal_capture(store.plan_capture().expect("capture plan")),
            Err(FolderbaseCaptureError::ConflictingTransaction(message))
                if message.contains("restore")
        ));
        fs::set_permissions(&restore_transactions, fs::Permissions::from_mode(0o700))
            .expect("restore transaction permissions");
        drop(store);

        let restored = FolderbaseVersionStore::open(root.path())
            .expect("reopen")
            .restore_tombstone("active.bin")
            .expect("cleanup receipt retry");
        assert!(!restored.created());
        assert!(
            !root.path().join(ACTIVE_RESTORE_TRANSACTION_PATH).exists()
                && !root.path().join(RESTORE_CLEANUP_RECOVERY_PATH).exists(),
            "receipt retry must retire only global mutable intent"
        );
        assert!(
            fs::read_dir(&restore_transactions)
                .expect("restore transactions")
                .filter_map(|entry| entry.ok())
                .any(|entry| entry.path().join(RESTORE_AUTHORITY_FILENAME).is_file()),
            "receipt retry must retain one durable private authority"
        );
    }

    #[test]
    fn projection_failure_after_head_restores_the_prior_head() {
        let root = folderbase();
        let store = FolderbaseVersionStore::open(root.path()).expect("open");
        store
            .seal_capture(store.plan_capture().expect("genesis"))
            .expect("genesis");
        fs::remove_file(root.path().join("active.bin")).expect("delete");
        let deletion = store
            .seal_capture(store.plan_capture().expect("deletion"))
            .expect("deletion");

        let error = store
            .restore_tombstone_with_hook("active.bin", |checkpoint| {
                if checkpoint == &RestoreCheckpoint::PublicationVerified {
                    let transaction = read_active_restore_transaction(
                        &FolderbaseState::open(root.path()).expect("state"),
                    )
                    .expect("restore journal")
                    .expect("active restore");
                    let identity = root.path().join(capture_identity_relative_path(
                        transaction.binding.object_id(),
                    ));
                    fs::remove_file(&identity).expect("remove prior identity projection");
                    fs::create_dir(&identity).expect("block identity projection");
                }
            })
            .expect_err("projection failure after Head must fail the restore");

        assert!(matches!(error, FolderbaseCaptureError::LocalStore(_)));
        assert_eq!(
            local_head(root.path())
                .expect("rolled back deletion Head")
                .version_id,
            deletion.version_id()
        );
    }

    #[cfg(unix)]
    #[test]
    fn projection_never_reopens_a_replacement_ambient_root() {
        let root = folderbase();
        let store = FolderbaseVersionStore::open(root.path()).expect("open");
        store
            .seal_capture(store.plan_capture().expect("genesis"))
            .expect("genesis");
        fs::remove_file(root.path().join("active.bin")).expect("delete");
        let deletion = store
            .seal_capture(store.plan_capture().expect("deletion"))
            .expect("deletion");
        let detached = root.path().with_extension("projection-detached");

        let result = store.restore_tombstone_with_hook("active.bin", |checkpoint| {
            if checkpoint == &RestoreCheckpoint::PublicationVerified {
                fs::rename(root.path(), &detached).expect("detach retained root");
                copy_directory(&detached, root.path());
            }
        });

        assert!(
            result.is_err(),
            "replacement ambient root must revoke restore"
        );
        assert_eq!(
            local_head(&detached)
                .expect("retained root rolled back")
                .version_id,
            deletion.version_id()
        );
        fs::remove_dir_all(&detached).expect("remove detached fixture");
    }

    #[test]
    fn restore_rechecks_a_nested_boundary_created_after_publication() {
        let root = folderbase();
        fs::create_dir(root.path().join("client")).expect("client");
        fs::rename(
            root.path().join("active.bin"),
            root.path().join("client/active.bin"),
        )
        .expect("nested active");
        let store = FolderbaseVersionStore::open(root.path()).expect("open");
        store
            .seal_capture(store.plan_capture().expect("genesis"))
            .expect("genesis");
        fs::remove_file(root.path().join("client/active.bin")).expect("delete");
        let deletion = store
            .seal_capture(store.plan_capture().expect("deletion"))
            .expect("deletion");
        let result = store.restore_tombstone_with_hook("client/active.bin", |checkpoint| {
            if checkpoint == &RestoreCheckpoint::TargetPublished {
                fs::create_dir(root.path().join("client/.FOLDERBASE")).expect("late nested state");
                fs::write(
                    root.path().join("client/.FOLDERBASE/MANIFEST.JSON"),
                    MANIFEST,
                )
                .expect("late nested manifest");
                fs::write(root.path().join("client/FOLDERBASE.md"), "# Child\n")
                    .expect("late nested entry");
            }
        });
        assert!(result.is_err());
        assert_eq!(
            local_head(root.path()).expect("deletion Head").version_id,
            deletion.version_id()
        );

        let root = folderbase();
        fs::create_dir(root.path().join("client")).expect("client");
        fs::rename(
            root.path().join("active.bin"),
            root.path().join("client/active.bin"),
        )
        .expect("nested active");
        let store = FolderbaseVersionStore::open(root.path()).expect("open");
        store
            .seal_capture(store.plan_capture().expect("genesis"))
            .expect("genesis");
        fs::remove_file(root.path().join("client/active.bin")).expect("delete");
        let deletion = store
            .seal_capture(store.plan_capture().expect("deletion"))
            .expect("deletion");
        let interrupted = catch_unwind(AssertUnwindSafe(|| {
            store.restore_tombstone_with_hook("client/active.bin", |checkpoint| {
                if checkpoint == &RestoreCheckpoint::HeadReplaced {
                    panic!("crash after Head replacement");
                }
            })
        }));
        assert!(interrupted.is_err());
        fs::create_dir(root.path().join("client/.FOLDERBASE")).expect("late nested state");
        fs::write(
            root.path().join("client/.FOLDERBASE/MANIFEST.JSON"),
            MANIFEST,
        )
        .expect("late nested manifest");
        fs::write(root.path().join("client/FOLDERBASE.md"), "# Child\n")
            .expect("late nested entry");
        assert!(store.restore_tombstone("client/active.bin").is_err());
        assert_eq!(
            local_head(root.path())
                .expect("rolled back deletion Head")
                .version_id,
            deletion.version_id()
        );
    }

    #[test]
    fn stale_store_refuses_a_replacement_physical_root_with_copied_state() {
        let root = folderbase();
        let store = FolderbaseVersionStore::open(root.path()).expect("open");
        store
            .seal_capture(store.plan_capture().expect("genesis"))
            .expect("genesis");
        fs::remove_file(root.path().join("active.bin")).expect("delete");
        let deletion = store
            .seal_capture(store.plan_capture().expect("deletion"))
            .expect("deletion");
        let detached = root.path().with_extension("detached");
        fs::rename(root.path(), &detached).expect("detach original root");
        copy_directory(&detached, root.path());

        assert!(store.restore_tombstone("active.bin").is_err());
        assert!(!root.path().join("active.bin").exists());
        assert_eq!(
            local_head(root.path())
                .expect("copied deletion Head")
                .version_id,
            deletion.version_id()
        );
    }

    #[cfg(unix)]
    #[test]
    fn post_head_root_swap_rolls_back_the_exact_detached_root() {
        let root = folderbase();
        let store = FolderbaseVersionStore::open(root.path()).expect("open");
        store
            .seal_capture(store.plan_capture().expect("genesis"))
            .expect("genesis");
        fs::remove_file(root.path().join("active.bin")).expect("delete");
        let deletion = store
            .seal_capture(store.plan_capture().expect("deletion"))
            .expect("deletion");
        let detached = root.path().with_extension("post-head-detached");
        let result = store.restore_tombstone_with_hook("active.bin", |checkpoint| {
            if checkpoint == &RestoreCheckpoint::HeadReplaced {
                fs::rename(root.path(), &detached).expect("detach committed root");
                copy_directory(&detached, root.path());
            }
        });
        assert!(result.is_err());
        assert_eq!(
            local_head(&detached)
                .expect("detached prior Head")
                .version_id,
            deletion.version_id()
        );
        fs::remove_dir_all(&detached).expect("remove detached fixture");
    }

    #[cfg(unix)]
    #[test]
    fn restore_parent_symlink_swap_never_writes_outside_retained_root() {
        use std::os::unix::fs::symlink;

        let root = folderbase();
        fs::create_dir(root.path().join("docs")).expect("docs");
        fs::rename(
            root.path().join("active.bin"),
            root.path().join("docs/active.bin"),
        )
        .expect("nested active");
        let store = FolderbaseVersionStore::open(root.path()).expect("open");
        store
            .seal_capture(store.plan_capture().expect("genesis"))
            .expect("genesis");
        fs::remove_file(root.path().join("docs/active.bin")).expect("delete");
        store
            .seal_capture(store.plan_capture().expect("deletion"))
            .expect("deletion");
        let outside = tempdir().expect("outside");

        let error = store
            .restore_tombstone_with_hook("docs/active.bin", |checkpoint| {
                if checkpoint == &RestoreCheckpoint::StageDurable {
                    fs::rename(root.path().join("docs"), root.path().join("detached-docs"))
                        .expect("detach parent");
                    symlink(outside.path(), root.path().join("docs")).expect("redirect parent");
                }
            })
            .expect_err("parent symlink swap must fail closed");
        assert!(matches!(
            error,
            FolderbaseCaptureError::LocalStore(_)
                | FolderbaseCaptureError::RestoreTargetOccupied(_)
        ));
        assert!(!outside.path().join("active.bin").exists());
        assert!(!root.path().join("detached-docs/active.bin").exists());
    }

    #[test]
    fn restore_never_crosses_a_new_nested_folderbase_boundary() {
        let root = folderbase();
        fs::create_dir(root.path().join("client")).expect("client");
        fs::rename(
            root.path().join("active.bin"),
            root.path().join("client/active.bin"),
        )
        .expect("nested active");
        let store = FolderbaseVersionStore::open(root.path()).expect("open");
        store
            .seal_capture(store.plan_capture().expect("genesis"))
            .expect("genesis");
        fs::remove_file(root.path().join("client/active.bin")).expect("delete");
        let deletion = store
            .seal_capture(store.plan_capture().expect("deletion"))
            .expect("deletion");
        fs::create_dir(root.path().join("client/.folderbase")).expect("nested state");
        fs::write(
            root.path().join("client/.folderbase/manifest.json"),
            br#"{
  "protocol_version": "0.4.0",
  "folderbase": {
    "id": "folderbase_019f9b75-4f42-7f65-a012-2bfecdd8c474"
  }
}
"#,
        )
        .expect("nested manifest");
        fs::write(
            root.path().join("client/FOLDERBASE.md"),
            "# Nested Folderbase\n",
        )
        .expect("nested entry");

        assert!(store.restore_tombstone("client/active.bin").is_err());
        assert!(!root.path().join("client/active.bin").exists());
        assert_eq!(
            local_head(root.path()).expect("deletion Head").version_id,
            deletion.version_id()
        );
    }

    #[test]
    fn restore_never_crosses_a_case_folded_nested_folderbase_boundary() {
        let root = folderbase();
        fs::create_dir(root.path().join("client")).expect("client");
        fs::rename(
            root.path().join("active.bin"),
            root.path().join("client/active.bin"),
        )
        .expect("nested active");
        let store = FolderbaseVersionStore::open(root.path()).expect("open");
        store
            .seal_capture(store.plan_capture().expect("genesis"))
            .expect("genesis");
        fs::remove_file(root.path().join("client/active.bin")).expect("delete");
        let deletion = store
            .seal_capture(store.plan_capture().expect("deletion"))
            .expect("deletion");
        fs::create_dir(root.path().join("client/.FOLDERBASE")).expect("nested state alias");
        fs::write(
            root.path().join("client/.FOLDERBASE/MANIFEST.JSON"),
            br#"{
  "protocol_version": "0.4.0",
  "folderbase": {
    "id": "folderbase_019f9b75-4f42-7f65-a012-2bfecdd8c474"
  }
}
"#,
        )
        .expect("nested manifest alias");

        assert!(store.restore_tombstone("client/active.bin").is_err());
        assert!(!root.path().join("client/active.bin").exists());
        assert_eq!(
            local_head(root.path()).expect("deletion Head").version_id,
            deletion.version_id()
        );
    }

    #[test]
    fn every_persistence_checkpoint_reopens_and_converges_on_exact_assigned_version() {
        for fault in [
            CaptureCheckpoint::JournalDurable,
            CaptureCheckpoint::ObjectWritesDurable,
            CaptureCheckpoint::VersionDurable,
            CaptureCheckpoint::HeadReplaced,
            CaptureCheckpoint::CleanupComplete,
        ] {
            let root = folderbase();
            let store = FolderbaseVersionStore::open(root.path()).expect("open");
            let plan = store.plan_capture().expect("plan");
            let interrupted = catch_unwind(AssertUnwindSafe(|| {
                store.seal_capture_with_hook(plan, |checkpoint| {
                    if checkpoint == &fault {
                        panic!("simulated process termination at {fault:?}");
                    }
                })
            }));
            assert!(interrupted.is_err(), "fault {fault:?}");

            let assigned = active_transaction(root.path())
                .map(|transaction| transaction.target_version_id)
                .or_else(|| local_head(root.path()).map(|head| head.version_id))
                .expect("durable assigned target");
            drop(store);
            let reopened = FolderbaseVersionStore::open(root.path()).expect("crash reopen");
            let retry = reopened
                .seal_capture(reopened.plan_capture().expect("reopen plan"))
                .expect("exact retry");
            assert_eq!(retry.version_id(), assigned, "fault {fault:?}");
            let verified = reopened
                .read_version(retry.version_id())
                .expect("all referenced bytes verify");
            assert_eq!(verified.canonical_digest().unwrap(), retry.version_sha256());
            assert!(active_transaction(root.path()).is_none());
            let head = local_head(root.path()).expect("Local Head");
            assert_eq!(head.version_id, assigned);
        }
    }

    #[test]
    fn local_head_wire_distinguishes_capture_and_version_derived_authority() {
        let root = folderbase();
        let store = FolderbaseVersionStore::open(root.path()).expect("open");
        store
            .seal_capture(store.plan_capture().expect("genesis"))
            .expect("genesis");
        let captured: serde_json::Value = serde_json::from_slice(
            &fs::read(root.path().join(LOCAL_HEAD_PATH)).expect("captured Head"),
        )
        .expect("captured Head JSON");
        assert_eq!(captured["format"], "folderbase-local-head-v2");
        assert_eq!(captured["authority"]["kind"], "capture_transaction_v1");
        assert!(captured["authority"]["sha256"].as_str().is_some());
        assert!(captured.get("transaction_sha256").is_none());

        fs::remove_file(root.path().join("active.bin")).expect("delete");
        store
            .seal_capture(store.plan_capture().expect("deletion"))
            .expect("deletion");
        store
            .restore_tombstone("active.bin")
            .expect("restore Tombstone");
        let restored: serde_json::Value = serde_json::from_slice(
            &fs::read(root.path().join(LOCAL_HEAD_PATH)).expect("restored Head"),
        )
        .expect("restored Head JSON");
        assert_eq!(restored["format"], "folderbase-local-head-v2");
        assert_eq!(restored["authority"]["kind"], "version_derived_v1");
        assert!(restored["authority"]["sha256"].as_str().is_some());
        assert!(restored.get("transaction_sha256").is_none());
    }

    #[test]
    fn released_v1_capture_heads_recover_and_normalize_without_losing_authority() {
        fn write_v1_head(root: &Path, transaction_sha256: &str) {
            let head = local_head(root).expect("current Head");
            FolderbaseState::open(root)
                .expect("state")
                .replace(
                    Path::new(LOCAL_HEAD_PATH),
                    &json_bytes(&serde_json::json!({
                        "format": "folderbase-local-head-v1",
                        "folderbase_id": head.folderbase_id,
                        "root_instance_sha256": head.root_instance_sha256,
                        "version_id": head.version_id,
                        "version_sha256": head.version_sha256,
                        "transaction_sha256": transaction_sha256
                    }))
                    .expect("v1 Head bytes"),
                )
                .expect("install v1 Head");
        }

        let recovering = folderbase();
        let store = FolderbaseVersionStore::open(recovering.path()).expect("open");
        let interrupted = catch_unwind(AssertUnwindSafe(|| {
            store.seal_capture_with_hook(store.plan_capture().expect("plan"), |checkpoint| {
                if checkpoint == &CaptureCheckpoint::HeadReplaced {
                    let transaction =
                        active_transaction(recovering.path()).expect("active capture transaction");
                    write_v1_head(
                        recovering.path(),
                        &capture_transaction_sha256(&transaction).expect("transaction authority"),
                    );
                    panic!("simulate released v1 process termination");
                }
            })
        }));
        assert!(interrupted.is_err());
        drop(store);

        let reopened = FolderbaseVersionStore::open(recovering.path()).expect("reopen");
        let recovered = reopened
            .seal_capture(reopened.plan_capture().expect("v1 recovery plan"))
            .expect("recover v1 Head and active capture");
        let recovered_head: serde_json::Value = serde_json::from_slice(
            &fs::read(recovering.path().join(LOCAL_HEAD_PATH)).expect("recovered Head"),
        )
        .expect("recovered Head JSON");
        assert_eq!(recovered_head["format"], "folderbase-local-head-v2");
        assert_eq!(
            recovered_head["authority"]["kind"],
            "capture_transaction_v1"
        );
        assert_eq!(recovered_head["version_id"], recovered.version_id());

        let steady = folderbase();
        let steady_store = FolderbaseVersionStore::open(steady.path()).expect("open steady");
        steady_store
            .seal_capture(steady_store.plan_capture().expect("steady plan"))
            .expect("steady capture");
        let authority = local_head(steady.path())
            .expect("steady Head")
            .authority
            .sha256()
            .to_owned();
        write_v1_head(steady.path(), &authority);
        drop(steady_store);

        let reopened = FolderbaseVersionStore::open(steady.path()).expect("reopen steady");
        let unchanged = reopened
            .seal_capture(reopened.plan_capture().expect("steady v1 plan"))
            .expect("normalize steady v1 Head");
        assert!(!unchanged.created());
        let normalized: serde_json::Value = serde_json::from_slice(
            &fs::read(steady.path().join(LOCAL_HEAD_PATH)).expect("normalized Head"),
        )
        .expect("normalized Head JSON");
        assert_eq!(normalized["format"], "folderbase-local-head-v2");
        assert_eq!(normalized["authority"]["sha256"], authority);
    }

    #[test]
    fn released_v1_non_genesis_active_journal_recovers_before_and_after_head() {
        #[derive(Serialize)]
        struct ReleasedJournalHead {
            version_id: String,
            version_sha256: String,
            transaction_sha256: String,
        }

        #[derive(Serialize)]
        struct ReleasedCaptureTransaction {
            format: String,
            transaction_id: String,
            folderbase_id: String,
            root_instance_sha256: String,
            plan_sha256: String,
            expected_head: Option<ReleasedJournalHead>,
            target_version_id: String,
            created_at: String,
            root_manifest_object_id: String,
            root_manifest_candidate_version_id: String,
            prior_root_manifest_version_id: Option<String>,
            assignments: Vec<CaptureAssignment>,
            #[serde(skip_serializing_if = "Vec::is_empty")]
            target_tombstones: Vec<Tombstone>,
        }

        fn released_journal_bytes(transaction: &CaptureTransaction) -> Vec<u8> {
            let expected_head = transaction.expected_head.as_ref().map(|head| {
                let LocalHeadAuthority::CaptureTransactionV1 { sha256 } = &head.authority else {
                    panic!("released capture parent must retain capture authority");
                };
                ReleasedJournalHead {
                    version_id: head.version_id.clone(),
                    version_sha256: head.version_sha256.clone(),
                    transaction_sha256: sha256.clone(),
                }
            });
            let released = ReleasedCaptureTransaction {
                format: transaction.format.clone(),
                transaction_id: transaction.transaction_id.clone(),
                folderbase_id: transaction.folderbase_id.clone(),
                root_instance_sha256: transaction.root_instance_sha256.clone(),
                plan_sha256: transaction.plan_sha256.clone(),
                expected_head,
                target_version_id: transaction.target_version_id.clone(),
                created_at: transaction.created_at.clone(),
                root_manifest_object_id: transaction.root_manifest_object_id.clone(),
                root_manifest_candidate_version_id: transaction
                    .root_manifest_candidate_version_id
                    .clone(),
                prior_root_manifest_version_id: transaction.prior_root_manifest_version_id.clone(),
                assignments: transaction.assignments.clone(),
                target_tombstones: transaction.target_tombstones.clone(),
            };
            let mut encoded =
                serde_json::to_vec_pretty(&released).expect("released capture journal JSON");
            encoded.push(b'\n');
            encoded
        }

        fn write_released_head(root: &Path, transaction_sha256: &str) {
            let head = local_head(root).expect("current Head");
            FolderbaseState::open(root)
                .expect("state")
                .replace(
                    Path::new(LOCAL_HEAD_PATH),
                    &json_bytes(&serde_json::json!({
                        "format": "folderbase-local-head-v1",
                        "folderbase_id": head.folderbase_id,
                        "root_instance_sha256": head.root_instance_sha256,
                        "version_id": head.version_id,
                        "version_sha256": head.version_sha256,
                        "transaction_sha256": transaction_sha256
                    }))
                    .expect("released Head bytes"),
                )
                .expect("install released Head");
        }

        for fault in [
            CaptureCheckpoint::JournalDurable,
            CaptureCheckpoint::HeadReplaced,
        ] {
            let root = folderbase();
            let store = FolderbaseVersionStore::open(root.path()).expect("open");
            store
                .seal_capture(store.plan_capture().expect("genesis"))
                .expect("genesis");
            fs::write(root.path().join("active.bin"), b"non-genesis update")
                .expect("update live file");
            let plan = store.plan_capture().expect("update plan");
            let interrupted = catch_unwind(AssertUnwindSafe(|| {
                store.seal_capture_with_hook(plan, |checkpoint| {
                    if checkpoint == &fault {
                        panic!("simulate released v1 process termination at {fault:?}");
                    }
                })
            }));
            assert!(interrupted.is_err(), "fault {fault:?}");

            let transaction = active_transaction(root.path()).expect("active capture");
            assert!(
                transaction.expected_head.is_some(),
                "fixture must be non-genesis"
            );
            let released_bytes = released_journal_bytes(&transaction);
            let released_sha256 = format!("{:x}", Sha256::digest(&released_bytes));
            FolderbaseState::open(root.path())
                .expect("state")
                .replace(Path::new(ACTIVE_CAPTURE_TRANSACTION_PATH), &released_bytes)
                .expect("install exact released active journal bytes");
            let head_authority = if fault == CaptureCheckpoint::HeadReplaced {
                released_sha256.clone()
            } else {
                local_head(root.path())
                    .expect("prior Head")
                    .authority
                    .sha256()
                    .to_owned()
            };
            write_released_head(root.path(), &head_authority);
            drop(store);

            let reopened = FolderbaseVersionStore::open(root.path()).expect("fresh reopen");
            let recovered = reopened
                .seal_capture(reopened.plan_capture().expect("recovery plan"))
                .expect("released active journal recovery");
            assert_eq!(recovered.version_id(), transaction.target_version_id);
            assert!(active_transaction(root.path()).is_none());
            let head = local_head(root.path()).expect("normalized recovered Head");
            assert_eq!(head.format, "folderbase-local-head-v2");
            assert_eq!(head.authority.sha256(), released_sha256);
        }
    }

    #[test]
    fn local_head_rejects_unknown_or_mismatched_authority_discriminators() {
        let root = folderbase();
        let store = FolderbaseVersionStore::open(root.path()).expect("open");
        store
            .seal_capture(store.plan_capture().expect("genesis"))
            .expect("genesis");
        let head = local_head(root.path()).expect("captured Head");
        let version_authority =
            local_head_authority_sha256(&store, &head.version_id, &head.version_sha256)
                .expect("version authority");
        assert_ne!(head.authority.sha256(), version_authority);
        let head_path = Path::new(LOCAL_HEAD_PATH);
        let state = FolderbaseState::open(root.path()).expect("state");
        let mut wire: serde_json::Value = serde_json::from_slice(
            &state
                .read_bounded(head_path, crate::MAX_LOCAL_HEAD_BYTES)
                .expect("read Head")
                .expect("Head"),
        )
        .expect("Head JSON");

        wire["authority"]["kind"] = serde_json::Value::String("version_derived_v1".to_owned());
        state
            .replace(head_path, &json_bytes(&wire).expect("mismatched Head"))
            .expect("install mismatched Head");
        assert!(matches!(
            FolderbaseVersionStore::open(root.path()),
            Err(FolderbaseCaptureError::InvalidLocalHead(message))
                if message.contains("version-derived")
        ));

        wire["authority"]["kind"] = serde_json::Value::String("future_authority_v9".to_owned());
        state
            .replace(head_path, &json_bytes(&wire).expect("unknown Head"))
            .expect("install unknown Head");
        assert!(matches!(
            FolderbaseVersionStore::open(root.path()),
            Err(FolderbaseCaptureError::InvalidLocalHead(_))
        ));
    }

    #[test]
    fn post_head_legacy_journal_without_tombstone_field_still_recovers() {
        let root = folderbase();
        let store = FolderbaseVersionStore::open(root.path()).expect("open");
        let plan = store.plan_capture().expect("plan");
        let interrupted = catch_unwind(AssertUnwindSafe(|| {
            store.seal_capture_with_hook(plan, |checkpoint| {
                if checkpoint == &CaptureCheckpoint::HeadReplaced {
                    let state = FolderbaseState::open(root.path()).expect("state");
                    let active_path = Path::new(ACTIVE_CAPTURE_TRANSACTION_PATH);
                    let encoded = state
                        .read_bounded(active_path, MAX_CAPTURE_TRANSACTION_BYTES)
                        .expect("read active journal")
                        .expect("active journal");
                    let mut wire: serde_json::Value =
                        serde_json::from_slice(&encoded).expect("journal JSON");
                    wire.as_object_mut()
                        .expect("journal object")
                        .remove("target_tombstones");
                    assert!(wire.get("target_tombstones").is_none());
                    let legacy_encoded = json_bytes(&wire).expect("legacy journal bytes");
                    state
                        .replace(active_path, &legacy_encoded)
                        .expect("install legacy journal");

                    let mut head = local_head(root.path()).expect("Local Head");
                    head.authority = LocalHeadAuthority::CaptureTransactionV1 {
                        sha256: format!("{:x}", Sha256::digest(&legacy_encoded)),
                    };
                    state
                        .replace(Path::new(LOCAL_HEAD_PATH), &json_bytes(&head).unwrap())
                        .expect("bind Head to legacy journal");
                    panic!("stop after legacy Head replacement");
                }
            })
        }));
        assert!(interrupted.is_err());

        let assigned = local_head(root.path()).expect("legacy Head").version_id;
        let reopened = FolderbaseVersionStore::open(root.path()).expect("reopen");
        let retry = reopened
            .seal_capture(reopened.plan_capture().expect("same live plan"))
            .expect("legacy post-Head intent must recover");
        assert_eq!(retry.version_id(), assigned);
        assert!(reopened.read_version(retry.version_id()).is_ok());
        assert!(active_transaction(root.path()).is_none());
    }

    fn interrupt_update_after_journal(
        root: &Path,
        store: &FolderbaseVersionStore,
    ) -> (Vec<u8>, String) {
        fs::write(root.join("pending.bin"), b"pending update").expect("pending update");
        let plan = store.plan_capture().expect("update plan");
        let interrupted = catch_unwind(AssertUnwindSafe(|| {
            store.seal_capture_with_hook(plan, |checkpoint| {
                if checkpoint == &CaptureCheckpoint::JournalDurable {
                    panic!("stop after active journal");
                }
            })
        }));
        assert!(interrupted.is_err());
        let transaction = active_transaction(root).expect("active intent");
        let encoded = fs::read(root.join(ACTIVE_CAPTURE_TRANSACTION_PATH))
            .expect("exact active journal bytes");
        (encoded, transaction.target_version_id)
    }

    fn assert_hidden_retry_preserves_active_intent(
        root: &Path,
        store: &FolderbaseVersionStore,
        journal_before: &[u8],
        hidden_path: &Path,
    ) {
        let head_before = fs::read(root.join(LOCAL_HEAD_PATH)).expect("prior Head");
        let error = store
            .seal_capture(store.plan_capture().expect("scope-change plan"))
            .expect_err("hidden prior binding must be refused");
        assert!(matches!(
            error,
            FolderbaseCaptureError::PriorBindingHidden(path) if path == hidden_path
        ));
        assert_eq!(
            fs::read(root.join(ACTIVE_CAPTURE_TRANSACTION_PATH)).expect("preserved active intent"),
            journal_before
        );
        assert_eq!(
            fs::read(root.join(LOCAL_HEAD_PATH)).expect("unchanged prior Head"),
            head_before
        );
    }

    #[test]
    fn newly_ignored_path_preserves_stale_active_intent_before_refusal() {
        let root = folderbase();
        let store = FolderbaseVersionStore::open(root.path()).expect("open");
        store
            .seal_capture(store.plan_capture().expect("genesis plan"))
            .expect("genesis");
        let ignore_path = root.path().join(".folderbaseignore");
        let original_modified = fs::metadata(&ignore_path)
            .expect("ignore metadata")
            .modified()
            .expect("ignore modified time");
        let (journal, assigned) = interrupt_update_after_journal(root.path(), &store);

        fs::write(&ignore_path, "active.bin\n").expect("hide prior binding");
        assert_hidden_retry_preserves_active_intent(
            root.path(),
            &store,
            &journal,
            Path::new("active.bin"),
        );

        fs::write(&ignore_path, "").expect("restore ignore policy");
        File::options()
            .write(true)
            .open(&ignore_path)
            .expect("open restored policy")
            .set_times(std::fs::FileTimes::new().set_modified(original_modified))
            .expect("restore approved plan time");
        let retry = store
            .seal_capture(store.plan_capture().expect("restored update plan"))
            .expect("preserved intent remains recoverable");
        assert_eq!(retry.version_id(), assigned);
        assert!(active_transaction(root.path()).is_none());
    }

    #[test]
    fn new_nested_boundary_preserves_stale_active_intent_before_refusal() {
        let root = folderbase();
        fs::create_dir(root.path().join("client")).expect("client");
        fs::write(root.path().join("client/notes.md"), "client notes").expect("client notes");
        let store = FolderbaseVersionStore::open(root.path()).expect("open");
        store
            .seal_capture(store.plan_capture().expect("genesis plan"))
            .expect("genesis");
        let (journal, _) = interrupt_update_after_journal(root.path(), &store);

        fs::create_dir(root.path().join("client/.folderbase")).expect("nested state");
        fs::write(
            root.path().join("client/.folderbase/manifest.json"),
            br#"{
  "protocol_version": "0.4.0",
  "folderbase": {
    "id": "folderbase_019f9b75-4f42-7f65-a012-2bfecdd8c474"
  }
}
"#,
        )
        .expect("nested manifest");
        fs::write(
            root.path().join("client/FOLDERBASE.md"),
            "# Nested Folderbase\n",
        )
        .expect("nested entry");
        assert_hidden_retry_preserves_active_intent(
            root.path(),
            &store,
            &journal,
            Path::new("client"),
        );
    }

    #[cfg(unix)]
    #[test]
    fn unsupported_replacement_preserves_stale_active_intent_before_refusal() {
        let root = folderbase();
        let store = FolderbaseVersionStore::open(root.path()).expect("open");
        store
            .seal_capture(store.plan_capture().expect("genesis plan"))
            .expect("genesis");
        let (journal, _) = interrupt_update_after_journal(root.path(), &store);

        let original = root.path().join("original-active.bin");
        fs::rename(root.path().join("active.bin"), &original).expect("retain original inode");
        fs::hard_link(&original, root.path().join("active.bin")).expect("unsupported hard link");
        assert_hidden_retry_preserves_active_intent(
            root.path(),
            &store,
            &journal,
            Path::new("active.bin"),
        );
    }

    #[test]
    fn tombstone_capture_reopens_and_converges_at_every_persistence_checkpoint() {
        for fault in [
            CaptureCheckpoint::JournalDurable,
            CaptureCheckpoint::ObjectWritesDurable,
            CaptureCheckpoint::VersionDurable,
            CaptureCheckpoint::HeadReplaced,
            CaptureCheckpoint::CleanupComplete,
        ] {
            let root = folderbase();
            let store = FolderbaseVersionStore::open(root.path()).expect("open");
            let genesis = store
                .seal_capture(store.plan_capture().expect("genesis plan"))
                .expect("genesis");
            let prior = store
                .read_version(genesis.version_id())
                .expect("genesis version");
            let prior_binding = prior.lookup_binding("active.bin").expect("prior binding");
            let prior_object_id = prior_binding.object_id().to_owned();
            let prior_object_version_id = prior_binding
                .object_version_id()
                .expect("prior Object Version")
                .to_owned();
            fs::remove_file(root.path().join("active.bin")).expect("delete active file");

            let plan = store.plan_capture().expect("deletion plan");
            let interrupted = catch_unwind(AssertUnwindSafe(|| {
                store.seal_capture_with_hook(plan, |checkpoint| {
                    if checkpoint == &fault {
                        panic!("simulated Tombstone termination at {fault:?}");
                    }
                })
            }));
            assert!(interrupted.is_err(), "fault {fault:?}");

            let assigned = active_transaction(root.path())
                .map(|transaction| transaction.target_version_id)
                .or_else(|| local_head(root.path()).map(|head| head.version_id))
                .expect("durable assigned Tombstone target");
            drop(store);
            let reopened = FolderbaseVersionStore::open(root.path()).expect("crash reopen");
            let retry = reopened
                .seal_capture(reopened.plan_capture().expect("reopen deletion plan"))
                .expect("exact Tombstone retry");
            assert_eq!(retry.version_id(), assigned, "fault {fault:?}");
            let verified = reopened
                .read_version(retry.version_id())
                .expect("Tombstone references verify");
            assert_eq!(verified.parents(), &[genesis.version_id().to_owned()]);
            assert!(verified.lookup_binding("active.bin").is_none());
            assert_eq!(verified.tombstones().len(), 1);
            let tombstone = &verified.tombstones()[0];
            assert_eq!(tombstone.path(), "active.bin");
            assert_eq!(tombstone.object_id(), prior_object_id);
            assert_eq!(
                tombstone.last_object_version_id(),
                Some(prior_object_version_id.as_str())
            );
            assert!(active_transaction(root.path()).is_none());
            assert_eq!(
                local_head(root.path()).expect("Local Head").version_id,
                assigned
            );
        }
    }

    #[test]
    fn active_journal_tombstone_tamper_never_changes_the_verified_deletion_target() {
        let root = folderbase();
        let store = FolderbaseVersionStore::open(root.path()).expect("open");
        let genesis = store
            .seal_capture(store.plan_capture().expect("genesis plan"))
            .expect("genesis");
        fs::remove_file(root.path().join("active.bin")).expect("delete active file");
        let plan = store.plan_capture().expect("deletion plan");
        let interrupted = catch_unwind(AssertUnwindSafe(|| {
            store.seal_capture_with_hook(plan, |checkpoint| {
                if checkpoint == &CaptureCheckpoint::JournalDurable {
                    panic!("stop after Tombstone journal");
                }
            })
        }));
        assert!(interrupted.is_err());

        let mut transaction = active_transaction(root.path()).expect("active Tombstone intent");
        let original = transaction
            .target_tombstones
            .first()
            .expect("target Tombstone")
            .clone();
        transaction.target_tombstones[0] = Tombstone::from_verified_producer(
            original.path(),
            ObjectId::new().to_string(),
            original.deleted_kind(),
            original.last_object_version_id().map(str::to_owned),
        );
        FolderbaseState::open(root.path())
            .expect("state")
            .replace(
                Path::new(ACTIVE_CAPTURE_TRANSACTION_PATH),
                &json_bytes(&transaction).expect("tampered journal"),
            )
            .expect("replace active journal");

        let reopened = FolderbaseVersionStore::open(root.path()).expect("reopen");
        let error = reopened
            .seal_capture(reopened.plan_capture().expect("same deletion plan"))
            .expect_err("tampered target Tombstone must fail closed");
        assert!(matches!(
            error,
            FolderbaseCaptureError::InvalidCaptureTransaction(message)
                if message.contains("Tombstones")
        ));
        assert_eq!(
            local_head(root.path()).expect("prior Head").version_id,
            genesis.version_id()
        );
    }

    #[cfg(unix)]
    #[test]
    fn seal_retains_state_capability_before_any_publication_and_never_writes_through_a_swap() {
        use std::os::unix::fs::symlink;

        let root = folderbase();
        let outside = tempdir().expect("outside");
        fs::write(outside.path().join("sentinel"), b"outside").expect("sentinel");
        let store = FolderbaseVersionStore::open(root.path()).expect("open");
        let plan = store.plan_capture().expect("plan");
        let error = store
            .seal_capture_with_hook(plan, |checkpoint| {
                if checkpoint == &CaptureCheckpoint::StateCapabilityOpen {
                    assert!(
                        !root
                            .path()
                            .join(".folderbase/locks/transactions.lock")
                            .exists(),
                        "no mutating prelude may run before the retained state capability"
                    );
                    fs::rename(
                        root.path().join(".folderbase"),
                        root.path().join(".folderbase-detached"),
                    )
                    .expect("detach original state");
                    symlink(outside.path(), root.path().join(".folderbase"))
                        .expect("replace visible state with outside link");
                }
            })
            .expect_err("state attachment swap must fail closed");
        assert!(matches!(
            error,
            FolderbaseCaptureError::PlanningStateChanged
                | FolderbaseCaptureError::PlanStoreMismatch
                | FolderbaseCaptureError::CaptureStateChanged(_)
                | FolderbaseCaptureError::LocalStore(_)
                | FolderbaseCaptureError::RootAttestation(_)
        ));
        assert_eq!(
            fs::read_dir(outside.path())
                .expect("outside directory")
                .map(|entry| entry.expect("entry").file_name())
                .collect::<Vec<_>>(),
            vec![std::ffi::OsString::from("sentinel")],
            "the swapped outside directory receives no Folderbase state"
        );
    }

    #[test]
    fn update_faults_never_lose_prior_head_and_retry_preserves_parent() {
        for fault in [
            CaptureCheckpoint::JournalDurable,
            CaptureCheckpoint::ObjectWritesDurable,
            CaptureCheckpoint::VersionDurable,
            CaptureCheckpoint::HeadReplaced,
            CaptureCheckpoint::CleanupComplete,
        ] {
            let root = folderbase();
            let store = FolderbaseVersionStore::open(root.path()).expect("open");
            let genesis = store
                .seal_capture(store.plan_capture().expect("genesis plan"))
                .expect("genesis");
            fs::write(root.path().join("active.bin"), b"second opaque byte")
                .expect("same-inode edit");
            let plan = store.plan_capture().expect("update plan");
            let interrupted = catch_unwind(AssertUnwindSafe(|| {
                store.seal_capture_with_hook(plan, |checkpoint| {
                    if checkpoint == &fault {
                        panic!("simulated update termination at {fault:?}");
                    }
                })
            }));
            assert!(interrupted.is_err());
            let active = active_transaction(root.path());
            let head = local_head(root.path()).expect("Head survives");
            if matches!(
                fault,
                CaptureCheckpoint::JournalDurable
                    | CaptureCheckpoint::ObjectWritesDurable
                    | CaptureCheckpoint::VersionDurable
            ) {
                assert_eq!(head.version_id, genesis.version_id());
            }
            let assigned = active
                .map(|transaction| transaction.target_version_id)
                .unwrap_or_else(|| head.version_id.clone());
            drop(store);
            let reopened = FolderbaseVersionStore::open(root.path()).expect("crash reopen");
            let retry = reopened
                .seal_capture(reopened.plan_capture().expect("retry plan"))
                .expect("retry");
            assert_eq!(retry.version_id(), assigned);
            let update = reopened.read_version(retry.version_id()).expect("update");
            assert_eq!(update.parents(), &[genesis.version_id().to_owned()]);
        }
    }

    #[test]
    fn mutation_after_preflight_and_before_byte_read_fails_without_head_movement() {
        let root = folderbase();
        let store = FolderbaseVersionStore::open(root.path()).expect("open");
        let plan = store.plan_capture().expect("plan");
        let error = store
            .seal_capture_with_hook(plan, |checkpoint| {
                if checkpoint == &CaptureCheckpoint::BeforeObjectBytesRead("active.bin".to_owned())
                {
                    fs::write(root.path().join("active.bin"), b"mutated opaque data")
                        .expect("concurrent edit");
                }
            })
            .expect_err("concurrent edit fails");
        assert!(matches!(
            error,
            FolderbaseCaptureError::CaptureStateChanged(path)
                if path == Path::new("active.bin")
        ));
        assert!(local_head(root.path()).is_none());
    }

    #[test]
    fn extra_hard_link_before_restored_object_bytes_read_fails_without_head_movement() {
        let root = folderbase();
        let store = FolderbaseVersionStore::open(root.path()).expect("open");
        store
            .seal_capture(store.plan_capture().expect("genesis"))
            .expect("genesis");
        fs::remove_file(root.path().join("active.bin")).expect("delete");
        store
            .seal_capture(store.plan_capture().expect("deletion"))
            .expect("deletion");
        let restored = store
            .restore_tombstone("active.bin")
            .expect("restore with retained authority");
        let plan = store.plan_capture().expect("authority-aware plan");

        let error = store
            .seal_capture_with_hook(plan, |checkpoint| {
                if checkpoint == &CaptureCheckpoint::BeforeObjectBytesRead("active.bin".to_owned())
                {
                    fs::hard_link(
                        root.path().join("active.bin"),
                        root.path().join("unapproved-extra-link.bin"),
                    )
                    .expect("concurrent extra hard link");
                }
            })
            .expect_err("an uncommitted hard link must fail closed");
        assert!(matches!(
            error,
            FolderbaseCaptureError::CaptureStateChanged(path)
                if path == Path::new("active.bin")
        ));
        assert_eq!(
            local_head(root.path())
                .expect("restored Local Head remains")
                .version_id,
            restored.version_id()
        );
    }

    #[test]
    fn abandoned_attempt_removes_only_intent_and_reuses_safe_content_addressed_orphans() {
        let root = folderbase();
        let store = FolderbaseVersionStore::open(root.path()).expect("open");
        let plan = store.plan_capture().expect("plan");
        let interrupted = catch_unwind(AssertUnwindSafe(|| {
            store.seal_capture_with_hook(plan, |checkpoint| {
                if checkpoint == &CaptureCheckpoint::ObjectWritesDurable {
                    panic!("crash after immutable object writes");
                }
            })
        }));
        assert!(interrupted.is_err());
        let abandoned = active_transaction(root.path())
            .expect("abandoned intent")
            .target_version_id;
        fs::write(root.path().join("active.bin"), b"newer opaque bytes").expect("new state");
        let sealed = store
            .seal_capture(store.plan_capture().expect("fresh plan"))
            .expect("fresh capture cleans stale intent");
        assert_ne!(sealed.version_id(), abandoned);
        assert!(active_transaction(root.path()).is_none());
        assert!(
            read_regular_beneath(
                root.path(),
                &folderbase_version_relative_path(&abandoned),
                MAX_ENCODED_VERSION_BYTES
            )
            .unwrap()
            .is_none(),
            "an uncommitted Folderbase Version never became visible"
        );
        assert!(
            fs::read_dir(root.path().join(".folderbase/versions/blobs/sha256"))
                .unwrap()
                .count()
                >= 2,
            "verified content-addressed orphans are safe and reusable"
        );
    }

    #[test]
    fn missing_physical_identity_rebuilds_evidence_without_splitting_logical_identity() {
        let root = folderbase();
        let store = FolderbaseVersionStore::open(root.path()).expect("open");
        let genesis = store
            .seal_capture(store.plan_capture().expect("genesis plan"))
            .expect("genesis");
        let version = store.read_version(genesis.version_id()).expect("version");
        let prior = version
            .lookup_binding("active.bin")
            .expect("active binding");
        let object_id = prior.object_id().to_owned();
        let object_version_id = prior
            .object_version_id()
            .expect("Object Version")
            .to_owned();
        fs::remove_file(root.path().join(capture_identity_relative_path(&object_id)))
            .expect("remove local identity evidence");

        let repaired = store
            .seal_capture(store.plan_capture().expect("next plan"))
            .expect("same-path same-kind continuity");
        assert!(repaired.created());
        let current = store
            .read_version(repaired.version_id())
            .expect("repaired version");
        let current = current
            .lookup_binding("active.bin")
            .expect("active binding");
        assert_eq!(current.object_id(), object_id);
        assert_eq!(
            current.object_version_id(),
            Some(object_version_id.as_str())
        );
        assert!(
            root.path()
                .join(capture_identity_relative_path(&object_id))
                .is_file()
        );
    }

    fn assert_same_kind_replacement_after_head_preserves_logical_identity(start: Option<&Barrier>) {
        let root = folderbase();
        let store = FolderbaseVersionStore::open(root.path()).expect("open");
        let plan = store.plan_capture().expect("plan");
        if let Some(start) = start {
            start.wait();
        }
        let mut head_replaced_count = 0;
        let mut replacement_identities = None;
        let interrupted = catch_unwind(AssertUnwindSafe(|| {
            store.seal_capture_with_hook(plan, |checkpoint| {
                if checkpoint == &CaptureCheckpoint::HeadReplaced {
                    head_replaced_count += 1;
                    let active_path = root.path().join("active.bin");
                    let captured = File::open(&active_path).expect("open captured file");
                    let captured_identity = CaptureMetadataFingerprint::from_std_file(&captured)
                        .expect("captured fingerprint")
                        .physical_identity;
                    fs::remove_file(&active_path).expect("remove captured file");
                    fs::write(&active_path, b"same path, replacement identity")
                        .expect("replace captured file");
                    let replacement = File::open(&active_path).expect("open replacement file");
                    let replacement_identity =
                        CaptureMetadataFingerprint::from_std_file(&replacement)
                            .expect("replacement fingerprint")
                            .physical_identity;
                    replacement_identities = Some((captured_identity, replacement_identity));
                    drop(captured);
                    panic!("stop before identity projection");
                }
            })
        }));
        assert!(interrupted.is_err());
        assert_eq!(
            head_replaced_count, 1,
            "one per-call fault hook must observe Head replacement exactly once"
        );
        let (captured_identity, replacement_identity) =
            replacement_identities.expect("fault hook records both physical identities");
        assert_ne!(
            captured_identity, replacement_identity,
            "the fault fixture must create a provably different filesystem object"
        );

        let reopened = FolderbaseVersionStore::open(root.path()).expect("reopen");
        let captured_head = reopened
            .plan_capture()
            .expect("replacement plan")
            .current_local_head()
            .expect("captured Head")
            .version_id()
            .to_owned();
        let captured = reopened
            .read_version(&captured_head)
            .expect("captured version");
        let captured_binding = captured
            .lookup_binding("active.bin")
            .expect("captured binding");
        let captured_object_id = captured_binding.object_id().to_owned();
        let captured_object_version_id = captured_binding
            .object_version_id()
            .expect("captured Object Version")
            .to_owned();
        let updated = reopened
            .seal_capture(reopened.plan_capture().expect("replacement plan"))
            .expect("same-kind replacement remains the same Knowledge Object");
        let current = reopened
            .read_version(updated.version_id())
            .expect("replacement version");
        let current_binding = current
            .lookup_binding("active.bin")
            .expect("replacement binding");
        assert_eq!(current.parents(), &[captured_head]);
        assert_eq!(current_binding.object_id(), captured_object_id);
        assert_ne!(
            current_binding.object_version_id(),
            Some(captured_object_version_id.as_str())
        );
        assert!(current.tombstones().is_empty());
    }

    #[test]
    fn replacement_after_head_and_before_identity_projection_preserves_logical_identity() {
        assert_same_kind_replacement_after_head_preserves_logical_identity(None);
    }

    #[test]
    fn post_head_replacement_faults_remain_isolated_under_parallel_stress() {
        const WORKERS: usize = 8;

        let start = Arc::new(Barrier::new(WORKERS));
        thread::scope(|scope| {
            let workers = (0..WORKERS)
                .map(|_| {
                    let start = Arc::clone(&start);
                    scope.spawn(move || {
                        assert_same_kind_replacement_after_head_preserves_logical_identity(Some(
                            &start,
                        ));
                    })
                })
                .collect::<Vec<_>>();
            for worker in workers {
                worker.join().expect("parallel seal worker");
            }
        });
    }

    #[test]
    fn post_head_journal_observation_tamper_never_blesses_a_replacement_identity() {
        let root = folderbase();
        let store = FolderbaseVersionStore::open(root.path()).expect("open");
        let plan = store.plan_capture().expect("plan");
        let interrupted = catch_unwind(AssertUnwindSafe(|| {
            store.seal_capture_with_hook(plan, |checkpoint| {
                if checkpoint == &CaptureCheckpoint::HeadReplaced {
                    let active_path = root.path().join("active.bin");
                    let sealed_bytes = fs::read(&active_path).expect("sealed bytes");
                    fs::remove_file(&active_path).expect("remove captured identity");
                    fs::write(&active_path, sealed_bytes).expect("same-byte replacement");

                    let replacement = File::open(&active_path).expect("replacement file");
                    let replacement_observed =
                        CaptureMetadataFingerprint::from_std_file(&replacement)
                            .expect("replacement fingerprint");
                    let mut transaction = active_transaction(root.path()).expect("active journal");
                    transaction
                        .assignments
                        .iter_mut()
                        .find(|assignment| assignment.path == "active.bin")
                        .expect("active assignment")
                        .observed = replacement_observed;
                    FolderbaseState::open(root.path())
                        .expect("state")
                        .replace(
                            Path::new(ACTIVE_CAPTURE_TRANSACTION_PATH),
                            &json_bytes(&transaction).unwrap(),
                        )
                        .expect("tamper post-Head journal");
                    panic!("stop before identity projection");
                }
            })
        }));
        assert!(interrupted.is_err());

        let reopened = FolderbaseVersionStore::open(root.path()).expect("reopen");
        let error = reopened
            .seal_capture(reopened.plan_capture().expect("replacement plan"))
            .expect_err("mutable journal evidence must not authorize identity continuity");
        assert!(matches!(
            error,
            FolderbaseCaptureError::InvalidCaptureTransaction(_)
        ));
    }

    #[test]
    fn post_head_committed_parent_and_time_tamper_never_recovers_as_the_journal_target() {
        let root = folderbase();
        let store = FolderbaseVersionStore::open(root.path()).expect("open");
        let plan = store.plan_capture().expect("plan");
        let interrupted = catch_unwind(AssertUnwindSafe(|| {
            store.seal_capture_with_hook(plan, |checkpoint| {
                if checkpoint == &CaptureCheckpoint::HeadReplaced {
                    let state = FolderbaseState::open(root.path()).expect("state");
                    let transaction = active_transaction(root.path()).expect("active journal");
                    let relative = folderbase_version_relative_path(&transaction.target_version_id);
                    let encoded = state
                        .read_bounded(&relative, MAX_ENCODED_VERSION_BYTES)
                        .expect("read version")
                        .expect("committed version");
                    let mut wire: serde_json::Value =
                        serde_json::from_slice(&encoded).expect("version JSON");
                    wire["created_at"] =
                        serde_json::Value::String("2026-01-01T00:00:00Z".to_owned());
                    wire["parents"] =
                        serde_json::json!(["fbversion_019faf78-b120-73c9-a6d4-07112d2517ba"]);
                    let tampered = serde_json::to_vec(&wire).expect("tampered version");
                    let decoded = FolderbaseVersion::decode_bounded(tampered.as_slice())
                        .expect("well-formed tampered version");
                    state
                        .replace(&relative, &tampered)
                        .expect("replace committed bytes");

                    let mut head = local_head(root.path()).expect("Local Head");
                    head.version_sha256 = decoded.canonical_digest().expect("tampered digest");
                    state
                        .replace(Path::new(LOCAL_HEAD_PATH), &json_bytes(&head).unwrap())
                        .expect("bind Head to tampered version");
                    panic!("stop before committed recovery");
                }
            })
        }));
        assert!(interrupted.is_err());

        let reopened = FolderbaseVersionStore::open(root.path()).expect("reopen");
        let error = reopened
            .seal_capture(reopened.plan_capture().expect("same live plan"))
            .expect_err("committed lineage and time must match the anchored journal");
        assert!(matches!(
            error,
            FolderbaseCaptureError::InvalidCaptureTransaction(_)
        ));
    }

    #[test]
    fn truncated_active_journal_cannot_seal_a_subset_of_the_plan() {
        let root = folderbase();
        let store = FolderbaseVersionStore::open(root.path()).expect("open");
        let plan = store.plan_capture().expect("plan");
        let interrupted = catch_unwind(AssertUnwindSafe(|| {
            store.seal_capture_with_hook(plan, |checkpoint| {
                if checkpoint == &CaptureCheckpoint::JournalDurable {
                    panic!("stop after journal");
                }
            })
        }));
        assert!(interrupted.is_err());

        let mut transaction = active_transaction(root.path()).expect("active journal");
        transaction.assignments.pop().expect("trailing assignment");
        FolderbaseState::open(root.path())
            .expect("state")
            .replace(
                Path::new(ACTIVE_CAPTURE_TRANSACTION_PATH),
                &json_bytes(&transaction).unwrap(),
            )
            .expect("tamper journal");

        let error = store
            .seal_capture(store.plan_capture().expect("same plan"))
            .expect_err("subset journal must fail closed");
        assert!(matches!(
            error,
            FolderbaseCaptureError::InvalidCaptureTransaction(_)
        ));
        assert!(local_head(root.path()).is_none());
    }

    #[test]
    fn tampered_reused_assignment_cannot_rewrite_prior_identity_lineage() {
        let root = folderbase();
        let store = FolderbaseVersionStore::open(root.path()).expect("open");
        let genesis = store
            .seal_capture(store.plan_capture().expect("genesis plan"))
            .expect("genesis");
        fs::write(root.path().join("active.bin"), b"same object, new bytes").expect("edit");
        let plan = store.plan_capture().expect("update plan");
        let interrupted = catch_unwind(AssertUnwindSafe(|| {
            store.seal_capture_with_hook(plan, |checkpoint| {
                if checkpoint == &CaptureCheckpoint::JournalDurable {
                    panic!("stop after journal");
                }
            })
        }));
        assert!(interrupted.is_err());

        let mut transaction = active_transaction(root.path()).expect("active journal");
        let assignment = transaction
            .assignments
            .iter_mut()
            .find(|assignment| assignment.path == "active.bin")
            .expect("active assignment");
        assignment.object_id = ObjectId::new().to_string();
        FolderbaseState::open(root.path())
            .expect("state")
            .replace(
                Path::new(ACTIVE_CAPTURE_TRANSACTION_PATH),
                &json_bytes(&transaction).unwrap(),
            )
            .expect("tamper journal lineage");

        let error = store
            .seal_capture(store.plan_capture().expect("same update plan"))
            .expect_err("lineage rewrite must fail closed");
        assert!(matches!(
            error,
            FolderbaseCaptureError::InvalidCaptureTransaction(_)
        ));
        assert_eq!(
            local_head(root.path()).expect("prior Head").version_id,
            genesis.version_id()
        );
    }

    #[test]
    fn active_journal_write_and_restart_use_one_explicit_byte_bound() {
        let root = folderbase();
        let store = FolderbaseVersionStore::open(root.path()).expect("open");
        let plan = store.plan_capture().expect("plan");
        let transaction = assign_capture_transaction(
            &plan,
            &capture_plan_sha256(&plan).expect("plan digest"),
            None,
        )
        .expect("assignment");
        let encoded = json_bytes(&transaction).expect("journal bytes");

        assert_eq!(
            encode_active_transaction(&transaction, encoded.len() as u64)
                .expect("exact bound accepted"),
            encoded
        );
        assert!(matches!(
            encode_active_transaction(&transaction, encoded.len() as u64 - 1),
            Err(FolderbaseCaptureError::InvalidCaptureTransaction(message))
                if message.contains("bounded record limit")
        ));
        assert_eq!(
            MAX_CAPTURE_TRANSACTION_BYTES, MAX_ENCODED_VERSION_BYTES,
            "writer and restart reader intentionally share one declared bound"
        );
    }

    #[test]
    fn active_journal_bounds_assignments_and_tombstones_as_one_version_entry_set() {
        let root = folderbase();
        let store = FolderbaseVersionStore::open(root.path()).expect("open");
        let plan = store.plan_capture().expect("plan");
        let mut transaction = assign_capture_transaction(
            &plan,
            &capture_plan_sha256(&plan).expect("plan digest"),
            None,
        )
        .expect("assignment");
        transaction.target_tombstones = (0..crate::folderbase_version::MAX_VERSION_ENTRIES)
            .map(|index| {
                Tombstone::from_verified_producer(
                    format!("deleted/{index:05}.bin"),
                    ObjectId::new().to_string(),
                    DeletedKind::RegularFile,
                    Some(VersionId::new().to_string()),
                )
            })
            .collect();

        let error = validate_transaction(&store, &transaction)
            .expect_err("journal aggregate must fit one bounded Folderbase Version");
        assert!(matches!(
            error,
            FolderbaseCaptureError::InvalidCaptureTransaction(message)
                if message.contains("aggregate")
        ));
    }

    #[test]
    fn future_version_envelope_is_bounded_before_journal_or_immutable_writes() {
        let root = folderbase();
        let store = FolderbaseVersionStore::open(root.path()).expect("open");
        let plan = store.plan_capture().expect("plan");
        let error = store
            .seal_capture_with_hook_and_limits(plan, |_| {}, MAX_CAPTURE_TRANSACTION_BYTES, 1)
            .expect_err("future version envelope must be preflighted");
        assert!(matches!(
            error,
            FolderbaseCaptureError::InvalidCaptureTransaction(message)
                if message.contains("Folderbase Version envelope")
        ));
        assert!(active_transaction(root.path()).is_none());
        assert!(local_head(root.path()).is_none());
        assert_eq!(
            fs::read_dir(root.path().join(".folderbase/versions/blobs/sha256"))
                .expect("blob directory")
                .count(),
            0,
            "preflight refusal occurs before immutable content writes"
        );
    }

    #[test]
    fn repeat_capture_stops_at_the_approved_length_without_moving_local_head() {
        let root = folderbase();
        let store = FolderbaseVersionStore::open(root.path()).expect("open");
        let genesis = store
            .seal_capture(store.plan_capture().expect("genesis plan"))
            .expect("genesis");
        let repeat = store.plan_capture().expect("repeat plan");
        let mut grew_source = false;

        let error = store
            .seal_capture_with_hook(repeat, |checkpoint| {
                if !grew_source
                    && checkpoint
                        == &CaptureCheckpoint::BeforeObjectBytesRead("active.bin".to_owned())
                {
                    grew_source = true;
                    use std::io::Write;

                    fs::OpenOptions::new()
                        .append(true)
                        .open(root.path().join("active.bin"))
                        .expect("open growing regular source")
                        .write_all(b"x")
                        .expect("grow beyond approved length");
                }
            })
            .expect_err("repeat capture must reject growth beyond the approved length");

        assert!(
            grew_source,
            "repeat verification must expose its byte-read seam"
        );
        assert!(matches!(
            error,
            FolderbaseCaptureError::CaptureStateChanged(path)
                if path == Path::new("active.bin")
        ));
        assert_eq!(
            local_head(root.path())
                .expect("prior Local Head")
                .version_id,
            genesis.version_id()
        );
        assert!(
            active_transaction(root.path()).is_none(),
            "repeat verification must fail before assigning a new transaction"
        );
    }
}

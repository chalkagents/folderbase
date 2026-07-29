//! Durable, byte-verified Folderbase Version capture and device-local Head.
//!
//! Capture journals IDs before installing immutable records. The Folderbase
//! Version remains the only full-state manifest; mutable object projections and
//! Local Head are derived, recoverable local state.

use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    io::Read,
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
        FolderbaseVersionStore, capture_entry_fingerprint,
    },
    folderbase_state::FolderbaseState,
    folderbase_version::{
        Exclusion, ExclusionKind, ExclusionReason, FolderbaseVersion, FolderbaseVersionEntries,
        FolderbaseVersionParts, MAX_ENCODED_VERSION_BYTES, PathBinding, PathBindingKind,
        RootManifest, validate_capture_version_id,
    },
    local_versions::{
        ContentDigest, LocalObjectRecord, LocalVersionRecord, LocalVersionStore, ObjectId,
        ObjectLifecycle, ObjectProvenance, VersionId,
    },
    root_attestation::metadata_is_link_or_reparse,
};

const CAPTURE_TRANSACTION_FORMAT_V1: &str = "folderbase-capture-transaction-v1";
const CAPTURE_TRANSACTIONS_DIRECTORY: &str = ".folderbase/transactions/folderbase-version-captures";
const ACTIVE_CAPTURE_TRANSACTION_PATH: &str =
    ".folderbase/transactions/folderbase-version-captures/active.json";
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct JournalHead {
    version_id: String,
    version_sha256: String,
    transaction_sha256: String,
}

impl From<&CaptureLocalHead> for JournalHead {
    fn from(value: &CaptureLocalHead) -> Self {
        Self {
            version_id: value.version_id().to_owned(),
            version_sha256: value.version_sha256().to_owned(),
            transaction_sha256: value.transaction_sha256().to_owned(),
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
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalHeadRecord {
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
    regular_projections: Vec<(LocalObjectRecord, ContentDigest)>,
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
        let state = FolderbaseState::open_existing(&self.root_attestation.root)?;
        read_and_verify_folderbase_version(self, &local, &state, version_id)
    }

    fn seal_capture_with_hook(
        &self,
        plan: CapturePlan,
        mut checkpoint: impl FnMut(&CaptureCheckpoint),
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
            ".folderbase/local/path-identities",
        ] {
            state.ensure_private_dir(Path::new(relative))?;
        }
        state.ensure_private_dir(Path::new(CAPTURE_TRANSACTIONS_DIRECTORY))?;
        state.ensure_private_dir(Path::new(FOLDERBASE_VERSIONS_DIRECTORY))?;
        state.ensure_private_dir(Path::new(CAPTURE_IDENTITIES_DIRECTORY))?;

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
                if capture_transaction_sha256(transaction)? != head.transaction_sha256 {
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
                // The old Head still owns authority. Immutable records already
                // installed by the abandoned attempt remain safe orphans;
                // removing only the active intent permits a fresh assignment.
                remove_active_transaction(&state)?;
                active = None;
            }
        }

        let prior = load_prior_head(self, &local, &state, plan.current_local_head())?;
        if active.is_none()
            && live_state_matches_prior(self, &plan, &local, &state, prior.as_ref())?
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
                let transaction =
                    assign_capture_transaction(self, &state, &plan, &plan_sha256, prior.as_ref())?;
                write_active_transaction(&state, &transaction)?;
                checkpoint(&CaptureCheckpoint::JournalDurable);
                transaction
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
                format: "folderbase-local-head-v1".to_owned(),
                folderbase_id: self.root_attestation.folderbase_id.clone(),
                root_instance_sha256: self.root_attestation.root_instance_sha256.clone(),
                version_id: built.version.version_id().to_owned(),
                version_sha256: built.version_sha256.clone(),
                transaction_sha256: capture_transaction_sha256(&transaction)?,
            },
        )?;
        checkpoint(&CaptureCheckpoint::HeadReplaced);

        for (projection, content) in &built.regular_projections {
            local.write_capture_object_projection_in(&state, projection, content)?;
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
    store: &FolderbaseVersionStore,
    state: &FolderbaseState,
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
    if let Some(version) = prior {
        for binding in version.bindings() {
            if !plan
                .entries()
                .iter()
                .any(|entry| entry.path() == binding.path())
            {
                return Err(FolderbaseCaptureError::TombstonesRequired(PathBuf::from(
                    binding.path(),
                )));
            }
        }
    }

    let mut assignments = Vec::with_capacity(plan.entries().len());
    for entry in plan.entries() {
        let prior_binding = prior_bindings.get(entry.path()).copied();
        if prior_binding.is_some_and(|binding| binding.kind() != path_binding_kind(entry.kind())) {
            return Err(FolderbaseCaptureError::TombstonesRequired(PathBuf::from(
                entry.path(),
            )));
        }
        let reused_object = match prior_binding {
            Some(binding) => identity_allows_reuse(
                state,
                &store.root_attestation.root,
                binding.object_id(),
                entry,
            )?,
            None => false,
        };
        if prior_binding.is_some() && !reused_object {
            return Err(FolderbaseCaptureError::TombstonesRequired(PathBuf::from(
                entry.path(),
            )));
        }
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
    })
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
                    || {},
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
                    regular_projections.push((
                        regular_projection(
                            local,
                            state,
                            assignment,
                            &object_version_id,
                            prior_binding.and_then(|binding| binding.object_version_id()),
                            &transaction.created_at,
                        )?,
                        content,
                    ));
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
    let tombstones = prior
        .map(|version| version.tombstones().to_vec())
        .unwrap_or_default();
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
    let content = local.install_content_reader_in(
        state,
        &mut file,
        &store.root_attestation.root.join(relative),
    )?;
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
        Some((local, state)) => local.install_content_reader_in(state, &mut file, &display)?,
        None => hash_reader(&mut file, &display)?,
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
) -> Result<ContentDigest, FolderbaseCaptureError> {
    let mut digest = Sha256::new();
    let mut bytes = 0_u64;
    let mut buffer = [0_u8; IO_BUFFER_BYTES];
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|source| FolderbaseCaptureError::Io {
                path: path.to_path_buf(),
                source,
            })?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
        bytes = bytes.checked_add(read as u64).ok_or_else(|| {
            FolderbaseCaptureError::InvalidCaptureTransaction(format!(
                "content byte count overflowed at {}",
                path.display()
            ))
        })?;
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
        || transaction.assignments.len() > crate::folderbase_version::MAX_VERSION_ENTRIES
    {
        return Err(FolderbaseCaptureError::InvalidCaptureTransaction(
            "active journal metadata is inconsistent".to_owned(),
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
            None if !assignment.reused_object && assignment.prior_object_version_id.is_none() => {}
            _ => {
                return Err(FolderbaseCaptureError::InvalidCaptureTransaction(format!(
                    "journal identity lineage does not match the verified parent at {}",
                    entry.path()
                )));
            }
        }
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
) -> Result<Option<CaptureTransaction>, FolderbaseCaptureError> {
    let Some(encoded) = state.read_bounded(
        Path::new(ACTIVE_CAPTURE_TRANSACTION_PATH),
        MAX_CAPTURE_TRANSACTION_BYTES,
    )?
    else {
        return Ok(None);
    };
    serde_json::from_slice(&encoded)
        .map(Some)
        .map_err(|source| {
            FolderbaseCaptureError::InvalidCaptureTransaction(format!(
                "active journal is invalid JSON: {source}"
            ))
        })
}

fn write_active_transaction(
    state: &FolderbaseState,
    transaction: &CaptureTransaction,
) -> Result<(), FolderbaseCaptureError> {
    let encoded = encode_active_transaction(transaction, MAX_CAPTURE_TRANSACTION_BYTES)?;
    state
        .publish_new(Path::new(ACTIVE_CAPTURE_TRANSACTION_PATH), &encoded)
        .map_err(Into::into)
}

fn encode_active_transaction(
    transaction: &CaptureTransaction,
    maximum_bytes: u64,
) -> Result<Vec<u8>, FolderbaseCaptureError> {
    let encoded = json_bytes(transaction)?;
    if encoded.len() as u64 > maximum_bytes {
        return Err(FolderbaseCaptureError::InvalidCaptureTransaction(
            "active journal exceeds its bounded record limit".to_owned(),
        ));
    }
    Ok(encoded)
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
        transaction_sha256: head.transaction_sha256.clone(),
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
    let head: LocalHeadRecord = serde_json::from_slice(&encoded).map_err(|source| {
        FolderbaseCaptureError::InvalidLocalHead(format!("Local Head JSON is invalid: {source}"))
    })?;
    if head.format != "folderbase-local-head-v1"
        || head.version_sha256.len() != 64
        || head.transaction_sha256.len() != 64
        || !head
            .version_sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || !head
            .transaction_sha256
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
            let content = ContentDigest {
                algorithm: "sha256".to_owned(),
                digest: binding.content_sha256().expect("regular digest").to_owned(),
                bytes: binding.bytes().expect("regular bytes"),
            };
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
            local.write_capture_object_projection_in(state, &projection, &content)?;
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

    fn active_transaction(root: &Path) -> Option<CaptureTransaction> {
        read_active_transaction(&FolderbaseState::open(root).expect("state"))
            .expect("active intent")
    }

    fn local_head(root: &Path) -> Option<LocalHeadRecord> {
        read_head_record(&FolderbaseState::open(root).expect("state")).expect("Local Head")
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
    fn missing_identity_evidence_never_authorizes_prior_object_reuse() {
        let root = folderbase();
        let store = FolderbaseVersionStore::open(root.path()).expect("open");
        let genesis = store
            .seal_capture(store.plan_capture().expect("genesis plan"))
            .expect("genesis");
        let version = store.read_version(genesis.version_id()).expect("version");
        let object_id = version
            .lookup_binding("active.bin")
            .expect("active binding")
            .object_id();
        fs::remove_file(root.path().join(capture_identity_relative_path(object_id)))
            .expect("remove local identity evidence");

        let error = store
            .seal_capture(store.plan_capture().expect("next plan"))
            .expect_err("missing identity must fail closed");
        assert!(matches!(
            error,
            FolderbaseCaptureError::TombstonesRequired(path)
                if path == Path::new("active.bin")
        ));
        assert_eq!(
            local_head(root.path()).expect("prior Head").version_id,
            genesis.version_id()
        );
    }

    #[test]
    fn replacement_after_head_and_before_identity_projection_requires_a_tombstone() {
        let root = folderbase();
        let store = FolderbaseVersionStore::open(root.path()).expect("open");
        let plan = store.plan_capture().expect("plan");
        let interrupted = catch_unwind(AssertUnwindSafe(|| {
            store.seal_capture_with_hook(plan, |checkpoint| {
                if checkpoint == &CaptureCheckpoint::HeadReplaced {
                    fs::remove_file(root.path().join("active.bin")).expect("remove captured file");
                    fs::write(
                        root.path().join("active.bin"),
                        b"same path, replacement identity",
                    )
                    .expect("replace captured file");
                    panic!("stop before identity projection");
                }
            })
        }));
        assert!(interrupted.is_err());

        let reopened = FolderbaseVersionStore::open(root.path()).expect("reopen");
        let error = reopened
            .seal_capture(reopened.plan_capture().expect("replacement plan"))
            .expect_err("replacement needs a tombstone");
        assert!(matches!(
            error,
            FolderbaseCaptureError::TombstonesRequired(path)
                if path == Path::new("active.bin")
        ));
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
        let state = FolderbaseState::open_existing(root.path()).expect("state");
        let transaction = assign_capture_transaction(
            &store,
            &state,
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
}

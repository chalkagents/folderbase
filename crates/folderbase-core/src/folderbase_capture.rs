//! Read-only planning for a future Folderbase Version capture transaction.
//!
//! This module inventories bounded filesystem metadata. It does not read
//! ordinary file contents, seal a Folderbase Version, mutate Local Head, or
//! write any protocol state.

use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::{OsStr, OsString},
    fmt, fs,
    io::{self, Read},
    path::{Component, Path, PathBuf},
};

use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt};
use cap_std::fs::{Dir, DirEntry, Metadata, OpenOptions, ReadDir};
use ignore::{
    Match,
    gitignore::{Gitignore, GitignoreBuilder},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use unicode_casefold::UnicodeCaseFold;
use unicode_normalization::UnicodeNormalization;

use crate::{
    FolderbaseError, FolderbaseRootAttestation, RootAttestationError,
    folderbase_restore_authority::{
        MAX_RESTORE_AUTHORITIES, MAX_RESTORE_AUTHORITY_BYTES, RESTORE_AUTHORITIES_DIRECTORY,
        RESTORE_AUTHORITY_FORMAT_V1, RestoreAuthorityRecord, restore_authority_record_path,
        restore_stage_path, stable_file_identity_sha256, stable_file_link_count,
    },
    folderbase_state::FolderbaseState,
    folderbase_version::{
        FolderbaseVersionError, MAX_OBJECT_BYTES, MAX_VERSION_ENTRIES, validate_capture_path,
        validate_capture_sha256, validate_capture_symlink_targets, validate_capture_version_id,
    },
    physical_identity::PhysicalIdentity,
    root_attestation::{
        ManifestProtocolProfile, RootInstanceAuthority, attest_folderbase_root_with_profile,
    },
    traversal_policy::{
        NestedFolderbaseBoundaryKind, RECONSTRUCTABLE_DIRECTORIES,
        classify_nested_folderbase_boundary, is_folderbase_state_component,
    },
};

#[cfg(unix)]
use crate::folderbase_restore_authority::stable_unix_file_identity_sha256;

pub const MAX_FOLDERBASEIGNORE_BYTES: u64 = 1024 * 1024;
pub const MAX_LOCAL_HEAD_BYTES: u64 = 4096;
pub const MAX_CAPTURE_PLAN_RECORDS: usize = MAX_VERSION_ENTRIES;
const LOCAL_HEAD_PATH: &str = ".folderbase/local/head.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapturePlanLimitKind {
    Entries,
    ObjectBytes,
}

impl fmt::Display for CapturePlanLimitKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Entries => "entries",
            Self::ObjectBytes => "object_bytes",
        })
    }
}

/// Metadata kind observed for a future live Path Binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureEntryKind {
    Directory,
    RegularFile,
    Symlink,
}

/// One metadata-only inventory entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturePlanEntry {
    path: String,
    kind: CaptureEntryKind,
    bytes: Option<u64>,
    executable: Option<bool>,
    symlink_target: Option<String>,
    observed: CaptureMetadataFingerprint,
    link_commitment: CaptureLinkCommitment,
}

impl CapturePlanEntry {
    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn kind(&self) -> CaptureEntryKind {
        self.kind
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

    pub(crate) fn observed(&self) -> &CaptureMetadataFingerprint {
        &self.observed
    }

    pub(crate) fn link_commitment(&self) -> &CaptureLinkCommitment {
        &self.link_commitment
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CaptureAuthorityLink {
    receipt_path: String,
    receipt_sha256: String,
    private_stage_path: String,
    published_identity_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CaptureLinkCommitment {
    expected_live_link_count: u64,
    authority_set_sha256: Option<String>,
    authorities: Vec<CaptureAuthorityLink>,
}

impl Default for CaptureLinkCommitment {
    fn default() -> Self {
        Self {
            expected_live_link_count: 1,
            authority_set_sha256: None,
            authorities: Vec::new(),
        }
    }
}

impl CaptureLinkCommitment {
    pub(crate) fn is_legacy_default(&self) -> bool {
        self == &Self::default()
    }

    pub(crate) fn is_well_formed(&self) -> bool {
        let exact_link_count = self
            .authorities
            .len()
            .checked_add(1)
            .and_then(|count| u64::try_from(count).ok());
        let expected_digest =
            (!self.authorities.is_empty()).then(|| capture_authority_set_sha256(&self.authorities));
        if exact_link_count != Some(self.expected_live_link_count)
            || self.authority_set_sha256 != expected_digest
        {
            return false;
        }
        let mut previous = None;
        for authority in &self.authorities {
            if previous
                .is_some_and(|path: &str| path.as_bytes() >= authority.receipt_path.as_bytes())
                || validate_capture_sha256(&authority.receipt_sha256).is_err()
                || validate_capture_sha256(&authority.published_identity_sha256).is_err()
            {
                return false;
            }
            let receipt_path = Path::new(&authority.receipt_path);
            let Some(transaction_id) = receipt_path
                .parent()
                .and_then(Path::file_name)
                .and_then(OsStr::to_str)
            else {
                return false;
            };
            if restore_authority_record_path(transaction_id) != receipt_path
                || restore_stage_path(transaction_id) != Path::new(&authority.private_stage_path)
            {
                return false;
            }
            previous = Some(authority.receipt_path.as_str());
        }
        true
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CaptureMetadataFingerprint {
    pub(crate) bytes: u64,
    pub(crate) modified_unix_nanos: Option<u128>,
    pub(crate) readonly: bool,
    pub(crate) executable: bool,
    pub(crate) device: Option<u64>,
    pub(crate) inode: Option<u64>,
    #[serde(default)]
    pub(crate) physical_identity: Option<String>,
}

impl CaptureMetadataFingerprint {
    pub(crate) fn from_cap_metadata(metadata: &Metadata) -> Self {
        let modified_unix_nanos = metadata
            .modified()
            .ok()
            .and_then(|value| value.into_std().duration_since(std::time::UNIX_EPOCH).ok())
            .map(|value| value.as_nanos());
        #[cfg(unix)]
        let (device, inode) = {
            use cap_std::fs::MetadataExt;

            (Some(metadata.dev()), Some(metadata.ino()))
        };
        #[cfg(not(unix))]
        let (device, inode) = (None, None);
        Self {
            bytes: metadata.len(),
            modified_unix_nanos,
            readonly: metadata.permissions().readonly(),
            executable: is_executable(metadata),
            device,
            inode,
            physical_identity: physical_identity_from_cap_metadata(metadata),
        }
    }

    pub(crate) fn from_std_metadata(metadata: &fs::Metadata) -> Self {
        let modified_unix_nanos = metadata
            .modified()
            .ok()
            .and_then(|value| value.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|value| value.as_nanos());
        #[cfg(unix)]
        let (device, inode, executable) = {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};

            (
                Some(metadata.dev()),
                Some(metadata.ino()),
                metadata.permissions().mode() & 0o111 != 0,
            )
        };
        #[cfg(not(unix))]
        let (device, inode, executable) = (None, None, false);
        Self {
            bytes: metadata.len(),
            modified_unix_nanos,
            readonly: metadata.permissions().readonly(),
            executable,
            device,
            inode,
            physical_identity: physical_identity_from_std_metadata(metadata),
        }
    }

    pub(crate) fn from_std_file(file: &fs::File) -> io::Result<Self> {
        let metadata = file.metadata()?;
        let fingerprint = Self::from_std_metadata(&metadata);
        #[cfg(windows)]
        {
            return Ok(fingerprint.with_physical_identity(Some(windows_file_identity(file)?)));
        }
        #[cfg(not(windows))]
        Ok(fingerprint)
    }

    #[cfg(windows)]
    fn with_physical_identity(mut self, physical_identity: Option<String>) -> Self {
        self.physical_identity = physical_identity;
        self
    }
}

#[cfg(unix)]
fn physical_identity_from_cap_metadata(metadata: &Metadata) -> Option<String> {
    use cap_std::fs::MetadataExt;

    Some(format!(
        "unix:{:016x}:{:016x}",
        metadata.dev(),
        metadata.ino()
    ))
}

#[cfg(not(unix))]
fn physical_identity_from_cap_metadata(_metadata: &Metadata) -> Option<String> {
    None
}

#[cfg(unix)]
fn physical_identity_from_std_metadata(metadata: &fs::Metadata) -> Option<String> {
    use std::os::unix::fs::MetadataExt;

    Some(format!(
        "unix:{:016x}:{:016x}",
        metadata.dev(),
        metadata.ino()
    ))
}

#[cfg(not(unix))]
fn physical_identity_from_std_metadata(_metadata: &fs::Metadata) -> Option<String> {
    None
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureExclusionKind {
    NestedFolderbase,
    HardLink,
    Fifo,
    Socket,
    BlockDevice,
    CharacterDevice,
    OtherSpecial,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CaptureExclusionReason {
    NestedFolderbaseBoundary,
    UnsupportedV1,
}

/// One typed item that cannot become a v1 Path Binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturePlanExclusion {
    path: String,
    kind: CaptureExclusionKind,
    reason: CaptureExclusionReason,
}

impl CapturePlanExclusion {
    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn kind(&self) -> CaptureExclusionKind {
        self.kind
    }

    pub fn reason(&self) -> CaptureExclusionReason {
        self.reason
    }
}

/// One path omitted by ordered Folderbase ignore policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureIgnoredPath {
    path: String,
}

impl CaptureIgnoredPath {
    pub fn path(&self) -> &str {
        &self.path
    }
}

/// A device-local pointer observed while planning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureLocalHead {
    version_id: String,
    version_sha256: String,
    authority: LocalHeadAuthority,
    encoded_sha256: String,
    observed: CaptureMetadataFingerprint,
}

/// The closed meaning of one Local Head authority digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum LocalHeadAuthority {
    #[serde(rename = "capture_transaction_v1")]
    CaptureTransactionV1 { sha256: String },
    #[serde(rename = "version_derived_v1")]
    VersionDerivedV1 { sha256: String },
}

impl LocalHeadAuthority {
    pub fn sha256(&self) -> &str {
        match self {
            Self::CaptureTransactionV1 { sha256 } | Self::VersionDerivedV1 { sha256 } => sha256,
        }
    }
}

pub(crate) fn version_derived_local_head_sha256(
    folderbase_id: &str,
    root_instance_sha256: &str,
    version_id: &str,
    version_sha256: &str,
) -> Result<String, FolderbaseCaptureError> {
    #[derive(Serialize)]
    struct VersionDerivedLocalHeadAuthority<'a> {
        format: &'static str,
        folderbase_id: &'a str,
        root_instance_sha256: &'a str,
        version_id: &'a str,
        version_sha256: &'a str,
    }

    let authority = serde_json::to_vec(&VersionDerivedLocalHeadAuthority {
        format: "folderbase-local-head-authority-v1",
        folderbase_id,
        root_instance_sha256,
        version_id,
        version_sha256,
    })
    .map_err(|source| {
        FolderbaseCaptureError::InvalidLocalHead(format!(
            "Local Head authority encoding failed: {source}"
        ))
    })?;
    Ok(format!("{:x}", Sha256::digest(authority)))
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum LocalHeadWire {
    V2(LocalHeadWireV2),
    V1(LocalHeadWireV1),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalHeadWireV2 {
    format: String,
    folderbase_id: String,
    root_instance_sha256: String,
    version_id: String,
    version_sha256: String,
    authority: LocalHeadAuthority,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalHeadWireV1 {
    format: String,
    folderbase_id: String,
    root_instance_sha256: String,
    version_id: String,
    version_sha256: String,
    transaction_sha256: String,
}

impl CaptureLocalHead {
    pub fn version_id(&self) -> &str {
        &self.version_id
    }

    pub fn version_sha256(&self) -> &str {
        &self.version_sha256
    }

    pub fn authority(&self) -> &LocalHeadAuthority {
        &self.authority
    }

    pub(crate) fn encoded_sha256(&self) -> &str {
        &self.encoded_sha256
    }

    pub(crate) fn observed(&self) -> &CaptureMetadataFingerprint {
        &self.observed
    }
}

/// An opaque, read-only metadata inventory bound to one physical root.
#[derive(Debug)]
pub struct CapturePlan {
    root_attestation: FolderbaseRootAttestation,
    root_manifest_bytes: u64,
    root_manifest_observed: CaptureMetadataFingerprint,
    folderbase_version_protocol: &'static str,
    current_local_head: Option<CaptureLocalHead>,
    ignore_policy_sha256: String,
    entries: Vec<CapturePlanEntry>,
    exclusions: Vec<CapturePlanExclusion>,
    ignored_paths: Vec<CaptureIgnoredPath>,
}

impl CapturePlan {
    pub fn root(&self) -> &Path {
        &self.root_attestation.root
    }

    pub fn folderbase_id(&self) -> &str {
        &self.root_attestation.folderbase_id
    }

    pub fn root_instance_sha256(&self) -> &str {
        &self.root_attestation.root_instance_sha256
    }

    pub fn root_manifest_sha256(&self) -> &str {
        &self.root_attestation.manifest_sha256
    }

    pub fn root_manifest_bytes(&self) -> u64 {
        self.root_manifest_bytes
    }

    pub(crate) fn root_manifest_observed(&self) -> &CaptureMetadataFingerprint {
        &self.root_manifest_observed
    }

    pub(crate) fn folderbase_version_protocol(&self) -> &'static str {
        self.folderbase_version_protocol
    }

    pub fn current_local_head(&self) -> Option<&CaptureLocalHead> {
        self.current_local_head.as_ref()
    }

    pub fn ignore_policy_sha256(&self) -> &str {
        &self.ignore_policy_sha256
    }

    pub fn entries(&self) -> &[CapturePlanEntry] {
        &self.entries
    }

    pub fn exclusions(&self) -> &[CapturePlanExclusion] {
        &self.exclusions
    }

    pub fn ignored_paths(&self) -> &[CaptureIgnoredPath] {
        &self.ignored_paths
    }
}

/// Failures that prevent a trustworthy metadata-only capture plan.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum FolderbaseCaptureError {
    #[error(transparent)]
    RootAttestation(#[from] RootAttestationError),

    #[error("required capture marker is missing or not a regular file: {0}")]
    RequiredMarker(PathBuf),

    #[error("capture inventory contains an unsafe portable path: {0}")]
    UnsafePortablePath(PathBuf),

    #[error("portable capture paths collide: {existing} and {path}")]
    PortablePathCollision { existing: String, path: String },

    #[error("capture inventory contains an unsafe symlink target at: {0}")]
    UnsafeSymlinkTarget(PathBuf),

    #[error("Folderbase ignore policy exceeds {maximum_bytes} bytes")]
    IgnorePolicyTooLarge { maximum_bytes: u64 },

    #[error("Folderbase ignore policy is not valid UTF-8")]
    IgnorePolicyNotUtf8,

    #[error("Folderbase ignore policy is invalid: {0}")]
    InvalidIgnorePolicy(String),

    #[error("Local Head exceeds {maximum_bytes} bytes")]
    LocalHeadTooLarge { maximum_bytes: u64 },

    #[error("Local Head is not a safe regular JSON file")]
    UnsafeLocalHead,

    #[error("Local Head is invalid: {0}")]
    InvalidLocalHead(String),

    #[error("capture planning state changed while it was being observed")]
    PlanningStateChanged,

    #[error("capture state changed after planning at: {0}")]
    CaptureStateChanged(PathBuf),

    #[error("capture plan belongs to a different Folderbase Version Store")]
    PlanStoreMismatch,

    #[error("Local Head changed after capture planning")]
    LocalHeadChanged,

    #[error("the prior Local Head cannot be verified: {0}")]
    InvalidPriorLocalHead(String),

    #[error("a prior live Path Binding became hidden by capture policy or an exclusion: {0}")]
    PriorBindingHidden(PathBuf),

    #[error("durable capture transaction is invalid: {0}")]
    InvalidCaptureTransaction(String),

    #[error("no Local Head exists to restore from")]
    MissingLocalHead,

    #[error("the current Local Head has no Tombstone at: {0}")]
    TombstoneNotFound(PathBuf),

    #[error("the current Tombstone kind is not supported by v1 restore at: {0}")]
    UnsupportedTombstoneKind(PathBuf),

    #[error("Tombstone restore ancestry is invalid: {0}")]
    InvalidRestoreAncestry(String),

    #[error("durable Tombstone restore transaction is invalid: {0}")]
    InvalidRestoreTransaction(String),

    #[error(
        "Tombstone restore authority maintenance is required at the bounded limit of {maximum}"
    )]
    RestoreAuthorityMaintenanceRequired { maximum: usize },

    #[error("Tombstone restore namespace repair is required before retrying at: {0}")]
    RestoreNamespaceRepairRequired(PathBuf),

    #[error("Tombstone restore refuses to overwrite the occupied path: {0}")]
    RestoreTargetOccupied(PathBuf),

    #[error("another Folderbase transaction is active: {0}")]
    ConflictingTransaction(&'static str),

    #[error(transparent)]
    LocalStore(#[from] FolderbaseError),

    #[error(transparent)]
    FolderbaseVersion(#[from] FolderbaseVersionError),

    #[error("capture inventory exceeded the {limit} limit of {maximum} at {path}")]
    InventoryLimitExceeded {
        limit: CapturePlanLimitKind,
        maximum: u64,
        path: PathBuf,
    },

    #[error("filesystem I/O failed while planning capture at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

/// Read-only handle for planning Folderbase Version capture.
#[derive(Debug)]
pub struct FolderbaseVersionStore {
    pub(crate) root_attestation: FolderbaseRootAttestation,
    pub(crate) root_instance_authority: RootInstanceAuthority,
    pub(crate) protocol_profile: ManifestProtocolProfile,
    root_capability: Dir,
    root_physical_identity: PhysicalIdentity,
}

impl FolderbaseVersionStore {
    /// Open one exact, existing Folderbase Root without writing any state.
    pub fn open(root: impl AsRef<Path>) -> Result<Self, FolderbaseCaptureError> {
        let requested_root = root.as_ref();
        let (requested_attestation, _, requested_profile) =
            attest_folderbase_root_with_profile(requested_root)?;
        let canonical_root =
            requested_root
                .canonicalize()
                .map_err(|source| FolderbaseCaptureError::Io {
                    path: requested_root.to_path_buf(),
                    source,
                })?;
        let (root_attestation, root_instance_authority, protocol_profile) =
            attest_folderbase_root_with_profile(&canonical_root)?;
        if requested_attestation.folderbase_id != root_attestation.folderbase_id
            || requested_attestation.protocol_version != root_attestation.protocol_version
            || requested_attestation.manifest_sha256 != root_attestation.manifest_sha256
            || requested_attestation.root_instance_sha256 != root_attestation.root_instance_sha256
            || requested_profile != protocol_profile
        {
            return Err(RootAttestationError::RootChangedDuringAttestation.into());
        }
        let root_capability = open_planning_root(&canonical_root)?;
        verify_root_capability(&root_capability, &canonical_root)?;
        let legacy_root_files = protocol_profile.requires_legacy_root_files();
        if legacy_root_files {
            require_regular_marker(
                &root_capability,
                &canonical_root,
                Path::new(".folderbaseignore"),
            )?;
        }
        read_local_head(
            &root_attestation,
            &root_instance_authority,
            &root_capability,
        )?;
        verify_root_capability(&root_capability, &canonical_root)?;
        let root_physical_identity = directory_identity(&root_capability, &canonical_root)?;
        Ok(Self {
            root_attestation,
            root_instance_authority,
            protocol_profile,
            root_capability,
            root_physical_identity,
        })
    }

    pub(crate) fn root_physical_identity(&self) -> &PhysicalIdentity {
        &self.root_physical_identity
    }

    /// Plan a bounded metadata inventory without reading ordinary file bytes.
    pub fn plan_capture(&self) -> Result<CapturePlan, FolderbaseCaptureError> {
        self.plan_capture_with_after_protocol_observation(|| ())
    }

    fn plan_capture_with_after_protocol_observation<G>(
        &self,
        after_protocol_observation: impl FnOnce() -> G,
    ) -> Result<CapturePlan, FolderbaseCaptureError> {
        let (current, _, current_profile) =
            attest_folderbase_root_with_profile(&self.root_attestation.root)?;
        if current.root_instance_sha256 != self.root_attestation.root_instance_sha256 {
            return Err(RootAttestationError::RootChangedDuringAttestation.into());
        }
        if current_profile != self.protocol_profile {
            return Err(RootAttestationError::RootChangedDuringAttestation.into());
        }
        let root_capability =
            self.root_capability
                .try_clone()
                .map_err(|source| FolderbaseCaptureError::Io {
                    path: current.root.clone(),
                    source,
                })?;
        verify_root_capability(&root_capability, &current.root)?;
        let legacy_root_files = current_profile.requires_legacy_root_files();
        if legacy_root_files {
            require_regular_marker(
                &root_capability,
                &current.root,
                Path::new(".folderbaseignore"),
            )?;
        }
        let root_manifest_observed = protocol_file_observation(
            &root_capability,
            &current.root,
            Path::new(".folderbase/manifest.json"),
        )?;
        let root_manifest_bytes = root_manifest_observed.bytes;
        let ignore = read_ignore_policy(&root_capability, &current.root, &current_profile)?;
        let current_local_head =
            read_local_head(&current, &self.root_instance_authority, &root_capability)?;
        let protocol_observation_guard = after_protocol_observation();
        let restore_authorities = read_restore_authorities(
            &current,
            &self.root_instance_authority,
            MAX_RESTORE_AUTHORITIES,
        )?;
        drop(protocol_observation_guard);

        let mut planner = CapturePlanner::new(
            &current.root,
            &ignore,
            restore_authorities,
            legacy_root_files,
        );
        planner.visit_directory(&root_capability, Path::new(""))?;
        verify_root_capability(&root_capability, &current.root)?;

        let mut entries = planner.entries;
        let mut exclusions = planner.exclusions;
        let mut ignored_paths = planner.ignored_paths;
        entries.sort_by(|left, right| left.path.as_bytes().cmp(right.path.as_bytes()));
        exclusions.sort_by(|left, right| left.path.as_bytes().cmp(right.path.as_bytes()));
        ignored_paths.sort_by(|left, right| left.path.as_bytes().cmp(right.path.as_bytes()));
        let nested_boundaries = exclusions
            .iter()
            .filter(|exclusion| exclusion.kind == CaptureExclusionKind::NestedFolderbase)
            .map(|exclusion| exclusion.path.clone())
            .collect::<Vec<_>>();
        validate_capture_symlink_targets(
            entries.iter().filter_map(|entry| {
                entry
                    .symlink_target
                    .as_deref()
                    .map(|target| (entry.path.as_str(), target))
            }),
            &nested_boundaries,
        )
        .map_err(|path| FolderbaseCaptureError::UnsafeSymlinkTarget(PathBuf::from(path)))?;
        let final_ignore = read_ignore_policy(&root_capability, &current.root, &current_profile)?;
        let final_local_head =
            read_local_head(&current, &self.root_instance_authority, &root_capability)?;
        let final_manifest_observed = protocol_file_observation(
            &root_capability,
            &current.root,
            Path::new(".folderbase/manifest.json"),
        )?;
        verify_root_capability(&root_capability, &current.root)?;
        let (final_attestation, _, final_profile) =
            attest_folderbase_root_with_profile(&current.root)?;
        if final_local_head != current_local_head
            || final_ignore.sha256 != ignore.sha256
            || final_attestation != current
            || final_profile != current_profile
            || final_manifest_observed != root_manifest_observed
        {
            return Err(FolderbaseCaptureError::PlanningStateChanged);
        }

        Ok(CapturePlan {
            root_attestation: current,
            root_manifest_bytes,
            root_manifest_observed,
            folderbase_version_protocol: current_profile.folderbase_version_protocol(),
            current_local_head,
            ignore_policy_sha256: ignore.sha256,
            entries,
            exclusions,
            ignored_paths,
        })
    }
}

struct CapturePlanner<'a> {
    root: &'a Path,
    ignore: &'a IgnorePolicy,
    restore_authorities: RestoreAuthorityRegistry,
    legacy_root_files: bool,
    entries: Vec<CapturePlanEntry>,
    exclusions: Vec<CapturePlanExclusion>,
    ignored_paths: Vec<CaptureIgnoredPath>,
    path_index: CapturePathIndex,
}

struct ObservedRestoreAuthority {
    record: RestoreAuthorityRecord,
    encoded: Vec<u8>,
}

struct RestoreAuthorityRegistry {
    state: FolderbaseState,
    records: Vec<ObservedRestoreAuthority>,
}

impl RestoreAuthorityRegistry {
    fn validated_link_commitment(
        &self,
        workspace_identity: &str,
        link_count: usize,
        workspace_path: &str,
        display_path: &Path,
    ) -> Result<CaptureLinkCommitment, FolderbaseCaptureError> {
        validated_link_commitment(
            &self.state,
            &self.records,
            workspace_identity,
            link_count,
            workspace_path,
            display_path,
        )
    }
}

fn validated_link_commitment(
    state: &FolderbaseState,
    records: &[ObservedRestoreAuthority],
    workspace_identity: &str,
    link_count: usize,
    workspace_path: &str,
    display_path: &Path,
) -> Result<CaptureLinkCommitment, FolderbaseCaptureError> {
    let mut validated_paths = BTreeSet::new();
    for observed in records.iter().filter(|observed| {
        observed.record.workspace_path == workspace_path
            && observed.record.published_identity_sha256 == workspace_identity
    }) {
        let record_path = restore_authority_record_path(&observed.record.transaction_id);
        if state
            .read_bounded(&record_path, MAX_RESTORE_AUTHORITY_BYTES)?
            .as_deref()
            != Some(observed.encoded.as_slice())
        {
            return Err(FolderbaseCaptureError::InvalidRestoreTransaction(
                "restore authority changed during capture planning".to_owned(),
            ));
        }
        let observed_identity = state.planned_workspace_restore_identity_sha256(
            Path::new(&observed.record.private_stage_path),
            Path::new(workspace_path),
        )?;
        if observed_identity != workspace_identity {
            return Err(FolderbaseCaptureError::InvalidRestoreTransaction(
                "restore authority no longer names the current workspace file".to_owned(),
            ));
        }
        if !validated_paths.insert(observed.record.private_stage_path.as_str()) {
            return Err(FolderbaseCaptureError::InvalidRestoreTransaction(
                "restore authorities name one private link more than once".to_owned(),
            ));
        }
    }
    state.verify_still_attached()?;
    let mut authorities = records
        .iter()
        .filter(|observed| {
            observed.record.workspace_path == workspace_path
                && observed.record.published_identity_sha256 == workspace_identity
        })
        .map(|observed| {
            let receipt_path = restore_authority_record_path(&observed.record.transaction_id);
            CaptureAuthorityLink {
                receipt_path: receipt_path
                    .to_str()
                    .expect("restore authority paths are UTF-8")
                    .to_owned(),
                receipt_sha256: format!("{:x}", Sha256::digest(&observed.encoded)),
                private_stage_path: observed.record.private_stage_path.clone(),
                published_identity_sha256: observed.record.published_identity_sha256.clone(),
            }
        })
        .collect::<Vec<_>>();
    authorities.sort_by(|left, right| left.receipt_path.cmp(&right.receipt_path));
    let authority_set_sha256 =
        (!authorities.is_empty()).then(|| capture_authority_set_sha256(&authorities));
    Ok(CaptureLinkCommitment {
        expected_live_link_count: u64::try_from(link_count)
            .map_err(|_| FolderbaseCaptureError::CaptureStateChanged(display_path.to_path_buf()))?,
        authority_set_sha256,
        authorities,
    })
}

fn capture_authority_set_sha256(authorities: &[CaptureAuthorityLink]) -> String {
    #[derive(Serialize)]
    struct AuthoritySet<'a> {
        format: &'static str,
        authorities: &'a [CaptureAuthorityLink],
    }

    let encoded = serde_json::to_vec(&AuthoritySet {
        format: "folderbase-capture-authority-set-v1",
        authorities,
    })
    .expect("capture authority commitments are serializable");
    format!("{:x}", Sha256::digest(encoded))
}

pub(crate) fn restore_authority_count(
    root_attestation: &FolderbaseRootAttestation,
    root_instance_authority: &RootInstanceAuthority,
    maximum: usize,
) -> Result<usize, FolderbaseCaptureError> {
    Ok(
        read_restore_authorities(root_attestation, root_instance_authority, maximum)?
            .records
            .len(),
    )
}

fn read_restore_authorities(
    root_attestation: &FolderbaseRootAttestation,
    root_instance_authority: &RootInstanceAuthority,
    maximum: usize,
) -> Result<RestoreAuthorityRegistry, FolderbaseCaptureError> {
    let state = FolderbaseState::open_existing_read_only(&root_attestation.root)?;
    let records =
        read_restore_authority_records(root_attestation, root_instance_authority, &state, maximum)?;
    Ok(RestoreAuthorityRegistry { state, records })
}

fn read_restore_authority_records(
    root_attestation: &FolderbaseRootAttestation,
    root_instance_authority: &RootInstanceAuthority,
    state: &FolderbaseState,
    maximum: usize,
) -> Result<Vec<ObservedRestoreAuthority>, FolderbaseCaptureError> {
    let names = match state.private_directory_names(
        Path::new(RESTORE_AUTHORITIES_DIRECTORY),
        MAX_RESTORE_AUTHORITIES.saturating_add(1024),
    ) {
        Ok(names) => names,
        Err(FolderbaseError::Io { source, .. }) if source.kind() == io::ErrorKind::NotFound => {
            Vec::new()
        }
        Err(error) => return Err(error.into()),
    };
    let mut records = Vec::new();
    for name in names {
        let Some(transaction_id) = name.to_str() else {
            continue;
        };
        let Some(uuid) = transaction_id.strip_prefix("fbrestore_") else {
            continue;
        };
        if uuid::Uuid::parse_str(uuid).is_err() {
            continue;
        }
        let relative = restore_authority_record_path(transaction_id);
        let Some(encoded) = state.read_bounded(&relative, MAX_RESTORE_AUTHORITY_BYTES)? else {
            continue;
        };
        let record: RestoreAuthorityRecord =
            serde_json::from_slice(&encoded).map_err(|source| {
                FolderbaseCaptureError::InvalidRestoreTransaction(format!(
                    "restore authority is invalid JSON: {source}"
                ))
            })?;
        validate_restore_authority(
            root_attestation,
            root_instance_authority,
            transaction_id,
            &record,
        )?;
        records.push(ObservedRestoreAuthority { record, encoded });
        if records.len() > maximum {
            return Err(FolderbaseCaptureError::RestoreAuthorityMaintenanceRequired { maximum });
        }
    }
    state.verify_still_attached()?;
    Ok(records)
}

pub(crate) fn verify_capture_link_commitment(
    root_attestation: &FolderbaseRootAttestation,
    root_instance_authority: &RootInstanceAuthority,
    state: &FolderbaseState,
    entry: &CapturePlanEntry,
    workspace_file: &fs::File,
) -> Result<(), FolderbaseCaptureError> {
    if entry.kind() != CaptureEntryKind::RegularFile {
        return Ok(());
    }
    let display_path = root_attestation.root.join(entry.path());
    let link_count = usize::try_from(stable_file_link_count(workspace_file).map_err(|source| {
        FolderbaseCaptureError::Io {
            path: display_path.clone(),
            source,
        }
    })?)
    .map_err(|_| FolderbaseCaptureError::CaptureStateChanged(PathBuf::from(entry.path())))?;
    let records = read_restore_authority_records(
        root_attestation,
        root_instance_authority,
        state,
        MAX_RESTORE_AUTHORITIES,
    )?;
    let workspace_identity = stable_file_identity_sha256(workspace_file).map_err(|source| {
        FolderbaseCaptureError::Io {
            path: display_path.clone(),
            source,
        }
    })?;
    let actual = validated_link_commitment(
        state,
        &records,
        &workspace_identity,
        link_count,
        entry.path(),
        &display_path,
    )?;
    let exact_expected_link_count = entry
        .link_commitment()
        .authorities
        .len()
        .checked_add(1)
        .and_then(|count| u64::try_from(count).ok());
    let exact_actual_link_count = actual
        .authorities
        .len()
        .checked_add(1)
        .and_then(|count| u64::try_from(count).ok());
    let expected_digest = (!entry.link_commitment().authorities.is_empty())
        .then(|| capture_authority_set_sha256(&entry.link_commitment().authorities));
    if exact_expected_link_count != Some(entry.link_commitment().expected_live_link_count)
        || entry.link_commitment().authority_set_sha256 != expected_digest
        || exact_actual_link_count != Some(actual.expected_live_link_count)
        || &actual != entry.link_commitment()
    {
        return Err(FolderbaseCaptureError::CaptureStateChanged(PathBuf::from(
            entry.path(),
        )));
    }
    Ok(())
}

fn validate_restore_authority(
    root_attestation: &FolderbaseRootAttestation,
    root_instance_authority: &RootInstanceAuthority,
    transaction_id: &str,
    record: &RestoreAuthorityRecord,
) -> Result<(), FolderbaseCaptureError> {
    if record.format != RESTORE_AUTHORITY_FORMAT_V1
        || record.folderbase_id != root_attestation.folderbase_id
        || root_instance_authority
            .admit(&record.root_instance_sha256)
            .is_none()
        || record.transaction_id != transaction_id
        || record.private_stage_path
            != restore_stage_path(transaction_id)
                .to_str()
                .expect("restore authority paths are UTF-8")
        || validate_capture_path(&record.workspace_path).is_err()
        || validate_capture_sha256(&record.published_identity_sha256).is_err()
    {
        return Err(FolderbaseCaptureError::InvalidRestoreTransaction(
            "restore authority does not match its Folderbase, path, identity, or slot".to_owned(),
        ));
    }
    Ok(())
}

struct CaptureDirectoryFrame {
    directory: Dir,
    entries: ReadDir,
    relative_parent: PathBuf,
    completion: Option<CaptureChildVerification>,
}

struct CaptureChildVerification {
    name: OsString,
    identity: PhysicalIdentity,
    display_path: PathBuf,
}

struct PendingCaptureDirectory {
    directory: Dir,
    relative_parent: PathBuf,
    verification: CaptureChildVerification,
}

impl<'a> CapturePlanner<'a> {
    fn new(
        root: &'a Path,
        ignore: &'a IgnorePolicy,
        restore_authorities: RestoreAuthorityRegistry,
        legacy_root_files: bool,
    ) -> Self {
        Self {
            root,
            ignore,
            restore_authorities,
            legacy_root_files,
            entries: Vec::new(),
            exclusions: Vec::new(),
            ignored_paths: Vec::new(),
            path_index: CapturePathIndex::default(),
        }
    }

    fn visit_directory(
        &mut self,
        directory: &Dir,
        relative_parent: &Path,
    ) -> Result<(), FolderbaseCaptureError> {
        let root_directory =
            directory
                .try_clone()
                .map_err(|source| FolderbaseCaptureError::Io {
                    path: self.root.join(relative_parent),
                    source,
                })?;
        let mut stack = vec![capture_directory_frame(
            root_directory,
            relative_parent.to_path_buf(),
            self.root,
            None,
        )?];

        while !stack.is_empty() {
            let next = stack
                .last_mut()
                .expect("non-empty traversal stack")
                .entries
                .next();
            let Some(entry) = next else {
                let completed = stack.pop().expect("non-empty traversal stack");
                if let Some(verification) = completed.completion {
                    let parent = stack
                        .last()
                        .ok_or(FolderbaseCaptureError::PlanningStateChanged)?;
                    verify_child_identity(
                        &parent.directory,
                        &verification.name,
                        &verification.identity,
                        &verification.display_path,
                    )?;
                }
                continue;
            };
            let entry = entry.map_err(|source| {
                let relative_parent = &stack
                    .last()
                    .expect("non-empty traversal stack")
                    .relative_parent;
                FolderbaseCaptureError::Io {
                    path: self.root.join(relative_parent),
                    source,
                }
            })?;
            let pending = {
                let current = stack.last().expect("non-empty traversal stack");
                self.visit_entry(&current.directory, &current.relative_parent, entry)?
            };
            if let Some(pending) = pending {
                stack.push(capture_directory_frame(
                    pending.directory,
                    pending.relative_parent,
                    self.root,
                    Some(pending.verification),
                )?);
            }
        }
        Ok(())
    }

    fn visit_entry(
        &mut self,
        directory: &Dir,
        relative_parent: &Path,
        entry: DirEntry,
    ) -> Result<Option<PendingCaptureDirectory>, FolderbaseCaptureError> {
        let name = entry.file_name();
        let relative = relative_parent.join(&name);
        let display_path = self.root.join(&relative);
        let metadata =
            directory
                .symlink_metadata(&name)
                .map_err(|source| FolderbaseCaptureError::Io {
                    path: display_path.clone(),
                    source,
                })?;

        if name == OsStr::new(".folderbase") {
            return Ok(None);
        }
        if is_folderbase_state_component(&name) {
            return Err(FolderbaseCaptureError::UnsafePortablePath(relative));
        }

        let required_marker = relative == Path::new(".folderbaseignore")
            || (self.legacy_root_files && relative == Path::new("FOLDERBASE.md"));
        let force_included = relative == Path::new(".folderbaseignore")
            || (self.legacy_root_files && relative == Path::new("FOLDERBASE.md"));
        if !force_included
            && matches!(
                self.ignore
                    .matcher
                    .matched(self.root.join(&relative), metadata.is_dir()),
                Match::Ignore(_)
            )
        {
            self.ensure_capacity(&relative)?;
            self.ignored_paths.push(CaptureIgnoredPath {
                path: portable_relative(&relative)?,
            });
            return Ok(None);
        }

        self.ensure_capacity(&relative)?;
        let path = portable_relative(&relative)?;
        validate_capture_path(&path)
            .map_err(|_| FolderbaseCaptureError::UnsafePortablePath(relative.clone()))?;
        self.path_index.insert(&path)?;

        if metadata.is_dir() && !metadata.file_type().is_symlink() {
            let (child, identity) = open_stable_child(directory, &name, &display_path)?;
            match classify_nested_folderbase_boundary(&child, &display_path)? {
                NestedFolderbaseBoundaryKind::ExactBoundary => {
                    verify_child_identity(directory, &name, &identity, &display_path)?;
                    self.exclusions.push(CapturePlanExclusion {
                        path,
                        kind: CaptureExclusionKind::NestedFolderbase,
                        reason: CaptureExclusionReason::NestedFolderbaseBoundary,
                    });
                    return Ok(None);
                }
                NestedFolderbaseBoundaryKind::UnsafeAliasShape => {
                    return Err(FolderbaseCaptureError::UnsafePortablePath(display_path));
                }
                NestedFolderbaseBoundaryKind::None => {}
            }
            self.entries.push(CapturePlanEntry {
                path,
                kind: CaptureEntryKind::Directory,
                bytes: None,
                executable: None,
                symlink_target: None,
                observed: capture_entry_fingerprint(
                    directory,
                    &name,
                    CaptureEntryKind::Directory,
                    &metadata,
                    &display_path,
                )?,
                link_commitment: CaptureLinkCommitment::default(),
            });
            return Ok(Some(PendingCaptureDirectory {
                directory: child,
                relative_parent: relative,
                verification: CaptureChildVerification {
                    name,
                    identity,
                    display_path,
                },
            }));
        }

        let mut link_commitment = CaptureLinkCommitment::default();
        let mut regular_observed = None;
        let mut regular_bytes = None;
        let mut regular_executable = None;
        if metadata.is_file() && !metadata.file_type().is_symlink() {
            let (observed, workspace_identity, link_count) =
                planned_regular_link_observation(directory, &name, &metadata, &display_path)?;
            regular_bytes = Some(observed.bytes);
            regular_executable = Some(observed.executable);
            regular_observed = Some(observed);
            link_commitment = self.restore_authorities.validated_link_commitment(
                &workspace_identity,
                link_count,
                &path,
                &display_path,
            )?;
            if link_count != link_commitment.authorities.len().saturating_add(1) {
                if required_marker {
                    return Err(FolderbaseCaptureError::RequiredMarker(display_path));
                }
                self.exclusions.push(CapturePlanExclusion {
                    path,
                    kind: CaptureExclusionKind::HardLink,
                    reason: CaptureExclusionReason::UnsupportedV1,
                });
                return Ok(None);
            }
        }

        if let Some(kind) = unsupported_entry_kind(directory, &name, &display_path, &metadata)? {
            if required_marker {
                return Err(FolderbaseCaptureError::RequiredMarker(display_path));
            }
            self.exclusions.push(CapturePlanExclusion {
                path,
                kind,
                reason: CaptureExclusionReason::UnsupportedV1,
            });
            return Ok(None);
        }

        let (kind, bytes, executable, symlink_target) = if metadata.file_type().is_symlink() {
            let target = read_stable_symlink(directory, &name, &relative, &display_path)?;
            (CaptureEntryKind::Symlink, None, None, Some(target))
        } else if metadata.is_file() {
            let bytes = regular_bytes.ok_or(FolderbaseCaptureError::PlanningStateChanged)?;
            if bytes > MAX_OBJECT_BYTES {
                return Err(FolderbaseCaptureError::InventoryLimitExceeded {
                    limit: CapturePlanLimitKind::ObjectBytes,
                    maximum: MAX_OBJECT_BYTES,
                    path: relative,
                });
            }
            (
                CaptureEntryKind::RegularFile,
                Some(bytes),
                regular_executable,
                None,
            )
        } else {
            return Err(FolderbaseCaptureError::PlanningStateChanged);
        };
        let observed = match kind {
            CaptureEntryKind::RegularFile => {
                regular_observed.ok_or(FolderbaseCaptureError::PlanningStateChanged)?
            }
            CaptureEntryKind::Directory | CaptureEntryKind::Symlink => {
                capture_entry_fingerprint(directory, &name, kind, &metadata, &display_path)?
            }
        };
        self.entries.push(CapturePlanEntry {
            path,
            kind,
            bytes,
            executable,
            symlink_target,
            observed,
            link_commitment,
        });
        Ok(None)
    }

    fn ensure_capacity(&self, path: &Path) -> Result<(), FolderbaseCaptureError> {
        ensure_record_capacity(
            self.entries.len() + self.exclusions.len() + self.ignored_paths.len(),
            path,
        )
    }
}

fn capture_directory_frame(
    directory: Dir,
    relative_parent: PathBuf,
    root: &Path,
    completion: Option<CaptureChildVerification>,
) -> Result<CaptureDirectoryFrame, FolderbaseCaptureError> {
    let entries = directory
        .read_dir(".")
        .map_err(|source| FolderbaseCaptureError::Io {
            path: root.join(&relative_parent),
            source,
        })?;
    Ok(CaptureDirectoryFrame {
        directory,
        entries,
        relative_parent,
        completion,
    })
}

struct IgnorePolicy {
    matcher: ignore::gitignore::Gitignore,
    sha256: String,
}

#[derive(Default)]
struct CapturePathIndex {
    exact: BTreeMap<String, String>,
    nfc: BTreeMap<String, String>,
    folded: BTreeMap<String, String>,
}

impl CapturePathIndex {
    fn insert(&mut self, path: &str) -> Result<(), FolderbaseCaptureError> {
        let nfc = path.nfc().collect::<String>();
        let folded = nfc
            .case_fold()
            .collect::<String>()
            .nfc()
            .collect::<String>();
        if let Some(existing) = self.exact.get(path) {
            return Err(FolderbaseCaptureError::PortablePathCollision {
                existing: existing.clone(),
                path: path.to_owned(),
            });
        }
        if let Some(existing) = [self.nfc.get(&nfc), self.folded.get(&folded)]
            .into_iter()
            .flatten()
            .next()
        {
            return Err(FolderbaseCaptureError::PortablePathCollision {
                existing: existing.clone(),
                path: path.to_owned(),
            });
        }
        self.exact.insert(path.to_owned(), path.to_owned());
        self.nfc.insert(nfc, path.to_owned());
        self.folded.insert(folded, path.to_owned());
        Ok(())
    }
}

fn portable_relative(path: &Path) -> Result<String, FolderbaseCaptureError> {
    let mut parts = Vec::new();
    for component in path.components() {
        let Component::Normal(part) = component else {
            return Err(FolderbaseCaptureError::UnsafePortablePath(
                path.to_path_buf(),
            ));
        };
        parts.push(
            part.to_str()
                .ok_or_else(|| FolderbaseCaptureError::UnsafePortablePath(path.to_path_buf()))?
                .to_owned(),
        );
    }
    if parts.is_empty() {
        return Err(FolderbaseCaptureError::UnsafePortablePath(
            path.to_path_buf(),
        ));
    }
    Ok(parts.join("/"))
}

#[cfg(unix)]
fn is_executable(metadata: &Metadata) -> bool {
    use cap_std::fs::PermissionsExt;

    metadata.permissions().mode() & 0o111 != 0
}

#[cfg(windows)]
fn is_executable(_metadata: &Metadata) -> bool {
    false
}

#[cfg(unix)]
pub(crate) fn capture_entry_fingerprint(
    _directory: &Dir,
    _name: &OsStr,
    _kind: CaptureEntryKind,
    metadata: &Metadata,
    _display_path: &Path,
) -> Result<CaptureMetadataFingerprint, FolderbaseCaptureError> {
    Ok(CaptureMetadataFingerprint::from_cap_metadata(metadata))
}

#[cfg(windows)]
pub(crate) fn capture_entry_fingerprint(
    directory: &Dir,
    name: &OsStr,
    kind: CaptureEntryKind,
    metadata: &Metadata,
    display_path: &Path,
) -> Result<CaptureMetadataFingerprint, FolderbaseCaptureError> {
    let file = match kind {
        CaptureEntryKind::Directory => directory
            .open_dir_nofollow(name)
            .map_err(|source| FolderbaseCaptureError::Io {
                path: display_path.to_path_buf(),
                source,
            })?
            .into_std_file(),
        CaptureEntryKind::RegularFile | CaptureEntryKind::Symlink => {
            use cap_std::fs::OpenOptionsExt;
            use windows_sys::Win32::Storage::FileSystem::{
                FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
            };

            let mut options = OpenOptions::new();
            options
                .read(true)
                .follow(FollowSymlinks::No)
                .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
            directory
                .open_with(name, &options)
                .map_err(|source| FolderbaseCaptureError::Io {
                    path: display_path.to_path_buf(),
                    source,
                })?
                .into_std()
        }
    };
    let identity = windows_file_identity(&file).map_err(|source| FolderbaseCaptureError::Io {
        path: display_path.to_path_buf(),
        source,
    })?;
    Ok(CaptureMetadataFingerprint::from_cap_metadata(metadata)
        .with_physical_identity(Some(identity)))
}

#[cfg(unix)]
fn planned_regular_link_observation(
    _directory: &Dir,
    _name: &OsStr,
    metadata: &Metadata,
    _display_path: &Path,
) -> Result<(CaptureMetadataFingerprint, String, usize), FolderbaseCaptureError> {
    use cap_std::fs::MetadataExt;

    let link_count = usize::try_from(metadata.nlink())
        .map_err(|_| FolderbaseCaptureError::PlanningStateChanged)?;
    Ok((
        CaptureMetadataFingerprint::from_cap_metadata(metadata),
        stable_unix_file_identity_sha256(metadata.dev(), metadata.ino()),
        link_count,
    ))
}

#[cfg(windows)]
fn planned_regular_link_observation(
    directory: &Dir,
    name: &OsStr,
    metadata: &Metadata,
    display_path: &Path,
) -> Result<(CaptureMetadataFingerprint, String, usize), FolderbaseCaptureError> {
    use cap_std::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE,
        FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    let mut options = OpenOptions::new();
    options
        .access_mode(0)
        .follow(FollowSymlinks::No)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE);
    let file = directory
        .open_with(name, &options)
        .map_err(|source| FolderbaseCaptureError::Io {
            path: display_path.to_path_buf(),
            source,
        })?
        .into_std();
    let identity =
        stable_file_identity_sha256(&file).map_err(|source| FolderbaseCaptureError::Io {
            path: display_path.to_path_buf(),
            source,
        })?;
    let link_count = usize::try_from(stable_file_link_count(&file).map_err(|source| {
        FolderbaseCaptureError::Io {
            path: display_path.to_path_buf(),
            source,
        }
    })?)
    .map_err(|_| FolderbaseCaptureError::PlanningStateChanged)?;
    Ok((
        CaptureMetadataFingerprint::from_cap_metadata(metadata).with_physical_identity(Some(
            windows_file_identity(&file).map_err(|source| FolderbaseCaptureError::Io {
                path: display_path.to_path_buf(),
                source,
            })?,
        )),
        identity,
        link_count,
    ))
}

#[cfg(windows)]
fn windows_file_identity(file: &fs::File) -> io::Result<String> {
    use std::{mem::size_of, os::windows::io::AsRawHandle};
    use windows_sys::Win32::{
        Foundation::HANDLE,
        Storage::FileSystem::{FILE_ID_INFO, FileIdInfo, GetFileInformationByHandleEx},
    };

    let mut information = FILE_ID_INFO::default();
    if unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle() as HANDLE,
            FileIdInfo,
            (&raw mut information).cast(),
            size_of::<FILE_ID_INFO>() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let mut encoded = format!(
        "windows-file-id-128:{:016x}:",
        information.VolumeSerialNumber
    );
    for byte in information.FileId.Identifier {
        use fmt::Write as _;
        let _ = write!(encoded, "{byte:02x}");
    }
    Ok(encoded)
}

#[cfg(unix)]
fn unsupported_entry_kind(
    _directory: &Dir,
    _name: &OsStr,
    _display_path: &Path,
    metadata: &Metadata,
) -> Result<Option<CaptureExclusionKind>, FolderbaseCaptureError> {
    use cap_std::fs::FileTypeExt;

    let file_type = metadata.file_type();
    let kind = if file_type.is_fifo() {
        Some(CaptureExclusionKind::Fifo)
    } else if file_type.is_socket() {
        Some(CaptureExclusionKind::Socket)
    } else if file_type.is_block_device() {
        Some(CaptureExclusionKind::BlockDevice)
    } else if file_type.is_char_device() {
        Some(CaptureExclusionKind::CharacterDevice)
    } else if !metadata.is_file() && !metadata.is_dir() && !metadata.file_type().is_symlink() {
        Some(CaptureExclusionKind::OtherSpecial)
    } else {
        None
    };
    Ok(kind)
}

#[cfg(windows)]
fn unsupported_entry_kind(
    _directory: &Dir,
    _name: &OsStr,
    _display_path: &Path,
    _metadata: &Metadata,
) -> Result<Option<CaptureExclusionKind>, FolderbaseCaptureError> {
    Ok(None)
}

fn open_planning_root(root: &Path) -> Result<Dir, FolderbaseCaptureError> {
    let mut options = fs::OpenOptions::new();
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
    if !metadata.is_dir() || std_metadata_is_link_or_reparse(&metadata) {
        return Err(FolderbaseCaptureError::PlanningStateChanged);
    }
    Ok(Dir::from_std_file(file))
}

#[cfg(unix)]
fn std_metadata_is_link_or_reparse(metadata: &fs::Metadata) -> bool {
    metadata.file_type().is_symlink()
}

#[cfg(windows)]
fn std_metadata_is_link_or_reparse(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    metadata.file_type().is_symlink()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

fn directory_identity(
    directory: &Dir,
    display_path: &Path,
) -> Result<PhysicalIdentity, FolderbaseCaptureError> {
    let file = directory
        .try_clone()
        .map_err(|source| FolderbaseCaptureError::Io {
            path: display_path.to_path_buf(),
            source,
        })?
        .into_std_file();
    PhysicalIdentity::from_file(&file).map_err(|source| FolderbaseCaptureError::Io {
        path: display_path.to_path_buf(),
        source,
    })
}

fn verify_root_capability(expected: &Dir, root: &Path) -> Result<(), FolderbaseCaptureError> {
    let expected = directory_identity(expected, root)?;
    let reopened = open_planning_root(root)?;
    if directory_identity(&reopened, root)? != expected {
        return Err(FolderbaseCaptureError::PlanningStateChanged);
    }
    Ok(())
}

fn open_stable_child(
    parent: &Dir,
    name: &OsStr,
    display_path: &Path,
) -> Result<(Dir, PhysicalIdentity), FolderbaseCaptureError> {
    let child = parent
        .open_dir_nofollow(name)
        .map_err(|source| FolderbaseCaptureError::Io {
            path: display_path.to_path_buf(),
            source,
        })?;
    let identity = directory_identity(&child, display_path)?;
    verify_child_identity(parent, name, &identity, display_path)?;
    Ok((child, identity))
}

fn verify_child_identity(
    parent: &Dir,
    name: &OsStr,
    expected: &PhysicalIdentity,
    display_path: &Path,
) -> Result<(), FolderbaseCaptureError> {
    let reopened = parent
        .open_dir_nofollow(name)
        .map_err(|source| FolderbaseCaptureError::Io {
            path: display_path.to_path_buf(),
            source,
        })?;
    if &directory_identity(&reopened, display_path)? != expected {
        return Err(FolderbaseCaptureError::PlanningStateChanged);
    }
    Ok(())
}

fn read_stable_symlink(
    directory: &Dir,
    name: &OsStr,
    relative: &Path,
    display_path: &Path,
) -> Result<String, FolderbaseCaptureError> {
    let target = directory
        .read_link(name)
        .map_err(|source| FolderbaseCaptureError::Io {
            path: display_path.to_path_buf(),
            source,
        })?;
    let rechecked = directory
        .read_link(name)
        .map_err(|source| FolderbaseCaptureError::Io {
            path: display_path.to_path_buf(),
            source,
        })?;
    if rechecked != target {
        return Err(FolderbaseCaptureError::PlanningStateChanged);
    }
    target
        .to_str()
        .map(str::to_owned)
        .ok_or_else(|| FolderbaseCaptureError::UnsafeSymlinkTarget(relative.to_path_buf()))
}

fn ensure_record_capacity(current: usize, path: &Path) -> Result<(), FolderbaseCaptureError> {
    if current == MAX_CAPTURE_PLAN_RECORDS {
        return Err(FolderbaseCaptureError::InventoryLimitExceeded {
            limit: CapturePlanLimitKind::Entries,
            maximum: MAX_CAPTURE_PLAN_RECORDS as u64,
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

fn read_local_head(
    attestation: &FolderbaseRootAttestation,
    root_instance_authority: &RootInstanceAuthority,
    root: &Dir,
) -> Result<Option<CaptureLocalHead>, FolderbaseCaptureError> {
    let path = attestation.root.join(LOCAL_HEAD_PATH);
    let state = root
        .open_dir_nofollow(".folderbase")
        .map_err(|_| FolderbaseCaptureError::UnsafeLocalHead)?;
    let local_metadata = match state.symlink_metadata("local") {
        Ok(metadata) => metadata,
        Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(source) => return Err(FolderbaseCaptureError::Io { path, source }),
    };
    if local_metadata.file_type().is_symlink() || !local_metadata.is_dir() {
        return Err(FolderbaseCaptureError::UnsafeLocalHead);
    }
    let local = state
        .open_dir_nofollow("local")
        .map_err(|_| FolderbaseCaptureError::UnsafeLocalHead)?;
    let metadata = match local.symlink_metadata("head.json") {
        Ok(metadata) => metadata,
        Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(source) => return Err(FolderbaseCaptureError::Io { path, source }),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(FolderbaseCaptureError::UnsafeLocalHead);
    }
    if metadata.len() > MAX_LOCAL_HEAD_BYTES {
        return Err(FolderbaseCaptureError::LocalHeadTooLarge {
            maximum_bytes: MAX_LOCAL_HEAD_BYTES,
        });
    }
    let mut file = open_regular_nofollow(&local, Path::new("head.json"))
        .map_err(|_| FolderbaseCaptureError::UnsafeLocalHead)?;
    let observed = CaptureMetadataFingerprint::from_std_file(&file).map_err(|source| {
        FolderbaseCaptureError::Io {
            path: path.clone(),
            source,
        }
    })?;
    let mut encoded = Vec::new();
    file.by_ref()
        .take(MAX_LOCAL_HEAD_BYTES + 1)
        .read_to_end(&mut encoded)
        .map_err(|source| FolderbaseCaptureError::Io {
            path: path.clone(),
            source,
        })?;
    if encoded.len() as u64 > MAX_LOCAL_HEAD_BYTES {
        return Err(FolderbaseCaptureError::LocalHeadTooLarge {
            maximum_bytes: MAX_LOCAL_HEAD_BYTES,
        });
    }
    let final_observed = CaptureMetadataFingerprint::from_std_file(&file).map_err(|source| {
        FolderbaseCaptureError::Io {
            path: path.clone(),
            source,
        }
    })?;
    if final_observed != observed {
        return Err(FolderbaseCaptureError::PlanningStateChanged);
    }
    let encoded_sha256 = format!("{:x}", Sha256::digest(&encoded));
    let head: LocalHeadWire = serde_json::from_slice(&encoded)
        .map_err(|error| FolderbaseCaptureError::InvalidLocalHead(error.to_string()))?;
    let (folderbase_id, root_instance_sha256, version_id, version_sha256, authority) = match head {
        LocalHeadWire::V2(head) if head.format == "folderbase-local-head-v2" => (
            head.folderbase_id,
            head.root_instance_sha256,
            head.version_id,
            head.version_sha256,
            head.authority,
        ),
        LocalHeadWire::V1(head) if head.format == "folderbase-local-head-v1" => (
            head.folderbase_id,
            head.root_instance_sha256,
            head.version_id,
            head.version_sha256,
            LocalHeadAuthority::CaptureTransactionV1 {
                sha256: head.transaction_sha256,
            },
        ),
        _ => {
            return Err(FolderbaseCaptureError::InvalidLocalHead(
                "record has an unsupported Local Head format".to_owned(),
            ));
        }
    };
    if folderbase_id != attestation.folderbase_id
        || root_instance_authority
            .admit(&root_instance_sha256)
            .is_none()
    {
        return Err(FolderbaseCaptureError::InvalidLocalHead(
            "record does not bind the attested physical Folderbase Root".to_owned(),
        ));
    }
    validate_capture_sha256(&root_instance_sha256)
        .map_err(|error| FolderbaseCaptureError::InvalidLocalHead(error.to_string()))?;
    validate_capture_version_id(&version_id)
        .map_err(|error| FolderbaseCaptureError::InvalidLocalHead(error.to_string()))?;
    validate_capture_sha256(&version_sha256)
        .map_err(|error| FolderbaseCaptureError::InvalidLocalHead(error.to_string()))?;
    validate_capture_sha256(authority.sha256())
        .map_err(|error| FolderbaseCaptureError::InvalidLocalHead(error.to_string()))?;
    if let LocalHeadAuthority::VersionDerivedV1 { sha256 } = &authority {
        let expected = version_derived_local_head_sha256(
            &folderbase_id,
            &root_instance_sha256,
            &version_id,
            &version_sha256,
        )?;
        if sha256 != &expected {
            return Err(FolderbaseCaptureError::InvalidLocalHead(
                "version-derived Local Head authority does not match its bound Folderbase Version"
                    .to_owned(),
            ));
        }
    }
    Ok(Some(CaptureLocalHead {
        version_id,
        version_sha256,
        authority,
        encoded_sha256,
        observed,
    }))
}

fn read_ignore_policy(
    root_directory: &Dir,
    root: &Path,
    profile: &ManifestProtocolProfile,
) -> Result<IgnorePolicy, FolderbaseCaptureError> {
    let required = profile.requires_legacy_root_files();
    let path = root.join(".folderbaseignore");
    let mut encoded = Vec::new();
    let present = match root_directory.symlink_metadata(".folderbaseignore") {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(FolderbaseCaptureError::RequiredMarker(path));
            }
            if metadata.len() > MAX_FOLDERBASEIGNORE_BYTES {
                return Err(FolderbaseCaptureError::IgnorePolicyTooLarge {
                    maximum_bytes: MAX_FOLDERBASEIGNORE_BYTES,
                });
            }
            let mut file = open_regular_nofollow(root_directory, Path::new(".folderbaseignore"))
                .map_err(|source| FolderbaseCaptureError::Io {
                    path: path.clone(),
                    source,
                })?;
            file.by_ref()
                .take(MAX_FOLDERBASEIGNORE_BYTES + 1)
                .read_to_end(&mut encoded)
                .map_err(|source| FolderbaseCaptureError::Io {
                    path: path.clone(),
                    source,
                })?;
            true
        }
        Err(source) if source.kind() == io::ErrorKind::NotFound && !required => false,
        Err(_) if required => return Err(FolderbaseCaptureError::RequiredMarker(path)),
        Err(source) => return Err(FolderbaseCaptureError::Io { path, source }),
    };
    if encoded.len() as u64 > MAX_FOLDERBASEIGNORE_BYTES {
        return Err(FolderbaseCaptureError::IgnorePolicyTooLarge {
            maximum_bytes: MAX_FOLDERBASEIGNORE_BYTES,
        });
    }
    let policy =
        std::str::from_utf8(&encoded).map_err(|_| FolderbaseCaptureError::IgnorePolicyNotUtf8)?;
    let mut digest = Sha256::new();
    let engine_rules = if required {
        digest.update(b"folderbase-ignore-policy-v1\0");
        RECONSTRUCTABLE_DIRECTORIES
            .iter()
            .map(|directory| format!("{directory}/"))
            .chain([".DS_Store", "*.tmp", "~$*"].into_iter().map(str::to_owned))
            .collect::<Vec<_>>()
    } else {
        digest.update(b"folderbase-ignore-policy-v2\0");
        digest.update(if present {
            b"present\0".as_slice()
        } else {
            b"absent\0".as_slice()
        });
        profile
            .capture_ignore_rules()
            .expect("ordinary profile carries exact engine rules")
            .to_vec()
    };
    for pattern in &engine_rules {
        digest.update(pattern.as_bytes());
        digest.update(b"\n");
    }
    digest.update(b"\0");
    digest.update(&encoded);
    let matcher = build_folderbaseignore_matcher(root, &path, &engine_rules, policy)?;
    Ok(IgnorePolicy {
        matcher,
        sha256: format!("{:x}", digest.finalize()),
    })
}

pub(crate) fn validate_folderbaseignore_content(
    root: &Path,
    content: &str,
) -> Result<(), FolderbaseCaptureError> {
    build_folderbaseignore_matcher(root, &root.join(".folderbaseignore"), &[], content).map(drop)
}

fn build_folderbaseignore_matcher(
    root: &Path,
    path: &Path,
    engine_rules: &[String],
    content: &str,
) -> Result<Gitignore, FolderbaseCaptureError> {
    if content.len() as u64 > MAX_FOLDERBASEIGNORE_BYTES {
        return Err(FolderbaseCaptureError::IgnorePolicyTooLarge {
            maximum_bytes: MAX_FOLDERBASEIGNORE_BYTES,
        });
    }
    let mut builder = GitignoreBuilder::new(root);
    for pattern in engine_rules {
        builder
            .add_line(None, pattern)
            .map_err(|error| FolderbaseCaptureError::InvalidIgnorePolicy(error.to_string()))?;
    }
    for line in content.lines() {
        builder
            .add_line(Some(path.to_path_buf()), line)
            .map_err(|error| FolderbaseCaptureError::InvalidIgnorePolicy(error.to_string()))?;
    }
    builder
        .build()
        .map_err(|error| FolderbaseCaptureError::InvalidIgnorePolicy(error.to_string()))
}

fn require_regular_marker(
    root_directory: &Dir,
    root: &Path,
    relative: &Path,
) -> Result<(), FolderbaseCaptureError> {
    let path = root.join(relative);
    let metadata = root_directory
        .symlink_metadata(relative)
        .map_err(|_| FolderbaseCaptureError::RequiredMarker(path.clone()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(FolderbaseCaptureError::RequiredMarker(path));
    }
    Ok(())
}

fn protocol_file_observation(
    root_directory: &Dir,
    root: &Path,
    relative: &Path,
) -> Result<CaptureMetadataFingerprint, FolderbaseCaptureError> {
    let path = root.join(relative);
    let state_directory = root_directory
        .open_dir_nofollow(".folderbase")
        .map_err(|source| FolderbaseCaptureError::Io {
            path: path.clone(),
            source,
        })?;
    let file =
        open_regular_nofollow(&state_directory, Path::new("manifest.json")).map_err(|source| {
            FolderbaseCaptureError::Io {
                path: path.clone(),
                source,
            }
        })?;
    let metadata = file
        .metadata()
        .map_err(|source| FolderbaseCaptureError::Io {
            path: path.clone(),
            source,
        })?;
    if !metadata.is_file() {
        return Err(FolderbaseCaptureError::RequiredMarker(root.join(relative)));
    }
    CaptureMetadataFingerprint::from_std_file(&file)
        .map_err(|source| FolderbaseCaptureError::Io { path, source })
}

fn open_regular_nofollow(root: &Dir, relative: &Path) -> io::Result<fs::File> {
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    root.open_with(relative, &options)
        .map(|file| file.into_std())
}

#[cfg(test)]
mod capability_tests {
    use super::*;

    const MANIFEST: &[u8] = br#"{
      "$schema": "https://folderbase.ai/protocol/0.5/folderbase.schema.json",
      "protocol_version": "0.5.0",
      "folderbase": {
        "id": "folderbase_019f9b75-4f42-7f65-a012-2bfecdd8c473",
        "name": "Capture capability fixture",
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

    struct AmbientRootSwap {
        visible: PathBuf,
        detached: PathBuf,
        replacement: PathBuf,
    }

    impl AmbientRootSwap {
        fn activate(visible: &Path, replacement: &Path) -> Self {
            let detached = visible.with_file_name("detached-capture-root");
            fs::rename(visible, &detached).expect("detach capture root");
            fs::rename(replacement, visible).expect("install replacement root");
            Self {
                visible: visible.to_path_buf(),
                detached,
                replacement: replacement.to_path_buf(),
            }
        }
    }

    impl Drop for AmbientRootSwap {
        fn drop(&mut self) {
            fs::rename(&self.visible, &self.replacement).expect("remove replacement root");
            fs::rename(&self.detached, &self.visible).expect("restore capture root");
        }
    }

    fn initialize_root(root: &Path) {
        fs::create_dir(root).expect("Folderbase root");
        fs::create_dir(root.join(".folderbase")).expect("state");
        fs::write(root.join(".folderbase/manifest.json"), MANIFEST).expect("manifest");
    }

    #[cfg(unix)]
    #[test]
    fn retained_child_identity_rejects_a_directory_to_symlink_swap() {
        let root = tempfile::tempdir().expect("root");
        let outside = tempfile::tempdir().expect("outside");
        fs::create_dir(root.path().join("child")).expect("child");
        let root_directory = open_planning_root(root.path()).expect("root capability");
        let (_child, identity) = open_stable_child(
            &root_directory,
            OsStr::new("child"),
            &root.path().join("child"),
        )
        .expect("retained child");

        fs::rename(root.path().join("child"), root.path().join("detached")).expect("detach child");
        std::os::unix::fs::symlink(outside.path(), root.path().join("child"))
            .expect("outside replacement");

        assert!(
            verify_child_identity(
                &root_directory,
                OsStr::new("child"),
                &identity,
                &root.path().join("child"),
            )
            .is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn capture_restore_authorities_never_cross_an_ambient_root_aba() {
        let owner = tempfile::tempdir().expect("root owner");
        let visible = owner.path().join("workspace");
        let replacement = owner.path().join("replacement");
        initialize_root(&visible);
        initialize_root(&replacement);
        let opening_file = visible.join("ordinary.md");
        fs::write(&opening_file, b"opening bytes\n").expect("opening file");
        let store = FolderbaseVersionStore::open(&visible).expect("version store");

        let transaction_id = "fbrestore_019f0000-0000-7000-8000-000000000077";
        let stage = replacement.join(restore_stage_path(transaction_id));
        fs::create_dir_all(stage.parent().expect("stage parent")).expect("restore transaction");
        fs::hard_link(&opening_file, replacement.join("ordinary.md"))
            .expect("replacement workspace hard link");
        fs::hard_link(&opening_file, &stage).expect("replacement private authority link");
        let file = fs::File::open(&opening_file).expect("opening file identity");
        let record = RestoreAuthorityRecord {
            format: RESTORE_AUTHORITY_FORMAT_V1.to_owned(),
            folderbase_id: store.root_attestation.folderbase_id.clone(),
            root_instance_sha256: store.root_attestation.root_instance_sha256.clone(),
            transaction_id: transaction_id.to_owned(),
            workspace_path: "ordinary.md".to_owned(),
            private_stage_path: restore_stage_path(transaction_id)
                .to_str()
                .expect("UTF-8 stage")
                .to_owned(),
            published_identity_sha256: stable_file_identity_sha256(&file)
                .expect("opening identity"),
        };
        fs::write(
            replacement.join(restore_authority_record_path(transaction_id)),
            serde_json::to_vec(&record).expect("authority record"),
        )
        .expect("B-only restore authority");

        let plan = store
            .plan_capture_with_after_protocol_observation(|| {
                AmbientRootSwap::activate(&visible, &replacement)
            })
            .expect("capture opening root");

        assert!(
            plan.entries()
                .iter()
                .all(|entry| entry.path() != "ordinary.md")
        );
        assert!(plan.exclusions().iter().any(|exclusion| {
            exclusion.path() == "ordinary.md" && exclusion.kind() == CaptureExclusionKind::HardLink
        }));
    }
}

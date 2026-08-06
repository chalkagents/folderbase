//! Bounded planning, retained-capability staging, exact verification, restart,
//! and no-clobber publication for one root-reconstruction package.

use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::{OsStr, OsString},
    io::{Read, Write},
    path::{Component, Path, PathBuf},
};

#[cfg(not(windows))]
use cap_fs_ext::DirExt;
use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt};
use cap_std::fs::{Dir, OpenOptions as CapOpenOptions};
use serde::{
    Deserialize, Serialize,
    de::{IgnoredAny, SeqAccess, Visitor},
};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    FolderbaseCaptureError, FolderbaseError,
    folderbase_seal::{
        ReconstructedHistoryClosure, ReconstructedTombstoneAssociation,
        install_reconstructed_history, prepare_reconstructed_history,
    },
    folderbase_state::FolderbaseState,
    folderbase_version::{
        DeletedKind, FolderbaseVersion, FolderbaseVersionError, MAX_PATH_BYTES,
        MAX_PATH_COMPONENT_BYTES, PathBindingKind,
    },
    local_versions::{
        LocalObjectRecord, LocalVersionRecord, LocalVersionStore, ObjectId, ObjectLifecycle,
        ObjectProvenance, VersionId,
    },
    migration_filesystem::{
        publish_retained_directory_noreplace, require_retained_directory_publication,
        sync_retained_directory,
    },
    physical_identity::PhysicalIdentity,
    root_attestation::{
        FolderbaseRootAttestation, ManifestProtocolProfile, RootAttestationError,
        attest_retained_folderbase_root_with_profile, metadata_is_link_or_reparse,
        open_root_nofollow,
    },
    transfer_manifest::{ChunkManifest, ManifestError, ObjectVerificationError},
};

pub const PACKAGE_FORMAT_V1: &str = "folderbase-root-reconstruction-package-v1";
pub const MAX_PACKAGE_INDEX_BYTES: u64 = 8_388_608;
pub const MAX_PACKAGE_VERSION_BYTES: u64 = 67_108_864;
pub const MAX_PACKAGE_MANIFEST_BYTES: u64 = 67_108_864;
pub const MAX_PACKAGE_REFERENCES: usize = 16_385;
pub const MAX_DISTINCT_MANIFESTS: usize = 16_385;
pub const MAX_DISTINCT_CHUNKS: usize = 1_048_576;
pub const MAX_CHUNKS_PER_MANIFEST: usize = 262_144;
pub const MAX_PACKAGE_OBJECT_BYTES: u64 = 1_099_511_627_776;
pub const MAX_TOTAL_OBJECT_BYTES: u64 = 9_007_199_254_740_991;
pub const MAX_VISIBLE_ENTRIES: usize = 16_384;
const ACTIVE_RECONSTRUCTION_PATH: &str = ".folderbase/local/root-reconstruction/active.json";
const COMPLETED_RECONSTRUCTION_PATH: &str = ".folderbase/local/root-reconstruction/completed.json";
const RECONSTRUCTION_OBJECTS_DIRECTORY: &str = ".folderbase/local/root-reconstruction/objects";
const MAX_RECONSTRUCTION_RECORD_BYTES: u64 = 64 * 1024;
const FORCE_UNSUPPORTED_FILESYSTEM_ENV: &str =
    "FOLDERBASE_ROOT_RECONSTRUCTION_CONFORMANCE_FORCE_UNSUPPORTED_FILESYSTEM";
const STAGE_OWNERSHIP_FORMAT_V1: &str = "folderbase-root-reconstruction-stage-ownership-v1";

/// One canonical manifest document supplied by the package reader.
pub struct ManifestInput<R> {
    chunk_manifest_sha256: String,
    encoded: R,
}

impl<R> ManifestInput<R> {
    pub fn new(chunk_manifest_sha256: impl Into<String>, encoded: R) -> Self {
        Self {
            chunk_manifest_sha256: chunk_manifest_sha256.into(),
            encoded,
        }
    }

    pub fn digest(&self) -> &str {
        &self.chunk_manifest_sha256
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ReconstructionReferenceRole {
    RootManifest,
    LiveRegularFile,
    RetainedTombstone,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedObjectReference {
    object_version_id: String,
    object_id: Option<String>,
    roles: Vec<ReconstructionReferenceRole>,
    chunk_manifest_sha256: String,
}

impl PlannedObjectReference {
    pub fn object_version_id(&self) -> &str {
        &self.object_version_id
    }

    pub fn object_id(&self) -> Option<&str> {
        self.object_id.as_deref()
    }

    pub fn roles(&self) -> &[ReconstructionReferenceRole] {
        &self.roles
    }

    pub fn chunk_manifest_sha256(&self) -> &str {
        &self.chunk_manifest_sha256
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedManifest {
    chunk_manifest_sha256: String,
    object_sha256: String,
    object_bytes: u64,
    chunk_count: usize,
}

impl PlannedManifest {
    pub fn chunk_manifest_sha256(&self) -> &str {
        &self.chunk_manifest_sha256
    }

    pub fn object_sha256(&self) -> &str {
        &self.object_sha256
    }

    pub fn object_bytes(&self) -> u64 {
        self.object_bytes
    }

    pub fn chunk_count(&self) -> usize {
        self.chunk_count
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivedSymlink {
    path: String,
    object_id: String,
    object_version_id: String,
    target: String,
    content_sha256: String,
    bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedTombstoneFidelity {
    path: String,
    object_id: String,
    object_version_id: String,
    executable: bool,
}

impl PlannedTombstoneFidelity {
    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn object_id(&self) -> &str {
        &self.object_id
    }

    pub fn object_version_id(&self) -> &str {
        &self.object_version_id
    }

    pub fn executable(&self) -> bool {
        self.executable
    }
}

impl DerivedSymlink {
    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn object_id(&self) -> &str {
        &self.object_id
    }

    pub fn object_version_id(&self) -> &str {
        &self.object_version_id
    }

    pub fn target(&self) -> &str {
        &self.target
    }

    pub fn content_sha256(&self) -> &str {
        &self.content_sha256
    }

    pub fn bytes(&self) -> u64 {
        self.bytes
    }
}

#[derive(Debug)]
pub struct RootReconstructionPlan {
    package_index_sha256: String,
    encoded_version_sha256: String,
    canonical_version_sha256: String,
    version: FolderbaseVersion,
    references: Vec<PlannedObjectReference>,
    manifests: Vec<PlannedManifest>,
    derived_symlinks: Vec<DerivedSymlink>,
    tombstone_fidelity: Vec<PlannedTombstoneFidelity>,
    distinct_chunk_count: usize,
    total_object_bytes: u64,
}

/// One stable execution identity bound to an already-validated plan.
pub struct RootReconstructionOperation<'a> {
    plan: &'a RootReconstructionPlan,
    operation_id: String,
    request_sha256: String,
}

impl<'a> RootReconstructionOperation<'a> {
    pub fn new(
        plan: &'a RootReconstructionPlan,
        operation_id: impl Into<String>,
        package_index_sha256: impl Into<String>,
    ) -> Result<Self, RootReconstructionError> {
        let operation_id = operation_id.into();
        let package_index_sha256 = package_index_sha256.into();
        let Some(uuid) = operation_id.strip_prefix("reconstruction_") else {
            return Err(RootReconstructionError::InvalidOperation);
        };
        let parsed =
            Uuid::parse_str(uuid).map_err(|_| RootReconstructionError::InvalidOperation)?;
        if parsed.hyphenated().to_string() != uuid || !(1..=8).contains(&parsed.get_version_num()) {
            return Err(RootReconstructionError::InvalidOperation);
        }
        if package_index_sha256 != plan.package_index_sha256() {
            return Err(RootReconstructionError::PackageIndexPinMismatch);
        }
        let request_sha256 =
            root_reconstruction_request_sha256(&operation_id, &package_index_sha256)?;
        Ok(Self {
            plan,
            operation_id,
            request_sha256,
        })
    }

    pub fn request_sha256(&self) -> &str {
        &self.request_sha256
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootReconstructionPhase {
    StageEntryDurable,
    PreparedJournal,
    VerifiedStaging,
    Publication,
    CompletionDurable,
}

/// A retained, no-follow package root. Its path is diagnostic-only after open.
pub struct RetainedReconstructionPackage {
    root: Dir,
    display_root: PathBuf,
}

struct ValidatedPackage {
    manifests: BTreeMap<String, ChunkManifest>,
    _manifests_directory: Dir,
    chunks_directory: Dir,
    index_identity: PhysicalIdentity,
    version_identity: PhysicalIdentity,
    manifests_directory_identity: PhysicalIdentity,
    chunks_directory_identity: PhysicalIdentity,
    manifest_identities: BTreeMap<String, PhysicalIdentity>,
    chunk_identities: BTreeMap<String, PackageRegularIdentity>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct PackageRegularIdentity {
    physical: PhysicalIdentity,
    bytes: u64,
}

impl RetainedReconstructionPackage {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, RootReconstructionError> {
        let display_root = root.as_ref().to_path_buf();
        let file =
            open_root_nofollow(&display_root).map_err(|source| RootReconstructionError::Io {
                path: display_root.clone(),
                source,
            })?;
        let metadata = file
            .metadata()
            .map_err(|source| RootReconstructionError::Io {
                path: display_root.clone(),
                source,
            })?;
        if metadata_is_link_or_reparse(&metadata) || !metadata.is_dir() {
            return Err(RootReconstructionError::PackageChanged(display_root));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o022 != 0 {
                return Err(RootReconstructionError::PackageChanged(display_root));
            }
        }
        let root = Dir::from_std_file(file);
        Ok(Self { root, display_root })
    }
}

/// A retained parent plus one validated destination leaf. The leaf may be
/// absent for a new reconstruction or occupied for exact replay/no-clobber
/// classification.
pub struct RetainedReconstructionDestination {
    parent: Dir,
    display_parent: PathBuf,
    name: OsString,
}

impl RetainedReconstructionDestination {
    pub fn open(
        parent: impl AsRef<Path>,
        name: impl AsRef<OsStr>,
    ) -> Result<Self, RootReconstructionError> {
        Self::open_with_preflight(
            parent.as_ref(),
            name.as_ref(),
            std::env::var_os(FORCE_UNSUPPORTED_FILESYSTEM_ENV).is_some(),
        )
    }

    fn open_with_preflight(
        parent: &Path,
        name: &OsStr,
        force_unsupported: bool,
    ) -> Result<Self, RootReconstructionError> {
        let display_parent = parent.to_path_buf();
        if force_unsupported {
            return Err(
                RootReconstructionError::UnsupportedReconstructionFilesystem {
                    path: display_parent,
                    reason: "conformance seam forced unsupported reconstruction filesystem"
                        .to_owned(),
                },
            );
        }
        let name = name.to_os_string();
        if name.is_empty()
            || Path::new(&name).components().count() != 1
            || !matches!(
                Path::new(&name).components().next(),
                Some(Component::Normal(_))
            )
        {
            return Err(RootReconstructionError::InvalidDestination);
        }
        let file =
            open_root_nofollow(&display_parent).map_err(|source| RootReconstructionError::Io {
                path: display_parent.clone(),
                source,
            })?;
        let metadata = file
            .metadata()
            .map_err(|source| RootReconstructionError::Io {
                path: display_parent.clone(),
                source,
            })?;
        if metadata_is_link_or_reparse(&metadata) || !metadata.is_dir() {
            return Err(RootReconstructionError::InvalidDestination);
        }
        let parent = Dir::from_std_file(file);
        match parent.symlink_metadata(&name) {
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                require_retained_directory_publication(&parent, &display_parent)
                    .map_err(|error| unsupported_publication_error(error, &display_parent))?;
            }
            Ok(_) => {}
            Err(source) => {
                return Err(RootReconstructionError::Io {
                    path: display_parent.join(&name),
                    source,
                });
            }
        }
        Ok(Self {
            parent,
            display_parent,
            name,
        })
    }
}

#[derive(Debug, Clone)]
pub struct RootReconstructionResult {
    replayed: bool,
    attestation: FolderbaseRootAttestation,
}

impl RootReconstructionResult {
    pub fn replayed(&self) -> bool {
        self.replayed
    }

    pub fn attestation(&self) -> &FolderbaseRootAttestation {
        &self.attestation
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReconstructionRecord {
    format: String,
    operation_id: String,
    request_sha256: String,
    package_index_sha256: String,
    folderbase_id: String,
    folderbase_version_id: String,
    canonical_version_sha256: String,
    visible_entries: usize,
    external_objects: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReconstructionCompletion {
    #[serde(flatten)]
    operation: ReconstructionRecord,
    root_instance_sha256: String,
    manifest_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StageOwnershipRecord {
    format: String,
    operation: ReconstructionRecord,
    staged_name: String,
    phase: StageOwnershipPhase,
    physical_identity_sha256: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum StageOwnershipPhase {
    IntentDurable,
    StageOwned,
}

impl RootReconstructionPlan {
    pub fn package_index_sha256(&self) -> &str {
        &self.package_index_sha256
    }

    pub fn encoded_version_sha256(&self) -> &str {
        &self.encoded_version_sha256
    }

    pub fn canonical_version_sha256(&self) -> &str {
        &self.canonical_version_sha256
    }

    pub fn version(&self) -> &FolderbaseVersion {
        &self.version
    }

    pub fn references(&self) -> &[PlannedObjectReference] {
        &self.references
    }

    pub fn manifests(&self) -> &[PlannedManifest] {
        &self.manifests
    }

    pub fn derived_symlinks(&self) -> &[DerivedSymlink] {
        &self.derived_symlinks
    }

    pub fn tombstone_fidelity(&self) -> &[PlannedTombstoneFidelity] {
        &self.tombstone_fidelity
    }

    pub fn externally_materialized_object_count(&self) -> usize {
        self.references.len()
    }

    pub fn visible_entry_count(&self) -> usize {
        self.version.binding_count()
    }

    pub fn distinct_chunk_count(&self) -> usize {
        self.distinct_chunk_count
    }

    pub fn total_object_bytes(&self) -> u64 {
        self.total_object_bytes
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RootReconstructionError {
    #[error("root reconstruction operation identity is invalid")]
    InvalidOperation,
    #[error("root reconstruction package-index pin differs from the validated plan")]
    PackageIndexPinMismatch,
    #[error("root reconstruction destination leaf is invalid")]
    InvalidDestination,
    #[error("root reconstruction destination is occupied: {0}")]
    DestinationOccupied(PathBuf),
    #[error("root reconstruction operation conflicts with retained state")]
    OperationConflict,
    #[error("root reconstruction package changed at {0}")]
    PackageChanged(PathBuf),
    #[error("root reconstruction filesystem is unsupported at {path}: {reason}")]
    UnsupportedReconstructionFilesystem { path: PathBuf, reason: String },
    #[error("root reconstruction filesystem operation failed: {0}")]
    Filesystem(#[from] FolderbaseError),
    #[error("root reconstruction history installation failed: {0}")]
    History(#[from] FolderbaseCaptureError),
    #[error("reconstructed root attestation failed: {0}")]
    Attestation(#[from] RootAttestationError),
    #[error("root reconstruction object verification failed: {0}")]
    ObjectVerification(#[from] ObjectVerificationError),
    #[error("root reconstruction I/O failed at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("package index input failed: {0}")]
    IndexReader(#[source] std::io::Error),
    #[error("encoded package index exceeds {maximum_bytes} bytes")]
    IndexTooLarge { maximum_bytes: u64 },
    #[error("package index is not valid closed JSON: {0}")]
    InvalidIndexJson(#[source] serde_json::Error),
    #[error("package index limit declaration is not the fixed v1 declaration")]
    LimitsMismatch,
    #[error("package index format is unsupported")]
    UnknownFormat,
    #[error("package index contains more than {maximum} references")]
    TooManyReferences { maximum: usize },
    #[error("Folderbase Version input failed: {0}")]
    VersionReader(#[source] std::io::Error),
    #[error("encoded Folderbase Version exceeds {maximum_bytes} bytes")]
    VersionTooLarge { maximum_bytes: u64 },
    #[error("Folderbase Version is invalid: {0}")]
    InvalidVersion(#[source] FolderbaseVersionError),
    #[error("package index Folderbase identity differs from the Version")]
    FolderbaseIdMismatch,
    #[error("package index Folderbase Version identity differs from the Version")]
    VersionIdMismatch,
    #[error("encoded Folderbase Version digest differs from the package index")]
    EncodedVersionDigestMismatch,
    #[error("canonical Folderbase Version digest differs from the package index")]
    CanonicalVersionDigestMismatch,
    #[error("package references are not strictly ordered by Object Version ID")]
    ReferencesOutOfOrder,
    #[error("package contains duplicate Object Version reference {object_version_id}")]
    DuplicateReference { object_version_id: String },
    #[error("package reference {object_version_id} has a noncanonical role set")]
    InvalidReferenceRoles { object_version_id: String },
    #[error("package reference {object_version_id} is not in the Version closure")]
    UnexpectedReference { object_version_id: String },
    #[error("Version closure reference {object_version_id} is missing")]
    MissingReference { object_version_id: String },
    #[error("package reference {object_version_id} differs from the Version closure")]
    ReferenceMismatch { object_version_id: String },
    #[error("package reference {object_version_id} has an invalid manifest digest")]
    InvalidManifestDigest { object_version_id: String },
    #[error("package contains more than {maximum} manifest documents")]
    TooManyManifests { maximum: usize },
    #[error("manifest {chunk_manifest_sha256} is not referenced by the Version closure")]
    UnreferencedManifest { chunk_manifest_sha256: String },
    #[error("manifest {chunk_manifest_sha256} is supplied more than once")]
    DuplicateManifest { chunk_manifest_sha256: String },
    #[error("referenced manifest {chunk_manifest_sha256} is missing")]
    MissingManifest { chunk_manifest_sha256: String },
    #[error("manifest {chunk_manifest_sha256} is invalid: {source}")]
    InvalidManifest {
        chunk_manifest_sha256: String,
        #[source]
        source: ManifestError,
    },
    #[error("manifest document does not match its canonical digest {chunk_manifest_sha256}")]
    ManifestDigestMismatch { chunk_manifest_sha256: String },
    #[error("package manifests reference more than {maximum} distinct chunks")]
    TooManyDistinctChunks { maximum: usize },
    #[error("manifest for {object_version_id} differs from the Version-bound object")]
    ManifestObjectMismatch { object_version_id: String },
    #[error("package object bytes exceed the aggregate v1 maximum of {maximum}")]
    TotalObjectBytesTooLarge { maximum: u64 },
    #[error("package Tombstone fidelity closure differs from the Folderbase Version")]
    TombstoneFidelityMismatch,
}

/// Execute or exactly replay one reconstruction operation.
///
/// All staging and publication is rooted in retained capabilities. The final
/// public destination appears only through one atomic no-replace directory
/// rename after bytes, history, Local Head, attestation, and completion have
/// all verified.
pub fn execute_root_reconstruction(
    operation: RootReconstructionOperation<'_>,
    package: &RetainedReconstructionPackage,
    destination: &RetainedReconstructionDestination,
) -> Result<RootReconstructionResult, RootReconstructionError> {
    execute_root_reconstruction_with_phase_callback(operation, package, destination, |_| {})
}

#[doc(hidden)]
pub fn execute_root_reconstruction_with_phase_callback<F>(
    operation: RootReconstructionOperation<'_>,
    package: &RetainedReconstructionPackage,
    destination: &RetainedReconstructionDestination,
    mut phase: F,
) -> Result<RootReconstructionResult, RootReconstructionError>
where
    F: FnMut(RootReconstructionPhase),
{
    let record = reconstruction_record(&operation);

    if let Some(root) = open_directory_if_present(
        &destination.parent,
        &destination.name,
        &destination.display_parent.join(&destination.name),
    )? {
        return replay_published_root(&root, destination, &record);
    }
    let validated_package = revalidate_package(package, operation.plan)?;

    let staged_name = staged_root_name(&operation.operation_id);
    let staged_display = destination.display_parent.join(&staged_name);
    let owner_name = stage_owner_name(&operation.operation_id);
    let (staged, ownership) = acquire_owned_stage(
        destination,
        &staged_name,
        &owner_name,
        &staged_display,
        &record,
        &mut phase,
    )?;

    ensure_directory(&staged, Path::new(".folderbase"), &staged_display)?;
    let state = FolderbaseState::from_retained_root(&staged, &staged_display)?;
    state.ensure_private_dir(Path::new(".folderbase/local/root-reconstruction"))?;
    state.ensure_private_dir(Path::new(RECONSTRUCTION_OBJECTS_DIRECTORY))?;
    install_exact_record(&state, Path::new(ACTIVE_RECONSTRUCTION_PATH), &record)?;
    phase(RootReconstructionPhase::PreparedJournal);
    require_same_package_identity(
        package,
        &validated_package,
        &revalidate_package(package, operation.plan)?,
    )?;
    prepare_reconstructed_history(&state)?;

    let local = LocalVersionStore::for_retained_root(&staged_display);
    let history = materialize_reconstruction(
        &staged,
        &staged_display,
        &state,
        &local,
        package,
        operation.plan,
        &validated_package,
    )?;
    let (attestation, _, profile) =
        attest_retained_folderbase_root_with_profile(&staged, &staged_display)?;
    if attestation.folderbase_id != operation.plan.version().folderbase_id() {
        return Err(RootReconstructionError::OperationConflict);
    }
    require_matching_protocol_profile(operation.plan.version(), &profile)?;
    install_reconstructed_history(
        &local,
        &state,
        &attestation,
        operation.plan.version(),
        operation.plan.canonical_version_sha256(),
        &history,
    )?;
    require_same_package_identity(
        package,
        &validated_package,
        &revalidate_package(package, operation.plan)?,
    )?;
    verify_visible_tree(&staged, &staged_display, operation.plan.version())?;
    phase(RootReconstructionPhase::VerifiedStaging);
    let verified = attest_retained_folderbase_root_with_profile(&staged, &staged_display)?.0;
    let completion = ReconstructionCompletion {
        operation: record.clone(),
        root_instance_sha256: verified.root_instance_sha256.clone(),
        manifest_sha256: verified.manifest_sha256.clone(),
    };
    install_exact_record(
        &state,
        Path::new(COMPLETED_RECONSTRUCTION_PATH),
        &completion,
    )?;

    publish_retained_directory_noreplace(
        &destination.parent,
        &staged_name,
        &destination.name,
        &destination.display_parent,
    )
    .map_err(|error| match error {
        FolderbaseError::WouldOverwrite(path) => RootReconstructionError::DestinationOccupied(path),
        error => RootReconstructionError::Filesystem(error),
    })?;
    let final_display = destination.display_parent.join(&destination.name);
    let published_root =
        open_directory_if_present(&destination.parent, &destination.name, &final_display)?
            .ok_or(RootReconstructionError::OperationConflict)?;
    if Some(directory_identity_sha256(&published_root, &final_display)?)
        != ownership.physical_identity_sha256
    {
        return Err(RootReconstructionError::OperationConflict);
    }
    verify_visible_tree(&published_root, &final_display, operation.plan.version())?;
    let final_attestation =
        attest_retained_folderbase_root_with_profile(&published_root, &final_display)?.0;
    if final_attestation.root_instance_sha256 != completion.root_instance_sha256
        || final_attestation.manifest_sha256 != completion.manifest_sha256
    {
        return Err(RootReconstructionError::OperationConflict);
    }
    phase(RootReconstructionPhase::Publication);
    retire_stage_owner(destination, &owner_name, &ownership, &published_root)?;
    phase(RootReconstructionPhase::CompletionDurable);
    Ok(RootReconstructionResult {
        replayed: false,
        attestation: final_attestation,
    })
}

fn reconstruction_record(operation: &RootReconstructionOperation<'_>) -> ReconstructionRecord {
    ReconstructionRecord {
        format: "folderbase-root-reconstruction-operation-v1".to_owned(),
        operation_id: operation.operation_id.clone(),
        request_sha256: operation.request_sha256.clone(),
        package_index_sha256: operation.plan.package_index_sha256().to_owned(),
        folderbase_id: operation.plan.version().folderbase_id().to_owned(),
        folderbase_version_id: operation.plan.version().version_id().to_owned(),
        canonical_version_sha256: operation.plan.canonical_version_sha256().to_owned(),
        visible_entries: operation.plan.visible_entry_count(),
        external_objects: operation.plan.externally_materialized_object_count(),
    }
}

fn require_matching_protocol_profile(
    version: &FolderbaseVersion,
    profile: &ManifestProtocolProfile,
) -> Result<(), RootReconstructionError> {
    let matches = matches!(
        (version.protocol_version(), profile),
        ("0.4", ManifestProtocolProfile::LegacyV01V02)
            | ("0.5", ManifestProtocolProfile::OrdinaryV05 { .. })
    );
    if matches {
        Ok(())
    } else {
        Err(RootReconstructionError::OperationConflict)
    }
}

fn unsupported_publication_error(
    error: FolderbaseError,
    display: &Path,
) -> RootReconstructionError {
    match error {
        FolderbaseError::UnsupportedMigrationFilesystem { reason, .. } => {
            RootReconstructionError::UnsupportedReconstructionFilesystem {
                path: display.to_path_buf(),
                reason,
            }
        }
        error => RootReconstructionError::Filesystem(error),
    }
}

fn staged_root_name(operation_id: &str) -> OsString {
    OsString::from(format!(
        ".folderbase-reconstruction-{}.stage",
        operation_id
            .strip_prefix("reconstruction_")
            .expect("validated operation ID")
    ))
}

fn stage_owner_name(operation_id: &str) -> OsString {
    OsString::from(format!(
        ".folderbase-reconstruction-{}.owner.json",
        operation_id
            .strip_prefix("reconstruction_")
            .expect("validated operation ID")
    ))
}

fn stage_proof_name(operation_id: &str) -> OsString {
    OsString::from(format!(
        ".folderbase-reconstruction-{}.stage-owned.json",
        operation_id
            .strip_prefix("reconstruction_")
            .expect("validated operation ID")
    ))
}

fn acquire_owned_stage<F>(
    destination: &RetainedReconstructionDestination,
    staged_name: &OsStr,
    owner_name: &OsStr,
    staged_display: &Path,
    operation: &ReconstructionRecord,
    phase: &mut F,
) -> Result<(Dir, StageOwnershipRecord), RootReconstructionError>
where
    F: FnMut(RootReconstructionPhase),
{
    let owner_display = destination.display_parent.join(owner_name);
    let proof_name = stage_proof_name(&operation.operation_id);
    let proof_display = destination.display_parent.join(&proof_name);
    let expected_intent = StageOwnershipRecord {
        format: STAGE_OWNERSHIP_FORMAT_V1.to_owned(),
        operation: operation.clone(),
        staged_name: staged_name.to_string_lossy().into_owned(),
        phase: StageOwnershipPhase::IntentDurable,
        physical_identity_sha256: None,
    };
    let intent = read_parent_regular(
        &destination.parent,
        owner_name,
        &owner_display,
        MAX_RECONSTRUCTION_RECORD_BYTES,
    )?;
    if let Some(encoded) = intent.as_deref() {
        require_exact_stage_ownership(encoded, &expected_intent)?;
    } else {
        if read_parent_regular(
            &destination.parent,
            &proof_name,
            &proof_display,
            MAX_RECONSTRUCTION_RECORD_BYTES,
        )?
        .is_some()
            || open_owned_stage_if_present(destination, staged_name, staged_display)?.is_some()
        {
            return Err(RootReconstructionError::OperationConflict);
        }
        write_parent_new(
            &destination.parent,
            owner_name,
            &owner_display,
            &destination.display_parent,
            &serde_json::to_vec(&expected_intent)
                .map_err(|_| RootReconstructionError::OperationConflict)?,
        )?;
    }

    let stage = open_owned_stage_if_present(destination, staged_name, staged_display)?;
    let proof = read_parent_regular(
        &destination.parent,
        &proof_name,
        &proof_display,
        MAX_RECONSTRUCTION_RECORD_BYTES,
    )?;
    match (stage, proof) {
        (None, None) => {
            destination
                .parent
                .create_dir(staged_name)
                .map_err(|source| RootReconstructionError::Io {
                    path: staged_display.to_path_buf(),
                    source,
                })?;
            sync_retained_directory(&destination.parent, &destination.display_parent)?;
            let staged = open_owned_stage_if_present(destination, staged_name, staged_display)?
                .ok_or(RootReconstructionError::OperationConflict)?;
            phase(RootReconstructionPhase::StageEntryDurable);
            let ownership = persist_stage_ownership(
                destination,
                &staged,
                staged_name,
                staged_display,
                &proof_name,
                &proof_display,
                operation,
            )?;
            Ok((staged, ownership))
        }
        (Some(staged), None) => {
            let ownership = persist_stage_ownership(
                destination,
                &staged,
                staged_name,
                staged_display,
                &proof_name,
                &proof_display,
                operation,
            )?;
            Ok((staged, ownership))
        }
        (Some(staged), Some(encoded)) => {
            let ownership = decode_stage_ownership(&encoded)?;
            let actual_identity = directory_identity_sha256(&staged, staged_display)?;
            if ownership.format != STAGE_OWNERSHIP_FORMAT_V1
                || ownership.operation != *operation
                || ownership.staged_name != staged_name.to_string_lossy()
                || ownership.phase != StageOwnershipPhase::StageOwned
                || ownership.physical_identity_sha256.as_deref() != Some(actual_identity.as_str())
            {
                return Err(RootReconstructionError::OperationConflict);
            }
            Ok((staged, ownership))
        }
        _ => Err(RootReconstructionError::OperationConflict),
    }
}

fn persist_stage_ownership(
    destination: &RetainedReconstructionDestination,
    staged: &Dir,
    staged_name: &OsStr,
    staged_display: &Path,
    proof_name: &OsStr,
    proof_display: &Path,
    operation: &ReconstructionRecord,
) -> Result<StageOwnershipRecord, RootReconstructionError> {
    let ownership = StageOwnershipRecord {
        format: STAGE_OWNERSHIP_FORMAT_V1.to_owned(),
        operation: operation.clone(),
        staged_name: staged_name.to_string_lossy().into_owned(),
        phase: StageOwnershipPhase::StageOwned,
        physical_identity_sha256: Some(directory_identity_sha256(staged, staged_display)?),
    };
    write_parent_new(
        &destination.parent,
        proof_name,
        proof_display,
        &destination.display_parent,
        &serde_json::to_vec(&ownership).map_err(|_| RootReconstructionError::OperationConflict)?,
    )?;
    Ok(ownership)
}

fn open_owned_stage_if_present(
    destination: &RetainedReconstructionDestination,
    staged_name: &OsStr,
    staged_display: &Path,
) -> Result<Option<Dir>, RootReconstructionError> {
    match open_directory_if_present(&destination.parent, staged_name, staged_display) {
        Err(RootReconstructionError::DestinationOccupied(_)) => {
            Err(RootReconstructionError::OperationConflict)
        }
        result => result,
    }
}

fn decode_stage_ownership(encoded: &[u8]) -> Result<StageOwnershipRecord, RootReconstructionError> {
    let record: StageOwnershipRecord =
        serde_json::from_slice(encoded).map_err(|_| RootReconstructionError::OperationConflict)?;
    if serde_json::to_vec(&record).ok().as_deref() != Some(encoded) {
        return Err(RootReconstructionError::OperationConflict);
    }
    Ok(record)
}

fn require_exact_stage_ownership(
    encoded: &[u8],
    expected: &StageOwnershipRecord,
) -> Result<(), RootReconstructionError> {
    if decode_stage_ownership(encoded)? == *expected {
        Ok(())
    } else {
        Err(RootReconstructionError::OperationConflict)
    }
}

fn directory_identity_sha256(
    directory: &Dir,
    display: &Path,
) -> Result<String, RootReconstructionError> {
    cap_directory_identity(directory, display).map(PhysicalIdentity::stable_sha256)
}

fn cap_directory_identity(
    directory: &Dir,
    display: &Path,
) -> Result<PhysicalIdentity, RootReconstructionError> {
    let file = directory
        .try_clone()
        .map_err(|source| RootReconstructionError::Io {
            path: display.to_path_buf(),
            source,
        })?
        .into_std_file();
    PhysicalIdentity::from_file(&file).map_err(|source| RootReconstructionError::Io {
        path: display.to_path_buf(),
        source,
    })
}

fn read_parent_regular(
    parent: &Dir,
    name: &OsStr,
    display: &Path,
    maximum: u64,
) -> Result<Option<Vec<u8>>, RootReconstructionError> {
    let mut options = CapOpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    let mut file = match parent.open_with(name, &options) {
        Ok(file) => file,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(RootReconstructionError::Io {
                path: display.to_path_buf(),
                source,
            });
        }
    };
    let metadata = file
        .metadata()
        .map_err(|source| RootReconstructionError::Io {
            path: display.to_path_buf(),
            source,
        })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > maximum {
        return Err(RootReconstructionError::OperationConflict);
    }
    let mut encoded = Vec::new();
    Read::by_ref(&mut file)
        .take(maximum.saturating_add(1))
        .read_to_end(&mut encoded)
        .map_err(|source| RootReconstructionError::Io {
            path: display.to_path_buf(),
            source,
        })?;
    if encoded.len() as u64 > maximum {
        return Err(RootReconstructionError::OperationConflict);
    }
    Ok(Some(encoded))
}

fn write_parent_new(
    parent: &Dir,
    name: &OsStr,
    display: &Path,
    parent_display: &Path,
    encoded: &[u8],
) -> Result<(), RootReconstructionError> {
    let mut options = CapOpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .follow(FollowSymlinks::No);
    let mut file =
        parent
            .open_with(name, &options)
            .map_err(|source| RootReconstructionError::Io {
                path: display.to_path_buf(),
                source,
            })?;
    file.write_all(encoded)
        .and_then(|()| file.sync_all())
        .map_err(|source| RootReconstructionError::Io {
            path: display.to_path_buf(),
            source,
        })?;
    sync_retained_directory(parent, parent_display)?;
    Ok(())
}

fn retire_stage_owner(
    destination: &RetainedReconstructionDestination,
    owner_name: &OsStr,
    expected: &StageOwnershipRecord,
    published_root: &Dir,
) -> Result<(), RootReconstructionError> {
    let owner_display = destination.display_parent.join(owner_name);
    let staged_name = staged_root_name(&expected.operation.operation_id);
    let intent = StageOwnershipRecord {
        format: STAGE_OWNERSHIP_FORMAT_V1.to_owned(),
        operation: expected.operation.clone(),
        staged_name: staged_name.to_string_lossy().into_owned(),
        phase: StageOwnershipPhase::IntentDurable,
        physical_identity_sha256: None,
    };
    let intent_encoded = read_parent_regular(
        &destination.parent,
        owner_name,
        &owner_display,
        MAX_RECONSTRUCTION_RECORD_BYTES,
    )?
    .ok_or(RootReconstructionError::OperationConflict)?;
    require_exact_stage_ownership(&intent_encoded, &intent)?;
    let proof_name = stage_proof_name(&expected.operation.operation_id);
    let proof_display = destination.display_parent.join(&proof_name);
    let proof_encoded = read_parent_regular(
        &destination.parent,
        &proof_name,
        &proof_display,
        MAX_RECONSTRUCTION_RECORD_BYTES,
    )?
    .ok_or(RootReconstructionError::OperationConflict)?;
    require_exact_stage_ownership(&proof_encoded, expected)?;
    if expected.format != STAGE_OWNERSHIP_FORMAT_V1
        || expected.staged_name != staged_name.to_string_lossy()
        || expected.phase != StageOwnershipPhase::StageOwned
        || directory_identity_sha256(
            published_root,
            &destination.display_parent.join(&destination.name),
        )? != expected
            .physical_identity_sha256
            .as_deref()
            .ok_or(RootReconstructionError::OperationConflict)?
    {
        return Err(RootReconstructionError::OperationConflict);
    }
    destination
        .parent
        .remove_file(&proof_name)
        .map_err(|source| RootReconstructionError::Io {
            path: proof_display,
            source,
        })?;
    sync_retained_directory(&destination.parent, &destination.display_parent)?;
    destination
        .parent
        .remove_file(owner_name)
        .map_err(|source| RootReconstructionError::Io {
            path: owner_display,
            source,
        })?;
    sync_retained_directory(&destination.parent, &destination.display_parent)?;
    Ok(())
}

fn retire_stage_owner_after_replay(
    destination: &RetainedReconstructionDestination,
    expected_operation: &ReconstructionRecord,
    published_root: &Dir,
) -> Result<(), RootReconstructionError> {
    let owner_name = stage_owner_name(&expected_operation.operation_id);
    let owner_display = destination.display_parent.join(&owner_name);
    let owner = read_parent_regular(
        &destination.parent,
        &owner_name,
        &owner_display,
        MAX_RECONSTRUCTION_RECORD_BYTES,
    )?;
    let proof_name = stage_proof_name(&expected_operation.operation_id);
    let proof_display = destination.display_parent.join(&proof_name);
    let proof = read_parent_regular(
        &destination.parent,
        &proof_name,
        &proof_display,
        MAX_RECONSTRUCTION_RECORD_BYTES,
    )?;
    let Some(owner) = owner else {
        return if proof.is_none() {
            Ok(())
        } else {
            Err(RootReconstructionError::OperationConflict)
        };
    };
    let staged_name = staged_root_name(&expected_operation.operation_id);
    let intent = StageOwnershipRecord {
        format: STAGE_OWNERSHIP_FORMAT_V1.to_owned(),
        operation: expected_operation.clone(),
        staged_name: staged_name.to_string_lossy().into_owned(),
        phase: StageOwnershipPhase::IntentDurable,
        physical_identity_sha256: None,
    };
    require_exact_stage_ownership(&owner, &intent)?;
    if let Some(proof) = proof {
        let ownership = decode_stage_ownership(&proof)?;
        let actual_identity = directory_identity_sha256(
            published_root,
            &destination.display_parent.join(&destination.name),
        )?;
        if ownership.format != STAGE_OWNERSHIP_FORMAT_V1
            || ownership.operation != *expected_operation
            || ownership.staged_name != staged_name.to_string_lossy()
            || ownership.phase != StageOwnershipPhase::StageOwned
            || ownership.physical_identity_sha256.as_deref() != Some(actual_identity.as_str())
        {
            return Err(RootReconstructionError::OperationConflict);
        }
        destination
            .parent
            .remove_file(&proof_name)
            .map_err(|source| RootReconstructionError::Io {
                path: proof_display,
                source,
            })?;
        sync_retained_directory(&destination.parent, &destination.display_parent)?;
    }
    if intent.operation != *expected_operation {
        return Err(RootReconstructionError::OperationConflict);
    }
    destination
        .parent
        .remove_file(&owner_name)
        .map_err(|source| RootReconstructionError::Io {
            path: owner_display,
            source,
        })?;
    sync_retained_directory(&destination.parent, &destination.display_parent)?;
    Ok(())
}

fn open_directory_if_present(
    parent: &Dir,
    name: &OsStr,
    display: &Path,
) -> Result<Option<Dir>, RootReconstructionError> {
    let metadata = match parent.symlink_metadata(name) {
        Ok(metadata) => metadata,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(RootReconstructionError::Io {
                path: display.to_path_buf(),
                source,
            });
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(RootReconstructionError::DestinationOccupied(
            display.to_path_buf(),
        ));
    }
    parent
        .open_dir_nofollow(name)
        .map(Some)
        .map_err(|source| RootReconstructionError::Io {
            path: display.to_path_buf(),
            source,
        })
}

fn replay_published_root(
    root: &Dir,
    destination: &RetainedReconstructionDestination,
    expected: &ReconstructionRecord,
) -> Result<RootReconstructionResult, RootReconstructionError> {
    let display = destination.display_parent.join(&destination.name);
    match replay_published_root_exact(root, destination, expected) {
        Ok(result) => Ok(result),
        Err(PublishedReplayError::NotExact) => {
            Err(RootReconstructionError::DestinationOccupied(display))
        }
        Err(PublishedReplayError::Operational(error)) => Err(error),
    }
}

enum PublishedReplayError {
    NotExact,
    Operational(RootReconstructionError),
}

impl From<RootReconstructionError> for PublishedReplayError {
    fn from(error: RootReconstructionError) -> Self {
        Self::Operational(error)
    }
}

fn replay_published_root_exact(
    root: &Dir,
    destination: &RetainedReconstructionDestination,
    expected: &ReconstructionRecord,
) -> Result<RootReconstructionResult, PublishedReplayError> {
    let display = destination.display_parent.join(&destination.name);
    let state = match FolderbaseState::from_retained_root(root, &display) {
        Ok(state) => state,
        Err(FolderbaseError::Io { source, .. })
            if source.kind() == std::io::ErrorKind::NotFound =>
        {
            return Err(PublishedReplayError::NotExact);
        }
        Err(error) => {
            return Err(PublishedReplayError::Operational(
                RootReconstructionError::Filesystem(error),
            ));
        }
    };
    let Some(bytes) = state
        .read_bounded(
            Path::new(COMPLETED_RECONSTRUCTION_PATH),
            MAX_RECONSTRUCTION_RECORD_BYTES,
        )
        .map_err(|error| {
            PublishedReplayError::Operational(RootReconstructionError::Filesystem(error))
        })?
    else {
        return Err(PublishedReplayError::NotExact);
    };
    let completion: ReconstructionCompletion =
        serde_json::from_slice(&bytes).map_err(|_| PublishedReplayError::NotExact)?;
    if serde_json::to_vec(&completion).ok().as_deref() != Some(bytes.as_slice())
        || &completion.operation != expected
    {
        return Err(PublishedReplayError::NotExact);
    }
    let (attestation, _, profile) = attest_retained_folderbase_root_with_profile(root, &display)
        .map_err(|error| match &error {
            RootAttestationError::Io { source, .. }
                if source.kind() == std::io::ErrorKind::NotFound =>
            {
                PublishedReplayError::NotExact
            }
            RootAttestationError::Io { .. }
            | RootAttestationError::RootChangedDuringAttestation
            | RootAttestationError::PhysicalIdentityUnavailable => {
                PublishedReplayError::Operational(RootReconstructionError::Attestation(error))
            }
            _ => PublishedReplayError::NotExact,
        })?;
    if attestation.folderbase_id != expected.folderbase_id
        || attestation.root_instance_sha256 != completion.root_instance_sha256
        || attestation.manifest_sha256 != completion.manifest_sha256
    {
        return Err(PublishedReplayError::NotExact);
    }
    let version_bytes = state
        .read_bounded(
            &Path::new(".folderbase/versions/folderbase")
                .join(format!("{}.json", expected.folderbase_version_id)),
            MAX_PACKAGE_VERSION_BYTES,
        )
        .map_err(|error| {
            PublishedReplayError::Operational(RootReconstructionError::Filesystem(error))
        })?
        .ok_or(PublishedReplayError::NotExact)?;
    let version = FolderbaseVersion::decode_bounded(version_bytes.as_slice())
        .map_err(|_| PublishedReplayError::NotExact)?;
    if version
        .canonical_digest()
        .map_err(|_| PublishedReplayError::NotExact)?
        != expected.canonical_version_sha256
    {
        return Err(PublishedReplayError::NotExact);
    }
    require_matching_protocol_profile(&version, &profile)
        .map_err(|_| PublishedReplayError::NotExact)?;
    verify_visible_tree(root, &display, &version).map_err(|error| match error {
        RootReconstructionError::OperationConflict => PublishedReplayError::NotExact,
        error => PublishedReplayError::Operational(error),
    })?;
    retire_stage_owner_after_replay(destination, expected, root)
        .map_err(PublishedReplayError::Operational)?;
    Ok(RootReconstructionResult {
        replayed: true,
        attestation,
    })
}

fn install_exact_record<T: Serialize>(
    state: &FolderbaseState,
    path: &Path,
    record: &T,
) -> Result<(), RootReconstructionError> {
    let encoded =
        serde_json::to_vec(record).map_err(|_| RootReconstructionError::OperationConflict)?;
    match state.publish_new(path, &encoded) {
        Ok(()) => Ok(()),
        Err(FolderbaseError::WouldOverwrite(_)) => {
            if state
                .read_bounded(path, MAX_RECONSTRUCTION_RECORD_BYTES)?
                .as_deref()
                == Some(encoded.as_slice())
            {
                Ok(())
            } else {
                Err(RootReconstructionError::OperationConflict)
            }
        }
        Err(error) => Err(error.into()),
    }
}

fn revalidate_package(
    package: &RetainedReconstructionPackage,
    plan: &RootReconstructionPlan,
) -> Result<ValidatedPackage, RootReconstructionError> {
    let (index, index_identity) = read_package_regular_with_identity(
        package,
        Path::new("index.json"),
        MAX_PACKAGE_INDEX_BYTES,
    )?;
    if sha256(&index) != plan.package_index_sha256() {
        return Err(RootReconstructionError::PackageChanged(
            package.display_root.join("index.json"),
        ));
    }
    let (version, version_identity) = read_package_regular_with_identity(
        package,
        Path::new("version.json"),
        MAX_PACKAGE_VERSION_BYTES,
    )?;
    if sha256(&version) != plan.encoded_version_sha256() {
        return Err(RootReconstructionError::PackageChanged(
            package.display_root.join("version.json"),
        ));
    }
    let decoded = FolderbaseVersion::decode_bounded(version.as_slice())
        .map_err(RootReconstructionError::InvalidVersion)?;
    if decoded
        .canonical_digest()
        .map_err(RootReconstructionError::InvalidVersion)?
        != plan.canonical_version_sha256()
    {
        return Err(RootReconstructionError::PackageChanged(
            package.display_root.join("version.json"),
        ));
    }

    require_exact_entries(
        &package.root,
        &package.display_root,
        &["chunks", "index.json", "manifests", "version.json"]
            .into_iter()
            .map(str::to_owned)
            .collect(),
    )?;
    let manifests_dir = open_package_directory(package, "manifests")?;
    let chunks_dir = open_package_directory(package, "chunks")?;
    let manifests_directory_identity =
        cap_directory_identity(&manifests_dir, &package.display_root.join("manifests"))?;
    let chunks_directory_identity =
        cap_directory_identity(&chunks_dir, &package.display_root.join("chunks"))?;
    let mut manifests = BTreeMap::new();
    let mut manifest_identities = BTreeMap::new();
    let mut manifest_names = BTreeSet::new();
    let mut chunk_names = BTreeSet::new();
    for planned in plan.manifests() {
        let name = format!("{}.json", planned.chunk_manifest_sha256());
        manifest_names.insert(name.clone());
        let (encoded, identity) = read_regular_from_with_identity(
            &manifests_dir,
            &package.display_root.join("manifests").join(&name),
            Path::new(&name),
            MAX_PACKAGE_MANIFEST_BYTES,
        )?;
        manifest_identities.insert(name.clone(), identity);
        let manifest = ChunkManifest::decode_slice_bounded(&encoded).map_err(|source| {
            RootReconstructionError::InvalidManifest {
                chunk_manifest_sha256: planned.chunk_manifest_sha256().to_owned(),
                source,
            }
        })?;
        if manifest.canonical_digest().ok().as_deref() != Some(planned.chunk_manifest_sha256())
            || manifest.object_sha256 != planned.object_sha256()
            || manifest.object_bytes != planned.object_bytes()
            || manifest.chunks.len() != planned.chunk_count()
        {
            return Err(RootReconstructionError::PackageChanged(
                package.display_root.join("manifests").join(name),
            ));
        }
        chunk_names.extend(manifest.chunks.iter().map(|chunk| chunk.sha256.clone()));
        manifests.insert(planned.chunk_manifest_sha256().to_owned(), manifest);
    }
    require_exact_entries(
        &manifests_dir,
        &package.display_root.join("manifests"),
        &manifest_names,
    )?;
    require_exact_entries(
        &chunks_dir,
        &package.display_root.join("chunks"),
        &chunk_names,
    )?;
    let mut chunk_identities = BTreeMap::new();
    for name in &chunk_names {
        let display = package.display_root.join("chunks").join(name);
        let file = open_regular_from(&chunks_dir, &display, Path::new(name))?;
        let metadata = file
            .metadata()
            .map_err(|source| RootReconstructionError::Io {
                path: display.clone(),
                source,
            })?;
        validate_package_regular_metadata(&metadata, &display)?;
        chunk_identities.insert(
            name.clone(),
            PackageRegularIdentity {
                physical: cap_file_identity(&file, &display)?,
                bytes: metadata.len(),
            },
        );
    }
    Ok(ValidatedPackage {
        manifests,
        _manifests_directory: manifests_dir,
        chunks_directory: chunks_dir,
        index_identity,
        version_identity,
        manifests_directory_identity,
        chunks_directory_identity,
        manifest_identities,
        chunk_identities,
    })
}

fn require_same_package_identity(
    package: &RetainedReconstructionPackage,
    expected: &ValidatedPackage,
    actual: &ValidatedPackage,
) -> Result<(), RootReconstructionError> {
    if expected.index_identity != actual.index_identity
        || expected.version_identity != actual.version_identity
        || expected.manifests_directory_identity != actual.manifests_directory_identity
        || expected.chunks_directory_identity != actual.chunks_directory_identity
        || expected.manifest_identities != actual.manifest_identities
        || expected.chunk_identities != actual.chunk_identities
    {
        return Err(RootReconstructionError::PackageChanged(
            package.display_root.clone(),
        ));
    }
    Ok(())
}

fn open_package_directory(
    package: &RetainedReconstructionPackage,
    name: &str,
) -> Result<Dir, RootReconstructionError> {
    let directory =
        package
            .root
            .open_dir_nofollow(name)
            .map_err(|source| RootReconstructionError::Io {
                path: package.display_root.join(name),
                source,
            })?;
    let metadata = directory
        .dir_metadata()
        .map_err(|source| RootReconstructionError::Io {
            path: package.display_root.join(name),
            source,
        })?;
    #[cfg(unix)]
    {
        use cap_std::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o022 != 0 {
            return Err(RootReconstructionError::PackageChanged(
                package.display_root.join(name),
            ));
        }
    }
    Ok(directory)
}

fn require_exact_entries(
    directory: &Dir,
    display: &Path,
    expected: &BTreeSet<String>,
) -> Result<(), RootReconstructionError> {
    let mut actual = BTreeSet::new();
    let maximum_observations = expected.len().saturating_add(1);
    for entry in directory
        .entries()
        .map_err(|source| RootReconstructionError::Io {
            path: display.to_path_buf(),
            source,
        })?
    {
        if actual.len() >= maximum_observations {
            return Err(RootReconstructionError::PackageChanged(
                display.to_path_buf(),
            ));
        }
        let entry = entry.map_err(|source| RootReconstructionError::Io {
            path: display.to_path_buf(),
            source,
        })?;
        let name = entry.file_name();
        if name.as_encoded_bytes().len() > MAX_PATH_COMPONENT_BYTES {
            return Err(RootReconstructionError::PackageChanged(
                display.to_path_buf(),
            ));
        }
        let name = name
            .into_string()
            .map_err(|_| RootReconstructionError::PackageChanged(display.to_path_buf()))?;
        actual.insert(name);
    }
    if &actual == expected {
        Ok(())
    } else {
        Err(RootReconstructionError::PackageChanged(
            display.to_path_buf(),
        ))
    }
}

fn read_package_regular_with_identity(
    package: &RetainedReconstructionPackage,
    relative: &Path,
    maximum: u64,
) -> Result<(Vec<u8>, PhysicalIdentity), RootReconstructionError> {
    read_regular_from_with_identity(
        &package.root,
        &package.display_root.join(relative),
        relative,
        maximum,
    )
}

fn read_regular_from_with_identity(
    directory: &Dir,
    display: &Path,
    relative: &Path,
    maximum: u64,
) -> Result<(Vec<u8>, PhysicalIdentity), RootReconstructionError> {
    let mut file = open_regular_from(directory, display, relative)?;
    let identity = cap_file_identity(&file, display)?;
    let metadata = file
        .metadata()
        .map_err(|source| RootReconstructionError::Io {
            path: display.to_path_buf(),
            source,
        })?;
    validate_package_regular_metadata(&metadata, display)?;
    if metadata.len() > maximum {
        return Err(RootReconstructionError::PackageChanged(
            display.to_path_buf(),
        ));
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|source| RootReconstructionError::Io {
            path: display.to_path_buf(),
            source,
        })?;
    if bytes.len() as u64 > maximum {
        return Err(RootReconstructionError::PackageChanged(
            display.to_path_buf(),
        ));
    }
    let reopened = open_regular_from(directory, display, relative)?;
    let reopened_identity = cap_file_identity(&reopened, display)?;
    let after = reopened
        .metadata()
        .map_err(|source| RootReconstructionError::Io {
            path: display.to_path_buf(),
            source,
        })?;
    validate_package_regular_metadata(&after, display)?;
    if after.len() != metadata.len() || reopened_identity != identity {
        return Err(RootReconstructionError::PackageChanged(
            display.to_path_buf(),
        ));
    }
    Ok((bytes, identity))
}

fn validate_package_regular_metadata(
    metadata: &cap_std::fs::Metadata,
    display: &Path,
) -> Result<(), RootReconstructionError> {
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(RootReconstructionError::PackageChanged(
            display.to_path_buf(),
        ));
    }
    #[cfg(unix)]
    {
        use cap_fs_ext::OsMetadataExt;
        use cap_std::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o022 != 0 || metadata.nlink() != 1 {
            return Err(RootReconstructionError::PackageChanged(
                display.to_path_buf(),
            ));
        }
    }
    Ok(())
}

fn cap_file_identity(
    file: &cap_std::fs::File,
    display: &Path,
) -> Result<PhysicalIdentity, RootReconstructionError> {
    let file = file
        .try_clone()
        .map_err(|source| RootReconstructionError::Io {
            path: display.to_path_buf(),
            source,
        })?
        .into_std();
    PhysicalIdentity::from_file(&file).map_err(|source| RootReconstructionError::Io {
        path: display.to_path_buf(),
        source,
    })
}

fn open_regular_from(
    directory: &Dir,
    display: &Path,
    relative: &Path,
) -> Result<cap_std::fs::File, RootReconstructionError> {
    let leaf = retain_leaf_parent(directory, relative, display)?;
    let mut options = CapOpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    let file = leaf
        .parent
        .open_with(&leaf.name, &options)
        .map_err(|source| RootReconstructionError::Io {
            path: display.to_path_buf(),
            source,
        })?;
    let metadata = file
        .metadata()
        .map_err(|source| RootReconstructionError::Io {
            path: display.to_path_buf(),
            source,
        })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(RootReconstructionError::PackageChanged(
            display.to_path_buf(),
        ));
    }
    Ok(file)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ObservedVisibleKind {
    Directory,
    RegularFile,
    Symlink,
}

fn verify_visible_tree(
    root: &Dir,
    display_root: &Path,
    version: &FolderbaseVersion,
) -> Result<(), RootReconstructionError> {
    let expected = version
        .bindings()
        .iter()
        .map(|binding| (binding.path().to_owned(), binding.kind()))
        .collect::<BTreeMap<_, _>>();
    let mut observed = BTreeMap::new();
    inventory_visible_directory(
        root,
        display_root,
        Path::new(""),
        expected.len(),
        &mut observed,
    )?;
    if observed.len() != expected.len()
        || expected.iter().any(|(path, kind)| {
            observed.get(path).copied()
                != Some(match kind {
                    PathBindingKind::Directory => ObservedVisibleKind::Directory,
                    PathBindingKind::RegularFile => ObservedVisibleKind::RegularFile,
                    PathBindingKind::Symlink => ObservedVisibleKind::Symlink,
                })
        })
    {
        return Err(RootReconstructionError::OperationConflict);
    }

    for binding in version.bindings() {
        let relative = Path::new(binding.path());
        let display = display_root.join(relative);
        let leaf = retain_leaf_parent(root, relative, &display)?;
        match binding.kind() {
            PathBindingKind::Directory => {
                let metadata = leaf.parent.symlink_metadata(&leaf.name).map_err(|source| {
                    RootReconstructionError::Io {
                        path: display,
                        source,
                    }
                })?;
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return Err(RootReconstructionError::OperationConflict);
                }
            }
            PathBindingKind::RegularFile => {
                verify_exact_regular_binding(root, display_root, binding)?;
            }
            PathBindingKind::Symlink => {
                let target = leaf.parent.read_link(&leaf.name).map_err(|source| {
                    RootReconstructionError::Io {
                        path: display,
                        source,
                    }
                })?;
                if target != Path::new(binding.symlink_target().expect("symlink target")) {
                    return Err(RootReconstructionError::OperationConflict);
                }
            }
        }
    }
    Ok(())
}

fn inventory_visible_directory(
    directory: &Dir,
    display_root: &Path,
    relative_directory: &Path,
    maximum: usize,
    observed: &mut BTreeMap<String, ObservedVisibleKind>,
) -> Result<(), RootReconstructionError> {
    let display_directory = display_root.join(relative_directory);
    for entry in directory
        .entries()
        .map_err(|source| RootReconstructionError::Io {
            path: display_directory.clone(),
            source,
        })?
    {
        if observed.len() >= maximum.saturating_add(1) {
            return Err(RootReconstructionError::OperationConflict);
        }
        let entry = entry.map_err(|source| RootReconstructionError::Io {
            path: display_directory.clone(),
            source,
        })?;
        let name = entry.file_name();
        if name.as_encoded_bytes().is_empty()
            || name.as_encoded_bytes().len() > MAX_PATH_COMPONENT_BYTES
        {
            return Err(RootReconstructionError::OperationConflict);
        }
        if relative_directory.as_os_str().is_empty()
            && name.to_str().is_some_and(|name| name == ".folderbase")
        {
            continue;
        }
        let relative = relative_directory.join(&name);
        let path = relative
            .to_str()
            .filter(|path| path.len() <= MAX_PATH_BYTES)
            .ok_or(RootReconstructionError::OperationConflict)?
            .to_owned();
        let metadata =
            directory
                .symlink_metadata(&name)
                .map_err(|source| RootReconstructionError::Io {
                    path: display_root.join(&relative),
                    source,
                })?;
        let kind = if metadata.file_type().is_symlink() {
            ObservedVisibleKind::Symlink
        } else if metadata.is_dir() {
            ObservedVisibleKind::Directory
        } else if metadata.is_file() {
            ObservedVisibleKind::RegularFile
        } else {
            return Err(RootReconstructionError::OperationConflict);
        };
        if observed.insert(path, kind).is_some() {
            return Err(RootReconstructionError::OperationConflict);
        }
        if kind == ObservedVisibleKind::Directory {
            let child = directory.open_dir_nofollow(&name).map_err(|source| {
                RootReconstructionError::Io {
                    path: display_root.join(&relative),
                    source,
                }
            })?;
            inventory_visible_directory(&child, display_root, &relative, maximum, observed)?;
        }
    }
    Ok(())
}

fn verify_exact_regular_binding(
    root: &Dir,
    display_root: &Path,
    binding: &crate::folderbase_version::PathBinding,
) -> Result<(), RootReconstructionError> {
    let relative = Path::new(binding.path());
    let display = display_root.join(relative);
    let mut file = open_regular_from(root, &display, relative)?;
    let expected_bytes = binding.bytes().expect("regular bytes");
    let metadata = file
        .metadata()
        .map_err(|source| RootReconstructionError::Io {
            path: display.clone(),
            source,
        })?;
    let identity = cap_file_identity(&file, &display)?;
    if metadata.len() != expected_bytes
        || regular_is_executable(&metadata) != binding.executable().expect("regular executable")
    {
        return Err(RootReconstructionError::OperationConflict);
    }
    let mut digest = Sha256::new();
    let mut bytes = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    let mut bounded = Read::by_ref(&mut file).take(expected_bytes.saturating_add(1));
    loop {
        let read = bounded
            .read(&mut buffer)
            .map_err(|source| RootReconstructionError::Io {
                path: display.clone(),
                source,
            })?;
        if read == 0 {
            break;
        }
        bytes = bytes.saturating_add(read as u64);
        digest.update(&buffer[..read]);
    }
    if bytes != expected_bytes
        || format!("{:x}", digest.finalize()) != binding.content_sha256().expect("regular digest")
    {
        return Err(RootReconstructionError::OperationConflict);
    }
    let reopened = open_regular_from(root, &display, relative)?;
    let reopened_metadata = reopened
        .metadata()
        .map_err(|source| RootReconstructionError::Io {
            path: display.clone(),
            source,
        })?;
    if cap_file_identity(&reopened, &display)? != identity
        || reopened_metadata.len() != expected_bytes
        || regular_is_executable(&reopened_metadata)
            != binding.executable().expect("regular executable")
    {
        return Err(RootReconstructionError::OperationConflict);
    }
    Ok(())
}

fn regular_is_executable(metadata: &cap_std::fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use cap_std::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        false
    }
}

struct RetainedLeafParent {
    parent: Dir,
    name: OsString,
    parent_display: PathBuf,
    display: PathBuf,
}

fn retain_leaf_parent(
    root: &Dir,
    relative: &Path,
    display: &Path,
) -> Result<RetainedLeafParent, RootReconstructionError> {
    let name = relative
        .file_name()
        .ok_or(RootReconstructionError::InvalidDestination)?
        .to_os_string();
    let mut parent = root
        .try_clone()
        .map_err(|source| RootReconstructionError::Io {
            path: display.to_path_buf(),
            source,
        })?;
    if let Some(ancestors) = relative.parent() {
        for component in ancestors.components() {
            let Component::Normal(component) = component else {
                return Err(RootReconstructionError::InvalidDestination);
            };
            parent = parent.open_dir_nofollow(component).map_err(|source| {
                RootReconstructionError::Io {
                    path: display.to_path_buf(),
                    source,
                }
            })?;
        }
    }
    Ok(RetainedLeafParent {
        parent,
        name,
        parent_display: display.parent().unwrap_or(display).to_path_buf(),
        display: display.to_path_buf(),
    })
}

fn materialize_reconstruction(
    root: &Dir,
    display_root: &Path,
    state: &FolderbaseState,
    local: &LocalVersionStore,
    _package: &RetainedReconstructionPackage,
    plan: &RootReconstructionPlan,
    validated_package: &ValidatedPackage,
) -> Result<ReconstructedHistoryClosure, RootReconstructionError> {
    for binding in plan.version().bindings() {
        if binding.kind() == PathBindingKind::Directory {
            ensure_directory(root, Path::new(binding.path()), display_root)?;
        } else if let Some(parent) = Path::new(binding.path()).parent()
            && !parent.as_os_str().is_empty()
        {
            ensure_directory(root, parent, display_root)?;
        }
    }

    let mut object_paths = BTreeMap::new();
    let mut object_versions = Vec::new();
    for reference in plan.references() {
        let manifest = validated_package
            .manifests
            .get(reference.chunk_manifest_sha256())
            .ok_or(RootReconstructionError::OperationConflict)?;
        let relative = Path::new(RECONSTRUCTION_OBJECTS_DIRECTORY)
            .join(format!("{}.object", reference.object_version_id()));
        write_verified_package_object(root, display_root, &relative, validated_package, manifest)?;
        let mut staged_object = open_regular_from(root, &display_root.join(&relative), &relative)?;
        let installed = local.install_content_reader_in(
            state,
            &mut staged_object,
            &display_root.join(&relative),
            manifest.object_bytes,
        )?;
        if installed.digest != manifest.object_sha256 || installed.bytes != manifest.object_bytes {
            return Err(RootReconstructionError::OperationConflict);
        }
        let object_id = match reference.object_id() {
            Some(value) => ObjectId::parse(value.to_owned())?,
            None => derived_root_object_id(plan)?,
        };
        object_versions.push(LocalVersionRecord {
            id: VersionId::parse(reference.object_version_id().to_owned())?,
            object_id,
            content: installed,
            captured_at: plan.version().created_at().to_owned(),
            extensions: BTreeMap::new(),
        });
        object_paths.insert(reference.object_version_id().to_owned(), relative);
    }

    let root_reference = plan
        .references()
        .iter()
        .find(|reference| {
            reference
                .roles()
                .contains(&ReconstructionReferenceRole::RootManifest)
        })
        .ok_or(RootReconstructionError::OperationConflict)?;
    let root_manifest = validated_package
        .manifests
        .get(root_reference.chunk_manifest_sha256())
        .ok_or(RootReconstructionError::OperationConflict)?;
    copy_verified_stage_object(
        root,
        display_root,
        object_paths
            .get(root_reference.object_version_id())
            .ok_or(RootReconstructionError::OperationConflict)?,
        Path::new(".folderbase/manifest.json"),
        root_manifest,
        false,
    )?;

    for binding in plan.version().bindings() {
        if binding.kind() != PathBindingKind::RegularFile {
            continue;
        }
        let version_id = binding
            .object_version_id()
            .ok_or(RootReconstructionError::OperationConflict)?;
        let reference = plan
            .references()
            .iter()
            .find(|reference| reference.object_version_id() == version_id)
            .ok_or(RootReconstructionError::OperationConflict)?;
        let manifest = validated_package
            .manifests
            .get(reference.chunk_manifest_sha256())
            .ok_or(RootReconstructionError::OperationConflict)?;
        copy_verified_stage_object(
            root,
            display_root,
            object_paths
                .get(version_id)
                .ok_or(RootReconstructionError::OperationConflict)?,
            Path::new(binding.path()),
            manifest,
            binding.executable().unwrap_or(false),
        )?;
    }

    for symlink in plan.derived_symlinks() {
        create_exact_symlink(root, display_root, symlink)?;
        let content = local.install_content_bytes_in(state, symlink.target().as_bytes())?;
        if content.digest != symlink.content_sha256() || content.bytes != symlink.bytes() {
            return Err(RootReconstructionError::OperationConflict);
        }
        object_versions.push(LocalVersionRecord {
            id: VersionId::parse(symlink.object_version_id().to_owned())?,
            object_id: ObjectId::parse(symlink.object_id().to_owned())?,
            content,
            captured_at: plan.version().created_at().to_owned(),
            extensions: BTreeMap::new(),
        });
    }

    let mut projections = Vec::new();
    for binding in plan.version().bindings() {
        if binding.kind() != PathBindingKind::RegularFile {
            continue;
        }
        let object_id = ObjectId::parse(binding.object_id().to_owned())?;
        let version_id = VersionId::parse(
            binding
                .object_version_id()
                .ok_or(RootReconstructionError::OperationConflict)?
                .to_owned(),
        )?;
        projections.push(reconstructed_projection(
            object_id,
            version_id,
            binding.path(),
            plan.version().created_at(),
        ));
    }
    object_versions.sort_by(|left, right| left.id.as_str().cmp(right.id.as_str()));
    projections.sort_by(|left, right| left.id.as_str().cmp(right.id.as_str()));
    let tombstone_associations = plan
        .tombstone_fidelity()
        .iter()
        .map(|fidelity| {
            let record = object_versions
                .iter()
                .find(|record| {
                    record.id.as_str() == fidelity.object_version_id()
                        && record.object_id.as_str() == fidelity.object_id()
                })
                .ok_or(RootReconstructionError::OperationConflict)?;
            Ok(ReconstructedTombstoneAssociation::for_tombstone(
                fidelity.path(),
                fidelity.object_id(),
                fidelity.object_version_id(),
                &record.content.digest,
                record.content.bytes,
                fidelity.executable(),
            ))
        })
        .collect::<Result<Vec<_>, RootReconstructionError>>()?;
    Ok(ReconstructedHistoryClosure {
        object_versions,
        object_projections: projections,
        tombstone_associations,
    })
}

fn reconstructed_projection(
    object_id: ObjectId,
    version_id: VersionId,
    path: &str,
    created_at: &str,
) -> LocalObjectRecord {
    LocalObjectRecord {
        schema: "https://folderbase.ai/protocol/0.1/object.schema.json".to_owned(),
        id: object_id,
        object_type: "file".to_owned(),
        path: path.to_owned(),
        lifecycle: ObjectLifecycle {
            status: "canonical".to_owned(),
            extensions: BTreeMap::new(),
        },
        provenance: ObjectProvenance {
            created_at: created_at.to_owned(),
            source: "folderbase-root-reconstruction".to_owned(),
            extensions: BTreeMap::new(),
        },
        current_version: version_id.clone(),
        versions: vec![version_id],
        extensions: BTreeMap::new(),
    }
}

fn derived_root_object_id(
    plan: &RootReconstructionPlan,
) -> Result<ObjectId, RootReconstructionError> {
    let digest = Sha256::digest(
        format!(
            "folderbase-root-reconstruction-root-object-v1\0{}\0{}",
            plan.version().folderbase_id(),
            plan.version().root_manifest().object_version_id()
        )
        .as_bytes(),
    );
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x70;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    ObjectId::parse(format!("obj_{}", Uuid::from_bytes(bytes).hyphenated())).map_err(Into::into)
}

fn write_verified_package_object(
    root: &Dir,
    display_root: &Path,
    relative: &Path,
    validated_package: &ValidatedPackage,
    manifest: &ChunkManifest,
) -> Result<(), RootReconstructionError> {
    let leaf = retain_leaf_parent(root, relative, &display_root.join(relative))?;
    match leaf.parent.symlink_metadata(&leaf.name) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
            let existing = open_regular_from(root, &leaf.display, relative)?;
            if manifest.verify_object(existing).is_ok() {
                manifest.verify_object(PackageObjectReader::new(validated_package, manifest)?)?;
                return Ok(());
            }
            leaf.parent
                .remove_file(&leaf.name)
                .map_err(|source| RootReconstructionError::Io {
                    path: leaf.display.clone(),
                    source,
                })?;
            sync_retained_directory(&leaf.parent, &leaf.parent_display)?;
        }
        Ok(_) => return Err(RootReconstructionError::OperationConflict),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(RootReconstructionError::Io {
                path: leaf.display.clone(),
                source,
            });
        }
    }
    let mut options = CapOpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .follow(FollowSymlinks::No);
    let mut file = leaf
        .parent
        .open_with(&leaf.name, &options)
        .map_err(|source| RootReconstructionError::Io {
            path: leaf.display.clone(),
            source,
        })?;
    manifest.verify_object_and_copy(
        PackageObjectReader::new(validated_package, manifest)?,
        &mut file,
    )?;
    file.sync_all()
        .map_err(|source| RootReconstructionError::Io {
            path: leaf.display.clone(),
            source,
        })?;
    sync_retained_directory(&leaf.parent, &leaf.parent_display)?;
    manifest.verify_object(open_regular_from(
        root,
        &display_root.join(relative),
        relative,
    )?)?;
    Ok(())
}

fn copy_verified_stage_object(
    root: &Dir,
    display_root: &Path,
    source: &Path,
    destination: &Path,
    manifest: &ChunkManifest,
    executable: bool,
) -> Result<(), RootReconstructionError> {
    let leaf = retain_leaf_parent(root, destination, &display_root.join(destination))?;
    match leaf.parent.symlink_metadata(&leaf.name) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
            let existing = open_regular_from(root, &leaf.display, destination)?;
            if manifest.verify_object(existing).is_ok()
                && regular_is_executable(&metadata) == executable
            {
                return Ok(());
            }
            leaf.parent
                .remove_file(&leaf.name)
                .map_err(|source| RootReconstructionError::Io {
                    path: leaf.display.clone(),
                    source,
                })?;
            sync_retained_directory(&leaf.parent, &leaf.parent_display)?;
        }
        Ok(_) => return Err(RootReconstructionError::OperationConflict),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(RootReconstructionError::Io {
                path: leaf.display.clone(),
                source,
            });
        }
    }
    let mut options = CapOpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .follow(FollowSymlinks::No);
    let mut destination_file = leaf
        .parent
        .open_with(&leaf.name, &options)
        .map_err(|source| RootReconstructionError::Io {
            path: leaf.display.clone(),
            source,
        })?;
    let source_file = open_regular_from(root, &display_root.join(source), source)?;
    manifest.verify_object_and_copy(source_file, &mut destination_file)?;
    set_regular_executable(
        &destination_file,
        executable,
        &display_root.join(destination),
    )?;
    destination_file
        .sync_all()
        .map_err(|source| RootReconstructionError::Io {
            path: leaf.display.clone(),
            source,
        })?;
    sync_retained_directory(&leaf.parent, &leaf.parent_display)?;
    Ok(())
}

fn set_regular_executable(
    file: &cap_std::fs::File,
    executable: bool,
    display: &Path,
) -> Result<(), RootReconstructionError> {
    #[cfg(unix)]
    {
        use cap_std::fs::PermissionsExt;
        let mode = if executable { 0o755 } else { 0o644 };
        file.set_permissions(cap_std::fs::Permissions::from_mode(mode))
            .map_err(|source| RootReconstructionError::Io {
                path: display.to_path_buf(),
                source,
            })?;
    }
    #[cfg(not(unix))]
    let _ = (file, executable, display);
    Ok(())
}

fn create_exact_symlink(
    root: &Dir,
    display_root: &Path,
    symlink: &DerivedSymlink,
) -> Result<(), RootReconstructionError> {
    let relative = Path::new(symlink.path());
    let leaf = retain_leaf_parent(root, relative, &display_root.join(relative))?;
    match leaf.parent.read_link(&leaf.name) {
        Ok(target) if target == Path::new(symlink.target()) => return Ok(()),
        Ok(_) => return Err(RootReconstructionError::OperationConflict),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(RootReconstructionError::Io {
                path: display_root.join(relative),
                source,
            });
        }
    }
    leaf.parent
        .symlink_contents(symlink.target(), &leaf.name)
        .map_err(|source| RootReconstructionError::Io {
            path: leaf.display.clone(),
            source,
        })?;
    sync_retained_directory(&leaf.parent, &leaf.parent_display)?;
    Ok(())
}

fn ensure_directory(
    root: &Dir,
    relative: &Path,
    display_root: &Path,
) -> Result<(), RootReconstructionError> {
    let mut current = root
        .try_clone()
        .map_err(|source| RootReconstructionError::Io {
            path: display_root.to_path_buf(),
            source,
        })?;
    let mut display = display_root.to_path_buf();
    for component in relative.components() {
        let Component::Normal(name) = component else {
            return Err(RootReconstructionError::InvalidDestination);
        };
        display.push(name);
        match current.symlink_metadata(name) {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
            Ok(_) => return Err(RootReconstructionError::OperationConflict),
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                current
                    .create_dir(name)
                    .map_err(|source| RootReconstructionError::Io {
                        path: display.clone(),
                        source,
                    })?;
                sync_retained_directory(&current, &display)?;
            }
            Err(source) => {
                return Err(RootReconstructionError::Io {
                    path: display.clone(),
                    source,
                });
            }
        }
        current =
            current
                .open_dir_nofollow(name)
                .map_err(|source| RootReconstructionError::Io {
                    path: display.clone(),
                    source,
                })?;
    }
    Ok(())
}

struct PackageObjectReader<'a> {
    chunks: Dir,
    display: PathBuf,
    expected_identities: &'a BTreeMap<String, PackageRegularIdentity>,
    descriptors: Vec<(String, u64)>,
    next: usize,
    current: Option<OpenPackageChunk>,
}

struct OpenPackageChunk {
    file: cap_std::fs::File,
    name: String,
    bytes: u64,
    identity: PhysicalIdentity,
}

impl<'a> PackageObjectReader<'a> {
    fn new(
        package: &'a ValidatedPackage,
        manifest: &ChunkManifest,
    ) -> Result<Self, RootReconstructionError> {
        Ok(Self {
            chunks: package.chunks_directory.try_clone().map_err(|source| {
                RootReconstructionError::Io {
                    path: PathBuf::from("chunks"),
                    source,
                }
            })?,
            display: PathBuf::from("chunks"),
            expected_identities: &package.chunk_identities,
            descriptors: manifest
                .chunks
                .iter()
                .map(|chunk| (chunk.sha256.clone(), chunk.bytes))
                .collect(),
            next: 0,
            current: None,
        })
    }

    fn open_next(&mut self) -> std::io::Result<bool> {
        let Some((name, bytes)) = self.descriptors.get(self.next) else {
            return Ok(false);
        };
        let mut options = CapOpenOptions::new();
        options.read(true).follow(FollowSymlinks::No);
        let file = self.chunks.open_with(name, &options)?;
        let metadata = file.metadata()?;
        validate_package_regular_metadata(&metadata, &self.display.join(name))
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        let expected = self
            .expected_identities
            .get(name)
            .ok_or_else(|| std::io::Error::other("package chunk identity is unbound"))?;
        let identity = cap_file_identity(&file, &self.display.join(name)).map_err(|error| {
            std::io::Error::other(format!("package chunk identity failed: {error}"))
        })?;
        if metadata.len() != *bytes
            || metadata.len() != expected.bytes
            || identity != expected.physical
        {
            return Err(std::io::Error::other(format!(
                "package chunk changed: {}",
                self.display.join(name).display()
            )));
        }
        self.current = Some(OpenPackageChunk {
            file,
            name: name.clone(),
            bytes: *bytes,
            identity,
        });
        self.next += 1;
        Ok(true)
    }
}

impl Read for PackageObjectReader<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        loop {
            if self.current.is_none() && !self.open_next()? {
                return Ok(0);
            }
            let read = self
                .current
                .as_mut()
                .expect("opened package chunk")
                .file
                .read(buffer)?;
            if read != 0 {
                return Ok(read);
            }
            let completed = self.current.take().expect("completed package chunk");
            let mut options = CapOpenOptions::new();
            options.read(true).follow(FollowSymlinks::No);
            let reopened = self.chunks.open_with(&completed.name, &options)?;
            let metadata = reopened.metadata()?;
            validate_package_regular_metadata(&metadata, &self.display.join(&completed.name))
                .map_err(|error| std::io::Error::other(error.to_string()))?;
            let identity = cap_file_identity(&reopened, &self.display.join(&completed.name))
                .map_err(|error| std::io::Error::other(error.to_string()))?;
            if metadata.len() != completed.bytes || identity != completed.identity {
                return Err(std::io::Error::other("package chunk changed during read"));
            }
        }
    }
}

/// Decode one closed package index and Version, validate its exact reference
/// and manifest closure, and return a deterministic bounded plan.
pub fn decode_and_plan<IR, VR, MR, MI>(
    index_reader: IR,
    version_reader: VR,
    manifest_inputs: MI,
) -> Result<RootReconstructionPlan, RootReconstructionError>
where
    IR: Read,
    VR: Read,
    MR: Read,
    MI: IntoIterator<Item = ManifestInput<MR>>,
{
    let index_encoded = read_bounded_index(index_reader)?;
    let count: ReferenceCountProbe = serde_json::from_slice(&index_encoded)
        .map_err(RootReconstructionError::InvalidIndexJson)?;
    if count.references.exceeds_maximum {
        return Err(RootReconstructionError::TooManyReferences {
            maximum: MAX_PACKAGE_REFERENCES,
        });
    }
    let index: PackageIndexWire = serde_json::from_slice(&index_encoded)
        .map_err(RootReconstructionError::InvalidIndexJson)?;
    if index.format != PACKAGE_FORMAT_V1 {
        return Err(RootReconstructionError::UnknownFormat);
    }
    if index.limits != PackageLimitsWire::v1() {
        return Err(RootReconstructionError::LimitsMismatch);
    }

    let version_encoded = read_bounded_version(version_reader)?;
    let encoded_version_sha256 = sha256(&version_encoded);
    if index.encoded_version_sha256 != encoded_version_sha256 {
        return Err(RootReconstructionError::EncodedVersionDigestMismatch);
    }
    let version = FolderbaseVersion::decode_bounded(version_encoded.as_slice())
        .map_err(RootReconstructionError::InvalidVersion)?;
    if index.folderbase_id != version.folderbase_id() {
        return Err(RootReconstructionError::FolderbaseIdMismatch);
    }
    if index.folderbase_version_id != version.version_id() {
        return Err(RootReconstructionError::VersionIdMismatch);
    }
    let canonical_version_sha256 = version
        .canonical_digest()
        .map_err(RootReconstructionError::InvalidVersion)?;
    if index.canonical_version_sha256 != canonical_version_sha256 {
        return Err(RootReconstructionError::CanonicalVersionDigestMismatch);
    }
    if version.binding_count() > MAX_VISIBLE_ENTRIES {
        return Err(RootReconstructionError::LimitsMismatch);
    }

    let tombstone_fidelity = validate_tombstone_fidelity(&version, index.tombstone_fidelity)?;
    let (expected, derived_symlinks) = expected_closure(&version);
    let references = validate_references(index.references, &expected)?;
    let expected_manifest_digests = references
        .iter()
        .map(|reference| reference.chunk_manifest_sha256.clone())
        .collect::<BTreeSet<_>>();
    if expected_manifest_digests.len() > MAX_DISTINCT_MANIFESTS {
        return Err(RootReconstructionError::TooManyManifests {
            maximum: MAX_DISTINCT_MANIFESTS,
        });
    }

    let mut manifests = BTreeMap::new();
    let mut distinct_chunks = BTreeSet::new();
    for (position, input) in manifest_inputs.into_iter().enumerate() {
        if position >= MAX_DISTINCT_MANIFESTS {
            return Err(RootReconstructionError::TooManyManifests {
                maximum: MAX_DISTINCT_MANIFESTS,
            });
        }
        let digest = input.chunk_manifest_sha256;
        if !expected_manifest_digests.contains(&digest) {
            return Err(RootReconstructionError::UnreferencedManifest {
                chunk_manifest_sha256: digest,
            });
        }
        if manifests.contains_key(&digest) {
            return Err(RootReconstructionError::DuplicateManifest {
                chunk_manifest_sha256: digest,
            });
        }
        let manifest = ChunkManifest::decode_bounded(input.encoded).map_err(|source| {
            RootReconstructionError::InvalidManifest {
                chunk_manifest_sha256: digest.clone(),
                source,
            }
        })?;
        let canonical = manifest.canonical_digest().map_err(|source| {
            RootReconstructionError::InvalidManifest {
                chunk_manifest_sha256: digest.clone(),
                source: ManifestError::InvalidManifest(source),
            }
        })?;
        if canonical != digest {
            return Err(RootReconstructionError::ManifestDigestMismatch {
                chunk_manifest_sha256: digest,
            });
        }
        for chunk in &manifest.chunks {
            distinct_chunks.insert(chunk.sha256.clone());
            if distinct_chunks.len() > MAX_DISTINCT_CHUNKS {
                return Err(RootReconstructionError::TooManyDistinctChunks {
                    maximum: MAX_DISTINCT_CHUNKS,
                });
            }
        }
        manifests.insert(
            canonical.clone(),
            PlannedManifest {
                chunk_manifest_sha256: canonical,
                object_sha256: manifest.object_sha256,
                object_bytes: manifest.object_bytes,
                chunk_count: manifest.chunks.len(),
            },
        );
    }
    for expected_digest in &expected_manifest_digests {
        if !manifests.contains_key(expected_digest) {
            return Err(RootReconstructionError::MissingManifest {
                chunk_manifest_sha256: expected_digest.clone(),
            });
        }
    }

    let mut total_object_bytes = 0_u64;
    for reference in &references {
        let manifest = &manifests[&reference.chunk_manifest_sha256];
        let expected_object = &expected[&reference.object_version_id];
        if let Some(identity) = &expected_object.authenticated
            && (manifest.object_sha256 != identity.sha256
                || manifest.object_bytes != identity.bytes)
        {
            return Err(RootReconstructionError::ManifestObjectMismatch {
                object_version_id: reference.object_version_id.clone(),
            });
        }
        total_object_bytes = total_object_bytes
            .checked_add(manifest.object_bytes)
            .ok_or(RootReconstructionError::TotalObjectBytesTooLarge {
                maximum: MAX_TOTAL_OBJECT_BYTES,
            })?;
        if total_object_bytes > MAX_TOTAL_OBJECT_BYTES {
            return Err(RootReconstructionError::TotalObjectBytesTooLarge {
                maximum: MAX_TOTAL_OBJECT_BYTES,
            });
        }
    }

    Ok(RootReconstructionPlan {
        package_index_sha256: sha256(&index_encoded),
        encoded_version_sha256,
        canonical_version_sha256,
        version,
        references,
        manifests: manifests.into_values().collect(),
        derived_symlinks,
        tombstone_fidelity,
        distinct_chunk_count: distinct_chunks.len(),
        total_object_bytes,
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PackageIndexWire {
    format: String,
    folderbase_id: String,
    folderbase_version_id: String,
    canonical_version_sha256: String,
    encoded_version_sha256: String,
    limits: PackageLimitsWire,
    references: Vec<ReferenceWire>,
    tombstone_fidelity: Vec<TombstoneFidelityWire>,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct TombstoneFidelityWire {
    path: String,
    object_id: String,
    object_version_id: String,
    executable: bool,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct PackageLimitsWire {
    max_index_bytes: u64,
    max_version_bytes: u64,
    max_manifest_bytes: u64,
    max_references: usize,
    max_distinct_manifests: usize,
    max_distinct_chunks: usize,
    max_chunks_per_manifest: usize,
    max_object_bytes: u64,
    max_total_object_bytes: u64,
    max_visible_entries: usize,
}

impl PackageLimitsWire {
    fn v1() -> Self {
        Self {
            max_index_bytes: MAX_PACKAGE_INDEX_BYTES,
            max_version_bytes: MAX_PACKAGE_VERSION_BYTES,
            max_manifest_bytes: MAX_PACKAGE_MANIFEST_BYTES,
            max_references: MAX_PACKAGE_REFERENCES,
            max_distinct_manifests: MAX_DISTINCT_MANIFESTS,
            max_distinct_chunks: MAX_DISTINCT_CHUNKS,
            max_chunks_per_manifest: MAX_CHUNKS_PER_MANIFEST,
            max_object_bytes: MAX_PACKAGE_OBJECT_BYTES,
            max_total_object_bytes: MAX_TOTAL_OBJECT_BYTES,
            max_visible_entries: MAX_VISIBLE_ENTRIES,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReferenceWire {
    object_version_id: String,
    #[serde(default, deserialize_with = "deserialize_optional_object_id")]
    object_id: OptionalObjectId,
    #[serde(deserialize_with = "deserialize_bounded_roles")]
    roles: Vec<ReferenceRoleWire>,
    chunk_manifest_sha256: String,
}

#[derive(Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum ReferenceRoleWire {
    RootManifest,
    LiveRegularFile,
    RetainedTombstone,
}

#[derive(Default)]
struct OptionalObjectId {
    present: bool,
    value: Option<String>,
}

fn deserialize_optional_object_id<'de, D>(deserializer: D) -> Result<OptionalObjectId, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(OptionalObjectId {
        present: true,
        value: Option::<String>::deserialize(deserializer)?,
    })
}

fn deserialize_bounded_roles<'de, D>(deserializer: D) -> Result<Vec<ReferenceRoleWire>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct RolesVisitor;
    impl<'de> Visitor<'de> for RolesVisitor {
        type Value = Vec<ReferenceRoleWire>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a canonical root-reconstruction role array")
        }

        fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut roles = Vec::with_capacity(2);
            while let Some(role) = sequence.next_element()? {
                if roles.len() == 2 {
                    return Err(serde::de::Error::custom("reference has too many roles"));
                }
                roles.push(role);
            }
            Ok(roles)
        }
    }
    deserializer.deserialize_seq(RolesVisitor)
}

#[derive(Deserialize)]
struct ReferenceCountProbe {
    references: ReferenceCount,
}

struct ReferenceCount {
    exceeds_maximum: bool,
}

impl<'de> Deserialize<'de> for ReferenceCount {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct CountVisitor;
        impl<'de> Visitor<'de> for CountVisitor {
            type Value = ReferenceCount;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a package reference array")
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut count = 0_usize;
                while sequence.next_element::<IgnoredAny>()?.is_some() {
                    count = count.saturating_add(1);
                }
                Ok(ReferenceCount {
                    exceeds_maximum: count > MAX_PACKAGE_REFERENCES,
                })
            }
        }
        deserializer.deserialize_seq(CountVisitor)
    }
}

#[derive(Clone)]
struct ObjectIdentity {
    sha256: String,
    bytes: u64,
}

struct ExpectedObject {
    object_id: Option<String>,
    roles: BTreeSet<ReconstructionReferenceRole>,
    authenticated: Option<ObjectIdentity>,
}

fn expected_closure(
    version: &FolderbaseVersion,
) -> (BTreeMap<String, ExpectedObject>, Vec<DerivedSymlink>) {
    let root = version.root_manifest();
    let mut expected = BTreeMap::from([(
        root.object_version_id().to_owned(),
        ExpectedObject {
            object_id: None,
            roles: BTreeSet::from([ReconstructionReferenceRole::RootManifest]),
            authenticated: Some(ObjectIdentity {
                sha256: root.content_sha256().to_owned(),
                bytes: root.bytes(),
            }),
        },
    )]);
    let mut symlinks = Vec::new();
    for binding in version.bindings() {
        let Some(object_version_id) = binding.object_version_id() else {
            continue;
        };
        match binding.kind() {
            PathBindingKind::Directory => {}
            PathBindingKind::RegularFile => {
                expected.insert(
                    object_version_id.to_owned(),
                    ExpectedObject {
                        object_id: Some(binding.object_id().to_owned()),
                        roles: BTreeSet::from([ReconstructionReferenceRole::LiveRegularFile]),
                        authenticated: Some(ObjectIdentity {
                            sha256: binding.content_sha256().expect("regular digest").to_owned(),
                            bytes: binding.bytes().expect("regular length"),
                        }),
                    },
                );
            }
            PathBindingKind::Symlink => {
                let target = binding.symlink_target().expect("symlink target");
                let identity = ObjectIdentity {
                    sha256: sha256(target.as_bytes()),
                    bytes: target.len() as u64,
                };
                expected.insert(
                    object_version_id.to_owned(),
                    ExpectedObject {
                        object_id: Some(binding.object_id().to_owned()),
                        roles: BTreeSet::new(),
                        authenticated: Some(identity.clone()),
                    },
                );
                symlinks.push(DerivedSymlink {
                    path: binding.path().to_owned(),
                    object_id: binding.object_id().to_owned(),
                    object_version_id: object_version_id.to_owned(),
                    target: target.to_owned(),
                    content_sha256: identity.sha256,
                    bytes: identity.bytes,
                });
            }
        }
    }
    for tombstone in version.tombstones() {
        let Some(object_version_id) = tombstone.last_object_version_id() else {
            continue;
        };
        expected
            .entry(object_version_id.to_owned())
            .and_modify(|object| {
                object
                    .roles
                    .insert(ReconstructionReferenceRole::RetainedTombstone);
            })
            .or_insert_with(|| ExpectedObject {
                object_id: Some(tombstone.object_id().to_owned()),
                roles: BTreeSet::from([ReconstructionReferenceRole::RetainedTombstone]),
                authenticated: None,
            });
    }
    (expected, symlinks)
}

fn validate_tombstone_fidelity(
    version: &FolderbaseVersion,
    supplied: Vec<TombstoneFidelityWire>,
) -> Result<Vec<PlannedTombstoneFidelity>, RootReconstructionError> {
    let expected = version
        .tombstones()
        .iter()
        .filter(|tombstone| tombstone.deleted_kind() == DeletedKind::RegularFile)
        .filter_map(|tombstone| {
            tombstone.last_object_version_id().map(|object_version_id| {
                (tombstone.path(), tombstone.object_id(), object_version_id)
            })
        })
        .collect::<Vec<_>>();
    if supplied.len() != expected.len() {
        return Err(RootReconstructionError::TombstoneFidelityMismatch);
    }
    let mut planned = Vec::with_capacity(supplied.len());
    let mut previous_path: Option<&str> = None;
    for (record, (path, object_id, object_version_id)) in supplied.iter().zip(expected) {
        if previous_path.is_some_and(|previous| previous.as_bytes() >= record.path.as_bytes())
            || record.path != path
            || record.object_id != object_id
            || record.object_version_id != object_version_id
        {
            return Err(RootReconstructionError::TombstoneFidelityMismatch);
        }
        previous_path = Some(&record.path);
        planned.push(PlannedTombstoneFidelity {
            path: record.path.clone(),
            object_id: record.object_id.clone(),
            object_version_id: record.object_version_id.clone(),
            executable: record.executable,
        });
    }
    Ok(planned)
}

fn validate_references(
    references: Vec<ReferenceWire>,
    expected: &BTreeMap<String, ExpectedObject>,
) -> Result<Vec<PlannedObjectReference>, RootReconstructionError> {
    let mut planned = Vec::with_capacity(references.len());
    let mut previous: Option<String> = None;
    let mut observed = BTreeSet::new();
    for reference in references {
        if let Some(previous) = &previous {
            match previous
                .as_bytes()
                .cmp(reference.object_version_id.as_bytes())
            {
                std::cmp::Ordering::Equal => {
                    return Err(RootReconstructionError::DuplicateReference {
                        object_version_id: reference.object_version_id,
                    });
                }
                std::cmp::Ordering::Greater => {
                    return Err(RootReconstructionError::ReferencesOutOfOrder);
                }
                std::cmp::Ordering::Less => {}
            }
        }
        previous = Some(reference.object_version_id.clone());
        let roles = canonical_roles(&reference)?;
        let Some(expected_object) = expected.get(&reference.object_version_id) else {
            return Err(RootReconstructionError::UnexpectedReference {
                object_version_id: reference.object_version_id,
            });
        };
        let expected_roles = expected_object.roles.iter().copied().collect::<Vec<_>>();
        if roles != expected_roles || reference.object_id.value != expected_object.object_id {
            return Err(RootReconstructionError::ReferenceMismatch {
                object_version_id: reference.object_version_id,
            });
        }
        if !is_sha256(&reference.chunk_manifest_sha256) {
            return Err(RootReconstructionError::InvalidManifestDigest {
                object_version_id: reference.object_version_id,
            });
        }
        observed.insert(reference.object_version_id.clone());
        planned.push(PlannedObjectReference {
            object_version_id: reference.object_version_id,
            object_id: reference.object_id.value,
            roles,
            chunk_manifest_sha256: reference.chunk_manifest_sha256,
        });
    }
    for (object_version_id, expected_object) in expected {
        if !expected_object.roles.is_empty() && !observed.contains(object_version_id) {
            return Err(RootReconstructionError::MissingReference {
                object_version_id: object_version_id.clone(),
            });
        }
    }
    Ok(planned)
}

fn canonical_roles(
    reference: &ReferenceWire,
) -> Result<Vec<ReconstructionReferenceRole>, RootReconstructionError> {
    let roles = match reference.roles.as_slice() {
        [ReferenceRoleWire::RootManifest] if !reference.object_id.present => {
            vec![ReconstructionReferenceRole::RootManifest]
        }
        [ReferenceRoleWire::LiveRegularFile] if reference.object_id.value.is_some() => {
            vec![ReconstructionReferenceRole::LiveRegularFile]
        }
        [ReferenceRoleWire::RetainedTombstone] if reference.object_id.value.is_some() => {
            vec![ReconstructionReferenceRole::RetainedTombstone]
        }
        [
            ReferenceRoleWire::LiveRegularFile,
            ReferenceRoleWire::RetainedTombstone,
        ] if reference.object_id.value.is_some() => {
            vec![
                ReconstructionReferenceRole::LiveRegularFile,
                ReconstructionReferenceRole::RetainedTombstone,
            ]
        }
        _ => {
            return Err(RootReconstructionError::InvalidReferenceRoles {
                object_version_id: reference.object_version_id.clone(),
            });
        }
    };
    Ok(roles)
}

fn read_bounded_index(mut reader: impl Read) -> Result<Vec<u8>, RootReconstructionError> {
    let mut encoded = Vec::new();
    reader
        .by_ref()
        .take(MAX_PACKAGE_INDEX_BYTES + 1)
        .read_to_end(&mut encoded)
        .map_err(RootReconstructionError::IndexReader)?;
    if encoded.len() as u64 > MAX_PACKAGE_INDEX_BYTES {
        return Err(RootReconstructionError::IndexTooLarge {
            maximum_bytes: MAX_PACKAGE_INDEX_BYTES,
        });
    }
    Ok(encoded)
}

fn read_bounded_version(mut reader: impl Read) -> Result<Vec<u8>, RootReconstructionError> {
    let mut encoded = Vec::new();
    reader
        .by_ref()
        .take(MAX_PACKAGE_VERSION_BYTES + 1)
        .read_to_end(&mut encoded)
        .map_err(RootReconstructionError::VersionReader)?;
    if encoded.len() as u64 > MAX_PACKAGE_VERSION_BYTES {
        return Err(RootReconstructionError::VersionTooLarge {
            maximum_bytes: MAX_PACKAGE_VERSION_BYTES,
        });
    }
    Ok(encoded)
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn root_reconstruction_request_sha256(
    operation_id: &str,
    package_index_sha256: &str,
) -> Result<String, RootReconstructionError> {
    if !is_sha256(package_index_sha256) {
        return Err(RootReconstructionError::InvalidOperation);
    }
    let operation = operation_id.as_bytes();
    let operation_bytes =
        u32::try_from(operation.len()).map_err(|_| RootReconstructionError::InvalidOperation)?;
    let mut digest = Sha256::new();
    digest.update(b"folderbase-root-reconstruction-request-v1\0");
    digest.update(operation_bytes.to_be_bytes());
    digest.update(operation);
    let mut pin = [0_u8; 32];
    for (index, pair) in package_index_sha256.as_bytes().chunks_exact(2).enumerate() {
        let encoded = std::str::from_utf8(pair)
            .ok()
            .and_then(|value| u8::from_str_radix(value, 16).ok())
            .ok_or(RootReconstructionError::InvalidOperation)?;
        pin[index] = encoded;
    }
    digest.update(pin);
    Ok(format!("{:x}", digest.finalize()))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use std::{
        io::{Cursor, Read as _},
        panic::{AssertUnwindSafe, catch_unwind},
    };

    use serde_json::{Value, json};
    use sha2::{Digest, Sha256};

    use super::{
        COMPLETED_RECONSTRUCTION_PATH, MAX_PACKAGE_INDEX_BYTES, MAX_PACKAGE_MANIFEST_BYTES,
        MAX_PACKAGE_REFERENCES, RetainedReconstructionDestination, RetainedReconstructionPackage,
        RootReconstructionError, RootReconstructionOperation, RootReconstructionPhase,
        execute_root_reconstruction, execute_root_reconstruction_with_phase_callback,
        root_reconstruction_request_sha256, stage_owner_name, stage_proof_name, staged_root_name,
    };
    use super::{ManifestInput, ReconstructionReferenceRole, decode_and_plan};
    use crate::{
        folderbase_version::FolderbaseVersion,
        transfer_manifest::{
            CHUNKING_ALGORITHM_V1, ChunkDescriptor, ChunkManifest, MANIFEST_FORMAT_V1,
            ManifestError, STANDARD_PROFILE_V1,
        },
    };

    const FOLDERBASE_ID: &str = "folderbase_01900000-0000-7000-8000-000000000001";
    const FOLDERBASE_VERSION_ID: &str = "fbversion_01900000-0000-7000-8000-000000000002";
    const ROOT_VERSION_ID: &str = "version_01900000-0000-7000-8000-000000000003";
    const LIVE_VERSION_ID: &str = "version_01900000-0000-7000-8000-000000000004";
    const SYMLINK_VERSION_ID: &str = "version_01900000-0000-7000-8000-000000000005";
    const LIVE_OBJECT_ID: &str = "obj_01900000-0000-7000-8000-000000000006";

    struct Fixture {
        index: Vec<u8>,
        version: Vec<u8>,
        manifests: Vec<ManifestInput<Cursor<Vec<u8>>>>,
    }

    #[test]
    fn complete_package_plans_exact_reference_closure_and_derived_symlink() {
        let fixture = complete_fixture();

        let plan = decode_and_plan(
            fixture.index.as_slice(),
            fixture.version.as_slice(),
            fixture.manifests,
        )
        .expect("complete package should plan");

        assert_eq!(plan.version().folderbase_id(), FOLDERBASE_ID);
        assert_eq!(plan.version().version_id(), FOLDERBASE_VERSION_ID);
        assert_eq!(plan.references().len(), 2);
        assert_eq!(
            plan.references()[1].roles(),
            &[
                ReconstructionReferenceRole::LiveRegularFile,
                ReconstructionReferenceRole::RetainedTombstone,
            ]
        );
        assert_eq!(plan.manifests().len(), 2);
        assert_eq!(plan.derived_symlinks().len(), 1);
        assert_eq!(plan.derived_symlinks()[0].path(), "shortcut");
        assert_eq!(plan.derived_symlinks()[0].target(), "current.txt");
        assert_eq!(
            plan.derived_symlinks()[0].content_sha256(),
            sha256(b"current.txt")
        );
        assert_eq!(plan.derived_symlinks()[0].bytes(), 11);
        assert_eq!(plan.externally_materialized_object_count(), 2);
        assert_eq!(plan.visible_entry_count(), 2);
        assert_eq!(
            plan.total_object_bytes(),
            root_manifest_bytes().len() as u64 + 7
        );
    }

    #[test]
    fn execution_publishes_one_complete_verified_root() {
        let temporary = tempfile::tempdir().expect("temporary root");
        let source = temporary.path().join("package");
        let destination_parent = temporary.path().join("destinations");
        std::fs::create_dir(&source).expect("package root");
        std::fs::create_dir(&destination_parent).expect("destination parent");
        let fixture = complete_fixture();
        write_package(&source, &fixture);
        let plan = plan_from_fixture(&fixture);
        let package = RetainedReconstructionPackage::open(&source).expect("retained package");
        let destination = RetainedReconstructionDestination::open(&destination_parent, "restored")
            .expect("retained absent destination");
        let operation = RootReconstructionOperation::new(
            &plan,
            "reconstruction_01900000-0000-7000-8000-000000000100",
            plan.package_index_sha256(),
        )
        .expect("valid operation");

        let result = execute_root_reconstruction(operation, &package, &destination)
            .expect("root reconstruction");

        let restored = destination_parent.join("restored");
        assert!(!result.replayed());
        assert_eq!(result.attestation().root, restored);
        assert_eq!(
            std::fs::read(restored.join("current.txt")).unwrap(),
            b"payload"
        );
        assert_eq!(
            std::fs::read_link(restored.join("shortcut")).unwrap(),
            std::path::Path::new("current.txt")
        );
        assert_eq!(
            crate::attest_folderbase_root(&restored)
                .expect("published root attests")
                .folderbase_id,
            FOLDERBASE_ID
        );
        let store =
            crate::FolderbaseVersionStore::open(&restored).expect("open reconstructed root");
        assert_eq!(
            store
                .read_version(FOLDERBASE_VERSION_ID)
                .expect("installed Version")
                .canonical_digest()
                .expect("Version digest"),
            plan.canonical_version_sha256()
        );
        let capture = store.plan_capture().expect("follow-up capture plan");
        store
            .seal_capture(capture)
            .expect("follow-up capture remains operational");

        let owner = stage_owner_name("reconstruction_01900000-0000-7000-8000-000000000100");
        let proof = stage_proof_name("reconstruction_01900000-0000-7000-8000-000000000100");
        assert!(!destination_parent.join(owner).exists());
        assert!(!destination_parent.join(proof).exists());
        std::fs::remove_dir_all(&source).expect("transport may disappear after completion");
        let replay = execute_root_reconstruction(
            RootReconstructionOperation::new(
                &plan,
                "reconstruction_01900000-0000-7000-8000-000000000100",
                plan.package_index_sha256(),
            )
            .unwrap(),
            &package,
            &destination,
        )
        .expect("exact replay does not require transport");
        assert!(replay.replayed());
        assert_eq!(replay.attestation().root, restored);

        let occupied = execute_root_reconstruction(
            RootReconstructionOperation::new(
                &plan,
                "reconstruction_01900000-0000-7000-8000-000000000101",
                plan.package_index_sha256(),
            )
            .unwrap(),
            &package,
            &destination,
        );
        assert!(matches!(
            occupied,
            Err(RootReconstructionError::DestinationOccupied(path)) if path == restored
        ));
        assert_eq!(
            std::fs::read(restored.join("current.txt")).unwrap(),
            b"payload"
        );
    }

    #[test]
    fn reconstructed_tombstone_only_history_restores_exact_fidelity() {
        let temporary = tempfile::tempdir().expect("temporary root");
        let source = temporary.path().join("package");
        let destination_parent = temporary.path().join("destinations");
        std::fs::create_dir(&source).expect("package root");
        std::fs::create_dir(&destination_parent).expect("destination parent");
        let fixture = tombstone_only_fixture();
        write_package(&source, &fixture);
        let plan = plan_from_fixture(&fixture);
        let package = RetainedReconstructionPackage::open(&source).expect("retained package");
        let destination = RetainedReconstructionDestination::open(&destination_parent, "restored")
            .expect("retained absent destination");

        execute_root_reconstruction(
            RootReconstructionOperation::new(
                &plan,
                "reconstruction_01900000-0000-7000-8000-000000000102",
                plan.package_index_sha256(),
            )
            .expect("valid operation"),
            &package,
            &destination,
        )
        .expect("root reconstruction");

        let restored = destination_parent.join("restored");
        let store = crate::FolderbaseVersionStore::open(&restored).expect("reopen root");
        store
            .restore_tombstone("previous.txt")
            .expect("retained Tombstone remains restorable without ancestor Versions");
        assert_eq!(
            std::fs::read(restored.join("previous.txt")).unwrap(),
            b"payload"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(restored.join("previous.txt"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o111,
                0
            );
        }
    }

    #[test]
    fn operation_derives_the_normative_request_digest_and_rejects_invalid_identity_or_pin() {
        assert_eq!(
            root_reconstruction_request_sha256(
                "reconstruction_019f0000-0000-7000-8000-000000000001",
                "c646776fc7a7c2f8b3d6320fcb647f19fa2df32f7061ed70944efc5bf13aac28",
            )
            .unwrap(),
            "3c306292ba513818e68b83a09f65a127dca5ae44a892ce7db4485e4f29b45115"
        );
        let fixture = complete_fixture();
        let plan = plan_from_fixture(&fixture);
        let operation = RootReconstructionOperation::new(
            &plan,
            "reconstruction_01900000-0000-7000-8000-000000000100",
            plan.package_index_sha256(),
        )
        .expect("canonical UUID and exact pin");
        assert!(super::is_sha256(operation.request_sha256()));
        assert!(matches!(
            RootReconstructionOperation::new(
                &plan,
                "reconstruction_01900000-0000-7000-8000-000000000100",
                "ab".repeat(32),
            ),
            Err(RootReconstructionError::PackageIndexPinMismatch)
        ));
        assert!(matches!(
            RootReconstructionOperation::new(
                &plan,
                "reconstruction_01900000-0000-9000-8000-000000000100",
                plan.package_index_sha256(),
            ),
            Err(RootReconstructionError::InvalidOperation)
        ));
    }

    #[test]
    fn occupied_destination_and_foreign_private_state_are_preserved() {
        let temporary = tempfile::tempdir().unwrap();
        let source = temporary.path().join("package");
        let parent = temporary.path().join("destinations");
        std::fs::create_dir(&source).unwrap();
        std::fs::create_dir(&parent).unwrap();
        let fixture = complete_fixture();
        write_package(&source, &fixture);
        let plan = plan_from_fixture(&fixture);
        let package = RetainedReconstructionPackage::open(&source).unwrap();

        std::fs::create_dir(parent.join("occupied")).unwrap();
        std::fs::write(parent.join("occupied/keep.txt"), b"keep").unwrap();
        let occupied_destination =
            RetainedReconstructionDestination::open(&parent, "occupied").unwrap();
        let result = execute_root_reconstruction(
            RootReconstructionOperation::new(
                &plan,
                "reconstruction_01900000-0000-7000-8000-000000000110",
                plan.package_index_sha256(),
            )
            .unwrap(),
            &package,
            &occupied_destination,
        );
        assert!(matches!(
            result,
            Err(RootReconstructionError::DestinationOccupied(_))
        ));
        assert_eq!(
            std::fs::read(parent.join("occupied/keep.txt")).unwrap(),
            b"keep"
        );

        let operation_id = "reconstruction_01900000-0000-7000-8000-000000000111";
        let foreign_stage = parent.join(staged_root_name(operation_id));
        std::fs::create_dir(&foreign_stage).unwrap();
        std::fs::write(foreign_stage.join("keep.txt"), b"foreign").unwrap();
        let destination =
            RetainedReconstructionDestination::open(&parent, "foreign-target").unwrap();
        let result = execute_root_reconstruction(
            RootReconstructionOperation::new(&plan, operation_id, plan.package_index_sha256())
                .unwrap(),
            &package,
            &destination,
        );
        assert!(matches!(
            result,
            Err(RootReconstructionError::OperationConflict)
        ));
        assert_eq!(
            std::fs::read(foreign_stage.join("keep.txt")).unwrap(),
            b"foreign"
        );

        let operation_id = "reconstruction_01900000-0000-7000-8000-000000000112";
        let foreign_owner = parent.join(stage_owner_name(operation_id));
        std::fs::write(&foreign_owner, b"foreign-owner").unwrap();
        let destination =
            RetainedReconstructionDestination::open(&parent, "foreign-owner-target").unwrap();
        let result = execute_root_reconstruction(
            RootReconstructionOperation::new(&plan, operation_id, plan.package_index_sha256())
                .unwrap(),
            &package,
            &destination,
        );
        assert!(matches!(
            result,
            Err(RootReconstructionError::OperationConflict)
        ));
        assert_eq!(std::fs::read(foreign_owner).unwrap(), b"foreign-owner");
    }

    #[test]
    fn unsupported_preflight_creates_no_private_stage() {
        let temporary = tempfile::tempdir().unwrap();
        let parent = temporary.path().join("destinations");
        std::fs::create_dir(&parent).unwrap();
        let result = RetainedReconstructionDestination::open_with_preflight(
            &parent,
            std::ffi::OsStr::new("restored"),
            true,
        );
        assert!(matches!(
            result,
            Err(RootReconstructionError::UnsupportedReconstructionFilesystem { .. })
        ));
        assert_eq!(std::fs::read_dir(&parent).unwrap().count(), 0);
    }

    #[test]
    fn exact_owned_stage_rejects_extra_entries_and_repairs_executable_fidelity() {
        let temporary = tempfile::tempdir().unwrap();
        let source = temporary.path().join("package");
        let parent = temporary.path().join("destinations");
        std::fs::create_dir(&source).unwrap();
        std::fs::create_dir(&parent).unwrap();
        let fixture = complete_fixture();
        write_package(&source, &fixture);
        let plan = plan_from_fixture(&fixture);
        let package = RetainedReconstructionPackage::open(&source).unwrap();
        let operation_id = "reconstruction_01900000-0000-7000-8000-000000000120";
        let destination = RetainedReconstructionDestination::open(&parent, "extra-target").unwrap();
        let crash = catch_unwind(AssertUnwindSafe(|| {
            let _ = execute_root_reconstruction_with_phase_callback(
                RootReconstructionOperation::new(&plan, operation_id, plan.package_index_sha256())
                    .unwrap(),
                &package,
                &destination,
                |phase| {
                    if phase == RootReconstructionPhase::PreparedJournal {
                        let stage = parent.join(staged_root_name(operation_id));
                        std::fs::write(stage.join("extra.txt"), b"extra").unwrap();
                        panic!("simulated loss");
                    }
                },
            );
        }));
        assert!(crash.is_err());
        let result = execute_root_reconstruction(
            RootReconstructionOperation::new(&plan, operation_id, plan.package_index_sha256())
                .unwrap(),
            &package,
            &destination,
        );
        assert!(matches!(
            result,
            Err(RootReconstructionError::OperationConflict)
        ));
        assert_eq!(
            std::fs::read(
                parent
                    .join(staged_root_name(operation_id))
                    .join("extra.txt")
            )
            .unwrap(),
            b"extra"
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let operation_id = "reconstruction_01900000-0000-7000-8000-000000000121";
            let destination =
                RetainedReconstructionDestination::open(&parent, "mode-target").unwrap();
            let crash = catch_unwind(AssertUnwindSafe(|| {
                let _ = execute_root_reconstruction_with_phase_callback(
                    RootReconstructionOperation::new(
                        &plan,
                        operation_id,
                        plan.package_index_sha256(),
                    )
                    .unwrap(),
                    &package,
                    &destination,
                    |phase| {
                        if phase == RootReconstructionPhase::VerifiedStaging {
                            let file = parent
                                .join(staged_root_name(operation_id))
                                .join("current.txt");
                            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o755))
                                .unwrap();
                            panic!("simulated loss");
                        }
                    },
                );
            }));
            assert!(crash.is_err());
            let result = execute_root_reconstruction(
                RootReconstructionOperation::new(&plan, operation_id, plan.package_index_sha256())
                    .unwrap(),
                &package,
                &destination,
            )
            .expect("retry repairs exact executable fidelity");
            assert!(!result.replayed());
            assert_eq!(
                std::fs::metadata(parent.join("mode-target/current.txt"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o111,
                0
            );
        }
    }

    #[test]
    fn post_publication_phase_losses_replay_and_retire_only_owned_records() {
        for (suffix, crash_phase) in [
            ("130", RootReconstructionPhase::Publication),
            ("131", RootReconstructionPhase::CompletionDurable),
        ] {
            let temporary = tempfile::tempdir().unwrap();
            let source = temporary.path().join("package");
            let parent = temporary.path().join("destinations");
            std::fs::create_dir(&source).unwrap();
            std::fs::create_dir(&parent).unwrap();
            let fixture = complete_fixture();
            write_package(&source, &fixture);
            let plan = plan_from_fixture(&fixture);
            let package = RetainedReconstructionPackage::open(&source).unwrap();
            let destination = RetainedReconstructionDestination::open(&parent, "restored").unwrap();
            let operation_id = format!("reconstruction_01900000-0000-7000-8000-000000000{suffix}");

            let crashed = catch_unwind(AssertUnwindSafe(|| {
                let _ = execute_root_reconstruction_with_phase_callback(
                    RootReconstructionOperation::new(
                        &plan,
                        &operation_id,
                        plan.package_index_sha256(),
                    )
                    .unwrap(),
                    &package,
                    &destination,
                    |phase| {
                        if phase == crash_phase {
                            panic!("simulated post-publication loss");
                        }
                    },
                );
            }));
            assert!(crashed.is_err());
            assert!(parent.join("restored").is_dir());

            let replay = execute_root_reconstruction(
                RootReconstructionOperation::new(&plan, &operation_id, plan.package_index_sha256())
                    .unwrap(),
                &package,
                &destination,
            )
            .expect("published completion replays");
            assert!(replay.replayed());
            assert!(!parent.join(stage_owner_name(&operation_id)).exists());
            assert!(!parent.join(stage_proof_name(&operation_id)).exists());
        }
    }

    #[test]
    fn durable_owned_stage_entry_without_proof_converges_on_retry() {
        let temporary = tempfile::tempdir().unwrap();
        let source = temporary.path().join("package");
        let parent = temporary.path().join("destinations");
        std::fs::create_dir(&source).unwrap();
        std::fs::create_dir(&parent).unwrap();
        let fixture = complete_fixture();
        write_package(&source, &fixture);
        let plan = plan_from_fixture(&fixture);
        let package = RetainedReconstructionPackage::open(&source).unwrap();
        let destination = RetainedReconstructionDestination::open(&parent, "restored").unwrap();
        let operation_id = "reconstruction_01900000-0000-7000-8000-000000000132";

        let crashed = catch_unwind(AssertUnwindSafe(|| {
            let _ = execute_root_reconstruction_with_phase_callback(
                RootReconstructionOperation::new(&plan, operation_id, plan.package_index_sha256())
                    .unwrap(),
                &package,
                &destination,
                |phase| {
                    if phase == RootReconstructionPhase::StageEntryDurable {
                        panic!("simulated loss after durable stage entry");
                    }
                },
            );
        }));
        assert!(crashed.is_err());
        assert!(!parent.join("restored").exists());

        let recovered = execute_root_reconstruction(
            RootReconstructionOperation::new(&plan, operation_id, plan.package_index_sha256())
                .unwrap(),
            &package,
            &destination,
        )
        .expect("exact owned stage resumes after loss before proof");
        assert!(!recovered.replayed());
        assert!(parent.join("restored").is_dir());
    }

    #[test]
    fn same_byte_package_child_substitution_fails_closed() {
        let temporary = tempfile::tempdir().unwrap();
        let source = temporary.path().join("package");
        let parent = temporary.path().join("destinations");
        std::fs::create_dir(&source).unwrap();
        std::fs::create_dir(&parent).unwrap();
        let fixture = complete_fixture();
        write_package(&source, &fixture);
        let plan = plan_from_fixture(&fixture);
        let package = RetainedReconstructionPackage::open(&source).unwrap();
        let destination = RetainedReconstructionDestination::open(&parent, "restored").unwrap();
        let operation_id = "reconstruction_01900000-0000-7000-8000-000000000133";
        let chunk_name = std::fs::read_dir(source.join("chunks"))
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .file_name();
        let chunk_path = source.join("chunks").join(chunk_name);
        let original = std::fs::read(&chunk_path).unwrap();
        let mut substituted = false;

        let result = execute_root_reconstruction_with_phase_callback(
            RootReconstructionOperation::new(&plan, operation_id, plan.package_index_sha256())
                .unwrap(),
            &package,
            &destination,
            |phase| {
                if phase == RootReconstructionPhase::PreparedJournal && !substituted {
                    std::fs::remove_file(&chunk_path).unwrap();
                    std::fs::write(&chunk_path, &original).unwrap();
                    substituted = true;
                }
            },
        );
        assert!(matches!(
            result,
            Err(RootReconstructionError::PackageChanged(_))
        ));
        assert!(!parent.join("restored").exists());
    }

    #[cfg(unix)]
    #[test]
    fn replay_operational_read_failure_is_not_destination_attention() {
        use std::os::unix::fs::PermissionsExt;

        let temporary = tempfile::tempdir().unwrap();
        let source = temporary.path().join("package");
        let parent = temporary.path().join("destinations");
        std::fs::create_dir(&source).unwrap();
        std::fs::create_dir(&parent).unwrap();
        let fixture = complete_fixture();
        write_package(&source, &fixture);
        let plan = plan_from_fixture(&fixture);
        let package = RetainedReconstructionPackage::open(&source).unwrap();
        let destination = RetainedReconstructionDestination::open(&parent, "restored").unwrap();
        let operation_id = "reconstruction_01900000-0000-7000-8000-000000000134";
        execute_root_reconstruction(
            RootReconstructionOperation::new(&plan, operation_id, plan.package_index_sha256())
                .unwrap(),
            &package,
            &destination,
        )
        .unwrap();

        let completion = parent.join("restored").join(COMPLETED_RECONSTRUCTION_PATH);
        std::fs::set_permissions(&completion, std::fs::Permissions::from_mode(0o000)).unwrap();
        let replay = execute_root_reconstruction(
            RootReconstructionOperation::new(&plan, operation_id, plan.package_index_sha256())
                .unwrap(),
            &package,
            &destination,
        );
        std::fs::set_permissions(&completion, std::fs::Permissions::from_mode(0o600)).unwrap();

        assert!(replay.is_err());
        assert!(!matches!(
            replay,
            Err(RootReconstructionError::DestinationOccupied(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn unsafe_package_permissions_and_hardlink_aliases_fail_before_staging() {
        use std::os::unix::fs::PermissionsExt;

        for (suffix, make_unsafe) in [("140", 0_u8), ("141", 1_u8)] {
            let temporary = tempfile::tempdir().unwrap();
            let source = temporary.path().join("package");
            let parent = temporary.path().join("destinations");
            std::fs::create_dir(&source).unwrap();
            std::fs::create_dir(&parent).unwrap();
            let fixture = complete_fixture();
            write_package(&source, &fixture);
            let plan = plan_from_fixture(&fixture);
            if make_unsafe == 0 {
                std::fs::set_permissions(
                    source.join("index.json"),
                    std::fs::Permissions::from_mode(0o666),
                )
                .unwrap();
            } else {
                let chunk = source.join("chunks").join(sha256(b"payload"));
                std::fs::hard_link(&chunk, temporary.path().join("chunk-alias")).unwrap();
            }
            let package = RetainedReconstructionPackage::open(&source).unwrap();
            let destination = RetainedReconstructionDestination::open(&parent, "restored").unwrap();
            let operation_id = format!("reconstruction_01900000-0000-7000-8000-000000000{suffix}");
            let result = execute_root_reconstruction(
                RootReconstructionOperation::new(&plan, &operation_id, plan.package_index_sha256())
                    .unwrap(),
                &package,
                &destination,
            );
            assert!(matches!(
                result,
                Err(RootReconstructionError::PackageChanged(_))
            ));
            assert!(!parent.join("restored").exists());
            assert!(!parent.join(staged_root_name(&operation_id)).exists());
        }
    }

    #[test]
    fn closure_rejects_missing_root_live_and_retained_tombstone_roles() {
        let mut missing_fidelity = complete_fixture();
        mutate_index(&mut missing_fidelity, |index| {
            index["tombstone_fidelity"] = json!([]);
        });
        assert!(matches!(
            plan(missing_fidelity),
            Err(RootReconstructionError::TombstoneFidelityMismatch)
        ));

        let mut missing_root = complete_fixture();
        mutate_index(&mut missing_root, |index| {
            index["references"]
                .as_array_mut()
                .expect("references")
                .remove(0);
        });
        assert!(matches!(
            plan(missing_root),
            Err(RootReconstructionError::MissingReference { object_version_id })
                if object_version_id == ROOT_VERSION_ID
        ));

        let mut missing_live = complete_fixture();
        mutate_index(&mut missing_live, |index| {
            index["references"]
                .as_array_mut()
                .expect("references")
                .remove(1);
        });
        assert!(matches!(
            plan(missing_live),
            Err(RootReconstructionError::MissingReference { object_version_id })
                if object_version_id == LIVE_VERSION_ID
        ));

        let mut missing_tombstone_role = complete_fixture();
        mutate_index(&mut missing_tombstone_role, |index| {
            index["references"][1]["roles"] = json!(["live_regular_file"]);
        });
        assert!(matches!(
            plan(missing_tombstone_role),
            Err(RootReconstructionError::ReferenceMismatch { object_version_id })
                if object_version_id == LIVE_VERSION_ID
        ));
    }

    #[test]
    fn closure_rejects_duplicate_extra_and_out_of_order_references() {
        let mut duplicate = complete_fixture();
        mutate_index(&mut duplicate, |index| {
            let repeated = index["references"][1].clone();
            index["references"]
                .as_array_mut()
                .expect("references")
                .push(repeated);
        });
        assert!(matches!(
            plan(duplicate),
            Err(RootReconstructionError::DuplicateReference { .. })
        ));

        let mut extra = complete_fixture();
        mutate_index(&mut extra, |index| {
            index["references"]
                .as_array_mut()
                .expect("references")
                .push(json!({
                    "object_version_id": "version_01900000-0000-7000-8000-000000000099",
                    "object_id": "obj_01900000-0000-7000-8000-000000000099",
                    "roles": ["retained_tombstone"],
                    "chunk_manifest_sha256": "99".repeat(32)
                }));
        });
        assert!(matches!(
            plan(extra),
            Err(RootReconstructionError::UnexpectedReference { .. })
        ));

        let mut reordered = complete_fixture();
        mutate_index(&mut reordered, |index| {
            index["references"]
                .as_array_mut()
                .expect("references")
                .swap(0, 1);
        });
        assert!(matches!(
            plan(reordered),
            Err(RootReconstructionError::ReferencesOutOfOrder)
        ));
    }

    #[test]
    fn manifests_must_match_canonical_digest_and_version_digest_and_length() {
        let mut changed_plan = complete_fixture();
        let changed_manifest = manifest(b"changed", 0x33);
        changed_plan.manifests[0].encoded =
            Cursor::new(serde_json::to_vec(&changed_manifest).expect("encode changed manifest"));
        assert!(matches!(
            plan(changed_plan),
            Err(RootReconstructionError::ManifestDigestMismatch { .. })
        ));

        let mut digest_mismatch = complete_fixture();
        let mut changed_digest = manifest(b"payload", 0x22);
        changed_digest.object_sha256 = "aa".repeat(32);
        replace_live_manifest(&mut digest_mismatch, changed_digest);
        assert!(matches!(
            plan(digest_mismatch),
            Err(RootReconstructionError::ManifestObjectMismatch { object_version_id })
                if object_version_id == LIVE_VERSION_ID
        ));

        let mut length_mismatch = complete_fixture();
        let mut changed_length = manifest(b"payload", 0x22);
        changed_length.object_bytes += 1;
        changed_length.chunks[0].bytes += 1;
        replace_live_manifest(&mut length_mismatch, changed_length);
        assert!(matches!(
            plan(length_mismatch),
            Err(RootReconstructionError::ManifestObjectMismatch { object_version_id })
                if object_version_id == LIVE_VERSION_ID
        ));
    }

    #[test]
    fn manifest_set_is_exact_without_missing_duplicate_or_unreferenced_documents() {
        let mut missing = complete_fixture();
        missing.manifests.pop();
        assert!(matches!(
            plan(missing),
            Err(RootReconstructionError::MissingManifest { .. })
        ));

        let mut duplicate = complete_fixture();
        let digest = duplicate.manifests[0].digest().to_owned();
        let encoded = duplicate.manifests[0].encoded.get_ref().clone();
        duplicate
            .manifests
            .push(ManifestInput::new(digest, Cursor::new(encoded)));
        assert!(matches!(
            plan(duplicate),
            Err(RootReconstructionError::DuplicateManifest { .. })
        ));

        let mut extra = complete_fixture();
        let extra_manifest = manifest(b"extra", 0x44);
        let extra_digest = extra_manifest.canonical_digest().expect("valid manifest");
        extra
            .manifests
            .push(manifest_input(extra_digest, extra_manifest));
        assert!(matches!(
            plan(extra),
            Err(RootReconstructionError::UnreferencedManifest { .. })
        ));
    }

    #[test]
    fn fixed_limits_and_encoded_input_bounds_fail_closed() {
        let mut changed_limits = complete_fixture();
        mutate_index(&mut changed_limits, |index| {
            index["limits"]["max_visible_entries"] = json!(16_383);
        });
        assert!(matches!(
            plan(changed_limits),
            Err(RootReconstructionError::LimitsMismatch)
        ));

        let too_many_references = serde_json::to_vec(&json!({
            "references": vec![Value::Null; MAX_PACKAGE_REFERENCES + 1]
        }))
        .expect("encode count probe");
        let empty_manifests: Vec<ManifestInput<Cursor<Vec<u8>>>> = Vec::new();
        assert!(matches!(
            decode_and_plan(
                too_many_references.as_slice(),
                std::io::empty(),
                empty_manifests
            ),
            Err(RootReconstructionError::TooManyReferences { .. })
        ));

        let empty_manifests: Vec<ManifestInput<Cursor<Vec<u8>>>> = Vec::new();
        assert!(matches!(
            decode_and_plan(
                std::io::repeat(b' ').take(MAX_PACKAGE_INDEX_BYTES + 1),
                std::io::empty(),
                empty_manifests
            ),
            Err(RootReconstructionError::IndexTooLarge { .. })
        ));

        let fixture = complete_fixture();
        let oversized_digest = fixture.manifests[0].digest().to_owned();
        let mut boxed_inputs: Vec<ManifestInput<Box<dyn std::io::Read>>> = Vec::new();
        for input in fixture.manifests {
            let reader: Box<dyn std::io::Read> = if input.digest() == oversized_digest {
                Box::new(std::io::repeat(b' ').take(MAX_PACKAGE_MANIFEST_BYTES + 1))
            } else {
                Box::new(input.encoded)
            };
            boxed_inputs.push(ManifestInput::new(input.chunk_manifest_sha256, reader));
        }
        assert!(matches!(
            decode_and_plan(
                fixture.index.as_slice(),
                fixture.version.as_slice(),
                boxed_inputs
            ),
            Err(RootReconstructionError::InvalidManifest {
                source: ManifestError::EncodedManifestTooLarge { .. },
                ..
            })
        ));
    }

    fn complete_fixture() -> Fixture {
        let root_manifest = manifest(&root_manifest_bytes(), 0x11);
        let live_manifest = manifest(b"payload", 0x22);
        let root_manifest_digest = root_manifest.canonical_digest().expect("valid manifest");
        let live_manifest_digest = live_manifest.canonical_digest().expect("valid manifest");
        let version_value = version_json(&root_manifest, &live_manifest);
        let version = serde_json::to_vec(&version_value).expect("encode version");
        let decoded = FolderbaseVersion::decode_bounded(version.as_slice()).expect("valid version");
        let mut references = vec![
            json!({
                "object_version_id": ROOT_VERSION_ID,
                "roles": ["root_manifest"],
                "chunk_manifest_sha256": root_manifest_digest,
            }),
            json!({
                "object_version_id": LIVE_VERSION_ID,
                "object_id": LIVE_OBJECT_ID,
                "roles": ["live_regular_file", "retained_tombstone"],
                "chunk_manifest_sha256": live_manifest_digest,
            }),
        ];
        references.sort_by(|left, right| {
            left["object_version_id"]
                .as_str()
                .expect("object version")
                .as_bytes()
                .cmp(
                    right["object_version_id"]
                        .as_str()
                        .expect("object version")
                        .as_bytes(),
                )
        });
        let index = serde_json::to_vec(&json!({
            "format": "folderbase-root-reconstruction-package-v1",
            "folderbase_id": FOLDERBASE_ID,
            "folderbase_version_id": FOLDERBASE_VERSION_ID,
            "canonical_version_sha256": decoded.canonical_digest().expect("version digest"),
            "encoded_version_sha256": sha256(&version),
            "limits": package_limits(),
            "references": references,
            "tombstone_fidelity": [{
                "path": "previous.txt",
                "object_id": LIVE_OBJECT_ID,
                "object_version_id": LIVE_VERSION_ID,
                "executable": false
            }],
        }))
        .expect("encode index");
        let mut manifests = vec![
            manifest_input(root_manifest_digest, root_manifest),
            manifest_input(live_manifest_digest, live_manifest),
        ];
        manifests.sort_by(|left, right| left.digest().as_bytes().cmp(right.digest().as_bytes()));
        Fixture {
            index,
            version,
            manifests,
        }
    }

    fn tombstone_only_fixture() -> Fixture {
        let root_manifest = manifest(&root_manifest_bytes(), 0x11);
        let retained_manifest = manifest(b"payload", 0x22);
        let root_manifest_digest = root_manifest.canonical_digest().expect("valid manifest");
        let retained_manifest_digest = retained_manifest
            .canonical_digest()
            .expect("valid manifest");
        let mut version_value = version_json(&root_manifest, &retained_manifest);
        version_value["bindings"] = json!([]);
        let version = serde_json::to_vec(&version_value).expect("encode version");
        let decoded = FolderbaseVersion::decode_bounded(version.as_slice()).expect("valid version");
        let mut references = vec![
            json!({
                "object_version_id": ROOT_VERSION_ID,
                "roles": ["root_manifest"],
                "chunk_manifest_sha256": root_manifest_digest,
            }),
            json!({
                "object_version_id": LIVE_VERSION_ID,
                "object_id": LIVE_OBJECT_ID,
                "roles": ["retained_tombstone"],
                "chunk_manifest_sha256": retained_manifest_digest,
            }),
        ];
        references.sort_by(|left, right| {
            left["object_version_id"]
                .as_str()
                .expect("object version")
                .as_bytes()
                .cmp(
                    right["object_version_id"]
                        .as_str()
                        .expect("object version")
                        .as_bytes(),
                )
        });
        let index = serde_json::to_vec(&json!({
            "format": "folderbase-root-reconstruction-package-v1",
            "folderbase_id": FOLDERBASE_ID,
            "folderbase_version_id": FOLDERBASE_VERSION_ID,
            "canonical_version_sha256": decoded.canonical_digest().expect("version digest"),
            "encoded_version_sha256": sha256(&version),
            "limits": package_limits(),
            "references": references,
            "tombstone_fidelity": [{
                "path": "previous.txt",
                "object_id": LIVE_OBJECT_ID,
                "object_version_id": LIVE_VERSION_ID,
                "executable": false
            }],
        }))
        .expect("encode index");
        let mut manifests = vec![
            manifest_input(root_manifest_digest, root_manifest),
            manifest_input(retained_manifest_digest, retained_manifest),
        ];
        manifests.sort_by(|left, right| left.digest().as_bytes().cmp(right.digest().as_bytes()));
        Fixture {
            index,
            version,
            manifests,
        }
    }

    fn plan(fixture: Fixture) -> Result<super::RootReconstructionPlan, RootReconstructionError> {
        decode_and_plan(
            fixture.index.as_slice(),
            fixture.version.as_slice(),
            fixture.manifests,
        )
    }

    fn plan_from_fixture(fixture: &Fixture) -> super::RootReconstructionPlan {
        let manifests = fixture
            .manifests
            .iter()
            .map(|input| {
                ManifestInput::new(input.digest(), Cursor::new(input.encoded.get_ref().clone()))
            })
            .collect::<Vec<_>>();
        decode_and_plan(
            fixture.index.as_slice(),
            fixture.version.as_slice(),
            manifests,
        )
        .expect("complete plan")
    }

    fn write_package(root: &std::path::Path, fixture: &Fixture) {
        std::fs::create_dir(root.join("manifests")).expect("manifest directory");
        std::fs::create_dir(root.join("chunks")).expect("chunk directory");
        std::fs::write(root.join("index.json"), &fixture.index).expect("package index");
        std::fs::write(root.join("version.json"), &fixture.version).expect("package Version");
        for input in &fixture.manifests {
            std::fs::write(
                root.join("manifests")
                    .join(format!("{}.json", input.digest())),
                input.encoded.get_ref(),
            )
            .expect("package manifest");
        }
        for bytes in [root_manifest_bytes(), b"payload".to_vec()] {
            std::fs::write(root.join("chunks").join(sha256(&bytes)), bytes).expect("package chunk");
        }
    }

    fn root_manifest_bytes() -> Vec<u8> {
        serde_json::to_vec_pretty(&json!({
            "$schema": "https://folderbase.ai/protocol/0.5/folderbase.schema.json",
            "protocol_version": "0.5.0",
            "folderbase": {
                "id": FOLDERBASE_ID,
                "name": "Root reconstruction test",
                "kind": "project",
                "status": "active",
                "created_at": "2026-08-06T00:00:00Z"
            },
            "adapters": [],
            "policies": {
                "availability": "keep_local",
                "structural_changes": "approve",
                "archive": "manual",
                "cloud_sync": "disabled",
                "capture_ignore": {
                    "format": "folderbase-capture-ignore-v1",
                    "rules": []
                }
            }
        }))
        .expect("root manifest")
    }

    fn mutate_index(fixture: &mut Fixture, mutate: impl FnOnce(&mut Value)) {
        let mut index: Value = serde_json::from_slice(&fixture.index).expect("decode index");
        mutate(&mut index);
        fixture.index = serde_json::to_vec(&index).expect("encode index");
    }

    fn replace_live_manifest(fixture: &mut Fixture, replacement: ChunkManifest) {
        let replacement_digest = replacement.canonical_digest().expect("valid replacement");
        let mut previous_digest = None;
        mutate_index(fixture, |index| {
            let reference = &mut index["references"][1];
            previous_digest = Some(
                reference["chunk_manifest_sha256"]
                    .as_str()
                    .expect("manifest digest")
                    .to_owned(),
            );
            reference["chunk_manifest_sha256"] = json!(replacement_digest);
        });
        let previous_digest = previous_digest.expect("previous manifest digest");
        fixture
            .manifests
            .retain(|input| input.digest() != previous_digest);
        fixture
            .manifests
            .push(manifest_input(replacement_digest, replacement));
    }

    fn version_json(root_manifest: &ChunkManifest, live_manifest: &ChunkManifest) -> Value {
        json!({
            "format": "folderbase-version-v1",
            "protocol_version": "0.5",
            "folderbase_id": FOLDERBASE_ID,
            "version_id": FOLDERBASE_VERSION_ID,
            "parents": [],
            "created_at": "2026-08-06T00:00:00Z",
            "path_policy": {
                "format": "folderbase-portable-path-v1",
                "normalization": "NFC",
                "normalization_unicode_version": "17.0.0",
                "case_folding": "full-default",
                "case_folding_unicode_version": "9.0.0"
            },
            "root_manifest": {
                "path": ".folderbase/manifest.json",
                "object_version_id": ROOT_VERSION_ID,
                "content_sha256": root_manifest.object_sha256,
                "bytes": root_manifest.object_bytes
            },
            "bindings": [
                {
                    "path": "current.txt",
                    "object_id": LIVE_OBJECT_ID,
                    "lifecycle": "live",
                    "kind": "regular_file",
                    "object_version_id": LIVE_VERSION_ID,
                    "content_sha256": live_manifest.object_sha256,
                    "bytes": live_manifest.object_bytes,
                    "executable": false
                },
                {
                    "path": "shortcut",
                    "object_id": "obj_01900000-0000-7000-8000-000000000007",
                    "lifecycle": "live",
                    "kind": "symlink",
                    "object_version_id": SYMLINK_VERSION_ID,
                    "target": "current.txt",
                    "target_safety": "relative-within-folderbase"
                }
            ],
            "tombstones": [{
                "path": "previous.txt",
                "object_id": LIVE_OBJECT_ID,
                "lifecycle": "deleted",
                "deleted_kind": "regular_file",
                "last_object_version_id": LIVE_VERSION_ID
            }],
            "exclusions": []
        })
    }

    fn package_limits() -> Value {
        json!({
            "max_index_bytes": 8_388_608,
            "max_version_bytes": 67_108_864,
            "max_manifest_bytes": 67_108_864,
            "max_references": 16_385,
            "max_distinct_manifests": 16_385,
            "max_distinct_chunks": 1_048_576,
            "max_chunks_per_manifest": 262_144,
            "max_object_bytes": 1_099_511_627_776_u64,
            "max_total_object_bytes": 9_007_199_254_740_991_u64,
            "max_visible_entries": 16_384
        })
    }

    fn manifest(bytes: &[u8], _chunk_byte: u8) -> ChunkManifest {
        ChunkManifest {
            format: MANIFEST_FORMAT_V1.to_owned(),
            algorithm: CHUNKING_ALGORITHM_V1.to_owned(),
            profile: STANDARD_PROFILE_V1.to_owned(),
            minimum_chunk_bytes: 256 * 1024,
            average_chunk_bytes: 1024 * 1024,
            maximum_chunk_bytes: 4 * 1024 * 1024,
            object_sha256: sha256(bytes),
            object_bytes: bytes.len() as u64,
            chunks: vec![ChunkDescriptor {
                index: 0,
                offset: 0,
                bytes: bytes.len() as u64,
                sha256: sha256(bytes),
            }],
        }
    }

    fn manifest_input(digest: String, manifest: ChunkManifest) -> ManifestInput<Cursor<Vec<u8>>> {
        ManifestInput::new(
            digest,
            Cursor::new(serde_json::to_vec(&manifest).expect("encode manifest")),
        )
    }

    fn sha256(bytes: &[u8]) -> String {
        format!("{:x}", Sha256::digest(bytes))
    }
}

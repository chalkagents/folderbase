//! Read-only planning for a future Folderbase Version capture transaction.
//!
//! This module inventories bounded filesystem metadata. It does not read
//! ordinary file contents, seal a Folderbase Version, mutate Local Head, or
//! write any protocol state.

use std::{
    collections::BTreeMap,
    ffi::OsStr,
    fmt, fs,
    io::{self, Read},
    path::{Component, Path, PathBuf},
};

use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt};
use cap_std::fs::{Dir, Metadata, OpenOptions};
use ignore::{Match, gitignore::GitignoreBuilder};
use same_file::Handle;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use unicode_casefold::UnicodeCaseFold;
use unicode_normalization::UnicodeNormalization;

use crate::{
    FolderbaseError, FolderbaseRootAttestation, RootAttestationError, attest_folderbase_root,
    folderbase_version::{
        FolderbaseVersionError, MAX_OBJECT_BYTES, MAX_VERSION_ENTRIES, validate_capture_path,
        validate_capture_sha256, validate_capture_symlink_targets, validate_capture_version_id,
    },
    traversal_policy::{RECONSTRUCTABLE_DIRECTORIES, is_folderbase_state_component},
};

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
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CaptureMetadataFingerprint {
    pub(crate) bytes: u64,
    pub(crate) modified_unix_nanos: Option<u128>,
    pub(crate) readonly: bool,
    pub(crate) executable: bool,
    pub(crate) device: Option<u64>,
    pub(crate) inode: Option<u64>,
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
        }
    }
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
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalHeadWire {
    format: String,
    folderbase_id: String,
    root_instance_sha256: String,
    version_id: String,
    version_sha256: String,
}

impl CaptureLocalHead {
    pub fn version_id(&self) -> &str {
        &self.version_id
    }

    pub fn version_sha256(&self) -> &str {
        &self.version_sha256
    }
}

/// An opaque, read-only metadata inventory bound to one physical root.
#[derive(Debug)]
pub struct CapturePlan {
    root_attestation: FolderbaseRootAttestation,
    root_manifest_bytes: u64,
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

    #[error("this update requires Tombstone production, which is not implemented yet: {0}")]
    TombstonesRequired(PathBuf),

    #[error("durable capture transaction is invalid: {0}")]
    InvalidCaptureTransaction(String),

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
}

impl FolderbaseVersionStore {
    /// Open one exact, existing Folderbase Root without writing any state.
    pub fn open(root: impl AsRef<Path>) -> Result<Self, FolderbaseCaptureError> {
        let requested_root = root.as_ref();
        let requested_attestation = attest_folderbase_root(requested_root)?;
        let canonical_root =
            requested_root
                .canonicalize()
                .map_err(|source| FolderbaseCaptureError::Io {
                    path: requested_root.to_path_buf(),
                    source,
                })?;
        let root_attestation = attest_folderbase_root(&canonical_root)?;
        if requested_attestation.folderbase_id != root_attestation.folderbase_id
            || requested_attestation.protocol_version != root_attestation.protocol_version
            || requested_attestation.manifest_sha256 != root_attestation.manifest_sha256
            || requested_attestation.root_instance_sha256 != root_attestation.root_instance_sha256
        {
            return Err(RootAttestationError::RootChangedDuringAttestation.into());
        }
        let root_capability = open_planning_root(&canonical_root)?;
        verify_root_capability(&root_capability, &canonical_root)?;
        require_regular_marker(
            &root_capability,
            &canonical_root,
            Path::new(".folderbaseignore"),
        )?;
        read_local_head(&root_attestation, &root_capability)?;
        verify_root_capability(&root_capability, &canonical_root)?;
        Ok(Self { root_attestation })
    }

    /// Plan a bounded metadata inventory without reading ordinary file bytes.
    pub fn plan_capture(&self) -> Result<CapturePlan, FolderbaseCaptureError> {
        let current = attest_folderbase_root(&self.root_attestation.root)?;
        if current.root_instance_sha256 != self.root_attestation.root_instance_sha256 {
            return Err(RootAttestationError::RootChangedDuringAttestation.into());
        }
        let root_capability = open_planning_root(&current.root)?;
        verify_root_capability(&root_capability, &current.root)?;
        require_regular_marker(
            &root_capability,
            &current.root,
            Path::new(".folderbaseignore"),
        )?;
        let root_manifest_bytes = protocol_file_length(
            &root_capability,
            &current.root,
            Path::new(".folderbase/manifest.json"),
        )?;
        let ignore = read_ignore_policy(&root_capability, &current.root)?;
        let current_local_head = read_local_head(&current, &root_capability)?;

        let mut planner = CapturePlanner::new(&current.root, &ignore);
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
        let final_ignore = read_ignore_policy(&root_capability, &current.root)?;
        let final_local_head = read_local_head(&current, &root_capability)?;
        let final_manifest_bytes = protocol_file_length(
            &root_capability,
            &current.root,
            Path::new(".folderbase/manifest.json"),
        )?;
        verify_root_capability(&root_capability, &current.root)?;
        let final_attestation = attest_folderbase_root(&current.root)?;
        if final_local_head != current_local_head
            || final_ignore.sha256 != ignore.sha256
            || final_attestation != current
            || final_manifest_bytes != root_manifest_bytes
        {
            return Err(FolderbaseCaptureError::PlanningStateChanged);
        }

        Ok(CapturePlan {
            root_attestation: current,
            root_manifest_bytes,
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
    entries: Vec<CapturePlanEntry>,
    exclusions: Vec<CapturePlanExclusion>,
    ignored_paths: Vec<CaptureIgnoredPath>,
    path_index: CapturePathIndex,
}

impl<'a> CapturePlanner<'a> {
    fn new(root: &'a Path, ignore: &'a IgnorePolicy) -> Self {
        Self {
            root,
            ignore,
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
        let entries = directory
            .read_dir(".")
            .map_err(|source| FolderbaseCaptureError::Io {
                path: self.root.join(relative_parent),
                source,
            })?;
        for entry in entries {
            let entry = entry.map_err(|source| FolderbaseCaptureError::Io {
                path: self.root.join(relative_parent),
                source,
            })?;
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
                continue;
            }
            if is_folderbase_state_component(&name) {
                return Err(FolderbaseCaptureError::UnsafePortablePath(relative));
            }

            let required_marker = relative == Path::new(".folderbaseignore")
                || relative == Path::new("FOLDERBASE.md");
            if !required_marker
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
                continue;
            }

            self.ensure_capacity(&relative)?;
            let path = portable_relative(&relative)?;
            validate_capture_path(&path)
                .map_err(|_| FolderbaseCaptureError::UnsafePortablePath(relative.clone()))?;
            self.path_index.insert(&path)?;

            if metadata.is_dir() && !metadata.file_type().is_symlink() {
                let (child, identity) = open_stable_child(directory, &name, &display_path)?;
                if is_nested_folderbase(&child, &display_path)? {
                    verify_child_identity(directory, &name, &identity, &display_path)?;
                    self.exclusions.push(CapturePlanExclusion {
                        path,
                        kind: CaptureExclusionKind::NestedFolderbase,
                        reason: CaptureExclusionReason::NestedFolderbaseBoundary,
                    });
                    continue;
                }
                self.entries.push(CapturePlanEntry {
                    path,
                    kind: CaptureEntryKind::Directory,
                    bytes: None,
                    executable: None,
                    symlink_target: None,
                    observed: CaptureMetadataFingerprint::from_cap_metadata(&metadata),
                });
                self.visit_directory(&child, &relative)?;
                verify_child_identity(directory, &name, &identity, &display_path)?;
                continue;
            }

            if let Some(kind) = unsupported_entry_kind(directory, &name, &display_path, &metadata)?
            {
                if required_marker {
                    return Err(FolderbaseCaptureError::RequiredMarker(display_path));
                }
                self.exclusions.push(CapturePlanExclusion {
                    path,
                    kind,
                    reason: CaptureExclusionReason::UnsupportedV1,
                });
                continue;
            }

            let (kind, bytes, executable, symlink_target) = if metadata.file_type().is_symlink() {
                let target = read_stable_symlink(directory, &name, &relative, &display_path)?;
                (CaptureEntryKind::Symlink, None, None, Some(target))
            } else if metadata.is_file() {
                if metadata.len() > MAX_OBJECT_BYTES {
                    return Err(FolderbaseCaptureError::InventoryLimitExceeded {
                        limit: CapturePlanLimitKind::ObjectBytes,
                        maximum: MAX_OBJECT_BYTES,
                        path: relative,
                    });
                }
                (
                    CaptureEntryKind::RegularFile,
                    Some(metadata.len()),
                    Some(is_executable(&metadata)),
                    None,
                )
            } else {
                return Err(FolderbaseCaptureError::PlanningStateChanged);
            };
            self.entries.push(CapturePlanEntry {
                path,
                kind,
                bytes,
                executable,
                symlink_target,
                observed: CaptureMetadataFingerprint::from_cap_metadata(&metadata),
            });
        }
        Ok(())
    }

    fn ensure_capacity(&self, path: &Path) -> Result<(), FolderbaseCaptureError> {
        ensure_record_capacity(
            self.entries.len() + self.exclusions.len() + self.ignored_paths.len(),
            path,
        )
    }
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
fn unsupported_entry_kind(
    _directory: &Dir,
    _name: &OsStr,
    _display_path: &Path,
    metadata: &Metadata,
) -> Result<Option<CaptureExclusionKind>, FolderbaseCaptureError> {
    use cap_std::fs::{FileTypeExt, MetadataExt};

    let file_type = metadata.file_type();
    let kind = if metadata.is_file() && metadata.nlink() > 1 {
        Some(CaptureExclusionKind::HardLink)
    } else if file_type.is_fifo() {
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
    directory: &Dir,
    name: &OsStr,
    display_path: &Path,
    metadata: &Metadata,
) -> Result<Option<CaptureExclusionKind>, FolderbaseCaptureError> {
    use cap_std::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Ok(None);
    }
    let mut options = OpenOptions::new();
    options
        .read(true)
        .access_mode(0)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE);
    let file =
        directory
            .open_with(name, &options)
            .map_err(|source| FolderbaseCaptureError::Io {
                path: display_path.to_path_buf(),
                source,
            })?;
    let information = winapi_util::file::information(file.into_std()).map_err(|source| {
        FolderbaseCaptureError::Io {
            path: display_path.to_path_buf(),
            source,
        }
    })?;
    Ok((information.number_of_links() > 1).then_some(CaptureExclusionKind::HardLink))
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
) -> Result<Handle, FolderbaseCaptureError> {
    let file = directory
        .try_clone()
        .map_err(|source| FolderbaseCaptureError::Io {
            path: display_path.to_path_buf(),
            source,
        })?
        .into_std_file();
    Handle::from_file(file).map_err(|source| FolderbaseCaptureError::Io {
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
) -> Result<(Dir, Handle), FolderbaseCaptureError> {
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
    expected: &Handle,
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
    let head: LocalHeadWire = serde_json::from_slice(&encoded)
        .map_err(|error| FolderbaseCaptureError::InvalidLocalHead(error.to_string()))?;
    if head.format != "folderbase-local-head-v1"
        || head.folderbase_id != attestation.folderbase_id
        || head.root_instance_sha256 != attestation.root_instance_sha256
    {
        return Err(FolderbaseCaptureError::InvalidLocalHead(
            "record does not bind the attested physical Folderbase Root".to_owned(),
        ));
    }
    validate_capture_sha256(&head.root_instance_sha256)
        .map_err(|error| FolderbaseCaptureError::InvalidLocalHead(error.to_string()))?;
    validate_capture_version_id(&head.version_id)
        .map_err(|error| FolderbaseCaptureError::InvalidLocalHead(error.to_string()))?;
    validate_capture_sha256(&head.version_sha256)
        .map_err(|error| FolderbaseCaptureError::InvalidLocalHead(error.to_string()))?;
    Ok(Some(CaptureLocalHead {
        version_id: head.version_id,
        version_sha256: head.version_sha256,
    }))
}

fn is_nested_folderbase(
    directory: &Dir,
    display_path: &Path,
) -> Result<bool, FolderbaseCaptureError> {
    let entry_path = display_path.join("FOLDERBASE.md");
    match directory.symlink_metadata("FOLDERBASE.md") {
        Ok(metadata) => metadata,
        Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(source) => {
            return Err(FolderbaseCaptureError::Io {
                path: entry_path,
                source,
            });
        }
    };
    let state_path = display_path.join(".folderbase");
    let state = match directory.symlink_metadata(".folderbase") {
        Ok(metadata) => metadata,
        Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(source) => {
            return Err(FolderbaseCaptureError::Io {
                path: state_path,
                source,
            });
        }
    };
    if state.file_type().is_symlink() {
        return Ok(true);
    }
    if !state.is_dir() {
        return Ok(false);
    }

    let manifest_path = state_path.join("manifest.json");
    let state_directory = directory
        .open_dir_nofollow(".folderbase")
        .map_err(|source| FolderbaseCaptureError::Io {
            path: state_path,
            source,
        })?;
    match state_directory.symlink_metadata("manifest.json") {
        Ok(_) => Ok(true),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(FolderbaseCaptureError::Io {
            path: manifest_path,
            source,
        }),
    }
}

fn read_ignore_policy(
    root_directory: &Dir,
    root: &Path,
) -> Result<IgnorePolicy, FolderbaseCaptureError> {
    let path = root.join(".folderbaseignore");
    let mut file = open_regular_nofollow(root_directory, Path::new(".folderbaseignore")).map_err(
        |source| FolderbaseCaptureError::Io {
            path: path.clone(),
            source,
        },
    )?;
    let metadata = file
        .metadata()
        .map_err(|source| FolderbaseCaptureError::Io {
            path: path.clone(),
            source,
        })?;
    if metadata.len() > MAX_FOLDERBASEIGNORE_BYTES {
        return Err(FolderbaseCaptureError::IgnorePolicyTooLarge {
            maximum_bytes: MAX_FOLDERBASEIGNORE_BYTES,
        });
    }
    let mut encoded = Vec::new();
    file.by_ref()
        .take(MAX_FOLDERBASEIGNORE_BYTES + 1)
        .read_to_end(&mut encoded)
        .map_err(|source| FolderbaseCaptureError::Io {
            path: path.clone(),
            source,
        })?;
    if encoded.len() as u64 > MAX_FOLDERBASEIGNORE_BYTES {
        return Err(FolderbaseCaptureError::IgnorePolicyTooLarge {
            maximum_bytes: MAX_FOLDERBASEIGNORE_BYTES,
        });
    }
    let policy =
        std::str::from_utf8(&encoded).map_err(|_| FolderbaseCaptureError::IgnorePolicyNotUtf8)?;
    let mut builder = GitignoreBuilder::new(root);
    let mut digest = Sha256::new();
    digest.update(b"folderbase-ignore-policy-v1\0");
    for directory in RECONSTRUCTABLE_DIRECTORIES {
        let pattern = format!("{directory}/");
        builder
            .add_line(None, &pattern)
            .map_err(|error| FolderbaseCaptureError::InvalidIgnorePolicy(error.to_string()))?;
        digest.update(pattern.as_bytes());
        digest.update(b"\n");
    }
    for pattern in [".DS_Store", "*.tmp", "~$*"] {
        builder
            .add_line(None, pattern)
            .map_err(|error| FolderbaseCaptureError::InvalidIgnorePolicy(error.to_string()))?;
        digest.update(pattern.as_bytes());
        digest.update(b"\n");
    }
    digest.update(b"\0");
    digest.update(&encoded);
    for line in policy.lines() {
        builder
            .add_line(Some(path.clone()), line)
            .map_err(|error| FolderbaseCaptureError::InvalidIgnorePolicy(error.to_string()))?;
    }
    let matcher = builder
        .build()
        .map_err(|error| FolderbaseCaptureError::InvalidIgnorePolicy(error.to_string()))?;
    Ok(IgnorePolicy {
        matcher,
        sha256: format!("{:x}", digest.finalize()),
    })
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

fn protocol_file_length(
    root_directory: &Dir,
    root: &Path,
    relative: &Path,
) -> Result<u64, FolderbaseCaptureError> {
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
        .map_err(|source| FolderbaseCaptureError::Io { path, source })?;
    if !metadata.is_file() {
        return Err(FolderbaseCaptureError::RequiredMarker(root.join(relative)));
    }
    Ok(metadata.len())
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
}

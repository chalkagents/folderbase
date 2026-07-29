//! Read-only planning for a future Folderbase Version capture transaction.
//!
//! This module inventories bounded filesystem metadata. It does not read
//! ordinary file contents, seal a Folderbase Version, mutate Local Head, or
//! write any protocol state.

use std::{
    collections::BTreeMap,
    fs,
    io::{self, Read},
    path::{Component, Path, PathBuf},
};

use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt};
use cap_std::{
    ambient_authority,
    fs::{Dir, OpenOptions},
};
use ignore::{Match, gitignore::GitignoreBuilder};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use unicode_casefold::UnicodeCaseFold;
use unicode_normalization::UnicodeNormalization;
use walkdir::WalkDir;

use crate::{
    FolderbaseRootAttestation, RootAttestationError, attest_folderbase_root,
    folderbase_version::{
        MAX_OBJECT_BYTES, MAX_VERSION_ENTRIES, validate_capture_path, validate_capture_sha256,
        validate_capture_symlink_target, validate_capture_version_id,
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

/// Metadata kind observed for a future live Path Binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureExclusionKind {
    NestedFolderbase,
    HardLink,
    Fifo,
    Socket,
    BlockDevice,
    CharacterDevice,
    OtherSpecial,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

    #[error("capture inventory exceeded the {limit:?} limit of {maximum} at {path:?}")]
    InventoryLimitExceeded {
        limit: CapturePlanLimitKind,
        maximum: u64,
        path: Option<PathBuf>,
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
    root_attestation: FolderbaseRootAttestation,
}

impl FolderbaseVersionStore {
    /// Open one exact, existing Folderbase Root without writing any state.
    pub fn open(root: impl AsRef<Path>) -> Result<Self, FolderbaseCaptureError> {
        let root = root
            .as_ref()
            .canonicalize()
            .map_err(|source| FolderbaseCaptureError::Io {
                path: root.as_ref().to_path_buf(),
                source,
            })?;
        let root_attestation = attest_folderbase_root(&root)?;
        require_regular_marker(&root.join(".folderbaseignore"))?;
        read_local_head(&root_attestation)?;
        Ok(Self { root_attestation })
    }

    /// Plan a bounded metadata inventory without reading ordinary file bytes.
    pub fn plan_capture(&self) -> Result<CapturePlan, FolderbaseCaptureError> {
        let current = attest_folderbase_root(&self.root_attestation.root)?;
        require_regular_marker(&current.root.join(".folderbaseignore"))?;
        if current.root_instance_sha256 != self.root_attestation.root_instance_sha256 {
            return Err(RootAttestationError::RootChangedDuringAttestation.into());
        }
        let ignore = read_ignore_policy(&current.root)?;
        let current_local_head = read_local_head(&current)?;

        let mut entries = Vec::new();
        let mut exclusions = Vec::new();
        let mut ignored_paths = Vec::new();
        let mut path_index = CapturePathIndex::default();
        let mut walker = WalkDir::new(&current.root)
            .follow_links(false)
            .sort_by_file_name()
            .into_iter();
        while let Some(entry) = walker.next() {
            let entry = entry.map_err(|error| {
                let path = error
                    .path()
                    .map(Path::to_path_buf)
                    .unwrap_or_else(|| current.root.clone());
                FolderbaseCaptureError::Io {
                    path,
                    source: error
                        .into_io_error()
                        .unwrap_or_else(|| io::Error::other("capture traversal failed")),
                }
            })?;
            if entry.depth() == 0 {
                continue;
            }
            if is_folderbase_state_component(entry.file_name()) {
                if entry.file_type().is_dir() {
                    walker.skip_current_dir();
                }
                continue;
            }
            let relative = entry
                .path()
                .strip_prefix(&current.root)
                .expect("WalkDir entries remain under their root");
            if entry.file_type().is_dir() && is_nested_folderbase(entry.path())? {
                walker.skip_current_dir();
                let path = portable_relative(relative)?;
                validate_capture_path(&path).map_err(|_| {
                    FolderbaseCaptureError::UnsafePortablePath(relative.to_path_buf())
                })?;
                path_index.insert(&path)?;
                ensure_record_capacity(
                    entries.len() + exclusions.len() + ignored_paths.len(),
                    relative,
                )?;
                exclusions.push(CapturePlanExclusion {
                    path,
                    kind: CaptureExclusionKind::NestedFolderbase,
                    reason: CaptureExclusionReason::NestedFolderbaseBoundary,
                });
                continue;
            }
            let required_marker = relative == Path::new(".folderbaseignore")
                || relative == Path::new("FOLDERBASE.md");
            if !required_marker
                && matches!(
                    ignore
                        .matcher
                        .matched(entry.path(), entry.file_type().is_dir()),
                    Match::Ignore(_)
                )
            {
                if entry.file_type().is_dir() {
                    walker.skip_current_dir();
                }
                let path = portable_relative(relative)?;
                ensure_record_capacity(
                    entries.len() + exclusions.len() + ignored_paths.len(),
                    relative,
                )?;
                ignored_paths.push(CaptureIgnoredPath { path });
                continue;
            }
            let path = portable_relative(relative)?;
            validate_capture_path(&path)
                .map_err(|_| FolderbaseCaptureError::UnsafePortablePath(relative.to_path_buf()))?;
            path_index.insert(&path)?;
            let metadata = fs::symlink_metadata(entry.path()).map_err(|source| {
                FolderbaseCaptureError::Io {
                    path: entry.path().to_path_buf(),
                    source,
                }
            })?;
            if let Some(kind) = unsupported_entry_kind(entry.path(), &metadata)? {
                ensure_record_capacity(
                    entries.len() + exclusions.len() + ignored_paths.len(),
                    relative,
                )?;
                exclusions.push(CapturePlanExclusion {
                    path,
                    kind,
                    reason: CaptureExclusionReason::UnsupportedV1,
                });
                continue;
            }
            let (kind, bytes, executable, symlink_target) = if metadata.file_type().is_symlink() {
                let target =
                    fs::read_link(entry.path()).map_err(|source| FolderbaseCaptureError::Io {
                        path: entry.path().to_path_buf(),
                        source,
                    })?;
                let target = target.to_str().ok_or_else(|| {
                    FolderbaseCaptureError::UnsafeSymlinkTarget(relative.to_path_buf())
                })?;
                (
                    CaptureEntryKind::Symlink,
                    None,
                    None,
                    Some(target.to_owned()),
                )
            } else if metadata.is_dir() {
                (CaptureEntryKind::Directory, None, None, None)
            } else if metadata.is_file() {
                if metadata.len() > MAX_OBJECT_BYTES {
                    return Err(FolderbaseCaptureError::InventoryLimitExceeded {
                        limit: CapturePlanLimitKind::ObjectBytes,
                        maximum: MAX_OBJECT_BYTES,
                        path: Some(relative.to_path_buf()),
                    });
                }
                (
                    CaptureEntryKind::RegularFile,
                    Some(metadata.len()),
                    Some(is_executable(&metadata)),
                    None,
                )
            } else {
                continue;
            };
            ensure_record_capacity(
                entries.len() + exclusions.len() + ignored_paths.len(),
                relative,
            )?;
            entries.push(CapturePlanEntry {
                path,
                kind,
                bytes,
                executable,
                symlink_target,
            });
        }
        entries.sort_by(|left, right| left.path.as_bytes().cmp(right.path.as_bytes()));
        exclusions.sort_by(|left, right| left.path.as_bytes().cmp(right.path.as_bytes()));
        ignored_paths.sort_by(|left, right| left.path.as_bytes().cmp(right.path.as_bytes()));
        let nested_boundaries = exclusions
            .iter()
            .filter(|exclusion| exclusion.kind == CaptureExclusionKind::NestedFolderbase)
            .map(|exclusion| exclusion.path.clone())
            .collect::<Vec<_>>();
        for entry in &entries {
            if let Some(target) = &entry.symlink_target {
                validate_capture_symlink_target(&entry.path, target, &nested_boundaries).map_err(
                    |_| FolderbaseCaptureError::UnsafeSymlinkTarget(PathBuf::from(&entry.path)),
                )?;
            }
        }
        let final_ignore = read_ignore_policy(&current.root)?;
        if read_local_head(&current)? != current_local_head || final_ignore.sha256 != ignore.sha256
        {
            return Err(FolderbaseCaptureError::PlanningStateChanged);
        }

        Ok(CapturePlan {
            root_attestation: current,
            current_local_head,
            ignore_policy_sha256: ignore.sha256,
            entries,
            exclusions,
            ignored_paths,
        })
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
fn is_executable(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;

    metadata.permissions().mode() & 0o111 != 0
}

#[cfg(windows)]
fn is_executable(_metadata: &fs::Metadata) -> bool {
    false
}

#[cfg(unix)]
fn unsupported_entry_kind(
    _path: &Path,
    metadata: &fs::Metadata,
) -> Result<Option<CaptureExclusionKind>, FolderbaseCaptureError> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};

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
    path: &Path,
    metadata: &fs::Metadata,
) -> Result<Option<CaptureExclusionKind>, FolderbaseCaptureError> {
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Ok(None);
    }
    let file = fs::File::open(path).map_err(|source| FolderbaseCaptureError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let information =
        winapi_util::file::information(&file).map_err(|source| FolderbaseCaptureError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    Ok((information.number_of_links() > 1).then_some(CaptureExclusionKind::HardLink))
}

fn ensure_record_capacity(current: usize, path: &Path) -> Result<(), FolderbaseCaptureError> {
    if current == MAX_CAPTURE_PLAN_RECORDS {
        return Err(FolderbaseCaptureError::InventoryLimitExceeded {
            limit: CapturePlanLimitKind::Entries,
            maximum: MAX_CAPTURE_PLAN_RECORDS as u64,
            path: Some(path.to_path_buf()),
        });
    }
    Ok(())
}

fn read_local_head(
    attestation: &FolderbaseRootAttestation,
) -> Result<Option<CaptureLocalHead>, FolderbaseCaptureError> {
    let path = attestation.root.join(LOCAL_HEAD_PATH);
    let metadata = match fs::symlink_metadata(&path) {
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
    let mut file = open_regular_nofollow(&attestation.root, Path::new(LOCAL_HEAD_PATH))
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

fn is_nested_folderbase(path: &Path) -> Result<bool, FolderbaseCaptureError> {
    let mut has_entry = false;
    let mut state_paths = Vec::new();
    let entries = fs::read_dir(path).map_err(|source| FolderbaseCaptureError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    for entry in entries {
        let entry = entry.map_err(|source| FolderbaseCaptureError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        let name = entry.file_name();
        if name
            .to_str()
            .is_some_and(|name| name.eq_ignore_ascii_case("FOLDERBASE.md"))
        {
            has_entry = true;
        } else if name
            .to_str()
            .is_some_and(|name| name.eq_ignore_ascii_case(".folderbase"))
        {
            state_paths.push(entry.path());
        }
    }
    if !has_entry {
        return Ok(false);
    }
    for state_path in state_paths {
        let metadata =
            fs::symlink_metadata(&state_path).map_err(|source| FolderbaseCaptureError::Io {
                path: state_path.clone(),
                source,
            })?;
        if metadata.file_type().is_symlink() {
            return Ok(true);
        }
        if !metadata.is_dir() {
            continue;
        }
        let entries = fs::read_dir(&state_path).map_err(|source| FolderbaseCaptureError::Io {
            path: state_path.clone(),
            source,
        })?;
        for entry in entries {
            let entry = entry.map_err(|source| FolderbaseCaptureError::Io {
                path: state_path.clone(),
                source,
            })?;
            if entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.eq_ignore_ascii_case("manifest.json"))
            {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn read_ignore_policy(root: &Path) -> Result<IgnorePolicy, FolderbaseCaptureError> {
    let path = root.join(".folderbaseignore");
    let mut file =
        open_regular_nofollow(root, Path::new(".folderbaseignore")).map_err(|source| {
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

fn require_regular_marker(path: &Path) -> Result<(), FolderbaseCaptureError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| FolderbaseCaptureError::RequiredMarker(path.to_path_buf()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(FolderbaseCaptureError::RequiredMarker(path.to_path_buf()));
    }
    Ok(())
}

fn open_regular_nofollow(root: &Path, relative: &Path) -> io::Result<fs::File> {
    let root = Dir::open_ambient_dir(root, ambient_authority())?;
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    root.open_with(relative, &options)
        .map(|file| file.into_std())
}

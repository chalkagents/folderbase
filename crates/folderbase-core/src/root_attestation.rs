use std::{
    fmt, fs,
    io::{self, Read},
    path::{Path, PathBuf},
};

use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt};
use cap_std::fs::{Dir, OpenOptions};
use chrono::DateTime;
use semver::Version;
use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{self, MapAccess, SeqAccess, Visitor},
    ser::SerializeStruct,
};
use serde_json::{Map, Number, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::physical_identity::PhysicalIdentity;

/// Largest manifest accepted by the root-attestation seam.
pub const MAX_FOLDERBASE_MANIFEST_BYTES: u64 = 16 * 1024 * 1024;

/// Domain separator for the current device-local root-instance digest.
pub const ROOT_INSTANCE_FORMAT_V1: &str = "folderbase-physical-root-instance-v1";
/// Domain separator for full Windows `FILE_ID_INFO` root identity.
pub const ROOT_INSTANCE_FORMAT_V2: &str = "folderbase-physical-root-instance-v2";

const STATE_DIRECTORY: &str = ".folderbase";
const MANIFEST_FILE: &str = "manifest.json";
const ENTRY_FILE: &str = "FOLDERBASE.md";
const DUPLICATE_KEY_SENTINEL: &str = "folderbase_duplicate_json_object_key";
const MAX_CAPTURE_IGNORE_RULES: usize = 1_024;
const MAX_CAPTURE_IGNORE_RULE_BYTES: usize = 4_096;

/// Portable defaults for native 0.5 roots.
///
/// This intentionally differs from the broader legacy reconstructable-directory
/// classifier: 0.5 roots declare their exact portable policy in the manifest.
pub(crate) const DEFAULT_V05_CAPTURE_IGNORE_RULES: &[&str] = &[
    "node_modules/",
    ".next/",
    "dist/",
    "build/",
    "coverage/",
    ".venv/",
    "__pycache__/",
    ".dart_tool/",
    "Pods/",
    ".DS_Store",
    "*.tmp",
    "~$*",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ManifestProtocolProfile {
    LegacyV01V02,
    OrdinaryV05 { capture_ignore_rules: Vec<String> },
}

impl ManifestProtocolProfile {
    pub(crate) fn requires_legacy_root_files(&self) -> bool {
        matches!(self, Self::LegacyV01V02)
    }

    pub(crate) fn folderbase_version_protocol(&self) -> &'static str {
        match self {
            Self::LegacyV01V02 => crate::folderbase_version::VERSION_PROTOCOL_V04,
            Self::OrdinaryV05 { .. } => crate::folderbase_version::VERSION_PROTOCOL_V05,
        }
    }

    pub(crate) fn capture_ignore_rules(&self) -> Option<&[String]> {
        match self {
            Self::LegacyV01V02 => None,
            Self::OrdinaryV05 {
                capture_ignore_rules,
            } => Some(capture_ignore_rules),
        }
    }
}

/// A closed identifier for every marker required by root attestation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FolderbaseRootMarker {
    StateDirectory,
    Manifest,
    Entry,
}

impl FolderbaseRootMarker {
    /// Return the root-relative protocol path represented by this marker.
    pub const fn relative_path(self) -> &'static str {
        match self {
            Self::StateDirectory => STATE_DIRECTORY,
            Self::Manifest => ".folderbase/manifest.json",
            Self::Entry => ENTRY_FILE,
        }
    }
}

impl fmt::Display for FolderbaseRootMarker {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.relative_path())
    }
}

/// Evidence that one exact path is a well-formed Folderbase root.
///
/// `root` is display context only. It is excluded from both SHA-256 values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FolderbaseRootAttestation {
    pub root: PathBuf,
    pub folderbase_id: String,
    pub protocol_version: String,
    pub manifest_sha256: String,
    pub root_instance_sha256: String,
}

impl Serialize for FolderbaseRootAttestation {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut receipt = serializer.serialize_struct("FolderbaseRootAttestation", 5)?;
        receipt.serialize_field("root", self.root.to_string_lossy().as_ref())?;
        receipt.serialize_field("folderbase_id", &self.folderbase_id)?;
        receipt.serialize_field("protocol_version", &self.protocol_version)?;
        receipt.serialize_field("manifest_sha256", &self.manifest_sha256)?;
        receipt.serialize_field("root_instance_sha256", &self.root_instance_sha256)?;
        receipt.end()
    }
}

/// Failures produced while attesting one exact Folderbase root.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RootAttestationError {
    #[error("Folderbase root does not exist: {root}")]
    RootNotFound { root: PathBuf },

    #[error("Folderbase root must not be a symbolic link or reparse point: {root}")]
    RootSymlink { root: PathBuf },

    #[error("Folderbase root is not a directory: {root}")]
    RootNotDirectory { root: PathBuf },

    #[error("required Folderbase marker is missing: {marker}")]
    MarkerMissing { marker: FolderbaseRootMarker },

    #[error("Folderbase marker must not be a symbolic link or reparse point: {marker}")]
    MarkerSymlink { marker: FolderbaseRootMarker },

    #[error("Folderbase marker has the wrong filesystem type: {marker}")]
    MarkerWrongType { marker: FolderbaseRootMarker },

    #[error("Folderbase manifest exceeds the attestation maximum of {maximum_bytes} bytes")]
    ManifestTooLarge { maximum_bytes: u64 },

    #[error("Folderbase manifest is not valid JSON")]
    ManifestInvalidJson,

    #[error("Folderbase manifest contains a duplicate object key")]
    ManifestDuplicateField,

    #[error("Folderbase manifest field is missing: {field}")]
    ManifestFieldMissing { field: &'static str },

    #[error("Folderbase manifest field has the wrong JSON type: {field}")]
    ManifestFieldWrongType { field: &'static str },

    #[error("Folderbase manifest id is not folderbase_<lowercase-hyphenated-UUID>")]
    InvalidFolderbaseId,

    #[error("Folderbase manifest protocol_version is not valid semantic versioning")]
    InvalidProtocolVersion,

    #[error("Folderbase manifest protocol_version is unsupported")]
    UnsupportedProtocolVersion,

    #[error("Folderbase manifest capture-ignore policy is invalid")]
    InvalidCaptureIgnorePolicy,

    #[error("Folderbase manifest does not match the required live 0.5 shape")]
    InvalidManifestShape,

    #[error("Folderbase root identity changed during attestation")]
    RootChangedDuringAttestation,

    #[error("this platform does not expose the physical identity required by root-instance-v1")]
    PhysicalIdentityUnavailable,

    #[error("filesystem I/O failed while attesting {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

impl RootAttestationError {
    /// Stable machine-readable code used by the Folderbase CLI.
    pub const fn code(&self) -> &'static str {
        match self {
            Self::RootNotFound { .. } => "root_not_found",
            Self::RootSymlink { .. } => "root_symlink",
            Self::RootNotDirectory { .. } => "root_not_directory",
            Self::MarkerMissing { .. } => "marker_missing",
            Self::MarkerSymlink { .. } => "marker_symlink",
            Self::MarkerWrongType { .. } => "marker_wrong_type",
            Self::ManifestTooLarge { .. } => "manifest_too_large",
            Self::ManifestInvalidJson => "manifest_invalid_json",
            Self::ManifestDuplicateField => "manifest_duplicate_field",
            Self::ManifestFieldMissing { .. } => "manifest_field_missing",
            Self::ManifestFieldWrongType { .. } => "manifest_field_wrong_type",
            Self::InvalidFolderbaseId => "invalid_folderbase_id",
            Self::InvalidProtocolVersion => "invalid_protocol_version",
            Self::UnsupportedProtocolVersion => "unsupported_protocol_version",
            Self::InvalidCaptureIgnorePolicy => "invalid_capture_ignore_policy",
            Self::InvalidManifestShape => "invalid_manifest_shape",
            Self::RootChangedDuringAttestation => "root_changed_during_attestation",
            Self::PhysicalIdentityUnavailable => "physical_identity_unavailable",
            Self::Io { .. } => "attestation_io",
        }
    }
}

struct OpenedMarker {
    identity: PhysicalIdentity,
    snapshot: FileSnapshot,
    file: fs::File,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RootInstanceAuthority {
    current_sha256: String,
    legacy_v1_sha256: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RootInstanceAdmission<'a> {
    recorded_sha256: &'a str,
    legacy_v1: bool,
}

impl RootInstanceAdmission<'_> {
    pub(crate) fn recorded_sha256(&self) -> &str {
        self.recorded_sha256
    }

    pub(crate) fn is_legacy_v1(&self) -> bool {
        self.legacy_v1
    }
}

impl RootInstanceAuthority {
    pub(crate) fn current_sha256(&self) -> &str {
        &self.current_sha256
    }

    pub(crate) fn admit<'a>(&self, candidate: &'a str) -> Option<RootInstanceAdmission<'a>> {
        if candidate == self.current_sha256 {
            return Some(RootInstanceAdmission {
                recorded_sha256: candidate,
                legacy_v1: false,
            });
        }
        self.legacy_v1_sha256
            .as_deref()
            .filter(|legacy| candidate == *legacy)
            .map(|_| RootInstanceAdmission {
                recorded_sha256: candidate,
                legacy_v1: true,
            })
    }

    #[cfg(test)]
    pub(crate) fn for_test(current_sha256: String, legacy_v1_sha256: Option<String>) -> Self {
        Self {
            current_sha256,
            legacy_v1_sha256,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileSnapshot {
    bytes: u64,
}

impl FileSnapshot {
    fn read(file: &fs::File) -> io::Result<Self> {
        let metadata = file.metadata()?;
        Ok(Self {
            bytes: metadata.len(),
        })
    }
}

/// Attest one exact Folderbase root without writing protocol or ordinary files.
pub fn attest_folderbase_root(
    root: impl AsRef<Path>,
) -> Result<FolderbaseRootAttestation, RootAttestationError> {
    attest_folderbase_root_inner(root.as_ref(), || {})
}

pub(crate) fn attest_folderbase_root_with_profile(
    root: &Path,
) -> Result<
    (
        FolderbaseRootAttestation,
        RootInstanceAuthority,
        ManifestProtocolProfile,
    ),
    RootAttestationError,
> {
    attest_folderbase_root_with_authority_inner(root, || {})
}

fn attest_folderbase_root_inner(
    root: &Path,
    before_final_validation: impl FnOnce(),
) -> Result<FolderbaseRootAttestation, RootAttestationError> {
    attest_folderbase_root_with_authority_inner(root, before_final_validation)
        .map(|(attestation, _, _)| attestation)
}

fn attest_folderbase_root_with_authority_inner(
    root: &Path,
    before_final_validation: impl FnOnce(),
) -> Result<
    (
        FolderbaseRootAttestation,
        RootInstanceAuthority,
        ManifestProtocolProfile,
    ),
    RootAttestationError,
> {
    classify_root(root)?;
    let root_file = open_root_nofollow(root).map_err(|source| RootAttestationError::Io {
        path: root.to_path_buf(),
        source,
    })?;
    let opened_root_metadata = root_file
        .metadata()
        .map_err(|source| RootAttestationError::Io {
            path: root.to_path_buf(),
            source,
        })?;
    if metadata_is_link_or_reparse(&opened_root_metadata) {
        return Err(RootAttestationError::RootSymlink {
            root: root.to_path_buf(),
        });
    }
    if !opened_root_metadata.is_dir() {
        return Err(RootAttestationError::RootNotDirectory {
            root: root.to_path_buf(),
        });
    }
    let root_identity =
        PhysicalIdentity::from_file(&root_file).map_err(|source| RootAttestationError::Io {
            path: root.to_path_buf(),
            source,
        })?;
    let root_instance_authority = root_instance_authority(&root_file, root)?;
    let root_instance_sha256 = root_instance_authority.current_sha256().to_owned();
    let root_dir = Dir::from_std_file(root_file);

    let state_metadata = marker_metadata(
        &root_dir,
        STATE_DIRECTORY,
        FolderbaseRootMarker::StateDirectory,
        root,
    )?;
    if state_metadata.file_type().is_symlink() {
        return Err(RootAttestationError::MarkerSymlink {
            marker: FolderbaseRootMarker::StateDirectory,
        });
    }
    if !state_metadata.is_dir() {
        return Err(RootAttestationError::MarkerWrongType {
            marker: FolderbaseRootMarker::StateDirectory,
        });
    }
    let state_dir = root_dir
        .open_dir_nofollow(STATE_DIRECTORY)
        .map_err(|source| marker_open_error(root, FolderbaseRootMarker::StateDirectory, source))?;
    let state_file = state_dir
        .try_clone()
        .map_err(|source| RootAttestationError::Io {
            path: root.join(STATE_DIRECTORY),
            source,
        })?
        .into_std_file();
    let opened_state_metadata =
        state_file
            .metadata()
            .map_err(|source| RootAttestationError::Io {
                path: root.join(STATE_DIRECTORY),
                source,
            })?;
    if metadata_is_link_or_reparse(&opened_state_metadata) {
        return Err(RootAttestationError::MarkerSymlink {
            marker: FolderbaseRootMarker::StateDirectory,
        });
    }
    if !opened_state_metadata.is_dir() {
        return Err(RootAttestationError::MarkerWrongType {
            marker: FolderbaseRootMarker::StateDirectory,
        });
    }
    let state_identity =
        PhysicalIdentity::from_file(&state_file).map_err(|source| RootAttestationError::Io {
            path: root.join(STATE_DIRECTORY),
            source,
        })?;

    let mut manifest = open_regular_marker(
        &state_dir,
        MANIFEST_FILE,
        FolderbaseRootMarker::Manifest,
        root,
    )?;
    if manifest.snapshot.bytes > MAX_FOLDERBASE_MANIFEST_BYTES {
        return Err(RootAttestationError::ManifestTooLarge {
            maximum_bytes: MAX_FOLDERBASE_MANIFEST_BYTES,
        });
    }
    let manifest_bytes = read_manifest_bounded(&mut manifest.file, root)?;
    if FileSnapshot::read(&manifest.file).map_err(|source| RootAttestationError::Io {
        path: root.join(FolderbaseRootMarker::Manifest.relative_path()),
        source,
    })? != manifest.snapshot
    {
        return Err(RootAttestationError::RootChangedDuringAttestation);
    }

    let (_, folderbase_id, protocol_version, protocol_profile) =
        decode_manifest_protocol_profile(&manifest_bytes)?;
    let entry = if !protocol_profile.requires_legacy_root_files() {
        None
    } else {
        Some(open_regular_marker(
            &root_dir,
            ENTRY_FILE,
            FolderbaseRootMarker::Entry,
            root,
        )?)
    };
    let manifest_sha256 = hex_sha256(&manifest_bytes);

    before_final_validation();

    let reopened_root = revalidate_root(root, &root_identity)?;
    let reopened_state = revalidate_directory(
        &reopened_root,
        STATE_DIRECTORY,
        FolderbaseRootMarker::StateDirectory,
        &state_identity,
    )?;
    revalidate_manifest(
        &reopened_state,
        MANIFEST_FILE,
        FolderbaseRootMarker::Manifest,
        &manifest.identity,
        &manifest_sha256,
        root,
    )?;
    if let Some(entry) = entry {
        revalidate_file(
            &reopened_root,
            ENTRY_FILE,
            FolderbaseRootMarker::Entry,
            &entry.identity,
            Some(&entry.snapshot),
            root,
        )?;
    }

    Ok((
        FolderbaseRootAttestation {
            root: root.to_path_buf(),
            folderbase_id,
            protocol_version,
            manifest_sha256,
            root_instance_sha256,
        },
        root_instance_authority,
        protocol_profile,
    ))
}

pub(crate) fn decode_manifest_protocol_profile(
    encoded: &[u8],
) -> Result<(Value, String, String, ManifestProtocolProfile), RootAttestationError> {
    let manifest = decode_unique_json(encoded)?;
    let (folderbase_id, protocol_version) = required_manifest_fields(&manifest)?;
    validate_folderbase_id(&folderbase_id)?;
    let version = Version::parse(&protocol_version)
        .map_err(|_| RootAttestationError::InvalidProtocolVersion)?;
    let profile = manifest_protocol_profile(&manifest, &version)?;
    Ok((manifest, folderbase_id, protocol_version, profile))
}

fn manifest_protocol_profile(
    manifest: &Value,
    version: &Version,
) -> Result<ManifestProtocolProfile, RootAttestationError> {
    if version.major == 0 && matches!(version.minor, 1 | 2) {
        return Ok(ManifestProtocolProfile::LegacyV01V02);
    }
    if version != &Version::new(0, 5, 0) {
        return Err(RootAttestationError::UnsupportedProtocolVersion);
    }
    validate_ordinary_manifest_shape(manifest)?;
    let policy = manifest
        .pointer("/policies/capture_ignore")
        .and_then(Value::as_object)
        .ok_or(RootAttestationError::InvalidCaptureIgnorePolicy)?;
    if policy.len() != 2 || !policy.contains_key("format") || !policy.contains_key("rules") {
        return Err(RootAttestationError::InvalidCaptureIgnorePolicy);
    }
    if policy.get("format").and_then(Value::as_str) != Some("folderbase-capture-ignore-v1") {
        return Err(RootAttestationError::InvalidCaptureIgnorePolicy);
    }
    let rules = policy
        .get("rules")
        .and_then(Value::as_array)
        .ok_or(RootAttestationError::InvalidCaptureIgnorePolicy)?;
    if rules.len() > MAX_CAPTURE_IGNORE_RULES {
        return Err(RootAttestationError::InvalidCaptureIgnorePolicy);
    }
    let capture_ignore_rules = rules
        .iter()
        .map(|rule| {
            let rule = rule
                .as_str()
                .ok_or(RootAttestationError::InvalidCaptureIgnorePolicy)?;
            if rule.is_empty()
                || rule.len() > MAX_CAPTURE_IGNORE_RULE_BYTES
                || rule.as_bytes().contains(&0)
            {
                return Err(RootAttestationError::InvalidCaptureIgnorePolicy);
            }
            Ok(rule.to_owned())
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ManifestProtocolProfile::OrdinaryV05 {
        capture_ignore_rules,
    })
}

fn validate_ordinary_manifest_shape(manifest: &Value) -> Result<(), RootAttestationError> {
    let record = manifest
        .as_object()
        .ok_or(RootAttestationError::InvalidManifestShape)?;
    if record.get("$schema").is_some_and(|schema| {
        schema.as_str() != Some("https://folderbase.ai/protocol/0.5/folderbase.schema.json")
    }) {
        return Err(RootAttestationError::InvalidManifestShape);
    }
    let folderbase = record
        .get("folderbase")
        .and_then(Value::as_object)
        .ok_or(RootAttestationError::InvalidManifestShape)?;
    let valid_nonempty = |key: &str| {
        folderbase
            .get(key)
            .and_then(Value::as_str)
            .is_some_and(|value| !value.is_empty())
    };
    if !valid_nonempty("name")
        || !matches!(
            folderbase.get("kind").and_then(Value::as_str),
            Some(
                "person"
                    | "organization"
                    | "engagement"
                    | "project"
                    | "customer"
                    | "temporary"
                    | "custom"
            )
        )
        || !matches!(
            folderbase.get("status").and_then(Value::as_str),
            Some("active" | "paused" | "archived")
        )
        || folderbase
            .get("created_at")
            .and_then(Value::as_str)
            .is_none_or(|created_at| DateTime::parse_from_rfc3339(created_at).is_err())
        || folderbase
            .get("template_provenance")
            .is_some_and(|value| !value.is_object())
    {
        return Err(RootAttestationError::InvalidManifestShape);
    }

    let policies = record
        .get("policies")
        .and_then(Value::as_object)
        .ok_or(RootAttestationError::InvalidManifestShape)?;
    if !matches!(
        policies.get("availability").and_then(Value::as_str),
        Some("keep_local" | "managed" | "cloud_only")
    ) || !matches!(
        policies.get("structural_changes").and_then(Value::as_str),
        Some("suggest" | "approve" | "autonomous")
    ) || !matches!(
        policies.get("archive").and_then(Value::as_str),
        Some("manual" | "approve" | "automatic")
    ) || !matches!(
        policies.get("cloud_sync").and_then(Value::as_str),
        Some("disabled" | "enabled")
    ) {
        return Err(RootAttestationError::InvalidManifestShape);
    }

    if let Some(adapters) = record.get("adapters") {
        let adapters = adapters
            .as_array()
            .ok_or(RootAttestationError::InvalidManifestShape)?;
        for adapter in adapters {
            let adapter = adapter
                .as_object()
                .ok_or(RootAttestationError::InvalidManifestShape)?;
            let agent = adapter
                .get("agent")
                .and_then(Value::as_str)
                .ok_or(RootAttestationError::InvalidManifestShape)?;
            let mut agent_bytes = agent.bytes();
            if !agent_bytes
                .next()
                .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
                || !agent_bytes.all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b'_' | b'-')
                })
            {
                return Err(RootAttestationError::InvalidManifestShape);
            }
            let path = adapter
                .get("path")
                .and_then(Value::as_str)
                .ok_or(RootAttestationError::InvalidManifestShape)?;
            if crate::folderbase_version::validate_capture_path(path).is_err()
                || Path::new(path)
                    .components()
                    .filter_map(|component| match component {
                        std::path::Component::Normal(name) => Some(name),
                        _ => None,
                    })
                    .any(crate::traversal_policy::is_reserved_workspace_component)
            {
                return Err(RootAttestationError::InvalidManifestShape);
            }
        }
    }
    Ok(())
}

fn classify_root(root: &Path) -> Result<(), RootAttestationError> {
    let metadata = fs::symlink_metadata(root).map_err(|source| {
        if source.kind() == io::ErrorKind::NotFound {
            RootAttestationError::RootNotFound {
                root: root.to_path_buf(),
            }
        } else {
            RootAttestationError::Io {
                path: root.to_path_buf(),
                source,
            }
        }
    })?;
    if metadata_is_link_or_reparse(&metadata) {
        return Err(RootAttestationError::RootSymlink {
            root: root.to_path_buf(),
        });
    }
    if !metadata.is_dir() {
        return Err(RootAttestationError::RootNotDirectory {
            root: root.to_path_buf(),
        });
    }
    Ok(())
}

pub(crate) fn metadata_is_link_or_reparse(metadata: &fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }

    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;

        return windows_attributes_are_reparse(metadata.file_attributes());
    }

    #[cfg(not(windows))]
    false
}

#[cfg(any(windows, test))]
pub(crate) const fn windows_attributes_are_reparse(attributes: u32) -> bool {
    const FILE_ATTRIBUTE_REPARSE_POINT_VALUE: u32 = 0x0000_0400;

    attributes & FILE_ATTRIBUTE_REPARSE_POINT_VALUE != 0
}

fn marker_metadata(
    directory: &Dir,
    name: &str,
    marker: FolderbaseRootMarker,
    root: &Path,
) -> Result<cap_std::fs::Metadata, RootAttestationError> {
    directory
        .symlink_metadata(name)
        .map_err(|source| marker_open_error(root, marker, source))
}

fn open_root_nofollow(path: &Path) -> io::Result<fs::File> {
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
            FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
            FILE_SHARE_WRITE,
        };

        options
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE);
    }
    options.open(path)
}

fn marker_open_error(
    root: &Path,
    marker: FolderbaseRootMarker,
    source: io::Error,
) -> RootAttestationError {
    if source.kind() == io::ErrorKind::NotFound {
        RootAttestationError::MarkerMissing { marker }
    } else {
        RootAttestationError::Io {
            path: root.join(marker.relative_path()),
            source,
        }
    }
}

fn open_regular_marker(
    directory: &Dir,
    name: &str,
    marker: FolderbaseRootMarker,
    root: &Path,
) -> Result<OpenedMarker, RootAttestationError> {
    let metadata = marker_metadata(directory, name, marker, root)?;
    if metadata.file_type().is_symlink() {
        return Err(RootAttestationError::MarkerSymlink { marker });
    }
    if !metadata.is_file() {
        if metadata.is_dir() {
            let opened_directory = directory
                .open_dir_nofollow(name)
                .map_err(|source| marker_open_error(root, marker, source))?;
            let opened_file = opened_directory
                .try_clone()
                .map_err(|source| RootAttestationError::Io {
                    path: root.join(marker.relative_path()),
                    source,
                })?
                .into_std_file();
            let opened_metadata =
                opened_file
                    .metadata()
                    .map_err(|source| RootAttestationError::Io {
                        path: root.join(marker.relative_path()),
                        source,
                    })?;
            if metadata_is_link_or_reparse(&opened_metadata) {
                return Err(RootAttestationError::MarkerSymlink { marker });
            }
        }
        return Err(RootAttestationError::MarkerWrongType { marker });
    }
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    let file = directory
        .open_with(name, &options)
        .map_err(|source| marker_open_error(root, marker, source))?
        .into_std();
    let snapshot = FileSnapshot::read(&file).map_err(|source| RootAttestationError::Io {
        path: root.join(marker.relative_path()),
        source,
    })?;
    let opened_metadata = file.metadata().map_err(|source| RootAttestationError::Io {
        path: root.join(marker.relative_path()),
        source,
    })?;
    if metadata_is_link_or_reparse(&opened_metadata) {
        return Err(RootAttestationError::MarkerSymlink { marker });
    }
    if !opened_metadata.is_file() {
        return Err(RootAttestationError::MarkerWrongType { marker });
    }
    let identity =
        PhysicalIdentity::from_file(&file).map_err(|source| RootAttestationError::Io {
            path: root.join(marker.relative_path()),
            source,
        })?;
    Ok(OpenedMarker {
        identity,
        snapshot,
        file,
    })
}

fn read_manifest_bounded(
    manifest: &mut fs::File,
    root: &Path,
) -> Result<Vec<u8>, RootAttestationError> {
    let mut bytes = Vec::new();
    manifest
        .by_ref()
        .take(MAX_FOLDERBASE_MANIFEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| RootAttestationError::Io {
            path: root.join(FolderbaseRootMarker::Manifest.relative_path()),
            source,
        })?;
    if bytes.len() as u64 > MAX_FOLDERBASE_MANIFEST_BYTES {
        return Err(RootAttestationError::ManifestTooLarge {
            maximum_bytes: MAX_FOLDERBASE_MANIFEST_BYTES,
        });
    }
    Ok(bytes)
}

fn revalidate_root(root: &Path, expected: &PhysicalIdentity) -> Result<Dir, RootAttestationError> {
    let reopened =
        open_root_nofollow(root).map_err(|_| RootAttestationError::RootChangedDuringAttestation)?;
    let metadata = reopened
        .metadata()
        .map_err(|_| RootAttestationError::RootChangedDuringAttestation)?;
    if metadata_is_link_or_reparse(&metadata) || !metadata.is_dir() {
        return Err(RootAttestationError::RootChangedDuringAttestation);
    }
    let actual = PhysicalIdentity::from_file(&reopened)
        .map_err(|_| RootAttestationError::RootChangedDuringAttestation)?;
    if &actual != expected {
        return Err(RootAttestationError::RootChangedDuringAttestation);
    }
    Ok(Dir::from_std_file(reopened))
}

fn revalidate_directory(
    parent: &Dir,
    name: &str,
    _marker: FolderbaseRootMarker,
    expected: &PhysicalIdentity,
) -> Result<Dir, RootAttestationError> {
    let directory = parent
        .open_dir_nofollow(name)
        .map_err(|_| RootAttestationError::RootChangedDuringAttestation)?;
    let reopened = directory
        .try_clone()
        .map_err(|_| RootAttestationError::RootChangedDuringAttestation)?
        .into_std_file();
    let metadata = reopened
        .metadata()
        .map_err(|_| RootAttestationError::RootChangedDuringAttestation)?;
    if metadata_is_link_or_reparse(&metadata) || !metadata.is_dir() {
        return Err(RootAttestationError::RootChangedDuringAttestation);
    }
    let actual = PhysicalIdentity::from_file(&reopened)
        .map_err(|_| RootAttestationError::RootChangedDuringAttestation)?;
    if &actual != expected {
        return Err(RootAttestationError::RootChangedDuringAttestation);
    }
    Ok(directory)
}

fn revalidate_file(
    parent: &Dir,
    name: &str,
    marker: FolderbaseRootMarker,
    expected: &PhysicalIdentity,
    expected_snapshot: Option<&FileSnapshot>,
    root: &Path,
) -> Result<(), RootAttestationError> {
    let reopened = open_regular_marker(parent, name, marker, root)
        .map_err(|_| RootAttestationError::RootChangedDuringAttestation)?;
    if &reopened.identity != expected
        || expected_snapshot.is_some_and(|snapshot| snapshot != &reopened.snapshot)
    {
        return Err(RootAttestationError::RootChangedDuringAttestation);
    }
    Ok(())
}

fn revalidate_manifest(
    parent: &Dir,
    name: &str,
    marker: FolderbaseRootMarker,
    expected: &PhysicalIdentity,
    expected_sha256: &str,
    root: &Path,
) -> Result<(), RootAttestationError> {
    let mut reopened = open_regular_marker(parent, name, marker, root)
        .map_err(|_| RootAttestationError::RootChangedDuringAttestation)?;
    if &reopened.identity != expected {
        return Err(RootAttestationError::RootChangedDuringAttestation);
    }
    let bytes = read_manifest_bounded(&mut reopened.file, root)
        .map_err(|_| RootAttestationError::RootChangedDuringAttestation)?;
    if hex_sha256(&bytes) != expected_sha256 {
        return Err(RootAttestationError::RootChangedDuringAttestation);
    }
    Ok(())
}

fn required_manifest_fields(value: &Value) -> Result<(String, String), RootAttestationError> {
    let object = value
        .as_object()
        .ok_or(RootAttestationError::ManifestFieldWrongType { field: "$" })?;
    let protocol_version_value =
        object
            .get("protocol_version")
            .ok_or(RootAttestationError::ManifestFieldMissing {
                field: "protocol_version",
            })?;
    let protocol_version =
        protocol_version_value
            .as_str()
            .ok_or(RootAttestationError::ManifestFieldWrongType {
                field: "protocol_version",
            })?;
    let folderbase_value =
        object
            .get("folderbase")
            .ok_or(RootAttestationError::ManifestFieldMissing {
                field: "folderbase",
            })?;
    let folderbase =
        folderbase_value
            .as_object()
            .ok_or(RootAttestationError::ManifestFieldWrongType {
                field: "folderbase",
            })?;
    let folderbase_id_value =
        folderbase
            .get("id")
            .ok_or(RootAttestationError::ManifestFieldMissing {
                field: "folderbase.id",
            })?;
    let folderbase_id =
        folderbase_id_value
            .as_str()
            .ok_or(RootAttestationError::ManifestFieldWrongType {
                field: "folderbase.id",
            })?;
    Ok((folderbase_id.to_owned(), protocol_version.to_owned()))
}

fn validate_folderbase_id(folderbase_id: &str) -> Result<(), RootAttestationError> {
    let suffix = folderbase_id
        .strip_prefix("folderbase_")
        .ok_or(RootAttestationError::InvalidFolderbaseId)?;
    let uuid = Uuid::parse_str(suffix).map_err(|_| RootAttestationError::InvalidFolderbaseId)?;
    if suffix != uuid.hyphenated().to_string() {
        return Err(RootAttestationError::InvalidFolderbaseId);
    }
    Ok(())
}

fn decode_unique_json(bytes: &[u8]) -> Result<Value, RootAttestationError> {
    serde_json::from_slice::<UniqueJson>(bytes)
        .map(|value| value.0)
        .map_err(|source| {
            if source.to_string().contains(DUPLICATE_KEY_SENTINEL) {
                RootAttestationError::ManifestDuplicateField
            } else {
                RootAttestationError::ManifestInvalidJson
            }
        })
}

struct UniqueJson(Value);

impl<'de> Deserialize<'de> for UniqueJson {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(UniqueJsonVisitor)
    }
}

struct UniqueJsonVisitor;

impl<'de> Visitor<'de> for UniqueJsonVisitor {
    type Value = UniqueJson;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value without duplicate object keys")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(UniqueJson(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(UniqueJson(Value::Number(value.into())))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(UniqueJson(Value::Number(value.into())))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Number::from_f64(value)
            .map(Value::Number)
            .map(UniqueJson)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(UniqueJson(Value::String(value.to_owned())))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(UniqueJson(Value::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueJson(Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueJson(Value::Null))
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        UniqueJson::deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<UniqueJson>()? {
            values.push(value.0);
        }
        Ok(UniqueJson(Value::Array(values)))
    }

    fn visit_map<A>(self, mut object: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = Map::new();
        while let Some(key) = object.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(de::Error::custom(DUPLICATE_KEY_SENTINEL));
            }
            let value = object.next_value::<UniqueJson>()?;
            values.insert(key, value.0);
        }
        Ok(UniqueJson(Value::Object(values)))
    }
}

fn hex_sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn root_instance_authority(
    file: &fs::File,
    root: &Path,
) -> Result<RootInstanceAuthority, RootAttestationError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        let metadata = file.metadata().map_err(|source| RootAttestationError::Io {
            path: root.to_path_buf(),
            source,
        })?;
        Ok(RootInstanceAuthority {
            current_sha256: root_instance_digest(
                ROOT_INSTANCE_FORMAT_V1,
                b"unix",
                &[&metadata.dev().to_be_bytes(), &metadata.ino().to_be_bytes()],
            ),
            legacy_v1_sha256: None,
        })
    }

    #[cfg(windows)]
    {
        let full_identity =
            PhysicalIdentity::from_file(file).map_err(|source| RootAttestationError::Io {
                path: root.to_path_buf(),
                source,
            })?;
        let PhysicalIdentity::Windows {
            volume_serial,
            file_id,
        } = full_identity
        else {
            return Err(RootAttestationError::PhysicalIdentityUnavailable);
        };
        let legacy =
            winapi_util::file::information(file).map_err(|source| RootAttestationError::Io {
                path: root.to_path_buf(),
                source,
            })?;
        Ok(windows_root_instance_authority(
            volume_serial,
            file_id,
            legacy.volume_serial_number() as u32,
            legacy.file_index(),
        ))
    }

    #[cfg(not(any(unix, windows)))]
    {
        let _ = file;
        let _ = root;
        Err(RootAttestationError::PhysicalIdentityUnavailable)
    }
}

fn root_instance_digest(format: &str, platform: &[u8], fields: &[&[u8]]) -> String {
    let mut digest = Sha256::new();
    digest.update(format.as_bytes());
    digest.update([0]);
    digest.update(platform);
    digest.update([0]);
    for field in fields {
        digest.update(field);
    }
    format!("{:x}", digest.finalize())
}

#[cfg(any(windows, test))]
fn windows_root_instance_authority(
    volume_serial: u64,
    file_id: [u8; 16],
    legacy_volume_serial: u32,
    legacy_file_index: u64,
) -> RootInstanceAuthority {
    RootInstanceAuthority {
        current_sha256: root_instance_digest(
            ROOT_INSTANCE_FORMAT_V2,
            b"windows",
            &[&volume_serial.to_be_bytes(), &file_id],
        ),
        legacy_v1_sha256: Some(root_instance_digest(
            ROOT_INSTANCE_FORMAT_V1,
            b"windows",
            &[
                &legacy_volume_serial.to_be_bytes(),
                &legacy_file_index.to_be_bytes(),
            ],
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn released_windows_v1_root_identity_remains_compatible_without_weakening_v2() {
        let first = windows_root_instance_authority(
            0x1020_3040_5060_7080,
            [
                0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0,
                0xf0, 0x01,
            ],
            0x1020_3040,
            0x1122_3344_5566_7788,
        );
        let legacy_collision = windows_root_instance_authority(
            0x1020_3040_5060_7080,
            [
                0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                0x0f, 0x10,
            ],
            0x1020_3040,
            0x1122_3344_5566_7788,
        );

        assert_eq!(
            first.current_sha256(),
            "8ff64630529b2fbda0062c3c15b8109e050e99f905cf497ad3a864cc19db6b2c"
        );
        assert_eq!(
            first.legacy_v1_sha256.as_deref(),
            Some("b3bd16243ce08bcb477e45af8682519dbbbeb3d33bd50d4a1660fe04a073bc03")
        );
        let current = first.admit(first.current_sha256()).unwrap();
        assert_eq!(current.recorded_sha256(), first.current_sha256());
        assert!(!current.is_legacy_v1());
        let legacy = first
            .admit(first.legacy_v1_sha256.as_deref().unwrap())
            .unwrap();
        assert_eq!(
            legacy.recorded_sha256(),
            first.legacy_v1_sha256.as_deref().unwrap()
        );
        assert!(legacy.is_legacy_v1());
        assert_ne!(
            first.current_sha256(),
            legacy_collision.current_sha256(),
            "new Windows authority must reject a ReFS upper-bit collision"
        );
        assert!(first.admit(legacy_collision.current_sha256()).is_none());
        assert_eq!(
            legacy_collision.current_sha256(),
            "2afb8ccf76a5f517a400d52b539060d66a99ee816b9f2c94f63a7c3e2a32b6dc"
        );
    }

    #[test]
    fn released_unix_v1_root_identity_vector_is_unchanged() {
        assert_eq!(
            root_instance_digest(
                ROOT_INSTANCE_FORMAT_V1,
                b"unix",
                &[
                    &0x0102_0304_0506_0708_u64.to_be_bytes(),
                    &0x1122_3344_5566_7788_u64.to_be_bytes(),
                ],
            ),
            "f3684cd589445d66add75c1151f5df853fa89d37beae54a51e324606ba43736a"
        );
    }

    #[test]
    fn closed_marker_paths_are_stable() {
        let paths = [
            (FolderbaseRootMarker::StateDirectory, ".folderbase"),
            (FolderbaseRootMarker::Manifest, ".folderbase/manifest.json"),
            (FolderbaseRootMarker::Entry, "FOLDERBASE.md"),
        ];

        for (marker, expected) in paths {
            assert_eq!(marker.relative_path(), expected);
            assert_eq!(marker.to_string(), expected);
        }
    }

    #[test]
    fn windows_reparse_attribute_is_rejected_independently_of_symlink_tag() {
        assert!(windows_attributes_are_reparse(0x0000_0400));
        assert!(windows_attributes_are_reparse(0x0000_0410));
        assert!(!windows_attributes_are_reparse(0x0000_0010));
    }

    #[test]
    fn final_validation_rejects_equal_length_in_place_manifest_rewrite() {
        let root = tempdir().expect("root");
        fs::create_dir(root.path().join(STATE_DIRECTORY)).expect("state");
        let first = br#"{"protocol_version":"0.2.0","folderbase":{"id":"folderbase_019f9b75-4f42-7f65-a012-2bfecdd8c473"}}"#;
        let changed = br#"{"protocol_version":"0.2.0","folderbase":{"id":"folderbase_019f9b75-4f42-7f65-a012-2bfecdd8c474"}}"#;
        assert_eq!(first.len(), changed.len());
        let manifest_path = root.path().join(".folderbase/manifest.json");
        fs::write(&manifest_path, first).expect("manifest");
        fs::write(root.path().join(ENTRY_FILE), b"# Folderbase\n").expect("entry");

        let result = attest_folderbase_root_inner(root.path(), || {
            fs::write(&manifest_path, changed).expect("equal-length in-place rewrite");
        });

        assert!(matches!(
            result,
            Err(RootAttestationError::RootChangedDuringAttestation)
        ));
    }
}

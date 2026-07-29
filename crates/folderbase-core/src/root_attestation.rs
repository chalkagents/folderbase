use std::{
    fmt, fs,
    io::{self, Read},
    path::{Path, PathBuf},
};

use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt};
use cap_std::fs::{Dir, OpenOptions};
use same_file::Handle;
use semver::Version;
use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{self, MapAccess, SeqAccess, Visitor},
    ser::SerializeStruct,
};
use serde_json::{Map, Number, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Largest manifest accepted by the root-attestation seam.
pub const MAX_FOLDERBASE_MANIFEST_BYTES: u64 = 16 * 1024 * 1024;

/// Domain separator for the current device-local root-instance digest.
pub const ROOT_INSTANCE_FORMAT_V1: &str = "folderbase-physical-root-instance-v1";

const STATE_DIRECTORY: &str = ".folderbase";
const MANIFEST_FILE: &str = "manifest.json";
const ENTRY_FILE: &str = "FOLDERBASE.md";
const DUPLICATE_KEY_SENTINEL: &str = "folderbase_duplicate_json_object_key";

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
            Self::RootChangedDuringAttestation => "root_changed_during_attestation",
            Self::PhysicalIdentityUnavailable => "physical_identity_unavailable",
            Self::Io { .. } => "attestation_io",
        }
    }
}

struct OpenedMarker {
    identity: Handle,
    snapshot: FileSnapshot,
    file: fs::File,
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

fn attest_folderbase_root_inner(
    root: &Path,
    before_final_validation: impl FnOnce(),
) -> Result<FolderbaseRootAttestation, RootAttestationError> {
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
        Handle::from_file(
            root_file
                .try_clone()
                .map_err(|source| RootAttestationError::Io {
                    path: root.to_path_buf(),
                    source,
                })?,
        )
        .map_err(|source| RootAttestationError::Io {
            path: root.to_path_buf(),
            source,
        })?;
    let root_instance_sha256 = root_instance_sha256(&root_file, root)?;
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
        Handle::from_file(state_file).map_err(|source| RootAttestationError::Io {
            path: root.join(STATE_DIRECTORY),
            source,
        })?;

    let mut manifest = open_regular_marker(
        &state_dir,
        MANIFEST_FILE,
        FolderbaseRootMarker::Manifest,
        root,
    )?;
    let entry = open_regular_marker(&root_dir, ENTRY_FILE, FolderbaseRootMarker::Entry, root)?;

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

    let parsed = decode_unique_json(&manifest_bytes)?;
    let (folderbase_id, protocol_version) = required_manifest_fields(&parsed)?;
    validate_folderbase_id(&folderbase_id)?;
    Version::parse(&protocol_version).map_err(|_| RootAttestationError::InvalidProtocolVersion)?;
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
    revalidate_file(
        &reopened_root,
        ENTRY_FILE,
        FolderbaseRootMarker::Entry,
        &entry.identity,
        Some(&entry.snapshot),
        root,
    )?;

    Ok(FolderbaseRootAttestation {
        root: root.to_path_buf(),
        folderbase_id,
        protocol_version,
        manifest_sha256,
        root_instance_sha256,
    })
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

fn metadata_is_link_or_reparse(metadata: &fs::Metadata) -> bool {
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
const fn windows_attributes_are_reparse(attributes: u32) -> bool {
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
        Handle::from_file(
            file.try_clone()
                .map_err(|source| RootAttestationError::Io {
                    path: root.join(marker.relative_path()),
                    source,
                })?,
        )
        .map_err(|source| RootAttestationError::Io {
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

fn revalidate_root(root: &Path, expected: &Handle) -> Result<Dir, RootAttestationError> {
    let reopened =
        open_root_nofollow(root).map_err(|_| RootAttestationError::RootChangedDuringAttestation)?;
    let metadata = reopened
        .metadata()
        .map_err(|_| RootAttestationError::RootChangedDuringAttestation)?;
    if metadata_is_link_or_reparse(&metadata) || !metadata.is_dir() {
        return Err(RootAttestationError::RootChangedDuringAttestation);
    }
    let actual = Handle::from_file(
        reopened
            .try_clone()
            .map_err(|_| RootAttestationError::RootChangedDuringAttestation)?,
    )
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
    expected: &Handle,
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
    let actual = Handle::from_file(reopened)
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
    expected: &Handle,
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
    expected: &Handle,
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

fn root_instance_sha256(file: &fs::File, root: &Path) -> Result<String, RootAttestationError> {
    let mut digest = Sha256::new();
    digest.update(ROOT_INSTANCE_FORMAT_V1.as_bytes());
    digest.update([0]);

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        let metadata = file.metadata().map_err(|source| RootAttestationError::Io {
            path: root.to_path_buf(),
            source,
        })?;
        digest.update(b"unix");
        digest.update([0]);
        digest.update(metadata.dev().to_be_bytes());
        digest.update(metadata.ino().to_be_bytes());
    }

    #[cfg(windows)]
    {
        let information =
            winapi_util::file::information(file).map_err(|source| RootAttestationError::Io {
                path: root.to_path_buf(),
                source,
            })?;
        digest.update(b"windows");
        digest.update([0]);
        digest.update((information.volume_serial_number() as u32).to_be_bytes());
        digest.update(information.file_index().to_be_bytes());
    }

    #[cfg(not(any(unix, windows)))]
    {
        let _ = file;
        let _ = root;
        return Err(RootAttestationError::PhysicalIdentityUnavailable);
    }

    Ok(format!("{:x}", digest.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

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

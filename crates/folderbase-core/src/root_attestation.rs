use std::{
    fmt, fs,
    io::{self, Read},
    path::{Path, PathBuf},
    time::SystemTime,
};

use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt};
use cap_std::fs::{Dir, OpenOptions};
use same_file::Handle;
use semver::Version;
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{self, MapAccess, SeqAccess, Visitor},
};
use serde_json::{Map, Number, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Largest manifest accepted by the root-attestation seam.
pub const MAX_FOLDERBASE_ROOT_MANIFEST_BYTES: u64 = 16 * 1024 * 1024;

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
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FolderbaseRootAttestation {
    pub root: PathBuf,
    pub folderbase_id: String,
    pub protocol_version: String,
    pub manifest_sha256: String,
    pub root_instance_sha256: String,
}

/// Failures produced while attesting one exact Folderbase root.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RootAttestationError {
    #[error("root is not an exact no-follow directory: {root}")]
    InvalidRoot { root: PathBuf },

    #[error("required Folderbase marker is missing: {marker}")]
    MissingMarker { marker: FolderbaseRootMarker },

    #[error("Folderbase marker must not be a symbolic link or reparse point: {marker}")]
    MarkerIsLink { marker: FolderbaseRootMarker },

    #[error("Folderbase marker has the wrong filesystem type: {marker}")]
    WrongMarkerType { marker: FolderbaseRootMarker },

    #[error("Folderbase manifest exceeds the attestation maximum of {maximum_bytes} bytes")]
    ManifestTooLarge { maximum_bytes: u64 },

    #[error("Folderbase manifest is not valid JSON")]
    InvalidManifestJson,

    #[error("Folderbase manifest contains a duplicate object key")]
    DuplicateManifestKey,

    #[error("Folderbase manifest does not contain the required string fields")]
    InvalidManifestShape,

    #[error("Folderbase manifest id is not folderbase_<lowercase-hyphenated-UUID>")]
    InvalidFolderbaseId,

    #[error("Folderbase manifest protocol_version is not valid semantic versioning")]
    InvalidProtocolVersion,

    #[error("Folderbase root identity changed during attestation")]
    RootStateChanged,

    #[error("Folderbase marker changed during attestation: {marker}")]
    MarkerStateChanged { marker: FolderbaseRootMarker },

    #[error("this platform does not expose the physical identity required by root-instance-v1")]
    RootIdentityUnavailable,

    #[error("filesystem I/O failed while attesting {marker}: {source}")]
    Io {
        marker: FolderbaseRootMarker,
        #[source]
        source: io::Error,
    },
}

impl RootAttestationError {
    /// Stable machine-readable code used by the Folderbase CLI.
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidRoot { .. } => "invalid_root",
            Self::MissingMarker { .. } => "missing_marker",
            Self::MarkerIsLink { .. } => "marker_is_link",
            Self::WrongMarkerType { .. } => "wrong_marker_type",
            Self::ManifestTooLarge { .. } => "manifest_too_large",
            Self::InvalidManifestJson => "invalid_manifest_json",
            Self::DuplicateManifestKey => "duplicate_manifest_key",
            Self::InvalidManifestShape => "invalid_manifest_shape",
            Self::InvalidFolderbaseId => "invalid_folderbase_id",
            Self::InvalidProtocolVersion => "invalid_protocol_version",
            Self::RootStateChanged => "root_state_changed",
            Self::MarkerStateChanged { .. } => "marker_state_changed",
            Self::RootIdentityUnavailable => "root_identity_unavailable",
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
    modified: Option<SystemTime>,
}

impl FileSnapshot {
    fn read(file: &fs::File) -> io::Result<Self> {
        let metadata = file.metadata()?;
        Ok(Self {
            bytes: metadata.len(),
            modified: metadata.modified().ok(),
        })
    }
}

/// Attest one exact Folderbase root without writing protocol or ordinary files.
pub fn attest_folderbase_root(
    root: impl AsRef<Path>,
) -> Result<FolderbaseRootAttestation, RootAttestationError> {
    let root = root.as_ref();
    let root_file = open_root_nofollow(root).map_err(|_| RootAttestationError::InvalidRoot {
        root: root.to_path_buf(),
    })?;
    let root_identity =
        Handle::from_file(
            root_file
                .try_clone()
                .map_err(|source| RootAttestationError::Io {
                    marker: FolderbaseRootMarker::StateDirectory,
                    source,
                })?,
        )
        .map_err(|source| RootAttestationError::Io {
            marker: FolderbaseRootMarker::StateDirectory,
            source,
        })?;
    let root_instance_sha256 = root_instance_sha256(&root_file)?;
    let root_dir = Dir::from_std_file(root_file);

    let state_metadata = marker_metadata(
        &root_dir,
        STATE_DIRECTORY,
        FolderbaseRootMarker::StateDirectory,
    )?;
    if state_metadata.file_type().is_symlink() {
        return Err(RootAttestationError::MarkerIsLink {
            marker: FolderbaseRootMarker::StateDirectory,
        });
    }
    if !state_metadata.is_dir() {
        return Err(RootAttestationError::WrongMarkerType {
            marker: FolderbaseRootMarker::StateDirectory,
        });
    }
    let state_dir = root_dir
        .open_dir_nofollow(STATE_DIRECTORY)
        .map_err(|source| marker_open_error(FolderbaseRootMarker::StateDirectory, source))?;
    let state_identity = Handle::from_file(
        state_dir
            .try_clone()
            .map_err(|source| RootAttestationError::Io {
                marker: FolderbaseRootMarker::StateDirectory,
                source,
            })?
            .into_std_file(),
    )
    .map_err(|source| RootAttestationError::Io {
        marker: FolderbaseRootMarker::StateDirectory,
        source,
    })?;

    let mut manifest =
        open_regular_marker(&state_dir, MANIFEST_FILE, FolderbaseRootMarker::Manifest)?;
    let entry = open_regular_marker(&root_dir, ENTRY_FILE, FolderbaseRootMarker::Entry)?;

    if manifest.snapshot.bytes > MAX_FOLDERBASE_ROOT_MANIFEST_BYTES {
        return Err(RootAttestationError::ManifestTooLarge {
            maximum_bytes: MAX_FOLDERBASE_ROOT_MANIFEST_BYTES,
        });
    }
    let mut manifest_bytes = Vec::with_capacity(manifest.snapshot.bytes as usize);
    manifest
        .file
        .by_ref()
        .take(MAX_FOLDERBASE_ROOT_MANIFEST_BYTES + 1)
        .read_to_end(&mut manifest_bytes)
        .map_err(|source| RootAttestationError::Io {
            marker: FolderbaseRootMarker::Manifest,
            source,
        })?;
    if manifest_bytes.len() as u64 > MAX_FOLDERBASE_ROOT_MANIFEST_BYTES {
        return Err(RootAttestationError::ManifestTooLarge {
            maximum_bytes: MAX_FOLDERBASE_ROOT_MANIFEST_BYTES,
        });
    }
    if FileSnapshot::read(&manifest.file).map_err(|source| RootAttestationError::Io {
        marker: FolderbaseRootMarker::Manifest,
        source,
    })? != manifest.snapshot
    {
        return Err(RootAttestationError::MarkerStateChanged {
            marker: FolderbaseRootMarker::Manifest,
        });
    }

    let parsed = decode_unique_json(&manifest_bytes)?;
    let (folderbase_id, protocol_version) = required_manifest_fields(&parsed)?;
    validate_folderbase_id(&folderbase_id)?;
    Version::parse(&protocol_version).map_err(|_| RootAttestationError::InvalidProtocolVersion)?;
    let manifest_sha256 = hex_sha256(&manifest_bytes);

    revalidate_root(root, &root_identity)?;
    revalidate_directory(
        &root_dir,
        STATE_DIRECTORY,
        FolderbaseRootMarker::StateDirectory,
        &state_identity,
    )?;
    revalidate_file(
        &state_dir,
        MANIFEST_FILE,
        FolderbaseRootMarker::Manifest,
        &manifest.identity,
        Some(&manifest.snapshot),
    )?;
    revalidate_file(
        &root_dir,
        ENTRY_FILE,
        FolderbaseRootMarker::Entry,
        &entry.identity,
        Some(&entry.snapshot),
    )?;

    Ok(FolderbaseRootAttestation {
        root: root.to_path_buf(),
        folderbase_id,
        protocol_version,
        manifest_sha256,
        root_instance_sha256,
    })
}

fn marker_metadata(
    directory: &Dir,
    name: &str,
    marker: FolderbaseRootMarker,
) -> Result<cap_std::fs::Metadata, RootAttestationError> {
    directory
        .symlink_metadata(name)
        .map_err(|source| marker_open_error(marker, source))
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
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(io::Error::other("attestation root is not a directory"));
    }
    Ok(file)
}

fn marker_open_error(marker: FolderbaseRootMarker, source: io::Error) -> RootAttestationError {
    if source.kind() == io::ErrorKind::NotFound {
        RootAttestationError::MissingMarker { marker }
    } else {
        RootAttestationError::Io { marker, source }
    }
}

fn open_regular_marker(
    directory: &Dir,
    name: &str,
    marker: FolderbaseRootMarker,
) -> Result<OpenedMarker, RootAttestationError> {
    let metadata = marker_metadata(directory, name, marker)?;
    if metadata.file_type().is_symlink() {
        return Err(RootAttestationError::MarkerIsLink { marker });
    }
    if !metadata.is_file() {
        return Err(RootAttestationError::WrongMarkerType { marker });
    }
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    let file = directory
        .open_with(name, &options)
        .map_err(|source| marker_open_error(marker, source))?
        .into_std();
    let snapshot =
        FileSnapshot::read(&file).map_err(|source| RootAttestationError::Io { marker, source })?;
    if !file
        .metadata()
        .map_err(|source| RootAttestationError::Io { marker, source })?
        .is_file()
    {
        return Err(RootAttestationError::WrongMarkerType { marker });
    }
    let identity = Handle::from_file(
        file.try_clone()
            .map_err(|source| RootAttestationError::Io { marker, source })?,
    )
    .map_err(|source| RootAttestationError::Io { marker, source })?;
    Ok(OpenedMarker {
        identity,
        snapshot,
        file,
    })
}

fn revalidate_root(root: &Path, expected: &Handle) -> Result<(), RootAttestationError> {
    let reopened = open_root_nofollow(root).map_err(|_| RootAttestationError::RootStateChanged)?;
    let actual = Handle::from_file(reopened).map_err(|_| RootAttestationError::RootStateChanged)?;
    if &actual != expected {
        return Err(RootAttestationError::RootStateChanged);
    }
    Ok(())
}

fn revalidate_directory(
    parent: &Dir,
    name: &str,
    marker: FolderbaseRootMarker,
    expected: &Handle,
) -> Result<(), RootAttestationError> {
    let actual = parent
        .open_dir_nofollow(name)
        .map(Dir::into_std_file)
        .and_then(Handle::from_file)
        .map_err(|_| RootAttestationError::MarkerStateChanged { marker })?;
    if &actual != expected {
        return Err(RootAttestationError::MarkerStateChanged { marker });
    }
    Ok(())
}

fn revalidate_file(
    parent: &Dir,
    name: &str,
    marker: FolderbaseRootMarker,
    expected: &Handle,
    expected_snapshot: Option<&FileSnapshot>,
) -> Result<(), RootAttestationError> {
    let reopened = open_regular_marker(parent, name, marker)
        .map_err(|_| RootAttestationError::MarkerStateChanged { marker })?;
    if &reopened.identity != expected
        || expected_snapshot.is_some_and(|snapshot| snapshot != &reopened.snapshot)
    {
        return Err(RootAttestationError::MarkerStateChanged { marker });
    }
    Ok(())
}

fn required_manifest_fields(value: &Value) -> Result<(String, String), RootAttestationError> {
    let object = value
        .as_object()
        .ok_or(RootAttestationError::InvalidManifestShape)?;
    let protocol_version = object
        .get("protocol_version")
        .and_then(Value::as_str)
        .ok_or(RootAttestationError::InvalidManifestShape)?;
    let folderbase_id = object
        .get("folderbase")
        .and_then(Value::as_object)
        .and_then(|folderbase| folderbase.get("id"))
        .and_then(Value::as_str)
        .ok_or(RootAttestationError::InvalidManifestShape)?;
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
                RootAttestationError::DuplicateManifestKey
            } else {
                RootAttestationError::InvalidManifestJson
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

fn root_instance_sha256(file: &fs::File) -> Result<String, RootAttestationError> {
    let mut digest = Sha256::new();
    digest.update(ROOT_INSTANCE_FORMAT_V1.as_bytes());
    digest.update([0]);

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        let metadata = file.metadata().map_err(|source| RootAttestationError::Io {
            marker: FolderbaseRootMarker::StateDirectory,
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
                marker: FolderbaseRootMarker::StateDirectory,
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
        return Err(RootAttestationError::RootIdentityUnavailable);
    }

    Ok(format!("{:x}", digest.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

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
}

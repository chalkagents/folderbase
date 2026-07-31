//! Bounded-memory planning and streaming for immutable local versions.
//!
//! A [`ChunkTransferSource`] is bound to one Core-owned version record, one
//! content-addressed blob, one chunking profile, and one canonical manifest.
//! It never reads the mutable workspace path recorded for the object.

use std::{
    ffi::{OsStr, OsString},
    fs,
    io::{Read, Seek, SeekFrom, Write},
    path::{Component, Path, PathBuf},
    time::SystemTime,
};

use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt};
use cap_std::fs::{Dir, OpenOptions};
use sha2::{Digest, Sha256};

use crate::{
    FolderbaseError, LocalObjectRecord, LocalVersionRecord, LocalVersionStore, ObjectId, VersionId,
    local_versions::{folderbase_id_from_manifest_bytes, validate_chunk_transfer_receipt_bytes},
    physical_identity::{PhysicalIdentity, RetainedPhysicalIdentity},
    transfer_manifest::{
        ChunkManifest, LARGE_PROFILE_V1, MAX_OBJECT_BYTES, ManifestViolation,
        ObjectVerificationError, STANDARD_PROFILE_V1, is_sha256, plan_streamed_manifest,
    },
    traversal_policy::{NestedFolderbaseBoundaryKind, classify_nested_folderbase_boundary},
};

pub use crate::transfer_manifest::TRANSFER_IO_BUFFER_BYTES;

/// The current managed-profile policy switches to `large-v1` at 1 GiB.
///
/// This is a planner policy, not a manifest validation rule. An explicit
/// supported profile remains valid for any object whose resulting manifest
/// conforms to v1.
pub const MANAGED_LARGE_PROFILE_THRESHOLD_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_VERSION_RECORD_BYTES: u64 = 1024 * 1024;
const MAX_OBJECT_RECORD_BYTES: u64 = 8 * 1024 * 1024;
const MAX_TRANSFER_AUTHORITY_RECORD_BYTES: u64 = 1024 * 1024;
const FOLDERBASE_MANIFEST_PATH: &str = ".folderbase/manifest.json";
const OUTGOING_TRANSFER_AUTHORITY_DIRECTORY: &str = ".folderbase/history-transfers/outgoing";

/// Selects one of the two exact public v1 profiles or Core's managed policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChunkTransferProfile {
    StandardV1,
    LargeV1,
    Managed,
}

impl ChunkTransferProfile {
    /// Resolve the exact manifest profile from bounded object metadata.
    ///
    /// The managed decision needs only the byte length; it does not read or
    /// allocate the payload.
    pub fn selected_profile_for_bytes(
        self,
        object_bytes: u64,
    ) -> Result<&'static str, TransferSourceError> {
        if object_bytes > MAX_OBJECT_BYTES {
            return Err(TransferSourceError::ObjectTooLarge {
                maximum: MAX_OBJECT_BYTES,
            });
        }
        Ok(self.resolve(object_bytes).name())
    }

    fn resolve(self, object_bytes: u64) -> ResolvedProfile {
        match self {
            Self::StandardV1 => ResolvedProfile::StandardV1,
            Self::LargeV1 => ResolvedProfile::LargeV1,
            Self::Managed if object_bytes >= MANAGED_LARGE_PROFILE_THRESHOLD_BYTES => {
                ResolvedProfile::LargeV1
            }
            Self::Managed => ResolvedProfile::StandardV1,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResolvedProfile {
    StandardV1,
    LargeV1,
}

impl ResolvedProfile {
    fn name(self) -> &'static str {
        match self {
            Self::StandardV1 => STANDARD_PROFILE_V1,
            Self::LargeV1 => LARGE_PROFILE_V1,
        }
    }
}

/// Integrity proof for bytes emitted by one successful chunk copy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedChunk {
    pub manifest_digest: String,
    pub chunk_index: u32,
    pub chunk_sha256: String,
    pub chunk_bytes: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum TransferSourceError {
    #[error(transparent)]
    Folderbase(#[from] FolderbaseError),

    #[error("transfer source I/O failed: {0}")]
    Io(#[source] std::io::Error),

    #[error("immutable transfer source changed after it was opened")]
    SourceChanged,

    #[error("immutable object exceeds the v1 maximum of {maximum} bytes")]
    ObjectTooLarge { maximum: u64 },

    #[error("canonical manifest planning failed: {0}")]
    InvalidManifest(#[from] ManifestViolation),

    #[error("chunk {0} is not present in the bound manifest")]
    UnknownChunk(u32),

    #[error("chunk {0} changed while it was being copied")]
    ChunkDigestMismatch(u32),

    #[error("chunk {0} length changed while it was being copied")]
    ChunkLengthMismatch(u32),

    #[error("chunk output failed: {0}")]
    Writer(#[source] std::io::Error),

    #[error("replanned manifest digest {actual} differs from expected digest {expected}")]
    ManifestDigestMismatch { expected: String, actual: String },

    #[error("expected manifest digest is not lowercase hexadecimal SHA-256")]
    InvalidExpectedManifestDigest,
}

/// An opaque, capability-bound source for one immutable local version.
///
/// The source retains open handles for the root, version record, and blob.
/// Every copy revalidates those handles and the exact version record before
/// and after streaming the requested byte range.
#[derive(Debug)]
pub struct ChunkTransferSource {
    store: LocalVersionStore,
    root_dir: Dir,
    root_identity: PhysicalIdentity,
    version_record_identity: RetainedPhysicalIdentity,
    version_record_snapshot: FileSnapshot,
    blob: RetainedPhysicalIdentity,
    blob_snapshot: FileSnapshot,
    version: LocalVersionRecord,
    manifest: ChunkManifest,
    manifest_digest: String,
}

impl LocalVersionStore {
    /// Plan a canonical transfer from an exact immutable Core-owned version.
    pub fn open_chunk_transfer(
        &self,
        version_id: &VersionId,
        profile: ChunkTransferProfile,
    ) -> Result<ChunkTransferSource, TransferSourceError> {
        ChunkTransferSource::open(self.clone(), version_id, profile)
    }

    /// Deterministically replan a source and bind it to a durable resume
    /// checkpoint's canonical manifest digest.
    pub fn reopen_chunk_transfer(
        &self,
        version_id: &VersionId,
        profile: ChunkTransferProfile,
        expected_manifest_digest: &str,
    ) -> Result<ChunkTransferSource, TransferSourceError> {
        if !is_sha256(expected_manifest_digest) {
            return Err(TransferSourceError::InvalidExpectedManifestDigest);
        }
        let source = self.open_chunk_transfer(version_id, profile)?;
        if source.manifest_digest != expected_manifest_digest {
            return Err(TransferSourceError::ManifestDigestMismatch {
                expected: expected_manifest_digest.to_owned(),
                actual: source.manifest_digest,
            });
        }
        Ok(source)
    }
}

impl ChunkTransferSource {
    fn open(
        store: LocalVersionStore,
        version_id: &VersionId,
        profile: ChunkTransferProfile,
    ) -> Result<Self, TransferSourceError> {
        VersionId::parse(version_id.as_str().to_owned())?;
        let root_file = open_root_nofollow(store.root()).map_err(TransferSourceError::Io)?;
        let root_dir = Dir::from_std_file(root_file);
        let root_guard = root_dir
            .try_clone()
            .map_err(TransferSourceError::Io)?
            .into_std_file();
        let root_identity =
            PhysicalIdentity::from_file(&root_guard).map_err(TransferSourceError::Io)?;
        let (version, _object, version_record) = read_bound_records(&store, &root_dir, version_id)?;
        if version.content.bytes > MAX_OBJECT_BYTES {
            return Err(TransferSourceError::ObjectTooLarge {
                maximum: MAX_OBJECT_BYTES,
            });
        }
        let version_record_snapshot =
            FileSnapshot::read(&version_record).map_err(TransferSourceError::Io)?;
        let version_record_identity =
            RetainedPhysicalIdentity::from_file(version_record).map_err(TransferSourceError::Io)?;

        let blob_relative = store.blob_relative_path(&version.content.digest);
        let blob_file =
            open_file_nofollow(&root_dir, &blob_relative).map_err(TransferSourceError::Io)?;
        let blob_snapshot = FileSnapshot::read(&blob_file).map_err(TransferSourceError::Io)?;
        if blob_snapshot.bytes != version.content.bytes {
            return Err(TransferSourceError::SourceChanged);
        }
        let mut blob =
            RetainedPhysicalIdentity::from_file(blob_file).map_err(TransferSourceError::Io)?;
        let resolved = profile.resolve(version.content.bytes);
        let manifest = plan_manifest(blob.as_file_mut(), &version, resolved)?;
        let manifest_digest = manifest.canonical_digest()?;

        let mut source = Self {
            store,
            root_dir,
            root_identity,
            version_record_identity,
            version_record_snapshot,
            blob,
            blob_snapshot,
            version,
            manifest,
            manifest_digest,
        };
        source.verify_binding()?;
        Ok(source)
    }

    pub fn version_id(&self) -> &VersionId {
        &self.version.id
    }

    pub fn manifest(&self) -> &ChunkManifest {
        &self.manifest
    }

    pub fn manifest_digest(&self) -> &str {
        &self.manifest_digest
    }

    /// Stream one exact manifest range into `writer` using fixed-size buffers.
    ///
    /// A success result proves the digest and length observed by this process.
    /// A writer failure or changed source returns no proof.
    pub fn copy_chunk(
        &mut self,
        index: u32,
        mut writer: impl Write,
    ) -> Result<VerifiedChunk, TransferSourceError> {
        let descriptor = self
            .manifest
            .chunks
            .get(index as usize)
            .filter(|descriptor| descriptor.index == index)
            .cloned()
            .ok_or(TransferSourceError::UnknownChunk(index))?;

        self.verify_binding()?;
        self.blob
            .as_file_mut()
            .seek(SeekFrom::Start(descriptor.offset))
            .map_err(TransferSourceError::Io)?;
        let mut remaining = descriptor.bytes;
        let mut copied = 0_u64;
        let mut hasher = Sha256::new();
        let mut buffer = [0_u8; TRANSFER_IO_BUFFER_BYTES];
        while remaining > 0 {
            let wanted = usize::try_from(remaining.min(buffer.len() as u64))
                .expect("bounded buffer length fits usize");
            let read = self
                .blob
                .as_file_mut()
                .read(&mut buffer[..wanted])
                .map_err(TransferSourceError::Io)?;
            if read == 0 {
                return Err(TransferSourceError::ChunkLengthMismatch(index));
            }
            writer
                .write_all(&buffer[..read])
                .map_err(TransferSourceError::Writer)?;
            hasher.update(&buffer[..read]);
            copied += read as u64;
            remaining -= read as u64;
        }
        if copied != descriptor.bytes {
            return Err(TransferSourceError::ChunkLengthMismatch(index));
        }
        let actual_digest = format!("{:x}", hasher.finalize());
        if actual_digest != descriptor.sha256 {
            return Err(TransferSourceError::ChunkDigestMismatch(index));
        }
        self.verify_binding()?;

        Ok(VerifiedChunk {
            manifest_digest: self.manifest_digest.clone(),
            chunk_index: index,
            chunk_sha256: descriptor.sha256,
            chunk_bytes: descriptor.bytes,
        })
    }

    fn verify_binding(&mut self) -> Result<(), TransferSourceError> {
        let current_root_file =
            open_root_nofollow(self.store.root()).map_err(TransferSourceError::Io)?;
        let current_root =
            PhysicalIdentity::from_file(&current_root_file).map_err(TransferSourceError::Io)?;
        if current_root != self.root_identity {
            return Err(TransferSourceError::SourceChanged);
        }

        let (current_version, _object, current_version_file) =
            read_bound_records(&self.store, &self.root_dir, &self.version.id)?;
        if current_version != self.version {
            return Err(TransferSourceError::SourceChanged);
        }
        if FileSnapshot::read(&current_version_file).map_err(TransferSourceError::Io)?
            != self.version_record_snapshot
        {
            return Err(TransferSourceError::SourceChanged);
        }
        let current_record =
            PhysicalIdentity::from_file(&current_version_file).map_err(TransferSourceError::Io)?;
        if current_record != self.version_record_identity.identity() {
            return Err(TransferSourceError::SourceChanged);
        }

        let current_blob = open_file_nofollow(
            &self.root_dir,
            &self.store.blob_relative_path(&self.version.content.digest),
        )
        .map_err(TransferSourceError::Io)?;
        if FileSnapshot::read(&current_blob).map_err(TransferSourceError::Io)? != self.blob_snapshot
        {
            return Err(TransferSourceError::SourceChanged);
        }
        let current_blob =
            PhysicalIdentity::from_file(&current_blob).map_err(TransferSourceError::Io)?;
        if current_blob != self.blob.identity() {
            return Err(TransferSourceError::SourceChanged);
        }

        let final_root_file =
            open_root_nofollow(self.store.root()).map_err(TransferSourceError::Io)?;
        let final_root =
            PhysicalIdentity::from_file(&final_root_file).map_err(TransferSourceError::Io)?;
        if final_root != self.root_identity {
            return Err(TransferSourceError::SourceChanged);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileSnapshot {
    bytes: u64,
    modified: Option<SystemTime>,
}

impl FileSnapshot {
    fn read(file: &fs::File) -> std::io::Result<Self> {
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            return Err(std::io::Error::other("source is not a regular file"));
        }
        Ok(Self {
            bytes: metadata.len(),
            modified: metadata.modified().ok(),
        })
    }
}

fn plan_manifest(
    blob: &mut fs::File,
    version: &LocalVersionRecord,
    profile: ResolvedProfile,
) -> Result<ChunkManifest, TransferSourceError> {
    blob.seek(SeekFrom::Start(0))
        .map_err(TransferSourceError::Io)?;
    let manifest = plan_streamed_manifest(
        Read::by_ref(blob).take(version.content.bytes.saturating_add(1)),
        profile.name(),
    )
    .map_err(|error| match error {
        ObjectVerificationError::Reader(source) | ObjectVerificationError::Writer(source) => {
            TransferSourceError::Io(source)
        }
        ObjectVerificationError::InvalidManifest(source) => {
            TransferSourceError::InvalidManifest(source)
        }
        ObjectVerificationError::ObjectTooLarge { maximum } => {
            TransferSourceError::ObjectTooLarge { maximum }
        }
        ObjectVerificationError::ObjectLengthMismatch { .. }
        | ObjectVerificationError::ObjectDigestMismatch
        | ObjectVerificationError::ChunkPlanMismatch => TransferSourceError::SourceChanged,
    })?;
    if manifest.object_bytes != version.content.bytes
        || manifest.object_sha256 != version.content.digest
    {
        return Err(TransferSourceError::SourceChanged);
    }
    Ok(manifest)
}

fn open_root_nofollow(path: &Path) -> std::io::Result<fs::File> {
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
        return Err(std::io::Error::other("source root is not a directory"));
    }
    Ok(file)
}

fn open_file_nofollow(root: &Dir, relative: &Path) -> std::io::Result<fs::File> {
    open_optional_file_nofollow_io(root, relative)?.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "required source file is absent",
        )
    })
}

fn read_bound_records(
    store: &LocalVersionStore,
    root: &Dir,
    version_id: &VersionId,
) -> Result<(LocalVersionRecord, LocalObjectRecord, fs::File), TransferSourceError> {
    let mut version_file =
        open_file_nofollow(root, &store.version_record_relative_path(version_id))
            .map_err(TransferSourceError::Io)?;
    let version: LocalVersionRecord =
        read_json_bounded(&mut version_file, MAX_VERSION_RECORD_BYTES)?;
    ObjectId::parse(version.object_id.as_str().to_owned())?;
    let mut object_file =
        open_file_nofollow(root, &store.object_record_relative_path(&version.object_id))
            .map_err(TransferSourceError::Io)?;
    let object: LocalObjectRecord = read_json_bounded(&mut object_file, MAX_OBJECT_RECORD_BYTES)?;
    let object_path = store
        .validate_chunk_transfer_membership(version_id, &version, &object)
        .map_err(|_| TransferSourceError::SourceChanged)?;
    TransferAuthority::new(store, root).validate(&version.object_id, &object_path)?;
    Ok((version, object, version_file))
}

struct TransferAuthority<'a> {
    store: &'a LocalVersionStore,
    root: &'a Dir,
}

impl<'a> TransferAuthority<'a> {
    fn new(store: &'a LocalVersionStore, root: &'a Dir) -> Self {
        Self { store, root }
    }

    fn validate(
        &self,
        object_id: &ObjectId,
        object_path: &Path,
    ) -> Result<(), TransferSourceError> {
        self.validate_current_boundary(object_path)?;
        let receipt_relative =
            Path::new(OUTGOING_TRANSFER_AUTHORITY_DIRECTORY).join(format!("{object_id}.json"));
        let Some(mut receipt) = open_optional_file_nofollow(self.root, &receipt_relative)? else {
            return Ok(());
        };
        let receipt_bytes = read_bytes_bounded(&mut receipt, MAX_TRANSFER_AUTHORITY_RECORD_BYTES)?;
        let mut manifest = open_file_nofollow(self.root, Path::new(FOLDERBASE_MANIFEST_PATH))
            .map_err(|_| TransferSourceError::SourceChanged)?;
        let manifest_bytes =
            read_bytes_bounded(&mut manifest, MAX_TRANSFER_AUTHORITY_RECORD_BYTES)?;
        let manifest_path = self.store.root().join(FOLDERBASE_MANIFEST_PATH);
        let folderbase_id = folderbase_id_from_manifest_bytes(&manifest_bytes, &manifest_path)
            .map_err(|_| TransferSourceError::SourceChanged)?;
        validate_chunk_transfer_receipt_bytes(
            &receipt_bytes,
            &self.store.root().join(receipt_relative),
            object_id,
            &folderbase_id,
        )
        .map_err(|_| TransferSourceError::SourceChanged)
    }

    fn validate_current_boundary(&self, relative: &Path) -> Result<(), TransferSourceError> {
        let mut current = self
            .root
            .try_clone()
            .map_err(|_| TransferSourceError::SourceChanged)?;
        let mut display = PathBuf::from(self.store.root());
        let mut components = relative.components().peekable();
        while let Some(component) = components.next() {
            let Component::Normal(expected) = component else {
                return Err(TransferSourceError::SourceChanged);
            };
            let Some(actual) = case_folded_child(&current, expected)? else {
                return Ok(());
            };
            let metadata = current
                .symlink_metadata(&actual)
                .map_err(|_| TransferSourceError::SourceChanged)?;
            if metadata.file_type().is_symlink() {
                return Err(TransferSourceError::SourceChanged);
            }
            if metadata.is_dir() {
                let child = current
                    .open_dir_nofollow(&actual)
                    .map_err(|_| TransferSourceError::SourceChanged)?;
                display.push(&actual);
                if classify_nested_folderbase_boundary(&child, &display)
                    .map_err(|_| TransferSourceError::SourceChanged)?
                    != NestedFolderbaseBoundaryKind::None
                {
                    return Err(TransferSourceError::SourceChanged);
                }
                current = child;
            } else if components.peek().is_some() {
                return Err(TransferSourceError::SourceChanged);
            }
        }
        Ok(())
    }
}

fn case_folded_child(
    directory: &Dir,
    expected: &OsStr,
) -> Result<Option<OsString>, TransferSourceError> {
    let expected = expected
        .to_str()
        .ok_or(TransferSourceError::SourceChanged)?;
    let mut found = None;
    for entry in directory
        .entries()
        .map_err(|_| TransferSourceError::SourceChanged)?
    {
        let entry = entry.map_err(|_| TransferSourceError::SourceChanged)?;
        let name = entry.file_name();
        if name
            .to_str()
            .is_some_and(|name| name.eq_ignore_ascii_case(expected))
        {
            if found.is_some() {
                return Err(TransferSourceError::SourceChanged);
            }
            found = Some(name);
        }
    }
    Ok(found)
}

fn open_optional_file_nofollow(
    root: &Dir,
    relative: &Path,
) -> Result<Option<fs::File>, TransferSourceError> {
    open_optional_file_nofollow_io(root, relative).map_err(|_| TransferSourceError::SourceChanged)
}

fn open_optional_file_nofollow_io(
    root: &Dir,
    relative: &Path,
) -> std::io::Result<Option<fs::File>> {
    let name = relative
        .file_name()
        .ok_or_else(|| std::io::Error::other("source path has no file name"))?;
    let mut current = root.try_clone()?;
    if let Some(parent) = relative.parent() {
        for component in parent.components() {
            let Component::Normal(component) = component else {
                return Err(std::io::Error::other("source path is not relative"));
            };
            match current.open_dir_nofollow(component) {
                Ok(next) => current = next,
                Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(source) => return Err(source),
            }
        }
    }
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    let file = match current.open_with(name, &options) {
        Ok(file) => file.into_std(),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => return Err(source),
    };
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::other("source is not a regular file"));
    }
    Ok(Some(file))
}

fn read_bytes_bounded(
    file: &mut fs::File,
    maximum_bytes: u64,
) -> Result<Vec<u8>, TransferSourceError> {
    let mut bytes = Vec::new();
    file.take(maximum_bytes + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| TransferSourceError::SourceChanged)?;
    if bytes.len() as u64 > maximum_bytes {
        return Err(TransferSourceError::SourceChanged);
    }
    Ok(bytes)
}

fn read_json_bounded<T: serde::de::DeserializeOwned>(
    file: &mut fs::File,
    maximum_bytes: u64,
) -> Result<T, TransferSourceError> {
    let mut encoded = Vec::new();
    file.take(maximum_bytes + 1)
        .read_to_end(&mut encoded)
        .map_err(TransferSourceError::Io)?;
    if encoded.len() as u64 > maximum_bytes {
        return Err(TransferSourceError::SourceChanged);
    }
    serde_json::from_slice(&encoded).map_err(|_| TransferSourceError::SourceChanged)
}

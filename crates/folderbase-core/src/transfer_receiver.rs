//! Durable, capability-rooted receipt of canonical immutable object chunks.
//!
//! This module owns checkpoint persistence, bounded chunk ingestion, resume
//! validation, and pagination. Materialization into a caller-selected
//! destination is deliberately a later module slice.

use std::{
    ffi::OsString,
    io::{Read, Write},
    path::{Component, Path},
    sync::Mutex,
};

use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt};
use cap_std::fs::{Dir, DirBuilder, OpenOptions};
#[cfg(unix)]
use cap_std::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use same_file::Handle;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use uuid::{Uuid, Version};

use crate::transfer_manifest::{
    ChunkDescriptor, ChunkManifest, MAX_ENCODED_MANIFEST_BYTES, ManifestError, ManifestViolation,
    TRANSFER_IO_BUFFER_BYTES, is_sha256,
};

const MANIFEST_FILE: &str = "manifest.json";
const CHUNKS_DIRECTORY: &str = "chunks";
const RECEIVER_LOCK_FILE: &str = "receiver.lock";
pub const MAX_MISSING_CHUNKS_PER_PAGE: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChunkAcceptance {
    Accepted,
    AlreadyPresent,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MissingChunkPage {
    pub chunk_indices: Vec<u32>,
    pub next_cursor: Option<u32>,
}

#[derive(Debug, thiserror::Error)]
pub enum TransferReceiverError {
    #[error("receiver checkpoint path must be a nonempty relative path")]
    UnsafeCheckpointPath,

    #[error("receiver checkpoint already exists")]
    CheckpointAlreadyExists,

    #[error("receiver checkpoint does not exist")]
    CheckpointNotFound,

    #[error("receiver checkpoint I/O failed: {0}")]
    Io(#[source] std::io::Error),

    #[error("chunk manifest violates the protocol: {0}")]
    InvalidManifest(#[from] ManifestViolation),

    #[error("encoded chunk manifest exceeds {maximum_bytes} bytes")]
    EncodedManifestTooLarge { maximum_bytes: u64 },

    #[error("receiver checkpoint manifest is not valid canonical manifest JSON")]
    InvalidCheckpointManifest,

    #[error("legacy pre-v1 transfer checkpoints are unsupported")]
    UnsupportedLegacyCheckpoint,

    #[error("expected manifest digest is not lowercase hexadecimal SHA-256")]
    InvalidExpectedManifestDigest,

    #[error("manifest digest {actual} differs from expected digest {expected}")]
    ManifestDigestMismatch { expected: String, actual: String },

    #[error("receiver checkpoint contains an unrecognized entry")]
    UnrecognizedCheckpointEntry,

    #[error("receiver checkpoint state is accessible outside its owning user")]
    InsecureCheckpointPermissions,

    #[error("receiver checkpoint state changed during the operation")]
    CheckpointStateChanged,

    #[error("chunk {0} is not present in the bound manifest")]
    UnknownChunk(u32),

    #[error("chunk {0} length differs from the manifest")]
    ChunkLengthMismatch(u32),

    #[error("chunk {0} digest differs from the manifest")]
    ChunkDigestMismatch(u32),

    #[error("missing-chunk page limit must be between 1 and {maximum}")]
    InvalidPageLimit { maximum: usize },
}

/// Opaque receiver state bound to one canonical manifest and one opened
/// capability-rooted checkpoint directory.
#[derive(Debug)]
pub struct PersistentTransfer {
    _directory: Dir,
    chunks: Dir,
    receiver_lock: std::fs::File,
    receiver_lock_identity: Handle,
    operation_mutex: Mutex<()>,
    manifest: ChunkManifest,
    manifest_digest: String,
}

impl PersistentTransfer {
    pub fn create(
        root: &Dir,
        relative_checkpoint: impl AsRef<Path>,
        manifest: ChunkManifest,
    ) -> Result<Self, TransferReceiverError> {
        manifest.validate()?;
        let manifest_digest = manifest.canonical_digest()?;
        let encoded = serde_json::to_vec_pretty(&manifest)
            .map_err(|_| TransferReceiverError::InvalidCheckpointManifest)?;
        if encoded.len() as u64 > MAX_ENCODED_MANIFEST_BYTES {
            return Err(TransferReceiverError::EncodedManifestTooLarge {
                maximum_bytes: MAX_ENCODED_MANIFEST_BYTES,
            });
        }

        let relative_checkpoint = relative_checkpoint.as_ref();
        let (parent, name) = open_parent_nofollow(root, relative_checkpoint)?;
        create_private_dir(&parent, &name).map_err(|source| {
            if source.kind() == std::io::ErrorKind::AlreadyExists {
                TransferReceiverError::CheckpointAlreadyExists
            } else {
                TransferReceiverError::Io(source)
            }
        })?;
        let directory = parent
            .open_dir_nofollow(&name)
            .map_err(TransferReceiverError::Io)?;

        (|| {
            create_private_dir(&directory, CHUNKS_DIRECTORY).map_err(TransferReceiverError::Io)?;
            write_private_new(&directory, MANIFEST_FILE, &encoded)?;
            write_private_new(&directory, RECEIVER_LOCK_FILE, &[])?;
            sync_directory(&directory)?;
            sync_directory(&parent)?;
            Self::from_open_directory(directory, manifest, manifest_digest)
        })()
    }

    pub fn open(
        root: &Dir,
        relative_checkpoint: impl AsRef<Path>,
        expected_manifest_digest: &str,
    ) -> Result<Self, TransferReceiverError> {
        validate_expected_digest(expected_manifest_digest)?;
        let relative_checkpoint = relative_checkpoint.as_ref();
        let (parent, name) = open_parent_nofollow(root, relative_checkpoint)?;
        let directory = parent.open_dir_nofollow(&name).map_err(|source| {
            if source.kind() == std::io::ErrorKind::NotFound {
                TransferReceiverError::CheckpointNotFound
            } else {
                TransferReceiverError::Io(source)
            }
        })?;
        validate_private_directory(&directory)?;
        validate_private_regular_file(&directory, MANIFEST_FILE)?;
        let encoded = read_file_bounded(&directory, MANIFEST_FILE, MAX_ENCODED_MANIFEST_BYTES)?;
        let manifest = match ChunkManifest::decode_slice_bounded(&encoded) {
            Ok(manifest) => manifest,
            Err(ManifestError::InvalidJson(_)) if is_legacy_manifest(&encoded) => {
                return Err(TransferReceiverError::UnsupportedLegacyCheckpoint);
            }
            Err(ManifestError::InvalidJson(_)) => {
                return Err(TransferReceiverError::InvalidCheckpointManifest);
            }
            Err(ManifestError::InvalidManifest(violation)) => return Err(violation.into()),
            Err(ManifestError::EncodedManifestTooLarge { maximum_bytes }) => {
                return Err(TransferReceiverError::EncodedManifestTooLarge { maximum_bytes });
            }
        };
        validate_checkpoint_top_level(&directory)?;
        let actual = manifest.canonical_digest()?;
        if actual != expected_manifest_digest {
            return Err(TransferReceiverError::ManifestDigestMismatch {
                expected: expected_manifest_digest.to_owned(),
                actual,
            });
        }
        Self::from_open_directory(directory, manifest, actual)
    }

    pub fn manifest(&self) -> &ChunkManifest {
        &self.manifest
    }

    pub fn manifest_digest(&self) -> &str {
        &self.manifest_digest
    }

    pub fn accept_chunk_from(
        &self,
        index: u32,
        mut reader: impl Read,
    ) -> Result<ChunkAcceptance, TransferReceiverError> {
        let descriptor = self
            .manifest
            .chunks
            .get(index as usize)
            .filter(|descriptor| descriptor.index == index)
            .ok_or(TransferReceiverError::UnknownChunk(index))?;
        let _in_process = self
            .operation_mutex
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _checkpoint_lease = CheckpointLease::acquire(&self.receiver_lock)?;
        let current_lock = open_named_file_identity(&self._directory, RECEIVER_LOCK_FILE)
            .map_err(|_| TransferReceiverError::CheckpointStateChanged)?;
        if current_lock != self.receiver_lock_identity {
            return Err(TransferReceiverError::CheckpointStateChanged);
        }
        reclaim_stale_staging(&self.chunks)?;

        let destination = chunk_file_name(index);
        let staging = format!(".chunk-{}.part", Uuid::now_v7());
        let mut options = OpenOptions::new();
        options
            .write(true)
            .create_new(true)
            .follow(FollowSymlinks::No);
        #[cfg(unix)]
        options.mode(0o600);
        let mut staged = self
            .chunks
            .open_with(&staging, &options)
            .map_err(TransferReceiverError::Io)?;
        let ingestion = copy_exact_chunk(descriptor, &mut reader, &mut staged)
            .and_then(|()| staged.sync_all().map_err(TransferReceiverError::Io));
        let staging_identity =
            Handle::from_file(staged.into_std()).map_err(TransferReceiverError::Io)?;
        let result = ingestion.and_then(|()| {
            let current_staging = open_named_file_identity(&self.chunks, &staging)
                .map_err(|_| TransferReceiverError::CheckpointStateChanged)?;
            if current_staging != staging_identity {
                return Err(TransferReceiverError::CheckpointStateChanged);
            }

            match self.chunks.hard_link(&staging, &self.chunks, &destination) {
                Ok(()) => {
                    sync_directory(&self.chunks)?;
                    let destination_identity = open_named_file_identity(&self.chunks, &destination)
                        .map_err(|_| TransferReceiverError::CheckpointStateChanged)?;
                    if destination_identity != staging_identity {
                        return Err(TransferReceiverError::CheckpointStateChanged);
                    }
                    Ok(ChunkAcceptance::Accepted)
                }
                Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => {
                    let mut existing = open_regular_file_nofollow(&self.chunks, &destination)
                        .map_err(TransferReceiverError::Io)?;
                    validate_chunk_reader(descriptor, &mut existing)?;
                    let existing_identity = Handle::from_file(existing.into_std())
                        .map_err(TransferReceiverError::Io)?;
                    let current_destination = open_named_file_identity(&self.chunks, &destination)
                        .map_err(|_| TransferReceiverError::CheckpointStateChanged)?;
                    if current_destination != existing_identity {
                        return Err(TransferReceiverError::CheckpointStateChanged);
                    }
                    sync_directory(&self.chunks)?;
                    Ok(ChunkAcceptance::AlreadyPresent)
                }
                Err(source) => Err(TransferReceiverError::Io(source)),
            }
        });
        let cleanup = cleanup_owned_staging(&self.chunks, &staging, &staging_identity);
        match cleanup {
            Err(error) => Err(error),
            Ok(()) => result,
        }
    }

    pub fn missing_chunks(
        &self,
        cursor: Option<u32>,
        limit: usize,
    ) -> Result<MissingChunkPage, TransferReceiverError> {
        if limit == 0 || limit > MAX_MISSING_CHUNKS_PER_PAGE {
            return Err(TransferReceiverError::InvalidPageLimit {
                maximum: MAX_MISSING_CHUNKS_PER_PAGE,
            });
        }
        let start = cursor.unwrap_or(0);
        let start = usize::try_from(start).unwrap_or(usize::MAX);
        let end = start.saturating_add(limit).min(self.manifest.chunks.len());
        let mut missing = Vec::with_capacity(end.saturating_sub(start));
        for descriptor in self.manifest.chunks.iter().take(end).skip(start) {
            let file_name = chunk_file_name(descriptor.index);
            match open_regular_file_nofollow(&self.chunks, &file_name) {
                Ok(mut file) => validate_chunk_reader(descriptor, &mut file)?,
                Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                    missing.push(descriptor.index);
                }
                Err(source) => return Err(TransferReceiverError::Io(source)),
            }
        }
        Ok(MissingChunkPage {
            chunk_indices: missing,
            next_cursor: (end < self.manifest.chunks.len()).then_some(end as u32),
        })
    }

    fn from_open_directory(
        directory: Dir,
        manifest: ChunkManifest,
        manifest_digest: String,
    ) -> Result<Self, TransferReceiverError> {
        let chunks = directory
            .open_dir_nofollow(CHUNKS_DIRECTORY)
            .map_err(TransferReceiverError::Io)?;
        let receiver_lock = open_lock_file_nofollow(&directory)?;
        let receiver_lock_identity = Handle::from_file(
            receiver_lock
                .try_clone()
                .map_err(TransferReceiverError::Io)?,
        )
        .map_err(TransferReceiverError::Io)?;
        validate_chunk_entries_for_manifest(&chunks, &manifest)?;
        let transfer = Self {
            _directory: directory,
            chunks,
            receiver_lock,
            receiver_lock_identity,
            operation_mutex: Mutex::new(()),
            manifest,
            manifest_digest,
        };
        transfer.validate_installed_chunks()?;
        Ok(transfer)
    }

    fn validate_installed_chunks(&self) -> Result<(), TransferReceiverError> {
        for descriptor in &self.manifest.chunks {
            match open_regular_file_nofollow(&self.chunks, chunk_file_name(descriptor.index)) {
                Ok(mut file) => validate_chunk_reader(descriptor, &mut file)?,
                Err(source) if source.kind() == std::io::ErrorKind::NotFound => {}
                Err(source) => return Err(TransferReceiverError::Io(source)),
            }
        }
        Ok(())
    }
}

fn open_parent_nofollow(
    root: &Dir,
    relative: &Path,
) -> Result<(Dir, OsString), TransferReceiverError> {
    let mut components = relative.components();
    let Some(Component::Normal(name)) = components.next() else {
        return Err(TransferReceiverError::UnsafeCheckpointPath);
    };
    if components.next().is_some() || relative.as_os_str() != name {
        return Err(TransferReceiverError::UnsafeCheckpointPath);
    }
    Ok((
        root.try_clone().map_err(TransferReceiverError::Io)?,
        name.to_os_string(),
    ))
}

fn create_private_dir(parent: &Dir, name: impl AsRef<Path>) -> std::io::Result<()> {
    let mut builder = DirBuilder::new();
    #[cfg(unix)]
    builder.mode(0o700);
    parent.create_dir_with(name, &builder)
}

fn write_private_new(
    directory: &Dir,
    name: impl AsRef<Path>,
    bytes: &[u8],
) -> Result<(), TransferReceiverError> {
    let mut options = OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .follow(FollowSymlinks::No);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = directory
        .open_with(name, &options)
        .map_err(TransferReceiverError::Io)?;
    file.write_all(bytes).map_err(TransferReceiverError::Io)?;
    file.sync_all().map_err(TransferReceiverError::Io)
}

fn read_file_bounded(
    directory: &Dir,
    name: impl AsRef<Path>,
    maximum: u64,
) -> Result<Vec<u8>, TransferReceiverError> {
    let mut file =
        open_regular_file_nofollow(directory, name).map_err(TransferReceiverError::Io)?;
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(TransferReceiverError::Io)?;
    if bytes.len() as u64 > maximum {
        return Err(TransferReceiverError::EncodedManifestTooLarge {
            maximum_bytes: maximum,
        });
    }
    Ok(bytes)
}

fn open_regular_file_nofollow(
    directory: &Dir,
    name: impl AsRef<Path>,
) -> std::io::Result<cap_std::fs::File> {
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    let file = directory.open_with(name, &options)?;
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::other(
            "checkpoint entry is not a regular file",
        ));
    }
    Ok(file)
}

fn open_lock_file_nofollow(directory: &Dir) -> Result<std::fs::File, TransferReceiverError> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).follow(FollowSymlinks::No);
    let file = directory
        .open_with(RECEIVER_LOCK_FILE, &options)
        .map_err(TransferReceiverError::Io)?;
    if !file
        .metadata()
        .map_err(TransferReceiverError::Io)?
        .is_file()
    {
        return Err(TransferReceiverError::UnrecognizedCheckpointEntry);
    }
    Ok(file.into_std())
}

fn open_named_file_identity(
    directory: &Dir,
    name: impl AsRef<Path>,
) -> Result<Handle, TransferReceiverError> {
    let file = open_regular_file_nofollow(directory, name).map_err(TransferReceiverError::Io)?;
    Handle::from_file(file.into_std()).map_err(TransferReceiverError::Io)
}

fn sync_directory(directory: &Dir) -> Result<(), TransferReceiverError> {
    directory
        .try_clone()
        .and_then(|clone| clone.into_std_file().sync_all())
        .map_err(TransferReceiverError::Io)
}

fn validate_expected_digest(digest: &str) -> Result<(), TransferReceiverError> {
    if !is_sha256(digest) {
        return Err(TransferReceiverError::InvalidExpectedManifestDigest);
    }
    Ok(())
}

fn copy_exact_chunk(
    descriptor: &ChunkDescriptor,
    reader: &mut impl Read,
    writer: &mut impl Write,
) -> Result<(), TransferReceiverError> {
    let mut remaining = descriptor.bytes;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; TRANSFER_IO_BUFFER_BYTES];
    while remaining > 0 {
        let wanted = usize::try_from(remaining.min(buffer.len() as u64))
            .expect("fixed transfer buffer fits usize");
        let read = reader
            .read(&mut buffer[..wanted])
            .map_err(TransferReceiverError::Io)?;
        if read == 0 {
            return Err(TransferReceiverError::ChunkLengthMismatch(descriptor.index));
        }
        writer
            .write_all(&buffer[..read])
            .map_err(TransferReceiverError::Io)?;
        hasher.update(&buffer[..read]);
        remaining -= read as u64;
    }
    let mut trailing = [0_u8; 1];
    if reader
        .read(&mut trailing)
        .map_err(TransferReceiverError::Io)?
        != 0
    {
        return Err(TransferReceiverError::ChunkLengthMismatch(descriptor.index));
    }
    if format!("{:x}", hasher.finalize()) != descriptor.sha256 {
        return Err(TransferReceiverError::ChunkDigestMismatch(descriptor.index));
    }
    Ok(())
}

fn validate_chunk_reader(
    descriptor: &ChunkDescriptor,
    reader: &mut impl Read,
) -> Result<(), TransferReceiverError> {
    copy_exact_chunk(descriptor, reader, &mut std::io::sink())
}

fn chunk_file_name(index: u32) -> String {
    format!("{index}.chunk")
}

struct CheckpointLease<'a> {
    file: &'a std::fs::File,
}

impl<'a> CheckpointLease<'a> {
    fn acquire(file: &'a std::fs::File) -> Result<Self, TransferReceiverError> {
        file.lock().map_err(TransferReceiverError::Io)?;
        Ok(Self { file })
    }
}

impl Drop for CheckpointLease<'_> {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

fn reclaim_stale_staging(chunks: &Dir) -> Result<(), TransferReceiverError> {
    for entry in chunks.entries().map_err(TransferReceiverError::Io)? {
        let entry = entry.map_err(TransferReceiverError::Io)?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| TransferReceiverError::UnrecognizedCheckpointEntry)?;
        if !is_staging_name(&name) {
            continue;
        }
        let metadata = chunks
            .symlink_metadata(&name)
            .map_err(TransferReceiverError::Io)?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(TransferReceiverError::CheckpointStateChanged);
        }
        validate_private_regular_file(chunks, &name)?;
        let identity = open_named_file_identity(chunks, &name)
            .map_err(|_| TransferReceiverError::CheckpointStateChanged)?;
        cleanup_owned_staging(chunks, &name, &identity)?;
    }
    Ok(())
}

fn cleanup_owned_staging(
    chunks: &Dir,
    name: &str,
    expected: &Handle,
) -> Result<(), TransferReceiverError> {
    let current = open_named_file_identity(chunks, name)
        .map_err(|_| TransferReceiverError::CheckpointStateChanged)?;
    if &current != expected {
        return Err(TransferReceiverError::CheckpointStateChanged);
    }
    chunks
        .remove_file(name)
        .map_err(TransferReceiverError::Io)?;
    sync_directory(chunks)
}

fn validate_checkpoint_top_level(directory: &Dir) -> Result<(), TransferReceiverError> {
    validate_private_directory(directory)?;
    let mut has_manifest = false;
    let mut has_chunks = false;
    let mut has_receiver_lock = false;
    for entry in directory.entries().map_err(TransferReceiverError::Io)? {
        let entry = entry.map_err(TransferReceiverError::Io)?;
        match entry.file_name().to_str() {
            Some(MANIFEST_FILE) => has_manifest = true,
            Some(CHUNKS_DIRECTORY) => has_chunks = true,
            Some(RECEIVER_LOCK_FILE) => has_receiver_lock = true,
            _ => return Err(TransferReceiverError::UnrecognizedCheckpointEntry),
        }
    }
    if !has_manifest || !has_chunks || !has_receiver_lock {
        return Err(TransferReceiverError::InvalidCheckpointManifest);
    }
    validate_private_regular_file(directory, MANIFEST_FILE)?;
    validate_private_regular_file(directory, RECEIVER_LOCK_FILE)?;
    let chunks = directory
        .open_dir_nofollow(CHUNKS_DIRECTORY)
        .map_err(TransferReceiverError::Io)?;
    validate_private_directory(&chunks)?;
    Ok(())
}

fn parse_installed_chunk_index(name: &str) -> Option<u32> {
    let index = name.strip_suffix(".chunk")?;
    if index.is_empty() || (index.len() > 1 && index.starts_with('0')) {
        return None;
    }
    index.parse().ok()
}

fn is_staging_name(name: &str) -> bool {
    let Some(encoded) = name
        .strip_prefix(".chunk-")
        .and_then(|suffix| suffix.strip_suffix(".part"))
    else {
        return false;
    };
    Uuid::parse_str(encoded).is_ok_and(|uuid| {
        uuid.get_version() == Some(Version::SortRand) && uuid.hyphenated().to_string() == encoded
    })
}

fn is_legacy_manifest(encoded: &[u8]) -> bool {
    #[derive(Deserialize)]
    struct LegacyManifestProbe {
        object_digest: serde_json::Value,
        bytes: serde_json::Value,
        chunks: serde_json::Value,
    }
    serde_json::from_slice::<LegacyManifestProbe>(encoded)
        .map(|probe| {
            let _ = (probe.object_digest, probe.bytes, probe.chunks);
            true
        })
        .unwrap_or(false)
}

fn validate_chunk_entries_for_manifest(
    chunks: &Dir,
    manifest: &ChunkManifest,
) -> Result<(), TransferReceiverError> {
    validate_private_directory(chunks)?;
    for entry in chunks.entries().map_err(TransferReceiverError::Io)? {
        let entry = entry.map_err(TransferReceiverError::Io)?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| TransferReceiverError::UnrecognizedCheckpointEntry)?;
        let metadata = chunks
            .symlink_metadata(&name)
            .map_err(TransferReceiverError::Io)?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(TransferReceiverError::UnrecognizedCheckpointEntry);
        }
        validate_private_regular_file(chunks, &name)?;
        if is_staging_name(&name) {
            continue;
        }
        let Some(index) = parse_installed_chunk_index(&name) else {
            return Err(TransferReceiverError::UnrecognizedCheckpointEntry);
        };
        if manifest
            .chunks
            .get(index as usize)
            .is_none_or(|descriptor| descriptor.index != index)
        {
            return Err(TransferReceiverError::UnrecognizedCheckpointEntry);
        }
    }
    Ok(())
}

#[cfg(unix)]
fn validate_private_directory(directory: &Dir) -> Result<(), TransferReceiverError> {
    if directory
        .dir_metadata()
        .map_err(TransferReceiverError::Io)?
        .mode()
        & 0o777
        != 0o700
    {
        return Err(TransferReceiverError::InsecureCheckpointPermissions);
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_private_directory(_directory: &Dir) -> Result<(), TransferReceiverError> {
    Ok(())
}

#[cfg(unix)]
fn validate_private_regular_file(
    directory: &Dir,
    name: impl AsRef<Path>,
) -> Result<(), TransferReceiverError> {
    if directory
        .symlink_metadata(name)
        .map_err(TransferReceiverError::Io)?
        .mode()
        & 0o777
        != 0o600
    {
        return Err(TransferReceiverError::InsecureCheckpointPermissions);
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_private_regular_file(
    _directory: &Dir,
    _name: impl AsRef<Path>,
) -> Result<(), TransferReceiverError> {
    Ok(())
}

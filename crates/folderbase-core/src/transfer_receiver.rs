//! Durable, capability-rooted receipt and materialization of immutable objects.
//!
//! This module owns checkpoint persistence, bounded chunk ingestion, resume
//! validation, pagination, canonical whole-object verification, and atomic
//! no-clobber installation beneath caller-opened destination capabilities.

use std::{
    ffi::OsString,
    io::{Read, Write},
    path::{Component, Path, PathBuf},
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
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
    ObjectVerificationError, TRANSFER_IO_BUFFER_BYTES, VerifiedObject, is_sha256,
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

/// Integrity proof for one exact file installed by this process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedMaterialization {
    pub object: VerifiedObject,
    pub relative_destination: PathBuf,
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

    #[error("materialization destination must be an exact nonempty relative path")]
    UnsafeDestinationPath,

    #[error("materialization destination already exists")]
    DestinationAlreadyExists,

    #[error("transfer is incomplete beginning with chunk {first_missing_chunk}")]
    IncompleteTransfer { first_missing_chunk: u32 },

    #[error("materialization destination state changed during the operation")]
    DestinationStateChanged,

    #[error("received object verification failed: {0}")]
    ObjectVerification(#[from] ObjectVerificationError),
}

/// Opaque receiver state bound to one canonical manifest and one opened
/// capability-rooted checkpoint directory.
#[derive(Debug)]
pub struct PersistentTransfer {
    _directory: Dir,
    chunks: Dir,
    receiver_lock: std::fs::File,
    receiver_lock_identity: Handle,
    checkpoint_lease_poisoned: AtomicBool,
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
        let checkpoint_lease =
            CheckpointLease::acquire(&self.receiver_lock, &self.checkpoint_lease_poisoned)?;
        let result = (|| {
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
                        let destination_identity =
                            open_named_file_identity(&self.chunks, &destination)
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
                        let current_destination =
                            open_named_file_identity(&self.chunks, &destination)
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
        })();
        checkpoint_lease.complete(result)
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

    /// Verify and atomically install the complete received object.
    ///
    /// The destination is resolved beneath `destination_root` without following
    /// parent symlinks and must not exist. Object bytes are streamed with fixed
    /// memory from the accepted chunks through the canonical whole-object
    /// verifier into private operation-owned staging beside the destination.
    pub fn materialize_to(
        &self,
        destination_root: &Dir,
        relative_destination: impl AsRef<Path>,
    ) -> Result<VerifiedMaterialization, TransferReceiverError> {
        let relative_destination = relative_destination.as_ref();
        let (destination_parent, destination_name) =
            open_destination_parent_nofollow(destination_root, relative_destination)?;
        let relative_destination = relative_destination.to_path_buf();
        let _in_process = self
            .operation_mutex
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let checkpoint_lease =
            CheckpointLease::acquire(&self.receiver_lock, &self.checkpoint_lease_poisoned)?;
        let result = (|| {
            let current_lock = open_named_file_identity(&self._directory, RECEIVER_LOCK_FILE)
                .map_err(|_| TransferReceiverError::CheckpointStateChanged)?;
            if current_lock != self.receiver_lock_identity {
                return Err(TransferReceiverError::CheckpointStateChanged);
            }
            if let Some(first_missing_chunk) = self.first_missing_chunk()? {
                return Err(TransferReceiverError::IncompleteTransfer {
                    first_missing_chunk,
                });
            }
            ensure_destination_absent(&destination_parent, &destination_name)?;

            let staging = format!(".folderbase-materialize-{}.part", Uuid::now_v7());
            let mut options = OpenOptions::new();
            options
                .write(true)
                .create_new(true)
                .follow(FollowSymlinks::No);
            #[cfg(unix)]
            options.mode(0o600);
            let mut staged = destination_parent
                .open_with(&staging, &options)
                .map_err(TransferReceiverError::Io)?;
            let staging_identity = Handle::from_file(
                staged
                    .try_clone()
                    .map_err(TransferReceiverError::Io)?
                    .into_std(),
            )
            .map_err(TransferReceiverError::Io)?;

            let operation = (|| {
                let reader = AcceptedChunkReader::new(&self.chunks, &self.manifest);
                let object = self.manifest.verify_object_and_copy(reader, &mut staged)?;
                staged.sync_all().map_err(TransferReceiverError::Io)?;
                validate_private_regular_file(&destination_parent, &staging)?;
                let current_staging = open_named_file_identity(&destination_parent, &staging)
                    .map_err(|_| TransferReceiverError::DestinationStateChanged)?;
                if current_staging != staging_identity {
                    return Err(TransferReceiverError::DestinationStateChanged);
                }
                let current_lock = open_named_file_identity(&self._directory, RECEIVER_LOCK_FILE)
                    .map_err(|_| TransferReceiverError::CheckpointStateChanged)?;
                if current_lock != self.receiver_lock_identity {
                    return Err(TransferReceiverError::CheckpointStateChanged);
                }

                match destination_parent.hard_link(&staging, &destination_parent, &destination_name)
                {
                    Ok(()) => {}
                    Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => {
                        return Err(TransferReceiverError::DestinationAlreadyExists);
                    }
                    Err(source) => return Err(TransferReceiverError::Io(source)),
                }
                let destination_identity =
                    open_named_file_identity(&destination_parent, &destination_name)
                        .map_err(|_| TransferReceiverError::DestinationStateChanged)?;
                if destination_identity != staging_identity {
                    return Err(TransferReceiverError::DestinationStateChanged);
                }
                sync_directory(&destination_parent)?;
                Ok(VerifiedMaterialization {
                    object,
                    relative_destination,
                })
            })();

            let cleanup =
                cleanup_materialization_staging(&destination_parent, &staging, &staging_identity);
            match cleanup {
                Err(error) => Err(error),
                Ok(()) => operation,
            }
        })();
        checkpoint_lease.complete(result)
    }

    fn first_missing_chunk(&self) -> Result<Option<u32>, TransferReceiverError> {
        for descriptor in &self.manifest.chunks {
            let name = chunk_file_name(descriptor.index);
            match open_regular_file_nofollow(&self.chunks, &name) {
                Ok(_) => validate_private_regular_file(&self.chunks, &name)?,
                Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                    return Ok(Some(descriptor.index));
                }
                Err(source) => return Err(TransferReceiverError::Io(source)),
            }
        }
        Ok(None)
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
            checkpoint_lease_poisoned: AtomicBool::new(false),
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

fn open_destination_parent_nofollow(
    root: &Dir,
    relative: &Path,
) -> Result<(Dir, OsString), TransferReceiverError> {
    if relative.as_os_str().is_empty() || relative.is_absolute() {
        return Err(TransferReceiverError::UnsafeDestinationPath);
    }
    let mut names = Vec::new();
    let mut exact = PathBuf::new();
    for component in relative.components() {
        let Component::Normal(name) = component else {
            return Err(TransferReceiverError::UnsafeDestinationPath);
        };
        exact.push(name);
        names.push(name.to_os_string());
    }
    if names.is_empty() || exact.as_os_str() != relative.as_os_str() {
        return Err(TransferReceiverError::UnsafeDestinationPath);
    }
    let destination_name = names
        .pop()
        .expect("a validated destination contains a leaf");
    let mut current = root.try_clone().map_err(TransferReceiverError::Io)?;
    for name in names {
        current = current
            .open_dir_nofollow(&name)
            .map_err(TransferReceiverError::Io)?;
    }
    Ok((current, destination_name))
}

fn ensure_destination_absent(
    parent: &Dir,
    name: impl AsRef<Path>,
) -> Result<(), TransferReceiverError> {
    match parent.symlink_metadata(name) {
        Ok(_) => Err(TransferReceiverError::DestinationAlreadyExists),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(TransferReceiverError::Io(source)),
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

struct AcceptedChunkReader<'a> {
    chunks: &'a Dir,
    manifest: &'a ChunkManifest,
    next_index: usize,
    current: Option<AcceptedChunkFile>,
}

struct AcceptedChunkFile {
    file: cap_std::fs::File,
    remaining: u64,
    index: u32,
    name: String,
    identity: Handle,
}

impl<'a> AcceptedChunkReader<'a> {
    fn new(chunks: &'a Dir, manifest: &'a ChunkManifest) -> Self {
        Self {
            chunks,
            manifest,
            next_index: 0,
            current: None,
        }
    }
}

impl Read for AcceptedChunkReader<'_> {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        loop {
            if let Some(current) = self.current.as_mut() {
                if current.remaining > 0 {
                    let wanted = usize::try_from(current.remaining.min(output.len() as u64))
                        .expect("fixed caller buffer fits usize");
                    let read = current.file.read(&mut output[..wanted])?;
                    if read == 0 {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            format!("accepted chunk {} is truncated", current.index),
                        ));
                    }
                    current.remaining -= read as u64;
                    return Ok(read);
                }
                let mut trailing = [0_u8; 1];
                if current.file.read(&mut trailing)? != 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("accepted chunk {} contains trailing bytes", current.index),
                    ));
                }
                let current_identity = open_named_file_identity(self.chunks, &current.name)
                    .map_err(|error| {
                        std::io::Error::other(format!(
                            "accepted chunk {} pathname changed: {error}",
                            current.index
                        ))
                    })?;
                if current_identity != current.identity {
                    return Err(std::io::Error::other(format!(
                        "accepted chunk {} pathname identity changed",
                        current.index
                    )));
                }
                self.current = None;
            }

            let Some(descriptor) = self.manifest.chunks.get(self.next_index) else {
                return Ok(0);
            };
            let name = chunk_file_name(descriptor.index);
            let file = open_regular_file_nofollow(self.chunks, &name)?;
            validate_private_regular_file(self.chunks, &name)
                .map_err(|error| std::io::Error::other(error.to_string()))?;
            let identity =
                Handle::from_file(file.try_clone()?.into_std()).map_err(std::io::Error::other)?;
            self.current = Some(AcceptedChunkFile {
                file,
                remaining: descriptor.bytes,
                index: descriptor.index,
                name,
                identity,
            });
            self.next_index += 1;
        }
    }
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

#[cfg(unix)]
fn sync_directory(directory: &Dir) -> Result<(), TransferReceiverError> {
    directory
        .open_with(
            ".",
            OpenOptions::new().read(true).follow(FollowSymlinks::No),
        )
        .and_then(|file| file.into_std().sync_all())
        .map_err(TransferReceiverError::Io)
}

#[cfg(windows)]
fn sync_directory(_directory: &Dir) -> Result<(), TransferReceiverError> {
    // Windows exposes no documented equivalent of POSIX directory fsync.
    // Every staged regular file is still flushed before its no-clobber install.
    Ok(())
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

trait CheckpointLock {
    fn lock_exclusive(&self) -> std::io::Result<()>;
    fn unlock_exclusive(&self) -> std::io::Result<()>;
}

impl CheckpointLock for std::fs::File {
    fn lock_exclusive(&self) -> std::io::Result<()> {
        self.lock()
    }

    fn unlock_exclusive(&self) -> std::io::Result<()> {
        self.unlock()
    }
}

struct CheckpointLease<'a, L: CheckpointLock + ?Sized> {
    lock: &'a L,
    poisoned: &'a AtomicBool,
    released: bool,
}

impl<'a, L: CheckpointLock + ?Sized> CheckpointLease<'a, L> {
    fn acquire(lock: &'a L, poisoned: &'a AtomicBool) -> Result<Self, TransferReceiverError> {
        if poisoned.load(Ordering::Acquire) {
            return Err(TransferReceiverError::CheckpointStateChanged);
        }
        lock.lock_exclusive().map_err(TransferReceiverError::Io)?;
        Ok(Self {
            lock,
            poisoned,
            released: false,
        })
    }

    fn complete<T>(
        mut self,
        operation: Result<T, TransferReceiverError>,
    ) -> Result<T, TransferReceiverError> {
        match self.lock.unlock_exclusive() {
            Ok(()) => {
                self.released = true;
                operation
            }
            Err(source) => {
                self.poisoned.store(true, Ordering::Release);
                Err(TransferReceiverError::Io(source))
            }
        }
    }
}

impl<L: CheckpointLock + ?Sized> Drop for CheckpointLease<'_, L> {
    fn drop(&mut self) {
        if !self.released && self.lock.unlock_exclusive().is_err() {
            self.poisoned.store(true, Ordering::Release);
        }
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

fn cleanup_materialization_staging(
    parent: &Dir,
    name: &str,
    expected: &Handle,
) -> Result<(), TransferReceiverError> {
    let current = open_named_file_identity(parent, name)
        .map_err(|_| TransferReceiverError::DestinationStateChanged)?;
    if &current != expected {
        return Err(TransferReceiverError::DestinationStateChanged);
    }
    parent
        .remove_file(name)
        .map_err(TransferReceiverError::Io)?;
    sync_directory(parent)
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

#[cfg(test)]
mod tests {
    use std::{
        cell::Cell,
        io,
        sync::atomic::{AtomicBool, Ordering},
    };

    use super::{CheckpointLease, CheckpointLock, ChunkAcceptance, TransferReceiverError};

    #[derive(Default)]
    struct InjectedUnlockFailure {
        lock_calls: Cell<usize>,
        unlock_calls: Cell<usize>,
    }

    impl CheckpointLock for InjectedUnlockFailure {
        fn lock_exclusive(&self) -> io::Result<()> {
            self.lock_calls.set(self.lock_calls.get() + 1);
            Ok(())
        }

        fn unlock_exclusive(&self) -> io::Result<()> {
            self.unlock_calls.set(self.unlock_calls.get() + 1);
            Err(io::Error::other("injected unlock failure"))
        }
    }

    #[test]
    fn explicit_unlock_failure_is_reported_and_poisoned_before_relock() {
        let lock = InjectedUnlockFailure::default();
        let poisoned = AtomicBool::new(false);
        let lease = CheckpointLease::acquire(&lock, &poisoned).unwrap();

        let result = lease.complete(Ok(ChunkAcceptance::Accepted));

        assert!(
            matches!(result, Err(TransferReceiverError::Io(ref error))
                if error.to_string() == "injected unlock failure"),
            "{result:?}"
        );
        assert!(poisoned.load(Ordering::Acquire));
        assert_eq!(lock.lock_calls.get(), 1);
        assert_eq!(
            lock.unlock_calls.get(),
            2,
            "ordinary release is explicit and Drop makes one best-effort retry"
        );
        assert!(matches!(
            CheckpointLease::acquire(&lock, &poisoned),
            Err(TransferReceiverError::CheckpointStateChanged)
        ));
        assert_eq!(
            lock.lock_calls.get(),
            1,
            "a poisoned receiver must fail before a platform-dependent relock"
        );
    }
}

use std::{
    collections::BTreeMap,
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkingConfig {
    pub minimum_bytes: usize,
    pub average_bytes: usize,
    pub maximum_bytes: usize,
}

impl Default for ChunkingConfig {
    fn default() -> Self {
        Self {
            minimum_bytes: 256 * 1024,
            average_bytes: 1024 * 1024,
            maximum_bytes: 4 * 1024 * 1024,
        }
    }
}

impl ChunkingConfig {
    fn validate(self) -> Result<(), TransferError> {
        if self.minimum_bytes == 0
            || self.average_bytes < self.minimum_bytes
            || self.maximum_bytes < self.average_bytes
            || !self.average_bytes.is_power_of_two()
        {
            return Err(TransferError::InvalidChunkingConfig);
        }
        Ok(())
    }
}

/// Legacy small-buffer checkpoint shape retained for existing Rust callers.
///
/// New portable transfers use
/// [`crate::transfer_manifest::ChunkManifest`]. The two JSON shapes are
/// intentionally distinct and are never decoded as one another.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChunkManifest {
    pub algorithm: String,
    pub object_digest: String,
    pub bytes: u64,
    pub chunks: Vec<ChunkDescriptor>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChunkDescriptor {
    pub index: u32,
    pub offset: u64,
    pub bytes: u64,
    pub digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransferError {
    InvalidChunkingConfig,
    InvalidCheckpoint,
    UnknownChunk(u32),
    ChunkDigestMismatch(u32),
    ChunkLengthMismatch(u32),
    Incomplete { missing: Vec<u32> },
    ObjectDigestMismatch,
    Io(String),
}

/// Split bytes at rolling, content-defined boundaries.
///
/// Identical regions continue to produce identical chunks when bytes are
/// inserted before them, unlike fixed-offset chunking. SHA-256 remains the
/// integrity identity; the rolling value is used only to select boundaries.
pub fn chunk_content(bytes: &[u8], config: ChunkingConfig) -> Result<ChunkManifest, TransferError> {
    config.validate()?;
    let mut descriptors = Vec::new();
    let mut start = 0;
    let mut rolling = 0_u64;
    let mask = (config.average_bytes - 1) as u64;

    for (index, byte) in bytes.iter().enumerate() {
        rolling = rolling
            .rotate_left(1)
            .wrapping_add((*byte as u64).wrapping_mul(0x9e37_79b1));
        let length = index + 1 - start;
        let at_content_boundary = length >= config.minimum_bytes && (rolling & mask) == 0;
        let at_maximum = length >= config.maximum_bytes;
        if at_content_boundary || at_maximum {
            descriptors.push(descriptor(descriptors.len(), start, &bytes[start..=index]));
            start = index + 1;
            rolling = 0;
        }
    }
    if start < bytes.len() {
        descriptors.push(descriptor(descriptors.len(), start, &bytes[start..]));
    }

    Ok(ChunkManifest {
        algorithm: "folderbase-cdc-v1+sha256".to_owned(),
        object_digest: digest(bytes),
        bytes: bytes.len() as u64,
        chunks: descriptors,
    })
}

/// Durable transfer state can serialize `manifest` plus the accepted chunk
/// digests. Retries may safely submit any chunk again.
#[derive(Debug, Clone)]
pub struct ResumableTransfer {
    manifest: ChunkManifest,
    received: BTreeMap<u32, Vec<u8>>,
}

/// Filesystem-backed transfer state that survives process and device restart.
///
/// Each accepted chunk is installed atomically with no-clobber semantics.
/// Incomplete staging files are ignored when the transfer is reopened.
#[derive(Debug)]
pub struct PersistentTransfer {
    directory: PathBuf,
    manifest: ChunkManifest,
}

impl PersistentTransfer {
    pub fn create(
        directory: impl AsRef<Path>,
        manifest: ChunkManifest,
    ) -> Result<Self, TransferError> {
        validate_manifest(&manifest)?;
        let directory = directory.as_ref().to_path_buf();
        fs::create_dir(&directory).map_err(io_error)?;
        fs::create_dir(directory.join("chunks")).map_err(io_error)?;
        let encoded =
            serde_json::to_vec_pretty(&manifest).map_err(|_| TransferError::InvalidCheckpoint)?;
        let manifest_path = directory.join("manifest.json");
        write_new_synced(&manifest_path, &encoded)?;
        sync_directory(&directory)?;
        Ok(Self {
            directory,
            manifest,
        })
    }

    pub fn open(directory: impl AsRef<Path>) -> Result<Self, TransferError> {
        let directory = directory.as_ref().to_path_buf();
        let encoded = fs::read(directory.join("manifest.json")).map_err(io_error)?;
        let manifest: ChunkManifest =
            serde_json::from_slice(&encoded).map_err(|_| TransferError::InvalidCheckpoint)?;
        validate_manifest(&manifest)?;
        let transfer = Self {
            directory,
            manifest,
        };
        for descriptor in &transfer.manifest.chunks {
            let path = transfer.chunk_path(descriptor.index);
            if path.exists() {
                let bytes = fs::read(&path).map_err(io_error)?;
                validate_chunk(descriptor, &bytes)?;
            }
        }
        Ok(transfer)
    }

    pub fn manifest(&self) -> &ChunkManifest {
        &self.manifest
    }

    pub fn accept_chunk(&self, index: u32, bytes: &[u8]) -> Result<bool, TransferError> {
        let descriptor = self
            .manifest
            .chunks
            .iter()
            .find(|chunk| chunk.index == index)
            .ok_or(TransferError::UnknownChunk(index))?;
        validate_chunk(descriptor, bytes)?;
        let destination = self.chunk_path(index);
        if destination.exists() {
            let existing = fs::read(&destination).map_err(io_error)?;
            validate_chunk(descriptor, &existing)?;
            return Ok(false);
        }

        let staged = self
            .directory
            .join("chunks")
            .join(format!(".{}.part", Uuid::now_v7()));
        write_new_synced(&staged, bytes)?;
        match fs::hard_link(&staged, &destination) {
            Ok(()) => {
                fs::remove_file(&staged).map_err(io_error)?;
                sync_directory(&self.directory.join("chunks"))?;
                Ok(true)
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let _ = fs::remove_file(&staged);
                let existing = fs::read(&destination).map_err(io_error)?;
                validate_chunk(descriptor, &existing)?;
                Ok(false)
            }
            Err(error) => {
                let _ = fs::remove_file(&staged);
                Err(io_error(error))
            }
        }
    }

    pub fn missing_chunks(&self) -> Result<Vec<u32>, TransferError> {
        let mut missing = Vec::new();
        for descriptor in &self.manifest.chunks {
            let path = self.chunk_path(descriptor.index);
            match fs::read(&path) {
                Ok(bytes) => validate_chunk(descriptor, &bytes)?,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    missing.push(descriptor.index);
                }
                Err(error) => return Err(io_error(error)),
            }
        }
        Ok(missing)
    }

    pub fn assemble(&self) -> Result<Vec<u8>, TransferError> {
        let missing = self.missing_chunks()?;
        if !missing.is_empty() {
            return Err(TransferError::Incomplete { missing });
        }
        let mut assembled = Vec::with_capacity(self.manifest.bytes as usize);
        for descriptor in &self.manifest.chunks {
            let bytes = fs::read(self.chunk_path(descriptor.index)).map_err(io_error)?;
            validate_chunk(descriptor, &bytes)?;
            assembled.extend_from_slice(&bytes);
        }
        if assembled.len() as u64 != self.manifest.bytes
            || digest(&assembled) != self.manifest.object_digest
        {
            return Err(TransferError::ObjectDigestMismatch);
        }
        Ok(assembled)
    }

    fn chunk_path(&self, index: u32) -> PathBuf {
        self.directory.join("chunks").join(format!("{index}.chunk"))
    }
}

impl ResumableTransfer {
    pub fn new(manifest: ChunkManifest) -> Self {
        Self {
            manifest,
            received: BTreeMap::new(),
        }
    }

    pub fn manifest(&self) -> &ChunkManifest {
        &self.manifest
    }

    pub fn accept_chunk(&mut self, index: u32, bytes: Vec<u8>) -> Result<bool, TransferError> {
        let expected = self
            .manifest
            .chunks
            .iter()
            .find(|chunk| chunk.index == index)
            .ok_or(TransferError::UnknownChunk(index))?;
        if bytes.len() as u64 != expected.bytes {
            return Err(TransferError::ChunkLengthMismatch(index));
        }
        if digest(&bytes) != expected.digest {
            return Err(TransferError::ChunkDigestMismatch(index));
        }
        if self.received.contains_key(&index) {
            return Ok(false);
        }
        self.received.insert(index, bytes);
        Ok(true)
    }

    pub fn missing_chunks(&self) -> Vec<u32> {
        self.manifest
            .chunks
            .iter()
            .filter(|chunk| !self.received.contains_key(&chunk.index))
            .map(|chunk| chunk.index)
            .collect()
    }

    pub fn received_bytes(&self) -> u64 {
        self.received.values().map(|bytes| bytes.len() as u64).sum()
    }

    pub fn assemble(&self) -> Result<Vec<u8>, TransferError> {
        let missing = self.missing_chunks();
        if !missing.is_empty() {
            return Err(TransferError::Incomplete { missing });
        }
        let mut assembled = Vec::with_capacity(self.manifest.bytes as usize);
        for chunk in &self.manifest.chunks {
            assembled.extend_from_slice(
                self.received
                    .get(&chunk.index)
                    .expect("missing chunks checked above"),
            );
        }
        if assembled.len() as u64 != self.manifest.bytes
            || digest(&assembled) != self.manifest.object_digest
        {
            return Err(TransferError::ObjectDigestMismatch);
        }
        Ok(assembled)
    }
}

pub fn chunks_for<'a>(
    bytes: &'a [u8],
    manifest: &'a ChunkManifest,
) -> impl Iterator<Item = (u32, &'a [u8])> + 'a {
    manifest.chunks.iter().map(move |chunk| {
        let start = chunk.offset as usize;
        let end = start + chunk.bytes as usize;
        (chunk.index, &bytes[start..end])
    })
}

fn descriptor(index: usize, offset: usize, bytes: &[u8]) -> ChunkDescriptor {
    ChunkDescriptor {
        index: index as u32,
        offset: offset as u64,
        bytes: bytes.len() as u64,
        digest: digest(bytes),
    }
}

fn validate_manifest(manifest: &ChunkManifest) -> Result<(), TransferError> {
    if manifest.algorithm != "folderbase-cdc-v1+sha256"
        || manifest.object_digest.len() != 64
        || manifest.chunks.iter().enumerate().any(|(index, chunk)| {
            chunk.index != index as u32
                || chunk.digest.len() != 64
                || (index == 0 && chunk.offset != 0)
                || (index > 0
                    && chunk.offset
                        != manifest.chunks[index - 1].offset + manifest.chunks[index - 1].bytes)
        })
        || manifest.chunks.iter().map(|chunk| chunk.bytes).sum::<u64>() != manifest.bytes
    {
        return Err(TransferError::InvalidCheckpoint);
    }
    Ok(())
}

fn validate_chunk(descriptor: &ChunkDescriptor, bytes: &[u8]) -> Result<(), TransferError> {
    if bytes.len() as u64 != descriptor.bytes {
        return Err(TransferError::ChunkLengthMismatch(descriptor.index));
    }
    if digest(bytes) != descriptor.digest {
        return Err(TransferError::ChunkDigestMismatch(descriptor.index));
    }
    Ok(())
}

fn write_new_synced(path: &Path, bytes: &[u8]) -> Result<(), TransferError> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(io_error)?;
    file.write_all(bytes).map_err(io_error)?;
    file.sync_all().map_err(io_error)
}

fn sync_directory(path: &Path) -> Result<(), TransferError> {
    fs::File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(io_error)
}

fn io_error(error: std::io::Error) -> TransferError {
    TransferError::Io(error.to_string())
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> ChunkingConfig {
        ChunkingConfig {
            minimum_bytes: 8,
            average_bytes: 16,
            maximum_bytes: 32,
        }
    }

    #[test]
    fn chunk_manifest_covers_every_byte_and_is_deterministic() {
        let bytes = (0..=255).cycle().take(8192).collect::<Vec<_>>();
        let first = chunk_content(&bytes, config()).unwrap();
        let second = chunk_content(&bytes, config()).unwrap();

        assert_eq!(first, second);
        assert_eq!(
            first.chunks.iter().map(|chunk| chunk.bytes).sum::<u64>(),
            bytes.len() as u64
        );
        assert!(first.chunks.iter().all(|chunk| chunk.bytes <= 32));
    }

    #[test]
    fn interrupted_transfer_resumes_from_missing_chunks() {
        let bytes = (0..=250).cycle().take(4096).collect::<Vec<_>>();
        let manifest = chunk_content(&bytes, config()).unwrap();
        let source_chunks = chunks_for(&bytes, &manifest)
            .map(|(index, chunk)| (index, chunk.to_vec()))
            .collect::<Vec<_>>();
        let mut transfer = ResumableTransfer::new(manifest);

        for (index, chunk) in source_chunks.iter().step_by(2) {
            transfer.accept_chunk(*index, chunk.clone()).unwrap();
        }
        let missing = transfer.missing_chunks();
        assert!(!missing.is_empty());
        assert!(matches!(
            transfer.assemble(),
            Err(TransferError::Incomplete { .. })
        ));

        for (index, chunk) in source_chunks {
            transfer.accept_chunk(index, chunk).unwrap();
        }
        assert_eq!(transfer.assemble().unwrap(), bytes);
    }

    #[test]
    fn duplicate_chunks_are_idempotent_and_corruption_is_rejected() {
        let bytes = b"abcdefghijklmnopqrstuvwxyz0123456789".repeat(12);
        let manifest = chunk_content(&bytes, config()).unwrap();
        let (index, first) = chunks_for(&bytes, &manifest)
            .next()
            .map(|(index, chunk)| (index, chunk.to_vec()))
            .unwrap();
        let mut transfer = ResumableTransfer::new(manifest);

        assert!(transfer.accept_chunk(index, first.clone()).unwrap());
        assert!(!transfer.accept_chunk(index, first.clone()).unwrap());
        let mut corrupt = first;
        corrupt[0] ^= 0xff;
        assert_eq!(
            transfer.accept_chunk(index, corrupt),
            Err(TransferError::ChunkDigestMismatch(index))
        );
    }

    #[test]
    fn persistent_transfer_reopens_after_process_restart() {
        let root = tempfile::tempdir().unwrap();
        let bytes = (0..=250).cycle().take(4096).collect::<Vec<_>>();
        let manifest = chunk_content(&bytes, config()).unwrap();
        let source_chunks = chunks_for(&bytes, &manifest)
            .map(|(index, chunk)| (index, chunk.to_vec()))
            .collect::<Vec<_>>();
        let directory = root.path().join("transfer");

        {
            let transfer = PersistentTransfer::create(&directory, manifest).unwrap();
            for (index, chunk) in source_chunks.iter().take(3) {
                transfer.accept_chunk(*index, chunk).unwrap();
            }
        }

        let reopened = PersistentTransfer::open(&directory).unwrap();
        assert!(!reopened.missing_chunks().unwrap().is_empty());
        for (index, chunk) in &source_chunks {
            reopened.accept_chunk(*index, chunk).unwrap();
        }
        drop(reopened);

        let reopened_again = PersistentTransfer::open(&directory).unwrap();
        assert!(reopened_again.missing_chunks().unwrap().is_empty());
        assert_eq!(reopened_again.assemble().unwrap(), bytes);
    }

    #[test]
    fn persistent_transfer_rejects_corrupted_checkpoint_chunks() {
        let root = tempfile::tempdir().unwrap();
        let bytes = b"abcdefghijklmnopqrstuvwxyz0123456789".repeat(12);
        let manifest = chunk_content(&bytes, config()).unwrap();
        let (index, chunk) = chunks_for(&bytes, &manifest)
            .next()
            .map(|(index, chunk)| (index, chunk.to_vec()))
            .unwrap();
        let directory = root.path().join("transfer");
        let transfer = PersistentTransfer::create(&directory, manifest).unwrap();
        transfer.accept_chunk(index, &chunk).unwrap();
        fs::write(
            directory.join("chunks").join(format!("{index}.chunk")),
            b"corrupt",
        )
        .unwrap();

        assert!(matches!(
            PersistentTransfer::open(&directory),
            Err(TransferError::ChunkLengthMismatch(_)) | Err(TransferError::ChunkDigestMismatch(_))
        ));
    }
}

use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Component, Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{FolderbaseError, Result};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ContentKind {
    Text,
    Binary,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SyncVersion {
    pub digest: String,
    pub bytes: u64,
    pub kind: ContentKind,
    pub author_device: String,
    pub sequence: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SyncEvent {
    pub id: String,
    pub path: PathBuf,
    pub version: SyncVersion,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SyncConflict {
    pub path: PathBuf,
    pub base_digest: Option<String>,
    pub local: SyncVersion,
    pub remote: SyncVersion,
    pub classification: ConflictClassification,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConflictClassification {
    TextNeedsMerge,
    PreserveBothBinary,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SyncReport {
    pub uploaded: Vec<PathBuf>,
    pub downloaded: Vec<PathBuf>,
    pub unchanged: Vec<PathBuf>,
    pub conflicts: Vec<SyncConflict>,
}

#[derive(Debug, Clone)]
struct LocalEntry {
    bytes: Vec<u8>,
    kind: ContentKind,
    base_digest: Option<String>,
}

/// A deterministic logical device used by the native client and fault tests.
///
/// It intentionally models sync separately from filesystem watching. Native
/// clients feed completed local writes into this module only after the local
/// object store has captured and verified them.
#[derive(Debug)]
pub struct SyncReplica {
    device_id: String,
    entries: BTreeMap<PathBuf, LocalEntry>,
    applied_events: BTreeSet<String>,
    applied_sequences: BTreeMap<PathBuf, u64>,
}

impl SyncReplica {
    pub fn new(device_id: impl Into<String>) -> Self {
        Self {
            device_id: device_id.into(),
            entries: BTreeMap::new(),
            applied_events: BTreeSet::new(),
            applied_sequences: BTreeMap::new(),
        }
    }

    pub fn write(
        &mut self,
        path: impl AsRef<Path>,
        bytes: impl Into<Vec<u8>>,
        kind: ContentKind,
    ) -> Result<()> {
        let path = path.as_ref().to_path_buf();
        ensure_safe_relative(&path)?;
        let base_digest = self
            .entries
            .get(&path)
            .and_then(|entry| entry.base_digest.clone());
        self.entries.insert(
            path,
            LocalEntry {
                bytes: bytes.into(),
                kind,
                base_digest,
            },
        );
        Ok(())
    }

    pub fn read(&self, path: impl AsRef<Path>) -> Option<&[u8]> {
        self.entries
            .get(path.as_ref())
            .map(|entry| entry.bytes.as_slice())
    }

    pub fn sync(&mut self, cloud: &mut MemorySyncCloud) -> Result<SyncReport> {
        let mut report = SyncReport::default();
        let mut paths = self.entries.keys().cloned().collect::<BTreeSet<_>>();
        paths.extend(cloud.canonical.keys().cloned());

        for path in paths {
            ensure_safe_relative(&path)?;
            let remote = cloud.canonical.get(&path).cloned();
            let local = self.entries.get(&path).cloned();

            match (local, remote) {
                (Some(mut local), None) => {
                    let local_version = cloud.capture(&self.device_id, &local.bytes, local.kind);
                    cloud.publish(path.clone(), local_version.clone());
                    local.base_digest = Some(local_version.digest.clone());
                    self.entries.insert(path.clone(), local);
                    self.applied_sequences
                        .insert(path.clone(), local_version.sequence);
                    report.uploaded.push(path);
                }
                (None, Some(remote)) => {
                    let bytes = cloud.materialize(&remote.digest)?.to_vec();
                    self.entries.insert(
                        path.clone(),
                        LocalEntry {
                            bytes,
                            kind: remote.kind,
                            base_digest: Some(remote.digest.clone()),
                        },
                    );
                    self.applied_sequences.insert(path.clone(), remote.sequence);
                    report.downloaded.push(path);
                }
                (Some(mut local), Some(remote)) => {
                    let local_digest = digest(&local.bytes);
                    if local_digest == remote.digest {
                        local.base_digest = Some(remote.digest.clone());
                        self.entries.insert(path.clone(), local);
                        self.applied_sequences.insert(path.clone(), remote.sequence);
                        report.unchanged.push(path);
                        continue;
                    }

                    if local.base_digest.as_deref() == Some(remote.digest.as_str()) {
                        let local_version =
                            cloud.capture(&self.device_id, &local.bytes, local.kind);
                        cloud.publish(path.clone(), local_version.clone());
                        local.base_digest = Some(local_version.digest.clone());
                        self.entries.insert(path.clone(), local);
                        self.applied_sequences
                            .insert(path.clone(), local_version.sequence);
                        report.uploaded.push(path);
                        continue;
                    }

                    if local.base_digest.as_deref() == Some(local_digest.as_str()) {
                        let bytes = cloud.materialize(&remote.digest)?.to_vec();
                        self.entries.insert(
                            path.clone(),
                            LocalEntry {
                                bytes,
                                kind: remote.kind,
                                base_digest: Some(remote.digest.clone()),
                            },
                        );
                        self.applied_sequences.insert(path.clone(), remote.sequence);
                        report.downloaded.push(path);
                        continue;
                    }

                    let local_version = cloud.capture(&self.device_id, &local.bytes, local.kind);
                    let classification =
                        if local.kind == ContentKind::Text && remote.kind == ContentKind::Text {
                            ConflictClassification::TextNeedsMerge
                        } else {
                            ConflictClassification::PreserveBothBinary
                        };
                    let conflict = SyncConflict {
                        path: path.clone(),
                        base_digest: local.base_digest.clone(),
                        local: local_version,
                        remote,
                        classification,
                    };
                    cloud.record_conflict(conflict.clone());
                    report.conflicts.push(conflict);
                }
                (None, None) => {}
            }
        }

        sort_report(&mut report);
        Ok(report)
    }

    /// Apply a notification idempotently.
    ///
    /// Dirty local content is never replaced; a normal sync will classify the
    /// divergence and preserve both sides.
    pub fn apply_event(&mut self, cloud: &MemorySyncCloud, event: &SyncEvent) -> Result<bool> {
        ensure_safe_relative(&event.path)?;
        if self.applied_events.contains(&event.id) {
            return Ok(false);
        }
        if self
            .applied_sequences
            .get(&event.path)
            .is_some_and(|sequence| *sequence >= event.version.sequence)
        {
            self.applied_events.insert(event.id.clone());
            return Ok(false);
        }

        let can_download = self.entries.get(&event.path).is_none_or(|entry| {
            let local_digest = digest(&entry.bytes);
            entry.base_digest.as_deref() == Some(local_digest.as_str())
        });
        if !can_download {
            return Ok(false);
        }

        let bytes = cloud.materialize(&event.version.digest)?.to_vec();
        if digest(&bytes) != event.version.digest || bytes.len() as u64 != event.version.bytes {
            return Err(FolderbaseError::InvalidRecord {
                path: event.path.clone(),
                message: "sync event content failed integrity verification".to_owned(),
            });
        }
        self.entries.insert(
            event.path.clone(),
            LocalEntry {
                bytes,
                kind: event.version.kind,
                base_digest: Some(event.version.digest.clone()),
            },
        );
        self.applied_events.insert(event.id.clone());
        self.applied_sequences
            .insert(event.path.clone(), event.version.sequence);
        Ok(true)
    }
}

/// In-memory implementation of the immutable cloud data-plane contract.
///
/// Production transports can replace this implementation while retaining the
/// planner semantics and deterministic simulator tests.
#[derive(Debug, Default)]
pub struct MemorySyncCloud {
    blobs: BTreeMap<String, Vec<u8>>,
    canonical: BTreeMap<PathBuf, SyncVersion>,
    events: Vec<SyncEvent>,
    conflicts: Vec<SyncConflict>,
    sequence: u64,
}

impl MemorySyncCloud {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn events(&self) -> &[SyncEvent] {
        &self.events
    }

    pub fn conflicts(&self) -> &[SyncConflict] {
        &self.conflicts
    }

    pub fn materialize(&self, digest: &str) -> Result<&[u8]> {
        self.blobs
            .get(digest)
            .map(Vec::as_slice)
            .ok_or_else(|| FolderbaseError::InvalidRecord {
                path: PathBuf::from(digest),
                message: "cloud version references a missing immutable blob".to_owned(),
            })
    }

    pub fn canonical_version(&self, path: impl AsRef<Path>) -> Option<&SyncVersion> {
        self.canonical.get(path.as_ref())
    }

    pub fn store_blob(&mut self, bytes: &[u8]) -> String {
        let digest = digest(bytes);
        self.blobs
            .entry(digest.clone())
            .or_insert_with(|| bytes.to_vec());
        digest
    }

    fn capture(&mut self, device_id: &str, bytes: &[u8], kind: ContentKind) -> SyncVersion {
        let digest = self.store_blob(bytes);
        self.sequence += 1;
        SyncVersion {
            digest,
            bytes: bytes.len() as u64,
            kind,
            author_device: device_id.to_owned(),
            sequence: self.sequence,
        }
    }

    fn publish(&mut self, path: PathBuf, version: SyncVersion) {
        self.canonical.insert(path.clone(), version.clone());
        self.events.push(SyncEvent {
            id: format!("event_{}", Uuid::now_v7()),
            path,
            version,
        });
    }

    fn record_conflict(&mut self, conflict: SyncConflict) {
        let duplicate = self.conflicts.iter().any(|existing| {
            existing.path == conflict.path
                && existing.local.digest == conflict.local.digest
                && existing.remote.digest == conflict.remote.digest
        });
        if !duplicate {
            self.conflicts.push(conflict);
        }
    }
}

fn ensure_safe_relative(path: &Path) -> Result<()> {
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(FolderbaseError::UnsafePath(path.to_path_buf()));
    }
    Ok(())
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn sort_report(report: &mut SyncReport) {
    report.uploaded.sort();
    report.downloaded.sort();
    report.unchanged.sort();
    report.conflicts.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then_with(|| left.local.digest.cmp(&right.local.digest))
    });
}

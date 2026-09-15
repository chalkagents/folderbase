//! Public local export discovery and immutable source selection.
//!
//! A child of local_versions so export uses the writer's validators and the
//! existing non-mutating history observation/locking implementation.

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    io,
    path::{Component, Path},
};

use serde::{Deserialize, Serialize};

use super::{
    ContentDigest, FileHistoryError, FolderbaseError, LocalObjectRecord, LocalVersionRecord,
    LocalVersionStore, OBJECTS_DIRECTORY, ObjectId, VersionId, canonical_folderbase_root,
    file_history::{Observation, ReadLock, ensure_idle},
    safe_content_path,
};
use crate::{
    FolderbaseCaptureError, FolderbaseVersionStore,
    folderbase_seal::export_tombstone_binding,
    folderbase_state::FolderbaseState,
    folderbase_version::{
        DeletedKind, FolderbaseVersion, FolderbaseVersionError, MAX_ENCODED_VERSION_BYTES,
        PathBindingKind,
    },
    root_attestation::{RootAttestationError, attest_retained_folderbase_root_with_profile},
    root_reconstruction::RootReconstructionTombstoneFidelity,
    transfer_source::{ChunkTransferProfile, ChunkTransferSource, TransferSourceError},
    traversal_policy::is_git_metadata_component,
};

const RETAINED_VERSIONS: &str = ".folderbase/versions/folderbase";
const MAX_RESULT_BYTES: usize = 8 * 1024 * 1024;
pub(crate) const MAX_HISTORY_VERSIONS: usize = 16_384;
pub(crate) const MAX_HISTORY_BYTES: u64 = 64 * 1024 * 1024;
const MAX_RECORD_BYTES: u64 = 1024 * 1024;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum LocalExportError {
    #[error(transparent)]
    Core(#[from] FolderbaseError),
    #[error(transparent)]
    Root(#[from] RootAttestationError),
    #[error(transparent)]
    History(#[from] FileHistoryError),
    #[error(transparent)]
    Version(#[from] FolderbaseVersionError),
    #[error(transparent)]
    Capture(#[from] FolderbaseCaptureError),
    #[error(transparent)]
    Transfer(#[from] TransferSourceError),
    #[error(transparent)]
    Package(#[from] crate::root_reconstruction::RootReconstructionError),
    #[error("retained full-Version metadata does not match its filename or Folderbase")]
    VersionMembership,
    #[error("the export JSON result exceeds its {maximum} byte bound")]
    ResultTooLarge { maximum: usize },
    #[error("export cannot preserve complete stored file history for {path}: {reason}")]
    UnsupportedHistory { path: String, reason: String },
    #[error("export exceeds the {limit} bound of {maximum}; no partial package is published")]
    LimitExceeded { limit: &'static str, maximum: u64 },
}

impl LocalExportError {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Core(_) => "local_export_state_invalid",
            Self::Root(_) => "local_export_root_invalid",
            Self::History(_) => "local_export_history_unavailable",
            Self::Version(_) | Self::VersionMembership => "local_export_version_invalid",
            Self::Capture(_) => "local_export_capture_failed",
            Self::Transfer(_) => "local_export_source_changed",
            Self::Package(_) => "local_export_package_invalid",
            Self::UnsupportedHistory { .. } => "local_export_history_unsupported",
            Self::ResultTooLarge { .. } | Self::LimitExceeded { .. } => {
                "local_export_limit_exceeded"
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExportSnapshotSelection {
    CurrentWorkspace,
    RetainedVersion(String),
}

/// Portable history data; source Object projections and local authority are
/// deliberately absent. `versions` retains the Object's complete stored order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExportObjectHistory {
    pub object_id: ObjectId,
    pub versions: Vec<LocalVersionRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotOnlyReservedPath {
    pub path: String,
    pub object_id: String,
    pub object_version_id: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OmittedExportObject {
    pub object_id: String,
    pub source_path: String,
    pub reason: String,
}

/// A distinct historical Object proven at or before the selected snapshot.
/// This is identity evidence, not a recoverable historical full snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportRetiredObject {
    pub object_id: String,
    pub path: String,
    pub last_object_version_id: String,
    pub witness_version_id: String,
    pub witness_version_sha256: String,
}

pub(crate) struct ExportSource<'a> {
    pub full_version: FolderbaseVersion,
    pub histories: Vec<ExportObjectHistory>,
    pub snapshot_only: Vec<SnapshotOnlyReservedPath>,
    pub omitted_objects: Vec<OmittedExportObject>,
    pub retired_objects: Vec<ExportRetiredObject>,
    pub snapshot_records: BTreeMap<String, LocalVersionRecord>,
    pub tombstone_fidelity: Vec<RootReconstructionTombstoneFidelity>,
    local: LocalVersionStore,
    state: &'a FolderbaseState,
    observation: Observation<'a>,
}

impl ExportSource<'_> {
    pub(crate) fn open_history_content(
        &self,
        version: &LocalVersionRecord,
    ) -> Result<ChunkTransferSource, LocalExportError> {
        Ok(self
            .local
            .open_chunk_transfer(&version.id, ChunkTransferProfile::Managed)?)
    }

    pub(crate) fn open_snapshot_content(
        &self,
        version: &LocalVersionRecord,
    ) -> Result<ChunkTransferSource, LocalExportError> {
        Ok(self
            .local
            .open_captured_chunk_transfer(version.clone(), ChunkTransferProfile::Managed)?)
    }

    fn verify(&self) -> Result<(), LocalExportError> {
        self.observation.verify()?;
        ensure_idle(&mut Observation::new(self.state))?;
        // No collection of open blob handles grows with the history count.
        // Every emitted immutable source is nevertheless reverified before
        // final export publication, including history-only content.
        for record in self
            .histories
            .iter()
            .flat_map(|history| &history.versions)
            .chain(self.snapshot_records.values())
        {
            self.local.verify_capture_object_version_in(
                self.state,
                &record.object_id,
                &record.id,
                &record.content,
            )?;
        }
        self.state.verify_still_attached()?;
        Ok(())
    }
}

/// The destination must have passed no-clobber and filesystem preflight before
/// this function may seal a current-workspace snapshot.
pub(crate) fn with_export_source<T>(
    root: &Path,
    selection: &ExportSnapshotSelection,
    build_staging: impl FnOnce(&ExportSource<'_>) -> Result<T, LocalExportError>,
) -> Result<T, LocalExportError> {
    let store = match selection {
        ExportSnapshotSelection::CurrentWorkspace => FolderbaseVersionStore::open(root)?,
        ExportSnapshotSelection::RetainedVersion(_) => {
            FolderbaseVersionStore::open_for_retained_export(root)?
        }
    };
    let selected = match selection {
        ExportSnapshotSelection::CurrentWorkspace => store
            .seal_capture(store.plan_capture()?)?
            .version_id()
            .to_owned(),
        ExportSnapshotSelection::RetainedVersion(id) => id.clone(),
    };
    let full_version = store.read_version(&selected)?;
    let root = &store.root_attestation.root;
    let state = FolderbaseState::open_existing_read_only(root)?;
    let root_cap = state.clone_root_capability()?;
    let attestation = attest_retained_folderbase_root_with_profile(&root_cap, root)?.0;
    let lock = ReadLock::acquire(&state)?;
    let local = LocalVersionStore::for_retained_root(root);
    let mut observation = Observation::new(&state);
    ensure_idle(&mut observation)?;
    let selected_bytes = observation.required(
        &Path::new(RETAINED_VERSIONS).join(format!("{selected}.json")),
        MAX_ENCODED_VERSION_BYTES,
    )?;
    let observed_version = FolderbaseVersion::decode_bounded(selected_bytes.as_slice())?;
    if observed_version.canonical_digest()? != full_version.canonical_digest()? {
        return Err(FileHistoryError::ObservationChanged.into());
    }

    let mut source = ExportSource {
        full_version,
        histories: Vec::new(),
        snapshot_only: Vec::new(),
        omitted_objects: Vec::new(),
        retired_objects: Vec::new(),
        snapshot_records: BTreeMap::new(),
        tombstone_fidelity: Vec::new(),
        local,
        state: &state,
        observation,
    };
    collect_snapshot_records(&store, &mut source)?;
    collect_file_histories(&mut source, selection)?;
    let result = build_staging(&source)?;
    source.verify()?;
    if attest_retained_folderbase_root_with_profile(&root_cap, root)?.0 != attestation {
        return Err(FileHistoryError::ObservationChanged.into());
    }
    lock.verify(&state)?;
    Ok(result)
}

fn collect_snapshot_records(
    store: &FolderbaseVersionStore,
    source: &mut ExportSource<'_>,
) -> Result<(), LocalExportError> {
    if source
        .full_version
        .tombstones()
        .iter()
        .any(|tombstone| tombstone.deleted_kind() == DeletedKind::RegularFile)
    {
        use crate::root_reconstruction::local_export_package::{
            EXPORT_ANCESTRY_PROOF_PATHS, EXPORT_PORTABLE_HISTORY_PROOF_PATH,
        };
        for path in EXPORT_ANCESTRY_PROOF_PATHS {
            source.observation.read(Path::new(path), 8 * 1024 * 1024)?;
        }
        source.observation.read(
            Path::new(EXPORT_PORTABLE_HISTORY_PROOF_PATH),
            MAX_HISTORY_BYTES,
        )?;
    }
    let manifest = source.full_version.root_manifest();
    let record = source.local.verify_capture_version_record_in(
        source.state,
        &VersionId::parse(manifest.object_version_id().to_owned())?,
        &ContentDigest {
            algorithm: "sha256".to_owned(),
            digest: manifest.content_sha256().to_owned(),
            bytes: manifest.bytes(),
        },
    )?;
    source
        .snapshot_records
        .insert(record.id.to_string(), record);
    for binding in source.full_version.bindings() {
        if binding.kind() != PathBindingKind::RegularFile {
            continue;
        }
        let id = binding
            .object_version_id()
            .expect("validated regular binding");
        let record = source.local.verify_capture_object_version_in(
            source.state,
            &ObjectId::parse(binding.object_id().to_owned())?,
            &VersionId::parse(id.to_owned())?,
            &ContentDigest {
                algorithm: "sha256".to_owned(),
                digest: binding.content_sha256().expect("regular digest").to_owned(),
                bytes: binding.bytes().expect("regular length"),
            },
        )?;
        validate_explicit_export_fidelity(
            &record,
            binding.executable().expect("regular fidelity"),
            binding.path(),
        )?;
        source.snapshot_records.insert(id.to_owned(), record);
        if snapshot_only_git_path(binding.path()) {
            source
                .snapshot_only
                .push(snapshot_only_path(binding.path(), binding.object_id(), id));
        }
    }
    for tombstone in source.full_version.tombstones() {
        let Some(id) = tombstone.last_object_version_id() else {
            continue;
        };
        let record = source.local.verify_capture_record_integrity_in(
            source.state,
            &ObjectId::parse(tombstone.object_id().to_owned())?,
            &VersionId::parse(id.to_owned())?,
        )?;
        source.snapshot_records.insert(id.to_owned(), record);
        if tombstone.deleted_kind() == DeletedKind::RegularFile {
            let binding = export_tombstone_binding(
                store,
                &source.local,
                source.state,
                &source.full_version,
                tombstone,
            )?;
            validate_explicit_export_fidelity(
                &source.snapshot_records[id],
                binding.executable().expect("regular fidelity"),
                tombstone.path(),
            )?;
            source
                .tombstone_fidelity
                .push(RootReconstructionTombstoneFidelity::new(
                    tombstone.path(),
                    tombstone.object_id(),
                    id,
                    binding.executable().expect("regular fidelity"),
                ));
            if snapshot_only_git_path(tombstone.path()) {
                source.snapshot_only.push(snapshot_only_path(
                    tombstone.path(),
                    tombstone.object_id(),
                    id,
                ));
            }
        }
    }
    source
        .snapshot_only
        .sort_by(|left, right| left.path.as_bytes().cmp(right.path.as_bytes()));
    for record in source.snapshot_records.values() {
        source.observation.required(
            &source.local.version_record_relative_path(&record.id),
            MAX_RECORD_BYTES,
        )?;
    }
    Ok(())
}

pub(crate) fn snapshot_only_git_path(path: &str) -> bool {
    Path::new(path).components().any(
        |component| matches!(component, Component::Normal(name) if is_git_metadata_component(name)),
    )
}

pub(crate) fn snapshot_only_path(
    path: &str,
    object: &str,
    version: &str,
) -> SnapshotOnlyReservedPath {
    SnapshotOnlyReservedPath {
        path: path.to_owned(),
        object_id: object.to_owned(),
        object_version_id: version.to_owned(),
        reason: "git_metadata_has_no_stored_file_history".to_owned(),
    }
}

fn collect_file_histories(
    source: &mut ExportSource<'_>,
    selection: &ExportSnapshotSelection,
) -> Result<(), LocalExportError> {
    let mut selected = BTreeMap::new();
    for binding in source.full_version.bindings() {
        if binding.kind() == PathBindingKind::RegularFile
            && !snapshot_only_git_path(binding.path())
            && selected
                .insert(binding.object_id().to_owned(), binding.path().to_owned())
                .is_some()
        {
            return Err(LocalExportError::UnsupportedHistory {
                path: binding.path().to_owned(),
                reason: "one regular Object has multiple live paths and cannot have one unambiguous projection".to_owned(),
            });
        }
    }
    for tombstone in source.full_version.tombstones() {
        if tombstone.deleted_kind() == DeletedKind::RegularFile
            && !snapshot_only_git_path(tombstone.path())
            && tombstone.last_object_version_id().is_some()
        {
            selected
                .entry(tombstone.object_id().to_owned())
                .or_insert(tombstone.path().to_owned());
        }
    }
    let reserved_ids = source
        .snapshot_only
        .iter()
        .map(|entry| entry.object_id.clone())
        .collect::<BTreeSet<_>>();
    let mut seen_versions = BTreeSet::new();
    let mut prior_objects = None;
    for name in source.observation.names(Path::new(OBJECTS_DIRECTORY))? {
        let relative = Path::new(OBJECTS_DIRECTORY).join(name);
        if relative.extension().and_then(|value| value.to_str()) != Some("json") {
            continue;
        }
        let encoded = source.observation.required(&relative, MAX_RECORD_BYTES)?;
        let object: LocalObjectRecord = serde_json::from_slice(&encoded)
            .map_err(|error| FolderbaseError::json(source.local.root().join(&relative), error))?;
        object.id.validate(&relative)?;
        if relative.file_stem().and_then(|value| value.to_str()) != Some(object.id.as_str()) {
            return Err(LocalExportError::VersionMembership);
        }
        if reserved_ids.contains(object.id.as_str()) {
            return Err(LocalExportError::UnsupportedHistory {
                path: object.path,
                reason: "reserved Git metadata unexpectedly has a stored Object history".to_owned(),
            });
        }
        safe_content_path(Path::new(&object.path))?;
        let selected_path = if let Some(path) = selected.remove(object.id.as_str()) {
            path
        } else {
            if prior_objects.is_none() {
                prior_objects = Some(observe_prior_object_witnesses(source, selection)?);
            }
            if let Some(witness) = prior_objects
                .as_ref()
                .and_then(|objects| objects.get(object.id.as_str()))
            {
                source.retired_objects.push(witness.clone());
                witness.path.clone()
            } else {
                if matches!(selection, ExportSnapshotSelection::CurrentWorkspace) {
                    return Err(LocalExportError::UnsupportedHistory {
                        path: object.path,
                        reason: "stored Object history is outside the selected current snapshot and verified ancestry".to_owned(),
                    });
                }
                source.omitted_objects.push(OmittedExportObject {
                    object_id: object.id.to_string(),
                    source_path: object.path,
                    reason: "object_not_in_selected_snapshot".to_owned(),
                });
                continue;
            }
        };
        let outgoing = Path::new(super::HISTORY_TRANSFER_OUTGOING_DIRECTORY)
            .join(format!("{}.json", object.id));
        if let Some(bytes) = source.observation.read(&outgoing, MAX_RECORD_BYTES)? {
            super::validate_chunk_transfer_receipt_bytes(
                &bytes,
                &source.local.root().join(&outgoing),
                &object.id,
                source.full_version.folderbase_id(),
            )?;
        }
        let incoming = Path::new(super::HISTORY_TRANSFER_INCOMING_DIRECTORY)
            .join(format!("{}.json", object.id));
        if let Some(bytes) = source.observation.read(&incoming, MAX_RECORD_BYTES)? {
            let receipt: super::HistoryTransferReceipt = serde_json::from_slice(&bytes)
                .map_err(|error| FolderbaseError::json(&incoming, error))?;
            super::validate_history_transfer_receipt(&receipt, &incoming)?;
            if receipt.object_id != object.id
                || receipt.destination_folderbase_id != source.full_version.folderbase_id()
                || !receipt
                    .version_ids
                    .iter()
                    .all(|id| object.versions.contains(id))
            {
                return Err(LocalExportError::VersionMembership);
            }
        }
        source.local.validate_object_record_membership(
            &object.id,
            &object,
            &source.local.root().join(&relative),
        )?;
        let mut versions = Vec::new();
        for id in &object.versions {
            if !seen_versions.insert(id.clone()) {
                return Err(LocalExportError::VersionMembership);
            }
            if seen_versions.len() > MAX_HISTORY_VERSIONS {
                return Err(LocalExportError::LimitExceeded {
                    limit: "retained file Versions",
                    maximum: MAX_HISTORY_VERSIONS as u64,
                });
            }
            let relative = source.local.version_record_relative_path(id);
            let encoded = source.observation.required(&relative, MAX_RECORD_BYTES)?;
            let record: LocalVersionRecord = serde_json::from_slice(&encoded).map_err(|error| {
                FolderbaseError::json(source.local.root().join(&relative), error)
            })?;
            source.local.validate_version_record(
                id,
                &record,
                &source.local.root().join(&relative),
            )?;
            if record.object_id != object.id {
                return Err(LocalExportError::VersionMembership);
            }
            versions.push(record);
        }
        for snapshot in source
            .snapshot_records
            .values()
            .filter(|record| record.object_id == object.id)
        {
            if !versions.contains(snapshot) {
                return Err(LocalExportError::UnsupportedHistory { path: selected_path.clone(), reason: "selected snapshot Version is missing or differs from the stored ordered file history".to_owned() });
            }
        }
        if let Some(retired) = source
            .retired_objects
            .iter()
            .find(|entry| entry.object_id == object.id.as_str())
            && !versions
                .iter()
                .any(|record| record.id.as_str() == retired.last_object_version_id)
        {
            return Err(LocalExportError::VersionMembership);
        }
        source.histories.push(ExportObjectHistory {
            object_id: object.id,
            versions,
        });
    }
    if let Some((_, path)) = selected.into_iter().next() {
        return Err(LocalExportError::UnsupportedHistory {
            path,
            reason: "ordinary file has no complete stored Object history".to_owned(),
        });
    }
    source
        .histories
        .sort_by(|left, right| left.object_id.cmp(&right.object_id));
    source.retired_objects.sort_by(|a, b| {
        a.path
            .as_bytes()
            .cmp(b.path.as_bytes())
            .then(a.object_id.as_bytes().cmp(b.object_id.as_bytes()))
    });
    source
        .omitted_objects
        .sort_by(|left, right| left.object_id.cmp(&right.object_id));
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExportVersionEntry {
    pub version_id: String,
    pub canonical_sha256: String,
    pub created_at: String,
    pub visible_entries: usize,
    pub retained_tombstones: usize,
}

/// Verified metadata discovery, not a certification that retained blobs exist.
/// Entries are sorted by ID; their order does not choose a current snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExportVersionList {
    pub format: String,
    pub folderbase_id: String,
    pub versions: Vec<ExportVersionEntry>,
}

/// Discover retained full-Version IDs without reading or adopting Local Head.
///
/// This bounded, read-only operation works on a stopped copied archive. It
/// validates encoded Version metadata and membership; export must separately
/// verify the selected snapshot's complete content and retained history closure.
/// It creates no lock or private state, performs no recovery, and does not
/// choose a Version from filenames or timestamps. Source attachment and
/// observed metadata are checked again before success.
pub fn list_export_versions(root: impl AsRef<Path>) -> Result<ExportVersionList, LocalExportError> {
    list_export_versions_with_hook(root.as_ref(), || {})
}

fn list_export_versions_with_hook(
    root: &Path,
    before_revalidation: impl FnOnce(),
) -> Result<ExportVersionList, LocalExportError> {
    let root = canonical_folderbase_root(root)?;
    let state = FolderbaseState::open_existing_read_only(&root)?;
    let root_cap = state.clone_root_capability()?;
    let attestation = attest_retained_folderbase_root_with_profile(&root_cap, &root)?.0;
    let lock = ReadLock::acquire(&state)?;
    let mut observation = Observation::new(&state);
    ensure_idle(&mut observation)?;
    let mut result = ExportVersionList {
        format: "folderbase-export-version-list-v1".to_owned(),
        folderbase_id: attestation.folderbase_id.clone(),
        versions: Vec::new(),
    };
    for name in observation.names(Path::new(RETAINED_VERSIONS))? {
        let relative = Path::new(RETAINED_VERSIONS).join(&name);
        if relative.extension().and_then(|value| value.to_str()) != Some("json") {
            return Err(LocalExportError::VersionMembership);
        }
        let encoded = observation.required(&relative, MAX_ENCODED_VERSION_BYTES)?;
        let version = FolderbaseVersion::decode_bounded(encoded.as_slice())?;
        if relative.file_stem().and_then(|value| value.to_str()) != Some(version.version_id())
            || version.folderbase_id() != attestation.folderbase_id
        {
            return Err(LocalExportError::VersionMembership);
        }
        result.versions.push(ExportVersionEntry {
            version_id: version.version_id().to_owned(),
            canonical_sha256: version.canonical_digest()?,
            created_at: version.created_at().to_owned(),
            visible_entries: version.bindings().len(),
            retained_tombstones: version.tombstones().len(),
        });
    }
    ensure_result_bound(&result)?;
    before_revalidation();
    observation.verify()?;
    ensure_idle(&mut Observation::new(&state))?;
    state.verify_still_attached()?;
    if attest_retained_folderbase_root_with_profile(&root_cap, &root)?.0 != attestation {
        return Err(FileHistoryError::ObservationChanged.into());
    }
    lock.verify(&state)?;
    Ok(result)
}

pub(crate) fn ensure_result_bound(value: &impl Serialize) -> Result<(), LocalExportError> {
    struct Budget(usize);
    impl io::Write for Budget {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0 = self.0.saturating_add(bytes.len());
            if self.0 > MAX_RESULT_BYTES {
                return Err(io::Error::other("export result exceeds its byte limit"));
            }
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    // Reserve the CLI's final newline without allocating the result encoding.
    serde_json::to_writer_pretty(Budget(1), value).map_err(|_| LocalExportError::ResultTooLarge {
        maximum: MAX_RESULT_BYTES,
    })
}

/// Validate portable Version metadata independently of any source path or
/// mutable Object projection. The reconstruction supplies the new projection.
pub(crate) fn validate_portable_history(
    history: &ExportObjectHistory,
) -> Result<(), FolderbaseError> {
    let label = Path::new("history/index.json");
    history.object_id.validate(label)?;
    let local = LocalVersionStore::for_retained_root(Path::new("."));
    for record in &history.versions {
        local.validate_version_record(&record.id, record, label)?;
        if record.object_id != history.object_id {
            return Err(super::invalid_record(
                label,
                "history Version belongs to a different Object",
            ));
        }
    }
    Ok(())
}

fn observe_prior_object_witnesses(
    source: &mut ExportSource<'_>,
    selection: &ExportSnapshotSelection,
) -> Result<BTreeMap<String, ExportRetiredObject>, LocalExportError> {
    use crate::root_reconstruction::local_export_package::{
        EXPORT_ANCESTRY_PROOF_PATHS, EXPORT_PORTABLE_HISTORY_PROOF_PATH, PortableExportAncestry,
        read_portable_export_ancestry_for_source, verified_export_ancestry,
    };
    for path in EXPORT_ANCESTRY_PROOF_PATHS {
        source.observation.read(Path::new(path), 8 * 1024 * 1024)?;
    }
    let anchor = match selection {
        ExportSnapshotSelection::CurrentWorkspace => {
            verified_export_ancestry(source.state)?.map(|proof| PortableExportAncestry {
                version_id: proof.version_id,
                version_sha256: proof.version_sha256,
                retired_objects: proof.retired_objects,
                tombstone_associations: proof.tombstone_associations,
            })
        }
        ExportSnapshotSelection::RetainedVersion(_) => {
            source.observation.read(
                Path::new(EXPORT_PORTABLE_HISTORY_PROOF_PATH),
                MAX_HISTORY_BYTES,
            )?;
            read_portable_export_ancestry_for_source(source.state)?
        }
    };
    let at_anchor = anchor.as_ref().is_some_and(|anchor| {
        anchor.version_id == source.full_version.version_id()
            && source.full_version.canonical_digest().ok().as_deref()
                == Some(anchor.version_sha256.as_str())
    });
    let parents = if at_anchor {
        Vec::new()
    } else {
        source.full_version.parents().to_vec()
    };
    let mut queue = parents.iter().cloned().collect::<VecDeque<_>>();
    let mut seen = BTreeSet::new();
    let mut adjacency = BTreeMap::from([(source.full_version.version_id().to_owned(), parents)]);
    let mut witnesses = BTreeMap::new();
    if at_anchor {
        for retired in &anchor.as_ref().expect("matched anchor").retired_objects {
            witnesses.insert(retired.object_id.clone(), retired.clone());
        }
    }
    while let Some(id) = queue.pop_front() {
        if !seen.insert(id.clone()) {
            continue;
        }
        if seen.len() > MAX_HISTORY_VERSIONS {
            return Err(LocalExportError::LimitExceeded {
                limit: "ancestor Versions",
                maximum: MAX_HISTORY_VERSIONS as u64,
            });
        }
        let bytes = source.observation.required(
            &Path::new(RETAINED_VERSIONS).join(format!("{id}.json")),
            MAX_ENCODED_VERSION_BYTES,
        )?;
        let version = FolderbaseVersion::decode_bounded(bytes.as_slice())?;
        if version.version_id() != id
            || version.folderbase_id() != source.full_version.folderbase_id()
        {
            return Err(LocalExportError::VersionMembership);
        }
        let digest = version.canonical_digest()?;
        for binding in version.bindings() {
            if binding.kind() == PathBindingKind::RegularFile
                && !snapshot_only_git_path(binding.path())
            {
                witnesses
                    .entry(binding.object_id().to_owned())
                    .or_insert_with(|| ExportRetiredObject {
                        object_id: binding.object_id().to_owned(),
                        path: binding.path().to_owned(),
                        last_object_version_id: binding
                            .object_version_id()
                            .expect("validated regular Version")
                            .to_owned(),
                        witness_version_id: id.clone(),
                        witness_version_sha256: digest.clone(),
                    });
            }
        }
        for tombstone in version.tombstones() {
            if tombstone.deleted_kind() == DeletedKind::RegularFile
                && !snapshot_only_git_path(tombstone.path())
                && let Some(last) = tombstone.last_object_version_id()
            {
                witnesses
                    .entry(tombstone.object_id().to_owned())
                    .or_insert_with(|| ExportRetiredObject {
                        object_id: tombstone.object_id().to_owned(),
                        path: tombstone.path().to_owned(),
                        last_object_version_id: last.to_owned(),
                        witness_version_id: id.clone(),
                        witness_version_sha256: digest.clone(),
                    });
            }
        }
        if let Some(anchor) = &anchor
            && anchor.version_id == id
        {
            if anchor.version_sha256 != digest {
                return Err(LocalExportError::VersionMembership);
            }
            for retired in &anchor.retired_objects {
                witnesses
                    .entry(retired.object_id.clone())
                    .or_insert_with(|| retired.clone());
            }
            adjacency.insert(id, Vec::new());
        } else {
            adjacency.insert(id, version.parents().to_vec());
            queue.extend(version.parents().iter().cloned());
        }
    }
    crate::folderbase_seal::ensure_restore_ancestry_acyclic(&adjacency)?;
    Ok(witnesses)
}

pub(crate) fn validate_export_path(path: &str) -> Result<(), FolderbaseError> {
    safe_content_path(Path::new(path)).map(|_| ())
}

pub(crate) fn validate_explicit_export_fidelity(
    record: &LocalVersionRecord,
    executable: bool,
    path: &str,
) -> Result<(), FolderbaseError> {
    match record.extensions.get("executable") {
        Some(serde_json::Value::Bool(value)) if *value == executable => Ok(()),
        None => Ok(()), // Legacy captures did not record per-file executable metadata.
        Some(_) => Err(super::invalid_record(
            path,
            "explicit per-file executable metadata differs from the selected snapshot fidelity",
        )),
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, fs, path::PathBuf};

    use tempfile::tempdir;

    use super::*;
    use crate::{
        ChunkTransferProfile, ContentDigest, FolderbaseVersionStore, InitializationOptions,
        LocalVersionStore, TransferSourceError, VersionId, initialize, plan_initialization,
    };

    fn initialize_root(root: &Path) {
        fs::create_dir_all(root).unwrap();
        initialize(&plan_initialization(root, InitializationOptions::default()).unwrap()).unwrap();
    }

    fn capture(root: &Path) -> String {
        let store = FolderbaseVersionStore::open(root).unwrap();
        store
            .seal_capture(store.plan_capture().unwrap())
            .unwrap()
            .version_id()
            .to_owned()
    }

    fn bytes(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
        walkdir::WalkDir::new(root)
            .into_iter()
            .map(Result::unwrap)
            .filter(|entry| entry.file_type().is_file())
            .map(|entry| {
                (
                    entry.path().strip_prefix(root).unwrap().to_owned(),
                    fs::read(entry.path()).unwrap(),
                )
            })
            .collect()
    }

    #[test]
    fn repeated_source_reads_never_replace_the_original_observation() {
        let fixture = tempdir().unwrap();
        initialize_root(fixture.path());
        let state = FolderbaseState::open_existing_read_only(fixture.path()).unwrap();
        let relative = Path::new(".folderbase/manifest.json");
        let mut observation = Observation::new(&state);
        let original = observation.required(relative, MAX_RECORD_BYTES).unwrap();
        assert_eq!(
            observation.required(relative, MAX_RECORD_BYTES).unwrap(),
            original
        );
        fs::write(fixture.path().join(relative), b"different observation").unwrap();
        assert!(matches!(
            observation.read(relative, MAX_RECORD_BYTES),
            Err(FileHistoryError::ObservationChanged)
        ));
    }

    #[test]
    fn discovers_exact_metadata_without_adopting_copied_local_head_or_writing() {
        let fixture = tempdir().unwrap();
        let root = fixture.path().join("original");
        let copied = fixture.path().join("copied");
        initialize_root(&root);
        fs::write(root.join("task.json"), b"first bytes").unwrap();
        let first = capture(&root);
        fs::write(root.join("task.json"), b"second bytes").unwrap();
        let second = capture(&root);
        let original = bytes(&root);
        let discovered = list_export_versions(&root).unwrap();
        assert_eq!(discovered.versions.len(), 2);
        assert_eq!(
            discovered
                .versions
                .iter()
                .map(|entry| &entry.version_id)
                .collect::<Vec<_>>(),
            vec![&first, &second],
        );
        for (relative, content) in &original {
            fs::create_dir_all(copied.join(relative).parent().unwrap()).unwrap();
            fs::write(copied.join(relative), content).unwrap();
        }
        assert!(FolderbaseVersionStore::open(&copied).is_err());
        assert_eq!(list_export_versions(&copied).unwrap(), discovered);
        assert_eq!(bytes(&root), original);
        assert_eq!(bytes(&copied), original);
    }

    #[test]
    fn metadata_discovery_does_not_certify_content_recoverability() {
        let fixture = tempdir().unwrap();
        initialize_root(fixture.path());
        fs::write(fixture.path().join("task.json"), b"retained content").unwrap();
        let version = capture(fixture.path());
        let blobs = fixture.path().join(".folderbase/versions/blobs/sha256");
        let first_blob = walkdir::WalkDir::new(blobs)
            .into_iter()
            .map(Result::unwrap)
            .find(|entry| entry.file_type().is_file())
            .unwrap();
        fs::remove_file(first_blob.path()).unwrap();
        assert_eq!(
            list_export_versions(fixture.path()).unwrap().versions[0].version_id,
            version
        );
        assert!(
            FolderbaseVersionStore::open(fixture.path())
                .unwrap()
                .read_version(&version)
                .is_err()
        );
    }

    #[test]
    fn pending_work_and_changed_version_inventory_are_refused_without_recovery() {
        let fixture = tempdir().unwrap();
        initialize_root(fixture.path());
        fs::write(fixture.path().join("task.json"), b"retained").unwrap();
        let version = capture(fixture.path());
        let failure = list_export_versions_with_hook(fixture.path(), || {
            fs::write(
                fixture
                    .path()
                    .join(RETAINED_VERSIONS)
                    .join("unexpected.json"),
                b"{}",
            )
            .unwrap();
        });
        assert!(matches!(
            failure,
            Err(LocalExportError::History(
                FileHistoryError::ObservationChanged
            ))
        ));
        fs::remove_file(
            fixture
                .path()
                .join(RETAINED_VERSIONS)
                .join("unexpected.json"),
        )
        .unwrap();
        let active = fixture
            .path()
            .join(".folderbase/transactions/folderbase-version-captures/active.json");
        fs::write(active, b"{}").unwrap();
        let before = bytes(fixture.path());
        assert!(matches!(
            list_export_versions(fixture.path()),
            Err(LocalExportError::History(
                FileHistoryError::RecoveryRequired { .. }
            ))
        ));
        assert_eq!(bytes(fixture.path()), before);
        assert!(before.contains_key(&Path::new(RETAINED_VERSIONS).join(format!("{version}.json"))));
    }

    #[test]
    fn immutable_capture_source_streams_manifest_without_fabricating_a_projection() {
        let fixture = tempdir().unwrap();
        initialize_root(fixture.path());
        let version_id = capture(fixture.path());
        let full = FolderbaseVersionStore::open(fixture.path())
            .unwrap()
            .read_version(&version_id)
            .unwrap();
        let local = LocalVersionStore::for_retained_root(fixture.path());
        let state = FolderbaseState::open_existing_read_only(fixture.path()).unwrap();
        let record = local
            .verify_capture_version_record_in(
                &state,
                &VersionId::parse(full.root_manifest().object_version_id().to_owned()).unwrap(),
                &ContentDigest {
                    algorithm: "sha256".to_owned(),
                    digest: full.root_manifest().content_sha256().to_owned(),
                    bytes: full.root_manifest().bytes(),
                },
            )
            .unwrap();
        assert!(
            local
                .open_chunk_transfer(&record.id, ChunkTransferProfile::Managed)
                .is_err()
        );
        let before = bytes(fixture.path());
        let mut source = local
            .open_captured_chunk_transfer(record.clone(), ChunkTransferProfile::Managed)
            .unwrap();
        let mut output = Vec::new();
        for index in 0..source.manifest().chunks.len() as u32 {
            source.copy_chunk(index, &mut output).unwrap();
        }
        assert_eq!(
            output,
            fs::read(fixture.path().join(".folderbase/manifest.json")).unwrap()
        );
        assert_eq!(bytes(fixture.path()), before);
        let mut changed = record.clone();
        changed.captured_at = "changed after source open".to_owned();
        fs::write(
            fixture
                .path()
                .join(local.version_record_relative_path(&record.id)),
            serde_json::to_vec(&changed).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            source.copy_chunk(0, Vec::new()),
            Err(TransferSourceError::SourceChanged)
        ));
        assert!(matches!(
            local.open_captured_chunk_transfer(record, ChunkTransferProfile::Managed),
            Err(TransferSourceError::SourceChanged)
        ));
    }

    #[test]
    fn source_preserves_later_ordered_versions_and_marks_only_exact_git_components() {
        let fixture = tempdir().unwrap();
        initialize_root(fixture.path());
        fs::create_dir_all(fixture.path().join("repo/.GIT")).unwrap();
        fs::write(
            fixture.path().join("repo/.GIT/HEAD"),
            b"ref: refs/heads/main\n",
        )
        .unwrap();
        fs::write(fixture.path().join(".gitignore"), b"target/\n").unwrap();
        fs::write(fixture.path().join("task.json"), b"one").unwrap();
        let selected = capture(fixture.path());
        let local = LocalVersionStore::open(fixture.path()).unwrap();
        let first = local.capture_file("task.json").unwrap();
        fs::write(fixture.path().join("task.json"), b"two").unwrap();
        let second = local.capture_file("task.json").unwrap();
        fs::write(fixture.path().join("task.json"), b"one").unwrap();
        let third = local.capture_file("task.json").unwrap();
        assert_ne!(first.version.id, third.version.id);
        assert_eq!(first.version.content, third.version.content);
        let before = bytes(fixture.path());
        with_export_source(
            fixture.path(),
            &ExportSnapshotSelection::RetainedVersion(selected.clone()),
            |source| {
                assert_eq!(source.full_version.version_id(), selected);
                let history = source
                    .histories
                    .iter()
                    .find(|history| history.object_id == first.object.id)
                    .unwrap();
                assert_eq!(
                    history.versions,
                    vec![
                        first.version.clone(),
                        second.version.clone(),
                        third.version.clone()
                    ]
                );
                assert_eq!(source.histories.len(), 2, ".gitignore has ordinary history");
                assert_eq!(source.snapshot_only.len(), 1);
                assert_eq!(source.snapshot_only[0].path, "repo/.GIT/HEAD");
                let mut emitted = Vec::new();
                let mut content = source.open_history_content(&history.versions[1])?;
                for index in 0..content.manifest().chunks.len() as u32 {
                    content.copy_chunk(index, &mut emitted)?;
                }
                assert_eq!(emitted, b"two");
                let reserved = source
                    .snapshot_records
                    .get(&source.snapshot_only[0].object_version_id)
                    .unwrap();
                let mut content = source.open_snapshot_content(reserved)?;
                let mut emitted = Vec::new();
                for index in 0..content.manifest().chunks.len() as u32 {
                    content.copy_chunk(index, &mut emitted)?;
                }
                assert_eq!(emitted, b"ref: refs/heads/main\n");
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(bytes(fixture.path()), before);
    }

    #[test]
    fn source_refuses_missing_ordinary_history_and_observed_record_changes() {
        let fixture = tempdir().unwrap();
        initialize_root(fixture.path());
        fs::write(fixture.path().join("task.json"), b"one").unwrap();
        let selected = capture(fixture.path());
        let local = LocalVersionStore::open(fixture.path()).unwrap();
        let captured = local.capture_file("task.json").unwrap();
        let object_path = fixture
            .path()
            .join(local.object_record_relative_path(&captured.object.id));
        let original = fs::read(&object_path).unwrap();
        let failure = with_export_source(
            fixture.path(),
            &ExportSnapshotSelection::RetainedVersion(selected.clone()),
            |_| {
                fs::write(&object_path, b"{}").unwrap();
                Ok(())
            },
        );
        assert!(matches!(
            failure,
            Err(LocalExportError::History(
                FileHistoryError::ObservationChanged
            ))
        ));
        fs::write(&object_path, original).unwrap();
        fs::remove_file(&object_path).unwrap();
        let before = bytes(fixture.path());
        let failure = with_export_source(
            fixture.path(),
            &ExportSnapshotSelection::RetainedVersion(selected),
            |_| Ok(()),
        );
        assert!(
            matches!(failure, Err(LocalExportError::UnsupportedHistory { path, .. }) if path == "task.json")
        );
        assert_eq!(bytes(fixture.path()), before);
    }
}

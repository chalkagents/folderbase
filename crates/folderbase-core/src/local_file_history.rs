//! Bounded, non-mutating observation of one ordinary file's retained Versions.
//!
//! This is a child of local_versions so validation stays shared with its writer.

use std::{collections::BTreeSet, ffi::OsString, fs::File, io};

use super::*;
use crate::{
    folderbase_state::WorkspaceTarget,
    physical_identity::PhysicalIdentity,
    root_attestation::{RootAttestationError, attest_retained_folderbase_root_with_profile},
};

const MAX_ENTRIES: usize = 16_384;
const MAX_RECORD_BYTES: u64 = 1024 * 1024;
const MAX_JOURNAL_BYTES: u64 = 16 * 1024 * 1024;
const MAX_READ_BYTES: u64 = 64 * 1024 * 1024;
const MAX_RESULT_BYTES: usize = 8 * 1024 * 1024;

/// Complete retained metadata, in the Object's stored Version order.
/// `current_version` is the recorded head, not a claim about the file's live bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileVersionHistory {
    pub format: String,
    pub path: String,
    pub object_id: Option<ObjectId>,
    pub current_version: Option<VersionId>,
    pub versions: Vec<LocalVersionRecord>,
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum FileHistoryError {
    #[error(transparent)]
    Core(#[from] FolderbaseError),
    #[error(transparent)]
    Root(#[from] RootAttestationError),
    #[error("file history requires an existing ordinary regular file: {0}")]
    FileNotFound(PathBuf),
    #[error("Folderbase is busy; retry file history after the current writer completes")]
    Busy,
    #[error("read-only file history does not yet support roots with migration metadata")]
    MigrationStateUnsupported,
    #[error("file history requires recovery before reading: {work}")]
    RecoveryRequired { work: String },
    #[error("Folderbase changed while reading file history; retry the observation")]
    ObservationChanged,
    #[error("file history exceeded the {limit} limit of {maximum}; no partial history returned")]
    LimitExceeded { limit: &'static str, maximum: u64 },
}

impl FileHistoryError {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Core(_) => "file_history_state_invalid",
            Self::Root(_) => "file_history_root_invalid",
            Self::FileNotFound(_) => "file_history_file_not_found",
            Self::Busy => "file_history_busy",
            Self::MigrationStateUnsupported => "file_history_migration_state_unsupported",
            Self::RecoveryRequired { .. } => "file_history_recovery_required",
            Self::ObservationChanged => "file_history_changed",
            Self::LimitExceeded { .. } => "file_history_limit_exceeded",
        }
    }
}

type HistoryResult<T> = std::result::Result<T, FileHistoryError>;

/// Read every retained Version of one existing regular file without writing,
/// capturing, repairing a journal, recovering a transaction, or creating a lock.
///
/// Requires an initialized, attested root with no migration metadata. Completed
/// migrations are also explicitly unsupported; no recovery validator is called.
/// An untracked file has null IDs and an empty history. Does not read live
/// content or verify retained content blobs.
/// Uses a nonblocking shared lock when the existing writer lock is present,
/// and rechecks authority observations even with that lock. This is a bounded
/// observation, not isolation from uncooperative same-user filesystem writers.
pub fn read_file_history(
    root: impl AsRef<Path>,
    relative_path: impl AsRef<Path>,
) -> HistoryResult<FileVersionHistory> {
    read_file_history_with_hook(root.as_ref(), relative_path.as_ref(), || {})
}

fn read_file_history_with_hook(
    root: &Path,
    relative_path: &Path,
    before_revalidation: impl FnOnce(),
) -> HistoryResult<FileVersionHistory> {
    let root = canonical_folderbase_root(root)?;
    let state = FolderbaseState::open_existing_read_only(&root)?;
    let root_cap = state.clone_root_capability()?;
    let attestation = attest_retained_folderbase_root_with_profile(&root_cap, &root)?.0;
    let lock = ReadLock::acquire(&state)?;
    let mut observation = Observation::new(&state);
    ensure_idle(&mut observation)?;
    let relative = safe_content_path(relative_path)?;
    let (_, canonical) =
        resolve_existing_workspace_file(&root, &relative).map_err(|error| match error {
            FolderbaseError::Io { source, .. } if source.kind() == io::ErrorKind::NotFound => {
                FileHistoryError::FileNotFound(relative.clone())
            }
            error => error.into(),
        })?;
    let file = open_selected_file(&state, &canonical)?;
    let file_identity = PhysicalIdentity::from_file(&file)
        .map_err(|source| FolderbaseError::io(root.join(&canonical), source))?;
    let store = LocalVersionStore::for_retained_root(&root);
    let mut objects = Vec::new();
    for name in observation.names(Path::new(OBJECTS_DIRECTORY))? {
        let path = Path::new(OBJECTS_DIRECTORY).join(&name);
        if path.extension().and_then(|value| value.to_str()) != Some("json") {
            continue;
        }
        let bytes = observation.required(&path, MAX_RECORD_BYTES)?;
        let record: LocalObjectRecord = serde_json::from_slice(&bytes)
            .map_err(|source| FolderbaseError::json(root.join(&path), source))?;
        record.id.validate(&root.join(&path))?;
        if path.file_stem().and_then(|name| name.to_str()) != Some(record.id.as_str()) {
            return Err(
                invalid_record(root.join(path), "object ID does not match its filename").into(),
            );
        }
        safe_content_path(Path::new(&record.path))?;
        objects.push((path, record));
    }
    let candidates = find_claimants(&store, &canonical, &objects)?;
    let ownership = if candidates.len() > 1 {
        let current = path_ownership::current_version(&root, &state, |path, maximum| {
            observation.read(path, maximum)
        })?;
        Some(
            path_ownership::OwnershipHistory::load(
                current,
                &candidates
                    .iter()
                    .map(|(_, object)| (canonical.clone(), object.id.clone()))
                    .collect::<Vec<_>>(),
                true,
                None,
                |path, maximum| observation.read(path, maximum),
            )?
            .resolve_created(
                &root,
                &state,
                &canonical,
                &candidates,
                |path, maximum| observation.read(path, maximum),
            )?,
        )
    } else {
        None
    };
    let selected = select_claimant(&canonical, &candidates, ownership.as_ref())?;
    if let Some(version) = &ownership {
        path_ownership::verify_references(
            &root,
            &canonical,
            &candidates,
            version,
            |path, maximum| observation.read(path, maximum),
        )?;
    }
    let mut result = FileVersionHistory {
        format: "folderbase-file-history-v1".to_owned(),
        path: relative_path_to_string(&canonical)?,
        object_id: None,
        current_version: None,
        versions: Vec::new(),
    };
    if let Some((path, object)) = selected {
        let outgoing =
            Path::new(HISTORY_TRANSFER_OUTGOING_DIRECTORY).join(format!("{}.json", object.id));
        if let Some(bytes) = observation.read(&outgoing, MAX_RECORD_BYTES)? {
            validate_chunk_transfer_receipt_bytes(
                &bytes,
                &root.join(outgoing),
                &object.id,
                &attestation.folderbase_id,
            )?;
        }
        let incoming =
            Path::new(HISTORY_TRANSFER_INCOMING_DIRECTORY).join(format!("{}.json", object.id));
        if let Some(bytes) = observation.read(&incoming, MAX_RECORD_BYTES)? {
            let receipt: HistoryTransferReceipt = serde_json::from_slice(&bytes)
                .map_err(|source| FolderbaseError::json(&incoming, source))?;
            validate_history_transfer_receipt(&receipt, &incoming)?;
            if receipt.object_id != object.id
                || receipt.destination_folderbase_id != attestation.folderbase_id
                || !receipt
                    .version_ids
                    .iter()
                    .all(|id| object.versions.contains(id))
            {
                return Err(invalid_record(
                    &incoming,
                    "incoming history receipt does not match this Object and root",
                )
                .into());
            }
        }
        store.validate_object_record_membership(&object.id, object, &root.join(path))?;
        if object.versions.len() > MAX_ENTRIES {
            return Err(limit("versions", MAX_ENTRIES as u64));
        }
        let mut seen = BTreeSet::new();
        for id in &object.versions {
            if !seen.insert(id) {
                return Err(invalid_record(
                    root.join(path),
                    "duplicate Version ID in Object history",
                )
                .into());
            }
            id.validate(&root.join(path))?;
            let version_path = store.version_record_relative_path(id);
            let bytes = observation.required(&version_path, MAX_RECORD_BYTES)?;
            let version: LocalVersionRecord = serde_json::from_slice(&bytes)
                .map_err(|source| FolderbaseError::json(root.join(&version_path), source))?;
            store.validate_version_record(id, &version, &root.join(&version_path))?;
            if version.object_id != object.id {
                return Err(invalid_record(
                    root.join(version_path),
                    "Version belongs to another Object",
                )
                .into());
            }
            result.versions.push(version);
        }
        result.object_id = Some(object.id.clone());
        result.current_version = Some(object.current_version.clone());
    }
    // Stop serialization at the wire cap, including the CLI's final newline.
    // A bounded input can still expand substantially under pretty indentation.
    let mut encoded = EncodedResultBudget {
        bytes: 1,
        exceeded: false,
    };
    if let Err(source) = serde_json::to_writer_pretty(&mut encoded, &result) {
        if encoded.exceeded {
            return Err(limit("encoded_result_bytes", MAX_RESULT_BYTES as u64));
        }
        return Err(FolderbaseError::json(&root, source).into());
    }
    before_revalidation();
    observation.verify()?;
    if let Some(ownership) = &ownership {
        ownership.verify_created(&root, &state)?;
    }
    let mut final_pending = Observation::new(&state);
    ensure_idle(&mut final_pending)?;
    if select_claimant(
        &canonical,
        &find_claimants(&store, &canonical, &objects)?,
        ownership.as_ref(),
    )?
    .map(|(_, object)| &object.id)
        != result.object_id.as_ref()
    {
        return Err(FileHistoryError::ObservationChanged);
    }
    let (_, final_path) = resolve_existing_workspace_file(&root, &relative)?;
    let final_file = open_selected_file(&state, &final_path)?;
    if final_path != canonical
        || PhysicalIdentity::from_file(&final_file)
            .map_err(|source| FolderbaseError::io(root.join(&final_path), source))?
            != file_identity
    {
        return Err(FileHistoryError::ObservationChanged);
    }
    state.verify_still_attached()?;
    if attest_retained_folderbase_root_with_profile(&root_cap, &root)?.0 != attestation {
        return Err(FileHistoryError::ObservationChanged);
    }
    lock.verify(&state)?;
    Ok(result)
}

/// Counts the exact encoding without retaining it or letting indentation expand
/// an otherwise bounded metadata input into an unbounded temporary allocation.
struct EncodedResultBudget {
    bytes: usize,
    exceeded: bool,
}

impl io::Write for EncodedResultBudget {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > MAX_RESULT_BYTES.saturating_sub(self.bytes) {
            self.exceeded = true;
            return Err(io::Error::other(
                "file history encoded result limit exceeded",
            ));
        }
        self.bytes += bytes.len();
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn open_selected_file(state: &FolderbaseState, path: &Path) -> HistoryResult<File> {
    match state.open_workspace_target_nofollow(path)? {
        WorkspaceTarget::RegularFile(file) => Ok(file.into_std()),
        WorkspaceTarget::Absent => Err(FileHistoryError::FileNotFound(path.to_path_buf())),
        WorkspaceTarget::Directory(_) => {
            Err(FolderbaseError::UnsafePath(path.to_path_buf()).into())
        }
    }
}

fn find_claimants<'a>(
    store: &LocalVersionStore,
    canonical: &Path,
    objects: &'a [(PathBuf, LocalObjectRecord)],
) -> Result<Vec<(&'a Path, &'a LocalObjectRecord)>> {
    let mut paths = WorkspacePathLookup::new(&store.root)?;
    let mut found = Vec::new();
    for (path, object) in objects {
        if object_path_matches(
            &mut paths,
            Path::new(&object.path),
            canonical,
            &store.root.join(path),
        )? {
            found.push((path.as_path(), object));
        }
    }
    paths.finish()?;
    Ok(found)
}

fn select_claimant<'a>(
    canonical: &Path,
    candidates: &[(&'a Path, &'a LocalObjectRecord)],
    ownership: Option<&path_ownership::OwnershipHistory>,
) -> Result<Option<(&'a Path, &'a LocalObjectRecord)>> {
    match candidates {
        [] => Ok(None),
        [only] => Ok(Some(*only)),
        _ => path_ownership::select(
            canonical,
            candidates,
            ownership.expect("multiple claims require ownership evidence"),
        )
        .map(Some),
    }
}

struct ReadLock(Option<(File, PhysicalIdentity)>);

impl ReadLock {
    fn acquire(state: &FolderbaseState) -> HistoryResult<Self> {
        let Some(file) = Self::open(state)? else {
            return Ok(Self(None));
        };
        file.try_lock_shared().map_err(|error| match error {
            std::fs::TryLockError::WouldBlock => FileHistoryError::Busy,
            std::fs::TryLockError::Error(source) => {
                FolderbaseError::io(TRANSACTION_LOCK_PATH, source).into()
            }
        })?;
        let identity = PhysicalIdentity::from_file(&file)
            .map_err(|source| FolderbaseError::io(TRANSACTION_LOCK_PATH, source))?;
        let lock = Self(Some((file, identity)));
        lock.verify(state)?;
        Ok(lock)
    }

    fn open(state: &FolderbaseState) -> Result<Option<File>> {
        match state.open_private_target_nofollow(Path::new(TRANSACTION_LOCK_PATH))? {
            WorkspaceTarget::Absent => Ok(None),
            WorkspaceTarget::RegularFile(file) => Ok(Some(file.into_std())),
            WorkspaceTarget::Directory(_) => Err(invalid_record(
                TRANSACTION_LOCK_PATH,
                "transaction lock is not a regular file",
            )),
        }
    }

    fn verify(&self, state: &FolderbaseState) -> HistoryResult<()> {
        let actual = Self::open(state)?
            .map(|file| PhysicalIdentity::from_file(&file))
            .transpose()
            .map_err(|source| FolderbaseError::io(TRANSACTION_LOCK_PATH, source))?;
        if actual != self.0.as_ref().map(|(_, identity)| *identity) {
            return Err(FileHistoryError::ObservationChanged);
        }
        Ok(())
    }
}

/// Bounded byte/name witnesses; no private file is opened with write access.
struct Observation<'a> {
    state: &'a FolderbaseState,
    files: BTreeMap<PathBuf, (u64, Option<Vec<u8>>)>,
    directories: BTreeMap<PathBuf, Vec<OsString>>,
    bytes: u64,
}

impl<'a> Observation<'a> {
    fn new(state: &'a FolderbaseState) -> Self {
        Self {
            state,
            files: BTreeMap::new(),
            directories: BTreeMap::new(),
            bytes: 0,
        }
    }

    fn read(&mut self, path: &Path, maximum: u64) -> HistoryResult<Option<Vec<u8>>> {
        let bytes = bounded_read(self.state, path, maximum)?;
        if let Some((_, prior)) = self.files.get(path) {
            if prior != &bytes {
                return Err(FileHistoryError::ObservationChanged);
            }
            return Ok(bytes);
        }
        self.bytes += bytes.as_ref().map_or(0, |bytes| bytes.len() as u64);
        if self.bytes > MAX_READ_BYTES {
            return Err(limit("metadata_bytes", MAX_READ_BYTES));
        }
        if self.files.len() >= MAX_ENTRIES * 2 {
            return Err(limit("metadata_records", (MAX_ENTRIES * 2) as u64));
        }
        self.files
            .insert(path.to_path_buf(), (maximum, bytes.clone()));
        Ok(bytes)
    }

    fn required(&mut self, path: &Path, maximum: u64) -> HistoryResult<Vec<u8>> {
        self.read(path, maximum)?
            .ok_or_else(|| invalid_record(path, "required history record is missing").into())
    }

    fn names(&mut self, path: &Path) -> HistoryResult<Vec<OsString>> {
        let names = directory_names(self.state, path)?;
        if self
            .directories
            .get(path)
            .is_some_and(|prior| prior != &names)
        {
            return Err(FileHistoryError::ObservationChanged);
        }
        self.directories.insert(path.to_path_buf(), names.clone());
        Ok(names)
    }

    fn verify(&self) -> HistoryResult<()> {
        for (path, (maximum, expected)) in &self.files {
            if bounded_read(self.state, path, *maximum)? != *expected {
                return Err(FileHistoryError::ObservationChanged);
            }
        }
        for (path, expected) in &self.directories {
            let names = directory_names(self.state, path)?;
            if names != *expected {
                return Err(FileHistoryError::ObservationChanged);
            }
        }
        Ok(())
    }
}

fn ensure_idle(observation: &mut Observation<'_>) -> HistoryResult<()> {
    for path in [
        super::file_create::ACTIVE_CREATE_PATH,
        ".folderbase/transactions/protocol-upgrades/active.json",
        ".folderbase/transactions/folderbase-version-captures/active.json",
        ".folderbase/transactions/folderbase-version-restores/active.json",
        ".folderbase/transactions/folderbase-version-restores/cleanup.json",
        ".folderbase/reorganizations/active.json",
        ".folderbase/transactions/change-set/active.json",
    ] {
        if observation
            .read(Path::new(path), MAX_JOURNAL_BYTES)?
            .is_some()
        {
            return Err(FileHistoryError::RecoveryRequired {
                work: path.to_owned(),
            });
        }
    }
    for name in observation.names(Path::new(TRANSACTIONS_DIRECTORY))? {
        if name.to_str().is_none_or(|name| name.ends_with(".json")) {
            return Err(FileHistoryError::RecoveryRequired {
                work: "local version transaction".to_owned(),
            });
        }
    }
    // Existing migration reopening may repair staging/reconcile claims even
    // when reached through the shared pending scanner. Never invoke it here.
    if !observation
        .names(Path::new(".folderbase/migrations"))?
        .is_empty()
    {
        return Err(FileHistoryError::MigrationStateUnsupported);
    }
    if !observation
        .names(Path::new(HISTORY_TRANSFER_STAGING_DIRECTORY))?
        .is_empty()
    {
        return Err(FileHistoryError::RecoveryRequired {
            work: "history-transfer staging".to_owned(),
        });
    }
    for name in observation.names(Path::new(HISTORY_TRANSFER_INTENTS_DIRECTORY))? {
        let path = Path::new(HISTORY_TRANSFER_INTENTS_DIRECTORY).join(name);
        let bytes = observation.required(&path, MAX_JOURNAL_BYTES)?;
        let plan: HistoryTransferPlan = serde_json::from_slice(&bytes)
            .map_err(|source| FolderbaseError::json(&path, source))?;
        validate_history_transfer_plan(&plan, &path)?;
        if path.file_stem().and_then(|name| name.to_str()) != Some(plan.id.as_str()) {
            return Err(invalid_record(&path, "transfer ID does not match filename").into());
        }
        if matches!(
            plan.state,
            HistoryTransferState::Approved
                | HistoryTransferState::Applying
                | HistoryTransferState::DestinationVerified
                | HistoryTransferState::SourceReleased
        ) {
            return Err(FileHistoryError::RecoveryRequired {
                work: format!("history transfer {}", plan.id),
            });
        }
    }
    if let Some(bytes) = observation.read(Path::new(JOURNAL_PATH), MAX_JOURNAL_BYTES)? {
        // Validate journal syntax and event shape, not the present ownership of
        // every historical path. Completed nested transfers remain legitimate.
        parse_journal_bytes(Path::new(JOURNAL_PATH), &bytes, false)?;
    }
    Ok(())
}

fn limit(limit: &'static str, maximum: u64) -> FileHistoryError {
    FileHistoryError::LimitExceeded { limit, maximum }
}

fn bounded_read(
    state: &FolderbaseState,
    path: &Path,
    maximum: u64,
) -> HistoryResult<Option<Vec<u8>>> {
    match state.open_private_target_nofollow(path)? {
        WorkspaceTarget::Absent => Ok(None),
        WorkspaceTarget::Directory(_) => {
            Err(invalid_record(path, "history metadata is not a regular file").into())
        }
        WorkspaceTarget::RegularFile(file) => {
            let file = file.into_std();
            if file
                .metadata()
                .map_err(|source| FolderbaseError::io(path, source))?
                .len()
                > maximum
            {
                return Err(limit("record_bytes", maximum));
            }
            let mut bytes = Vec::new();
            file.take(maximum + 1)
                .read_to_end(&mut bytes)
                .map_err(|source| FolderbaseError::io(path, source))?;
            if bytes.len() as u64 > maximum {
                return Err(limit("record_bytes", maximum));
            }
            Ok(Some(bytes))
        }
    }
}

fn directory_names(state: &FolderbaseState, path: &Path) -> HistoryResult<Vec<OsString>> {
    let directory = match state.open_private_target_nofollow(path)? {
        WorkspaceTarget::Absent => return Ok(Vec::new()),
        WorkspaceTarget::Directory(directory) => directory,
        WorkspaceTarget::RegularFile(_) => {
            return Err(
                invalid_record(path, "history metadata directory is not a directory").into(),
            );
        }
    };
    let mut names = Vec::new();
    for entry in directory
        .entries()
        .map_err(|source| FolderbaseError::io(path, source))?
    {
        let entry = entry.map_err(|source| FolderbaseError::io(path, source))?;
        if names.len() == MAX_ENTRIES {
            return Err(limit("directory_entries", MAX_ENTRIES as u64));
        }
        names.push(entry.file_name());
    }
    names.sort();
    Ok(names)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        InitializationOptions, initialize, plan_initialization, read_workspace_text,
        save_workspace_text,
    };
    use tempfile::{TempDir, tempdir};

    fn fixture() -> TempDir {
        let root = tempdir().unwrap();
        initialize(&plan_initialization(root.path(), InitializationOptions::default()).unwrap())
            .unwrap();
        fs::create_dir(root.path().join("tasks")).unwrap();
        fs::write(root.path().join("tasks/a.json"), b"first\0bytes").unwrap();
        root
    }

    fn tracked() -> (TempDir, CaptureResult) {
        let root = fixture();
        let captured = LocalVersionStore::open(root.path())
            .unwrap()
            .capture_file("tasks/a.json")
            .unwrap();
        (root, captured)
    }

    fn snapshot(root: &Path) -> BTreeMap<PathBuf, (Vec<u8>, std::time::SystemTime)> {
        walkdir::WalkDir::new(root)
            .into_iter()
            .map(|entry| {
                let entry = entry.unwrap();
                let meta = fs::symlink_metadata(entry.path()).unwrap();
                let bytes = if meta.is_file() {
                    fs::read(entry.path()).unwrap()
                } else {
                    Vec::new()
                };
                (
                    entry.path().strip_prefix(root).unwrap().to_path_buf(),
                    (bytes, meta.modified().unwrap()),
                )
            })
            .collect()
    }

    fn recreated() -> TempDir {
        let root = fixture();
        let store = crate::FolderbaseVersionStore::open(root.path()).unwrap();
        store.seal_capture(store.plan_capture().unwrap()).unwrap();
        fs::remove_file(root.path().join("tasks/a.json")).unwrap();
        store.seal_capture(store.plan_capture().unwrap()).unwrap();
        fs::write(root.path().join("tasks/a.json"), "a different file").unwrap();
        store.seal_capture(store.plan_capture().unwrap()).unwrap();
        root
    }

    #[test]
    fn completed_create_ownership_is_read_only_and_rechecks_receipt_inventory() {
        for change in [
            "none",
            "receipt",
            "inventory",
            "pending",
            "original-version",
        ] {
            let root = fixture();
            let store = crate::FolderbaseVersionStore::open(root.path()).unwrap();
            store.seal_capture(store.plan_capture().unwrap()).unwrap();
            fs::remove_file(root.path().join("tasks/a.json")).unwrap();
            store.seal_capture(store.plan_capture().unwrap()).unwrap();
            let created = crate::create_workspace_file(
                root.path(),
                "tasks/a.json",
                &Uuid::now_v7().to_string(),
                b"new generation",
            )
            .unwrap();
            let before = snapshot(root.path());
            let mut after_external_change = None;
            let result =
                read_file_history_with_hook(root.path(), Path::new("tasks/a.json"), || {
                    match change {
                        "none" => {}
                        "receipt" => {
                            let path = root.path().join(format!(
                                ".folderbase/local/workspace-create/receipts/{}.json",
                                created.operation_id
                            ));
                            let mut bytes = fs::read(&path).unwrap();
                            bytes.push(b' ');
                            fs::write(path, bytes).unwrap();
                        }
                        "inventory" => fs::write(
                            root.path()
                                .join(".folderbase/local/workspace-create/receipts/foreign.json"),
                            b"{}",
                        )
                        .unwrap(),
                        "pending" => {
                            fs::write(root.path().join(file_create::ACTIVE_CREATE_PATH), b"{}")
                                .unwrap()
                        }
                        "original-version" => fs::write(
                            root.path().join(format!(
                                "{VERSION_RECORDS_DIRECTORY}/{}.json",
                                created.version_id
                            )),
                            b"{}",
                        )
                        .unwrap(),
                        _ => unreachable!(),
                    }
                    after_external_change = Some(snapshot(root.path()));
                });
            if change == "none" {
                assert_eq!(result.unwrap().object_id, Some(created.object_id));
                assert_eq!(before, snapshot(root.path()));
            } else {
                assert!(result.is_err(), "accepted changed {change}");
                assert_eq!(
                    after_external_change.unwrap(),
                    snapshot(root.path()),
                    "history wrote after {change}"
                );
            }
        }
    }

    #[test]
    fn repeated_ownership_observation_cannot_replace_its_first_witness() {
        let root = fixture();
        let state = FolderbaseState::open_existing_read_only(root.path()).unwrap();
        let mut observation = Observation::new(&state);
        let path = Path::new(".folderbase/manifest.json");
        let original = observation.read(path, MAX_JOURNAL_BYTES).unwrap().unwrap();
        let mut changed = original.clone();
        changed.push(b' ');
        fs::write(root.path().join(path), changed).unwrap();
        assert!(matches!(
            observation.read(path, MAX_JOURNAL_BYTES),
            Err(FileHistoryError::ObservationChanged)
        ));
        assert_eq!(observation.files[path].1.as_ref(), Some(&original));
    }

    #[test]
    fn recreated_path_selects_only_live_history_without_mutation_and_rechecks_authority() {
        let root = recreated();
        let before = snapshot(root.path());
        let history = read_file_history(root.path(), "tasks/a.json").unwrap();
        assert_eq!(history.versions.len(), 1);
        assert_eq!(before, snapshot(root.path()));
        let head_path = root.path().join(".folderbase/local/head.json");
        let head: serde_json::Value =
            serde_json::from_slice(&fs::read(&head_path).unwrap()).unwrap();
        let version_path = root.path().join(format!(
            ".folderbase/versions/folderbase/{}.json",
            head["version_id"].as_str().unwrap()
        ));
        for path in [head_path, version_path] {
            let bytes = fs::read(&path).unwrap();
            let result =
                read_file_history_with_hook(root.path(), Path::new("tasks/a.json"), || {
                    let mut changed = bytes.clone();
                    changed.push(b' ');
                    fs::write(&path, changed).unwrap();
                });
            assert!(matches!(result, Err(FileHistoryError::ObservationChanged)));
            fs::write(path, bytes).unwrap();
        }
    }

    #[test]
    fn current_head_does_not_hide_an_unexplained_or_corrupt_claimant() {
        for damage in ["extra-object", "old-version", "alias"] {
            let root = recreated();
            let local = LocalVersionStore::open(root.path()).unwrap();
            let live = read_file_history(root.path(), "tasks/a.json")
                .unwrap()
                .object_id
                .unwrap();
            let mut object = local.read_object(&live).unwrap();
            if damage == "extra-object" {
                object.id = ObjectId::new();
                fs::write(
                    local.object_record_path(&object.id),
                    serde_json::to_vec(&object).unwrap(),
                )
                .unwrap();
            } else {
                let old = fs::read_dir(root.path().join(OBJECTS_DIRECTORY))
                    .unwrap()
                    .map(|entry| entry.unwrap().path())
                    .filter_map(|path| {
                        serde_json::from_slice::<LocalObjectRecord>(&fs::read(&path).unwrap())
                            .ok()
                            .map(|record| (path, record))
                    })
                    .find(|(_, record)| record.path == "tasks/a.json" && record.id != live)
                    .unwrap();
                if damage == "old-version" {
                    let mut version = local.read_version(&old.1.current_version).unwrap();
                    version.object_id = ObjectId::new();
                    fs::write(
                        local.version_record_path(&version.id),
                        serde_json::to_vec(&version).unwrap(),
                    )
                    .unwrap();
                } else {
                    let mut record = old.1;
                    record.path = "tasks/A.JSON".into();
                    fs::write(old.0, serde_json::to_vec(&record).unwrap()).unwrap();
                }
            }
            let before = snapshot(root.path());
            assert!(
                read_file_history(root.path(), "tasks/a.json").is_err(),
                "{damage}"
            );
            assert_eq!(before, snapshot(root.path()));
        }
    }

    #[test]
    fn complete_metadata_is_read_only_and_live_bytes_need_not_match_recorded_head() {
        let (root, first) = tracked();
        fs::write(root.path().join("tasks/a.json"), "second").unwrap();
        let second = LocalVersionStore::open(root.path())
            .unwrap()
            .capture_file("tasks/a.json")
            .unwrap();
        fs::write(root.path().join("tasks/a.json"), "uncaptured owner edit").unwrap();
        let before = snapshot(root.path());
        let history = read_file_history(root.path(), "tasks/a.json").unwrap();
        assert_eq!(history.path, "tasks/a.json");
        assert_eq!(history.object_id, Some(first.object.id));
        assert_eq!(history.current_version, Some(second.version.id.clone()));
        assert_eq!(history.versions, [first.version, second.version]);
        assert_eq!(before, snapshot(root.path()));
    }

    #[test]
    fn untracked_file_never_creates_layout_or_lock_and_missing_path_refuses() {
        let root = fixture();
        let before = snapshot(root.path());
        let history = read_file_history(root.path(), "tasks/a.json").unwrap();
        assert_eq!(
            (history.object_id, history.current_version, history.versions),
            (None, None, vec![])
        );
        assert!(matches!(
            read_file_history(root.path(), "missing.json"),
            Err(FileHistoryError::FileNotFound(_))
        ));
        assert_eq!(before, snapshot(root.path()));
        assert!(!root.path().join(TRANSACTION_LOCK_PATH).exists());
    }

    #[cfg(unix)]
    #[test]
    fn physically_read_only_root_needs_no_writable_handle() {
        use std::os::unix::fs::PermissionsExt;
        let (root, first) = tracked();
        let paths: Vec<_> = walkdir::WalkDir::new(root.path())
            .into_iter()
            .map(|entry| entry.unwrap().into_path())
            .collect();
        let before = snapshot(root.path());
        for path in &paths {
            fs::set_permissions(
                path,
                fs::Permissions::from_mode(if path.is_dir() { 0o555 } else { 0o444 }),
            )
            .unwrap();
        }
        let result = read_file_history(root.path(), "tasks/a.json");
        for path in &paths {
            fs::set_permissions(
                path,
                fs::Permissions::from_mode(if path.is_dir() { 0o755 } else { 0o644 }),
            )
            .unwrap();
        }
        assert_eq!(result.unwrap().versions, [first.version]);
        assert_eq!(before, snapshot(root.path()));
    }

    #[test]
    fn pending_work_and_torn_journal_refuse_without_recovery() {
        for damaged in [
            ".folderbase/transactions/transaction_pending.json",
            ".folderbase/transactions/change-set/active.json",
            ".folderbase/transactions/folderbase-version-captures/active.json",
            JOURNAL_PATH,
        ] {
            let (root, _) = tracked();
            let path = root.path().join(damaged);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, "{\"interrupted\":").unwrap();
            let before = snapshot(root.path());
            assert!(
                read_file_history(root.path(), "tasks/a.json").is_err(),
                "{damaged}"
            );
            assert_eq!(before, snapshot(root.path()));
        }
    }

    #[test]
    fn malformed_records_duplicate_claimants_and_foreign_versions_refuse_unchanged() {
        for damage in [
            "object_filename",
            "duplicate_claim",
            "unrelated_json",
            "unrelated_directory",
            "version_filename",
            "foreign_version",
            "duplicate_version",
            "oversized_record",
        ] {
            let (root, first) = tracked();
            let store = LocalVersionStore::open(root.path()).unwrap();
            let object_path = store.object_record_path(&first.object.id);
            let version_path = store.version_record_path(&first.version.id);
            match damage {
                "object_filename" => {
                    fs::rename(
                        &object_path,
                        root.path().join(OBJECTS_DIRECTORY).join("wrong.json"),
                    )
                    .unwrap();
                }
                "duplicate_claim" => {
                    let mut duplicate = first.object.clone();
                    duplicate.id = ObjectId::new();
                    fs::write(
                        store.object_record_path(&duplicate.id),
                        serde_json::to_vec(&duplicate).unwrap(),
                    )
                    .unwrap();
                }
                "unrelated_json" => {
                    fs::write(root.path().join(OBJECTS_DIRECTORY).join("broken.json"), "{")
                        .unwrap();
                }
                "unrelated_directory" => {
                    fs::create_dir(root.path().join(OBJECTS_DIRECTORY).join("directory.json"))
                        .unwrap();
                }
                "duplicate_version" => {
                    let mut object = first.object.clone();
                    object.versions.push(first.version.id.clone());
                    fs::write(&object_path, serde_json::to_vec(&object).unwrap()).unwrap();
                }
                "oversized_record" => {
                    fs::write(&object_path, vec![b' '; MAX_RECORD_BYTES as usize + 1]).unwrap();
                }
                _ => {
                    let mut version = first.version.clone();
                    if damage == "foreign_version" {
                        version.object_id = ObjectId::new();
                    } else {
                        version.id = VersionId::new();
                    }
                    fs::write(&version_path, serde_json::to_vec(&version).unwrap()).unwrap();
                }
            }
            let before = snapshot(root.path());
            let error = read_file_history(root.path(), "tasks/a.json").unwrap_err();
            if damage == "oversized_record" {
                assert!(matches!(
                    error,
                    FileHistoryError::LimitExceeded {
                        limit: "record_bytes",
                        ..
                    }
                ));
            }
            assert_eq!(before, snapshot(root.path()), "{damage}");
        }
    }

    #[test]
    fn mutation_between_observation_and_return_is_refused() {
        for change in [
            "object",
            "duplicate",
            "lock",
            "state",
            "root",
            "file",
            "marker",
        ] {
            let (root, first) = tracked();
            let error =
                read_file_history_with_hook(
                    root.path(),
                    Path::new("tasks/a.json"),
                    || match change {
                        "object" => {
                            let path = root
                                .path()
                                .join(OBJECTS_DIRECTORY)
                                .join(format!("{}.json", first.object.id));
                            let mut object = first.object.clone();
                            object
                                .extensions
                                .insert("owner".to_owned(), Value::Bool(true));
                            fs::write(path, serde_json::to_vec(&object).unwrap()).unwrap();
                        }
                        "duplicate" => {
                            let mut duplicate = first.object.clone();
                            duplicate.id = ObjectId::new();
                            fs::write(
                                root.path()
                                    .join(OBJECTS_DIRECTORY)
                                    .join(format!("{}.json", duplicate.id)),
                                serde_json::to_vec(&duplicate).unwrap(),
                            )
                            .unwrap();
                        }
                        "lock" => {
                            fs::rename(
                                root.path().join(TRANSACTION_LOCK_PATH),
                                root.path().join("old-lock"),
                            )
                            .unwrap();
                            fs::write(root.path().join(TRANSACTION_LOCK_PATH), "").unwrap();
                        }
                        "state" => {
                            fs::rename(
                                root.path().join(".folderbase"),
                                root.path().join("old-state"),
                            )
                            .unwrap();
                            fs::create_dir(root.path().join(".folderbase")).unwrap();
                        }
                        "root" => {
                            fs::rename(root.path(), root.path().with_extension("moved")).unwrap();
                            fs::create_dir(root.path()).unwrap();
                        }
                        "file" => {
                            fs::rename(
                                root.path().join("tasks/a.json"),
                                root.path().join("old-file"),
                            )
                            .unwrap();
                            fs::write(root.path().join("tasks/a.json"), b"first\0bytes").unwrap();
                        }
                        "marker" => {
                            fs::create_dir(root.path().join("tasks/.folderbase")).unwrap();
                            fs::write(root.path().join("tasks/.folderbase/manifest.json"), "{}")
                                .unwrap();
                        }
                        _ => unreachable!(),
                    },
                )
                .unwrap_err();
            assert!(!matches!(error, FileHistoryError::Busy), "{change}");
            if change == "root" {
                fs::remove_dir_all(root.path().with_extension("moved")).unwrap();
            }
        }
    }

    #[test]
    fn missing_lock_appearance_and_exclusive_writer_refuse() {
        let root = fixture();
        assert!(matches!(
            read_file_history_with_hook(root.path(), Path::new("tasks/a.json"), || {
                fs::create_dir_all(root.path().join(LOCKS_DIRECTORY)).unwrap();
                fs::write(root.path().join(TRANSACTION_LOCK_PATH), "").unwrap();
            }),
            Err(FileHistoryError::ObservationChanged)
        ));
        let file = File::options()
            .read(true)
            .write(true)
            .open(root.path().join(TRANSACTION_LOCK_PATH))
            .unwrap();
        file.lock().unwrap();
        let before = snapshot(root.path());
        assert!(matches!(
            read_file_history(root.path(), "tasks/a.json"),
            Err(FileHistoryError::Busy)
        ));
        assert_eq!(before, snapshot(root.path()));
    }

    #[test]
    fn ordinary_cas_adds_one_version_and_reader_preserves_extensions() {
        let (root, first) = tracked();
        fs::write(root.path().join("tasks/a.json"), "first").unwrap();
        let current = read_workspace_text(root.path(), "tasks/a.json").unwrap();
        let saved =
            save_workspace_text(root.path(), "tasks/a.json", &current.sha256, "second").unwrap();
        let mut version = first.version.clone();
        version
            .extensions
            .insert("vendor".to_owned(), serde_json::json!({"preserved": true}));
        fs::write(
            root.path()
                .join(VERSION_RECORDS_DIRECTORY)
                .join(format!("{}.json", version.id)),
            serde_json::to_vec(&version).unwrap(),
        )
        .unwrap();
        let history = read_file_history(root.path(), "tasks/a.json").unwrap();
        assert_eq!(history.versions.len(), 3); // initial binary, owner text checkpoint, accepted edit
        assert_eq!(history.current_version, Some(saved.version_id));
        assert_eq!(history.versions[0], version);
    }

    #[test]
    fn completed_and_repair_eligible_migration_metadata_are_unsupported_without_mutation() {
        let (root, first) = tracked();
        let plan = crate::MigrationPlan::propose_structural(
            root.path(),
            vec![crate::MigrationOperation::add_relationship(
                format!(".folderbase/objects/{}.json", first.object.id),
                "related_to",
                first.object.id.to_string(),
            )],
        )
        .unwrap();
        crate::apply_migration(crate::approve_migration(plan).unwrap()).unwrap();
        let before = snapshot(root.path());
        assert!(matches!(
            read_file_history(root.path(), "tasks/a.json"),
            Err(FileHistoryError::MigrationStateUnsupported)
        ));
        assert_eq!(before, snapshot(root.path()));
        // Reconstruct a recoverable interrupted write in an actual completed
        // migration's journal. The old pending validator quarantines this file.
        let journal = walkdir::WalkDir::new(root.path().join(".folderbase/migrations"))
            .into_iter()
            .map(|entry| entry.unwrap())
            .find(|entry| entry.file_type().is_dir() && entry.file_name() == "journal")
            .unwrap()
            .into_path();
        let writing = journal.join(".next-generation.writing");
        fs::write(&writing, b"{interrupted next generation").unwrap();
        let before = snapshot(root.path());
        assert!(matches!(
            read_file_history(root.path(), "tasks/a.json"),
            Err(FileHistoryError::MigrationStateUnsupported)
        ));
        assert_eq!(before, snapshot(root.path()));
        assert!(writing.exists());
    }

    #[test]
    fn completed_transfer_reads_at_destination_and_source_stays_revoked() {
        let root = fixture();
        let parent_id = crate::attest_folderbase_root(root.path())
            .unwrap()
            .folderbase_id;
        let parent = LocalVersionStore::open(root.path()).unwrap();
        let first = parent.capture_file("tasks/a.json").unwrap();
        let child_root = root.path().join("tasks");
        let child_fixture = tempdir().unwrap();
        let child = initialize(
            &plan_initialization(child_fixture.path(), InitializationOptions::default()).unwrap(),
        )
        .unwrap();
        fs::create_dir(child_root.join(".folderbase")).unwrap();
        fs::copy(
            child_fixture.path().join(".folderbase/manifest.json"),
            child_root.join(".folderbase/manifest.json"),
        )
        .unwrap();
        let destination = LocalVersionStore::open(&child_root).unwrap();
        let plan = parent
            .propose_history_transfer(
                &destination,
                &parent_id,
                &child.folderbase_id,
                &first.object.id,
                "a.json",
            )
            .unwrap();
        apply_history_transfer(approve_history_transfer(plan).unwrap()).unwrap();
        let before = snapshot(root.path());
        assert_eq!(
            read_file_history(&child_root, "a.json").unwrap().versions,
            [first.version]
        );
        assert!(read_file_history(root.path(), "tasks/a.json").is_err());
        assert_eq!(before, snapshot(root.path()));
        // Even if the nested marker disappears, the outgoing receipt revokes
        // source history authority independently of the current boundary.
        fs::rename(child_root.join(".folderbase"), child_root.join("old-state")).unwrap();
        let before = snapshot(root.path());
        assert!(read_file_history(root.path(), "tasks/a.json").is_err());
        assert_eq!(before, snapshot(root.path()));
    }

    #[test]
    fn encoded_result_limit_includes_extension_fields_and_returns_no_partial_history() {
        let (root, first) = tracked();
        let store = LocalVersionStore::open(root.path()).unwrap();
        let mut object = first.object;
        for _ in 0..10 {
            let mut version = first.version.clone();
            version.id = VersionId::new();
            version.extensions.insert(
                "large_vendor_data".to_owned(),
                Value::String("a".repeat(900_000)),
            );
            fs::write(
                store.version_record_path(&version.id),
                serde_json::to_vec(&version).unwrap(),
            )
            .unwrap();
            object.versions.push(version.id);
        }
        fs::write(
            store.object_record_path(&object.id),
            serde_json::to_vec(&object).unwrap(),
        )
        .unwrap();
        let before = snapshot(root.path());
        assert!(matches!(
            read_file_history(root.path(), "tasks/a.json"),
            Err(FileHistoryError::LimitExceeded {
                limit: "encoded_result_bytes",
                ..
            })
        ));
        assert_eq!(before, snapshot(root.path()));
    }

    #[test]
    fn deeply_nested_small_metadata_stops_before_serializing_the_remaining_output() {
        let (root, first) = tracked();
        let store = LocalVersionStore::open(root.path()).unwrap();
        let mut nested = Value::Array(vec![Value::Bool(false); 50_000]);
        for _ in 0..90 {
            nested = Value::Array(vec![nested]);
        }
        let mut version = first.version;
        version.extensions.insert("nested".to_owned(), nested);
        let bytes = serde_json::to_vec(&version).unwrap();
        assert!(bytes.len() < MAX_RECORD_BYTES as usize);
        fs::write(store.version_record_path(&version.id), &bytes).unwrap();
        let before = snapshot(root.path());
        assert!(matches!(
            read_file_history(root.path(), "tasks/a.json"),
            Err(FileHistoryError::LimitExceeded {
                limit: "encoded_result_bytes",
                ..
            })
        ));
        assert_eq!(before, snapshot(root.path()));

        // Prove that serialization propagates the bound before visiting a
        // subsequent field, rather than encoding everything and checking later.
        struct TailProbe<'a> {
            value: &'a LocalVersionRecord,
            visited: &'a std::cell::Cell<bool>,
        }
        impl Serialize for TailProbe<'_> {
            fn serialize<S: serde::Serializer>(
                &self,
                serializer: S,
            ) -> std::result::Result<S::Ok, S::Error> {
                use serde::ser::SerializeSeq;
                let mut sequence = serializer.serialize_seq(Some(2))?;
                sequence.serialize_element(self.value)?;
                self.visited.set(true);
                sequence.serialize_element("unvisited tail")?;
                sequence.end()
            }
        }
        let visited = std::cell::Cell::new(false);
        let mut budget = EncodedResultBudget {
            bytes: 1,
            exceeded: false,
        };
        assert!(
            serde_json::to_writer_pretty(
                &mut budget,
                &TailProbe {
                    value: &version,
                    visited: &visited
                }
            )
            .is_err()
        );
        assert!(budget.exceeded);
        assert!(budget.bytes <= MAX_RESULT_BYTES);
        assert!(!visited.get());
    }
}

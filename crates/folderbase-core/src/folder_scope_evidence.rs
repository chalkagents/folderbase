//! Trusted device-local evidence for one exact selected ordinary folder.

use std::{
    ffi::OsStr,
    io,
    path::{Component, Path, PathBuf},
};

#[cfg(not(windows))]
use cap_fs_ext::DirExt;
#[cfg(windows)]
use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt};
use cap_std::fs::Dir;
#[cfg(windows)]
use cap_std::fs::OpenOptions;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    CaptureEntryKind, CaptureExclusionKind, CapturePlan, FolderbaseCaptureError, FolderbaseError,
    FolderbaseVersionStore, LocalVersionStore, folderbase_state::FolderbaseState,
    physical_identity::PhysicalIdentity, root_attestation::FolderbaseRootAttestation,
    traversal_policy::is_reserved_workspace_component,
};

#[cfg(windows)]
use crate::root_attestation::metadata_is_link_or_reparse;

const EVIDENCE_FORMAT: &str = "folderbase-folder-scope-evidence-v1";
const JOURNAL_FORMAT: &str = "folderbase-folder-scope-journal-v1";
const EVENT_FORMAT: &str = "folderbase-folder-scope-journal-event-v1";
const JOURNAL_DIRECTORY: &str = ".folderbase/local/folder-scope-evidence-v1";
const EVENTS_DIRECTORY: &str = ".folderbase/local/folder-scope-evidence-v1/events";
const HEAD_PATH: &str = ".folderbase/local/folder-scope-evidence-v1/head.json";
const MAX_HEAD_BYTES: u64 = 64 * 1024;
const MAX_EVENT_BYTES: u64 = 256 * 1024;
const MAX_JOURNAL_EVENTS: u64 = 16_384;

/// Bounded observer input for allocating or advancing one durable Folder Scope.
///
/// The binding proof is an opaque continuity value. It is not a credential,
/// Folder Scope ID, grant, or authorization decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FolderScopeEvidence {
    pub format: String,
    pub folderbase_id: String,
    pub selected_path: String,
    pub event_id: String,
    pub device_sequence: u64,
    pub opaque_binding_proof: String,
    pub nested_boundaries: Vec<String>,
}

/// Failures produced before Folder Scope evidence can be trusted.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum FolderScopeEvidenceError {
    #[error(transparent)]
    Capture(#[from] FolderbaseCaptureError),

    #[error(transparent)]
    Core(#[from] FolderbaseError),

    #[error("selected Folder Scope path is not a safe ordinary relative folder: {path}")]
    UnsafeSelectedPath { path: PathBuf },

    #[error("selected Folder Scope path does not exist: {path}")]
    SelectedFolderNotFound { path: PathBuf },

    #[error("selected Folder Scope path must not be a symbolic link or reparse point: {path}")]
    SelectedFolderSymlink { path: PathBuf },

    #[error("selected Folder Scope path is not a directory: {path}")]
    SelectedFolderNotDirectory { path: PathBuf },

    #[error("selected Folder Scope path is excluded from the current Core inventory: {path}")]
    SelectedFolderExcluded { path: PathBuf },

    #[error("selected Folder Scope contains an unsupported node: {path}")]
    UnsupportedSelectedNode { path: PathBuf },

    #[error("a different physical folder now occupies an observed Folder Scope path: {path}")]
    SelectedFolderReplaced { path: PathBuf },

    #[error("selected Folder Scope or Folderbase Root changed during observation")]
    ObservationChanged,

    #[error("the device-local Folder Scope journal is invalid: {message}")]
    InvalidJournal { message: String },
}

impl FolderScopeEvidenceError {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Capture(_) => "folder_scope_capture_invalid",
            Self::Core(_) => "folder_scope_state_invalid",
            Self::UnsafeSelectedPath { .. } => "unsafe_selected_path",
            Self::SelectedFolderNotFound { .. } => "selected_folder_not_found",
            Self::SelectedFolderSymlink { .. } => "selected_folder_symlink",
            Self::SelectedFolderNotDirectory { .. } => "selected_folder_not_directory",
            Self::SelectedFolderExcluded { .. } => "selected_folder_excluded",
            Self::UnsupportedSelectedNode { .. } => "unsupported_selected_node",
            Self::SelectedFolderReplaced { .. } => "selected_folder_replaced",
            Self::ObservationChanged => "folder_scope_observation_changed",
            Self::InvalidJournal { .. } => "invalid_folder_scope_journal",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct JournalHead {
    format: String,
    folderbase_id: String,
    root_instance_sha256: String,
    device_sequence: u64,
    event_id: String,
    event_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct JournalEvent {
    format: String,
    folderbase_id: String,
    root_instance_sha256: String,
    selected_path: String,
    selected_instance_sha256: String,
    local_head_sha256: Option<String>,
    observation_sha256: String,
    event_id: String,
    device_sequence: u64,
    opaque_binding_proof: String,
    nested_boundaries: Vec<String>,
    previous_event_sha256: Option<String>,
}

impl JournalEvent {
    fn public_evidence(&self) -> FolderScopeEvidence {
        FolderScopeEvidence {
            format: EVIDENCE_FORMAT.to_owned(),
            folderbase_id: self.folderbase_id.clone(),
            selected_path: self.selected_path.clone(),
            event_id: self.event_id.clone(),
            device_sequence: self.device_sequence,
            opaque_binding_proof: self.opaque_binding_proof.clone(),
            nested_boundaries: self.nested_boundaries.clone(),
        }
    }
}

/// Observe one exact ordinary folder through Core-owned root confinement.
///
/// An identical repeated observation returns the previously committed event.
/// New observations advance one device-local sequence under the shared Core
/// transaction lock. No visible workspace path is created or changed.
pub fn observe_folder_scope(
    root: impl AsRef<Path>,
    selected_path: impl AsRef<Path>,
) -> Result<FolderScopeEvidence, FolderScopeEvidenceError> {
    let selected_path = safe_selected_path(selected_path.as_ref())?;
    let selected_wire = relative_wire_path(&selected_path)?;
    let store = FolderbaseVersionStore::open(root)?;
    let plan = store.plan_capture()?;
    let attestation = store.root_attestation.clone();
    let state = FolderbaseState::open_existing(&attestation.root)?;
    state.verify_root_identity(store.root_physical_identity())?;
    let root_capability = state.clone_root_capability()?;
    let selected_identity =
        selected_folder_identity(&root_capability, &attestation.root, &selected_path)?;
    let selected_instance_sha256 = selected_identity.stable_sha256();
    let nested_boundaries = scope_nested_boundaries(&plan, &selected_wire)?;
    let local_head_sha256 = plan
        .current_local_head()
        .map(|head| head.encoded_sha256().to_owned());
    let opaque_binding_proof = binding_proof(
        &attestation.folderbase_id,
        &attestation.root_instance_sha256,
        &selected_instance_sha256,
    );
    let observation_sha256 = observation_sha256(
        &attestation,
        &selected_wire,
        &selected_instance_sha256,
        local_head_sha256.as_deref(),
        &nested_boundaries,
    );

    state.ensure_private_dir(Path::new(".folderbase/locks"))?;
    let _lock = LocalVersionStore::acquire_transaction_lock_for_state(&attestation.root, &state)?;
    state.verify_still_attached()?;
    verify_attestation(&attestation)?;
    let final_identity =
        selected_folder_identity(&root_capability, &attestation.root, &selected_path)?;
    if final_identity != selected_identity {
        return Err(FolderScopeEvidenceError::ObservationChanged);
    }
    let final_plan = store.plan_capture()?;
    let final_local_head_sha256 = final_plan
        .current_local_head()
        .map(|head| head.encoded_sha256().to_owned());
    if scope_nested_boundaries(&final_plan, &selected_wire)? != nested_boundaries
        || final_local_head_sha256 != local_head_sha256
    {
        return Err(FolderScopeEvidenceError::ObservationChanged);
    }

    state.ensure_private_dir(Path::new(JOURNAL_DIRECTORY))?;
    state.ensure_private_dir(Path::new(EVENTS_DIRECTORY))?;
    let (head, history) = read_journal(&state, &attestation)?;
    if let Some(existing) = history
        .iter()
        .find(|event| event.observation_sha256 == observation_sha256)
    {
        return Ok(existing.public_evidence());
    }
    if history.iter().any(|event| {
        event.selected_path == selected_wire && event.opaque_binding_proof != opaque_binding_proof
    }) {
        return Err(FolderScopeEvidenceError::SelectedFolderReplaced {
            path: selected_path,
        });
    }

    let sequence = match head.as_ref() {
        Some(head) => head.device_sequence.checked_add(1).ok_or_else(|| {
            FolderScopeEvidenceError::InvalidJournal {
                message: "device sequence is exhausted".to_owned(),
            }
        })?,
        None => 1,
    };
    if sequence > MAX_JOURNAL_EVENTS {
        return Err(FolderScopeEvidenceError::InvalidJournal {
            message: format!("journal exceeds {MAX_JOURNAL_EVENTS} events"),
        });
    }
    let previous_event_sha256 = head.as_ref().map(|head| head.event_sha256.clone());
    let event_id = event_id(
        &attestation.root_instance_sha256,
        sequence,
        previous_event_sha256.as_deref(),
        &observation_sha256,
    );
    let event = JournalEvent {
        format: EVENT_FORMAT.to_owned(),
        folderbase_id: attestation.folderbase_id.clone(),
        root_instance_sha256: attestation.root_instance_sha256.clone(),
        selected_path: selected_wire,
        selected_instance_sha256,
        local_head_sha256,
        observation_sha256,
        event_id: event_id.clone(),
        device_sequence: sequence,
        opaque_binding_proof,
        nested_boundaries,
        previous_event_sha256,
    };
    let event_bytes = encode_bounded(&event, MAX_EVENT_BYTES, "journal event")?;
    let event_sha256 = hex_sha256(&event_bytes);
    let event_path = event_path(sequence);
    match state.publish_new(&event_path, &event_bytes) {
        Ok(()) => {}
        Err(FolderbaseError::WouldOverwrite(_)) => {
            let existing = state
                .read_bounded(&event_path, MAX_EVENT_BYTES)?
                .ok_or_else(|| FolderScopeEvidenceError::InvalidJournal {
                    message: "the next journal event disappeared during recovery".to_owned(),
                })?;
            if existing != event_bytes {
                return Err(FolderScopeEvidenceError::InvalidJournal {
                    message: "the next journal sequence is occupied by different evidence"
                        .to_owned(),
                });
            }
        }
        Err(error) => return Err(error.into()),
    }
    let next_head = JournalHead {
        format: JOURNAL_FORMAT.to_owned(),
        folderbase_id: attestation.folderbase_id,
        root_instance_sha256: attestation.root_instance_sha256,
        device_sequence: sequence,
        event_id,
        event_sha256,
    };
    let head_bytes = encode_bounded(&next_head, MAX_HEAD_BYTES, "journal head")?;
    if head.is_some() {
        state.replace(Path::new(HEAD_PATH), &head_bytes)?;
    } else {
        match state.publish_new(Path::new(HEAD_PATH), &head_bytes) {
            Ok(()) => {}
            Err(FolderbaseError::WouldOverwrite(_)) => {
                return Err(FolderScopeEvidenceError::InvalidJournal {
                    message: "the journal head changed while its transaction lock was held"
                        .to_owned(),
                });
            }
            Err(error) => return Err(error.into()),
        }
    }
    state.verify_still_attached()?;
    verify_attestation(&store.root_attestation)?;
    Ok(event.public_evidence())
}

fn scope_nested_boundaries(
    plan: &CapturePlan,
    selected_path: &str,
) -> Result<Vec<String>, FolderScopeEvidenceError> {
    let selected_is_captured_directory = plan
        .entries()
        .iter()
        .any(|entry| entry.path() == selected_path && entry.kind() == CaptureEntryKind::Directory);
    if !selected_is_captured_directory {
        return Err(FolderScopeEvidenceError::SelectedFolderExcluded {
            path: PathBuf::from(selected_path),
        });
    }

    let descendant_prefix = format!("{selected_path}/");
    let mut nested_boundaries = Vec::new();
    for exclusion in plan
        .exclusions()
        .iter()
        .filter(|exclusion| exclusion.path().starts_with(&descendant_prefix))
    {
        if exclusion.kind() == CaptureExclusionKind::NestedFolderbase {
            nested_boundaries.push(exclusion.path().to_owned());
        } else {
            return Err(FolderScopeEvidenceError::UnsupportedSelectedNode {
                path: PathBuf::from(exclusion.path()),
            });
        }
    }
    Ok(nested_boundaries)
}

fn read_journal(
    state: &FolderbaseState,
    attestation: &FolderbaseRootAttestation,
) -> Result<(Option<JournalHead>, Vec<JournalEvent>), FolderScopeEvidenceError> {
    let Some(bytes) = state.read_bounded(Path::new(HEAD_PATH), MAX_HEAD_BYTES)? else {
        return Ok((None, Vec::new()));
    };
    let head: JournalHead =
        serde_json::from_slice(&bytes).map_err(|_| FolderScopeEvidenceError::InvalidJournal {
            message: "the journal head is not a closed v1 record".to_owned(),
        })?;
    if head.format != JOURNAL_FORMAT
        || head.folderbase_id != attestation.folderbase_id
        || head.root_instance_sha256 != attestation.root_instance_sha256
        || head.device_sequence == 0
        || head.device_sequence > MAX_JOURNAL_EVENTS
        || !valid_prefixed_digest(&head.event_id, "folder_scope_event_")
        || !valid_sha256(&head.event_sha256)
    {
        return Err(FolderScopeEvidenceError::InvalidJournal {
            message: "the journal head does not bind this exact physical Folderbase Root"
                .to_owned(),
        });
    }
    let mut events = Vec::with_capacity(head.device_sequence as usize);
    let mut previous_event_sha256 = None;
    for sequence in 1..=head.device_sequence {
        let path = event_path(sequence);
        let event_bytes = state.read_bounded(&path, MAX_EVENT_BYTES)?.ok_or_else(|| {
            FolderScopeEvidenceError::InvalidJournal {
                message: format!("journal event {sequence} is missing"),
            }
        })?;
        let event_sha256 = hex_sha256(&event_bytes);
        let event: JournalEvent = serde_json::from_slice(&event_bytes).map_err(|_| {
            FolderScopeEvidenceError::InvalidJournal {
                message: format!("journal event {sequence} is not a closed v1 record"),
            }
        })?;
        if !valid_journal_event(
            &event,
            attestation,
            sequence,
            previous_event_sha256.as_deref(),
        ) {
            return Err(FolderScopeEvidenceError::InvalidJournal {
                message: format!("journal event {sequence} is not self-consistent"),
            });
        }
        if sequence == head.device_sequence
            && (event_sha256 != head.event_sha256 || event.event_id != head.event_id)
        {
            return Err(FolderScopeEvidenceError::InvalidJournal {
                message: "the journal head does not match its final event".to_owned(),
            });
        }
        previous_event_sha256 = Some(event_sha256);
        events.push(event);
    }
    Ok((Some(head), events))
}

fn valid_journal_event(
    event: &JournalEvent,
    attestation: &FolderbaseRootAttestation,
    sequence: u64,
    expected_previous_event_sha256: Option<&str>,
) -> bool {
    if event.format != EVENT_FORMAT
        || event.folderbase_id != attestation.folderbase_id
        || event.root_instance_sha256 != attestation.root_instance_sha256
        || event.device_sequence != sequence
        || event.previous_event_sha256.as_deref() != expected_previous_event_sha256
        || !valid_sha256(&event.selected_instance_sha256)
        || event
            .local_head_sha256
            .as_deref()
            .is_some_and(|value| !valid_sha256(value))
        || !valid_sha256(&event.observation_sha256)
        || !valid_prefixed_digest(&event.opaque_binding_proof, "fb_scope_binding_v1_")
        || event.opaque_binding_proof
            != binding_proof(
                &event.folderbase_id,
                &event.root_instance_sha256,
                &event.selected_instance_sha256,
            )
        || event.observation_sha256
            != observation_sha256(
                attestation,
                &event.selected_path,
                &event.selected_instance_sha256,
                event.local_head_sha256.as_deref(),
                &event.nested_boundaries,
            )
    {
        return false;
    }
    event.event_id
        == event_id(
            &event.root_instance_sha256,
            sequence,
            expected_previous_event_sha256,
            &event.observation_sha256,
        )
}

fn safe_selected_path(path: &Path) -> Result<PathBuf, FolderScopeEvidenceError> {
    if path.as_os_str().is_empty() || path.is_absolute() || path.to_str().is_none() {
        return Err(FolderScopeEvidenceError::UnsafeSelectedPath {
            path: path.to_path_buf(),
        });
    }
    let mut normalized = PathBuf::new();
    for component in path.components() {
        let Component::Normal(name) = component else {
            return Err(FolderScopeEvidenceError::UnsafeSelectedPath {
                path: path.to_path_buf(),
            });
        };
        let Some(name_text) = name.to_str() else {
            return Err(FolderScopeEvidenceError::UnsafeSelectedPath {
                path: path.to_path_buf(),
            });
        };
        if name_text.contains(['\\', '\0']) || is_reserved_workspace_component(name) {
            return Err(FolderScopeEvidenceError::UnsafeSelectedPath {
                path: path.to_path_buf(),
            });
        }
        normalized.push(name);
    }
    if normalized.as_os_str().is_empty() {
        return Err(FolderScopeEvidenceError::UnsafeSelectedPath {
            path: path.to_path_buf(),
        });
    }
    Ok(normalized)
}

fn relative_wire_path(path: &Path) -> Result<String, FolderScopeEvidenceError> {
    crate::portable_wire_path::relative_to_wire(path).map_err(|_| {
        FolderScopeEvidenceError::UnsafeSelectedPath {
            path: path.to_path_buf(),
        }
    })
}

fn selected_folder_identity(
    root: &Dir,
    display_root: &Path,
    selected_path: &Path,
) -> Result<PhysicalIdentity, FolderScopeEvidenceError> {
    let mut directory = root
        .try_clone()
        .map_err(|source| FolderbaseError::io(display_root, source))?;
    let mut display = display_root.to_path_buf();
    for component in selected_path.components() {
        let Component::Normal(name) = component else {
            return Err(FolderScopeEvidenceError::UnsafeSelectedPath {
                path: selected_path.to_path_buf(),
            });
        };
        display.push(name);
        let metadata = match directory.symlink_metadata(name) {
            Ok(metadata) => metadata,
            Err(source) if source.kind() == io::ErrorKind::NotFound => {
                return Err(FolderScopeEvidenceError::SelectedFolderNotFound {
                    path: selected_path.to_path_buf(),
                });
            }
            Err(source) => return Err(FolderbaseError::io(&display, source).into()),
        };
        if metadata.file_type().is_symlink() {
            return Err(FolderScopeEvidenceError::SelectedFolderSymlink {
                path: selected_path.to_path_buf(),
            });
        }
        if !metadata.is_dir() {
            return Err(FolderScopeEvidenceError::SelectedFolderNotDirectory {
                path: selected_path.to_path_buf(),
            });
        }
        directory = open_directory_nofollow(&directory, name, &display)?;
    }
    let file = directory
        .try_clone()
        .map_err(|source| FolderbaseError::io(&display, source))?
        .into_std_file();
    PhysicalIdentity::from_file(&file).map_err(|source| FolderbaseError::io(display, source).into())
}

#[cfg(not(windows))]
fn open_directory_nofollow(
    parent: &Dir,
    name: &OsStr,
    display: &Path,
) -> Result<Dir, FolderScopeEvidenceError> {
    parent
        .open_dir_nofollow(name)
        .map_err(|source| FolderbaseError::io(display, source).into())
}

#[cfg(windows)]
fn open_directory_nofollow(
    parent: &Dir,
    name: &OsStr,
    display: &Path,
) -> Result<Dir, FolderScopeEvidenceError> {
    use cap_std::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE,
        FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    let mut options = OpenOptions::new();
    options
        .access_mode(0)
        .follow(FollowSymlinks::No)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE);
    let file = parent
        .open_with(name, &options)
        .map_err(|source| FolderbaseError::io(display, source))?
        .into_std();
    let metadata = file
        .metadata()
        .map_err(|source| FolderbaseError::io(display, source))?;
    if metadata_is_link_or_reparse(&metadata) || !metadata.is_dir() {
        return Err(FolderScopeEvidenceError::SelectedFolderSymlink {
            path: display.to_path_buf(),
        });
    }
    Ok(Dir::from_std_file(file))
}

fn verify_attestation(
    expected: &FolderbaseRootAttestation,
) -> Result<(), FolderScopeEvidenceError> {
    let current =
        crate::attest_folderbase_root(&expected.root).map_err(FolderbaseCaptureError::from)?;
    if &current != expected {
        return Err(FolderScopeEvidenceError::ObservationChanged);
    }
    Ok(())
}

fn binding_proof(
    folderbase_id: &str,
    root_instance_sha256: &str,
    selected_instance_sha256: &str,
) -> String {
    let mut digest = Sha256::new();
    digest.update(b"folderbase-folder-scope-binding-v1\0");
    digest_field(&mut digest, folderbase_id.as_bytes());
    digest_field(&mut digest, root_instance_sha256.as_bytes());
    digest_field(&mut digest, selected_instance_sha256.as_bytes());
    format!("fb_scope_binding_v1_{:x}", digest.finalize())
}

fn observation_sha256(
    attestation: &FolderbaseRootAttestation,
    selected_path: &str,
    selected_instance_sha256: &str,
    local_head_sha256: Option<&str>,
    nested_boundaries: &[String],
) -> String {
    let mut digest = Sha256::new();
    digest.update(b"folderbase-folder-scope-observation-v1\0");
    for value in [
        attestation.folderbase_id.as_str(),
        attestation.protocol_version.as_str(),
        attestation.manifest_sha256.as_str(),
        attestation.root_instance_sha256.as_str(),
        selected_path,
        selected_instance_sha256,
    ] {
        digest_field(&mut digest, value.as_bytes());
    }
    digest_field(
        &mut digest,
        local_head_sha256.unwrap_or_default().as_bytes(),
    );
    digest.update((nested_boundaries.len() as u64).to_be_bytes());
    for boundary in nested_boundaries {
        digest_field(&mut digest, boundary.as_bytes());
    }
    format!("{:x}", digest.finalize())
}

fn event_id(
    root_instance_sha256: &str,
    sequence: u64,
    previous_event_sha256: Option<&str>,
    observation_sha256: &str,
) -> String {
    let mut digest = Sha256::new();
    digest.update(b"folderbase-folder-scope-event-id-v1\0");
    digest_field(&mut digest, root_instance_sha256.as_bytes());
    digest.update(sequence.to_be_bytes());
    digest_field(
        &mut digest,
        previous_event_sha256.unwrap_or_default().as_bytes(),
    );
    digest_field(&mut digest, observation_sha256.as_bytes());
    format!("folder_scope_event_{:x}", digest.finalize())
}

fn digest_field(digest: &mut Sha256, value: &[u8]) {
    digest.update((value.len() as u64).to_be_bytes());
    digest.update(value);
}

fn event_path(sequence: u64) -> PathBuf {
    PathBuf::from(EVENTS_DIRECTORY).join(format!("{sequence:020}.json"))
}

fn encode_bounded<T: Serialize>(
    value: &T,
    maximum_bytes: u64,
    label: &str,
) -> Result<Vec<u8>, FolderScopeEvidenceError> {
    let encoded =
        serde_json::to_vec(value).map_err(|source| FolderScopeEvidenceError::InvalidJournal {
            message: format!("{label} encoding failed: {source}"),
        })?;
    if encoded.len() as u64 > maximum_bytes {
        return Err(FolderScopeEvidenceError::InvalidJournal {
            message: format!("{label} exceeds {maximum_bytes} bytes"),
        });
    }
    Ok(encoded)
}

fn hex_sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn valid_prefixed_digest(value: &str, prefix: &str) -> bool {
    value.strip_prefix(prefix).is_some_and(valid_sha256)
}

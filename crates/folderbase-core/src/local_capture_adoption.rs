//! Bounded per-file Object claims observed under capture's existing writer lock.
//! These observations can reject a changed claim; they never authorize a write.

use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    io::Read,
    path::{Path, PathBuf},
};

use super::*;
use crate::folderbase_state::WorkspaceTarget;

const MAX_OBJECT_NAMES: usize = 16_384;
const MAX_SELECTED_VERSIONS: usize = 32_768;
const MAX_OBSERVATIONS: usize = 65_536;
const MAX_METADATA_BYTES: usize = 64 * 1024 * 1024;

pub(crate) struct CaptureObjectClaims {
    names: Vec<OsString>,
    observations: BTreeMap<PathBuf, (u64, Option<Vec<u8>>)>,
    bytes: usize,
    claims: BTreeMap<PathBuf, ObjectId>,
    adoptions: BTreeMap<PathBuf, ObjectId>,
}

impl CaptureObjectClaims {
    pub(crate) fn read(
        local: &LocalVersionStore,
        state: &FolderbaseState,
        folderbase_id: &str,
        requested: &BTreeSet<PathBuf>,
        unbound: &BTreeSet<PathBuf>,
        non_regular: &BTreeSet<PathBuf>,
        prior: Option<&crate::folderbase_version::FolderbaseVersion>,
    ) -> Result<Self> {
        state.verify_still_attached()?;
        let mut result = Self {
            names: object_names(state)?,
            observations: BTreeMap::new(),
            bytes: 0,
            claims: BTreeMap::new(),
            adoptions: BTreeMap::new(),
        };
        let folded = requested
            .iter()
            .chain(non_regular.iter())
            .filter_map(|path| path.to_str())
            .map(str::to_ascii_lowercase)
            .collect::<BTreeSet<_>>();
        let mut paths = WorkspacePathLookup::new(&local.root)?;
        let mut selected_versions = 0usize;
        let mut selected_records = Vec::new();
        for name in result.names.clone() {
            let relative = Path::new(OBJECTS_DIRECTORY).join(&name);
            if relative.extension().and_then(|value| value.to_str()) != Some("json") {
                continue;
            }
            let display = local.root.join(&relative);
            let bytes = result
                .observe(state, &relative)?
                .ok_or_else(|| invalid_record(&display, "Object claim disappeared"))?;
            let record: LocalObjectRecord = serde_json::from_slice(bytes)
                .map_err(|source| FolderbaseError::json(&display, source))?;
            record.id.validate(&display)?;
            if relative.file_stem().and_then(|value| value.to_str()) != Some(record.id.as_str()) {
                return Err(invalid_record(
                    &display,
                    "object ID does not match its filename",
                ));
            }
            let stored = safe_content_path(Path::new(&record.path))
                .map_err(|_| invalid_record(&display, "object path is not a safe relative path"))?;
            let selected = if requested.contains(&stored) || non_regular.contains(&stored) {
                Some(stored.clone())
            } else {
                resolve_object_path_claim(
                    &mut paths,
                    &stored,
                    &display,
                    stored
                        .to_str()
                        .is_some_and(|path| folded.contains(&path.to_ascii_lowercase())),
                )?
                .filter(|path| requested.contains(path))
            };
            let Some(selected) = selected else {
                continue;
            };
            selected_records.push((display, stored, selected, record));
        }
        paths.finish()?;
        let history = if let Some(prior) = prior.filter(|_| !selected_records.is_empty()) {
            let prior_path = Path::new(".folderbase/versions/folderbase")
                .join(format!("{}.json", prior.version_id()));
            let raw = result
                .observe_bounded(
                    state,
                    &prior_path,
                    crate::folderbase_version::MAX_ENCODED_VERSION_BYTES,
                )?
                .ok_or_else(|| {
                    invalid_record(&prior_path, "prior ownership Version disappeared")
                })?;
            let observed = crate::folderbase_version::FolderbaseVersion::decode_bounded(raw)
                .map_err(|error| invalid_record(&prior_path, error.to_string()))?;
            if observed
                .canonical_digest()
                .map_err(|error| invalid_record(&prior_path, error.to_string()))?
                != prior
                    .canonical_digest()
                    .map_err(|error| invalid_record(&prior_path, error.to_string()))?
            {
                return Err(invalid_record(
                    &prior_path,
                    "prior ownership Version changed",
                ));
            }
            Some(path_ownership::OwnershipHistory::load(
                observed,
                &selected_records
                    .iter()
                    .map(|(_, _, path, record)| (path.clone(), record.id.clone()))
                    .collect::<Vec<_>>(),
                true,
                None,
                |path, maximum| {
                    result
                        .observe_bounded(state, path, maximum)
                        .map(|bytes| bytes.map(<[u8]>::to_vec))
                },
            )?)
        } else {
            None
        };
        let mut paths = WorkspacePathLookup::new(&local.root)?;
        for (display, stored, selected, record) in selected_records {
            let is_historical = history
                .as_ref()
                .is_some_and(|history| history.retired(&selected, &record.id).is_some());
            let retiring_binding = prior
                .and_then(|version| {
                    version.bindings().iter().find(|binding| {
                        Path::new(binding.path()) == selected
                            && binding.object_id() == record.id.as_str()
                            && binding.kind()
                                == crate::folderbase_version::PathBindingKind::RegularFile
                    })
                })
                .filter(|_| non_regular.contains(&selected));
            let is_retiring = retiring_binding.is_some();
            if non_regular.contains(&selected) && !is_historical && !is_retiring {
                return Err(invalid_record(
                    &display,
                    "nonregular captured path has an unexplained file Object claim",
                ));
            }
            if !is_historical
                && !is_retiring
                && result
                    .claims
                    .insert(selected.clone(), record.id.clone())
                    .is_some()
            {
                return Err(invalid_record(
                    &display,
                    "multiple Object records claim a captured path",
                ));
            }
            if !unbound.contains(&selected) && !is_historical && !is_retiring {
                continue;
            }
            // Adoption never silently rewrites an alias into a new canonical claim.
            let canonical = if non_regular.contains(&selected) {
                // Exact spelling comes from the already validated capture plan.
                // The regular-file resolver cannot resolve a retired file whose
                // current path is a directory or supported symlink.
                selected.clone()
            } else {
                paths.resolve(&selected)?.1
            };
            if stored != canonical || selected != canonical {
                return Err(invalid_record(
                    &display,
                    "capture cannot adopt an aliased Object path",
                ));
            }
            if record.schema != "https://folderbase.ai/protocol/0.1/object.schema.json"
                || record.object_type != "file"
                || (record.lifecycle.status != "canonical"
                    && !(is_historical && record.lifecycle.status == "deleted"))
            {
                return Err(invalid_record(
                    &display,
                    "capture requires a canonical file Object or a proven retired deleted Object",
                ));
            }
            local.validate_object_record_membership(&record.id, &record, &display)?;
            if is_historical
                && !record.versions.iter().any(|id| {
                    Some(id.as_str())
                        == history
                            .as_ref()
                            .and_then(|history| history.retired(&selected, &record.id))
                })
            {
                return Err(invalid_record(
                    &display,
                    "historical Object claim omits its Tombstone Version",
                ));
            }
            if retiring_binding.is_some_and(|binding| {
                !record
                    .versions
                    .iter()
                    .any(|id| Some(id.as_str()) == binding.object_version_id())
            }) {
                return Err(invalid_record(
                    &display,
                    "retiring Object claim omits its prior bound Version",
                ));
            }
            selected_versions = selected_versions
                .checked_add(record.versions.len())
                .ok_or_else(|| adoption_limit("selected Version count"))?;
            if selected_versions > MAX_SELECTED_VERSIONS {
                return Err(adoption_limit("selected Version count"));
            }
            let mut seen = BTreeSet::new();
            for id in &record.versions {
                if !seen.insert(id) {
                    return Err(invalid_record(
                        &display,
                        "duplicate Version ID in adopted Object history",
                    ));
                }
                let version_path = local.version_record_relative_path(id);
                let encoded = result.observe(state, &version_path)?.ok_or_else(|| {
                    invalid_record(&version_path, "adopted Version record is missing")
                })?;
                let version: LocalVersionRecord =
                    serde_json::from_slice(encoded).map_err(|source| {
                        FolderbaseError::json(local.root.join(&version_path), source)
                    })?;
                local.validate_version_record(id, &version, &local.root.join(&version_path))?;
                if version.object_id != record.id {
                    return Err(invalid_record(
                        &version_path,
                        "adopted Version belongs to another Object",
                    ));
                }
                if id == &record.current_version {
                    // Adoption verifies the current retained bytes. Preserving historical
                    // IDs is not a new claim that every older blob remains available.
                    state.verify_sha256_blob(
                        Path::new(BLOBS_DIRECTORY),
                        &version.content.digest,
                        version.content.bytes,
                    )?;
                }
            }
            let outgoing =
                Path::new(HISTORY_TRANSFER_OUTGOING_DIRECTORY).join(format!("{}.json", record.id));
            if let Some(bytes) = result.observe(state, &outgoing)? {
                validate_chunk_transfer_receipt_bytes(
                    bytes,
                    &local.root.join(&outgoing),
                    &record.id,
                    folderbase_id,
                )?;
            }
            let incoming =
                Path::new(HISTORY_TRANSFER_INCOMING_DIRECTORY).join(format!("{}.json", record.id));
            if let Some(bytes) = result.observe(state, &incoming)? {
                let receipt: HistoryTransferReceipt = serde_json::from_slice(bytes)
                    .map_err(|source| FolderbaseError::json(local.root.join(&incoming), source))?;
                validate_history_transfer_receipt(&receipt, &incoming)?;
                if receipt.object_id != record.id
                    || receipt.destination_folderbase_id != folderbase_id
                    || !receipt
                        .version_ids
                        .iter()
                        .all(|id| record.versions.contains(id))
                {
                    return Err(invalid_record(
                        &incoming,
                        "incoming history receipt does not match adopted Object and root",
                    ));
                }
            }
            if !is_historical && !is_retiring {
                if history
                    .as_ref()
                    .is_some_and(|history| history.previously_known(&record.id))
                {
                    return Err(invalid_record(
                        &display,
                        "unbound Object identity already belongs to retained ancestry",
                    ));
                }
                result.adoptions.insert(selected, record.id);
            }
        }
        paths.finish()?;
        result.verify_unchanged(local, state)?;
        Ok(result)
    }

    /// A pending assignment alone cannot encode whether a now-absent Object
    /// projection had older standalone history. Retained Version records are
    /// an existing witness: never rebuild a shortened projection over them.
    pub(crate) fn verify_missing_replay_claims(
        &self,
        local: &LocalVersionStore,
        state: &FolderbaseState,
        candidates: &BTreeMap<ObjectId, VersionId>,
    ) -> Result<()> {
        if candidates.is_empty() {
            return Ok(());
        }
        let directory = Path::new(VERSION_RECORDS_DIRECTORY);
        let names = state.private_directory_names_if_present(directory, MAX_OBSERVATIONS)?;
        let mut total = 0usize;
        for name in names {
            let path = directory.join(name);
            if path.extension().and_then(|value| value.to_str()) != Some("json") {
                continue;
            }
            let bytes = read_claim_bytes(state, &path)?
                .ok_or_else(|| invalid_record(&path, "Version witness disappeared"))?;
            total = total
                .checked_add(bytes.len())
                .ok_or_else(|| adoption_limit("replay metadata bytes"))?;
            if total > MAX_METADATA_BYTES {
                return Err(adoption_limit("replay metadata bytes"));
            }
            let record: LocalVersionRecord = serde_json::from_slice(&bytes)
                .map_err(|source| FolderbaseError::json(local.root.join(&path), source))?;
            if candidates
                .get(&record.object_id)
                .is_some_and(|new_id| *new_id != record.id)
            {
                return Err(invalid_record(
                    local
                        .root
                        .join(OBJECTS_DIRECTORY)
                        .join(format!("{}.json", record.object_id)),
                    "pending capture lost an Object projection with retained earlier Version records",
                ));
            }
        }
        state.verify_still_attached()
    }

    pub(crate) fn adopted_id(&self, path: &str) -> Option<&ObjectId> {
        self.adoptions.get(Path::new(path))
    }

    pub(crate) fn adopted_ids(&self) -> impl Iterator<Item = (&Path, &ObjectId)> {
        self.adoptions.iter().map(|(path, id)| (path.as_path(), id))
    }

    pub(crate) fn claim_id(&self, path: &str) -> Option<&ObjectId> {
        self.claims.get(Path::new(path))
    }

    pub(crate) fn verify_unchanged(
        &self,
        local: &LocalVersionStore,
        state: &FolderbaseState,
    ) -> Result<()> {
        state.verify_still_attached()?;
        if object_names(state)? != self.names {
            return Err(invalid_record(
                local.root.join(OBJECTS_DIRECTORY),
                "Object claims changed during capture",
            ));
        }
        for (path, (maximum, bytes)) in &self.observations {
            if path_ownership::read_metadata(state, path, *maximum)? != *bytes {
                return Err(invalid_record(
                    local.root.join(path),
                    "Object adoption metadata changed during capture",
                ));
            }
        }
        let mut paths = WorkspacePathLookup::new(&local.root)?;
        for path in self.adoptions.keys() {
            let (_, canonical) = paths.resolve(path)?;
            if canonical != *path {
                return Err(invalid_record(
                    local.root.join(path),
                    "adopted file path changed during capture",
                ));
            }
        }
        paths.finish()?;
        state.verify_still_attached()
    }

    fn observe<'a>(&'a mut self, state: &FolderbaseState, path: &Path) -> Result<Option<&'a [u8]>> {
        self.observe_bounded(state, path, MAX_CAPTURE_PROJECTION_RECORD_BYTES)
    }

    fn observe_bounded<'a>(
        &'a mut self,
        state: &FolderbaseState,
        path: &Path,
        maximum: u64,
    ) -> Result<Option<&'a [u8]>> {
        if !self.observations.contains_key(path) {
            if self.observations.len() >= MAX_OBSERVATIONS {
                return Err(adoption_limit("metadata record count"));
            }
            let bytes = path_ownership::read_metadata(state, path, maximum)?;
            self.bytes = self
                .bytes
                .checked_add(bytes.as_ref().map_or(0, Vec::len))
                .ok_or_else(|| adoption_limit("aggregate metadata bytes"))?;
            if self.bytes > MAX_METADATA_BYTES {
                return Err(adoption_limit("aggregate metadata bytes"));
            }
            self.observations
                .insert(path.to_path_buf(), (maximum, bytes));
        }
        Ok(self
            .observations
            .get(path)
            .expect("observed path")
            .1
            .as_deref())
    }
}

fn object_names(state: &FolderbaseState) -> Result<Vec<OsString>> {
    let mut names =
        state.private_directory_names_if_present(Path::new(OBJECTS_DIRECTORY), MAX_OBJECT_NAMES)?;
    names.sort();
    Ok(names)
}

fn adoption_limit(name: &str) -> FolderbaseError {
    invalid_record(
        Path::new(OBJECTS_DIRECTORY),
        format!("capture Object adoption exceeds bounded {name}"),
    )
}

fn read_claim_bytes(state: &FolderbaseState, path: &Path) -> Result<Option<Vec<u8>>> {
    let file = match state.open_private_target_nofollow(path)? {
        WorkspaceTarget::Absent => return Ok(None),
        WorkspaceTarget::Directory(_) => {
            return Err(invalid_record(
                path,
                "capture metadata is not a regular file",
            ));
        }
        WorkspaceTarget::RegularFile(file) => file,
    };
    if file
        .metadata()
        .map_err(|source| FolderbaseError::io(path, source))?
        .len()
        > MAX_CAPTURE_PROJECTION_RECORD_BYTES
    {
        return Err(adoption_limit("record bytes"));
    }
    let mut bytes = Vec::new();
    file.take(MAX_CAPTURE_PROJECTION_RECORD_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| FolderbaseError::io(path, source))?;
    if bytes.len() as u64 > MAX_CAPTURE_PROJECTION_RECORD_BYTES {
        return Err(adoption_limit("record bytes"));
    }
    Ok(Some(bytes))
}

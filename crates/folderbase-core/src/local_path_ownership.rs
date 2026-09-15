//! A same-path recreation owns a new Object; its Tombstone retains the old one.
//! This metadata proof never captures, repairs, or merges distinct histories.

use super::*;
use crate::folderbase_version::{FolderbaseVersion, PathBindingKind};

const MAX_ANCESTOR_VERSIONS: usize = 1024;
const MAX_ANCESTOR_BYTES: usize = 64 * 1024 * 1024;

/// Only a separately verified, root-attested completed export receipt may
/// provide this proof. It applies at the exact encountered Version/digest.
pub(crate) struct OwnershipAnchor {
    pub(crate) version_id: String,
    pub(crate) version_sha256: String,
    pub(crate) retired: Vec<RetiredObjectClaim>,
}

pub(crate) struct RetiredObjectClaim {
    pub(crate) path: PathBuf,
    pub(crate) object_id: ObjectId,
    pub(crate) last_version_id: VersionId,
}

pub(super) struct OwnershipHistory {
    pub(super) current: FolderbaseVersion,
    ancestors: Vec<FolderbaseVersion>,
    anchored: Vec<RetiredObjectClaim>,
}

impl OwnershipHistory {
    pub(super) fn load<E: From<FolderbaseError>>(
        current: FolderbaseVersion,
        candidates: &[(PathBuf, ObjectId)],
        allow_new: bool,
        anchor: Option<&OwnershipAnchor>,
        mut read: impl FnMut(&Path, u64) -> std::result::Result<Option<Vec<u8>>, E>,
    ) -> std::result::Result<Self, E> {
        let mut result = Self {
            current,
            ancestors: Vec::new(),
            anchored: Vec::new(),
        };
        let unresolved = |history: &Self| {
            candidates.iter().any(|(path, id)| {
                !history.current.bindings().iter().any(|binding| {
                    Path::new(binding.path()) == path && binding.object_id() == id.as_str()
                }) && history.retired(path, id).is_none()
            })
        };
        if !unresolved(&result) {
            return Ok(result);
        }
        let invalid = |message: &str| invalid_record(".folderbase/versions/folderbase", message);
        let mut pending =
            std::collections::VecDeque::from([result.current.version_id().to_owned()]);
        let mut graph = BTreeMap::<String, Vec<String>>::new();
        let mut bytes_read = 0usize;
        while let Some(id) = pending.pop_front() {
            if graph.contains_key(&id) {
                continue;
            }
            if graph.len() >= MAX_ANCESTOR_VERSIONS {
                return Err(invalid("Object ownership ancestry exceeds 1024 Versions").into());
            }
            let version = if id == result.current.version_id() {
                &result.current
            } else {
                let path = Path::new(".folderbase/versions/folderbase").join(format!("{id}.json"));
                let bytes = read(&path, crate::folderbase_version::MAX_ENCODED_VERSION_BYTES)?
                    .ok_or_else(|| invalid("Object ownership ancestor is missing"))?;
                bytes_read = bytes_read
                    .checked_add(bytes.len())
                    .ok_or_else(|| invalid("Object ownership ancestry byte limit"))?;
                if bytes_read > MAX_ANCESTOR_BYTES {
                    return Err(invalid("Object ownership ancestry exceeds 64 MiB").into());
                }
                let version = FolderbaseVersion::decode_bounded(bytes.as_slice())
                    .map_err(|error| invalid(&error.to_string()))?;
                if version.version_id() != id
                    || version.folderbase_id() != result.current.folderbase_id()
                {
                    return Err(invalid(
                        "Object ownership ancestor ID or root membership is invalid",
                    )
                    .into());
                }
                result.ancestors.push(version);
                result.ancestors.last().expect("loaded ancestor")
            };
            let anchored = if let Some(anchor) = anchor.filter(|anchor| anchor.version_id == id) {
                if version
                    .canonical_digest()
                    .map_err(|error| invalid(&error.to_string()))?
                    != anchor.version_sha256
                {
                    return Err(invalid("Object ownership export anchor digest disagrees").into());
                }
                if anchor.retired.len() > crate::folderbase_version::MAX_VERSION_ENTRIES {
                    return Err(
                        invalid("Object ownership anchor exceeds retired claim limit").into(),
                    );
                }
                let mut prior = None;
                for claim in &anchor.retired {
                    safe_content_path(&claim.path)?;
                    claim.object_id.validate(&claim.path)?;
                    claim.last_version_id.validate(&claim.path)?;
                    let key = (&claim.path, &claim.object_id);
                    if prior.is_some_and(|previous| previous >= key) {
                        return Err(invalid(
                            "Object ownership anchor claims are not unique and sorted",
                        )
                        .into());
                    }
                    prior = Some(key);
                    result.anchored.push(RetiredObjectClaim {
                        path: claim.path.clone(),
                        object_id: claim.object_id.clone(),
                        last_version_id: claim.last_version_id.clone(),
                    });
                }
                true
            } else {
                false
            };
            let parents = if anchored {
                Vec::new()
            } else {
                version.parents().to_vec()
            };
            pending.extend(parents.iter().cloned());
            graph.insert(id, parents);
            ensure_observed_acyclic(&graph)?;
            if !unresolved(&result) {
                break;
            }
        }
        if !allow_new && unresolved(&result) {
            return Err(invalid(
                "multiple object records claim path without retired ancestry proof",
            )
            .into());
        }
        Ok(result)
    }

    pub(super) fn retired(&self, path: &Path, id: &ObjectId) -> Option<&str> {
        if self
            .current
            .bindings()
            .iter()
            .any(|binding| Path::new(binding.path()) == path && binding.object_id() == id.as_str())
        {
            return None;
        }
        std::iter::once(&self.current)
            .chain(&self.ancestors)
            .find_map(|version| {
                version
                    .tombstones()
                    .iter()
                    .find(|tombstone| {
                        Path::new(tombstone.path()) == path && tombstone.object_id() == id.as_str()
                    })
                    .and_then(|tombstone| tombstone.last_object_version_id())
            })
            .or_else(|| {
                self.anchored
                    .iter()
                    .find(|claim| claim.path == path && claim.object_id == *id)
                    .map(|claim| claim.last_version_id.as_str())
            })
    }

    pub(super) fn previously_known(&self, id: &ObjectId) -> bool {
        std::iter::once(&self.current)
            .chain(&self.ancestors)
            .any(|version| {
                version
                    .bindings()
                    .iter()
                    .any(|binding| binding.object_id() == id.as_str())
                    || version
                        .tombstones()
                        .iter()
                        .any(|tombstone| tombstone.object_id() == id.as_str())
            })
            || self.anchored.iter().any(|claim| claim.object_id == *id)
    }
}

fn ensure_observed_acyclic(graph: &BTreeMap<String, Vec<String>>) -> Result<()> {
    let mut degrees = graph
        .keys()
        .map(|key| (key, 0usize))
        .collect::<BTreeMap<_, _>>();
    for parents in graph.values() {
        for parent in parents {
            if let Some(degree) = degrees.get_mut(parent) {
                *degree += 1;
            }
        }
    }
    let mut ready = degrees
        .iter()
        .filter(|(_, degree)| **degree == 0)
        .map(|(id, _)| *id)
        .collect::<Vec<_>>();
    let mut removed = 0;
    while let Some(id) = ready.pop() {
        removed += 1;
        for parent in &graph[id] {
            if let Some(degree) = degrees.get_mut(parent) {
                *degree -= 1;
                if *degree == 0 {
                    ready.push(parent);
                }
            }
        }
    }
    if removed != graph.len() {
        return Err(invalid_record(
            ".folderbase/versions/folderbase",
            "Object ownership ancestry contains a cycle",
        ));
    }
    Ok(())
}

pub(super) fn current_version<E: From<FolderbaseError>>(
    root: &Path,
    state: &FolderbaseState,
    mut read: impl FnMut(&Path, u64) -> std::result::Result<Option<Vec<u8>>, E>,
) -> std::result::Result<FolderbaseVersion, E> {
    let invalid = |message: &str| invalid_record(root, message);
    let head_path = Path::new(".folderbase/local/head.json");
    let encoded = read(head_path, crate::MAX_LOCAL_HEAD_BYTES)?
        .ok_or_else(|| invalid("duplicate Object claims have no current Folderbase Version"))?;
    let root_cap = state.clone_root_capability()?;
    let (attestation, authority, _) =
        crate::root_attestation::attest_retained_folderbase_root_with_profile(&root_cap, root)
            .map_err(|error| invalid(&format!("invalid Object ownership root: {error}")))?;
    let manifest = read(
        Path::new(".folderbase/manifest.json"),
        crate::root_attestation::MAX_FOLDERBASE_MANIFEST_BYTES,
    )?
    .ok_or_else(|| invalid("Object ownership manifest disappeared"))?;
    if format!("{:x}", Sha256::digest(&manifest)) != attestation.manifest_sha256 {
        return Err(invalid("Object ownership manifest changed").into());
    }
    let head = crate::folderbase_capture::read_local_head(&attestation, &authority, &root_cap)
        .map_err(|error| invalid(&format!("invalid Object ownership Head: {error}")))?
        .ok_or_else(|| invalid("Object ownership Head disappeared"))?;
    if format!("{:x}", Sha256::digest(&encoded)) != head.encoded_sha256() {
        return Err(invalid("Object ownership Head changed").into());
    }
    let path =
        Path::new(".folderbase/versions/folderbase").join(format!("{}.json", head.version_id()));
    let bytes = read(&path, crate::folderbase_version::MAX_ENCODED_VERSION_BYTES)?
        .ok_or_else(|| invalid("Object ownership Folderbase Version is missing"))?;
    let version = FolderbaseVersion::decode_bounded(bytes.as_slice())
        .map_err(|error| invalid(&format!("invalid Object ownership Version: {error}")))?;
    if version.version_id() != head.version_id()
        || version.folderbase_id() != attestation.folderbase_id
        || version
            .canonical_digest()
            .map_err(|error| invalid(&error.to_string()))?
            != head.version_sha256()
    {
        return Err(invalid("Object ownership Version does not match the attested Head").into());
    }
    state.verify_still_attached()?;
    Ok(version)
}

pub(super) fn select<'a>(
    path: &Path,
    candidates: &[(&'a Path, &'a LocalObjectRecord)],
    history: &OwnershipHistory,
) -> Result<(&'a Path, &'a LocalObjectRecord)> {
    let invalid = || {
        invalid_record(
            path,
            "multiple object records claim path without proven live and Tombstone ownership",
        )
    };
    let binding = history
        .current
        .bindings()
        .iter()
        .find(|binding| Path::new(binding.path()) == path)
        .filter(|binding| binding.kind() == PathBindingKind::RegularFile)
        .ok_or_else(invalid)?;
    let mut live = None;
    for (record_path, object) in candidates {
        // A case alias or malformed historical claim cannot disappear merely
        // because a full Version also contains a same-path Tombstone.
        if record_path.file_stem().and_then(|name| name.to_str()) != Some(object.id.as_str())
            || Path::new(&object.path) != path
            || object.schema != OBJECT_SCHEMA
            || object.object_type != "file"
            || object.lifecycle.status != "canonical"
            || object.versions.is_empty()
            || !object.versions.contains(&object.current_version)
        {
            return Err(invalid());
        }
        let mut ids = std::collections::BTreeSet::new();
        for id in &object.versions {
            id.validate(record_path)?;
            if !ids.insert(id) {
                return Err(invalid());
            }
        }
        if object.id.as_str() == binding.object_id() {
            if live.replace((*record_path, *object)).is_some()
                || !object
                    .versions
                    .iter()
                    .any(|id| Some(id.as_str()) == binding.object_version_id())
            {
                return Err(invalid());
            }
        } else if !history
            .retired(path, &object.id)
            .is_some_and(|last| object.versions.iter().any(|id| id.as_str() == last))
        {
            return Err(invalid());
        }
    }
    live.ok_or_else(invalid)
}

pub(super) fn verify_references<E: From<FolderbaseError>>(
    root: &Path,
    path: &Path,
    candidates: &[(&Path, &LocalObjectRecord)],
    history: &OwnershipHistory,
    mut read: impl FnMut(&Path, u64) -> std::result::Result<Option<Vec<u8>>, E>,
) -> std::result::Result<(), E> {
    let local = LocalVersionStore::for_retained_root(root);
    for (_, object) in candidates {
        let binding = history.current.bindings().iter().find(|binding| {
            Path::new(binding.path()) == path && binding.object_id() == object.id.as_str()
        });
        let id = binding
            .and_then(|binding| binding.object_version_id())
            .or_else(|| history.retired(path, &object.id))
            .ok_or_else(|| invalid_record(path, "Object claim has no bound Version metadata"))?;
        let id = VersionId::parse(id.to_owned())?;
        let relative = local.version_record_relative_path(&id);
        let bytes = read(&relative, MAX_CAPTURE_PROJECTION_RECORD_BYTES)?.ok_or_else(|| {
            invalid_record(&relative, "Object ownership Version record is missing")
        })?;
        let record: LocalVersionRecord = serde_json::from_slice(&bytes)
            .map_err(|error| FolderbaseError::json(root.join(&relative), error))?;
        local.validate_version_record(&id, &record, &root.join(&relative))?;
        if record.object_id != object.id
            || binding.is_some_and(|binding| {
                binding.content_sha256() != Some(record.content.digest.as_str())
                    || binding.bytes() != Some(record.content.bytes)
            })
        {
            return Err(invalid_record(
                &relative,
                "Object ownership Version metadata disagrees with its binding",
            )
            .into());
        }
    }
    Ok(())
}

pub(super) fn read_metadata(
    state: &FolderbaseState,
    path: &Path,
    maximum: u64,
) -> Result<Option<Vec<u8>>> {
    let file = match state.open_private_target_nofollow(path)? {
        crate::folderbase_state::WorkspaceTarget::Absent => return Ok(None),
        crate::folderbase_state::WorkspaceTarget::Directory(_) => {
            return Err(invalid_record(
                path,
                "Object ownership metadata is not a regular file",
            ));
        }
        crate::folderbase_state::WorkspaceTarget::RegularFile(file) => file,
    };
    if file
        .metadata()
        .map_err(|error| FolderbaseError::io(path, error))?
        .len()
        > maximum
    {
        return Err(invalid_record(
            path,
            "Object ownership metadata exceeds its byte bound",
        ));
    }
    let mut bytes = Vec::new();
    file.take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| FolderbaseError::io(path, error))?;
    if bytes.len() as u64 > maximum {
        return Err(invalid_record(
            path,
            "Object ownership metadata exceeds its byte bound",
        ));
    }
    Ok(Some(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wire(id: &str, parents: &[String], retired: Option<(&ObjectId, &VersionId)>) -> Vec<u8> {
        let mut value: Value = serde_json::from_slice(include_bytes!(
            "../../../protocol/conformance/folderbase-version-0.5/valid/minimal-ordinary-v1.json"
        ))
        .unwrap();
        value["version_id"] = serde_json::json!(id);
        value["parents"] = serde_json::json!(parents);
        if let Some((object, version)) = retired {
            value["tombstones"] = serde_json::json!([{"path":"task.json","object_id":object,"lifecycle":"deleted","deleted_kind":"regular_file","last_object_version_id":version}]);
        }
        serde_json::to_vec(&value).unwrap()
    }

    fn decode(bytes: &[u8]) -> FolderbaseVersion {
        FolderbaseVersion::decode_bounded(bytes).unwrap()
    }
    fn id() -> String {
        format!("fbversion_{}", Uuid::now_v7())
    }

    #[test]
    fn sufficient_current_witness_never_opens_omitted_ancestors() {
        let object = ObjectId::new();
        let version = VersionId::new();
        let current = decode(&wire(&id(), &[id()], Some((&object, &version))));
        let history = OwnershipHistory::load::<FolderbaseError>(
            current,
            &[("task.json".into(), object.clone())],
            false,
            None,
            |_, _| panic!("already proven without ancestry"),
        )
        .unwrap();
        assert_eq!(
            history.retired(Path::new("task.json"), &object),
            Some(version.as_str())
        );
    }

    #[test]
    fn ancestor_proof_stops_when_sufficient_and_missing_cycles_or_wrong_membership_refuse() {
        let object = ObjectId::new();
        let version = VersionId::new();
        let current_id = id();
        let parent_id = id();
        let candidate = [(PathBuf::from("task.json"), object.clone())];
        let current = wire(&current_id, std::slice::from_ref(&parent_id), None);
        let parent = wire(&parent_id, &[id()], Some((&object, &version)));
        let mut reads = 0;
        let history = OwnershipHistory::load::<FolderbaseError>(
            decode(&current),
            &candidate,
            false,
            None,
            |path, _| {
                reads += 1;
                assert_eq!(path.file_stem().unwrap(), parent_id.as_str());
                Ok(Some(parent.clone()))
            },
        )
        .unwrap();
        assert_eq!(reads, 1);
        assert!(history.previously_known(&object));
        for damage in ["missing", "cycle", "wrong-id", "wrong-root"] {
            let result = OwnershipHistory::load::<FolderbaseError>(
                decode(&current),
                &candidate,
                false,
                None,
                |_, _| {
                    if damage == "missing" {
                        return Ok(None);
                    }
                    let bytes = wire(
                        if damage == "wrong-id" {
                            &current_id
                        } else {
                            &parent_id
                        },
                        std::slice::from_ref(&current_id),
                        None,
                    );
                    let mut value: Value = serde_json::from_slice(&bytes).unwrap();
                    if damage == "wrong-root" {
                        value["folderbase_id"] =
                            serde_json::json!(format!("folderbase_{}", Uuid::now_v7()));
                    }
                    Ok(Some(serde_json::to_vec(&value).unwrap()))
                },
            );
            assert!(result.is_err(), "{damage}");
        }
    }

    #[test]
    fn ancestry_version_limit_fails_before_an_unbounded_walk() {
        let object = ObjectId::new();
        let ids = (0..MAX_ANCESTOR_VERSIONS + 2)
            .map(|_| id())
            .collect::<Vec<_>>();
        let current = decode(&wire(&ids[0], std::slice::from_ref(&ids[1]), None));
        let mut reads = 0;
        let result = OwnershipHistory::load::<FolderbaseError>(
            current,
            &[("task.json".into(), object)],
            true,
            None,
            |_, _| {
                reads += 1;
                Ok(Some(wire(
                    &ids[reads],
                    std::slice::from_ref(&ids[reads + 1]),
                    None,
                )))
            },
        );
        assert!(result.err().unwrap().to_string().contains("1024"));
        assert_eq!(reads, MAX_ANCESTOR_VERSIONS - 1);
    }

    #[test]
    fn trusted_anchor_must_be_encountered_with_exact_digest_before_it_can_end_search() {
        let object = ObjectId::new();
        let version = VersionId::new();
        let current_id = id();
        let omitted_parent = id();
        let bytes = wire(&current_id, &[omitted_parent], None);
        let digest = decode(&bytes).canonical_digest().unwrap();
        for mode in ["exact", "wrong-digest", "unencountered"] {
            // This fixture supplies a preverified proof to the private seam;
            // the export module must independently validate the real receipt.
            let anchor = OwnershipAnchor {
                version_id: if mode == "unencountered" {
                    id()
                } else {
                    current_id.clone()
                },
                version_sha256: if mode == "wrong-digest" {
                    "0".repeat(64)
                } else {
                    digest.clone()
                },
                retired: vec![RetiredObjectClaim {
                    path: "task.json".into(),
                    object_id: object.clone(),
                    last_version_id: version.clone(),
                }],
            };
            let mut reads = 0;
            let result = OwnershipHistory::load::<FolderbaseError>(
                decode(&bytes),
                &[("task.json".into(), object.clone())],
                false,
                Some(&anchor),
                |_, _| {
                    reads += 1;
                    Ok(None)
                },
            );
            assert_eq!(result.is_ok(), mode == "exact", "{mode}");
            assert_eq!(reads, usize::from(mode == "unencountered"));
        }
    }
}

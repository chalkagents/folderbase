//! Canonical, provider-neutral full state for one Folderbase boundary.
//!
//! A Folderbase Version is a bounded data artifact. This module deliberately
//! does not capture filesystem state, resolve Cloud authority, or persist a
//! Local Head.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::{self, Write as _},
    io::{Read, Write},
    marker::PhantomData,
};

use chrono::{DateTime, SecondsFormat, Utc};
use serde::{
    Deserialize, Serialize,
    de::{IgnoredAny, SeqAccess, Visitor},
};
use sha2::{Digest, Sha256};
use unicode_casefold::UnicodeCaseFold;
use unicode_normalization::UnicodeNormalization;
use uuid::Uuid;

pub const VERSION_FORMAT_V1: &str = "folderbase-version-v1";
pub const PATH_POLICY_FORMAT_V1: &str = "folderbase-portable-path-v1";
pub const MAX_ENCODED_VERSION_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_VERSION_ENTRIES: usize = 16_384;
pub const MAX_OBJECT_BYTES: u64 = 1024 * 1024 * 1024 * 1024;
pub const MAX_ROOT_MANIFEST_BYTES: u64 = 16 * 1024 * 1024;
pub const MAX_PATH_BYTES: usize = 4_096;
pub const MAX_PATH_COMPONENT_BYTES: usize = 255;
pub const MAX_PATH_DEPTH: usize = 128;

#[derive(Debug)]
pub struct FolderbaseVersion {
    format: String,
    protocol_version: String,
    folderbase_id: String,
    version_id: String,
    parents: Vec<String>,
    created_at: String,
    path_policy: PathPolicy,
    root_manifest: RootManifest,
    bindings: Vec<PathBinding>,
    tombstones: Vec<Tombstone>,
    exclusions: Vec<Exclusion>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FolderbaseVersionWire {
    format: String,
    protocol_version: String,
    folderbase_id: String,
    version_id: String,
    parents: Vec<String>,
    created_at: String,
    path_policy: PathPolicy,
    root_manifest: RootManifest,
    #[serde(deserialize_with = "deserialize_bounded_bindings")]
    bindings: Vec<PathBinding>,
    #[serde(deserialize_with = "deserialize_bounded_tombstones")]
    tombstones: Vec<Tombstone>,
    #[serde(deserialize_with = "deserialize_bounded_exclusions")]
    exclusions: Vec<Exclusion>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PathPolicy {
    format: String,
    normalization: String,
    normalization_unicode_version: String,
    case_folding: String,
    case_folding_unicode_version: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RootManifest {
    path: String,
    object_version_id: String,
    content_sha256: String,
    bytes: ExactU64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathBindingKind {
    Directory,
    RegularFile,
    Symlink,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum PathBinding {
    Directory(DirectoryBinding),
    RegularFile(RegularFileBinding),
    Symlink(SymlinkBinding),
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DirectoryBinding {
    path: String,
    object_id: String,
    lifecycle: LiveLifecycle,
    kind: DirectoryKind,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RegularFileBinding {
    path: String,
    object_id: String,
    lifecycle: LiveLifecycle,
    kind: RegularFileKind,
    object_version_id: String,
    content_sha256: String,
    bytes: ExactU64,
    executable: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SymlinkBinding {
    path: String,
    object_id: String,
    lifecycle: LiveLifecycle,
    kind: SymlinkKind,
    object_version_id: String,
    target: String,
    target_safety: SymlinkTargetSafety,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum DirectoryKind {
    Directory,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum RegularFileKind {
    RegularFile,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum SymlinkKind {
    Symlink,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum LiveLifecycle {
    Live,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum SymlinkTargetSafety {
    RelativeWithinFolderbase,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Tombstone {
    path: String,
    object_id: String,
    lifecycle: DeletedLifecycle,
    deleted_kind: DeletedKind,
    last_object_version_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum DeletedLifecycle {
    Deleted,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DeletedKind {
    Directory,
    RegularFile,
    Symlink,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Exclusion {
    path: String,
    kind: ExclusionKind,
    reason: ExclusionReason,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExclusionKind {
    NestedFolderbase,
    HardLink,
    Fifo,
    Socket,
    BlockDevice,
    CharacterDevice,
    OtherSpecial,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ExclusionReason {
    NestedFolderbaseBoundary,
    UnsupportedV1,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FolderbaseVersionDiff {
    changes: Vec<FolderbaseVersionChange>,
}

impl FolderbaseVersionDiff {
    pub fn changes(&self) -> &[FolderbaseVersionChange] {
        &self.changes
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FolderbaseVersionChange {
    RootManifestUpdated {
        previous_object_version_id: String,
        object_version_id: String,
        previous_content_sha256: String,
        content_sha256: String,
    },
    Added {
        path: String,
        object_id: String,
    },
    Deleted {
        path: String,
        object_id: String,
        tombstone_present: bool,
    },
    Moved {
        object_id: String,
        from_path: String,
        to_path: String,
    },
    Recreated {
        path: String,
        previous_object_id: String,
        object_id: String,
    },
    Updated {
        path: String,
        object_id: String,
        previous_object_version_id: Option<String>,
        object_version_id: Option<String>,
    },
    TombstoneAdded {
        path: String,
        object_id: String,
    },
    TombstoneRemoved {
        path: String,
        object_id: String,
    },
    ExclusionAdded {
        path: String,
        kind: ExclusionKind,
    },
    ExclusionRemoved {
        path: String,
        kind: ExclusionKind,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum FolderbaseVersionError {
    #[error("encoded Folderbase Version exceeds {maximum_bytes} bytes")]
    EncodedVersionTooLarge { maximum_bytes: u64 },

    #[error("Folderbase Version is not valid JSON: {0}")]
    InvalidJson(#[from] serde_json::Error),

    #[error("could not write encoded Folderbase Version: {0}")]
    EncodingIo(#[source] std::io::Error),

    #[error("Folderbase Version violates the protocol: {0}")]
    InvalidVersion(String),
}

impl FolderbaseVersion {
    pub fn decode_bounded(mut reader: impl Read) -> Result<Self, FolderbaseVersionError> {
        let mut encoded = Vec::new();
        reader
            .by_ref()
            .take(MAX_ENCODED_VERSION_BYTES + 1)
            .read_to_end(&mut encoded)
            .map_err(serde_json::Error::io)?;
        if encoded.len() as u64 > MAX_ENCODED_VERSION_BYTES {
            return Err(FolderbaseVersionError::EncodedVersionTooLarge {
                maximum_bytes: MAX_ENCODED_VERSION_BYTES,
            });
        }
        Self::decode_verified_slice(&encoded)
    }

    /// Encode one already-validated Folderbase Version as bounded JSON.
    ///
    /// The public value intentionally does not implement `Serialize`; this
    /// method is the only supported JSON encoding path.
    pub fn encode_bounded(&self, mut writer: impl Write) -> Result<(), FolderbaseVersionError> {
        self.validate()?;
        let encoded = serde_json::to_vec(&FolderbaseVersionWireRef::from(self))?;
        if encoded.len() as u64 > MAX_ENCODED_VERSION_BYTES {
            return Err(FolderbaseVersionError::EncodedVersionTooLarge {
                maximum_bytes: MAX_ENCODED_VERSION_BYTES,
            });
        }
        writer
            .write_all(&encoded)
            .map_err(FolderbaseVersionError::EncodingIo)
    }

    /// Construct a validated value from a bounded in-memory representation.
    ///
    /// This crate-private seam is reserved for later producer transactions;
    /// external callers continue to use `decode_bounded`.
    pub(crate) fn decode_verified_slice(encoded: &[u8]) -> Result<Self, FolderbaseVersionError> {
        if encoded.len() as u64 > MAX_ENCODED_VERSION_BYTES {
            return Err(FolderbaseVersionError::EncodedVersionTooLarge {
                maximum_bytes: MAX_ENCODED_VERSION_BYTES,
            });
        }
        let counts: EntryCountProbe = serde_json::from_slice(encoded)?;
        if counts.total() > MAX_VERSION_ENTRIES {
            return invalid("Folderbase Version entry count exceeds the v1 limit");
        }
        let version = Self::from(serde_json::from_slice::<FolderbaseVersionWire>(encoded)?);
        version.validate()?;
        Ok(version)
    }

    pub fn validate(&self) -> Result<(), FolderbaseVersionError> {
        if self.format != VERSION_FORMAT_V1 || self.protocol_version != "0.4" {
            return invalid("unsupported Folderbase Version format or protocol");
        }
        validate_prefixed_uuid(&self.folderbase_id, "folderbase_")?;
        validate_prefixed_uuid(&self.version_id, "fbversion_")?;
        if self.parents.len() > 2 {
            return invalid("a Folderbase Version has at most two parents");
        }
        for parent in &self.parents {
            validate_prefixed_uuid(parent, "fbversion_")?;
            if parent == &self.version_id {
                return invalid("a Folderbase Version cannot be its own parent");
            }
        }
        if self.parents.len() == 2 && self.parents[0] == self.parents[1] {
            return invalid("Folderbase Version parents must be unique");
        }
        let parsed = DateTime::parse_from_rfc3339(&self.created_at)
            .map_err(|_| invalid_error("created_at must be canonical UTC RFC 3339 seconds"))?;
        if parsed.offset().local_minus_utc() != 0
            || parsed
                .with_timezone(&Utc)
                .to_rfc3339_opts(SecondsFormat::Secs, true)
                != self.created_at
        {
            return invalid("created_at must be canonical UTC RFC 3339 seconds");
        }
        if self.path_policy.format != PATH_POLICY_FORMAT_V1
            || self.path_policy.normalization != "NFC"
            || self.path_policy.normalization_unicode_version != "17.0.0"
            || self.path_policy.case_folding != "full-default"
            || self.path_policy.case_folding_unicode_version != "9.0.0"
        {
            return invalid("unsupported portable path policy");
        }
        if unicode_normalization::UNICODE_VERSION != (17, 0, 0)
            || unicode_casefold::UNICODE_VERSION != (9, 0, 0)
        {
            return invalid("Core build does not provide the declared Unicode path tables");
        }
        if self.root_manifest.path != ".folderbase/manifest.json" {
            return invalid("root_manifest must name the exact reserved manifest path");
        }
        validate_prefixed_uuid(&self.root_manifest.object_version_id, "version_")?;
        validate_sha256(&self.root_manifest.content_sha256)?;
        if self.root_manifest.bytes.0 == 0 || self.root_manifest.bytes.0 > MAX_ROOT_MANIFEST_BYTES {
            return invalid("root_manifest byte length is outside the v1 limit");
        }
        let total = self
            .bindings
            .len()
            .saturating_add(self.tombstones.len())
            .saturating_add(self.exclusions.len());
        if total > MAX_VERSION_ENTRIES {
            return invalid("Folderbase Version entry count exceeds the v1 limit");
        }

        validate_strict_path_order(self.bindings.iter().map(PathBinding::path), "bindings")?;
        validate_strict_path_order(
            self.tombstones
                .iter()
                .map(|tombstone| tombstone.path.as_str()),
            "tombstones",
        )?;
        validate_strict_path_order(
            self.exclusions
                .iter()
                .map(|exclusion| exclusion.path.as_str()),
            "exclusions",
        )?;

        let mut current_paths = CollisionIndex::default();
        let mut live_object_ids = BTreeSet::new();
        let mut object_version_owners = BTreeMap::new();
        object_version_owners.insert(
            self.root_manifest.object_version_id.as_str(),
            "__folderbase_root_manifest__",
        );
        for binding in &self.bindings {
            let keys = validate_portable_path(binding.path())?;
            current_paths.insert(binding.path(), keys, Some(binding.object_id()))?;
            validate_prefixed_uuid(binding.object_id(), "obj_")?;
            if !live_object_ids.insert(binding.object_id()) {
                return invalid("one live Object ID is bound to more than one path");
            }
            match binding {
                PathBinding::Directory(binding) => {
                    let _ = (&binding.lifecycle, &binding.kind);
                }
                PathBinding::RegularFile(binding) => {
                    let _ = (&binding.lifecycle, &binding.kind);
                    validate_prefixed_uuid(&binding.object_version_id, "version_")?;
                    bind_object_version(
                        &mut object_version_owners,
                        &binding.object_version_id,
                        &binding.object_id,
                    )?;
                    validate_sha256(&binding.content_sha256)?;
                    if binding.bytes.0 > MAX_OBJECT_BYTES {
                        return invalid("regular file exceeds the v1 object-size limit");
                    }
                }
                PathBinding::Symlink(binding) => {
                    let _ = (&binding.lifecycle, &binding.kind, &binding.target_safety);
                    validate_prefixed_uuid(&binding.object_version_id, "version_")?;
                    bind_object_version(
                        &mut object_version_owners,
                        &binding.object_version_id,
                        &binding.object_id,
                    )?;
                }
            }
        }
        for required_path in [".folderbaseignore", "FOLDERBASE.md"] {
            if !self.bindings.iter().any(|binding| {
                binding.path() == required_path && matches!(binding, PathBinding::RegularFile(_))
            }) {
                return invalid(format!(
                    "{required_path} must be a live regular-file Path Binding"
                ));
            }
        }

        for exclusion in &self.exclusions {
            let keys = validate_portable_path(&exclusion.path)?;
            current_paths.insert(&exclusion.path, keys, None)?;
            match (exclusion.kind, exclusion.reason) {
                (ExclusionKind::NestedFolderbase, ExclusionReason::NestedFolderbaseBoundary)
                | (
                    ExclusionKind::HardLink
                    | ExclusionKind::Fifo
                    | ExclusionKind::Socket
                    | ExclusionKind::BlockDevice
                    | ExclusionKind::CharacterDevice
                    | ExclusionKind::OtherSpecial,
                    ExclusionReason::UnsupportedV1,
                ) => {}
                _ => return invalid("exclusion kind and reason do not match"),
            }
        }

        let mut tombstone_paths = CollisionIndex::default();
        for tombstone in &self.tombstones {
            let _ = &tombstone.lifecycle;
            let keys = validate_portable_path(&tombstone.path)?;
            tombstone_paths.insert(&tombstone.path, keys.clone(), Some(&tombstone.object_id))?;
            if let Some(current) = current_paths.exact.get(tombstone.path.as_str()) {
                match current.object_id {
                    Some(current_object_id) if current_object_id != tombstone.object_id => {}
                    Some(_) => {
                        return invalid("same-path recreation must use a new stable Object ID");
                    }
                    None => {
                        return invalid("a tombstone cannot occupy an excluded current path");
                    }
                }
            } else {
                current_paths.reject_alias(&tombstone.path, &keys)?;
            }
            validate_prefixed_uuid(&tombstone.object_id, "obj_")?;
            if let Some(version_id) = &tombstone.last_object_version_id {
                validate_prefixed_uuid(version_id, "version_")?;
                bind_object_version(&mut object_version_owners, version_id, &tombstone.object_id)?;
            }
            match (
                tombstone.deleted_kind,
                tombstone.last_object_version_id.is_some(),
            ) {
                (DeletedKind::Directory, false)
                | (DeletedKind::RegularFile | DeletedKind::Symlink, true) => {}
                _ => {
                    return invalid(
                        "directory tombstones omit Object Version; content tombstones require it",
                    );
                }
            }
        }

        let nested_boundary_set = self
            .exclusions
            .iter()
            .filter(|exclusion| exclusion.kind == ExclusionKind::NestedFolderbase)
            .map(|exclusion| portable_folded_key(&exclusion.path))
            .collect::<BTreeSet<_>>();
        for boundary in &nested_boundary_set {
            for (separator, _) in boundary.match_indices('/') {
                if nested_boundary_set.contains(&boundary[..separator]) {
                    return invalid(format!(
                        "nested Folderbase boundary overlaps its ancestor: {boundary}"
                    ));
                }
            }
        }
        let nested_boundaries = nested_boundary_set.into_iter().collect::<Vec<_>>();
        for binding in &self.bindings {
            reject_nested_descendant(binding.path(), &nested_boundaries)?;
        }
        for tombstone in &self.tombstones {
            reject_nested_descendant(&tombstone.path, &nested_boundaries)?;
        }
        for exclusion in &self.exclusions {
            if exclusion.kind != ExclusionKind::NestedFolderbase {
                reject_nested_descendant(&exclusion.path, &nested_boundaries)?;
            }
        }
        for binding in &self.bindings {
            if let PathBinding::Symlink(symlink) = binding {
                validate_symlink_target(&symlink.path, &symlink.target, &nested_boundaries)?;
            }
        }
        Ok(())
    }

    pub fn version_id(&self) -> &str {
        &self.version_id
    }

    pub fn folderbase_id(&self) -> &str {
        &self.folderbase_id
    }

    pub fn parents(&self) -> &[String] {
        &self.parents
    }

    pub fn created_at(&self) -> &str {
        &self.created_at
    }

    pub fn root_manifest(&self) -> &RootManifest {
        &self.root_manifest
    }

    pub fn bindings(&self) -> &[PathBinding] {
        &self.bindings
    }

    pub fn tombstones(&self) -> &[Tombstone] {
        &self.tombstones
    }

    pub fn exclusions(&self) -> &[Exclusion] {
        &self.exclusions
    }

    pub fn binding_count(&self) -> usize {
        self.bindings.len()
    }

    pub fn tombstone_count(&self) -> usize {
        self.tombstones.len()
    }

    pub fn exclusion_count(&self) -> usize {
        self.exclusions.len()
    }

    pub fn lookup_binding(&self, path: &str) -> Option<&PathBinding> {
        self.bindings
            .binary_search_by(|binding| binding.path().as_bytes().cmp(path.as_bytes()))
            .ok()
            .map(|index| &self.bindings[index])
    }

    pub fn canonical_digest(&self) -> Result<String, FolderbaseVersionError> {
        self.validate()?;

        let mut digest = Sha256::new();
        digest.update(b"folderbase-version-v1\0");
        update_identifier(&mut digest, &self.protocol_version);
        update_identifier(&mut digest, &self.folderbase_id);
        update_identifier(&mut digest, &self.version_id);
        digest.update([self.parents.len() as u8]);
        for parent in &self.parents {
            update_identifier(&mut digest, parent);
        }
        update_identifier(&mut digest, &self.created_at);
        update_identifier(&mut digest, &self.path_policy.format);
        update_identifier(&mut digest, &self.path_policy.normalization);
        update_identifier(&mut digest, &self.path_policy.normalization_unicode_version);
        update_identifier(&mut digest, &self.path_policy.case_folding);
        update_identifier(&mut digest, &self.path_policy.case_folding_unicode_version);
        update_identifier(&mut digest, &self.root_manifest.path);
        update_identifier(&mut digest, &self.root_manifest.object_version_id);
        digest.update(decode_sha256(&self.root_manifest.content_sha256));
        digest.update(self.root_manifest.bytes.0.to_be_bytes());

        digest.update((self.bindings.len() as u32).to_be_bytes());
        for binding in &self.bindings {
            update_identifier(&mut digest, binding.path());
            update_identifier(&mut digest, binding.object_id());
            update_identifier(&mut digest, "live");
            match binding {
                PathBinding::Directory(_) => digest.update([0]),
                PathBinding::RegularFile(binding) => {
                    digest.update([1]);
                    update_identifier(&mut digest, &binding.object_version_id);
                    digest.update(decode_sha256(&binding.content_sha256));
                    digest.update(binding.bytes.0.to_be_bytes());
                    digest.update([u8::from(binding.executable)]);
                }
                PathBinding::Symlink(binding) => {
                    digest.update([2]);
                    update_identifier(&mut digest, &binding.object_version_id);
                    update_identifier(&mut digest, &binding.target);
                    update_identifier(&mut digest, "relative-within-folderbase");
                }
            }
        }

        digest.update((self.tombstones.len() as u32).to_be_bytes());
        for tombstone in &self.tombstones {
            update_identifier(&mut digest, &tombstone.path);
            update_identifier(&mut digest, &tombstone.object_id);
            update_identifier(&mut digest, "deleted");
            digest.update([match tombstone.deleted_kind {
                DeletedKind::Directory => 0,
                DeletedKind::RegularFile => 1,
                DeletedKind::Symlink => 2,
            }]);
            match &tombstone.last_object_version_id {
                Some(version_id) => {
                    digest.update([1]);
                    update_identifier(&mut digest, version_id);
                }
                None => digest.update([0]),
            }
        }

        digest.update((self.exclusions.len() as u32).to_be_bytes());
        for exclusion in &self.exclusions {
            update_identifier(&mut digest, &exclusion.path);
            digest.update([match exclusion.kind {
                ExclusionKind::NestedFolderbase => 0,
                ExclusionKind::HardLink => 1,
                ExclusionKind::Fifo => 2,
                ExclusionKind::Socket => 3,
                ExclusionKind::BlockDevice => 4,
                ExclusionKind::CharacterDevice => 5,
                ExclusionKind::OtherSpecial => 6,
            }]);
            update_identifier(
                &mut digest,
                match exclusion.reason {
                    ExclusionReason::NestedFolderbaseBoundary => "nested-folderbase-boundary",
                    ExclusionReason::UnsupportedV1 => "unsupported-v1",
                },
            );
        }

        Ok(digest_hex(&digest.finalize()))
    }

    pub fn diff(&self, newer: &Self) -> Result<FolderbaseVersionDiff, FolderbaseVersionError> {
        self.validate()?;
        newer.validate()?;
        if self.folderbase_id != newer.folderbase_id {
            return invalid("cannot diff Folderbase Versions from different Folderbases");
        }

        let mut changes = Vec::new();
        if self.root_manifest != newer.root_manifest {
            changes.push(FolderbaseVersionChange::RootManifestUpdated {
                previous_object_version_id: self.root_manifest.object_version_id.clone(),
                object_version_id: newer.root_manifest.object_version_id.clone(),
                previous_content_sha256: self.root_manifest.content_sha256.clone(),
                content_sha256: newer.root_manifest.content_sha256.clone(),
            });
        }

        let previous_by_object = self
            .bindings
            .iter()
            .map(|binding| (binding.object_id(), binding))
            .collect::<BTreeMap<_, _>>();
        let current_by_object = newer
            .bindings
            .iter()
            .map(|binding| (binding.object_id(), binding))
            .collect::<BTreeMap<_, _>>();
        for (object_id, previous) in &previous_by_object {
            if let Some(current) = current_by_object.get(object_id)
                && previous.path() != current.path()
            {
                changes.push(FolderbaseVersionChange::Moved {
                    object_id: (*object_id).to_owned(),
                    from_path: previous.path().to_owned(),
                    to_path: current.path().to_owned(),
                });
                if !previous.state_eq_ignoring_path(current) {
                    changes.push(FolderbaseVersionChange::Updated {
                        path: current.path().to_owned(),
                        object_id: (*object_id).to_owned(),
                        previous_object_version_id: previous.object_version_id().map(str::to_owned),
                        object_version_id: current.object_version_id().map(str::to_owned),
                    });
                }
            }
        }

        let previous_by_path = self
            .bindings
            .iter()
            .map(|binding| (binding.path(), binding))
            .collect::<BTreeMap<_, _>>();
        let current_by_path = newer
            .bindings
            .iter()
            .map(|binding| (binding.path(), binding))
            .collect::<BTreeMap<_, _>>();
        let all_paths = previous_by_path
            .keys()
            .chain(current_by_path.keys())
            .copied()
            .collect::<BTreeSet<_>>();
        for path in all_paths {
            match (previous_by_path.get(path), current_by_path.get(path)) {
                (None, Some(current)) if !previous_by_object.contains_key(current.object_id()) => {
                    changes.push(FolderbaseVersionChange::Added {
                        path: path.to_owned(),
                        object_id: current.object_id().to_owned(),
                    });
                }
                (Some(previous), None) if !current_by_object.contains_key(previous.object_id()) => {
                    let tombstone_present = newer.tombstones.iter().any(|tombstone| {
                        tombstone.path == path && tombstone.object_id == previous.object_id()
                    });
                    changes.push(FolderbaseVersionChange::Deleted {
                        path: path.to_owned(),
                        object_id: previous.object_id().to_owned(),
                        tombstone_present,
                    });
                }
                (Some(previous), Some(current)) if previous.object_id() != current.object_id() => {
                    changes.push(FolderbaseVersionChange::Recreated {
                        path: path.to_owned(),
                        previous_object_id: previous.object_id().to_owned(),
                        object_id: current.object_id().to_owned(),
                    });
                }
                (Some(previous), Some(current)) if *previous != *current => {
                    changes.push(FolderbaseVersionChange::Updated {
                        path: path.to_owned(),
                        object_id: current.object_id().to_owned(),
                        previous_object_version_id: previous.object_version_id().map(str::to_owned),
                        object_version_id: current.object_version_id().map(str::to_owned),
                    });
                }
                _ => {}
            }
        }

        let previous_tombstones = self
            .tombstones
            .iter()
            .map(|tombstone| {
                (
                    (tombstone.path.as_str(), tombstone.object_id.as_str()),
                    tombstone,
                )
            })
            .collect::<BTreeMap<_, _>>();
        let current_tombstones = newer
            .tombstones
            .iter()
            .map(|tombstone| {
                (
                    (tombstone.path.as_str(), tombstone.object_id.as_str()),
                    tombstone,
                )
            })
            .collect::<BTreeMap<_, _>>();
        let tombstone_keys = previous_tombstones
            .keys()
            .chain(current_tombstones.keys())
            .copied()
            .collect::<BTreeSet<_>>();
        for (path, object_id) in tombstone_keys {
            match (
                previous_tombstones.get(&(path, object_id)),
                current_tombstones.get(&(path, object_id)),
            ) {
                (None, Some(_)) => {
                    changes.push(FolderbaseVersionChange::TombstoneAdded {
                        path: path.to_owned(),
                        object_id: object_id.to_owned(),
                    });
                }
                (Some(_), None) => {
                    changes.push(FolderbaseVersionChange::TombstoneRemoved {
                        path: path.to_owned(),
                        object_id: object_id.to_owned(),
                    });
                }
                (Some(previous), Some(current)) if *previous != *current => {
                    changes.push(FolderbaseVersionChange::TombstoneRemoved {
                        path: path.to_owned(),
                        object_id: object_id.to_owned(),
                    });
                    changes.push(FolderbaseVersionChange::TombstoneAdded {
                        path: path.to_owned(),
                        object_id: object_id.to_owned(),
                    });
                }
                _ => {}
            }
        }

        let previous_exclusions = self
            .exclusions
            .iter()
            .map(|exclusion| (exclusion.path.as_str(), exclusion))
            .collect::<BTreeMap<_, _>>();
        let current_exclusions = newer
            .exclusions
            .iter()
            .map(|exclusion| (exclusion.path.as_str(), exclusion))
            .collect::<BTreeMap<_, _>>();
        let exclusion_paths = previous_exclusions
            .keys()
            .chain(current_exclusions.keys())
            .copied()
            .collect::<BTreeSet<_>>();
        for path in exclusion_paths {
            match (previous_exclusions.get(path), current_exclusions.get(path)) {
                (None, Some(current)) => {
                    changes.push(FolderbaseVersionChange::ExclusionAdded {
                        path: path.to_owned(),
                        kind: current.kind,
                    });
                }
                (Some(previous), None) => {
                    changes.push(FolderbaseVersionChange::ExclusionRemoved {
                        path: path.to_owned(),
                        kind: previous.kind,
                    });
                }
                (Some(previous), Some(current)) if *previous != *current => {
                    changes.push(FolderbaseVersionChange::ExclusionRemoved {
                        path: path.to_owned(),
                        kind: previous.kind,
                    });
                    changes.push(FolderbaseVersionChange::ExclusionAdded {
                        path: path.to_owned(),
                        kind: current.kind,
                    });
                }
                _ => {}
            }
        }

        changes.sort_by_cached_key(change_sort_key);
        Ok(FolderbaseVersionDiff { changes })
    }
}

#[derive(Serialize)]
struct FolderbaseVersionWireRef<'a> {
    format: &'a str,
    protocol_version: &'a str,
    folderbase_id: &'a str,
    version_id: &'a str,
    parents: &'a [String],
    created_at: &'a str,
    path_policy: &'a PathPolicy,
    root_manifest: &'a RootManifest,
    bindings: &'a [PathBinding],
    tombstones: &'a [Tombstone],
    exclusions: &'a [Exclusion],
}

impl<'a> From<&'a FolderbaseVersion> for FolderbaseVersionWireRef<'a> {
    fn from(version: &'a FolderbaseVersion) -> Self {
        Self {
            format: &version.format,
            protocol_version: &version.protocol_version,
            folderbase_id: &version.folderbase_id,
            version_id: &version.version_id,
            parents: &version.parents,
            created_at: &version.created_at,
            path_policy: &version.path_policy,
            root_manifest: &version.root_manifest,
            bindings: &version.bindings,
            tombstones: &version.tombstones,
            exclusions: &version.exclusions,
        }
    }
}

impl From<FolderbaseVersionWire> for FolderbaseVersion {
    fn from(wire: FolderbaseVersionWire) -> Self {
        Self {
            format: wire.format,
            protocol_version: wire.protocol_version,
            folderbase_id: wire.folderbase_id,
            version_id: wire.version_id,
            parents: wire.parents,
            created_at: wire.created_at,
            path_policy: wire.path_policy,
            root_manifest: wire.root_manifest,
            bindings: wire.bindings,
            tombstones: wire.tombstones,
            exclusions: wire.exclusions,
        }
    }
}

impl PathBinding {
    pub fn path(&self) -> &str {
        match self {
            Self::Directory(binding) => &binding.path,
            Self::RegularFile(binding) => &binding.path,
            Self::Symlink(binding) => &binding.path,
        }
    }

    pub fn object_id(&self) -> &str {
        match self {
            Self::Directory(binding) => &binding.object_id,
            Self::RegularFile(binding) => &binding.object_id,
            Self::Symlink(binding) => &binding.object_id,
        }
    }

    pub fn kind(&self) -> PathBindingKind {
        match self {
            Self::Directory(_) => PathBindingKind::Directory,
            Self::RegularFile(_) => PathBindingKind::RegularFile,
            Self::Symlink(_) => PathBindingKind::Symlink,
        }
    }

    pub fn object_version_id(&self) -> Option<&str> {
        match self {
            Self::Directory(_) => None,
            Self::RegularFile(binding) => Some(&binding.object_version_id),
            Self::Symlink(binding) => Some(&binding.object_version_id),
        }
    }

    pub fn bytes(&self) -> Option<u64> {
        match self {
            Self::RegularFile(binding) => Some(binding.bytes.0),
            _ => None,
        }
    }

    pub fn executable(&self) -> Option<bool> {
        match self {
            Self::RegularFile(binding) => Some(binding.executable),
            _ => None,
        }
    }

    pub fn symlink_target(&self) -> Option<&str> {
        match self {
            Self::Symlink(binding) => Some(&binding.target),
            _ => None,
        }
    }

    pub fn content_sha256(&self) -> Option<&str> {
        match self {
            Self::RegularFile(binding) => Some(&binding.content_sha256),
            _ => None,
        }
    }

    fn state_eq_ignoring_path(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Directory(previous), Self::Directory(current)) => {
                previous.object_id == current.object_id
                    && previous.lifecycle == current.lifecycle
                    && previous.kind == current.kind
            }
            (Self::RegularFile(previous), Self::RegularFile(current)) => {
                previous.object_id == current.object_id
                    && previous.lifecycle == current.lifecycle
                    && previous.kind == current.kind
                    && previous.object_version_id == current.object_version_id
                    && previous.content_sha256 == current.content_sha256
                    && previous.bytes == current.bytes
                    && previous.executable == current.executable
            }
            (Self::Symlink(previous), Self::Symlink(current)) => {
                previous.object_id == current.object_id
                    && previous.lifecycle == current.lifecycle
                    && previous.kind == current.kind
                    && previous.object_version_id == current.object_version_id
                    && previous.target == current.target
                    && previous.target_safety == current.target_safety
            }
            _ => false,
        }
    }
}

impl RootManifest {
    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn object_version_id(&self) -> &str {
        &self.object_version_id
    }

    pub fn content_sha256(&self) -> &str {
        &self.content_sha256
    }

    pub fn bytes(&self) -> u64 {
        self.bytes.0
    }
}

impl Tombstone {
    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn object_id(&self) -> &str {
        &self.object_id
    }

    pub fn deleted_kind(&self) -> DeletedKind {
        self.deleted_kind
    }

    pub fn last_object_version_id(&self) -> Option<&str> {
        self.last_object_version_id.as_deref()
    }
}

impl Exclusion {
    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn kind(&self) -> ExclusionKind {
        self.kind
    }

    pub fn reason(&self) -> ExclusionReason {
        self.reason
    }
}

fn validate_prefixed_uuid(value: &str, prefix: &str) -> Result<(), FolderbaseVersionError> {
    let Some(uuid) = value.strip_prefix(prefix) else {
        return invalid("identifier uses the wrong namespace");
    };
    let parsed = Uuid::parse_str(uuid).map_err(|_| invalid_error("identifier is not a UUID"))?;
    if parsed.hyphenated().to_string() != uuid {
        return invalid("identifier UUID is not canonical lowercase hyphenated text");
    }
    if !(1..=8).contains(&(parsed.as_bytes()[6] >> 4))
        || parsed.as_bytes()[8] & 0b1100_0000 != 0b1000_0000
    {
        return invalid("identifier UUID has an unsupported version or variant");
    }
    Ok(())
}

fn validate_sha256(value: &str) -> Result<(), FolderbaseVersionError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return invalid("content digest is not lowercase hexadecimal SHA-256");
    }
    Ok(())
}

fn update_identifier(digest: &mut Sha256, value: &str) {
    digest.update((value.len() as u32).to_be_bytes());
    digest.update(value.as_bytes());
}

fn decode_sha256(value: &str) -> [u8; 32] {
    let mut decoded = [0_u8; 32];
    for (destination, encoded) in decoded.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
        *destination = (hex_nibble(encoded[0]) << 4) | hex_nibble(encoded[1]);
    }
    decoded
}

fn hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => unreachable!("digest syntax is validated before canonical encoding"),
    }
}

fn digest_hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
}

fn change_sort_key(change: &FolderbaseVersionChange) -> (String, u8, String) {
    match change {
        FolderbaseVersionChange::RootManifestUpdated { .. } => (String::new(), 0, String::new()),
        FolderbaseVersionChange::Moved {
            object_id,
            from_path,
            ..
        } => (from_path.clone(), 1, object_id.clone()),
        FolderbaseVersionChange::Recreated {
            path, object_id, ..
        } => (path.clone(), 2, object_id.clone()),
        FolderbaseVersionChange::Added { path, object_id } => (path.clone(), 3, object_id.clone()),
        FolderbaseVersionChange::Updated {
            path, object_id, ..
        } => (path.clone(), 4, object_id.clone()),
        FolderbaseVersionChange::Deleted {
            path, object_id, ..
        } => (path.clone(), 5, object_id.clone()),
        FolderbaseVersionChange::TombstoneAdded { path, object_id } => {
            (path.clone(), 6, object_id.clone())
        }
        FolderbaseVersionChange::TombstoneRemoved { path, object_id } => {
            (path.clone(), 7, object_id.clone())
        }
        FolderbaseVersionChange::ExclusionAdded { path, .. } => (path.clone(), 8, String::new()),
        FolderbaseVersionChange::ExclusionRemoved { path, .. } => (path.clone(), 9, String::new()),
    }
}

#[derive(Debug, Clone)]
struct PathKeys {
    nfc: String,
    folded: String,
}

#[derive(Default)]
struct CollisionIndex<'a> {
    exact: BTreeMap<&'a str, PathOwner<'a>>,
    nfc: BTreeMap<String, &'a str>,
    folded: BTreeMap<String, &'a str>,
}

#[derive(Clone, Copy)]
struct PathOwner<'a> {
    object_id: Option<&'a str>,
}

impl<'a> CollisionIndex<'a> {
    fn insert(
        &mut self,
        path: &'a str,
        keys: PathKeys,
        object_id: Option<&'a str>,
    ) -> Result<(), FolderbaseVersionError> {
        if self.exact.insert(path, PathOwner { object_id }).is_some() {
            return invalid("exact portable paths collide");
        }
        if self.nfc.insert(keys.nfc, path).is_some() {
            return invalid("portable paths collide after NFC normalization");
        }
        if self.folded.insert(keys.folded, path).is_some() {
            return invalid("portable paths collide after full default case folding");
        }
        Ok(())
    }

    fn reject_alias(&self, path: &str, keys: &PathKeys) -> Result<(), FolderbaseVersionError> {
        if self
            .nfc
            .get(&keys.nfc)
            .is_some_and(|existing| *existing != path)
        {
            return invalid("portable paths collide after NFC normalization");
        }
        if self
            .folded
            .get(&keys.folded)
            .is_some_and(|existing| *existing != path)
        {
            return invalid("portable paths collide after full default case folding");
        }
        Ok(())
    }
}

fn validate_strict_path_order<'a>(
    paths: impl Iterator<Item = &'a str>,
    label: &str,
) -> Result<(), FolderbaseVersionError> {
    let mut previous: Option<&[u8]> = None;
    for path in paths {
        if previous.is_some_and(|previous| previous >= path.as_bytes()) {
            return invalid(format!(
                "{label} must be strictly sorted by exact UTF-8 path bytes"
            ));
        }
        previous = Some(path.as_bytes());
    }
    Ok(())
}

fn validate_portable_path(path: &str) -> Result<PathKeys, FolderbaseVersionError> {
    let bytes = path.as_bytes();
    let drive_prefix = bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':';
    if bytes.is_empty()
        || bytes.len() > MAX_PATH_BYTES
        || path.starts_with('/')
        || path.ends_with('/')
        || path.contains('\\')
        || path.contains('\0')
        || drive_prefix
    {
        return invalid(format!("unsafe portable path: {path}"));
    }
    let components = path.split('/').collect::<Vec<_>>();
    if components.len() > MAX_PATH_DEPTH {
        return invalid("portable path exceeds the v1 depth limit");
    }
    for component in components {
        validate_portable_component(component)?;
    }
    Ok(PathKeys {
        nfc: path.nfc().collect(),
        folded: path
            .nfc()
            .collect::<String>()
            .case_fold()
            .collect::<String>()
            .nfc()
            .collect(),
    })
}

fn validate_portable_component(component: &str) -> Result<(), FolderbaseVersionError> {
    if component.is_empty()
        || matches!(component, "." | "..")
        || component.len() > MAX_PATH_COMPONENT_BYTES
        || component.ends_with(['.', ' '])
        || component.eq_ignore_ascii_case(".folderbase")
        || component
            .chars()
            .any(|character| character <= '\u{1f}' || r#"<>:"|?*"#.contains(character))
    {
        return invalid(format!("unsafe portable path component: {component}"));
    }
    let stem = component.split('.').next().unwrap_or(component);
    let uppercase_stem = stem.to_ascii_uppercase();
    let reserved = matches!(
        uppercase_stem.as_str(),
        "CON"
            | "PRN"
            | "AUX"
            | "NUL"
            | "COM1"
            | "COM2"
            | "COM3"
            | "COM4"
            | "COM5"
            | "COM6"
            | "COM7"
            | "COM8"
            | "COM9"
            | "LPT1"
            | "LPT2"
            | "LPT3"
            | "LPT4"
            | "LPT5"
            | "LPT6"
            | "LPT7"
            | "LPT8"
            | "LPT9"
            | "COM¹"
            | "COM²"
            | "COM³"
            | "LPT¹"
            | "LPT²"
            | "LPT³"
    );
    if reserved {
        return invalid(format!(
            "Windows-reserved portable path component: {component}"
        ));
    }
    Ok(())
}

fn bind_object_version<'a>(
    owners: &mut BTreeMap<&'a str, &'a str>,
    version_id: &'a str,
    object_id: &'a str,
) -> Result<(), FolderbaseVersionError> {
    if owners
        .insert(version_id, object_id)
        .is_some_and(|existing| existing != object_id)
    {
        return invalid("one Object Version is referenced by different Object IDs");
    }
    Ok(())
}

fn reject_nested_descendant(
    path: &str,
    boundaries: &[String],
) -> Result<(), FolderbaseVersionError> {
    let path = portable_folded_key(path);
    if boundaries
        .iter()
        .any(|boundary| path.starts_with(&format!("{boundary}/")))
    {
        return invalid(format!(
            "path enters an excluded nested Folderbase boundary: {path}"
        ));
    }
    Ok(())
}

fn validate_symlink_target(
    link_path: &str,
    target: &str,
    nested_boundaries: &[String],
) -> Result<(), FolderbaseVersionError> {
    let bytes = target.as_bytes();
    let drive_prefix = bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':';
    if bytes.is_empty()
        || bytes.len() > MAX_PATH_BYTES
        || target.starts_with('/')
        || target.ends_with('/')
        || target.contains('\\')
        || target.contains('\0')
        || target.contains("//")
        || drive_prefix
    {
        return invalid("symlink target is not a portable relative target");
    }

    let mut resolved = link_path.split('/').rev().skip(1).collect::<Vec<_>>();
    resolved.reverse();
    for component in target.split('/') {
        match component {
            "." => {}
            ".." => {
                if resolved.pop().is_none() {
                    return invalid("symlink target escapes the Folderbase root");
                }
            }
            component => {
                validate_portable_component(component)?;
                resolved.push(component);
                if resolved.len() > MAX_PATH_DEPTH {
                    return invalid("symlink target exceeds the v1 path depth limit");
                }
            }
        }
    }
    let resolved = resolved.join("/");
    if !resolved.is_empty() {
        validate_portable_path(&resolved)?;
        if resolved.eq_ignore_ascii_case(".folderbase")
            || resolved
                .split('/')
                .next()
                .is_some_and(|component| component.eq_ignore_ascii_case(".folderbase"))
        {
            return invalid("symlink target enters Folderbase protocol state");
        }
        let folded_resolved = portable_folded_key(&resolved);
        if nested_boundaries.iter().any(|boundary| {
            folded_resolved == *boundary || folded_resolved.starts_with(&format!("{boundary}/"))
        }) {
            return invalid("symlink target enters a nested Folderbase boundary");
        }
    }
    Ok(())
}

fn portable_folded_key(path: &str) -> String {
    path.nfc()
        .collect::<String>()
        .case_fold()
        .collect::<String>()
        .nfc()
        .collect()
}

fn invalid<T>(message: impl Into<String>) -> Result<T, FolderbaseVersionError> {
    Err(invalid_error(message))
}

fn invalid_error(message: impl Into<String>) -> FolderbaseVersionError {
    FolderbaseVersionError::InvalidVersion(message.into())
}

#[derive(Deserialize)]
struct EntryCountProbe {
    bindings: EntryCount,
    tombstones: EntryCount,
    exclusions: EntryCount,
}

impl EntryCountProbe {
    fn total(&self) -> usize {
        self.bindings
            .0
            .saturating_add(self.tombstones.0)
            .saturating_add(self.exclusions.0)
    }
}

struct EntryCount(usize);

impl<'de> Deserialize<'de> for EntryCount {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_seq(EntryCountVisitor)
    }
}

struct EntryCountVisitor;

impl<'de> Visitor<'de> for EntryCountVisitor {
    type Value = EntryCount;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a bounded Folderbase Version entry array")
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut count = 0_usize;
        while sequence.next_element::<IgnoredAny>()?.is_some() {
            count = count.saturating_add(1);
        }
        Ok(EntryCount(count))
    }
}

fn deserialize_bounded_bindings<'de, D>(deserializer: D) -> Result<Vec<PathBinding>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_bounded_entries(deserializer, "bindings")
}

fn deserialize_bounded_tombstones<'de, D>(deserializer: D) -> Result<Vec<Tombstone>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_bounded_entries(deserializer, "tombstones")
}

fn deserialize_bounded_exclusions<'de, D>(deserializer: D) -> Result<Vec<Exclusion>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_bounded_entries(deserializer, "exclusions")
}

fn deserialize_bounded_entries<'de, D, T>(
    deserializer: D,
    label: &'static str,
) -> Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    deserializer.deserialize_seq(BoundedEntriesVisitor {
        label,
        marker: PhantomData,
    })
}

struct BoundedEntriesVisitor<T> {
    label: &'static str,
    marker: PhantomData<T>,
}

impl<'de, T> Visitor<'de> for BoundedEntriesVisitor<T>
where
    T: Deserialize<'de>,
{
    type Value = Vec<T>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "a bounded {} array", self.label)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let capacity = sequence.size_hint().unwrap_or(0).min(MAX_VERSION_ENTRIES);
        let mut entries = Vec::with_capacity(capacity);
        while entries.len() < MAX_VERSION_ENTRIES {
            match sequence.next_element()? {
                Some(entry) => entries.push(entry),
                None => return Ok(entries),
            }
        }
        if sequence.next_element::<IgnoredAny>()?.is_some() {
            return Err(serde::de::Error::custom(format!(
                "{} exceeds the v1 entry limit",
                self.label
            )));
        }
        Ok(entries)
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct ExactU64(u64);

impl<'de> Deserialize<'de> for ExactU64 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let number = serde_json::Number::deserialize(deserializer)?;
        parse_exact_unsigned(&number.to_string())
            .filter(|value| *value <= MAX_OBJECT_BYTES)
            .map(Self)
            .ok_or_else(|| {
                serde::de::Error::custom(format!(
                    "byte length must be an exact integer from 0 through {MAX_OBJECT_BYTES}"
                ))
            })
    }
}

fn parse_exact_unsigned(encoded: &str) -> Option<u64> {
    let (negative, unsigned) = match encoded.strip_prefix('-') {
        Some(unsigned) => (true, unsigned),
        None => (false, encoded),
    };
    let (coefficient, exponent) = unsigned
        .split_once(['e', 'E'])
        .map_or((unsigned, "0"), |parts| parts);
    let exponent = exponent.parse::<i64>().ok()?;
    let (integer, fraction) = coefficient
        .split_once('.')
        .map_or((coefficient, ""), |parts| parts);
    let digits = format!("{integer}{fraction}");
    let significant = digits.trim_start_matches('0');
    if significant.is_empty() {
        return Some(0);
    }
    if negative {
        return None;
    }
    let scale = exponent.checked_sub(fraction.len() as i64)?;
    let mut normalized = significant.to_owned();
    if scale >= 0 {
        let zero_count = usize::try_from(scale).ok()?;
        if normalized.len().checked_add(zero_count)? > 20 {
            return None;
        }
        normalized.extend(std::iter::repeat_n('0', zero_count));
    } else {
        let removed = usize::try_from(scale.unsigned_abs()).ok()?;
        if removed > normalized.len() {
            return None;
        }
        let retained = normalized.len() - removed;
        if !normalized.as_bytes()[retained..]
            .iter()
            .all(|byte| *byte == b'0')
        {
            return None;
        }
        normalized.truncate(retained);
        if normalized.is_empty() {
            return Some(0);
        }
    }
    normalized.parse().ok()
}

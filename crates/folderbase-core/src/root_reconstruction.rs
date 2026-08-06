//! Pure validation and deterministic planning for one root-reconstruction package.

use std::{
    collections::{BTreeMap, BTreeSet},
    io::Read,
};

use serde::{
    Deserialize,
    de::{IgnoredAny, SeqAccess, Visitor},
};
use sha2::{Digest, Sha256};

use crate::{
    folderbase_version::{FolderbaseVersion, FolderbaseVersionError, PathBindingKind},
    transfer_manifest::{ChunkManifest, ManifestError},
};

pub const PACKAGE_FORMAT_V1: &str = "folderbase-root-reconstruction-package-v1";
pub const MAX_PACKAGE_INDEX_BYTES: u64 = 8_388_608;
pub const MAX_PACKAGE_VERSION_BYTES: u64 = 67_108_864;
pub const MAX_PACKAGE_MANIFEST_BYTES: u64 = 67_108_864;
pub const MAX_PACKAGE_REFERENCES: usize = 16_385;
pub const MAX_DISTINCT_MANIFESTS: usize = 16_385;
pub const MAX_DISTINCT_CHUNKS: usize = 1_048_576;
pub const MAX_CHUNKS_PER_MANIFEST: usize = 262_144;
pub const MAX_PACKAGE_OBJECT_BYTES: u64 = 1_099_511_627_776;
pub const MAX_TOTAL_OBJECT_BYTES: u64 = 9_007_199_254_740_991;
pub const MAX_VISIBLE_ENTRIES: usize = 16_384;

/// One canonical manifest document supplied by the package reader.
pub struct ManifestInput<R> {
    chunk_manifest_sha256: String,
    encoded: R,
}

impl<R> ManifestInput<R> {
    pub fn new(chunk_manifest_sha256: impl Into<String>, encoded: R) -> Self {
        Self {
            chunk_manifest_sha256: chunk_manifest_sha256.into(),
            encoded,
        }
    }

    pub fn digest(&self) -> &str {
        &self.chunk_manifest_sha256
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ReconstructionReferenceRole {
    RootManifest,
    LiveRegularFile,
    RetainedTombstone,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedObjectReference {
    object_version_id: String,
    object_id: Option<String>,
    roles: Vec<ReconstructionReferenceRole>,
    chunk_manifest_sha256: String,
}

impl PlannedObjectReference {
    pub fn object_version_id(&self) -> &str {
        &self.object_version_id
    }

    pub fn object_id(&self) -> Option<&str> {
        self.object_id.as_deref()
    }

    pub fn roles(&self) -> &[ReconstructionReferenceRole] {
        &self.roles
    }

    pub fn chunk_manifest_sha256(&self) -> &str {
        &self.chunk_manifest_sha256
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedManifest {
    chunk_manifest_sha256: String,
    object_sha256: String,
    object_bytes: u64,
    chunk_count: usize,
}

impl PlannedManifest {
    pub fn chunk_manifest_sha256(&self) -> &str {
        &self.chunk_manifest_sha256
    }

    pub fn object_sha256(&self) -> &str {
        &self.object_sha256
    }

    pub fn object_bytes(&self) -> u64 {
        self.object_bytes
    }

    pub fn chunk_count(&self) -> usize {
        self.chunk_count
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivedSymlink {
    path: String,
    object_id: String,
    object_version_id: String,
    target: String,
    content_sha256: String,
    bytes: u64,
}

impl DerivedSymlink {
    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn object_id(&self) -> &str {
        &self.object_id
    }

    pub fn object_version_id(&self) -> &str {
        &self.object_version_id
    }

    pub fn target(&self) -> &str {
        &self.target
    }

    pub fn content_sha256(&self) -> &str {
        &self.content_sha256
    }

    pub fn bytes(&self) -> u64 {
        self.bytes
    }
}

#[derive(Debug)]
pub struct RootReconstructionPlan {
    package_index_sha256: String,
    encoded_version_sha256: String,
    canonical_version_sha256: String,
    version: FolderbaseVersion,
    references: Vec<PlannedObjectReference>,
    manifests: Vec<PlannedManifest>,
    derived_symlinks: Vec<DerivedSymlink>,
    distinct_chunk_count: usize,
    total_object_bytes: u64,
}

impl RootReconstructionPlan {
    pub fn package_index_sha256(&self) -> &str {
        &self.package_index_sha256
    }

    pub fn encoded_version_sha256(&self) -> &str {
        &self.encoded_version_sha256
    }

    pub fn canonical_version_sha256(&self) -> &str {
        &self.canonical_version_sha256
    }

    pub fn version(&self) -> &FolderbaseVersion {
        &self.version
    }

    pub fn references(&self) -> &[PlannedObjectReference] {
        &self.references
    }

    pub fn manifests(&self) -> &[PlannedManifest] {
        &self.manifests
    }

    pub fn derived_symlinks(&self) -> &[DerivedSymlink] {
        &self.derived_symlinks
    }

    pub fn externally_materialized_object_count(&self) -> usize {
        self.references.len()
    }

    pub fn visible_entry_count(&self) -> usize {
        self.version.binding_count()
    }

    pub fn distinct_chunk_count(&self) -> usize {
        self.distinct_chunk_count
    }

    pub fn total_object_bytes(&self) -> u64 {
        self.total_object_bytes
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RootReconstructionError {
    #[error("package index input failed: {0}")]
    IndexReader(#[source] std::io::Error),
    #[error("encoded package index exceeds {maximum_bytes} bytes")]
    IndexTooLarge { maximum_bytes: u64 },
    #[error("package index is not valid closed JSON: {0}")]
    InvalidIndexJson(#[source] serde_json::Error),
    #[error("package index limit declaration is not the fixed v1 declaration")]
    LimitsMismatch,
    #[error("package index format is unsupported")]
    UnknownFormat,
    #[error("package index contains more than {maximum} references")]
    TooManyReferences { maximum: usize },
    #[error("Folderbase Version input failed: {0}")]
    VersionReader(#[source] std::io::Error),
    #[error("encoded Folderbase Version exceeds {maximum_bytes} bytes")]
    VersionTooLarge { maximum_bytes: u64 },
    #[error("Folderbase Version is invalid: {0}")]
    InvalidVersion(#[source] FolderbaseVersionError),
    #[error("package index Folderbase identity differs from the Version")]
    FolderbaseIdMismatch,
    #[error("package index Folderbase Version identity differs from the Version")]
    VersionIdMismatch,
    #[error("encoded Folderbase Version digest differs from the package index")]
    EncodedVersionDigestMismatch,
    #[error("canonical Folderbase Version digest differs from the package index")]
    CanonicalVersionDigestMismatch,
    #[error("package references are not strictly ordered by Object Version ID")]
    ReferencesOutOfOrder,
    #[error("package contains duplicate Object Version reference {object_version_id}")]
    DuplicateReference { object_version_id: String },
    #[error("package reference {object_version_id} has a noncanonical role set")]
    InvalidReferenceRoles { object_version_id: String },
    #[error("package reference {object_version_id} is not in the Version closure")]
    UnexpectedReference { object_version_id: String },
    #[error("Version closure reference {object_version_id} is missing")]
    MissingReference { object_version_id: String },
    #[error("package reference {object_version_id} differs from the Version closure")]
    ReferenceMismatch { object_version_id: String },
    #[error("package reference {object_version_id} has an invalid manifest digest")]
    InvalidManifestDigest { object_version_id: String },
    #[error("package contains more than {maximum} manifest documents")]
    TooManyManifests { maximum: usize },
    #[error("manifest {chunk_manifest_sha256} is not referenced by the Version closure")]
    UnreferencedManifest { chunk_manifest_sha256: String },
    #[error("manifest {chunk_manifest_sha256} is supplied more than once")]
    DuplicateManifest { chunk_manifest_sha256: String },
    #[error("referenced manifest {chunk_manifest_sha256} is missing")]
    MissingManifest { chunk_manifest_sha256: String },
    #[error("manifest {chunk_manifest_sha256} is invalid: {source}")]
    InvalidManifest {
        chunk_manifest_sha256: String,
        #[source]
        source: ManifestError,
    },
    #[error("manifest document does not match its canonical digest {chunk_manifest_sha256}")]
    ManifestDigestMismatch { chunk_manifest_sha256: String },
    #[error("package manifests reference more than {maximum} distinct chunks")]
    TooManyDistinctChunks { maximum: usize },
    #[error("manifest for {object_version_id} differs from the Version-bound object")]
    ManifestObjectMismatch { object_version_id: String },
    #[error("package object bytes exceed the aggregate v1 maximum of {maximum}")]
    TotalObjectBytesTooLarge { maximum: u64 },
}

/// Decode one closed package index and Version, validate its exact reference
/// and manifest closure, and return a deterministic bounded plan.
pub fn decode_and_plan<IR, VR, MR, MI>(
    index_reader: IR,
    version_reader: VR,
    manifest_inputs: MI,
) -> Result<RootReconstructionPlan, RootReconstructionError>
where
    IR: Read,
    VR: Read,
    MR: Read,
    MI: IntoIterator<Item = ManifestInput<MR>>,
{
    let index_encoded = read_bounded_index(index_reader)?;
    let count: ReferenceCountProbe = serde_json::from_slice(&index_encoded)
        .map_err(RootReconstructionError::InvalidIndexJson)?;
    if count.references.exceeds_maximum {
        return Err(RootReconstructionError::TooManyReferences {
            maximum: MAX_PACKAGE_REFERENCES,
        });
    }
    let index: PackageIndexWire = serde_json::from_slice(&index_encoded)
        .map_err(RootReconstructionError::InvalidIndexJson)?;
    if index.format != PACKAGE_FORMAT_V1 {
        return Err(RootReconstructionError::UnknownFormat);
    }
    if index.limits != PackageLimitsWire::v1() {
        return Err(RootReconstructionError::LimitsMismatch);
    }

    let version_encoded = read_bounded_version(version_reader)?;
    let encoded_version_sha256 = sha256(&version_encoded);
    if index.encoded_version_sha256 != encoded_version_sha256 {
        return Err(RootReconstructionError::EncodedVersionDigestMismatch);
    }
    let version = FolderbaseVersion::decode_bounded(version_encoded.as_slice())
        .map_err(RootReconstructionError::InvalidVersion)?;
    if index.folderbase_id != version.folderbase_id() {
        return Err(RootReconstructionError::FolderbaseIdMismatch);
    }
    if index.folderbase_version_id != version.version_id() {
        return Err(RootReconstructionError::VersionIdMismatch);
    }
    let canonical_version_sha256 = version
        .canonical_digest()
        .map_err(RootReconstructionError::InvalidVersion)?;
    if index.canonical_version_sha256 != canonical_version_sha256 {
        return Err(RootReconstructionError::CanonicalVersionDigestMismatch);
    }
    if version.binding_count() > MAX_VISIBLE_ENTRIES {
        return Err(RootReconstructionError::LimitsMismatch);
    }

    let (expected, derived_symlinks) = expected_closure(&version);
    let references = validate_references(index.references, &expected)?;
    let expected_manifest_digests = references
        .iter()
        .map(|reference| reference.chunk_manifest_sha256.clone())
        .collect::<BTreeSet<_>>();
    if expected_manifest_digests.len() > MAX_DISTINCT_MANIFESTS {
        return Err(RootReconstructionError::TooManyManifests {
            maximum: MAX_DISTINCT_MANIFESTS,
        });
    }

    let mut manifests = BTreeMap::new();
    let mut distinct_chunks = BTreeSet::new();
    for (position, input) in manifest_inputs.into_iter().enumerate() {
        if position >= MAX_DISTINCT_MANIFESTS {
            return Err(RootReconstructionError::TooManyManifests {
                maximum: MAX_DISTINCT_MANIFESTS,
            });
        }
        let digest = input.chunk_manifest_sha256;
        if !expected_manifest_digests.contains(&digest) {
            return Err(RootReconstructionError::UnreferencedManifest {
                chunk_manifest_sha256: digest,
            });
        }
        if manifests.contains_key(&digest) {
            return Err(RootReconstructionError::DuplicateManifest {
                chunk_manifest_sha256: digest,
            });
        }
        let manifest = ChunkManifest::decode_bounded(input.encoded).map_err(|source| {
            RootReconstructionError::InvalidManifest {
                chunk_manifest_sha256: digest.clone(),
                source,
            }
        })?;
        let canonical = manifest.canonical_digest().map_err(|source| {
            RootReconstructionError::InvalidManifest {
                chunk_manifest_sha256: digest.clone(),
                source: ManifestError::InvalidManifest(source),
            }
        })?;
        if canonical != digest {
            return Err(RootReconstructionError::ManifestDigestMismatch {
                chunk_manifest_sha256: digest,
            });
        }
        for chunk in &manifest.chunks {
            distinct_chunks.insert(chunk.sha256.clone());
            if distinct_chunks.len() > MAX_DISTINCT_CHUNKS {
                return Err(RootReconstructionError::TooManyDistinctChunks {
                    maximum: MAX_DISTINCT_CHUNKS,
                });
            }
        }
        manifests.insert(
            canonical.clone(),
            PlannedManifest {
                chunk_manifest_sha256: canonical,
                object_sha256: manifest.object_sha256,
                object_bytes: manifest.object_bytes,
                chunk_count: manifest.chunks.len(),
            },
        );
    }
    for expected_digest in &expected_manifest_digests {
        if !manifests.contains_key(expected_digest) {
            return Err(RootReconstructionError::MissingManifest {
                chunk_manifest_sha256: expected_digest.clone(),
            });
        }
    }

    let mut total_object_bytes = 0_u64;
    for reference in &references {
        let manifest = &manifests[&reference.chunk_manifest_sha256];
        let expected_object = &expected[&reference.object_version_id];
        if let Some(identity) = &expected_object.authenticated
            && (manifest.object_sha256 != identity.sha256
                || manifest.object_bytes != identity.bytes)
        {
            return Err(RootReconstructionError::ManifestObjectMismatch {
                object_version_id: reference.object_version_id.clone(),
            });
        }
        total_object_bytes = total_object_bytes
            .checked_add(manifest.object_bytes)
            .ok_or(RootReconstructionError::TotalObjectBytesTooLarge {
                maximum: MAX_TOTAL_OBJECT_BYTES,
            })?;
        if total_object_bytes > MAX_TOTAL_OBJECT_BYTES {
            return Err(RootReconstructionError::TotalObjectBytesTooLarge {
                maximum: MAX_TOTAL_OBJECT_BYTES,
            });
        }
    }

    Ok(RootReconstructionPlan {
        package_index_sha256: sha256(&index_encoded),
        encoded_version_sha256,
        canonical_version_sha256,
        version,
        references,
        manifests: manifests.into_values().collect(),
        derived_symlinks,
        distinct_chunk_count: distinct_chunks.len(),
        total_object_bytes,
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PackageIndexWire {
    format: String,
    folderbase_id: String,
    folderbase_version_id: String,
    canonical_version_sha256: String,
    encoded_version_sha256: String,
    limits: PackageLimitsWire,
    references: Vec<ReferenceWire>,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct PackageLimitsWire {
    max_index_bytes: u64,
    max_version_bytes: u64,
    max_manifest_bytes: u64,
    max_references: usize,
    max_distinct_manifests: usize,
    max_distinct_chunks: usize,
    max_chunks_per_manifest: usize,
    max_object_bytes: u64,
    max_total_object_bytes: u64,
    max_visible_entries: usize,
}

impl PackageLimitsWire {
    fn v1() -> Self {
        Self {
            max_index_bytes: MAX_PACKAGE_INDEX_BYTES,
            max_version_bytes: MAX_PACKAGE_VERSION_BYTES,
            max_manifest_bytes: MAX_PACKAGE_MANIFEST_BYTES,
            max_references: MAX_PACKAGE_REFERENCES,
            max_distinct_manifests: MAX_DISTINCT_MANIFESTS,
            max_distinct_chunks: MAX_DISTINCT_CHUNKS,
            max_chunks_per_manifest: MAX_CHUNKS_PER_MANIFEST,
            max_object_bytes: MAX_PACKAGE_OBJECT_BYTES,
            max_total_object_bytes: MAX_TOTAL_OBJECT_BYTES,
            max_visible_entries: MAX_VISIBLE_ENTRIES,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReferenceWire {
    object_version_id: String,
    #[serde(default, deserialize_with = "deserialize_optional_object_id")]
    object_id: OptionalObjectId,
    #[serde(deserialize_with = "deserialize_bounded_roles")]
    roles: Vec<ReferenceRoleWire>,
    chunk_manifest_sha256: String,
}

#[derive(Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum ReferenceRoleWire {
    RootManifest,
    LiveRegularFile,
    RetainedTombstone,
}

#[derive(Default)]
struct OptionalObjectId {
    present: bool,
    value: Option<String>,
}

fn deserialize_optional_object_id<'de, D>(deserializer: D) -> Result<OptionalObjectId, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(OptionalObjectId {
        present: true,
        value: Option::<String>::deserialize(deserializer)?,
    })
}

fn deserialize_bounded_roles<'de, D>(deserializer: D) -> Result<Vec<ReferenceRoleWire>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct RolesVisitor;
    impl<'de> Visitor<'de> for RolesVisitor {
        type Value = Vec<ReferenceRoleWire>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a canonical root-reconstruction role array")
        }

        fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut roles = Vec::with_capacity(2);
            while let Some(role) = sequence.next_element()? {
                if roles.len() == 2 {
                    return Err(serde::de::Error::custom("reference has too many roles"));
                }
                roles.push(role);
            }
            Ok(roles)
        }
    }
    deserializer.deserialize_seq(RolesVisitor)
}

#[derive(Deserialize)]
struct ReferenceCountProbe {
    references: ReferenceCount,
}

struct ReferenceCount {
    exceeds_maximum: bool,
}

impl<'de> Deserialize<'de> for ReferenceCount {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct CountVisitor;
        impl<'de> Visitor<'de> for CountVisitor {
            type Value = ReferenceCount;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a package reference array")
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut count = 0_usize;
                while sequence.next_element::<IgnoredAny>()?.is_some() {
                    count = count.saturating_add(1);
                }
                Ok(ReferenceCount {
                    exceeds_maximum: count > MAX_PACKAGE_REFERENCES,
                })
            }
        }
        deserializer.deserialize_seq(CountVisitor)
    }
}

#[derive(Clone)]
struct ObjectIdentity {
    sha256: String,
    bytes: u64,
}

struct ExpectedObject {
    object_id: Option<String>,
    roles: BTreeSet<ReconstructionReferenceRole>,
    authenticated: Option<ObjectIdentity>,
}

fn expected_closure(
    version: &FolderbaseVersion,
) -> (BTreeMap<String, ExpectedObject>, Vec<DerivedSymlink>) {
    let root = version.root_manifest();
    let mut expected = BTreeMap::from([(
        root.object_version_id().to_owned(),
        ExpectedObject {
            object_id: None,
            roles: BTreeSet::from([ReconstructionReferenceRole::RootManifest]),
            authenticated: Some(ObjectIdentity {
                sha256: root.content_sha256().to_owned(),
                bytes: root.bytes(),
            }),
        },
    )]);
    let mut symlinks = Vec::new();
    for binding in version.bindings() {
        let Some(object_version_id) = binding.object_version_id() else {
            continue;
        };
        match binding.kind() {
            PathBindingKind::Directory => {}
            PathBindingKind::RegularFile => {
                expected.insert(
                    object_version_id.to_owned(),
                    ExpectedObject {
                        object_id: Some(binding.object_id().to_owned()),
                        roles: BTreeSet::from([ReconstructionReferenceRole::LiveRegularFile]),
                        authenticated: Some(ObjectIdentity {
                            sha256: binding.content_sha256().expect("regular digest").to_owned(),
                            bytes: binding.bytes().expect("regular length"),
                        }),
                    },
                );
            }
            PathBindingKind::Symlink => {
                let target = binding.symlink_target().expect("symlink target");
                let identity = ObjectIdentity {
                    sha256: sha256(target.as_bytes()),
                    bytes: target.len() as u64,
                };
                expected.insert(
                    object_version_id.to_owned(),
                    ExpectedObject {
                        object_id: Some(binding.object_id().to_owned()),
                        roles: BTreeSet::new(),
                        authenticated: Some(identity.clone()),
                    },
                );
                symlinks.push(DerivedSymlink {
                    path: binding.path().to_owned(),
                    object_id: binding.object_id().to_owned(),
                    object_version_id: object_version_id.to_owned(),
                    target: target.to_owned(),
                    content_sha256: identity.sha256,
                    bytes: identity.bytes,
                });
            }
        }
    }
    for tombstone in version.tombstones() {
        let Some(object_version_id) = tombstone.last_object_version_id() else {
            continue;
        };
        expected
            .entry(object_version_id.to_owned())
            .and_modify(|object| {
                object
                    .roles
                    .insert(ReconstructionReferenceRole::RetainedTombstone);
            })
            .or_insert_with(|| ExpectedObject {
                object_id: Some(tombstone.object_id().to_owned()),
                roles: BTreeSet::from([ReconstructionReferenceRole::RetainedTombstone]),
                authenticated: None,
            });
    }
    (expected, symlinks)
}

fn validate_references(
    references: Vec<ReferenceWire>,
    expected: &BTreeMap<String, ExpectedObject>,
) -> Result<Vec<PlannedObjectReference>, RootReconstructionError> {
    let mut planned = Vec::with_capacity(references.len());
    let mut previous: Option<String> = None;
    let mut observed = BTreeSet::new();
    for reference in references {
        if let Some(previous) = &previous {
            match previous
                .as_bytes()
                .cmp(reference.object_version_id.as_bytes())
            {
                std::cmp::Ordering::Equal => {
                    return Err(RootReconstructionError::DuplicateReference {
                        object_version_id: reference.object_version_id,
                    });
                }
                std::cmp::Ordering::Greater => {
                    return Err(RootReconstructionError::ReferencesOutOfOrder);
                }
                std::cmp::Ordering::Less => {}
            }
        }
        previous = Some(reference.object_version_id.clone());
        let roles = canonical_roles(&reference)?;
        let Some(expected_object) = expected.get(&reference.object_version_id) else {
            return Err(RootReconstructionError::UnexpectedReference {
                object_version_id: reference.object_version_id,
            });
        };
        let expected_roles = expected_object.roles.iter().copied().collect::<Vec<_>>();
        if roles != expected_roles || reference.object_id.value != expected_object.object_id {
            return Err(RootReconstructionError::ReferenceMismatch {
                object_version_id: reference.object_version_id,
            });
        }
        if !is_sha256(&reference.chunk_manifest_sha256) {
            return Err(RootReconstructionError::InvalidManifestDigest {
                object_version_id: reference.object_version_id,
            });
        }
        observed.insert(reference.object_version_id.clone());
        planned.push(PlannedObjectReference {
            object_version_id: reference.object_version_id,
            object_id: reference.object_id.value,
            roles,
            chunk_manifest_sha256: reference.chunk_manifest_sha256,
        });
    }
    for (object_version_id, expected_object) in expected {
        if !expected_object.roles.is_empty() && !observed.contains(object_version_id) {
            return Err(RootReconstructionError::MissingReference {
                object_version_id: object_version_id.clone(),
            });
        }
    }
    Ok(planned)
}

fn canonical_roles(
    reference: &ReferenceWire,
) -> Result<Vec<ReconstructionReferenceRole>, RootReconstructionError> {
    let roles = match reference.roles.as_slice() {
        [ReferenceRoleWire::RootManifest] if !reference.object_id.present => {
            vec![ReconstructionReferenceRole::RootManifest]
        }
        [ReferenceRoleWire::LiveRegularFile] if reference.object_id.value.is_some() => {
            vec![ReconstructionReferenceRole::LiveRegularFile]
        }
        [ReferenceRoleWire::RetainedTombstone] if reference.object_id.value.is_some() => {
            vec![ReconstructionReferenceRole::RetainedTombstone]
        }
        [
            ReferenceRoleWire::LiveRegularFile,
            ReferenceRoleWire::RetainedTombstone,
        ] if reference.object_id.value.is_some() => {
            vec![
                ReconstructionReferenceRole::LiveRegularFile,
                ReconstructionReferenceRole::RetainedTombstone,
            ]
        }
        _ => {
            return Err(RootReconstructionError::InvalidReferenceRoles {
                object_version_id: reference.object_version_id.clone(),
            });
        }
    };
    Ok(roles)
}

fn read_bounded_index(mut reader: impl Read) -> Result<Vec<u8>, RootReconstructionError> {
    let mut encoded = Vec::new();
    reader
        .by_ref()
        .take(MAX_PACKAGE_INDEX_BYTES + 1)
        .read_to_end(&mut encoded)
        .map_err(RootReconstructionError::IndexReader)?;
    if encoded.len() as u64 > MAX_PACKAGE_INDEX_BYTES {
        return Err(RootReconstructionError::IndexTooLarge {
            maximum_bytes: MAX_PACKAGE_INDEX_BYTES,
        });
    }
    Ok(encoded)
}

fn read_bounded_version(mut reader: impl Read) -> Result<Vec<u8>, RootReconstructionError> {
    let mut encoded = Vec::new();
    reader
        .by_ref()
        .take(MAX_PACKAGE_VERSION_BYTES + 1)
        .read_to_end(&mut encoded)
        .map_err(RootReconstructionError::VersionReader)?;
    if encoded.len() as u64 > MAX_PACKAGE_VERSION_BYTES {
        return Err(RootReconstructionError::VersionTooLarge {
            maximum_bytes: MAX_PACKAGE_VERSION_BYTES,
        });
    }
    Ok(encoded)
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Read as _};

    use serde_json::{Value, json};
    use sha2::{Digest, Sha256};

    use super::{
        MAX_PACKAGE_INDEX_BYTES, MAX_PACKAGE_MANIFEST_BYTES, MAX_PACKAGE_REFERENCES,
        RootReconstructionError,
    };
    use super::{ManifestInput, ReconstructionReferenceRole, decode_and_plan};
    use crate::{
        folderbase_version::FolderbaseVersion,
        transfer_manifest::{
            CHUNKING_ALGORITHM_V1, ChunkDescriptor, ChunkManifest, MANIFEST_FORMAT_V1,
            ManifestError, STANDARD_PROFILE_V1,
        },
    };

    const FOLDERBASE_ID: &str = "folderbase_01900000-0000-7000-8000-000000000001";
    const FOLDERBASE_VERSION_ID: &str = "fbversion_01900000-0000-7000-8000-000000000002";
    const ROOT_VERSION_ID: &str = "version_01900000-0000-7000-8000-000000000003";
    const LIVE_VERSION_ID: &str = "version_01900000-0000-7000-8000-000000000004";
    const SYMLINK_VERSION_ID: &str = "version_01900000-0000-7000-8000-000000000005";
    const LIVE_OBJECT_ID: &str = "obj_01900000-0000-7000-8000-000000000006";

    struct Fixture {
        index: Vec<u8>,
        version: Vec<u8>,
        manifests: Vec<ManifestInput<Cursor<Vec<u8>>>>,
    }

    #[test]
    fn complete_package_plans_exact_reference_closure_and_derived_symlink() {
        let fixture = complete_fixture();

        let plan = decode_and_plan(
            fixture.index.as_slice(),
            fixture.version.as_slice(),
            fixture.manifests,
        )
        .expect("complete package should plan");

        assert_eq!(plan.version().folderbase_id(), FOLDERBASE_ID);
        assert_eq!(plan.version().version_id(), FOLDERBASE_VERSION_ID);
        assert_eq!(plan.references().len(), 2);
        assert_eq!(
            plan.references()[1].roles(),
            &[
                ReconstructionReferenceRole::LiveRegularFile,
                ReconstructionReferenceRole::RetainedTombstone,
            ]
        );
        assert_eq!(plan.manifests().len(), 2);
        assert_eq!(plan.derived_symlinks().len(), 1);
        assert_eq!(plan.derived_symlinks()[0].path(), "shortcut");
        assert_eq!(plan.derived_symlinks()[0].target(), "current.txt");
        assert_eq!(
            plan.derived_symlinks()[0].content_sha256(),
            sha256(b"current.txt")
        );
        assert_eq!(plan.derived_symlinks()[0].bytes(), 11);
        assert_eq!(plan.externally_materialized_object_count(), 2);
        assert_eq!(plan.visible_entry_count(), 2);
        assert_eq!(plan.total_object_bytes(), 9);
    }

    #[test]
    fn closure_rejects_missing_root_live_and_retained_tombstone_roles() {
        let mut missing_root = complete_fixture();
        mutate_index(&mut missing_root, |index| {
            index["references"]
                .as_array_mut()
                .expect("references")
                .remove(0);
        });
        assert!(matches!(
            plan(missing_root),
            Err(RootReconstructionError::MissingReference { object_version_id })
                if object_version_id == ROOT_VERSION_ID
        ));

        let mut missing_live = complete_fixture();
        mutate_index(&mut missing_live, |index| {
            index["references"]
                .as_array_mut()
                .expect("references")
                .remove(1);
        });
        assert!(matches!(
            plan(missing_live),
            Err(RootReconstructionError::MissingReference { object_version_id })
                if object_version_id == LIVE_VERSION_ID
        ));

        let mut missing_tombstone_role = complete_fixture();
        mutate_index(&mut missing_tombstone_role, |index| {
            index["references"][1]["roles"] = json!(["live_regular_file"]);
        });
        assert!(matches!(
            plan(missing_tombstone_role),
            Err(RootReconstructionError::ReferenceMismatch { object_version_id })
                if object_version_id == LIVE_VERSION_ID
        ));
    }

    #[test]
    fn closure_rejects_duplicate_extra_and_out_of_order_references() {
        let mut duplicate = complete_fixture();
        mutate_index(&mut duplicate, |index| {
            let repeated = index["references"][1].clone();
            index["references"]
                .as_array_mut()
                .expect("references")
                .push(repeated);
        });
        assert!(matches!(
            plan(duplicate),
            Err(RootReconstructionError::DuplicateReference { .. })
        ));

        let mut extra = complete_fixture();
        mutate_index(&mut extra, |index| {
            index["references"]
                .as_array_mut()
                .expect("references")
                .push(json!({
                    "object_version_id": "version_01900000-0000-7000-8000-000000000099",
                    "object_id": "obj_01900000-0000-7000-8000-000000000099",
                    "roles": ["retained_tombstone"],
                    "chunk_manifest_sha256": "99".repeat(32)
                }));
        });
        assert!(matches!(
            plan(extra),
            Err(RootReconstructionError::UnexpectedReference { .. })
        ));

        let mut reordered = complete_fixture();
        mutate_index(&mut reordered, |index| {
            index["references"]
                .as_array_mut()
                .expect("references")
                .swap(0, 1);
        });
        assert!(matches!(
            plan(reordered),
            Err(RootReconstructionError::ReferencesOutOfOrder)
        ));
    }

    #[test]
    fn manifests_must_match_canonical_digest_and_version_digest_and_length() {
        let mut changed_plan = complete_fixture();
        let changed_manifest = manifest(b"changed", 0x33);
        changed_plan.manifests[0].encoded =
            Cursor::new(serde_json::to_vec(&changed_manifest).expect("encode changed manifest"));
        assert!(matches!(
            plan(changed_plan),
            Err(RootReconstructionError::ManifestDigestMismatch { .. })
        ));

        let mut digest_mismatch = complete_fixture();
        let mut changed_digest = manifest(b"payload", 0x22);
        changed_digest.object_sha256 = "aa".repeat(32);
        replace_live_manifest(&mut digest_mismatch, changed_digest);
        assert!(matches!(
            plan(digest_mismatch),
            Err(RootReconstructionError::ManifestObjectMismatch { object_version_id })
                if object_version_id == LIVE_VERSION_ID
        ));

        let mut length_mismatch = complete_fixture();
        let mut changed_length = manifest(b"payload", 0x22);
        changed_length.object_bytes += 1;
        changed_length.chunks[0].bytes += 1;
        replace_live_manifest(&mut length_mismatch, changed_length);
        assert!(matches!(
            plan(length_mismatch),
            Err(RootReconstructionError::ManifestObjectMismatch { object_version_id })
                if object_version_id == LIVE_VERSION_ID
        ));
    }

    #[test]
    fn manifest_set_is_exact_without_missing_duplicate_or_unreferenced_documents() {
        let mut missing = complete_fixture();
        missing.manifests.pop();
        assert!(matches!(
            plan(missing),
            Err(RootReconstructionError::MissingManifest { .. })
        ));

        let mut duplicate = complete_fixture();
        let digest = duplicate.manifests[0].digest().to_owned();
        let encoded = duplicate.manifests[0].encoded.get_ref().clone();
        duplicate
            .manifests
            .push(ManifestInput::new(digest, Cursor::new(encoded)));
        assert!(matches!(
            plan(duplicate),
            Err(RootReconstructionError::DuplicateManifest { .. })
        ));

        let mut extra = complete_fixture();
        let extra_manifest = manifest(b"extra", 0x44);
        let extra_digest = extra_manifest.canonical_digest().expect("valid manifest");
        extra
            .manifests
            .push(manifest_input(extra_digest, extra_manifest));
        assert!(matches!(
            plan(extra),
            Err(RootReconstructionError::UnreferencedManifest { .. })
        ));
    }

    #[test]
    fn fixed_limits_and_encoded_input_bounds_fail_closed() {
        let mut changed_limits = complete_fixture();
        mutate_index(&mut changed_limits, |index| {
            index["limits"]["max_visible_entries"] = json!(16_383);
        });
        assert!(matches!(
            plan(changed_limits),
            Err(RootReconstructionError::LimitsMismatch)
        ));

        let too_many_references = serde_json::to_vec(&json!({
            "references": vec![Value::Null; MAX_PACKAGE_REFERENCES + 1]
        }))
        .expect("encode count probe");
        let empty_manifests: Vec<ManifestInput<Cursor<Vec<u8>>>> = Vec::new();
        assert!(matches!(
            decode_and_plan(
                too_many_references.as_slice(),
                std::io::empty(),
                empty_manifests
            ),
            Err(RootReconstructionError::TooManyReferences { .. })
        ));

        let empty_manifests: Vec<ManifestInput<Cursor<Vec<u8>>>> = Vec::new();
        assert!(matches!(
            decode_and_plan(
                std::io::repeat(b' ').take(MAX_PACKAGE_INDEX_BYTES + 1),
                std::io::empty(),
                empty_manifests
            ),
            Err(RootReconstructionError::IndexTooLarge { .. })
        ));

        let fixture = complete_fixture();
        let oversized_digest = fixture.manifests[0].digest().to_owned();
        let mut boxed_inputs: Vec<ManifestInput<Box<dyn std::io::Read>>> = Vec::new();
        for input in fixture.manifests {
            let reader: Box<dyn std::io::Read> = if input.digest() == oversized_digest {
                Box::new(std::io::repeat(b' ').take(MAX_PACKAGE_MANIFEST_BYTES + 1))
            } else {
                Box::new(input.encoded)
            };
            boxed_inputs.push(ManifestInput::new(input.chunk_manifest_sha256, reader));
        }
        assert!(matches!(
            decode_and_plan(
                fixture.index.as_slice(),
                fixture.version.as_slice(),
                boxed_inputs
            ),
            Err(RootReconstructionError::InvalidManifest {
                source: ManifestError::EncodedManifestTooLarge { .. },
                ..
            })
        ));
    }

    fn complete_fixture() -> Fixture {
        let root_manifest = manifest(b"{}", 0x11);
        let live_manifest = manifest(b"payload", 0x22);
        let root_manifest_digest = root_manifest.canonical_digest().expect("valid manifest");
        let live_manifest_digest = live_manifest.canonical_digest().expect("valid manifest");
        let version_value = version_json(&root_manifest, &live_manifest);
        let version = serde_json::to_vec(&version_value).expect("encode version");
        let decoded = FolderbaseVersion::decode_bounded(version.as_slice()).expect("valid version");
        let mut references = vec![
            json!({
                "object_version_id": ROOT_VERSION_ID,
                "roles": ["root_manifest"],
                "chunk_manifest_sha256": root_manifest_digest,
            }),
            json!({
                "object_version_id": LIVE_VERSION_ID,
                "object_id": LIVE_OBJECT_ID,
                "roles": ["live_regular_file", "retained_tombstone"],
                "chunk_manifest_sha256": live_manifest_digest,
            }),
        ];
        references.sort_by(|left, right| {
            left["object_version_id"]
                .as_str()
                .expect("object version")
                .as_bytes()
                .cmp(
                    right["object_version_id"]
                        .as_str()
                        .expect("object version")
                        .as_bytes(),
                )
        });
        let index = serde_json::to_vec(&json!({
            "format": "folderbase-root-reconstruction-package-v1",
            "folderbase_id": FOLDERBASE_ID,
            "folderbase_version_id": FOLDERBASE_VERSION_ID,
            "canonical_version_sha256": decoded.canonical_digest().expect("version digest"),
            "encoded_version_sha256": sha256(&version),
            "limits": package_limits(),
            "references": references,
        }))
        .expect("encode index");
        let mut manifests = vec![
            manifest_input(root_manifest_digest, root_manifest),
            manifest_input(live_manifest_digest, live_manifest),
        ];
        manifests.sort_by(|left, right| left.digest().as_bytes().cmp(right.digest().as_bytes()));
        Fixture {
            index,
            version,
            manifests,
        }
    }

    fn plan(fixture: Fixture) -> Result<super::RootReconstructionPlan, RootReconstructionError> {
        decode_and_plan(
            fixture.index.as_slice(),
            fixture.version.as_slice(),
            fixture.manifests,
        )
    }

    fn mutate_index(fixture: &mut Fixture, mutate: impl FnOnce(&mut Value)) {
        let mut index: Value = serde_json::from_slice(&fixture.index).expect("decode index");
        mutate(&mut index);
        fixture.index = serde_json::to_vec(&index).expect("encode index");
    }

    fn replace_live_manifest(fixture: &mut Fixture, replacement: ChunkManifest) {
        let replacement_digest = replacement.canonical_digest().expect("valid replacement");
        let mut previous_digest = None;
        mutate_index(fixture, |index| {
            let reference = &mut index["references"][1];
            previous_digest = Some(
                reference["chunk_manifest_sha256"]
                    .as_str()
                    .expect("manifest digest")
                    .to_owned(),
            );
            reference["chunk_manifest_sha256"] = json!(replacement_digest);
        });
        let previous_digest = previous_digest.expect("previous manifest digest");
        fixture
            .manifests
            .retain(|input| input.digest() != previous_digest);
        fixture
            .manifests
            .push(manifest_input(replacement_digest, replacement));
    }

    fn version_json(root_manifest: &ChunkManifest, live_manifest: &ChunkManifest) -> Value {
        json!({
            "format": "folderbase-version-v1",
            "protocol_version": "0.5",
            "folderbase_id": FOLDERBASE_ID,
            "version_id": FOLDERBASE_VERSION_ID,
            "parents": [],
            "created_at": "2026-08-06T00:00:00Z",
            "path_policy": {
                "format": "folderbase-portable-path-v1",
                "normalization": "NFC",
                "normalization_unicode_version": "17.0.0",
                "case_folding": "full-default",
                "case_folding_unicode_version": "9.0.0"
            },
            "root_manifest": {
                "path": ".folderbase/manifest.json",
                "object_version_id": ROOT_VERSION_ID,
                "content_sha256": root_manifest.object_sha256,
                "bytes": root_manifest.object_bytes
            },
            "bindings": [
                {
                    "path": "current.txt",
                    "object_id": LIVE_OBJECT_ID,
                    "lifecycle": "live",
                    "kind": "regular_file",
                    "object_version_id": LIVE_VERSION_ID,
                    "content_sha256": live_manifest.object_sha256,
                    "bytes": live_manifest.object_bytes,
                    "executable": false
                },
                {
                    "path": "shortcut",
                    "object_id": "obj_01900000-0000-7000-8000-000000000007",
                    "lifecycle": "live",
                    "kind": "symlink",
                    "object_version_id": SYMLINK_VERSION_ID,
                    "target": "current.txt",
                    "target_safety": "relative-within-folderbase"
                }
            ],
            "tombstones": [{
                "path": "previous.txt",
                "object_id": LIVE_OBJECT_ID,
                "lifecycle": "deleted",
                "deleted_kind": "regular_file",
                "last_object_version_id": LIVE_VERSION_ID
            }],
            "exclusions": []
        })
    }

    fn package_limits() -> Value {
        json!({
            "max_index_bytes": 8_388_608,
            "max_version_bytes": 67_108_864,
            "max_manifest_bytes": 67_108_864,
            "max_references": 16_385,
            "max_distinct_manifests": 16_385,
            "max_distinct_chunks": 1_048_576,
            "max_chunks_per_manifest": 262_144,
            "max_object_bytes": 1_099_511_627_776_u64,
            "max_total_object_bytes": 9_007_199_254_740_991_u64,
            "max_visible_entries": 16_384
        })
    }

    fn manifest(bytes: &[u8], chunk_byte: u8) -> ChunkManifest {
        ChunkManifest {
            format: MANIFEST_FORMAT_V1.to_owned(),
            algorithm: CHUNKING_ALGORITHM_V1.to_owned(),
            profile: STANDARD_PROFILE_V1.to_owned(),
            minimum_chunk_bytes: 256 * 1024,
            average_chunk_bytes: 1024 * 1024,
            maximum_chunk_bytes: 4 * 1024 * 1024,
            object_sha256: sha256(bytes),
            object_bytes: bytes.len() as u64,
            chunks: vec![ChunkDescriptor {
                index: 0,
                offset: 0,
                bytes: bytes.len() as u64,
                sha256: format!("{chunk_byte:02x}").repeat(32),
            }],
        }
    }

    fn manifest_input(digest: String, manifest: ChunkManifest) -> ManifestInput<Cursor<Vec<u8>>> {
        ManifestInput::new(
            digest,
            Cursor::new(serde_json::to_vec(&manifest).expect("encode manifest")),
        )
    }

    fn sha256(bytes: &[u8]) -> String {
        format!("{:x}", Sha256::digest(bytes))
    }
}

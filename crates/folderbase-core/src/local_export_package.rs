//! The opt-in local export profile. Generic reconstruction 0.1 remains closed
//! and unchanged; this child reuses its retained I/O and publication executor.

use super::*;
use crate::local_versions::local_export::{
    ExportObjectHistory, ExportRetiredObject, ExportSnapshotSelection, ExportSource,
    LocalExportError, MAX_HISTORY_BYTES, MAX_HISTORY_VERSIONS, OmittedExportObject,
    SnapshotOnlyReservedPath, snapshot_only_git_path, snapshot_only_path,
    validate_portable_history, with_export_source,
};
use crate::transfer_source::ChunkTransferSource;

const EXPORT_FORMAT: &str = "folderbase-local-export-v1";
const HISTORY_FORMAT: &str = "folderbase-local-export-history-v1";
pub const RETENTION_PROFILE: &str = "selected-snapshot-file-history-v1";
const ANCHOR_PATH: &str = ".folderbase/local/root-reconstruction/export-anchor.json";
const ANCHOR_INDEX_PATH: &str = ".folderbase/local/root-reconstruction/export-index.json";
const ANCHOR_HISTORY_INDEX_PATH: &str =
    ".folderbase/local/root-reconstruction/export-history-index.json";
const ANCHOR_ROOT_INDEX_PATH: &str = ".folderbase/local/root-reconstruction/export-root-index.json";
const MAX_RECORD_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExportIndex {
    format: String,
    retention_profile: String,
    selection: String,
    root_index_sha256: String,
    history_index_sha256: String,
    retained_objects: usize,
    retained_file_versions: usize,
    #[serde(deserialize_with = "deserialize_inventory")]
    snapshot_only_reserved_paths: Vec<SnapshotOnlyReservedPath>,
    #[serde(deserialize_with = "deserialize_inventory")]
    omitted_objects: Vec<OmittedExportObject>,
    #[serde(deserialize_with = "deserialize_inventory")]
    retired_objects: Vec<ExportRetiredObject>,
    #[serde(deserialize_with = "deserialize_inventory")]
    tombstone_associations: Vec<ReconstructedTombstoneAssociation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoryIndex {
    format: String,
    objects: Vec<ExportObjectHistory>,
    #[serde(deserialize_with = "deserialize_manifest_mapping")]
    manifests: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalExportResult {
    pub format: String,
    pub export_index_sha256: String,
    pub retention_profile: String,
    pub selection: String,
    pub folderbase_id: String,
    pub folderbase_version_id: String,
    pub retained_objects: usize,
    pub retained_file_versions: usize,
    pub snapshot_only_reserved_paths: Vec<SnapshotOnlyReservedPath>,
    pub omitted_objects: Vec<OmittedExportObject>,
    pub capture_exclusions: usize,
    pub retired_objects: Vec<ExportRetiredObject>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalExportRestoreRequest {
    pub operation_id: String,
    pub export_index_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LocalExportRestoreResult {
    pub replayed: bool,
    pub export: LocalExportResult,
}

/// Already verified package metadata and retained authorities. All package
/// bytes are checked again before publication and on exact replay.
pub(super) struct VerifiedExport {
    outer: RetainedReconstructionPackage,
    root_package: RetainedReconstructionPackage,
    plan: RootReconstructionPlan,
    index: ExportIndex,
    index_bytes: Vec<u8>,
    history_bytes: Vec<u8>,
    root_index_bytes: Vec<u8>,
    history: HistoryIndex,
    content: ValidatedPackage,
    outer_identity: PhysicalIdentity,
    history_identity: PhysicalIdentity,
}

fn invalid_export() -> RootReconstructionError {
    RootReconstructionError::OperationConflict
}

fn bounded_json<T: Serialize>(value: &T, maximum: u64) -> Result<Vec<u8>, RootReconstructionError> {
    struct Counter {
        bytes: u64,
        maximum: u64,
    }
    impl Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.bytes = self
                .bytes
                .checked_add(bytes.len() as u64)
                .ok_or_else(|| std::io::Error::other("metadata length overflow"))?;
            if self.bytes > self.maximum {
                return Err(std::io::Error::other("metadata bound exceeded"));
            }
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    serde_json::to_writer(Counter { bytes: 0, maximum }, value).map_err(|_| invalid_export())?;
    serde_json::to_vec(value).map_err(|_| invalid_export())
}

fn destination_at(
    path: &Path,
) -> Result<RetainedReconstructionDestination, RootReconstructionError> {
    let name = path
        .file_name()
        .ok_or(RootReconstructionError::InvalidDestination)?;
    let parent = path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    RetainedReconstructionDestination::open(parent, name)
}

pub(super) fn require_export_destination_separation(
    package: &RetainedReconstructionPackage,
    destination: &RetainedReconstructionDestination,
) -> Result<(), RootReconstructionError> {
    let source = canonical_retained_directory(
        &package.root,
        &package.display_root,
        RootReconstructionError::PackageChanged(package.display_root.clone()),
    )?;
    let parent = canonical_retained_directory(
        &destination.parent,
        &destination.display_parent,
        RootReconstructionError::InvalidDestination,
    )?;
    let target = parent.join(&destination.name);
    let source_identity = cap_directory_identity(&package.root, &package.display_root)?;
    if physical_ancestor_chain_contains(&parent, source_identity)? || source.starts_with(&target) {
        return Err(RootReconstructionError::InvalidDestination);
    }
    Ok(())
}

pub fn create_local_export(
    root: impl AsRef<Path>,
    package: impl AsRef<Path>,
    selection: ExportSnapshotSelection,
) -> Result<LocalExportResult, LocalExportError> {
    let destination = destination_at(package.as_ref())?;
    let final_display = destination.display_parent.join(&destination.name);
    match destination.parent.symlink_metadata(&destination.name) {
        Ok(_) => return Err(RootReconstructionError::DestinationOccupied(final_display).into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(RootReconstructionError::Io {
                path: final_display,
                source,
            }
            .into());
        }
    }
    // A package inside or containing the source can be captured into itself.
    // Reject this before current-workspace capture has any side effect.
    let source_dir = RetainedReconstructionPackage::open(root.as_ref())?;
    require_export_destination_separation(&source_dir, &destination)?;
    let staged_name = OsString::from(format!(".folderbase-export-{}.stage", Uuid::now_v7()));
    let staged_display = destination.display_parent.join(&staged_name);
    let (result, identity) = with_export_source(root.as_ref(), &selection, |source| {
        destination
            .parent
            .create_dir(&staged_name)
            .map_err(|source| RootReconstructionError::Io {
                path: staged_display.clone(),
                source,
            })?;
        let staged = destination
            .parent
            .open_dir_nofollow(&staged_name)
            .map_err(|source| RootReconstructionError::Io {
                path: staged_display.clone(),
                source,
            })?;
        #[cfg(unix)]
        {
            use cap_std::fs::PermissionsExt;
            staged
                .set_permissions(".", cap_std::fs::Permissions::from_mode(0o700))
                .map_err(|source| RootReconstructionError::Io {
                    path: staged_display.clone(),
                    source,
                })?;
        }
        sync_retained_directory(&destination.parent, &destination.display_parent)?;
        let identity = cap_directory_identity(&staged, &staged_display)?;
        produce_package(&staged, &staged_display, source, &selection)?;
        let verified = VerifiedExport::open(&staged_display)?;
        verified.verify_content()?;
        let result = verified.result();
        crate::local_versions::local_export::ensure_result_bound(&result)?;
        if cap_directory_identity(&staged, &staged_display)? != identity {
            return Err(invalid_export().into());
        }
        Ok((result, identity))
    })?;
    let staged = destination
        .parent
        .open_dir_nofollow(&staged_name)
        .map_err(|source| RootReconstructionError::Io {
            path: staged_display.clone(),
            source,
        })?;
    if cap_directory_identity(&staged, &staged_display)? != identity {
        return Err(invalid_export().into());
    }
    publish_retained_directory_noreplace(
        &destination.parent,
        &staged_name,
        &destination.name,
        &destination.display_parent,
    )?;
    let final_package = VerifiedExport::open(&final_display)?;
    if final_package.outer_identity != identity || final_package.result() != result {
        return Err(invalid_export().into());
    }
    final_package.verify_content()?;
    Ok(result)
}

fn produce_package(
    staged: &Dir,
    display: &Path,
    source: &ExportSource<'_>,
    selection: &ExportSnapshotSelection,
) -> Result<(), LocalExportError> {
    for path in [
        "root/manifests",
        "root/chunks",
        "history/manifests",
        "history/chunks",
    ] {
        ensure_directory(staged, Path::new(path), display)?;
    }
    let mut root_manifests = BTreeMap::new();
    let mut root_chunks = BTreeSet::new();
    let mut associations = Vec::new();
    let mut history_metadata = 0_u64;
    for record in source.snapshot_records.values() {
        let mut content = source.open_snapshot_content(record)?;
        let digest = emit_content(
            staged,
            display,
            "root",
            &mut content,
            &mut root_manifests,
            &mut root_chunks,
            None,
        )?;
        associations.push(RootReconstructionObjectAssociation::new(
            record.id.to_string(),
            digest,
        ));
    }
    let mut version_bytes = Vec::new();
    source.full_version.encode_bounded(&mut version_bytes)?;
    let built = build_root_reconstruction_package(
        version_bytes.as_slice(),
        associations,
        source.tombstone_fidelity.clone(),
        root_manifests
            .iter()
            .map(|(digest, bytes)| ManifestInput::new(digest.clone(), bytes.as_slice())),
    )
    .map_err(|error| match error {
        RootReconstructionPackageBuildError::Validation(error) => error,
        RootReconstructionPackageBuildError::PackageEncoding(_) => invalid_export(),
    })?;
    write_relative_new(
        staged,
        display,
        Path::new("root/index.json"),
        built.encoded_index(),
    )?;
    write_relative_new(
        staged,
        display,
        Path::new("root/version.json"),
        built.encoded_version(),
    )?;
    let mut manifests = BTreeMap::new();
    let mut chunks = root_chunks;
    let mut mapping = BTreeMap::new();
    for object in &source.histories {
        for record in &object.versions {
            let mut content = source.open_history_content(record)?;
            let digest = emit_content(
                staged,
                display,
                "history",
                &mut content,
                &mut manifests,
                &mut chunks,
                Some(&mut history_metadata),
            )?;
            mapping.insert(record.id.to_string(), digest);
        }
    }
    let history = HistoryIndex {
        format: HISTORY_FORMAT.to_owned(),
        objects: source.histories.clone(),
        manifests: mapping,
    };
    let history_bytes = bounded_json(&history, MAX_HISTORY_BYTES.saturating_sub(history_metadata))?;
    write_relative_new(
        staged,
        display,
        Path::new("history/index.json"),
        &history_bytes,
    )?;
    let index = ExportIndex {
        format: EXPORT_FORMAT.to_owned(),
        retention_profile: RETENTION_PROFILE.to_owned(),
        selection: match selection {
            ExportSnapshotSelection::CurrentWorkspace => "current_workspace",
            ExportSnapshotSelection::RetainedVersion(_) => "retained_version",
        }
        .to_owned(),
        root_index_sha256: sha256(built.encoded_index()),
        history_index_sha256: sha256(&history_bytes),
        retained_objects: source.histories.len(),
        retained_file_versions: history.manifests.len(),
        snapshot_only_reserved_paths: source.snapshot_only.clone(),
        omitted_objects: source.omitted_objects.clone(),
        retired_objects: source.retired_objects.clone(),
        tombstone_associations: built
            .plan()
            .tombstone_fidelity()
            .iter()
            .map(|fidelity| {
                let record = &source.snapshot_records[fidelity.object_version_id()];
                ReconstructedTombstoneAssociation::for_tombstone(
                    fidelity.path(),
                    fidelity.object_id(),
                    fidelity.object_version_id(),
                    &record.content.digest,
                    record.content.bytes,
                    fidelity.executable(),
                )
            })
            .collect(),
    };
    let index_bytes = bounded_json(&index, MAX_PACKAGE_INDEX_BYTES)?;
    if history_metadata + history_bytes.len() as u64 + index_bytes.len() as u64 > MAX_HISTORY_BYTES
    {
        return Err(invalid_export().into());
    }
    write_relative_new(staged, display, Path::new("export.json"), &index_bytes)?;
    sync_retained_directory(staged, display)?;
    Ok(())
}

fn emit_content(
    staged: &Dir,
    display: &Path,
    prefix: &str,
    source: &mut ChunkTransferSource,
    manifests: &mut BTreeMap<String, Vec<u8>>,
    distinct_chunks: &mut BTreeSet<String>,
    metadata_bytes: Option<&mut u64>,
) -> Result<String, LocalExportError> {
    let digest = source.manifest_digest().to_owned();
    if manifests.contains_key(&digest) {
        return Ok(digest);
    }
    let encoded = bounded_json(source.manifest(), MAX_PACKAGE_MANIFEST_BYTES)?;
    if let Some(bytes) = metadata_bytes {
        *bytes = bytes
            .checked_add(encoded.len() as u64)
            .ok_or_else(invalid_export)?;
        if *bytes > MAX_HISTORY_BYTES {
            return Err(invalid_export().into());
        }
    }
    for index in 0..source.manifest().chunks.len() {
        let chunk = source.manifest().chunks[index].clone();
        distinct_chunks.insert(chunk.sha256.clone());
        if distinct_chunks.len() > MAX_DISTINCT_CHUNKS {
            return Err(invalid_export().into());
        }
        let relative = Path::new(prefix).join("chunks").join(&chunk.sha256);
        let leaf = retain_leaf_parent(staged, &relative, &display.join(&relative))?;
        match leaf.parent.symlink_metadata(&leaf.name) {
            Ok(_) => {
                // Repeated content was already emitted in this package prefix.
                let mut existing =
                    open_regular_from(&leaf.parent, &leaf.display, Path::new(&leaf.name))?;
                let mut sink = DigestWriter::new(std::io::sink());
                std::io::copy(&mut existing, &mut sink).map_err(|source| {
                    RootReconstructionError::Io {
                        path: leaf.display.clone(),
                        source,
                    }
                })?;
                if sink.bytes != chunk.bytes || sink.digest() != chunk.sha256 {
                    return Err(invalid_export().into());
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let mut options = CapOpenOptions::new();
                options
                    .write(true)
                    .create_new(true)
                    .follow(FollowSymlinks::No);
                let mut file = leaf
                    .parent
                    .open_with(&leaf.name, &options)
                    .map_err(|source| RootReconstructionError::Io {
                        path: leaf.display.clone(),
                        source,
                    })?;
                source.copy_chunk(chunk.index, &mut file)?;
                file.sync_all()
                    .map_err(|source| RootReconstructionError::Io {
                        path: leaf.display.clone(),
                        source,
                    })?;
                sync_retained_directory(&leaf.parent, &leaf.parent_display)?;
            }
            Err(source) => {
                return Err(RootReconstructionError::Io {
                    path: leaf.display,
                    source,
                }
                .into());
            }
        }
    }
    write_relative_new(
        staged,
        display,
        &Path::new(prefix)
            .join("manifests")
            .join(format!("{digest}.json")),
        &encoded,
    )?;
    manifests.insert(digest.clone(), encoded);
    Ok(digest)
}

fn write_relative_new(
    root: &Dir,
    display: &Path,
    relative: &Path,
    bytes: &[u8],
) -> Result<(), RootReconstructionError> {
    let leaf = retain_leaf_parent(root, relative, &display.join(relative))?;
    write_parent_new(
        &leaf.parent,
        &leaf.name,
        &leaf.display,
        &leaf.parent_display,
        bytes,
    )
}

struct DigestWriter<W> {
    inner: W,
    hash: Sha256,
    bytes: u64,
}
impl<W> DigestWriter<W> {
    fn new(inner: W) -> Self {
        Self {
            inner,
            hash: Sha256::new(),
            bytes: 0,
        }
    }
    fn digest(self) -> String {
        format!("{:x}", self.hash.finalize())
    }
}
impl<W: Write> Write for DigestWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let count = self.inner.write(bytes)?;
        self.hash.update(&bytes[..count]);
        self.bytes += count as u64;
        Ok(count)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

fn deserialize_inventory<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct Inventory<T>(std::marker::PhantomData<T>);
    impl<'de, T: Deserialize<'de>> Visitor<'de> for Inventory<T> {
        type Value = Vec<T>;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("a bounded export inventory")
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
            let mut entries = Vec::new();
            while let Some(entry) = seq.next_element()? {
                if entries.len() == MAX_HISTORY_VERSIONS {
                    return Err(serde::de::Error::custom("export inventory bound exceeded"));
                }
                entries.push(entry);
            }
            Ok(entries)
        }
    }
    deserializer.deserialize_seq(Inventory(std::marker::PhantomData))
}

fn deserialize_manifest_mapping<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<BTreeMap<String, String>, D::Error> {
    struct Mapping;
    impl<'de> Visitor<'de> for Mapping {
        type Value = BTreeMap<String, String>;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("a bounded unique Version-to-manifest mapping")
        }
        fn visit_map<A: serde::de::MapAccess<'de>>(
            self,
            mut map: A,
        ) -> Result<Self::Value, A::Error> {
            let mut entries = BTreeMap::new();
            while let Some((key, value)) = map.next_entry::<String, String>()? {
                if entries.len() == MAX_HISTORY_VERSIONS || entries.insert(key, value).is_some() {
                    return Err(serde::de::Error::custom("invalid export manifest mapping"));
                }
            }
            Ok(entries)
        }
    }
    deserializer.deserialize_map(Mapping)
}

// Count before allocating portable record collections. The encoded metadata
// aggregate also bounds repeated chunk references and extension values.
#[derive(Deserialize)]
struct HistoryCountProbe {
    objects: HistoryObjectCounts,
}
struct HistoryObjectCounts;
impl<'de> Deserialize<'de> for HistoryObjectCounts {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Objects;
        impl<'de> Visitor<'de> for Objects {
            type Value = HistoryObjectCounts;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("bounded retained Object histories")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                #[derive(Deserialize)]
                struct Object {
                    versions: VersionCount,
                }
                let mut objects = 0;
                let mut versions = 0;
                while let Some(object) = seq.next_element::<Object>()? {
                    objects += 1;
                    versions += object.versions.0;
                    if objects > MAX_HISTORY_VERSIONS || versions > MAX_HISTORY_VERSIONS {
                        return Err(serde::de::Error::custom(
                            "retained history record bound exceeded",
                        ));
                    }
                }
                Ok(HistoryObjectCounts)
            }
        }
        deserializer.deserialize_seq(Objects)
    }
}
struct VersionCount(usize);
impl<'de> Deserialize<'de> for VersionCount {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Versions;
        impl<'de> Visitor<'de> for Versions {
            type Value = VersionCount;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("bounded ordered Versions")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut count = 0;
                while seq.next_element::<IgnoredAny>()?.is_some() {
                    count += 1;
                    if count > MAX_HISTORY_VERSIONS {
                        return Err(serde::de::Error::custom("retained Version bound exceeded"));
                    }
                }
                Ok(VersionCount(count))
            }
        }
        deserializer.deserialize_seq(Versions)
    }
}

impl VerifiedExport {
    fn open(path: &Path) -> Result<Self, RootReconstructionError> {
        let outer = RetainedReconstructionPackage::open(path)?;
        let outer_identity = cap_directory_identity(&outer.root, path)?;
        require_exact_entries(
            &outer.root,
            path,
            &["export.json", "history", "root"]
                .into_iter()
                .map(str::to_owned)
                .collect(),
        )?;
        let (index_bytes, _) = read_package_regular_with_identity(
            &outer,
            Path::new("export.json"),
            MAX_PACKAGE_INDEX_BYTES,
        )?;
        let index: ExportIndex =
            serde_json::from_slice(&index_bytes).map_err(|_| invalid_export())?;
        if bounded_json(&index, MAX_PACKAGE_INDEX_BYTES)? != index_bytes
            || index.format != EXPORT_FORMAT
            || index.retention_profile != RETENTION_PROFILE
            || !matches!(
                index.selection.as_str(),
                "current_workspace" | "retained_version"
            )
            || !is_sha256(&index.root_index_sha256)
            || !is_sha256(&index.history_index_sha256)
            || index.retained_objects > MAX_HISTORY_VERSIONS
            || index.retained_file_versions > MAX_HISTORY_VERSIONS
            || index.snapshot_only_reserved_paths.len() > MAX_VISIBLE_ENTRIES
            || index.omitted_objects.len() > MAX_HISTORY_VERSIONS
        {
            return Err(invalid_export());
        }
        let root_package = RetainedReconstructionPackage {
            root: open_package_directory(&outer, "root")?,
            display_root: path.join("root"),
        };
        let plan = plan_retained_package(&root_package)?;
        let (root_index_bytes, _) = read_package_regular_with_identity(
            &root_package,
            Path::new("index.json"),
            MAX_PACKAGE_INDEX_BYTES,
        )?;
        if plan.package_index_sha256() != index.root_index_sha256 {
            return Err(invalid_export());
        }
        let history_package = RetainedReconstructionPackage {
            root: open_package_directory(&outer, "history")?,
            display_root: path.join("history"),
        };
        let history_identity =
            cap_directory_identity(&history_package.root, &history_package.display_root)?;
        require_exact_entries(
            &history_package.root,
            &history_package.display_root,
            &["index.json", "manifests", "chunks"]
                .into_iter()
                .map(str::to_owned)
                .collect(),
        )?;
        let (history_bytes, history_index_identity) = read_package_regular_with_identity(
            &history_package,
            Path::new("index.json"),
            MAX_HISTORY_BYTES.saturating_sub(index_bytes.len() as u64),
        )?;
        if sha256(&history_bytes) != index.history_index_sha256 {
            return Err(invalid_export());
        }
        let HistoryCountProbe { objects: _counted } =
            serde_json::from_slice(&history_bytes).map_err(|_| invalid_export())?;
        let history: HistoryIndex =
            serde_json::from_slice(&history_bytes).map_err(|_| invalid_export())?;
        if bounded_json(&history, MAX_HISTORY_BYTES)? != history_bytes
            || history.format != HISTORY_FORMAT
            || history.objects.len() != index.retained_objects
            || history.manifests.len() != index.retained_file_versions
        {
            return Err(invalid_export());
        }
        validate_retention(&index, &history, &plan)?;
        let manifests_dir = open_package_directory(&history_package, "manifests")?;
        let chunks_dir = open_package_directory(&history_package, "chunks")?;
        let mut manifests = BTreeMap::new();
        let mut manifest_names = BTreeSet::new();
        let mut manifest_identities = BTreeMap::new();
        let mut chunk_names = BTreeSet::new();
        let mut metadata_bytes = index_bytes.len() as u64 + history_bytes.len() as u64;
        for digest in history.manifests.values().collect::<BTreeSet<_>>() {
            if !is_sha256(digest) {
                return Err(invalid_export());
            }
            let name = format!("{digest}.json");
            let (encoded, identity) = read_regular_from_with_identity(
                &manifests_dir,
                &history_package.display_root.join("manifests").join(&name),
                Path::new(&name),
                MAX_HISTORY_BYTES.saturating_sub(metadata_bytes),
            )?;
            metadata_bytes += encoded.len() as u64;
            let manifest = ChunkManifest::decode_slice_bounded(&encoded).map_err(|source| {
                RootReconstructionError::InvalidManifest {
                    chunk_manifest_sha256: digest.clone(),
                    source,
                }
            })?;
            if manifest.canonical_digest().ok().as_deref() != Some(digest) {
                return Err(invalid_export());
            }
            chunk_names.extend(manifest.chunks.iter().map(|chunk| chunk.sha256.clone()));
            if chunk_names.len() > MAX_DISTINCT_CHUNKS {
                return Err(invalid_export());
            }
            manifest_names.insert(name.clone());
            manifest_identities.insert(name, identity);
            manifests.insert(digest.clone(), manifest);
        }
        require_exact_entries(
            &manifests_dir,
            &history_package.display_root.join("manifests"),
            &manifest_names,
        )?;
        require_exact_entries(
            &chunks_dir,
            &history_package.display_root.join("chunks"),
            &chunk_names,
        )?;
        let mut chunk_identities = BTreeMap::new();
        for name in &chunk_names {
            let display = history_package.display_root.join("chunks").join(name);
            let file = open_regular_from(&chunks_dir, &display, Path::new(name))?;
            let metadata = file
                .metadata()
                .map_err(|source| RootReconstructionError::Io {
                    path: display.clone(),
                    source,
                })?;
            validate_package_regular_metadata(&metadata, &display)?;
            chunk_identities.insert(
                name.clone(),
                PackageRegularIdentity {
                    physical: cap_file_identity(&file, &display)?,
                    bytes: metadata.len(),
                },
            );
        }
        let root_content = revalidate_package(&root_package, &plan)?;
        let all_chunks = root_content
            .chunk_identities
            .keys()
            .chain(chunk_names.iter())
            .collect::<BTreeSet<_>>();
        if all_chunks.len() > MAX_DISTINCT_CHUNKS {
            return Err(invalid_export());
        }
        let content = ValidatedPackage {
            manifests,
            manifests_directory_identity: cap_directory_identity(
                &manifests_dir,
                &history_package.display_root.join("manifests"),
            )?,
            chunks_directory_identity: cap_directory_identity(
                &chunks_dir,
                &history_package.display_root.join("chunks"),
            )?,
            _manifests_directory: manifests_dir,
            chunks_directory: chunks_dir,
            index_identity: history_index_identity,
            version_identity: history_index_identity,
            manifest_identities,
            chunk_identities,
        };
        for object in &history.objects {
            for record in &object.versions {
                let manifest = content
                    .manifests
                    .get(&history.manifests[record.id.as_str()])
                    .ok_or_else(invalid_export)?;
                if manifest.object_sha256 != record.content.digest
                    || manifest.object_bytes != record.content.bytes
                {
                    return Err(invalid_export());
                }
            }
        }
        Ok(Self {
            outer,
            root_package,
            plan,
            index,
            index_bytes,
            history_bytes,
            root_index_bytes,
            history,
            content,
            outer_identity,
            history_identity,
        })
    }

    fn result(&self) -> LocalExportResult {
        LocalExportResult {
            format: EXPORT_FORMAT.to_owned(),
            export_index_sha256: sha256(&self.index_bytes),
            retention_profile: self.index.retention_profile.clone(),
            selection: self.index.selection.clone(),
            folderbase_id: self.plan.version().folderbase_id().to_owned(),
            folderbase_version_id: self.plan.version().version_id().to_owned(),
            retained_objects: self.index.retained_objects,
            retained_file_versions: self.index.retained_file_versions,
            snapshot_only_reserved_paths: self.index.snapshot_only_reserved_paths.clone(),
            omitted_objects: self.index.omitted_objects.clone(),
            capture_exclusions: self.plan.version().exclusions().len(),
            retired_objects: self.index.retired_objects.clone(),
        }
    }

    fn verify_content(&self) -> Result<(), RootReconstructionError> {
        let root = revalidate_package(&self.root_package, &self.plan)?;
        for manifest in root.manifests.values() {
            manifest.verify_object(PackageObjectReader::new(&root, manifest)?)?;
        }
        for manifest in self.content.manifests.values() {
            manifest.verify_object(PackageObjectReader::new(&self.content, manifest)?)?;
        }
        self.verify_package_unchanged()
    }

    fn verify_package_unchanged(&self) -> Result<(), RootReconstructionError> {
        let fresh = Self::open(&self.outer.display_root)?;
        if fresh.outer_identity != self.outer_identity
            || fresh.history_identity != self.history_identity
            || fresh.index_bytes != self.index_bytes
            || fresh.history_bytes != self.history_bytes
            || fresh.root_index_bytes != self.root_index_bytes
        {
            return Err(invalid_export());
        }
        require_same_package_identity(&self.outer, &self.content, &fresh.content)?;
        Ok(())
    }

    pub(super) fn materialize_history(
        &self,
        root: &Dir,
        display: &Path,
        state: &FolderbaseState,
        local: &LocalVersionStore,
        closure: &mut ReconstructedHistoryClosure,
    ) -> Result<(), RootReconstructionError> {
        let mut original = BTreeMap::new();
        for object in &self.history.objects {
            for record in &object.versions {
                let manifest = &self.content.manifests[&self.history.manifests[record.id.as_str()]];
                let relative = Path::new(RECONSTRUCTION_OBJECTS_DIRECTORY)
                    .join(format!("{}.history", record.id));
                write_verified_package_object(root, display, &relative, &self.content, manifest)?;
                let mut file = open_regular_from(root, &display.join(&relative), &relative)?;
                let installed = local.install_content_reader_in(
                    state,
                    &mut file,
                    &display.join(&relative),
                    record.content.bytes,
                )?;
                if installed != record.content {
                    return Err(invalid_export());
                }
                original.insert(record.id.clone(), record.clone());
            }
        }
        // Replace synthetic current records BEFORE installing immutable records.
        closure
            .object_versions
            .retain(|record| !original.contains_key(&record.id));
        closure.object_versions.extend(original.into_values());
        closure
            .object_versions
            .sort_by(|a, b| a.id.as_str().cmp(b.id.as_str()));
        for projection in &mut closure.object_projections {
            let history = self
                .history
                .objects
                .iter()
                .find(|object| object.object_id == projection.id)
                .ok_or_else(invalid_export)?;
            if !history
                .versions
                .iter()
                .any(|record| record.id == projection.current_version)
            {
                return Err(invalid_export());
            }
            projection.versions = history
                .versions
                .iter()
                .map(|record| record.id.clone())
                .collect();
        }
        for retired in &self.index.retired_objects {
            let history = self
                .history
                .objects
                .iter()
                .find(|object| object.object_id.as_str() == retired.object_id)
                .ok_or_else(invalid_export)?;
            let mut projection = reconstructed_projection(
                history.object_id.clone(),
                VersionId::parse(retired.last_object_version_id.clone())?,
                &retired.path,
                self.plan.version().created_at(),
                "deleted",
            );
            projection.versions = history
                .versions
                .iter()
                .map(|record| record.id.clone())
                .collect();
            closure.object_projections.push(projection);
        }
        if closure.object_projections.len() != self.history.objects.len() {
            return Err(invalid_export());
        }
        self.verify_package_unchanged()
    }

    pub(super) fn verify_restored_history(
        &self,
        root: &Dir,
        display: &Path,
    ) -> Result<(), RootReconstructionError> {
        let state = FolderbaseState::from_retained_root(root, display)?;
        let local = LocalVersionStore::for_retained_root(display);
        for object in &self.history.objects {
            let path = Path::new(".folderbase/objects").join(format!("{}.json", object.object_id));
            let encoded = state
                .read_bounded(&path, MAX_RECORD_BYTES)?
                .ok_or_else(invalid_export)?;
            let projection: LocalObjectRecord =
                serde_json::from_slice(&encoded).map_err(|_| invalid_export())?;
            let expected = selected_projection(&self.plan, &self.index.retired_objects, object)?;
            if projection != expected {
                return Err(invalid_export());
            }
            for record in &object.versions {
                let installed = local.verify_capture_object_version_in(
                    &state,
                    &record.object_id,
                    &record.id,
                    &record.content,
                )?;
                if &installed != record {
                    return Err(invalid_export());
                }
            }
        }
        self.verify_content()?;
        state.verify_still_attached()?;
        Ok(())
    }

    pub(super) fn verify_replay_anchor(
        &self,
        root: &Dir,
        display: &Path,
        record: &ReconstructionRecord,
    ) -> Result<(), RootReconstructionError> {
        let state = FolderbaseState::from_retained_root(root, display)?;
        let expected = ExportAnchor {
            format: "folderbase-local-export-anchor-v1".to_owned(),
            export_index_sha256: sha256(&self.index_bytes),
            operation: record.clone(),
        };
        if state
            .read_bounded(Path::new(ANCHOR_PATH), MAX_RECONSTRUCTION_RECORD_BYTES)?
            .as_deref()
            != Some(bounded_json(&expected, MAX_RECONSTRUCTION_RECORD_BYTES)?.as_slice())
            || state
                .read_bounded(Path::new(ANCHOR_INDEX_PATH), MAX_PACKAGE_INDEX_BYTES)?
                .as_deref()
                != Some(&self.index_bytes)
            || state
                .read_bounded(Path::new(ANCHOR_ROOT_INDEX_PATH), MAX_PACKAGE_INDEX_BYTES)?
                .as_deref()
                != Some(&self.root_index_bytes)
            || state
                .read_bounded(Path::new(ANCHOR_HISTORY_INDEX_PATH), MAX_HISTORY_BYTES)?
                .as_deref()
                != Some(&self.history_bytes)
        {
            return Err(invalid_export());
        }
        let anchor = verified_export_ancestry(&state)?.ok_or_else(invalid_export)?;
        if anchor.version_id != self.plan.version().version_id()
            || anchor.version_sha256 != self.plan.canonical_version_sha256()
            || anchor.retired_objects != self.index.retired_objects
            || anchor.tombstone_associations != self.index.tombstone_associations
        {
            return Err(invalid_export());
        }
        Ok(())
    }

    pub(super) fn install_anchor(
        &self,
        state: &FolderbaseState,
        operation: &ReconstructionRecord,
    ) -> Result<(), RootReconstructionError> {
        state.publish_new_or_verify_export(Path::new(ANCHOR_INDEX_PATH), &self.index_bytes)?;
        state.publish_new_or_verify_export(
            Path::new(ANCHOR_HISTORY_INDEX_PATH),
            &self.history_bytes,
        )?;
        state.publish_new_or_verify_export(
            Path::new(ANCHOR_ROOT_INDEX_PATH),
            &self.root_index_bytes,
        )?;
        install_exact_record(
            state,
            Path::new(ANCHOR_PATH),
            &ExportAnchor {
                format: "folderbase-local-export-anchor-v1".to_owned(),
                export_index_sha256: sha256(&self.index_bytes),
                operation: operation.clone(),
            },
        )
    }
}

fn selected_projection(
    plan: &RootReconstructionPlan,
    retired: &[ExportRetiredObject],
    history: &ExportObjectHistory,
) -> Result<LocalObjectRecord, RootReconstructionError> {
    let mut projection = if let Some(binding) = plan.version().bindings().iter().find(|binding| {
        binding.kind() == PathBindingKind::RegularFile
            && binding.object_id() == history.object_id.as_str()
    }) {
        reconstructed_projection(
            history.object_id.clone(),
            VersionId::parse(
                binding
                    .object_version_id()
                    .ok_or_else(invalid_export)?
                    .to_owned(),
            )?,
            binding.path(),
            plan.version().created_at(),
            "canonical",
        )
    } else if let Some(retired) = retired
        .iter()
        .find(|retired| retired.object_id == history.object_id.as_str())
    {
        reconstructed_projection(
            history.object_id.clone(),
            VersionId::parse(retired.last_object_version_id.clone())?,
            &retired.path,
            plan.version().created_at(),
            "deleted",
        )
    } else {
        let tombstone = plan
            .version()
            .tombstones()
            .iter()
            .find(|tombstone| {
                tombstone.deleted_kind() == DeletedKind::RegularFile
                    && tombstone.object_id() == history.object_id.as_str()
            })
            .ok_or_else(invalid_export)?;
        reconstructed_projection(
            history.object_id.clone(),
            VersionId::parse(
                tombstone
                    .last_object_version_id()
                    .ok_or_else(invalid_export)?
                    .to_owned(),
            )?,
            tombstone.path(),
            plan.version().created_at(),
            "deleted",
        )
    };
    projection.versions = history
        .versions
        .iter()
        .map(|record| record.id.clone())
        .collect();
    Ok(projection)
}

fn validate_retention(
    index: &ExportIndex,
    history: &HistoryIndex,
    plan: &RootReconstructionPlan,
) -> Result<(), RootReconstructionError> {
    let mut executable_fidelity = BTreeMap::new();
    for binding in plan.version().bindings() {
        if binding.kind() == PathBindingKind::RegularFile {
            insert_executable_fidelity(
                &mut executable_fidelity,
                binding.object_version_id().ok_or_else(invalid_export)?,
                binding.executable().ok_or_else(invalid_export)?,
            )?;
        }
    }
    for fidelity in plan.tombstone_fidelity() {
        insert_executable_fidelity(
            &mut executable_fidelity,
            fidelity.object_version_id(),
            fidelity.executable(),
        )?;
    }
    let mut expected_objects = BTreeSet::new();
    let mut snapshot_only = Vec::new();
    let mut selected_records = BTreeMap::new();
    for binding in plan.version().bindings() {
        if binding.kind() != PathBindingKind::RegularFile {
            continue;
        }
        let id = binding.object_version_id().ok_or_else(invalid_export)?;
        if snapshot_only_git_path(binding.path()) {
            snapshot_only.push(snapshot_only_path(binding.path(), binding.object_id(), id));
        } else {
            if !expected_objects.insert(binding.object_id().to_owned()) {
                return Err(invalid_export());
            }
            selected_records.insert(id.to_owned(), binding.object_id().to_owned());
        }
    }
    for tombstone in plan.version().tombstones() {
        if tombstone.deleted_kind() != DeletedKind::RegularFile {
            continue;
        }
        let Some(id) = tombstone.last_object_version_id() else {
            continue;
        };
        if snapshot_only_git_path(tombstone.path()) {
            snapshot_only.push(snapshot_only_path(
                tombstone.path(),
                tombstone.object_id(),
                id,
            ));
        } else {
            expected_objects.insert(tombstone.object_id().to_owned());
            selected_records.insert(id.to_owned(), tombstone.object_id().to_owned());
        }
    }
    snapshot_only.sort_by(|a, b| a.path.as_bytes().cmp(b.path.as_bytes()));
    if snapshot_only != index.snapshot_only_reserved_paths {
        return Err(invalid_export());
    }
    if index.retired_objects.len() > MAX_HISTORY_VERSIONS
        || index.tombstone_associations.len() > MAX_VISIBLE_ENTRIES
    {
        return Err(invalid_export());
    }
    let mut previous_retired = None;
    for retired in &index.retired_objects {
        let key = (retired.path.as_str(), retired.object_id.as_str());
        if previous_retired.is_some_and(|previous| previous >= key)
            || expected_objects.contains(&retired.object_id)
            || !is_sha256(&retired.witness_version_sha256)
            || !can_project_reconstructed_object(&retired.path)
        {
            return Err(invalid_export());
        }
        crate::folderbase_version::validate_capture_version_id(&retired.witness_version_id)
            .map_err(RootReconstructionError::InvalidVersion)?;
        ObjectId::parse(retired.object_id.clone())?;
        VersionId::parse(retired.last_object_version_id.clone())?;
        // Reuse the portable full-Version path grammar through Core's existing
        // reconstructed projection validator before publication.
        crate::local_versions::local_export::validate_export_path(&retired.path)?;
        previous_retired = Some(key);
        expected_objects.insert(retired.object_id.clone());
    }
    let expected_associations = plan
        .tombstone_fidelity()
        .iter()
        .map(|fidelity| {
            let reference = plan
                .references()
                .iter()
                .find(|reference| reference.object_version_id() == fidelity.object_version_id())
                .ok_or_else(invalid_export)?;
            let manifest = plan
                .manifests()
                .iter()
                .find(|manifest| {
                    manifest.chunk_manifest_sha256() == reference.chunk_manifest_sha256()
                })
                .ok_or_else(invalid_export)?;
            Ok(ReconstructedTombstoneAssociation::for_tombstone(
                fidelity.path(),
                fidelity.object_id(),
                fidelity.object_version_id(),
                manifest.object_sha256(),
                manifest.object_bytes(),
                fidelity.executable(),
            ))
        })
        .collect::<Result<Vec<_>, RootReconstructionError>>()?;
    if expected_associations != index.tombstone_associations {
        return Err(invalid_export());
    }
    let mut object_ids = BTreeSet::new();
    let mut version_ids = BTreeSet::new();
    let mut previous = None;
    for object in &history.objects {
        validate_portable_history(object)?;
        if previous.is_some_and(|previous: &str| previous >= object.object_id.as_str())
            || object.versions.is_empty()
        {
            return Err(invalid_export());
        }
        previous = Some(object.object_id.as_str());
        object_ids.insert(object.object_id.to_string());
        if let Some(retired) = index
            .retired_objects
            .iter()
            .find(|retired| retired.object_id == object.object_id.as_str())
            && !object
                .versions
                .iter()
                .any(|record| record.id.as_str() == retired.last_object_version_id)
        {
            return Err(invalid_export());
        }
        for record in &object.versions {
            bounded_json(record, MAX_RECORD_BYTES)?;
            if let Some(executable) = executable_fidelity.get(record.id.as_str()) {
                crate::local_versions::local_export::validate_explicit_export_fidelity(
                    record,
                    *executable,
                    record.id.as_str(),
                )?;
            }
            if !version_ids.insert(record.id.to_string()) {
                return Err(invalid_export());
            }
            if let Some(expected) = selected_records.remove(record.id.as_str()) {
                if expected != record.object_id.as_str() {
                    return Err(invalid_export());
                }
                let reference = plan
                    .references()
                    .iter()
                    .find(|reference| reference.object_version_id() == record.id.as_str())
                    .ok_or_else(invalid_export)?;
                let manifest = plan
                    .manifests()
                    .iter()
                    .find(|manifest| {
                        manifest.chunk_manifest_sha256() == reference.chunk_manifest_sha256()
                    })
                    .ok_or_else(invalid_export)?;
                if record.content.digest != manifest.object_sha256()
                    || record.content.bytes != manifest.object_bytes()
                {
                    return Err(invalid_export());
                }
            }
        }
    }
    if object_ids != expected_objects
        || !selected_records.is_empty()
        || version_ids.len() > MAX_HISTORY_VERSIONS
        || version_ids != history.manifests.keys().cloned().collect()
    {
        return Err(invalid_export());
    }
    if index.selection == "current_workspace" && !index.omitted_objects.is_empty() {
        return Err(invalid_export());
    }
    let mut previous = None;
    for object in &index.omitted_objects {
        ObjectId::parse(object.object_id.clone())?;
        if previous.is_some_and(|previous: &str| previous >= object.object_id.as_str())
            || object_ids.contains(&object.object_id)
            || object.reason != "object_not_in_selected_snapshot"
        {
            return Err(invalid_export());
        }
        previous = Some(object.object_id.as_str());
    }
    Ok(())
}

pub fn restore_local_export(
    package: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    request: LocalExportRestoreRequest,
) -> Result<LocalExportRestoreResult, LocalExportError> {
    restore_local_export_with_phase_callback(package, destination, request, |_| {})
}

#[doc(hidden)]
pub fn restore_local_export_with_phase_callback(
    package: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    request: LocalExportRestoreRequest,
    mut phase: impl FnMut(RootReconstructionPhase),
) -> Result<LocalExportRestoreResult, LocalExportError> {
    let export = VerifiedExport::open(package.as_ref())?;
    if sha256(&export.index_bytes) != request.export_index_sha256 {
        return Err(RootReconstructionError::PackageIndexPinMismatch.into());
    }
    let mut operation = RootReconstructionOperation::new(
        &export.plan,
        request.operation_id,
        export.plan.package_index_sha256(),
    )?;
    operation.request_sha256 =
        export_request_sha256(&operation.operation_id, &request.export_index_sha256);
    let destination = destination_at(destination.as_ref())?;
    require_export_destination_separation(&export.outer, &destination)?;
    export.verify_content()?;
    let mut output = LocalExportRestoreResult {
        replayed: false,
        export: export.result(),
    };
    crate::local_versions::local_export::ensure_result_bound(&output)?;
    let result = execute_reconstruction_profile(
        operation,
        &export.root_package,
        &destination,
        Some(&export),
        &mut phase,
    )?;
    output.replayed = result.replayed();
    Ok(output)
}

fn export_request_sha256(operation_id: &str, digest: &str) -> String {
    sha256(format!("folderbase-local-export-restore-v1\0{operation_id}\0{digest}").as_bytes())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExportAnchor {
    format: String,
    export_index_sha256: String,
    operation: ReconstructionRecord,
}

// Exact immutable publication with this profile's larger bounded metadata.
trait ExportStateRecord {
    fn publish_new_or_verify_export(
        &self,
        path: &Path,
        encoded: &[u8],
    ) -> Result<(), RootReconstructionError>;
}
impl ExportStateRecord for FolderbaseState {
    fn publish_new_or_verify_export(
        &self,
        path: &Path,
        encoded: &[u8],
    ) -> Result<(), RootReconstructionError> {
        match self.publish_new(path, encoded) {
            Ok(()) => Ok(()),
            Err(FolderbaseError::WouldOverwrite(_))
                if self.read_bounded(path, MAX_HISTORY_BYTES)?.as_deref() == Some(encoded) =>
            {
                Ok(())
            }
            Err(error) => Err(error.into()),
        }
    }
}

pub(crate) const EXPORT_ANCESTRY_PROOF_PATHS: &[&str] = &[
    ANCHOR_PATH,
    ANCHOR_INDEX_PATH,
    ANCHOR_ROOT_INDEX_PATH,
    COMPLETED_RECONSTRUCTION_PATH,
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VerifiedExportAncestry {
    pub version_id: String,
    pub version_sha256: String,
    pub retired_objects: Vec<ExportRetiredObject>,
    pub tombstone_associations: Vec<ReconstructedTombstoneAssociation>,
}

/// Every stored export-proof byte comes through the caller's bounded observations.
/// This parser reads no content blobs or retained-history payload.
fn read_export_ancestry_metadata<E: From<FolderbaseError>>(
    state: &FolderbaseState,
    mut read: impl FnMut(&Path, u64) -> Result<Option<Vec<u8>>, E>,
) -> Result<Option<(VerifiedExportAncestry, String)>, E> {
    let invalid_metadata = || FolderbaseError::InvalidRecord {
        path: PathBuf::from(ANCHOR_PATH),
        message: "invalid completed export ancestry metadata".to_owned(),
    };
    let Some(anchor_bytes) = read(Path::new(ANCHOR_PATH), MAX_RECONSTRUCTION_RECORD_BYTES)? else {
        return Ok(None);
    };
    let anchor: ExportAnchor =
        serde_json::from_slice(&anchor_bytes).map_err(|_| invalid_metadata())?;
    if bounded_json(&anchor, MAX_RECONSTRUCTION_RECORD_BYTES).map_err(|_| invalid_metadata())?
        != anchor_bytes
        || anchor.format != "folderbase-local-export-anchor-v1"
        || !is_sha256(&anchor.export_index_sha256)
        || anchor.operation.request_sha256
            != export_request_sha256(&anchor.operation.operation_id, &anchor.export_index_sha256)
    {
        return Err(invalid_metadata().into());
    }
    let completion_bytes = read(
        Path::new(COMPLETED_RECONSTRUCTION_PATH),
        MAX_RECONSTRUCTION_RECORD_BYTES,
    )?
    .ok_or_else(&invalid_metadata)?;
    let completion: ReconstructionCompletion =
        serde_json::from_slice(&completion_bytes).map_err(|_| invalid_metadata())?;
    if bounded_json(&completion, MAX_RECONSTRUCTION_RECORD_BYTES).map_err(|_| invalid_metadata())?
        != completion_bytes
        || completion.operation != anchor.operation
    {
        return Err(invalid_metadata().into());
    }
    let root = state.clone_root_capability()?;
    let attestation = attest_retained_folderbase_root_with_profile(&root, state.display_root())
        .map_err(|_| invalid_metadata())?
        .0;
    if attestation.folderbase_id != anchor.operation.folderbase_id {
        return Err(invalid_metadata().into());
    }
    let index_bytes = read(Path::new(ANCHOR_INDEX_PATH), MAX_PACKAGE_INDEX_BYTES)?
        .ok_or_else(&invalid_metadata)?;
    if sha256(&index_bytes) != anchor.export_index_sha256 {
        return Err(invalid_metadata().into());
    }
    let index: ExportIndex =
        serde_json::from_slice(&index_bytes).map_err(|_| invalid_metadata())?;
    if index.format != EXPORT_FORMAT
        || index.retention_profile != RETENTION_PROFILE
        || index.retired_objects.len() > MAX_HISTORY_VERSIONS
        || index.root_index_sha256 != anchor.operation.package_index_sha256
    {
        return Err(invalid_metadata().into());
    }
    let root_index_bytes = read(Path::new(ANCHOR_ROOT_INDEX_PATH), MAX_PACKAGE_INDEX_BYTES)?
        .ok_or_else(&invalid_metadata)?;
    if sha256(&root_index_bytes) != index.root_index_sha256 {
        return Err(invalid_metadata().into());
    }
    let counts: ReferenceCountProbe =
        serde_json::from_slice(&root_index_bytes).map_err(|_| invalid_metadata())?;
    if counts.references.exceeds_maximum {
        return Err(invalid_metadata().into());
    }
    let root_index: PackageIndexWire =
        serde_json::from_slice(&root_index_bytes).map_err(|_| invalid_metadata())?;
    if root_index.folderbase_id != anchor.operation.folderbase_id
        || root_index.folderbase_version_id != anchor.operation.folderbase_version_id
        || root_index.canonical_version_sha256 != anchor.operation.canonical_version_sha256
        || root_index.format != PACKAGE_FORMAT_V1
        || root_index.limits != PackageLimitsWire::v1()
    {
        return Err(invalid_metadata().into());
    }
    let version_path = Path::new(".folderbase/versions/folderbase")
        .join(format!("{}.json", anchor.operation.folderbase_version_id));
    let version_bytes =
        read(&version_path, MAX_PACKAGE_VERSION_BYTES)?.ok_or_else(&invalid_metadata)?;
    let version = FolderbaseVersion::decode_bounded(version_bytes.as_slice())
        .map_err(|_| invalid_metadata())?;
    if version.version_id() != anchor.operation.folderbase_version_id
        || version.folderbase_id() != anchor.operation.folderbase_id
        || version.canonical_digest().map_err(|_| invalid_metadata())?
            != anchor.operation.canonical_version_sha256
        || sha256(&version_bytes) != root_index.encoded_version_sha256
        || version.root_manifest().content_sha256() != completion.manifest_sha256
    {
        return Err(invalid_metadata().into());
    }
    let mut previous = None;
    let mut seen = BTreeSet::new();
    for retired in &index.retired_objects {
        let key = (retired.path.as_str(), retired.object_id.as_str());
        if previous.is_some_and(|previous| previous >= key)
            || !seen.insert(retired.object_id.as_str())
        {
            return Err(invalid_metadata().into());
        }
        previous = Some(key);
        ObjectId::parse(retired.object_id.clone())?;
        VersionId::parse(retired.last_object_version_id.clone())?;
        crate::local_versions::local_export::validate_export_path(&retired.path)?;
        if !is_sha256(&retired.witness_version_sha256)
            || version
                .bindings()
                .iter()
                .any(|binding| binding.object_id() == retired.object_id)
            || version
                .tombstones()
                .iter()
                .any(|tombstone| tombstone.object_id() == retired.object_id)
        {
            return Err(invalid_metadata().into());
        }
    }
    if index.tombstone_associations.len() != root_index.tombstone_fidelity.len() {
        return Err(invalid_metadata().into());
    }
    for (association, fidelity) in index
        .tombstone_associations
        .iter()
        .zip(&root_index.tombstone_fidelity)
    {
        if association.path != fidelity.path
            || association.object_id != fidelity.object_id
            || association.object_version_id != fidelity.object_version_id
            || association.executable != fidelity.executable
            || !is_sha256(&association.content_sha256)
            || !version.tombstones().iter().any(|tombstone| {
                tombstone.path() == association.path
                    && tombstone.object_id() == association.object_id
                    && tombstone.last_object_version_id()
                        == Some(association.object_version_id.as_str())
            })
        {
            return Err(invalid_metadata().into());
        }
    }
    state.verify_still_attached()?;
    Ok(Some((
        VerifiedExportAncestry {
            version_id: anchor.operation.folderbase_version_id,
            version_sha256: anchor.operation.canonical_version_sha256,
            retired_objects: index.retired_objects,
            tombstone_associations: index.tombstone_associations,
        },
        completion.root_instance_sha256,
    )))
}

/// Content-verifying callers retain the full original verification, separately
/// from the metadata-only ownership proof used by read-only file history.
fn read_export_ancestry_proof(
    state: &FolderbaseState,
) -> Result<Option<(VerifiedExportAncestry, String)>, RootReconstructionError> {
    let proof = read_export_ancestry_metadata(state, |path, maximum| {
        match state.read_bounded(path, maximum) {
            Err(FolderbaseError::Io { source, .. })
                if source.kind() == std::io::ErrorKind::NotFound =>
            {
                Ok(None)
            }
            result => result.map_err(RootReconstructionError::from),
        }
    })?;
    if let Some((proof, _)) = &proof {
        let local = LocalVersionStore::for_retained_root(state.display_root());
        for association in &proof.tombstone_associations {
            local.verify_capture_object_version_in(
                state,
                &ObjectId::parse(association.object_id.clone())?,
                &VersionId::parse(association.object_version_id.clone())?,
                &crate::ContentDigest {
                    algorithm: "sha256".to_owned(),
                    digest: association.content_sha256.clone(),
                    bytes: association.bytes,
                },
            )?;
        }
    }
    state.verify_still_attached()?;
    Ok(proof)
}

/// Root-attested ownership evidence only. The callback must retain every read
/// in the operation's bounded witness set and recheck those bytes before success.
pub(crate) fn verified_export_ancestry_metadata<E: From<FolderbaseError>>(
    state: &FolderbaseState,
    read: impl FnMut(&Path, u64) -> Result<Option<Vec<u8>>, E>,
) -> Result<Option<VerifiedExportAncestry>, E> {
    let Some((proof, expected_physical_root)) = read_export_ancestry_metadata(state, read)? else {
        return Ok(None);
    };
    let root = state.clone_root_capability()?;
    let invalid = || FolderbaseError::InvalidRecord {
        path: PathBuf::from(ANCHOR_PATH),
        message: "export ancestry proof belongs to a different physical root".to_owned(),
    };
    if attest_retained_folderbase_root_with_profile(&root, state.display_root())
        .map_err(|_| invalid())?
        .0
        .root_instance_sha256
        != expected_physical_root
    {
        return Err(invalid().into());
    }
    Ok(Some(proof))
}

/// Admit this profile's ancestry cutoff for operations in this physical root.
pub(crate) fn verified_export_ancestry(
    state: &FolderbaseState,
) -> Result<Option<VerifiedExportAncestry>, RootReconstructionError> {
    let Some((proof, expected_physical_root)) = read_export_ancestry_proof(state)? else {
        return Ok(None);
    };
    let root = state.clone_root_capability()?;
    if attest_retained_folderbase_root_with_profile(&root, state.display_root())?
        .0
        .root_instance_sha256
        != expected_physical_root
    {
        return Err(invalid_export());
    }
    Ok(Some(proof))
}

/// Data for explicit immutable export only. It is deliberately a distinct type
/// from an admitted local ancestry anchor and cannot authorize normal writes.
pub(crate) struct PortableExportAncestry {
    pub version_id: String,
    pub version_sha256: String,
    pub retired_objects: Vec<ExportRetiredObject>,
    pub tombstone_associations: Vec<ReconstructedTombstoneAssociation>,
}

pub(crate) const EXPORT_PORTABLE_HISTORY_PROOF_PATH: &str = ANCHOR_HISTORY_INDEX_PATH;

pub(crate) fn read_portable_export_ancestry_for_source(
    state: &FolderbaseState,
) -> Result<Option<PortableExportAncestry>, RootReconstructionError> {
    let Some((proof, _old_physical_root)) = read_export_ancestry_proof(state)? else {
        return Ok(None);
    };
    let index_bytes = state
        .read_bounded(Path::new(ANCHOR_INDEX_PATH), MAX_PACKAGE_INDEX_BYTES)?
        .ok_or_else(invalid_export)?;
    let index: ExportIndex = serde_json::from_slice(&index_bytes).map_err(|_| invalid_export())?;
    let history_bytes = state
        .read_bounded(Path::new(ANCHOR_HISTORY_INDEX_PATH), MAX_HISTORY_BYTES)?
        .ok_or_else(invalid_export)?;
    if sha256(&history_bytes) != index.history_index_sha256 {
        return Err(invalid_export());
    }
    let HistoryCountProbe { objects: _counted } =
        serde_json::from_slice(&history_bytes).map_err(|_| invalid_export())?;
    let history: HistoryIndex =
        serde_json::from_slice(&history_bytes).map_err(|_| invalid_export())?;
    if history.format != HISTORY_FORMAT
        || history.objects.len() != index.retained_objects
        || history.manifests.len() != index.retained_file_versions
    {
        return Err(invalid_export());
    }
    let local = LocalVersionStore::for_retained_root(state.display_root());
    for object in &history.objects {
        validate_portable_history(object)?;
        for record in &object.versions {
            let installed = local.verify_capture_object_version_in(
                state,
                &record.object_id,
                &record.id,
                &record.content,
            )?;
            if &installed != record {
                return Err(invalid_export());
            }
        }
    }
    state.verify_still_attached()?;
    Ok(Some(PortableExportAncestry {
        version_id: proof.version_id,
        version_sha256: proof.version_sha256,
        retired_objects: proof.retired_objects,
        tombstone_associations: proof.tombstone_associations,
    }))
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod tests {
    use super::*;
    use crate::{FolderbaseVersionStore, InitializationOptions, initialize, plan_initialization};
    use std::fs;
    use tempfile::tempdir;

    fn initialized(root: &Path) {
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
    fn request(result: &LocalExportResult) -> LocalExportRestoreRequest {
        LocalExportRestoreRequest {
            operation_id: format!("reconstruction_{}", Uuid::now_v7()),
            export_index_sha256: result.export_index_sha256.clone(),
        }
    }
    #[test]
    fn selected_snapshot_retains_later_history_and_replay_checks_history_only_content() {
        let fixture = tempdir().unwrap();
        let root = fixture.path().join("source");
        let package = fixture.path().join("package");
        let restored = fixture.path().join("restored");
        initialized(&root);
        fs::write(root.join("task.json"), b"one").unwrap();
        let selected = capture(&root);
        let local = LocalVersionStore::open(&root).unwrap();
        let first = local.capture_file("task.json").unwrap();
        fs::write(root.join("task.json"), b"two").unwrap();
        let second = local.capture_file("task.json").unwrap();
        fs::write(root.join("task.json"), b"one").unwrap();
        let third = local.capture_file("task.json").unwrap();
        let original = crate::read_file_history(&root, "task.json").unwrap();
        assert_ne!(first.version.id, third.version.id);
        let result = create_local_export(
            &root,
            &package,
            ExportSnapshotSelection::RetainedVersion(selected),
        )
        .unwrap();
        let request = request(&result);
        assert!(
            !restore_local_export(&package, &restored, request.clone())
                .unwrap()
                .replayed
        );
        assert_eq!(fs::read(restored.join("task.json")).unwrap(), b"one");
        assert_eq!(
            crate::read_file_history(&restored, "task.json")
                .unwrap()
                .versions,
            original.versions
        );
        assert!(
            restore_local_export(&package, &restored, request.clone())
                .unwrap()
                .replayed
        );
        fs::write(
            restored
                .join(".folderbase/versions/blobs/sha256")
                .join(&second.version.content.digest),
            b"bad",
        )
        .unwrap();
        assert!(restore_local_export(&package, &restored, request).is_err());
    }

    #[test]
    fn git_bytes_are_snapshot_only_and_ordinary_gitignore_keeps_history() {
        let fixture = tempdir().unwrap();
        let root = fixture.path().join("source");
        let package = fixture.path().join("package");
        let restored = fixture.path().join("restored");
        initialized(&root);
        fs::create_dir_all(root.join("repo/.GIT")).unwrap();
        fs::write(root.join("repo/.GIT/HEAD"), b"exact git bytes").unwrap();
        fs::write(root.join(".gitignore"), b"ignored\n").unwrap();
        let result =
            create_local_export(&root, &package, ExportSnapshotSelection::CurrentWorkspace)
                .unwrap();
        assert_eq!(result.snapshot_only_reserved_paths.len(), 1);
        assert_eq!(result.retained_objects, 1);
        restore_local_export(&package, &restored, request(&result)).unwrap();
        assert_eq!(
            fs::read(restored.join("repo/.GIT/HEAD")).unwrap(),
            b"exact git bytes"
        );
        capture(&restored);
        assert_eq!(
            fs::read(restored.join("repo/.GIT/HEAD")).unwrap(),
            b"exact git bytes"
        );
        assert!(
            !crate::read_file_history(&restored, ".gitignore")
                .unwrap()
                .versions
                .is_empty()
        );
    }
    #[test]
    fn tombstone_restore_uses_only_the_completed_physical_anchor() {
        let fixture = tempdir().unwrap();
        let root = fixture.path().join("source");
        let package = fixture.path().join("package");
        let restored = fixture.path().join("restored");
        initialized(&root);
        fs::write(root.join("deleted.bin"), b"recover these bytes").unwrap();
        let old = capture(&root);
        fs::remove_file(root.join("deleted.bin")).unwrap();
        let result =
            create_local_export(&root, &package, ExportSnapshotSelection::CurrentWorkspace)
                .unwrap();
        restore_local_export(&package, &restored, request(&result)).unwrap();
        assert!(
            !restored
                .join(".folderbase/versions/folderbase")
                .join(format!("{old}.json"))
                .exists()
        );
        // A newer verified head must walk down to the exact imported anchor.
        fs::write(restored.join("new.txt"), b"new task").unwrap();
        capture(&restored);
        FolderbaseVersionStore::open(&restored)
            .unwrap()
            .restore_tombstone("deleted.bin")
            .unwrap();
        assert_eq!(
            fs::read(restored.join("deleted.bin")).unwrap(),
            b"recover these bytes"
        );
        // The same portable files and local receipt copied elsewhere confer no authority.
        let copied = fixture.path().join("copied");
        for entry in walkdir::WalkDir::new(&restored) {
            let entry = entry.unwrap();
            let target = copied.join(entry.path().strip_prefix(&restored).unwrap());
            if entry.file_type().is_dir() {
                fs::create_dir_all(target).unwrap();
            } else {
                fs::copy(entry.path(), target).unwrap();
            }
        }
        let copied_state = FolderbaseState::open_existing_read_only(&copied).unwrap();
        assert!(verified_export_ancestry(&copied_state).is_err());
    }

    #[test]
    fn restore_retries_owned_interrupted_stages_and_keeps_existing_destinations() {
        for phase in [
            RootReconstructionPhase::StageEntryDurable,
            RootReconstructionPhase::PreparedJournal,
            RootReconstructionPhase::VerifiedStaging,
            RootReconstructionPhase::Publication,
        ] {
            let fixture = tempdir().unwrap();
            let root = fixture.path().join("source");
            let package = fixture.path().join("package");
            let restored = fixture.path().join("restored");
            initialized(&root);
            fs::write(root.join("task.txt"), b"original").unwrap();
            let result =
                create_local_export(&root, &package, ExportSnapshotSelection::CurrentWorkspace)
                    .unwrap();
            let request = request(&result);
            let mut reached = false;
            let interrupted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                restore_local_export_with_phase_callback(
                    &package,
                    &restored,
                    request.clone(),
                    |current| {
                        if current == phase {
                            reached = true;
                            panic!("simulated interruption");
                        }
                    },
                )
                .unwrap();
            }));
            assert!(
                reached,
                "requested durable phase was not reached: {phase:?}"
            );
            assert!(interrupted.is_err());
            assert_eq!(
                restored.exists(),
                phase == RootReconstructionPhase::Publication
            );
            restore_local_export(&package, &restored, request.clone()).unwrap();
            assert_eq!(fs::read(restored.join("task.txt")).unwrap(), b"original");
            fs::write(restored.join("owner.txt"), b"preserve me").unwrap();
            assert!(restore_local_export(&package, &restored, request).is_err());
            assert_eq!(
                fs::read(restored.join("owner.txt")).unwrap(),
                b"preserve me"
            );
        }
    }

    #[test]
    fn occupied_export_destination_refuses_before_capturing_and_corrupt_package_never_publishes() {
        let fixture = tempdir().unwrap();
        let root = fixture.path().join("source");
        let package = fixture.path().join("package");
        let restored = fixture.path().join("restored");
        initialized(&root);
        fs::write(root.join("task.txt"), b"original").unwrap();
        fs::write(&package, b"owner package").unwrap();
        assert!(
            create_local_export(&root, &package, ExportSnapshotSelection::CurrentWorkspace)
                .is_err()
        );
        assert_eq!(fs::read(&package).unwrap(), b"owner package");
        assert!(!root.join(".folderbase/versions/folderbase").exists());
        fs::remove_file(&package).unwrap();
        let result =
            create_local_export(&root, &package, ExportSnapshotSelection::CurrentWorkspace)
                .unwrap();
        let chunk = fs::read_dir(package.join("history/chunks"))
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        fs::write(chunk, b"damaged").unwrap();
        assert!(restore_local_export(&package, &restored, request(&result)).is_err());
        assert!(!restored.exists());
        assert_eq!(fs::read(root.join("task.txt")).unwrap(), b"original");
    }

    #[test]
    fn repeated_generations_retain_separate_histories_and_older_selection_omits_future_objects() {
        let fixture = tempdir().unwrap();
        let root = fixture.path().join("source");
        let package = fixture.path().join("package");
        let restored = fixture.path().join("restored");
        initialized(&root);
        let mut objects = Vec::new();
        let mut oldest = None;
        for bytes in [
            b"first".as_slice(),
            b"second".as_slice(),
            b"third".as_slice(),
        ] {
            fs::write(root.join("task.json"), bytes).unwrap();
            let version = capture(&root);
            let store = FolderbaseVersionStore::open(&root).unwrap();
            objects.push(
                store
                    .read_version(&version)
                    .unwrap()
                    .lookup_binding("task.json")
                    .unwrap()
                    .object_id()
                    .to_owned(),
            );
            oldest.get_or_insert(version);
            fs::remove_file(root.join("task.json")).unwrap();
            capture(&root);
        }
        assert_eq!(objects.iter().collect::<BTreeSet<_>>().len(), 3);
        let result =
            create_local_export(&root, &package, ExportSnapshotSelection::CurrentWorkspace)
                .unwrap();
        assert_eq!(result.retained_objects, 3);
        assert_eq!(result.retired_objects.len(), 2);
        restore_local_export(&package, &restored, request(&result)).unwrap();
        for object in &objects {
            assert!(
                restored
                    .join(".folderbase/objects")
                    .join(format!("{object}.json"))
                    .is_file()
            );
        }
        let state = FolderbaseState::open_existing_read_only(&restored).unwrap();
        let anchor = verified_export_ancestry(&state).unwrap().unwrap();
        assert_eq!(anchor.retired_objects.len(), 2);
        let again = fixture.path().join("again");
        let repeated = create_local_export(
            &restored,
            &again,
            ExportSnapshotSelection::RetainedVersion(result.folderbase_version_id),
        )
        .unwrap();
        assert_eq!(repeated.retained_objects, 3);
        let copied = fixture.path().join("copied-restored");
        for entry in walkdir::WalkDir::new(&restored) {
            let entry = entry.unwrap();
            let target = copied.join(entry.path().strip_prefix(&restored).unwrap());
            if entry.file_type().is_dir() {
                fs::create_dir_all(target).unwrap();
            } else {
                fs::copy(entry.path(), target).unwrap();
            }
        }
        assert!(FolderbaseVersionStore::open(&copied).is_err());
        let copied_state = FolderbaseState::open_existing_read_only(&copied).unwrap();
        assert!(verified_export_ancestry(&copied_state).is_err());
        let portable_package = fixture.path().join("portable-from-archive");
        let portable = create_local_export(
            &copied,
            &portable_package,
            ExportSnapshotSelection::RetainedVersion(repeated.folderbase_version_id.clone()),
        )
        .unwrap();
        assert_eq!(portable.retained_objects, 3);
        let portable_root = fixture.path().join("portable-restored");
        restore_local_export(&portable_package, &portable_root, request(&portable)).unwrap();
        FolderbaseVersionStore::open(&portable_root)
            .unwrap()
            .restore_tombstone("task.json")
            .unwrap();
        assert_eq!(fs::read(portable_root.join("task.json")).unwrap(), b"third");
        fs::write(
            copied.join(ANCHOR_HISTORY_INDEX_PATH),
            b"corrupt history proof",
        )
        .unwrap();
        assert!(
            create_local_export(
                &copied,
                fixture.path().join("bad-archive-export"),
                ExportSnapshotSelection::RetainedVersion(repeated.folderbase_version_id)
            )
            .is_err()
        );
        let old_package = fixture.path().join("old-package");
        let old = create_local_export(
            &root,
            &old_package,
            ExportSnapshotSelection::RetainedVersion(oldest.unwrap()),
        )
        .unwrap();
        assert_eq!(old.retained_objects, 1);
        assert_eq!(old.omitted_objects.len(), 2);
        assert!(old.retired_objects.is_empty());
    }
    #[test]
    fn restored_generations_continue_with_metadata_only_history_and_complete_reexport() {
        let fixture = tempdir().unwrap();
        let root = fixture.path().join("source");
        let package = fixture.path().join("package");
        let restored = fixture.path().join("restored");
        initialized(&root);
        let mut generations = Vec::new();
        for (index, content) in ["first", "second", "third"].into_iter().enumerate() {
            fs::write(root.join("task.json"), content).unwrap();
            capture(&root);
            generations.push(crate::read_file_history(&root, "task.json").unwrap());
            if index < 2 {
                fs::remove_file(root.join("task.json")).unwrap();
                capture(&root);
            }
        }
        let export =
            create_local_export(&root, &package, ExportSnapshotSelection::CurrentWorkspace)
                .unwrap();
        assert_eq!(export.retained_objects, 3);
        assert_eq!(export.retired_objects.len(), 1);
        let restore_request = request(&export);
        restore_local_export(&package, &restored, restore_request.clone()).unwrap();
        let initial = crate::read_file_history(&restored, "task.json")
            .expect("restored live history resolves every retired generation");
        assert_eq!(
            initial,
            crate::read_file_history(&root, "task.json").unwrap()
        );
        assert_eq!(initial.object_id, generations[2].object_id);

        // This is the noncurrent Tombstone's blob, which the old content
        // accessor would hash even when only asking for live-file metadata.
        let retired = &generations[1].versions[0];
        let blob = restored
            .join(".folderbase/versions/blobs/sha256")
            .join(&retired.content.digest);
        let retained_bytes = fs::read(&blob).unwrap();
        fs::remove_file(&blob).unwrap();
        assert_eq!(
            crate::read_file_history(&restored, "task.json").unwrap(),
            initial
        );
        assert!(
            LocalVersionStore::open(&restored)
                .unwrap()
                .restore_version(&retired.id, "unrecoverable.json")
                .is_err()
        );
        let unavailable_package = fixture.path().join("unavailable-package");
        assert!(
            create_local_export(
                &restored,
                &unavailable_package,
                ExportSnapshotSelection::RetainedVersion(export.folderbase_version_id.clone())
            )
            .is_err()
        );
        assert!(!unavailable_package.exists());
        assert!(restore_local_export(&package, &restored, restore_request).is_err());
        fs::write(&blob, retained_bytes).unwrap();

        let old = crate::read_workspace_text(&restored, "task.json").unwrap();
        let saved =
            crate::save_workspace_text(&restored, "task.json", &old.sha256, "continued third")
                .unwrap();
        assert_eq!(Some(saved.object_id.clone()), initial.object_id);
        assert!(
            crate::save_workspace_text(&restored, "task.json", &old.sha256, "stale edit").is_err()
        );
        assert_eq!(
            fs::read(restored.join("task.json")).unwrap(),
            b"continued third"
        );
        let local = LocalVersionStore::open(&restored).unwrap();
        fs::write(restored.join("new-task.json"), b"new task").unwrap();
        let new_task = local.capture_file("new-task.json").unwrap();
        fs::write(restored.join("attachment.bin"), [0, 255, 3, 7]).unwrap();
        let attachment = local.capture_file("attachment.bin").unwrap();
        capture(&restored);
        assert_eq!(
            crate::read_file_history(&restored, "new-task.json")
                .unwrap()
                .object_id,
            Some(new_task.object.id)
        );
        assert_eq!(
            crate::read_file_history(&restored, "attachment.bin")
                .unwrap()
                .object_id,
            Some(attachment.object.id)
        );
        let continued = crate::read_file_history(&restored, "task.json").unwrap();
        assert_eq!(continued.object_id, initial.object_id);
        assert!(continued.versions.starts_with(&initial.versions));
        assert!(
            continued
                .versions
                .iter()
                .any(|version| version.id == saved.version_id)
        );

        let again_package = fixture.path().join("again-package");
        let again_export = create_local_export(
            &restored,
            &again_package,
            ExportSnapshotSelection::CurrentWorkspace,
        )
        .unwrap();
        assert_eq!(again_export.retained_objects, 5);
        let again_root = fixture.path().join("again-root");
        restore_local_export(&again_package, &again_root, request(&again_export)).unwrap();
        assert_eq!(
            crate::read_file_history(&again_root, "task.json").unwrap(),
            crate::read_file_history(&restored, "task.json").unwrap()
        );
        assert_eq!(
            fs::read(again_root.join("attachment.bin")).unwrap(),
            [0, 255, 3, 7]
        );
        let again_local = LocalVersionStore::open(&again_root).unwrap();
        for (index, generation) in generations.iter().take(2).enumerate() {
            let path = format!("recovered-{index}.json");
            again_local
                .restore_version(&generation.versions[0].id, &path)
                .unwrap();
            assert_eq!(
                fs::read(again_root.join(path)).unwrap(),
                [b"first".as_slice(), b"second".as_slice()][index]
            );
        }
        capture(&again_root);
        assert_eq!(
            crate::read_file_history(&again_root, "task.json")
                .unwrap()
                .object_id,
            initial.object_id
        );
    }

    #[test]
    fn exported_file_directory_file_replacement_keeps_retired_recovery_and_live_identity() {
        let fixture = tempdir().unwrap();
        let root = fixture.path().join("source");
        initialized(&root);
        fs::write(root.join("entry"), b"old file").unwrap();
        capture(&root);
        let original = crate::read_file_history(&root, "entry").unwrap();
        fs::remove_file(root.join("entry")).unwrap();
        fs::create_dir(root.join("entry")).unwrap();
        capture(&root);
        fs::remove_dir(root.join("entry")).unwrap();
        fs::write(root.join("entry"), b"new file").unwrap();
        capture(&root);
        let live = crate::read_file_history(&root, "entry").unwrap();
        assert_ne!(live.object_id, original.object_id);
        let package = fixture.path().join("package");
        let export =
            create_local_export(&root, &package, ExportSnapshotSelection::CurrentWorkspace)
                .unwrap();
        let restored = fixture.path().join("restored");
        restore_local_export(&package, &restored, request(&export)).unwrap();
        assert_eq!(
            crate::read_file_history(&restored, "entry")
                .unwrap()
                .object_id,
            live.object_id
        );
        let document = crate::read_workspace_text(&restored, "entry").unwrap();
        crate::save_workspace_text(&restored, "entry", &document.sha256, "continued new file")
            .unwrap();
        LocalVersionStore::open(&restored)
            .unwrap()
            .restore_version(&original.versions[0].id, "old-copy")
            .unwrap();
        assert_eq!(fs::read(restored.join("old-copy")).unwrap(), b"old file");
        capture(&restored);
        assert_eq!(
            crate::read_file_history(&restored, "entry")
                .unwrap()
                .object_id,
            live.object_id
        );
        let reexport = create_local_export(
            &restored,
            fixture.path().join("reexport"),
            ExportSnapshotSelection::CurrentWorkspace,
        )
        .unwrap();
        assert!(
            reexport
                .retired_objects
                .iter()
                .any(|retired| Some(retired.object_id.as_str())
                    == original.object_id.as_ref().map(|id| id.as_str()))
        );
    }

    #[test]
    fn imported_anchor_does_not_excuse_a_missing_newer_ancestor() {
        let fixture = tempdir().unwrap();
        let root = fixture.path().join("source");
        let restored = fixture.path().join("restored");
        let package = fixture.path().join("package");
        initialized(&root);
        fs::write(root.join("deleted.txt"), b"recover").unwrap();
        capture(&root);
        fs::remove_file(root.join("deleted.txt")).unwrap();
        let exported =
            create_local_export(&root, &package, ExportSnapshotSelection::CurrentWorkspace)
                .unwrap();
        restore_local_export(&package, &restored, request(&exported)).unwrap();
        fs::write(restored.join("new.txt"), b"one").unwrap();
        let middle = capture(&restored);
        fs::write(restored.join("new.txt"), b"two").unwrap();
        capture(&restored);
        fs::remove_file(
            restored
                .join(".folderbase/versions/folderbase")
                .join(format!("{middle}.json")),
        )
        .unwrap();
        assert!(
            FolderbaseVersionStore::open(&restored)
                .unwrap()
                .restore_tombstone("deleted.txt")
                .is_err()
        );
        assert!(!restored.join("deleted.txt").exists());
        assert_eq!(fs::read(restored.join("new.txt")).unwrap(), b"two");
    }
    #[test]
    fn explicit_executable_mismatch_is_refused_at_source_and_consumer() {
        let fixture = tempdir().unwrap();
        let root = fixture.path().join("source");
        let package = fixture.path().join("package");
        initialized(&root);
        fs::write(root.join("task.txt"), b"plain").unwrap();
        let exported =
            create_local_export(&root, &package, ExportSnapshotSelection::CurrentWorkspace)
                .unwrap();
        let history_path = package.join("history/index.json");
        let mut history: HistoryIndex =
            serde_json::from_slice(&fs::read(&history_path).unwrap()).unwrap();
        let record = &mut history.objects[0].versions[0];
        record
            .extensions
            .insert("executable".to_owned(), serde_json::Value::Bool(true));
        let wrong_record = record.clone();
        let encoded = bounded_json(&history, MAX_HISTORY_BYTES).unwrap();
        fs::write(&history_path, &encoded).unwrap();
        let mut index: ExportIndex =
            serde_json::from_slice(&fs::read(package.join("export.json")).unwrap()).unwrap();
        index.history_index_sha256 = sha256(&encoded);
        let index_encoded = bounded_json(&index, MAX_PACKAGE_INDEX_BYTES).unwrap();
        fs::write(package.join("export.json"), &index_encoded).unwrap();
        let destination = fixture.path().join("restored");
        assert!(
            restore_local_export(
                &package,
                &destination,
                LocalExportRestoreRequest {
                    operation_id: format!("reconstruction_{}", Uuid::now_v7()),
                    export_index_sha256: sha256(&index_encoded)
                }
            )
            .is_err()
        );
        assert!(!destination.exists());
        fs::write(
            root.join(".folderbase/versions/records")
                .join(format!("{}.json", wrong_record.id)),
            serde_json::to_vec(&wrong_record).unwrap(),
        )
        .unwrap();
        assert!(
            create_local_export(
                &root,
                fixture.path().join("mismatched-source"),
                ExportSnapshotSelection::RetainedVersion(exported.folderbase_version_id)
            )
            .is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn legacy_script_metadata_is_preserved_without_inventing_historical_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let fixture = tempdir().unwrap();
        let root = fixture.path().join("source");
        let package = fixture.path().join("package");
        let restored = fixture.path().join("restored");
        initialized(&root);
        fs::write(root.join("script.sh"), b"#!/bin/sh\necho hello\n").unwrap();
        fs::set_permissions(root.join("script.sh"), fs::Permissions::from_mode(0o755)).unwrap();
        let exported =
            create_local_export(&root, &package, ExportSnapshotSelection::CurrentWorkspace)
                .unwrap();
        let original = crate::read_file_history(&root, "script.sh").unwrap();
        assert!(!original.versions[0].extensions.contains_key("executable"));
        restore_local_export(&package, &restored, request(&exported)).unwrap();
        assert_ne!(
            fs::metadata(restored.join("script.sh"))
                .unwrap()
                .permissions()
                .mode()
                & 0o111,
            0
        );
        assert_eq!(
            crate::read_file_history(&restored, "script.sh")
                .unwrap()
                .versions,
            original.versions
        );
        LocalVersionStore::open(&restored)
            .unwrap()
            .restore_version(&original.versions[0].id, "historical-copy.sh")
            .unwrap();
        assert_eq!(
            fs::metadata(restored.join("historical-copy.sh"))
                .unwrap()
                .permissions()
                .mode()
                & 0o111,
            0
        );
    }
}

#[cfg(all(test, windows))]
mod windows_refusal_tests {
    use super::*;

    #[test]
    fn create_refuses_before_capture_or_package_publication() {
        let fixture = tempfile::tempdir().unwrap();
        let root = fixture.path().join("source");
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join("keep.txt"), b"original owner bytes").unwrap();
        let package = fixture.path().join("package");
        assert!(matches!(
            create_local_export(&root, &package, ExportSnapshotSelection::CurrentWorkspace),
            Err(LocalExportError::Package(
                RootReconstructionError::UnsupportedReconstructionFilesystem { .. }
            ))
        ));
        assert_eq!(
            std::fs::read(root.join("keep.txt")).unwrap(),
            b"original owner bytes"
        );
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 1);
        assert_eq!(std::fs::read_dir(fixture.path()).unwrap().count(), 1);
        assert!(!package.exists());
    }
}

use std::{
    collections::BTreeSet,
    ffi::{OsStr, OsString},
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use unicode_casefold::UnicodeCaseFold;

use super::{MigrationOperation, MigrationPlan};
use crate::{
    FolderbaseError, Result,
    migration_filesystem::{
        ExactDirectoryLeaf, ExactNestedBoundaryExpectation, ExactRegularLeaf,
        MigrationDirectoryFact, MigrationFilesystem, MigrationRegularFact,
        VerifiedPrivateDirectory, VerifiedVisibleDirectory,
    },
    traversal_policy::NestedFolderbaseBoundaryKind,
};

pub(super) const FORMAT: &str = "folderbase-migration-transaction-v1";
pub(super) const PROGRAM_FORMAT: &str = "folderbase-mutation-program-v1";
pub(super) const TRANSACTION_DIRECTORY: &str = "transaction-v1";
pub(super) const MAX_PROGRAM_BYTES: u64 = 8 * 1024 * 1024;
pub(super) const MAX_JOURNAL_GENERATION_BYTES: u64 = 2 * 1024 * 1024;
pub(super) const MAX_JOURNAL_GENERATIONS: usize = 65_536;
const JOURNAL_GENERATIONS_PER_OPERATION: usize = 4;
const JOURNAL_GENERATION_OVERHEAD: usize = 6;
pub(super) const MAX_RETAINED_CONFLICTS: usize = 8;
const JOURNAL_GENERATIONS_PER_RETAINED_CONFLICT: usize = 2;

const PROGRAM_DIGEST_DOMAIN: &[u8] = b"folderbase-mutation-program-v1";
const JOURNAL_CHECKSUM_DOMAIN: &[u8] = b"folderbase-migration-journal-generation-v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct MutationProgramV1 {
    format: String,
    transaction: TransactionFactsV1,
    root: RootFactsV1,
    scope: ScopeFactsV1,
    directories: Vec<DirectoryAuthorityV1>,
    blobs: Vec<PrivateBlobV1>,
    steps: Vec<LeafStepV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct TransactionFactsV1 {
    id: String,
    approval_scheme: String,
    approved_plan_sha256: String,
    approval_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct RootFactsV1 {
    root_identity_sha256: String,
    state_identity_sha256: String,
    root_device_sha256: String,
    path_profile: String,
    durability_profile: String,
    protocol: RootProtocolV1,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum RootProtocolV1 {
    Native {
        folderbase_id: String,
        manifest: BoundRegularV1,
    },
    Unmanaged {
        manifest: AbsentLeafV1,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ScopeFactsV1 {
    source_inventory_sha256: String,
    exclusions_sha256: String,
    source_topology_sha256: String,
    capture_ignore: CaptureIgnoreFactV1,
    manifest_policies_sha256: Option<String>,
    nested_boundaries_sha256: String,
    template_packages_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", content = "fact", rename_all = "snake_case")]
enum CaptureIgnoreFactV1 {
    Absent(AbsentLeafV1),
    Regular(BoundRegularV1),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct DirectoryAuthorityV1 {
    id: String,
    path: PathBuf,
    parent: Option<String>,
    expectation: DirectoryExpectationV1,
    nested_boundary: DirectoryBoundaryV1,
    device_sha256: String,
    case_key: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum DirectoryBoundaryV1 {
    Root,
    ProgramCreated,
    None,
    Exact,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum DirectoryExpectationV1 {
    Existing {
        physical_identity_sha256: String,
        fidelity: PortableFidelityV1,
    },
    CreatedBy {
        step_id: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct PortableFidelityV1 {
    read_only: bool,
    executable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct BoundRegularV1 {
    path: PathBuf,
    parent: String,
    physical_identity_sha256: String,
    bytes: u64,
    sha256: String,
    fidelity: PortableFidelityV1,
    link_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct AbsentLeafV1 {
    path: PathBuf,
    parent: String,
    case_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct PrivateBlobV1 {
    id: String,
    path: PathBuf,
    physical_identity_sha256: String,
    bytes: u64,
    sha256: String,
    visible_fidelity: PortableFidelityV1,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum LeafStepV1 {
    CreateDirectory {
        id: String,
        target: AbsentLeafV1,
        fidelity: PortableFidelityV1,
        rollback: CreateDirectoryRollbackV1,
        role: LeafRoleV1,
    },
    CreateFile {
        id: String,
        target: AbsentLeafV1,
        image: String,
        provenance: Option<BoundRegularV1>,
        rollback: CreateFileRollbackV1,
        role: LeafRoleV1,
    },
    ReplaceFile {
        id: String,
        target: BoundRegularV1,
        image: String,
        rollback_snapshot: String,
        role: LeafRoleV1,
    },
    MoveFile {
        id: String,
        source: BoundRegularV1,
        destination: AbsentLeafV1,
        rollback_snapshot: String,
        role: LeafRoleV1,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum CreateDirectoryRollbackV1 {
    RemoveCreatedDirectory,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum CreateFileRollbackV1 {
    RemoveCreatedFile,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum LeafRoleV1 {
    UserContent,
    AgentAdapter,
    CaptureIgnorePolicy,
    FolderbaseManifest,
    ObjectRecord,
    WorkspaceDescriptor,
    GeneratedGuidance,
    OrdinaryNarrative,
}

pub(super) struct ProgramMaterializationV1 {
    pub(super) directories: Vec<PathBuf>,
    pub(super) files: Vec<ProgramGeneratedFileV1>,
    pub(super) template_packages_sha256: String,
}

pub(super) struct ProgramGeneratedFileV1 {
    pub(super) path: PathBuf,
    pub(super) bytes: Vec<u8>,
    pub(super) role: ProgramGeneratedRoleV1,
}

pub(super) struct ProgramStepParentsV1 {
    parents: Vec<(String, VerifiedVisibleDirectory)>,
}

impl ProgramStepParentsV1 {
    pub(super) fn get(&self, id: &str) -> Result<&VerifiedVisibleDirectory> {
        self.parents
            .iter()
            .find(|(parent_id, _)| parent_id == id)
            .map(|(_, directory)| directory)
            .ok_or_else(|| invalid(Path::new("<mutation-program-v1>"), "step parent is missing"))
    }
}

#[derive(Debug, Clone, Copy)]
pub(super) enum ProgramGeneratedRoleV1 {
    AgentAdapter,
    FolderbaseManifest,
    WorkspaceDescriptor,
    GeneratedGuidance,
    OrdinaryNarrative,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct ProgramFidelityV1 {
    pub(super) read_only: bool,
    pub(super) executable: bool,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct ProgramBoundRegularV1<'a> {
    pub(super) path: &'a Path,
    pub(super) parent: &'a str,
    pub(super) physical_identity_sha256: &'a str,
    pub(super) device_sha256: &'a str,
    pub(super) bytes: u64,
    pub(super) sha256: &'a str,
    pub(super) fidelity: ProgramFidelityV1,
    pub(super) link_count: u64,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct ProgramAbsentLeafV1<'a> {
    pub(super) path: &'a Path,
    pub(super) parent: &'a str,
    pub(super) device_sha256: &'a str,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct ProgramPrivateBlobV1<'a> {
    pub(super) name: &'a OsStr,
    pub(super) directory: &'a str,
    pub(super) bytes: u64,
    pub(super) sha256: &'a str,
    pub(super) fidelity: ProgramFidelityV1,
}

#[derive(Debug, Clone)]
pub(super) struct ProgramConflictV1 {
    pub(super) operation_index: Option<usize>,
    pub(super) affected_paths: Vec<PathBuf>,
    pub(super) expected: String,
    pub(super) observed: String,
    pub(super) preserved_artifact: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy)]
pub(super) enum ProgramStepV1<'a> {
    CreateDirectory {
        target: ProgramAbsentLeafV1<'a>,
        fidelity: ProgramFidelityV1,
    },
    CreateFile {
        target: ProgramAbsentLeafV1<'a>,
        image: ProgramPrivateBlobV1<'a>,
    },
    ReplaceFile {
        target: ProgramBoundRegularV1<'a>,
        image: ProgramPrivateBlobV1<'a>,
        rollback_snapshot: ProgramPrivateBlobV1<'a>,
    },
    MoveFile {
        source: ProgramBoundRegularV1<'a>,
        destination: ProgramAbsentLeafV1<'a>,
        rollback_snapshot: ProgramPrivateBlobV1<'a>,
    },
}

impl From<&PortableFidelityV1> for ProgramFidelityV1 {
    fn from(fidelity: &PortableFidelityV1) -> Self {
        Self {
            read_only: fidelity.read_only,
            executable: fidelity.executable,
        }
    }
}

impl From<ProgramGeneratedRoleV1> for LeafRoleV1 {
    fn from(role: ProgramGeneratedRoleV1) -> Self {
        match role {
            ProgramGeneratedRoleV1::AgentAdapter => Self::AgentAdapter,
            ProgramGeneratedRoleV1::FolderbaseManifest => Self::FolderbaseManifest,
            ProgramGeneratedRoleV1::WorkspaceDescriptor => Self::WorkspaceDescriptor,
            ProgramGeneratedRoleV1::GeneratedGuidance => Self::GeneratedGuidance,
            ProgramGeneratedRoleV1::OrdinaryNarrative => Self::OrdinaryNarrative,
        }
    }
}

impl MutationProgramV1 {
    #[allow(
        clippy::too_many_arguments,
        reason = "program compilation intentionally receives each retained capability separately"
    )]
    pub(super) fn compile(
        plan: &MigrationPlan,
        approval_digest: &str,
        root_identity_sha256: String,
        filesystem: &MigrationFilesystem,
        stages: &VerifiedPrivateDirectory,
        snapshots: &VerifiedPrivateDirectory,
        materialization: ProgramMaterializationV1,
        mut replacement_bytes: impl FnMut(&MigrationOperation, &[u8]) -> Result<Vec<u8>>,
    ) -> Result<Self> {
        let transaction_root = PathBuf::from(".folderbase/migrations")
            .join(&plan.id)
            .join(TRANSACTION_DIRECTORY);
        let state = filesystem.directory_fact(Path::new(".folderbase"))?;
        let root = filesystem.directory_fact(Path::new(""))?;
        if state.device_sha256 != root.device_sha256 {
            return Err(invalid(
                Path::new(".folderbase"),
                "Folderbase state crosses the admitted root device",
            ));
        }
        let planned_directories = plan
            .operations
            .iter()
            .filter_map(|operation| match operation {
                MigrationOperation::CreateFolder { path } => Some(path.clone()),
                _ => None,
            })
            .collect::<BTreeSet<_>>();
        let template_packages_sha256 = materialization.template_packages_sha256;
        let materialization_files = materialization.files;
        let mut created_directory_paths = planned_directories.clone();
        created_directory_paths.extend(materialization.directories);
        let destinations = created_directory_paths
            .iter()
            .cloned()
            .chain(
                plan.operations
                    .iter()
                    .filter_map(operation_destination_path),
            )
            .chain(materialization_files.iter().map(|file| file.path.clone()))
            .collect::<Vec<_>>();
        for destination in destinations {
            collect_missing_destination_parents(
                filesystem,
                &destination,
                &mut created_directory_paths,
            )?;
        }
        let mut created_directory_paths = created_directory_paths.into_iter().collect::<Vec<_>>();
        created_directory_paths.sort_by(|left, right| {
            left.components()
                .count()
                .cmp(&right.components().count())
                .then_with(|| left.cmp(right))
        });
        created_directory_paths.dedup();
        let created_directories = created_directory_paths
            .iter()
            .enumerate()
            .map(|(index, path)| (path.clone(), format!("step_{index:08}")))
            .collect::<std::collections::BTreeMap<_, _>>();
        let mut directory_paths = BTreeSet::from([PathBuf::new(), PathBuf::from(".folderbase")]);
        for operation in &plan.operations {
            for path in [
                operation_source_path(operation),
                operation_destination_path(operation),
            ]
            .into_iter()
            .flatten()
            {
                collect_parent_paths(&path, &mut directory_paths);
            }
        }
        for path in created_directory_paths
            .iter()
            .chain(materialization_files.iter().map(|file| &file.path))
        {
            collect_parent_paths(path, &mut directory_paths);
        }
        let directories = compile_directory_authorities(
            filesystem,
            &directory_paths,
            &created_directories,
            &root.device_sha256,
        )?;
        let directory_ids = directories
            .iter()
            .map(|directory| (directory.path.clone(), directory.id.clone()))
            .collect::<std::collections::BTreeMap<_, _>>();

        let mut blobs = Vec::new();
        let mut steps = Vec::with_capacity(
            created_directory_paths.len()
                + plan
                    .operations
                    .iter()
                    .filter(|operation| {
                        !matches!(operation, MigrationOperation::CreateFolder { .. })
                    })
                    .count()
                + materialization_files.len(),
        );
        for path in &created_directory_paths {
            let index = steps.len();
            steps.push(LeafStepV1::CreateDirectory {
                id: format!("step_{index:08}"),
                target: absent_leaf(filesystem, path, &directory_ids)?,
                fidelity: PortableFidelityV1 {
                    read_only: false,
                    executable: true,
                },
                rollback: CreateDirectoryRollbackV1::RemoveCreatedDirectory,
                role: LeafRoleV1::UserContent,
            });
        }
        for operation in plan
            .operations
            .iter()
            .filter(|operation| !matches!(operation, MigrationOperation::CreateFolder { .. }))
        {
            let index = steps.len();
            let step_id = format!("step_{index:08}");
            let image_path = transaction_root
                .join("stages")
                .join(format!("{index:08}.stage"));
            let image_name = format!("{index:08}.stage");
            let snapshot_path = transaction_root
                .join("snapshots")
                .join(format!("{index:08}.snapshot"));
            let snapshot_name = format!("{index:08}.snapshot");
            let step = match operation {
                MigrationOperation::CreateFolder { .. } => {
                    unreachable!("directory operations are emitted parent-first")
                }
                MigrationOperation::CopyFile {
                    source_path,
                    destination_path,
                    expected_sha256,
                } => {
                    let source_fact = ensure_private_copy(
                        filesystem,
                        source_path,
                        stages,
                        &image_name,
                        expected_sha256,
                    )?;
                    let provenance = bound_regular_from_fact(
                        source_path,
                        expected_sha256,
                        source_fact,
                        &directory_ids,
                        &root.device_sha256,
                    )?;
                    let image_id = format!("blob_{index:08}_image");
                    blobs.push(private_blob(
                        stages,
                        &image_name,
                        image_id.clone(),
                        &image_path,
                        expected_sha256,
                        provenance.fidelity.clone(),
                    )?);
                    LeafStepV1::CreateFile {
                        id: step_id,
                        target: absent_leaf(filesystem, destination_path, &directory_ids)?,
                        image: image_id,
                        provenance: Some(provenance),
                        rollback: CreateFileRollbackV1::RemoveCreatedFile,
                        role: classify_leaf_role(destination_path),
                    }
                }
                MigrationOperation::MoveObject {
                    source_path,
                    destination_path,
                    expected_sha256,
                    snapshot_path: Some(legacy_snapshot_path),
                    snapshot_sha256: Some(snapshot_sha256),
                } => {
                    let source = bound_regular(
                        filesystem,
                        source_path,
                        expected_sha256,
                        &directory_ids,
                        &root.device_sha256,
                    )?;
                    if source.link_count != 1 {
                        return Err(invalid(
                            source_path,
                            "destructive move source has a hard-link alias",
                        ));
                    }
                    let _ = ensure_private_copy(
                        filesystem,
                        legacy_snapshot_path,
                        snapshots,
                        &snapshot_name,
                        snapshot_sha256,
                    )?;
                    let rollback_id = format!("blob_{index:08}_rollback");
                    blobs.push(private_blob(
                        snapshots,
                        &snapshot_name,
                        rollback_id.clone(),
                        &snapshot_path,
                        snapshot_sha256,
                        source.fidelity.clone(),
                    )?);
                    LeafStepV1::MoveFile {
                        id: step_id,
                        source,
                        destination: absent_leaf(filesystem, destination_path, &directory_ids)?,
                        rollback_snapshot: rollback_id,
                        role: classify_leaf_role(destination_path),
                    }
                }
                operation if operation.is_structural() => {
                    let source_path = operation
                        .structural_source_path()
                        .expect("structural replacement has a source");
                    let expected_source = operation
                        .structural_expected_sha256()
                        .expect("approved structural replacement has a digest");
                    let (source_fact, current) = filesystem.regular_fact_and_bytes_bounded(
                        source_path,
                        expected_source,
                        MAX_PROGRAM_BYTES,
                    )?;
                    let target = bound_regular_from_fact(
                        source_path,
                        expected_source,
                        source_fact,
                        &directory_ids,
                        &root.device_sha256,
                    )?;
                    if target.link_count != 1 {
                        return Err(invalid(
                            source_path,
                            "destructive replacement target has a hard-link alias",
                        ));
                    }
                    let result = replacement_bytes(operation, &current)?;
                    let expected_result = operation
                        .structural_expected_result_sha256()
                        .expect("approved structural replacement has a result digest");
                    if sha256(&result) != expected_result {
                        return Err(FolderbaseError::MigrationApprovalMismatch);
                    }
                    ensure_private_bytes(stages, &image_name, &result, expected_result)?;
                    let image_id = format!("blob_{index:08}_image");
                    blobs.push(private_blob(
                        stages,
                        &image_name,
                        image_id.clone(),
                        &image_path,
                        expected_result,
                        target.fidelity.clone(),
                    )?);
                    let (legacy_snapshot_path, snapshot_sha256) =
                        operation.structural_snapshot().ok_or_else(|| {
                            invalid(
                                source_path,
                                "approved structural replacement has no rollback snapshot",
                            )
                        })?;
                    let _ = ensure_private_copy(
                        filesystem,
                        legacy_snapshot_path,
                        snapshots,
                        &snapshot_name,
                        snapshot_sha256,
                    )?;
                    let rollback_id = format!("blob_{index:08}_rollback");
                    blobs.push(private_blob(
                        snapshots,
                        &snapshot_name,
                        rollback_id.clone(),
                        &snapshot_path,
                        snapshot_sha256,
                        target.fidelity.clone(),
                    )?);
                    LeafStepV1::ReplaceFile {
                        id: step_id,
                        target,
                        image: image_id,
                        rollback_snapshot: rollback_id,
                        role: classify_leaf_role(source_path),
                    }
                }
                _ => {
                    return Err(invalid(
                        Path::new("<mutation-program-v1>"),
                        "structural operation is missing its rollback snapshot",
                    ));
                }
            };
            steps.push(step);
        }
        for generated in materialization_files {
            let index = steps.len();
            let image_name = format!("{index:08}.stage");
            let image_path = transaction_root.join("stages").join(&image_name);
            let expected_sha256 = sha256(&generated.bytes);
            ensure_private_bytes(stages, &image_name, &generated.bytes, &expected_sha256)?;
            let image_id = format!("blob_{index:08}_image");
            let visible_fidelity = PortableFidelityV1 {
                read_only: false,
                executable: false,
            };
            blobs.push(private_blob(
                stages,
                &image_name,
                image_id.clone(),
                &image_path,
                &expected_sha256,
                visible_fidelity,
            )?);
            steps.push(LeafStepV1::CreateFile {
                id: format!("step_{index:08}"),
                target: absent_leaf(filesystem, &generated.path, &directory_ids)?,
                image: image_id,
                provenance: None,
                rollback: CreateFileRollbackV1::RemoveCreatedFile,
                role: generated.role.into(),
            });
        }

        let manifest_path = Path::new(".folderbase/manifest.json");
        let (protocol, manifest_policies_sha256) = if filesystem.metadata(manifest_path)?.is_some()
        {
            let manifest_digest = filesystem.sha256_regular(manifest_path)?;
            let (manifest_fact, manifest_bytes) = filesystem.regular_fact_and_bytes_bounded(
                manifest_path,
                &manifest_digest,
                MAX_PROGRAM_BYTES,
            )?;
            let manifest = bound_regular_from_fact(
                manifest_path,
                &manifest_digest,
                manifest_fact,
                &directory_ids,
                &root.device_sha256,
            )?;
            let manifest_json: serde_json::Value = serde_json::from_slice(&manifest_bytes)
                .map_err(|source| {
                    FolderbaseError::json(filesystem.display(manifest_path), source)
                })?;
            let folderbase_id = manifest_json
                .pointer("/folderbase/id")
                .and_then(serde_json::Value::as_str)
                .filter(|id| !id.is_empty())
                .ok_or_else(|| invalid(manifest_path, "manifest has no folderbase identity"))?
                .to_owned();
            (
                RootProtocolV1::Native {
                    folderbase_id,
                    manifest,
                },
                manifest_json
                    .get("policies")
                    .map(canonical_sha256)
                    .transpose()?,
            )
        } else {
            (
                RootProtocolV1::Unmanaged {
                    manifest: absent_leaf(filesystem, manifest_path, &directory_ids)?,
                },
                None,
            )
        };
        let capture_ignore_path = Path::new(".folderbaseignore");
        let capture_ignore = match filesystem.metadata(capture_ignore_path)? {
            None => CaptureIgnoreFactV1::Absent(absent_leaf(
                filesystem,
                capture_ignore_path,
                &directory_ids,
            )?),
            Some(_) => {
                let digest = filesystem.sha256_regular(capture_ignore_path)?;
                CaptureIgnoreFactV1::Regular(bound_regular(
                    filesystem,
                    capture_ignore_path,
                    &digest,
                    &directory_ids,
                    &root.device_sha256,
                )?)
            }
        };
        let source_topology = plan
            .extensions
            .get(super::SOURCE_TOPOLOGY_EXTENSION)
            .ok_or_else(|| {
                invalid(
                    Path::new("<mutation-program-v1>"),
                    "approved plan has no source-topology fact",
                )
            })?;
        let nested_boundaries = source_topology.get("nested_folderbases").ok_or_else(|| {
            invalid(
                Path::new("<mutation-program-v1>"),
                "source topology has no nested-boundary fact",
            )
        })?;
        let program = Self {
            format: PROGRAM_FORMAT.to_owned(),
            transaction: TransactionFactsV1 {
                id: plan.id.clone(),
                approval_scheme: "migration_plan_v0.2".to_owned(),
                approved_plan_sha256: approval_digest.to_owned(),
                approval_sha256: approval_digest.to_owned(),
            },
            root: RootFactsV1 {
                root_identity_sha256,
                state_identity_sha256: state.physical_identity_sha256,
                root_device_sha256: root.device_sha256,
                path_profile: "folderbase-portable-path-v1".to_owned(),
                durability_profile: durability_profile().to_owned(),
                protocol,
            },
            scope: ScopeFactsV1 {
                source_inventory_sha256: plan.source_inventory.digest.clone(),
                exclusions_sha256: canonical_sha256(&plan.exclusions)?,
                source_topology_sha256: canonical_sha256(source_topology)?,
                capture_ignore,
                manifest_policies_sha256,
                nested_boundaries_sha256: canonical_sha256(nested_boundaries)?,
                template_packages_sha256,
            },
            directories,
            blobs,
            steps,
        };
        program.validate()?;
        Ok(program)
    }

    pub(super) fn decode(path: &Path, bytes: &[u8]) -> Result<Self> {
        if bytes.len() as u64 > MAX_PROGRAM_BYTES {
            return Err(invalid(path, "mutation program exceeds its byte bound"));
        }
        let program: Self =
            serde_json::from_slice(bytes).map_err(|source| FolderbaseError::json(path, source))?;
        program.validate()?;
        if program.encode(path)? != bytes {
            return Err(invalid(
                path,
                "mutation program is not the exact canonical admitted encoding",
            ));
        }
        Ok(program)
    }

    pub(super) fn encode(&self, path: &Path) -> Result<Vec<u8>> {
        self.validate()?;
        let bytes =
            serde_json::to_vec(self).map_err(|source| FolderbaseError::json(path, source))?;
        if bytes.len() as u64 > MAX_PROGRAM_BYTES {
            return Err(invalid(path, "mutation program exceeds its byte bound"));
        }
        Ok(bytes)
    }

    pub(super) fn digest(&self, path: &Path) -> Result<String> {
        let bytes = self.encode(path)?;
        let mut digest = Sha256::new();
        digest.update(PROGRAM_DIGEST_DOMAIN);
        digest.update([0]);
        digest.update(bytes);
        Ok(format!("{:x}", digest.finalize()))
    }

    pub(super) fn transaction_id(&self) -> &str {
        &self.transaction.id
    }

    pub(super) fn approval_digest(&self) -> &str {
        &self.transaction.approval_sha256
    }

    pub(super) fn matches_approval(
        &self,
        transaction_id: &str,
        approval_sha256: &str,
        root_identity_sha256: &str,
    ) -> bool {
        self.transaction.id == transaction_id
            && self.transaction.approval_scheme == "migration_plan_v0.2"
            && self.transaction.approval_sha256 == approval_sha256
            && self.transaction.approved_plan_sha256 == approval_sha256
            && self.root.root_identity_sha256 == root_identity_sha256
    }

    pub(super) fn operation_count(&self) -> usize {
        self.steps.len()
    }

    pub(super) fn step(&self, index: usize) -> Result<ProgramStepV1<'_>> {
        let step = self
            .steps
            .get(index)
            .ok_or_else(|| invalid(Path::new("<mutation-program-v1>"), "step is out of bounds"))?;
        Ok(match step {
            LeafStepV1::CreateDirectory {
                target, fidelity, ..
            } => ProgramStepV1::CreateDirectory {
                target: self.absent_view(target),
                fidelity: fidelity.into(),
            },
            LeafStepV1::CreateFile { target, image, .. } => ProgramStepV1::CreateFile {
                target: self.absent_view(target),
                image: self.blob_view(image)?,
            },
            LeafStepV1::ReplaceFile {
                target,
                image,
                rollback_snapshot,
                ..
            } => ProgramStepV1::ReplaceFile {
                target: self.bound_regular_view(target),
                image: self.blob_view(image)?,
                rollback_snapshot: self.blob_view(rollback_snapshot)?,
            },
            LeafStepV1::MoveFile {
                source,
                destination,
                rollback_snapshot,
                ..
            } => ProgramStepV1::MoveFile {
                source: self.bound_regular_view(source),
                destination: self.absent_view(destination),
                rollback_snapshot: self.blob_view(rollback_snapshot)?,
            },
        })
    }

    fn bound_regular_view<'a>(&'a self, bound: &'a BoundRegularV1) -> ProgramBoundRegularV1<'a> {
        ProgramBoundRegularV1 {
            path: &bound.path,
            parent: &bound.parent,
            physical_identity_sha256: &bound.physical_identity_sha256,
            device_sha256: &self.root.root_device_sha256,
            bytes: bound.bytes,
            sha256: &bound.sha256,
            fidelity: (&bound.fidelity).into(),
            link_count: bound.link_count,
        }
    }

    fn absent_view<'a>(&'a self, absent: &'a AbsentLeafV1) -> ProgramAbsentLeafV1<'a> {
        ProgramAbsentLeafV1 {
            path: &absent.path,
            parent: &absent.parent,
            device_sha256: &self.root.root_device_sha256,
        }
    }

    pub(super) fn created_paths(&self) -> Vec<PathBuf> {
        self.steps
            .iter()
            .filter_map(|step| match step {
                LeafStepV1::CreateDirectory { target, .. }
                | LeafStepV1::CreateFile { target, .. } => Some(target.path.clone()),
                LeafStepV1::MoveFile { destination, .. } => Some(destination.path.clone()),
                LeafStepV1::ReplaceFile { .. } => None,
            })
            .collect()
    }

    pub(super) fn validate_step_parents(
        &self,
        filesystem: &MigrationFilesystem,
        index: usize,
        generation: &TransactionJournalGenerationV1,
    ) -> Result<()> {
        let _ = self.retain_step_parents(filesystem, index, generation)?;
        Ok(())
    }

    fn step_owns_created_boundary(&self, index: usize, root: &Path) -> Result<bool> {
        let step = self
            .steps
            .get(index)
            .ok_or_else(|| invalid(Path::new("<mutation-program-v1>"), "step is out of bounds"))?;
        let path = step_visible_path(step);
        Ok(path == root.join(".folderbase")
            || path == root.join(".folderbase").join("manifest.json"))
    }

    fn receipt_derived_boundary<'a>(
        &'a self,
        authority: &'a DirectoryAuthorityV1,
        generation: &'a TransactionJournalGenerationV1,
    ) -> Result<ExactNestedBoundaryExpectation<'a>> {
        let state_path = authority.path.join(".folderbase");
        let manifest_path = state_path.join("manifest.json");
        let state_step = self
            .steps
            .iter()
            .enumerate()
            .find_map(|(index, step)| match step {
                LeafStepV1::CreateDirectory {
                    target, fidelity, ..
                } if target.path == state_path => Some((index, fidelity)),
                _ => None,
            });
        let manifest_step = self
            .steps
            .iter()
            .enumerate()
            .find_map(|(index, step)| match step {
                LeafStepV1::CreateFile {
                    target,
                    image,
                    role: LeafRoleV1::FolderbaseManifest,
                    ..
                } if target.path == manifest_path => Some((index, image.as_str())),
                _ => None,
            });
        if state_step.is_none() && manifest_step.is_some() {
            return Err(invalid(
                &manifest_path,
                "program-created manifest has no state-directory owner",
            ));
        }

        let active_identity = |step_index: usize| {
            (!generation.has_inverse_receipt(step_index))
                .then(|| generation.receipt_identity(step_index))
                .flatten()
        };
        let active_state = state_step.and_then(|(step_index, fidelity)| {
            active_identity(step_index).map(|identity| (identity, fidelity))
        });
        let active_manifest = manifest_step.and_then(|(step_index, image)| {
            active_identity(step_index).map(|identity| (identity, image))
        });
        match (active_state, active_manifest) {
            (None, None) => Ok(ExactNestedBoundaryExpectation::None),
            (Some((state_identity, state_fidelity)), None) => {
                Ok(ExactNestedBoundaryExpectation::StateOnly {
                    state: ExactDirectoryLeaf {
                        physical_identity_sha256: state_identity,
                        device_sha256: &authority.device_sha256,
                        read_only: state_fidelity.read_only,
                        executable: state_fidelity.executable,
                    },
                })
            }
            (Some((state_identity, state_fidelity)), Some((manifest_identity, image))) => {
                let blob = self
                    .blobs
                    .iter()
                    .find(|blob| blob.id == image)
                    .ok_or_else(|| {
                        invalid(
                            Path::new("<mutation-program-v1>"),
                            "program-created manifest image is missing",
                        )
                    })?;
                Ok(ExactNestedBoundaryExpectation::Exact {
                    state: ExactDirectoryLeaf {
                        physical_identity_sha256: state_identity,
                        device_sha256: &authority.device_sha256,
                        read_only: state_fidelity.read_only,
                        executable: state_fidelity.executable,
                    },
                    manifest: ExactRegularLeaf {
                        physical_identity_sha256: manifest_identity,
                        device_sha256: &authority.device_sha256,
                        bytes: blob.bytes,
                        sha256: &blob.sha256,
                        read_only: blob.visible_fidelity.read_only,
                        executable: blob.visible_fidelity.executable,
                        link_count: 2,
                    },
                })
            }
            (None, Some(_)) => Err(invalid(
                &manifest_path,
                "active program-created manifest has no active state directory",
            )),
        }
    }

    fn validate_retained_directory_boundary(
        &self,
        filesystem: &MigrationFilesystem,
        index: usize,
        authority: &DirectoryAuthorityV1,
        generation: &TransactionJournalGenerationV1,
        directory: &VerifiedVisibleDirectory,
    ) -> Result<()> {
        let boundary_matches = match authority.nested_boundary {
            DirectoryBoundaryV1::Root => true,
            DirectoryBoundaryV1::ProgramCreated => {
                if self.step_owns_created_boundary(index, &authority.path)? {
                    true
                } else {
                    directory.require_exact_nested_boundary(
                        self.receipt_derived_boundary(authority, generation)?,
                    )?;
                    true
                }
            }
            DirectoryBoundaryV1::None => {
                directory.nested_boundary_kind()? == NestedFolderbaseBoundaryKind::None
            }
            DirectoryBoundaryV1::Exact => {
                directory.nested_boundary_kind()? == NestedFolderbaseBoundaryKind::ExactBoundary
            }
        };
        if !boundary_matches {
            return Err(FolderbaseError::MigrationSourceChanged(
                filesystem.display(&authority.path),
            ));
        }
        Ok(())
    }

    pub(super) fn validate_retained_step_parents(
        &self,
        filesystem: &MigrationFilesystem,
        index: usize,
        generation: &TransactionJournalGenerationV1,
        retained: &ProgramStepParentsV1,
    ) -> Result<()> {
        for (parent_id, directory) in &retained.parents {
            let authority = self
                .directories
                .iter()
                .find(|authority| authority.id == *parent_id)
                .ok_or_else(|| invalid(Path::new("<mutation-program-v1>"), "parent is missing"))?;
            self.validate_retained_directory_boundary(
                filesystem, index, authority, generation, directory,
            )?;
        }
        Ok(())
    }

    pub(super) fn retain_step_parents(
        &self,
        filesystem: &MigrationFilesystem,
        index: usize,
        generation: &TransactionJournalGenerationV1,
    ) -> Result<ProgramStepParentsV1> {
        let step = self
            .steps
            .get(index)
            .ok_or_else(|| invalid(Path::new("<mutation-program-v1>"), "step is out of bounds"))?;
        let mut parent_ids = match step {
            LeafStepV1::CreateDirectory { target, .. } | LeafStepV1::CreateFile { target, .. } => {
                vec![target.parent.as_str()]
            }
            LeafStepV1::ReplaceFile { target, .. } => vec![target.parent.as_str()],
            LeafStepV1::MoveFile {
                source,
                destination,
                ..
            } => vec![source.parent.as_str(), destination.parent.as_str()],
        };
        let mut cursor = 0;
        while cursor < parent_ids.len() {
            let authority = self
                .directories
                .iter()
                .find(|directory| directory.id == parent_ids[cursor])
                .ok_or_else(|| invalid(Path::new("<mutation-program-v1>"), "parent is missing"))?;
            if let Some(parent_id) = authority.parent.as_deref()
                && !parent_ids.contains(&parent_id)
            {
                parent_ids.push(parent_id);
            }
            cursor += 1;
        }
        let mut retained = Vec::with_capacity(parent_ids.len());
        for parent_id in parent_ids {
            let authority = self
                .directories
                .iter()
                .find(|directory| directory.id == parent_id)
                .ok_or_else(|| invalid(Path::new("<mutation-program-v1>"), "parent is missing"))?;
            let expected_identity = match &authority.expectation {
                DirectoryExpectationV1::Existing {
                    physical_identity_sha256,
                    ..
                } => physical_identity_sha256,
                DirectoryExpectationV1::CreatedBy { step_id } => {
                    let creator_index = self
                        .steps
                        .iter()
                        .position(|step| match step {
                            LeafStepV1::CreateDirectory { id, .. }
                            | LeafStepV1::CreateFile { id, .. }
                            | LeafStepV1::ReplaceFile { id, .. }
                            | LeafStepV1::MoveFile { id, .. } => id == step_id,
                        })
                        .ok_or_else(|| {
                            invalid(
                                Path::new("<mutation-program-v1>"),
                                "created parent step is missing",
                            )
                        })?;
                    generation.receipt_identity(creator_index).ok_or_else(|| {
                        invalid(
                            Path::new("<migration-journal-v1>"),
                            "created parent has no durable published identity",
                        )
                    })?
                }
            };
            let fidelity = match &authority.expectation {
                DirectoryExpectationV1::Existing { fidelity, .. } => fidelity.clone(),
                DirectoryExpectationV1::CreatedBy { .. } => PortableFidelityV1 {
                    read_only: false,
                    executable: true,
                },
            };
            let directory = filesystem.retain_verified_directory(
                &authority.path,
                expected_identity,
                &authority.device_sha256,
                fidelity.read_only,
                fidelity.executable,
            )?;
            self.validate_retained_directory_boundary(
                filesystem, index, authority, generation, &directory,
            )?;
            retained.push((authority.id.clone(), directory));
        }
        Ok(ProgramStepParentsV1 { parents: retained })
    }

    fn blob_view(&self, id: &str) -> Result<ProgramPrivateBlobV1<'_>> {
        let blob = self
            .blobs
            .iter()
            .find(|blob| blob.id == id)
            .ok_or_else(|| invalid(Path::new("<mutation-program-v1>"), "blob is missing"))?;
        Ok(ProgramPrivateBlobV1 {
            name: blob
                .path
                .file_name()
                .ok_or_else(|| invalid(&blob.path, "blob has no file name"))?,
            directory: blob
                .path
                .parent()
                .and_then(Path::file_name)
                .and_then(OsStr::to_str)
                .ok_or_else(|| invalid(&blob.path, "blob has no private directory"))?,
            bytes: blob.bytes,
            sha256: &blob.sha256,
            fidelity: (&blob.visible_fidelity).into(),
        })
    }

    pub(super) fn maximum_journal_generations(&self) -> usize {
        self.steps
            .len()
            .saturating_mul(JOURNAL_GENERATIONS_PER_OPERATION)
            .saturating_add(JOURNAL_GENERATION_OVERHEAD)
            .saturating_add(
                MAX_RETAINED_CONFLICTS.saturating_mul(JOURNAL_GENERATIONS_PER_RETAINED_CONFLICT),
            )
            .min(MAX_JOURNAL_GENERATIONS)
    }

    pub(super) fn allowed_private_file_names(&self, directory: &str) -> BTreeSet<OsString> {
        match directory {
            "stages" | "snapshots" => self
                .blobs
                .iter()
                .filter(|blob| {
                    blob.path.parent().and_then(Path::file_name) == Some(directory.as_ref())
                })
                .filter_map(|blob| blob.path.file_name().map(OsString::from))
                .collect(),
            "claims" => (0..self.steps.len())
                .flat_map(|index| {
                    ["source", "publish", "rollback", "restore"]
                        .into_iter()
                        .flat_map(move |kind| {
                            let claim = format!("{index:08}.{kind}.claim");
                            [
                                OsString::from(&claim),
                                OsString::from(format!(".{claim}.preparing")),
                            ]
                        })
                })
                .collect(),
            "receipts" => (0..self.steps.len())
                .flat_map(|index| {
                    [
                        OsString::from(format!("{index:08}.apply.receipt")),
                        OsString::from(format!("{index:08}.rollback.receipt")),
                        OsString::from(format!("{index:08}.abort.receipt")),
                    ]
                })
                .collect(),
            _ => BTreeSet::new(),
        }
    }

    pub(super) fn validate_private_blobs(
        &self,
        stages: &VerifiedPrivateDirectory,
        snapshots: &VerifiedPrivateDirectory,
    ) -> Result<()> {
        for blob in &self.blobs {
            let directory = blob
                .path
                .parent()
                .and_then(Path::file_name)
                .and_then(OsStr::to_str)
                .ok_or_else(|| {
                    invalid(&blob.path, "private blob path has no admitted directory")
                })?;
            let private = match directory {
                "stages" => stages,
                "snapshots" => snapshots,
                _ => return Err(invalid(&blob.path, "private blob directory is invalid")),
            };
            let name = blob
                .path
                .file_name()
                .ok_or_else(|| invalid(&blob.path, "private blob path has no file name"))?;
            let fact = private.regular_fact(name, &blob.sha256)?;
            if fact.physical_identity_sha256 != blob.physical_identity_sha256
                || fact.bytes != blob.bytes
                || fact.link_count != 1
            {
                return Err(FolderbaseError::MigrationVerificationFailed(
                    blob.path.clone(),
                ));
            }
        }
        Ok(())
    }

    pub(super) fn validate_root_and_state(&self, filesystem: &MigrationFilesystem) -> Result<()> {
        let root = filesystem.directory_fact(Path::new(""))?;
        let state = filesystem.directory_fact(Path::new(".folderbase"))?;
        if root.physical_identity_sha256 != self.root.root_identity_sha256
            || root.device_sha256 != self.root.root_device_sha256
            || state.physical_identity_sha256 != self.root.state_identity_sha256
            || state.device_sha256 != self.root.root_device_sha256
        {
            return Err(FolderbaseError::MigrationSourceChanged(
                filesystem.display_root().to_path_buf(),
            ));
        }
        Ok(())
    }

    pub(super) fn validate_initial_environment_leaf(
        &self,
        filesystem: &MigrationFilesystem,
        path: &Path,
    ) -> Result<()> {
        if path == Path::new(".folderbase/manifest.json") {
            return match &self.root.protocol {
                RootProtocolV1::Native { manifest, .. } => {
                    if bound_regular_matches(filesystem, manifest)? {
                        Ok(())
                    } else {
                        Err(FolderbaseError::MigrationSourceChanged(
                            filesystem.display(&manifest.path),
                        ))
                    }
                }
                RootProtocolV1::Unmanaged { manifest } => {
                    if filesystem.metadata(&manifest.path)?.is_none() {
                        Ok(())
                    } else {
                        Err(FolderbaseError::WouldOverwrite(
                            filesystem.display(&manifest.path),
                        ))
                    }
                }
            };
        }
        if path == Path::new(".folderbaseignore") {
            return match &self.scope.capture_ignore {
                CaptureIgnoreFactV1::Absent(absent) => require_absent(filesystem, absent),
                CaptureIgnoreFactV1::Regular(regular) => {
                    if bound_regular_matches(filesystem, regular)? {
                        Ok(())
                    } else {
                        Err(FolderbaseError::MigrationSourceChanged(
                            filesystem.display(path),
                        ))
                    }
                }
            };
        }
        Err(invalid(
            path,
            "requested immutable environment leaf is not admitted",
        ))
    }

    pub(super) fn validate_immutable_environment(
        &self,
        filesystem: &MigrationFilesystem,
    ) -> Result<()> {
        self.validate_root_and_state(filesystem)?;
        self.validate_initial_environment_leaf(filesystem, Path::new(".folderbase/manifest.json"))?;
        self.validate_initial_environment_leaf(filesystem, Path::new(".folderbaseignore"))?;
        Ok(())
    }

    pub(super) fn validate_prepared_environment(
        &self,
        filesystem: &MigrationFilesystem,
    ) -> Result<()> {
        self.validate_immutable_environment(filesystem)?;
        for directory in &self.directories {
            match &directory.expectation {
                DirectoryExpectationV1::Existing {
                    physical_identity_sha256,
                    fidelity,
                } => {
                    let current = filesystem.directory_fact(&directory.path)?;
                    if current.physical_identity_sha256 != *physical_identity_sha256
                        || current.device_sha256 != directory.device_sha256
                        || directory_fidelity(&current)? != *fidelity
                    {
                        return Err(FolderbaseError::MigrationSourceChanged(
                            filesystem.display(&directory.path),
                        ));
                    }
                }
                DirectoryExpectationV1::CreatedBy { .. } => {
                    if filesystem.metadata(&directory.path)?.is_some() {
                        return Err(FolderbaseError::WouldOverwrite(
                            filesystem.display(&directory.path),
                        ));
                    }
                }
            }
        }
        for step in &self.steps {
            match step {
                LeafStepV1::CreateDirectory { target, .. } => {
                    require_absent(filesystem, target)?;
                }
                LeafStepV1::CreateFile {
                    target, provenance, ..
                } => {
                    require_absent(filesystem, target)?;
                    if let Some(source) = provenance
                        && !bound_regular_matches(filesystem, source)?
                    {
                        return Err(FolderbaseError::MigrationSourceChanged(
                            filesystem.display(&source.path),
                        ));
                    }
                }
                LeafStepV1::ReplaceFile { target, .. } => {
                    if !bound_regular_matches(filesystem, target)? {
                        return Err(FolderbaseError::MigrationSourceChanged(
                            filesystem.display(&target.path),
                        ));
                    }
                }
                LeafStepV1::MoveFile {
                    source,
                    destination,
                    ..
                } => {
                    if !bound_regular_matches(filesystem, source)? {
                        return Err(FolderbaseError::MigrationSourceChanged(
                            filesystem.display(&source.path),
                        ));
                    }
                    require_absent(filesystem, destination)?;
                }
            }
        }
        Ok(())
    }

    fn validate(&self) -> Result<()> {
        let path = Path::new("<mutation-program-v1>");
        let journal_generation_bound = self
            .steps
            .len()
            .checked_mul(JOURNAL_GENERATIONS_PER_OPERATION)
            .and_then(|count| count.checked_add(JOURNAL_GENERATION_OVERHEAD))
            .and_then(|count| {
                MAX_RETAINED_CONFLICTS
                    .checked_mul(JOURNAL_GENERATIONS_PER_RETAINED_CONFLICT)
                    .and_then(|conflict_count| count.checked_add(conflict_count))
            });
        if self.format != PROGRAM_FORMAT
            || !self.transaction.id.starts_with("migration_")
            || self.transaction.approval_scheme != "migration_plan_v0.2"
            || !is_sha256(&self.transaction.approved_plan_sha256)
            || !is_sha256(&self.transaction.approval_sha256)
            || self.transaction.approved_plan_sha256 != self.transaction.approval_sha256
            || !is_sha256(&self.root.root_identity_sha256)
            || !is_sha256(&self.root.state_identity_sha256)
            || !is_sha256(&self.root.root_device_sha256)
            || self.root.path_profile != "folderbase-portable-path-v1"
            || self.root.durability_profile != durability_profile()
            || !scope_is_valid(&self.scope)
            || journal_generation_bound.is_none_or(|count| count > MAX_JOURNAL_GENERATIONS)
        {
            return Err(invalid(path, "mutation program metadata is inconsistent"));
        }
        validate_program_facts(self, path)
    }
}

fn collect_parent_paths(path: &Path, paths: &mut BTreeSet<PathBuf>) {
    let mut current = path.parent();
    while let Some(parent) = current {
        paths.insert(parent.to_path_buf());
        if parent.as_os_str().is_empty() {
            break;
        }
        current = parent.parent();
    }
}

fn collect_missing_destination_parents(
    filesystem: &MigrationFilesystem,
    destination: &Path,
    created_directories: &mut BTreeSet<PathBuf>,
) -> Result<()> {
    if !safe_relative(destination) {
        return Err(invalid(
            destination,
            "mutation destination is not a safe relative path",
        ));
    }
    let mut current = destination.parent();
    while let Some(parent) = current {
        if parent.as_os_str().is_empty() {
            break;
        }
        if !created_directories.contains(parent) {
            match filesystem.metadata(parent)? {
                Some(metadata) if !metadata.is_dir() || metadata.file_type().is_symlink() => {
                    return Err(invalid(
                        parent,
                        "mutation destination parent is not a regular directory",
                    ));
                }
                Some(_) => {}
                None => {
                    created_directories.insert(parent.to_path_buf());
                }
            }
        }
        current = parent.parent();
    }
    Ok(())
}

fn compile_directory_authorities(
    filesystem: &MigrationFilesystem,
    paths: &BTreeSet<PathBuf>,
    created_directories: &std::collections::BTreeMap<PathBuf, String>,
    root_device_sha256: &str,
) -> Result<Vec<DirectoryAuthorityV1>> {
    let mut ordered = paths.iter().cloned().collect::<Vec<_>>();
    for path in created_directories.keys() {
        if !ordered.contains(path) {
            ordered.push(path.clone());
        }
    }
    ordered.sort_by(|left, right| {
        left.components()
            .count()
            .cmp(&right.components().count())
            .then_with(|| left.cmp(right))
    });
    ordered.dedup();
    let mut authorities = Vec::<DirectoryAuthorityV1>::with_capacity(ordered.len());
    for path in ordered {
        let parent_path = (!path.as_os_str().is_empty())
            .then(|| path.parent().unwrap_or_else(|| Path::new("")).to_path_buf());
        let parent = parent_path.as_ref().map(|parent| directory_id(parent));
        let (expectation, nested_boundary, device_sha256) =
            if let Some(step_id) = created_directories.get(&path) {
                let device = parent_path
                    .as_ref()
                    .and_then(|parent| {
                        authorities
                            .iter()
                            .find(|authority| &authority.path == parent)
                    })
                    .map(|authority| authority.device_sha256.clone())
                    .ok_or_else(|| {
                        invalid(&path, "created directory has no admitted parent authority")
                    })?;
                (
                    DirectoryExpectationV1::CreatedBy {
                        step_id: step_id.clone(),
                    },
                    DirectoryBoundaryV1::ProgramCreated,
                    device,
                )
            } else {
                let fact = filesystem.directory_fact(&path)?;
                if fact.device_sha256 != root_device_sha256 {
                    return Err(invalid(
                        &path,
                        "directory authority crosses the admitted root device",
                    ));
                }
                let fidelity = directory_fidelity(&fact)?;
                let nested_boundary = if path.as_os_str().is_empty() {
                    DirectoryBoundaryV1::Root
                } else {
                    match filesystem
                        .retain_verified_directory(
                            &path,
                            &fact.physical_identity_sha256,
                            &fact.device_sha256,
                            fidelity.read_only,
                            fidelity.executable,
                        )?
                        .nested_boundary_kind()?
                    {
                        NestedFolderbaseBoundaryKind::None => DirectoryBoundaryV1::None,
                        NestedFolderbaseBoundaryKind::ExactBoundary => DirectoryBoundaryV1::Exact,
                        NestedFolderbaseBoundaryKind::UnsafeAliasShape => {
                            return Err(invalid(
                                &path,
                                "directory authority has an unsafe nested-boundary shape",
                            ));
                        }
                    }
                };
                (
                    DirectoryExpectationV1::Existing {
                        physical_identity_sha256: fact.physical_identity_sha256,
                        fidelity,
                    },
                    nested_boundary,
                    fact.device_sha256,
                )
            };
        authorities.push(DirectoryAuthorityV1 {
            id: directory_id(&path),
            path: path.clone(),
            parent,
            expectation,
            nested_boundary,
            device_sha256,
            case_key: portable_case_key(&path),
        });
    }
    Ok(authorities)
}

fn directory_id(path: &Path) -> String {
    format!(
        "dir_{}",
        domain_sha256(
            b"folderbase-directory-v1",
            portable_case_key(path).as_bytes()
        )
    )
}

fn bound_regular(
    filesystem: &MigrationFilesystem,
    path: &Path,
    expected_sha256: &str,
    directory_ids: &std::collections::BTreeMap<PathBuf, String>,
    root_device_sha256: &str,
) -> Result<BoundRegularV1> {
    let fact = filesystem.regular_fact_with_sha256(path, Some(expected_sha256))?;
    bound_regular_from_fact(
        path,
        expected_sha256,
        fact,
        directory_ids,
        root_device_sha256,
    )
}

fn bound_regular_from_fact(
    path: &Path,
    expected_sha256: &str,
    fact: MigrationRegularFact,
    directory_ids: &std::collections::BTreeMap<PathBuf, String>,
    root_device_sha256: &str,
) -> Result<BoundRegularV1> {
    if fact.device_sha256 != root_device_sha256 {
        return Err(invalid(
            path,
            "regular-file fact crosses the admitted root device",
        ));
    }
    let fidelity = regular_fidelity(&fact)?;
    let parent_path = path.parent().unwrap_or_else(|| Path::new(""));
    let parent = directory_ids.get(parent_path).cloned().ok_or_else(|| {
        invalid(
            path,
            "regular-file fact has no admitted parent directory authority",
        )
    })?;
    Ok(BoundRegularV1 {
        path: path.to_path_buf(),
        parent,
        physical_identity_sha256: fact.physical_identity_sha256,
        bytes: fact.bytes,
        sha256: expected_sha256.to_owned(),
        fidelity,
        link_count: fact.link_count,
    })
}

fn bound_regular_matches(
    filesystem: &MigrationFilesystem,
    expected: &BoundRegularV1,
) -> Result<bool> {
    let current = filesystem.regular_fact_with_sha256(&expected.path, Some(&expected.sha256))?;
    Ok(
        current.physical_identity_sha256 == expected.physical_identity_sha256
            && current.bytes == expected.bytes
            && current.link_count == expected.link_count
            && current.device_sha256
                == filesystem
                    .directory_fact(expected.path.parent().unwrap_or_else(|| Path::new("")))?
                    .device_sha256
            && regular_fidelity(&current)? == expected.fidelity,
    )
}

fn require_absent(filesystem: &MigrationFilesystem, expected: &AbsentLeafV1) -> Result<()> {
    require_portable_absence(filesystem, &expected.path)
}

fn require_portable_absence(filesystem: &MigrationFilesystem, path: &Path) -> Result<()> {
    if filesystem.metadata(path)?.is_some() {
        return Err(FolderbaseError::WouldOverwrite(filesystem.display(path)));
    }
    let parent = path.parent().unwrap_or_else(|| Path::new(""));
    if parent.as_os_str().is_empty() || filesystem.metadata(parent)?.is_some() {
        let expected_case_key = portable_leaf_case_key(path);
        if filesystem
            .directory_entry_names(parent, 65_536)?
            .iter()
            .any(|name| portable_leaf_case_key(Path::new(name)) == expected_case_key)
        {
            return Err(FolderbaseError::WouldOverwrite(filesystem.display(path)));
        }
    }
    Ok(())
}

fn absent_leaf(
    filesystem: &MigrationFilesystem,
    path: &Path,
    directory_ids: &std::collections::BTreeMap<PathBuf, String>,
) -> Result<AbsentLeafV1> {
    require_portable_absence(filesystem, path)?;
    let parent_path = path.parent().unwrap_or_else(|| Path::new(""));
    let parent = directory_ids.get(parent_path).cloned().ok_or_else(|| {
        invalid(
            path,
            "absent leaf has no admitted parent directory authority",
        )
    })?;
    Ok(AbsentLeafV1 {
        path: path.to_path_buf(),
        parent,
        case_key: portable_leaf_case_key(path),
    })
}

fn directory_fidelity(fact: &MigrationDirectoryFact) -> Result<PortableFidelityV1> {
    fidelity_from_fact(fact.read_only, true, fact.unix_mode)
}

fn regular_fidelity(fact: &MigrationRegularFact) -> Result<PortableFidelityV1> {
    fidelity_from_fact(fact.read_only, false, fact.unix_mode)
}

fn fidelity_from_fact(
    read_only: bool,
    executable_without_unix_mode: bool,
    mode: Option<u32>,
) -> Result<PortableFidelityV1> {
    if mode.is_some_and(|mode| mode & 0o7000 != 0) {
        return Err(invalid(
            Path::new("<mutation-program-v1>"),
            "setuid, setgid, and sticky fidelity is unsupported",
        ));
    }
    Ok(PortableFidelityV1 {
        read_only,
        executable: mode.map_or(executable_without_unix_mode, |mode| mode & 0o111 != 0),
    })
}

fn ensure_private_copy(
    filesystem: &MigrationFilesystem,
    source: &Path,
    destination: &VerifiedPrivateDirectory,
    destination_name: &str,
    expected_sha256: &str,
) -> Result<MigrationRegularFact> {
    filesystem.stage_regular_private(source, destination, destination_name, expected_sha256)
}

fn ensure_private_bytes(
    destination: &VerifiedPrivateDirectory,
    destination_name: &str,
    bytes: &[u8],
    expected_sha256: &str,
) -> Result<()> {
    if sha256(bytes) != expected_sha256 {
        return Err(FolderbaseError::MigrationApprovalMismatch);
    }
    let staging_name = format!(".{destination_name}.preparing");
    destination.publish_recoverable_new(destination_name, &staging_name, bytes)
}

fn private_blob(
    directory: &VerifiedPrivateDirectory,
    file_name: &str,
    id: String,
    path: &Path,
    expected_sha256: &str,
    visible_fidelity: PortableFidelityV1,
) -> Result<PrivateBlobV1> {
    let fact = directory.regular_fact(file_name.as_ref(), expected_sha256)?;
    Ok(PrivateBlobV1 {
        id,
        path: path.to_path_buf(),
        physical_identity_sha256: fact.physical_identity_sha256,
        bytes: fact.bytes,
        sha256: expected_sha256.to_owned(),
        visible_fidelity,
    })
}

fn classify_leaf_role(path: &Path) -> LeafRoleV1 {
    match path.file_name().and_then(|name| name.to_str()) {
        Some("AGENTS.md" | "CLAUDE.md") => LeafRoleV1::AgentAdapter,
        Some(".folderbaseignore") => LeafRoleV1::CaptureIgnorePolicy,
        Some("manifest.json") if path.starts_with(".folderbase") => LeafRoleV1::FolderbaseManifest,
        Some(".folderbase-workspace.json") => LeafRoleV1::WorkspaceDescriptor,
        Some("FOLDERBASE.md" | "SUMMARY.md" | "QUESTIONS.md") => LeafRoleV1::OrdinaryNarrative,
        Some(_) if path.starts_with(".folderbase/objects") => LeafRoleV1::ObjectRecord,
        Some("WORKSPACE.md") => LeafRoleV1::GeneratedGuidance,
        _ => LeafRoleV1::UserContent,
    }
}

fn step_visible_path(step: &LeafStepV1) -> &Path {
    match step {
        LeafStepV1::CreateDirectory { target, .. } | LeafStepV1::CreateFile { target, .. } => {
            &target.path
        }
        LeafStepV1::ReplaceFile { target, .. } => &target.path,
        LeafStepV1::MoveFile { destination, .. } => &destination.path,
    }
}

fn validate_program_facts(program: &MutationProgramV1, path: &Path) -> Result<()> {
    let created_steps = program
        .steps
        .iter()
        .enumerate()
        .filter_map(|(index, step)| match step {
            LeafStepV1::CreateDirectory { id, target, .. } => {
                Some((id.as_str(), (index, target.path.as_path())))
            }
            _ => None,
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    let directory_ids = program
        .directories
        .iter()
        .map(|directory| directory.id.as_str())
        .collect::<BTreeSet<_>>();
    let directory_paths = program
        .directories
        .iter()
        .map(|directory| directory.path.as_path())
        .collect::<BTreeSet<_>>();
    let directory_case_keys = program
        .directories
        .iter()
        .map(|directory| (directory.parent.as_deref(), directory.case_key.as_str()))
        .collect::<BTreeSet<_>>();
    let roots = program
        .directories
        .iter()
        .filter(|directory| directory.path.as_os_str().is_empty())
        .collect::<Vec<_>>();
    if directory_ids.len() != program.directories.len()
        || directory_paths.len() != program.directories.len()
        || directory_case_keys.len() != program.directories.len()
        || roots.len() != 1
        || roots[0].parent.is_some()
        || !matches!(
            roots[0].expectation,
            DirectoryExpectationV1::Existing { .. }
        )
        || program.directories.iter().any(|directory| {
            directory.id != directory_id(&directory.path)
                || (!directory.path.as_os_str().is_empty() && !safe_relative(&directory.path))
                || !is_sha256(&directory.device_sha256)
                || directory.device_sha256 != program.root.root_device_sha256
                || directory.case_key != portable_case_key(&directory.path)
                || if directory.path.as_os_str().is_empty() {
                    directory.parent.is_some()
                } else {
                    directory.parent.as_deref()
                        != Some(
                            directory_id(directory.path.parent().unwrap_or_else(|| Path::new("")))
                                .as_str(),
                        )
                }
                || match &directory.expectation {
                    DirectoryExpectationV1::Existing {
                        physical_identity_sha256,
                        ..
                    } => {
                        !is_sha256(physical_identity_sha256)
                            || if directory.path.as_os_str().is_empty() {
                                directory.nested_boundary != DirectoryBoundaryV1::Root
                            } else {
                                !matches!(
                                    directory.nested_boundary,
                                    DirectoryBoundaryV1::None | DirectoryBoundaryV1::Exact
                                )
                            }
                    }
                    DirectoryExpectationV1::CreatedBy { step_id } => {
                        created_steps
                            .get(step_id.as_str())
                            .is_none_or(|(_, created_path)| *created_path != directory.path)
                            || directory.nested_boundary != DirectoryBoundaryV1::ProgramCreated
                    }
                }
        })
    {
        return Err(invalid(path, "directory authority table is inconsistent"));
    }
    let directory_by_id = program
        .directories
        .iter()
        .map(|directory| (directory.id.as_str(), directory))
        .collect::<std::collections::BTreeMap<_, _>>();
    for directory in &program.directories {
        let DirectoryExpectationV1::CreatedBy { step_id } = &directory.expectation else {
            continue;
        };
        let Some((created_index, _)) = created_steps.get(step_id.as_str()).copied() else {
            return Err(invalid(path, "directory creation step is missing"));
        };
        if let Some(parent_id) = directory.parent.as_deref()
            && !directory_dependency_precedes(
                parent_id,
                created_index,
                &directory_by_id,
                &created_steps,
            )
        {
            return Err(invalid(
                path,
                "parent directory creation does not precede its child",
            ));
        }
    }
    let root_authority = roots[0];
    let root_identity_matches = matches!(
        &root_authority.expectation,
        DirectoryExpectationV1::Existing {
            physical_identity_sha256,
            ..
        } if physical_identity_sha256 == &program.root.root_identity_sha256
    );
    let state_identity_matches = program.directories.iter().any(|directory| {
        directory.path == Path::new(".folderbase")
            && matches!(
                &directory.expectation,
                DirectoryExpectationV1::Existing {
                    physical_identity_sha256,
                    ..
                } if physical_identity_sha256 == &program.root.state_identity_sha256
            )
    });
    let protocol_is_valid = match &program.root.protocol {
        RootProtocolV1::Native {
            folderbase_id,
            manifest,
        } => {
            !folderbase_id.is_empty()
                && manifest.path == Path::new(".folderbase/manifest.json")
                && validate_bound(manifest, &directory_ids)
        }
        RootProtocolV1::Unmanaged { manifest } => {
            manifest.path == Path::new(".folderbase/manifest.json")
                && validate_absent(manifest, &directory_ids)
        }
    };
    let capture_ignore_is_valid = match &program.scope.capture_ignore {
        CaptureIgnoreFactV1::Absent(absent) => {
            absent.path == Path::new(".folderbaseignore") && validate_absent(absent, &directory_ids)
        }
        CaptureIgnoreFactV1::Regular(regular) => {
            regular.path == Path::new(".folderbaseignore")
                && validate_bound(regular, &directory_ids)
        }
    };
    if !root_identity_matches
        || !state_identity_matches
        || !protocol_is_valid
        || !capture_ignore_is_valid
    {
        return Err(invalid(path, "root authority facts are inconsistent"));
    }
    let blob_ids = program
        .blobs
        .iter()
        .map(|blob| blob.id.as_str())
        .collect::<BTreeSet<_>>();
    let blob_paths = program
        .blobs
        .iter()
        .map(|blob| blob.path.as_path())
        .collect::<BTreeSet<_>>();
    if blob_ids.len() != program.blobs.len()
        || blob_paths.len() != program.blobs.len()
        || program.blobs.iter().any(|blob| {
            !is_sha256(&blob.physical_identity_sha256)
                || !is_sha256(&blob.sha256)
                || !safe_relative(&blob.path)
                || !private_blob_path_is_derived(&program.transaction.id, blob)
        })
    {
        return Err(invalid(path, "private blob table is inconsistent"));
    }
    let mut visible_case_keys = BTreeSet::new();
    let mut referenced_blob_ids = BTreeSet::new();
    for (index, step) in program.steps.iter().enumerate() {
        let expected_id = format!("step_{index:08}");
        let expected_image_id = format!("blob_{index:08}_image");
        let expected_rollback_id = format!("blob_{index:08}_rollback");
        let valid = match step {
            LeafStepV1::CreateDirectory { id, target, .. } => {
                id == &expected_id
                    && validate_absent(target, &directory_ids)
                    && directory_dependency_precedes(
                        &target.parent,
                        index,
                        &directory_by_id,
                        &created_steps,
                    )
                    && visible_case_keys.insert((target.parent.clone(), target.case_key.clone()))
            }
            LeafStepV1::CreateFile {
                id,
                target,
                image,
                provenance,
                ..
            } => {
                id == &expected_id
                    && image == &expected_image_id
                    && blob_ids.contains(image.as_str())
                    && referenced_blob_ids.insert(image.as_str())
                    && validate_absent(target, &directory_ids)
                    && directory_dependency_precedes(
                        &target.parent,
                        index,
                        &directory_by_id,
                        &created_steps,
                    )
                    && provenance.as_ref().is_none_or(|source| {
                        validate_bound(source, &directory_ids)
                            && directory_dependency_precedes(
                                &source.parent,
                                index,
                                &directory_by_id,
                                &created_steps,
                            )
                    })
                    && visible_case_keys.insert((target.parent.clone(), target.case_key.clone()))
            }
            LeafStepV1::ReplaceFile {
                id,
                target,
                image,
                rollback_snapshot,
                ..
            } => {
                id == &expected_id
                    && image == &expected_image_id
                    && rollback_snapshot == &expected_rollback_id
                    && blob_ids.contains(image.as_str())
                    && blob_ids.contains(rollback_snapshot.as_str())
                    && referenced_blob_ids.insert(image.as_str())
                    && referenced_blob_ids.insert(rollback_snapshot.as_str())
                    && validate_bound(target, &directory_ids)
                    && directory_dependency_precedes(
                        &target.parent,
                        index,
                        &directory_by_id,
                        &created_steps,
                    )
                    && target.link_count == 1
                    && visible_case_keys
                        .insert((target.parent.clone(), portable_leaf_case_key(&target.path)))
            }
            LeafStepV1::MoveFile {
                id,
                source,
                destination,
                rollback_snapshot,
                ..
            } => {
                id == &expected_id
                    && rollback_snapshot == &expected_rollback_id
                    && blob_ids.contains(rollback_snapshot.as_str())
                    && referenced_blob_ids.insert(rollback_snapshot.as_str())
                    && validate_bound(source, &directory_ids)
                    && directory_dependency_precedes(
                        &source.parent,
                        index,
                        &directory_by_id,
                        &created_steps,
                    )
                    && source.link_count == 1
                    && validate_absent(destination, &directory_ids)
                    && directory_dependency_precedes(
                        &destination.parent,
                        index,
                        &directory_by_id,
                        &created_steps,
                    )
                    && visible_case_keys
                        .insert((source.parent.clone(), portable_leaf_case_key(&source.path)))
                    && visible_case_keys
                        .insert((destination.parent.clone(), destination.case_key.clone()))
            }
        };
        if !valid {
            return Err(invalid(path, "leaf step table is inconsistent"));
        }
    }
    if referenced_blob_ids != blob_ids {
        return Err(invalid(
            path,
            "private blob table contains an unreferenced or cross-wired blob",
        ));
    }
    Ok(())
}

fn directory_dependency_precedes(
    directory_id: &str,
    dependent_step_index: usize,
    directories: &std::collections::BTreeMap<&str, &DirectoryAuthorityV1>,
    created_steps: &std::collections::BTreeMap<&str, (usize, &Path)>,
) -> bool {
    let Some(directory) = directories.get(directory_id) else {
        return false;
    };
    match &directory.expectation {
        DirectoryExpectationV1::Existing { .. } => true,
        DirectoryExpectationV1::CreatedBy { step_id } => created_steps
            .get(step_id.as_str())
            .is_some_and(|(created_index, created_path)| {
                *created_index < dependent_step_index && *created_path == directory.path
            }),
    }
}

fn validate_bound(bound: &BoundRegularV1, directories: &BTreeSet<&str>) -> bool {
    safe_relative(&bound.path)
        && directories.contains(bound.parent.as_str())
        && bound.parent == directory_id(bound.path.parent().unwrap_or_else(|| Path::new("")))
        && is_sha256(&bound.physical_identity_sha256)
        && is_sha256(&bound.sha256)
        && bound.link_count > 0
}

fn validate_absent(absent: &AbsentLeafV1, directories: &BTreeSet<&str>) -> bool {
    safe_relative(&absent.path)
        && directories.contains(absent.parent.as_str())
        && absent.parent == directory_id(absent.path.parent().unwrap_or_else(|| Path::new("")))
        && absent.case_key == portable_leaf_case_key(&absent.path)
}

fn private_blob_path_is_derived(transaction_id: &str, blob: &PrivateBlobV1) -> bool {
    let Some(rest) = blob.id.strip_prefix("blob_") else {
        return false;
    };
    let Some((index, kind)) = rest.split_once('_') else {
        return false;
    };
    if index.len() != 8 || !index.bytes().all(|byte| byte.is_ascii_digit()) {
        return false;
    }
    let (directory, extension) = match kind {
        "image" => ("stages", "stage"),
        "rollback" => ("snapshots", "snapshot"),
        _ => return false,
    };
    blob.path
        == PathBuf::from(".folderbase/migrations")
            .join(transaction_id)
            .join(TRANSACTION_DIRECTORY)
            .join(directory)
            .join(format!("{index}.{extension}"))
}

fn scope_is_valid(scope: &ScopeFactsV1) -> bool {
    [
        Some(scope.source_inventory_sha256.as_str()),
        Some(scope.exclusions_sha256.as_str()),
        Some(scope.source_topology_sha256.as_str()),
        scope.manifest_policies_sha256.as_deref(),
        Some(scope.nested_boundaries_sha256.as_str()),
        Some(scope.template_packages_sha256.as_str()),
    ]
    .into_iter()
    .flatten()
    .all(is_sha256)
}

fn canonical_sha256(value: &impl Serialize) -> Result<String> {
    let bytes = serde_json::to_vec(value)
        .map_err(|source| FolderbaseError::json(Path::new("<mutation-program-v1>"), source))?;
    Ok(domain_sha256(b"folderbase-mutation-facts-v1", &bytes))
}

fn domain_sha256(domain: &[u8], bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update([0]);
    digest.update(bytes);
    format!("{:x}", digest.finalize())
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn portable_case_key(path: &Path) -> String {
    path.components()
        .map(|component| {
            component
                .as_os_str()
                .to_string_lossy()
                .case_fold()
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn portable_leaf_case_key(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().case_fold().collect::<String>())
        .unwrap_or_default()
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum TransactionDirectionV1 {
    Apply,
    Rollback,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum TransactionPhaseV1 {
    Prepared,
    Applying,
    Applied,
    RollbackRequested,
    RollingBack,
    RolledBack,
    Conflicted,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct TransactionJournalGenerationV1 {
    format: String,
    transaction_id: String,
    program_digest: String,
    generation: u64,
    previous_checksum: Option<String>,
    direction: TransactionDirectionV1,
    phase: TransactionPhaseV1,
    operation_cursor: usize,
    in_flight_operation: Option<usize>,
    receipts: Vec<MutationReceiptV1>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    inverse_receipts: Vec<MutationReceiptV1>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    abort_receipts: Vec<ApplyAbortReceiptV1>,
    conflicts: Vec<MutationConflictEvidenceV1>,
    checksum: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct MutationReceiptV1 {
    operation_index: usize,
    published_identity_sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ApplyAbortReceiptV1 {
    operation_index: usize,
    private_receipt_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct MutationConflictEvidenceV1 {
    operation_index: Option<usize>,
    affected_paths: Vec<PathBuf>,
    expected: String,
    observed: String,
    preserved_artifact: Option<PathBuf>,
}

struct RollbackTransitionV1 {
    phase: TransactionPhaseV1,
    operation_cursor: usize,
    in_flight_operation: Option<usize>,
    receipts: Vec<MutationReceiptV1>,
    inverse_receipts: Vec<MutationReceiptV1>,
    abort_receipts: Vec<ApplyAbortReceiptV1>,
}

impl TransactionJournalGenerationV1 {
    pub(super) fn prepared(program: &MutationProgramV1, program_digest: String) -> Result<Self> {
        let mut generation = Self {
            format: FORMAT.to_owned(),
            transaction_id: program.transaction_id().to_owned(),
            program_digest,
            generation: 0,
            previous_checksum: None,
            direction: TransactionDirectionV1::Apply,
            phase: TransactionPhaseV1::Prepared,
            operation_cursor: 0,
            in_flight_operation: None,
            receipts: Vec::new(),
            inverse_receipts: Vec::new(),
            abort_receipts: Vec::new(),
            conflicts: Vec::new(),
            checksum: String::new(),
        };
        generation.checksum = generation.calculate_checksum()?;
        generation.validate(program)?;
        Ok(generation)
    }

    pub(super) fn decode(path: &Path, bytes: &[u8]) -> Result<Self> {
        if bytes.len() as u64 > MAX_JOURNAL_GENERATION_BYTES {
            return Err(invalid(path, "journal generation exceeds its byte bound"));
        }
        let generation: Self =
            serde_json::from_slice(bytes).map_err(|source| FolderbaseError::json(path, source))?;
        if generation.encode(path)? != bytes {
            return Err(invalid(
                path,
                "journal generation is not the exact canonical admitted encoding",
            ));
        }
        Ok(generation)
    }

    pub(super) fn encode(&self, path: &Path) -> Result<Vec<u8>> {
        let bytes =
            serde_json::to_vec(self).map_err(|source| FolderbaseError::json(path, source))?;
        if bytes.len() as u64 > MAX_JOURNAL_GENERATION_BYTES {
            return Err(invalid(path, "journal generation exceeds its byte bound"));
        }
        Ok(bytes)
    }

    pub(super) fn file_name(&self) -> String {
        format!("{:020}.json", self.generation)
    }

    pub(super) fn checksum(&self) -> &str {
        &self.checksum
    }

    pub(super) fn generation(&self) -> u64 {
        self.generation
    }

    pub(super) fn program_digest(&self) -> &str {
        &self.program_digest
    }

    pub(super) fn direction(&self) -> TransactionDirectionV1 {
        self.direction
    }

    pub(super) fn phase(&self) -> TransactionPhaseV1 {
        self.phase
    }

    pub(super) fn operation_cursor(&self) -> usize {
        self.operation_cursor
    }

    pub(super) fn in_flight_operation(&self) -> Option<usize> {
        self.in_flight_operation
    }

    pub(super) fn receipt_identity(&self, operation_index: usize) -> Option<&str> {
        self.receipts
            .get(operation_index)
            .and_then(|receipt| receipt.published_identity_sha256.as_deref())
    }

    fn has_inverse_receipt(&self, operation_index: usize) -> bool {
        self.inverse_receipts
            .iter()
            .any(|receipt| receipt.operation_index == operation_index)
    }

    pub(super) fn apply_receipt_records(&self) -> Vec<(usize, Option<String>)> {
        self.receipts
            .iter()
            .map(|receipt| {
                (
                    receipt.operation_index,
                    receipt.published_identity_sha256.clone(),
                )
            })
            .collect()
    }

    pub(super) fn inverse_receipt_records(&self) -> Vec<(usize, Option<String>)> {
        self.inverse_receipts
            .iter()
            .map(|receipt| {
                (
                    receipt.operation_index,
                    receipt.published_identity_sha256.clone(),
                )
            })
            .collect()
    }

    pub(super) fn abort_receipt_records(&self) -> Vec<(usize, String)> {
        self.abort_receipts
            .iter()
            .map(|receipt| {
                (
                    receipt.operation_index,
                    receipt.private_receipt_sha256.clone(),
                )
            })
            .collect()
    }

    pub(super) fn abort_receipt_sha256(&self, operation_index: usize) -> Option<&str> {
        self.abort_receipts
            .iter()
            .find(|receipt| receipt.operation_index == operation_index)
            .map(|receipt| receipt.private_receipt_sha256.as_str())
    }

    pub(super) fn conflict_records(&self) -> Vec<ProgramConflictV1> {
        self.conflicts
            .iter()
            .map(|conflict| ProgramConflictV1 {
                operation_index: conflict.operation_index,
                affected_paths: conflict.affected_paths.clone(),
                expected: conflict.expected.clone(),
                observed: conflict.observed.clone(),
                preserved_artifact: conflict.preserved_artifact.clone(),
            })
            .collect()
    }

    pub(super) fn next_conflicted(
        &self,
        program: &MutationProgramV1,
        operation_index: Option<usize>,
        affected_paths: Vec<PathBuf>,
        expected: String,
        observed: String,
        preserved_artifact: Option<PathBuf>,
    ) -> Result<Self> {
        let mut conflicts = self.conflicts.clone();
        conflicts.push(MutationConflictEvidenceV1 {
            operation_index,
            affected_paths,
            expected,
            observed,
            preserved_artifact,
        });
        let mut next = Self {
            format: FORMAT.to_owned(),
            transaction_id: self.transaction_id.clone(),
            program_digest: self.program_digest.clone(),
            generation: self.generation + 1,
            previous_checksum: Some(self.checksum.clone()),
            direction: self.direction,
            phase: TransactionPhaseV1::Conflicted,
            operation_cursor: self.operation_cursor,
            in_flight_operation: self.in_flight_operation,
            receipts: self.receipts.clone(),
            inverse_receipts: self.inverse_receipts.clone(),
            abort_receipts: self.abort_receipts.clone(),
            conflicts,
            checksum: String::new(),
        };
        next.checksum = next.calculate_checksum()?;
        next.validate(program)?;
        Ok(next)
    }

    pub(super) fn next_apply_intent(
        &self,
        program: &MutationProgramV1,
        operation_index: usize,
    ) -> Result<Self> {
        if operation_index != self.operation_cursor || operation_index >= program.operation_count()
        {
            return Err(invalid(
                Path::new("<migration-journal-v1>"),
                "apply intent is outside the next program operation",
            ));
        }
        self.next(
            program,
            TransactionDirectionV1::Apply,
            TransactionPhaseV1::Applying,
            operation_index,
            Some(operation_index),
            None,
        )
    }

    pub(super) fn next_apply_receipt(
        &self,
        program: &MutationProgramV1,
        operation_index: usize,
        published_identity_sha256: Option<String>,
    ) -> Result<Self> {
        if self.in_flight_operation != Some(operation_index) {
            return Err(invalid(
                Path::new("<migration-journal-v1>"),
                "apply receipt does not match the durable in-flight operation",
            ));
        }
        self.next(
            program,
            TransactionDirectionV1::Apply,
            TransactionPhaseV1::Applying,
            operation_index + 1,
            None,
            Some(MutationReceiptV1 {
                operation_index,
                published_identity_sha256,
            }),
        )
    }

    pub(super) fn next_applied(&self, program: &MutationProgramV1) -> Result<Self> {
        if self.operation_cursor != program.operation_count() || self.in_flight_operation.is_some()
        {
            return Err(invalid(
                Path::new("<migration-journal-v1>"),
                "applied state requires every program operation receipt",
            ));
        }
        self.next(
            program,
            TransactionDirectionV1::Apply,
            TransactionPhaseV1::Applied,
            self.operation_cursor,
            None,
            None,
        )
    }

    pub(super) fn next_rollback_requested(&self, program: &MutationProgramV1) -> Result<Self> {
        let aborting_unreceipted_apply = self.in_flight_operation == Some(self.operation_cursor)
            && self.receipts.get(self.operation_cursor).is_none();
        if self.direction != TransactionDirectionV1::Apply
            || (self.in_flight_operation.is_some() && !aborting_unreceipted_apply)
            || !matches!(
                self.phase,
                TransactionPhaseV1::Prepared
                    | TransactionPhaseV1::Applying
                    | TransactionPhaseV1::Applied
                    | TransactionPhaseV1::Conflicted
            )
        {
            return Err(invalid(
                Path::new("<migration-journal-v1>"),
                "rollback request requires a classified apply prefix",
            ));
        }
        self.next_rollback(
            program,
            TransactionPhaseV1::RollbackRequested,
            self.operation_cursor,
            self.in_flight_operation,
            self.receipts.clone(),
            self.inverse_receipts.clone(),
        )
    }

    pub(super) fn next_aborted_apply(
        &self,
        program: &MutationProgramV1,
        private_receipt_sha256: String,
    ) -> Result<Self> {
        let Some(operation_index) = self.in_flight_operation else {
            return Err(invalid(
                Path::new("<migration-journal-v1>"),
                "apply abort requires an in-flight operation",
            ));
        };
        if self.direction != TransactionDirectionV1::Rollback
            || !matches!(
                self.phase,
                TransactionPhaseV1::RollbackRequested | TransactionPhaseV1::Conflicted
            )
            || operation_index != self.operation_cursor
            || self.receipts.get(operation_index).is_some()
        {
            return Err(invalid(
                Path::new("<migration-journal-v1>"),
                "apply abort does not match an unreceipted rollback request",
            ));
        }
        if !is_sha256(&private_receipt_sha256) || !self.abort_receipts.is_empty() {
            return Err(invalid(
                Path::new("<migration-journal-v1>"),
                "apply abort receipt is invalid or duplicated",
            ));
        }
        let mut abort_receipts = self.abort_receipts.clone();
        abort_receipts.push(ApplyAbortReceiptV1 {
            operation_index,
            private_receipt_sha256,
        });
        self.next_rollback_with_abort_receipts(
            program,
            RollbackTransitionV1 {
                phase: TransactionPhaseV1::RollbackRequested,
                operation_cursor: self.operation_cursor,
                in_flight_operation: None,
                receipts: self.receipts.clone(),
                inverse_receipts: self.inverse_receipts.clone(),
                abort_receipts,
            },
        )
    }

    pub(super) fn next_rollback_intent(
        &self,
        program: &MutationProgramV1,
        operation_index: usize,
    ) -> Result<Self> {
        if self.direction != TransactionDirectionV1::Rollback
            || self.in_flight_operation.is_some()
            || self.operation_cursor == 0
            || operation_index + 1 != self.operation_cursor
            || !matches!(
                self.phase,
                TransactionPhaseV1::RollbackRequested
                    | TransactionPhaseV1::RollingBack
                    | TransactionPhaseV1::Conflicted
            )
        {
            return Err(invalid(
                Path::new("<migration-journal-v1>"),
                "rollback intent is outside the next inverse operation",
            ));
        }
        self.next_rollback(
            program,
            TransactionPhaseV1::RollingBack,
            self.operation_cursor,
            Some(operation_index),
            self.receipts.clone(),
            self.inverse_receipts.clone(),
        )
    }

    pub(super) fn next_rollback_receipt(
        &self,
        program: &MutationProgramV1,
        operation_index: usize,
        restored_identity_sha256: Option<String>,
    ) -> Result<Self> {
        if self.direction != TransactionDirectionV1::Rollback
            || !matches!(
                self.phase,
                TransactionPhaseV1::RollingBack | TransactionPhaseV1::Conflicted
            )
            || self.in_flight_operation != Some(operation_index)
            || operation_index + 1 != self.operation_cursor
        {
            return Err(invalid(
                Path::new("<migration-journal-v1>"),
                "rollback receipt does not match the durable inverse operation",
            ));
        }
        if self
            .receipts
            .get(operation_index)
            .is_none_or(|receipt| receipt.operation_index != operation_index)
        {
            return Err(invalid(
                Path::new("<migration-journal-v1>"),
                "rollback receipt has no matching apply evidence",
            ));
        }
        let mut inverse_receipts = self.inverse_receipts.clone();
        if inverse_receipts
            .iter()
            .any(|receipt| receipt.operation_index == operation_index)
        {
            return Err(invalid(
                Path::new("<migration-journal-v1>"),
                "rollback receipt duplicates inverse evidence",
            ));
        }
        inverse_receipts.push(MutationReceiptV1 {
            operation_index,
            published_identity_sha256: restored_identity_sha256,
        });
        self.next_rollback(
            program,
            TransactionPhaseV1::RollingBack,
            operation_index,
            None,
            self.receipts.clone(),
            inverse_receipts,
        )
    }

    pub(super) fn next_rolled_back(&self, program: &MutationProgramV1) -> Result<Self> {
        if self.direction != TransactionDirectionV1::Rollback
            || self.operation_cursor != 0
            || self.in_flight_operation.is_some()
            || self.inverse_receipts.len() != self.receipts.len()
        {
            return Err(invalid(
                Path::new("<migration-journal-v1>"),
                "rolled-back state requires every inverse receipt",
            ));
        }
        self.next_rollback(
            program,
            TransactionPhaseV1::RolledBack,
            0,
            None,
            self.receipts.clone(),
            self.inverse_receipts.clone(),
        )
    }

    fn next_rollback(
        &self,
        program: &MutationProgramV1,
        phase: TransactionPhaseV1,
        operation_cursor: usize,
        in_flight_operation: Option<usize>,
        receipts: Vec<MutationReceiptV1>,
        inverse_receipts: Vec<MutationReceiptV1>,
    ) -> Result<Self> {
        self.next_rollback_with_abort_receipts(
            program,
            RollbackTransitionV1 {
                phase,
                operation_cursor,
                in_flight_operation,
                receipts,
                inverse_receipts,
                abort_receipts: self.abort_receipts.clone(),
            },
        )
    }

    fn next_rollback_with_abort_receipts(
        &self,
        program: &MutationProgramV1,
        transition: RollbackTransitionV1,
    ) -> Result<Self> {
        let mut next = Self {
            format: FORMAT.to_owned(),
            transaction_id: self.transaction_id.clone(),
            program_digest: self.program_digest.clone(),
            generation: self.generation + 1,
            previous_checksum: Some(self.checksum.clone()),
            direction: TransactionDirectionV1::Rollback,
            phase: transition.phase,
            operation_cursor: transition.operation_cursor,
            in_flight_operation: transition.in_flight_operation,
            receipts: transition.receipts,
            inverse_receipts: transition.inverse_receipts,
            abort_receipts: transition.abort_receipts,
            conflicts: self.conflicts.clone(),
            checksum: String::new(),
        };
        next.checksum = next.calculate_checksum()?;
        next.validate(program)?;
        Ok(next)
    }

    fn next(
        &self,
        program: &MutationProgramV1,
        direction: TransactionDirectionV1,
        phase: TransactionPhaseV1,
        operation_cursor: usize,
        in_flight_operation: Option<usize>,
        receipt: Option<MutationReceiptV1>,
    ) -> Result<Self> {
        let mut receipts = self.receipts.clone();
        if let Some(receipt) = receipt {
            if receipts
                .iter()
                .any(|existing| existing.operation_index == receipt.operation_index)
            {
                return Err(invalid(
                    Path::new("<migration-journal-v1>"),
                    "journal contains a duplicate operation receipt",
                ));
            }
            receipts.push(receipt);
        }
        let mut next = Self {
            format: FORMAT.to_owned(),
            transaction_id: self.transaction_id.clone(),
            program_digest: self.program_digest.clone(),
            generation: self.generation + 1,
            previous_checksum: Some(self.checksum.clone()),
            direction,
            phase,
            operation_cursor,
            in_flight_operation,
            receipts,
            inverse_receipts: self.inverse_receipts.clone(),
            abort_receipts: self.abort_receipts.clone(),
            conflicts: self.conflicts.clone(),
            checksum: String::new(),
        };
        next.checksum = next.calculate_checksum()?;
        next.validate(program)?;
        Ok(next)
    }

    fn calculate_checksum(&self) -> Result<String> {
        let path = Path::new("<migration-journal-generation-v1>");
        let bytes = if self.abort_receipts.is_empty() {
            // Preserve the exact checksum bytes of every pre-abort transaction-v1
            // generation. The extension enters the checksum domain only when an
            // abort receipt actually exists.
            serde_json::to_vec(&(
                &self.format,
                &self.transaction_id,
                &self.program_digest,
                self.generation,
                &self.previous_checksum,
                self.direction,
                self.phase,
                self.operation_cursor,
                self.in_flight_operation,
                &self.receipts,
                &self.inverse_receipts,
                &self.conflicts,
            ))
        } else {
            serde_json::to_vec(&(
                &self.format,
                &self.transaction_id,
                &self.program_digest,
                self.generation,
                &self.previous_checksum,
                self.direction,
                self.phase,
                self.operation_cursor,
                self.in_flight_operation,
                &self.receipts,
                &self.inverse_receipts,
                &self.abort_receipts,
                &self.conflicts,
            ))
        }
        .map_err(|source| FolderbaseError::json(path, source))?;
        let mut checksum = Sha256::new();
        checksum.update(JOURNAL_CHECKSUM_DOMAIN);
        checksum.update([0]);
        checksum.update(bytes);
        Ok(format!("{:x}", checksum.finalize()))
    }

    fn validate(&self, program: &MutationProgramV1) -> Result<()> {
        let path = Path::new("<migration-journal-generation-v1>");
        if self.format != FORMAT
            || self.transaction_id != program.transaction_id()
            || !is_sha256(&self.program_digest)
            || self.operation_cursor > program.operation_count()
            || self
                .in_flight_operation
                .is_some_and(|index| index >= program.operation_count())
            || self
                .receipts
                .iter()
                .any(|receipt| receipt.operation_index >= program.operation_count())
            || self
                .receipts
                .iter()
                .enumerate()
                .any(|(index, receipt)| receipt.operation_index != index)
            || match self.direction {
                TransactionDirectionV1::Apply => {
                    self.receipts.len() != self.operation_cursor
                        || !self.inverse_receipts.is_empty()
                }
                TransactionDirectionV1::Rollback => {
                    self.receipts.len() < self.operation_cursor
                        || self.inverse_receipts.len()
                            != self.receipts.len().saturating_sub(self.operation_cursor)
                        || self
                            .inverse_receipts
                            .iter()
                            .enumerate()
                            .any(|(offset, receipt)| {
                                receipt.operation_index + offset + 1 != self.receipts.len()
                            })
                }
            }
            || self.receipts.iter().any(|receipt| {
                receipt
                    .published_identity_sha256
                    .as_deref()
                    .is_some_and(|digest| !is_sha256(digest))
            })
            || self.inverse_receipts.iter().any(|receipt| {
                receipt.operation_index >= program.operation_count()
                    || receipt
                        .published_identity_sha256
                        .as_deref()
                        .is_some_and(|digest| !is_sha256(digest))
            })
            || self.abort_receipts.len() > 1
            || self.abort_receipts.iter().any(|receipt| {
                receipt.operation_index >= program.operation_count()
                    || !is_sha256(&receipt.private_receipt_sha256)
            })
            || (self.direction == TransactionDirectionV1::Apply && !self.abort_receipts.is_empty())
            || self.checksum != self.calculate_checksum()?
        {
            return Err(invalid(path, "journal generation is inconsistent"));
        }
        if let Some(receipt) = self.abort_receipts.first()
            && (receipt.operation_index != self.receipts.len()
                || !matches!(
                    program.step(receipt.operation_index)?,
                    ProgramStepV1::CreateDirectory { .. }
                        | ProgramStepV1::CreateFile { .. }
                        | ProgramStepV1::ReplaceFile { .. }
                        | ProgramStepV1::MoveFile { .. }
                ))
        {
            return Err(invalid(
                path,
                "journal abort receipt does not match an abort-capable unreceipted operation",
            ));
        }
        Ok(())
    }
}

pub(super) fn validate_chain(
    program: &MutationProgramV1,
    program_digest: &str,
    generations: &[TransactionJournalGenerationV1],
) -> Result<()> {
    if generations.is_empty() || generations.len() > program.maximum_journal_generations() {
        return Err(invalid(
            Path::new("<migration-journal-v1>"),
            "journal chain is empty",
        ));
    }
    let mut previous = None;
    for (index, generation) in generations.iter().enumerate() {
        generation.validate(program)?;
        if generation.generation() != index as u64
            || generation.program_digest() != program_digest
            || generation.previous_checksum.as_deref() != previous
        {
            return Err(invalid(
                Path::new("<migration-journal-v1>"),
                "journal generation chain is inconsistent",
            ));
        }
        previous = Some(generation.checksum());
        if index == 0 {
            if generation.direction != TransactionDirectionV1::Apply
                || generation.phase != TransactionPhaseV1::Prepared
                || generation.operation_cursor != 0
                || generation.in_flight_operation.is_some()
                || !generation.receipts.is_empty()
                || !generation.inverse_receipts.is_empty()
                || !generation.abort_receipts.is_empty()
                || !generation.conflicts.is_empty()
            {
                return Err(invalid(
                    Path::new("<migration-journal-v1>"),
                    "journal does not begin with the prepared state",
                ));
            }
        } else {
            validate_transition(&generations[index - 1], generation, program)?;
        }
    }
    Ok(())
}

pub(super) fn validate_append(
    program: &MutationProgramV1,
    program_digest: &str,
    generations: &[TransactionJournalGenerationV1],
    next: &TransactionJournalGenerationV1,
) -> Result<()> {
    let Some(previous) = generations.last() else {
        return Err(invalid(
            Path::new("<migration-journal-v1>"),
            "journal append has no predecessor",
        ));
    };
    if generations.len() >= program.maximum_journal_generations()
        || next.generation() != generations.len() as u64
        || next.program_digest() != program_digest
        || next.previous_checksum.as_deref() != Some(previous.checksum())
    {
        return Err(invalid(
            Path::new("<migration-journal-v1>"),
            "journal append exceeds its bound or does not extend the exact head",
        ));
    }
    next.validate(program)?;
    validate_transition(previous, next, program)
}

fn validate_transition(
    previous: &TransactionJournalGenerationV1,
    next: &TransactionJournalGenerationV1,
    program: &MutationProgramV1,
) -> Result<()> {
    let apply_intent = next.direction == TransactionDirectionV1::Apply
        && next.phase == TransactionPhaseV1::Applying
        && next.conflicts == previous.conflicts
        && next.operation_cursor == previous.operation_cursor
        && next.in_flight_operation == Some(previous.operation_cursor)
        && next.receipts == previous.receipts
        && next.inverse_receipts == previous.inverse_receipts
        && next.abort_receipts == previous.abort_receipts
        && previous.in_flight_operation.is_none()
        && previous.operation_cursor < program.operation_count()
        && matches!(
            previous.phase,
            TransactionPhaseV1::Prepared
                | TransactionPhaseV1::Applying
                | TransactionPhaseV1::Conflicted
        );
    let apply_receipt = next.direction == TransactionDirectionV1::Apply
        && next.phase == TransactionPhaseV1::Applying
        && next.conflicts == previous.conflicts
        && matches!(
            previous.phase,
            TransactionPhaseV1::Applying | TransactionPhaseV1::Conflicted
        )
        && previous.in_flight_operation == Some(previous.operation_cursor)
        && next.in_flight_operation.is_none()
        && next.operation_cursor == previous.operation_cursor + 1
        && next.receipts.len() == previous.receipts.len() + 1
        && next.inverse_receipts == previous.inverse_receipts
        && next.abort_receipts == previous.abort_receipts
        && next.receipts[..previous.receipts.len()] == previous.receipts
        && next
            .receipts
            .last()
            .is_some_and(|receipt| receipt.operation_index == previous.operation_cursor);
    let applied = next.direction == TransactionDirectionV1::Apply
        && next.phase == TransactionPhaseV1::Applied
        && next.conflicts == previous.conflicts
        && next.in_flight_operation.is_none()
        && next.operation_cursor == program.operation_count()
        && next.receipts == previous.receipts
        && next.inverse_receipts == previous.inverse_receipts
        && next.abort_receipts == previous.abort_receipts
        && previous.operation_cursor == program.operation_count()
        && previous.in_flight_operation.is_none()
        && matches!(
            previous.phase,
            TransactionPhaseV1::Prepared
                | TransactionPhaseV1::Applying
                | TransactionPhaseV1::Conflicted
        );
    let rollback_requested = previous.direction == TransactionDirectionV1::Apply
        && matches!(
            previous.phase,
            TransactionPhaseV1::Prepared
                | TransactionPhaseV1::Applying
                | TransactionPhaseV1::Applied
                | TransactionPhaseV1::Conflicted
        )
        && next.direction == TransactionDirectionV1::Rollback
        && next.phase == TransactionPhaseV1::RollbackRequested
        && next.operation_cursor == previous.operation_cursor
        && next.in_flight_operation == previous.in_flight_operation
        && next.receipts == previous.receipts
        && next.inverse_receipts == previous.inverse_receipts
        && next.abort_receipts == previous.abort_receipts
        && next.conflicts == previous.conflicts;
    let aborted_apply = previous.direction == TransactionDirectionV1::Rollback
        && matches!(
            previous.phase,
            TransactionPhaseV1::RollbackRequested | TransactionPhaseV1::Conflicted
        )
        && previous.in_flight_operation == Some(previous.operation_cursor)
        && previous.receipts.get(previous.operation_cursor).is_none()
        && next.direction == TransactionDirectionV1::Rollback
        && next.phase == TransactionPhaseV1::RollbackRequested
        && next.operation_cursor == previous.operation_cursor
        && next.in_flight_operation.is_none()
        && next.receipts == previous.receipts
        && next.inverse_receipts == previous.inverse_receipts
        && next.abort_receipts.len() == previous.abort_receipts.len() + 1
        && next.abort_receipts[..previous.abort_receipts.len()] == previous.abort_receipts
        && next.abort_receipts.last().is_some_and(|receipt| {
            receipt.operation_index == previous.operation_cursor
                && is_sha256(&receipt.private_receipt_sha256)
        })
        && next.conflicts == previous.conflicts;
    let rollback_intent = previous.direction == TransactionDirectionV1::Rollback
        && matches!(
            previous.phase,
            TransactionPhaseV1::RollbackRequested
                | TransactionPhaseV1::RollingBack
                | TransactionPhaseV1::Conflicted
        )
        && previous.in_flight_operation.is_none()
        && previous.operation_cursor > 0
        && next.direction == TransactionDirectionV1::Rollback
        && next.phase == TransactionPhaseV1::RollingBack
        && next.operation_cursor == previous.operation_cursor
        && next.in_flight_operation == Some(previous.operation_cursor - 1)
        && next.receipts == previous.receipts
        && next.inverse_receipts == previous.inverse_receipts
        && next.abort_receipts == previous.abort_receipts
        && next.conflicts == previous.conflicts;
    let rollback_receipt = previous.direction == TransactionDirectionV1::Rollback
        && matches!(
            previous.phase,
            TransactionPhaseV1::RollingBack | TransactionPhaseV1::Conflicted
        )
        && previous.in_flight_operation == previous.operation_cursor.checked_sub(1)
        && next.direction == TransactionDirectionV1::Rollback
        && next.phase == TransactionPhaseV1::RollingBack
        && next.operation_cursor + 1 == previous.operation_cursor
        && next.in_flight_operation.is_none()
        && previous.receipts == next.receipts
        && next.abort_receipts == previous.abort_receipts
        && next.inverse_receipts.len() == previous.inverse_receipts.len() + 1
        && next.inverse_receipts[..previous.inverse_receipts.len()] == previous.inverse_receipts
        && next
            .inverse_receipts
            .last()
            .is_some_and(|receipt| receipt.operation_index + 1 == previous.operation_cursor)
        && next.conflicts == previous.conflicts;
    let rolled_back = previous.direction == TransactionDirectionV1::Rollback
        && matches!(
            previous.phase,
            TransactionPhaseV1::RollbackRequested | TransactionPhaseV1::RollingBack
        )
        && previous.operation_cursor == 0
        && previous.in_flight_operation.is_none()
        && previous.inverse_receipts.len() == previous.receipts.len()
        && next.direction == TransactionDirectionV1::Rollback
        && next.phase == TransactionPhaseV1::RolledBack
        && next.operation_cursor == 0
        && next.in_flight_operation.is_none()
        && next.receipts == previous.receipts
        && next.inverse_receipts == previous.inverse_receipts
        && next.abort_receipts == previous.abort_receipts
        && next.conflicts == previous.conflicts;
    let conflicted = next.direction == previous.direction
        && next.phase == TransactionPhaseV1::Conflicted
        && next.operation_cursor == previous.operation_cursor
        && next.in_flight_operation == previous.in_flight_operation
        && next.receipts == previous.receipts
        && next.inverse_receipts == previous.inverse_receipts
        && next.abort_receipts == previous.abort_receipts
        && next.conflicts.len() == previous.conflicts.len() + 1
        && next.conflicts[..previous.conflicts.len()] == previous.conflicts;
    if apply_intent
        || apply_receipt
        || applied
        || rollback_requested
        || aborted_apply
        || rollback_intent
        || rollback_receipt
        || rolled_back
        || conflicted
    {
        return Ok(());
    }
    Err(invalid(
        Path::new("<migration-journal-v1>"),
        "journal contains an illegal state transition",
    ))
}

fn operation_source_path(operation: &MigrationOperation) -> Option<PathBuf> {
    match operation {
        MigrationOperation::CopyFile { source_path, .. } => Some(source_path.clone()),
        operation if operation.is_structural() => {
            operation.structural_source_path().map(Path::to_path_buf)
        }
        _ => None,
    }
}

fn operation_destination_path(operation: &MigrationOperation) -> Option<PathBuf> {
    match operation {
        MigrationOperation::CreateFolder { path } => Some(path.clone()),
        MigrationOperation::CopyFile {
            destination_path, ..
        } => Some(destination_path.clone()),
        operation if operation.is_structural() => operation
            .structural_destination_path()
            .map(Path::to_path_buf),
        _ => None,
    }
}

fn durability_profile() -> &'static str {
    #[cfg(unix)]
    {
        "folderbase-unix-fsync-v1"
    }
    #[cfg(windows)]
    {
        "folderbase-windows-same-volume-no-directory-fsync-v1"
    }
    #[cfg(not(any(unix, windows)))]
    {
        "folderbase-generic-sync-v1"
    }
}

fn safe_relative(path: &Path) -> bool {
    !path.as_os_str().is_empty()
        && !path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, std::path::Component::Normal(_)))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn invalid(path: &Path, message: impl Into<String>) -> FolderbaseError {
    FolderbaseError::InvalidRecord {
        path: path.to_path_buf(),
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Serialize)]
    struct LegacyTransactionJournalGenerationV1<'a> {
        format: &'a str,
        transaction_id: &'a str,
        program_digest: &'a str,
        generation: u64,
        previous_checksum: &'a Option<String>,
        direction: TransactionDirectionV1,
        phase: TransactionPhaseV1,
        operation_cursor: usize,
        in_flight_operation: Option<usize>,
        receipts: &'a [MutationReceiptV1],
        #[serde(skip_serializing_if = "<[MutationReceiptV1]>::is_empty")]
        inverse_receipts: &'a [MutationReceiptV1],
        conflicts: &'a [MutationConflictEvidenceV1],
        checksum: &'a str,
    }

    fn no_abort_generation() -> TransactionJournalGenerationV1 {
        let mut generation = TransactionJournalGenerationV1 {
            format: FORMAT.to_owned(),
            transaction_id: "migration-compatibility".to_owned(),
            program_digest: "1".repeat(64),
            generation: 7,
            previous_checksum: Some("2".repeat(64)),
            direction: TransactionDirectionV1::Rollback,
            phase: TransactionPhaseV1::RollingBack,
            operation_cursor: 1,
            in_flight_operation: Some(0),
            receipts: vec![MutationReceiptV1 {
                operation_index: 0,
                published_identity_sha256: Some("3".repeat(64)),
            }],
            inverse_receipts: vec![MutationReceiptV1 {
                operation_index: 0,
                published_identity_sha256: Some("4".repeat(64)),
            }],
            abort_receipts: Vec::new(),
            conflicts: Vec::new(),
            checksum: String::new(),
        };
        generation.checksum = legacy_checksum(&generation);
        generation
    }

    fn legacy_checksum(generation: &TransactionJournalGenerationV1) -> String {
        let controlled = (
            &generation.format,
            &generation.transaction_id,
            &generation.program_digest,
            generation.generation,
            &generation.previous_checksum,
            generation.direction,
            generation.phase,
            generation.operation_cursor,
            generation.in_flight_operation,
            &generation.receipts,
            &generation.inverse_receipts,
            &generation.conflicts,
        );
        let mut checksum = Sha256::new();
        checksum.update(JOURNAL_CHECKSUM_DOMAIN);
        checksum.update([0]);
        checksum
            .update(serde_json::to_vec(&controlled).expect("legacy controlled checksum encoding"));
        format!("{:x}", checksum.finalize())
    }

    fn legacy_bytes(generation: &TransactionJournalGenerationV1) -> Vec<u8> {
        serde_json::to_vec(&LegacyTransactionJournalGenerationV1 {
            format: &generation.format,
            transaction_id: &generation.transaction_id,
            program_digest: &generation.program_digest,
            generation: generation.generation,
            previous_checksum: &generation.previous_checksum,
            direction: generation.direction,
            phase: generation.phase,
            operation_cursor: generation.operation_cursor,
            in_flight_operation: generation.in_flight_operation,
            receipts: &generation.receipts,
            inverse_receipts: &generation.inverse_receipts,
            conflicts: &generation.conflicts,
            checksum: &generation.checksum,
        })
        .expect("legacy journal encoding")
    }

    #[test]
    fn no_abort_journal_generation_preserves_legacy_checksum() {
        let generation = no_abort_generation();
        let checksum = generation
            .calculate_checksum()
            .expect("current journal checksum");

        assert_eq!(checksum, legacy_checksum(&generation));
        assert_eq!(
            checksum,
            "a2f0b09f6cc8479034575faf8563296245beb85cfd6f3564930c23ba8aba3f4b"
        );
    }

    #[test]
    fn no_abort_journal_generation_preserves_legacy_canonical_bytes() {
        let generation = no_abort_generation();
        let current = generation
            .encode(Path::new("<no-abort-journal-compatibility>"))
            .expect("current journal encoding");

        assert_eq!(current, legacy_bytes(&generation));
        assert_eq!(current.len(), 729);
        assert_eq!(
            format!("{:x}", Sha256::digest(&current)),
            "8a0e3471c0dfe6f8076b12fd33a32401cb72989a0e9937cd62a74793cc3c4a13"
        );
        assert!(
            !current
                .windows(b"abort_receipts".len())
                .any(|window| window == b"abort_receipts")
        );
    }
}

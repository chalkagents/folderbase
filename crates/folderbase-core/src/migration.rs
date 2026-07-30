use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::{OsStr, OsString},
    fs,
    io::{self, Read, Write},
    path::{Component, Path, PathBuf},
};

#[cfg(unix)]
use cap_fs_ext::DirExt;
use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt};
use cap_std::fs::{Dir, OpenOptions as CapOpenOptions};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use unicode_casefold::UnicodeCaseFold;
use uuid::Uuid;

use crate::{
    FolderbaseError, FolderbaseKind, InitializationOptions, NestedFolderbaseBoundary,
    ReconstructableTree, Result, TemplateAnswerValue, TemplateArtifactKind, ValidationLevel,
    folder_analysis::{AnalyzedFile, analyze_folder, expand_reconstructable_tree},
    initialization::{initialize, plan_template_initialization},
    local_versions::LocalVersionStore,
    physical_identity::{PhysicalIdentity, RetainedPhysicalIdentity},
    root_attestation::metadata_is_link_or_reparse,
    template::load_builtin_template,
    validation::validate,
    workspace::{has_nested_folderbase_marker, is_reserved_workspace_component},
};

const STATE_DIR: &str = ".folderbase";
const MIGRATIONS_DIR: &str = ".folderbase/migrations";
const MAX_MIGRATION_PLAN_BYTES: u64 = 8 * 1024 * 1024;
const MAX_STRUCTURAL_TEXT_BYTES: u64 = 2 * 1024 * 1024;
const GROUPED_ASSIGNMENT_THRESHOLD: usize = 32;
const ASSIGNMENT_GROUP_RULE_VERSION: &str = "top_level_content_kind_v1";
const GROUPED_ASSIGNMENTS_EXTENSION: &str = "x-folderbase-grouped-assignments-v1";
const EXPANDED_RECONSTRUCTABLE_TREES_EXTENSION: &str =
    "x-folderbase-expanded-reconstructable-trees-v1";
const STRUCTURAL_PLAN_KIND: &str = "structural_reorganization";
const SOURCE_TOPOLOGY_EXTENSION: &str = "x-folderbase-source-topology-v1";
const MANAGED_BLOCK_BEGIN: &str = "<!-- folderbase:begin -->";
const MANAGED_BLOCK_END: &str = "<!-- folderbase:end -->";

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MigrationAnalysis {
    pub id: String,
    pub root: PathBuf,
    pub captured_at: DateTime<Utc>,
    pub inventory_digest: String,
    pub file_count: u64,
    pub total_bytes: u64,
    pub questions: Vec<MigrationQuestion>,
    pub proposed_boundaries: Vec<ProposedBoundary>,
    #[serde(default)]
    pub proposed_targets: Vec<MigrationTarget>,
    #[serde(default)]
    pub reconstructable_trees: Vec<ReconstructableTree>,
    #[serde(default)]
    pub nested_folderbases: Vec<NestedFolderbaseBoundary>,
    #[serde(skip)]
    files: Vec<AnalyzedFile>,
    #[serde(skip)]
    root_identity: Option<RetainedPhysicalIdentity>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MigrationQuestion {
    pub id: String,
    pub prompt: String,
    pub context: String,
    pub kind: MigrationQuestionKind,
    #[serde(default)]
    pub options: Vec<MigrationOption>,
    #[serde(default)]
    pub recommended_option_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MigrationOption {
    pub id: String,
    pub label: String,
    pub consequence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum MigrationQuestionKind {
    Decision,
    Assignment {
        source_path: PathBuf,
        content_kind: MigrationContentKind,
    },
    AssignmentGroup {
        rule_version: String,
        source_root: PathBuf,
        source_paths: Vec<PathBuf>,
        content_kind: MigrationContentKind,
        coverage_digest: String,
    },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum MigrationContentKind {
    Canonical,
    Generated,
    SecretShaped,
    Temporary,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProposedBoundary {
    pub path: PathBuf,
    pub suggested_name: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MigrationTarget {
    pub id: String,
    pub kind: MigrationTargetKind,
    pub path: PathBuf,
    pub suggested_name: String,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MigrationTargetKind {
    Folderbase,
    Workspace,
    ScopedView,
    RetainedFolder,
    Exclusion,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MigrationAnswer {
    pub question_id: String,
    pub answer: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exceptions: Vec<MigrationAnswerException>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MigrationAnswerException {
    pub source_path: PathBuf,
    pub target_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MigrationPlan {
    pub protocol_version: String,
    pub id: String,
    pub root: PathBuf,
    pub state: MigrationState,
    source_inventory: SourceInventory,
    pub answers: Vec<MigrationAnswer>,
    #[serde(default)]
    pub template_references: Vec<String>,
    pub targets: Vec<MigrationTarget>,
    pub operations: Vec<MigrationOperation>,
    pub exclusions: Vec<MigrationExclusion>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    approval_digest: Option<String>,
    #[serde(default, flatten)]
    extensions: BTreeMap<String, serde_json::Value>,
    #[serde(skip)]
    root_identity: Option<RetainedPhysicalIdentity>,
}

impl PartialEq for MigrationPlan {
    fn eq(&self, other: &Self) -> bool {
        self.protocol_version == other.protocol_version
            && self.id == other.id
            && self.root == other.root
            && self.state == other.state
            && self.source_inventory == other.source_inventory
            && self.answers == other.answers
            && self.template_references == other.template_references
            && self.targets == other.targets
            && self.operations == other.operations
            && self.exclusions == other.exclusions
            && self.approval_digest == other.approval_digest
            && self.extensions == other.extensions
    }
}

impl Eq for MigrationPlan {}

impl MigrationPlan {
    /// Reopen a durable migration proposal by ID.
    pub fn reopen(root: impl AsRef<Path>, migration_id: &str) -> Result<Self> {
        let root = canonical_root(root.as_ref())?;
        load_plan(&root, migration_id)
    }

    /// Reject a proposed plan without applying content operations.
    pub fn reject(mut self) -> Result<Self> {
        require_state(self.state, MigrationState::Proposed)?;
        self.state = MigrationState::Rejected;
        persist_plan(&self)?;
        Ok(self)
    }

    /// Propose a digest-bound reorganization of an initialized folderbase.
    ///
    /// Planning reads current bytes and persists a preview, but does not mutate
    /// user content. Approval creates verified recovery snapshots before the
    /// plan can become apply-capable.
    pub fn propose_structural(
        root: impl AsRef<Path>,
        mut operations: Vec<MigrationOperation>,
    ) -> Result<Self> {
        let root = canonical_root(root.as_ref())?;
        let report = validate(&root, ValidationLevel::Shallow)?;
        if !report.valid {
            return Err(FolderbaseError::InvalidRoot(root));
        }
        if operations.is_empty()
            || operations
                .iter()
                .any(|operation| !operation.is_structural())
        {
            return Err(FolderbaseError::InvalidRecord {
                path: root,
                message: "a structural proposal requires at least one typed structural operation"
                    .to_owned(),
            });
        }

        let root_identity = RetainedPhysicalIdentity::from_path(&root)
            .map_err(|source| FolderbaseError::io(&root, source))?;
        let mut source_files = Vec::with_capacity(operations.len());
        let mut source_keys = BTreeSet::new();
        let mut move_destinations = BTreeSet::new();
        for operation in &mut operations {
            let source_path = operation
                .structural_source_path()
                .expect("structural operations always expose one mutable source");
            refuse_nested_folderbase_path(&root, source_path)?;
            if let Some(destination_path) = operation.structural_destination_path() {
                refuse_nested_folderbase_path(&root, destination_path)?;
            }
            enrich_structural_operation(&root, operation)?;
            let source_path = operation
                .structural_source_path()
                .expect("structural operations always expose one mutable source");
            let source_key = portable_path_key(source_path);
            if !source_keys.insert(source_key.clone()) {
                return Err(FolderbaseError::InvalidRecord {
                    path: root,
                    message: format!(
                        "structural operations may mutate a path only once: {}",
                        source_path.display()
                    ),
                });
            }
            if let Some(destination) = operation.structural_destination_path() {
                let destination_key = portable_path_key(destination);
                if !move_destinations.insert(destination_key.clone())
                    || destination_key == source_key
                {
                    return Err(FolderbaseError::InvalidRecord {
                        path: root,
                        message: format!(
                            "structural move destination is ambiguous: {}",
                            destination.display()
                        ),
                    });
                }
            }
            let absolute = safe_join(&root, source_path)?;
            let metadata = fs::symlink_metadata(&absolute)
                .map_err(|source| FolderbaseError::io(&absolute, source))?;
            source_files.push(SourceFile {
                path: source_path.to_path_buf(),
                bytes: metadata.len(),
                sha256: operation
                    .structural_expected_sha256()
                    .expect("enriched structural operation has a digest")
                    .to_owned(),
            });
        }
        if source_keys
            .iter()
            .any(|source| move_destinations.contains(source))
        {
            return Err(FolderbaseError::InvalidRecord {
                path: root,
                message: "structural moves may not form chains or cycles in one approved batch"
                    .to_owned(),
            });
        }
        source_files.sort_by(|left, right| left.path.cmp(&right.path));
        let source_digest = inventory_digest(&source_files);
        let mut extensions = BTreeMap::new();
        extensions.insert(
            "plan_kind".to_owned(),
            serde_json::Value::String(STRUCTURAL_PLAN_KIND.to_owned()),
        );
        extensions.insert(
            "snapshot_required".to_owned(),
            serde_json::Value::Bool(true),
        );
        extensions.insert(
            "base_folderbase_version".to_owned(),
            serde_json::Value::Null,
        );
        extensions.insert("questions".to_owned(), serde_json::Value::Array(Vec::new()));
        extensions.insert(
            "proposed_folderbases".to_owned(),
            serde_json::Value::Array(Vec::new()),
        );
        extensions.insert(
            "storage_impact".to_owned(),
            serde_json::json!({
                "local_bytes_delta": source_files.iter().map(|source| source.bytes).sum::<u64>(),
                "cloud_bytes_delta": 0,
                "reclaimable_local_bytes": 0,
            }),
        );
        extensions.insert(
            "rollback".to_owned(),
            serde_json::json!({
                "snapshot_required": true,
                "strategy": "restore_snapshot",
                "snapshot_id": null,
            }),
        );
        let plan = Self {
            protocol_version: "0.2.0".to_owned(),
            id: format!("migration_{}", Uuid::now_v7()),
            root,
            state: MigrationState::Proposed,
            source_inventory: SourceInventory {
                algorithm: "sha256".to_owned(),
                digest: source_digest,
                files: source_files,
            },
            answers: Vec::new(),
            template_references: Vec::new(),
            targets: Vec::new(),
            operations,
            exclusions: Vec::new(),
            approval_digest: None,
            extensions,
            root_identity: Some(root_identity),
        };
        persist_new_plan(&plan)?;
        Ok(plan)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MigrationState {
    Analyzing,
    Questions,
    Proposed,
    Approved,
    Applying,
    Verified,
    Conflicted,
    RollingBack,
    Rejected,
    RolledBack,
}

impl MigrationState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Analyzing => "analyzing",
            Self::Questions => "questions",
            Self::Proposed => "proposed",
            Self::Approved => "approved",
            Self::Applying => "applying",
            Self::Verified => "verified",
            Self::Conflicted => "conflicted",
            Self::RollingBack => "rolling_back",
            Self::Rejected => "rejected",
            Self::RolledBack => "rolled_back",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum MigrationOperation {
    CreateFolder {
        path: PathBuf,
    },
    CopyFile {
        source_path: PathBuf,
        destination_path: PathBuf,
        expected_sha256: String,
    },
    MoveObject {
        source_path: PathBuf,
        destination_path: PathBuf,
        #[serde(default)]
        expected_sha256: String,
        #[serde(default)]
        snapshot_path: Option<PathBuf>,
        #[serde(default)]
        snapshot_sha256: Option<String>,
    },
    UpdateAdapter {
        path: PathBuf,
        managed_block: String,
        #[serde(default)]
        expected_sha256: String,
        #[serde(default)]
        expected_result_sha256: String,
        #[serde(default)]
        snapshot_path: Option<PathBuf>,
        #[serde(default)]
        snapshot_sha256: Option<String>,
    },
    UpdateIgnorePolicy {
        path: PathBuf,
        content: String,
        #[serde(default)]
        expected_sha256: String,
        #[serde(default)]
        expected_result_sha256: String,
        #[serde(default)]
        snapshot_path: Option<PathBuf>,
        #[serde(default)]
        snapshot_sha256: Option<String>,
    },
    UpdatePolicy {
        manifest_path: PathBuf,
        policy: String,
        value: serde_json::Value,
        #[serde(default)]
        expected_sha256: String,
        #[serde(default)]
        expected_result_sha256: String,
        #[serde(default)]
        snapshot_path: Option<PathBuf>,
        #[serde(default)]
        snapshot_sha256: Option<String>,
    },
    ChangeKind {
        manifest_path: PathBuf,
        new_kind: FolderbaseKind,
        #[serde(default)]
        expected_sha256: String,
        #[serde(default)]
        expected_result_sha256: String,
        #[serde(default)]
        snapshot_path: Option<PathBuf>,
        #[serde(default)]
        snapshot_sha256: Option<String>,
    },
    MarkCanonical {
        object_record_path: PathBuf,
        #[serde(default)]
        expected_sha256: String,
        #[serde(default)]
        expected_result_sha256: String,
        #[serde(default)]
        snapshot_path: Option<PathBuf>,
        #[serde(default)]
        snapshot_sha256: Option<String>,
    },
    MarkSuperseded {
        object_record_path: PathBuf,
        superseded_by: String,
        #[serde(default)]
        expected_sha256: String,
        #[serde(default)]
        expected_result_sha256: String,
        #[serde(default)]
        snapshot_path: Option<PathBuf>,
        #[serde(default)]
        snapshot_sha256: Option<String>,
    },
    ArchiveObject {
        object_record_path: PathBuf,
        #[serde(default)]
        expected_sha256: String,
        #[serde(default)]
        expected_result_sha256: String,
        #[serde(default)]
        snapshot_path: Option<PathBuf>,
        #[serde(default)]
        snapshot_sha256: Option<String>,
    },
    AddRelationship {
        object_record_path: PathBuf,
        relationship_type: String,
        target_object_id: String,
        #[serde(default)]
        expected_sha256: String,
        #[serde(default)]
        expected_result_sha256: String,
        #[serde(default)]
        snapshot_path: Option<PathBuf>,
        #[serde(default)]
        snapshot_sha256: Option<String>,
    },
}

impl MigrationOperation {
    pub fn move_object(
        source_path: impl Into<PathBuf>,
        destination_path: impl Into<PathBuf>,
    ) -> Self {
        Self::MoveObject {
            source_path: source_path.into(),
            destination_path: destination_path.into(),
            expected_sha256: String::new(),
            snapshot_path: None,
            snapshot_sha256: None,
        }
    }

    pub fn update_adapter(path: impl Into<PathBuf>, managed_block: impl Into<String>) -> Self {
        Self::UpdateAdapter {
            path: path.into(),
            managed_block: managed_block.into(),
            expected_sha256: String::new(),
            expected_result_sha256: String::new(),
            snapshot_path: None,
            snapshot_sha256: None,
        }
    }

    pub fn update_ignore_policy(content: impl Into<String>) -> Self {
        Self::UpdateIgnorePolicy {
            path: PathBuf::from(".folderbaseignore"),
            content: content.into(),
            expected_sha256: String::new(),
            expected_result_sha256: String::new(),
            snapshot_path: None,
            snapshot_sha256: None,
        }
    }

    pub fn update_policy(policy: impl Into<String>, value: serde_json::Value) -> Self {
        Self::UpdatePolicy {
            manifest_path: PathBuf::from(".folderbase/manifest.json"),
            policy: policy.into(),
            value,
            expected_sha256: String::new(),
            expected_result_sha256: String::new(),
            snapshot_path: None,
            snapshot_sha256: None,
        }
    }

    pub fn change_kind(new_kind: FolderbaseKind) -> Self {
        Self::ChangeKind {
            manifest_path: PathBuf::from(".folderbase/manifest.json"),
            new_kind,
            expected_sha256: String::new(),
            expected_result_sha256: String::new(),
            snapshot_path: None,
            snapshot_sha256: None,
        }
    }

    pub fn mark_canonical(object_record_path: impl Into<PathBuf>) -> Self {
        Self::MarkCanonical {
            object_record_path: object_record_path.into(),
            expected_sha256: String::new(),
            expected_result_sha256: String::new(),
            snapshot_path: None,
            snapshot_sha256: None,
        }
    }

    pub fn mark_superseded(
        object_record_path: impl Into<PathBuf>,
        superseded_by: impl Into<String>,
    ) -> Self {
        Self::MarkSuperseded {
            object_record_path: object_record_path.into(),
            superseded_by: superseded_by.into(),
            expected_sha256: String::new(),
            expected_result_sha256: String::new(),
            snapshot_path: None,
            snapshot_sha256: None,
        }
    }

    pub fn archive_object(object_record_path: impl Into<PathBuf>) -> Self {
        Self::ArchiveObject {
            object_record_path: object_record_path.into(),
            expected_sha256: String::new(),
            expected_result_sha256: String::new(),
            snapshot_path: None,
            snapshot_sha256: None,
        }
    }

    pub fn add_relationship(
        object_record_path: impl Into<PathBuf>,
        relationship_type: impl Into<String>,
        target_object_id: impl Into<String>,
    ) -> Self {
        Self::AddRelationship {
            object_record_path: object_record_path.into(),
            relationship_type: relationship_type.into(),
            target_object_id: target_object_id.into(),
            expected_sha256: String::new(),
            expected_result_sha256: String::new(),
            snapshot_path: None,
            snapshot_sha256: None,
        }
    }

    fn is_structural(&self) -> bool {
        !matches!(self, Self::CreateFolder { .. } | Self::CopyFile { .. })
    }

    fn structural_source_path(&self) -> Option<&Path> {
        match self {
            Self::MoveObject { source_path, .. } => Some(source_path),
            Self::UpdateAdapter { path, .. } | Self::UpdateIgnorePolicy { path, .. } => Some(path),
            Self::UpdatePolicy { manifest_path, .. } | Self::ChangeKind { manifest_path, .. } => {
                Some(manifest_path)
            }
            Self::MarkCanonical {
                object_record_path, ..
            }
            | Self::MarkSuperseded {
                object_record_path, ..
            }
            | Self::ArchiveObject {
                object_record_path, ..
            }
            | Self::AddRelationship {
                object_record_path, ..
            } => Some(object_record_path),
            Self::CreateFolder { .. } | Self::CopyFile { .. } => None,
        }
    }

    fn structural_destination_path(&self) -> Option<&Path> {
        match self {
            Self::MoveObject {
                destination_path, ..
            } => Some(destination_path),
            _ => None,
        }
    }

    fn structural_expected_sha256(&self) -> Option<&str> {
        match self {
            Self::MoveObject {
                expected_sha256, ..
            }
            | Self::UpdateAdapter {
                expected_sha256, ..
            }
            | Self::UpdateIgnorePolicy {
                expected_sha256, ..
            }
            | Self::UpdatePolicy {
                expected_sha256, ..
            }
            | Self::ChangeKind {
                expected_sha256, ..
            }
            | Self::MarkCanonical {
                expected_sha256, ..
            }
            | Self::MarkSuperseded {
                expected_sha256, ..
            }
            | Self::ArchiveObject {
                expected_sha256, ..
            }
            | Self::AddRelationship {
                expected_sha256, ..
            } => Some(expected_sha256),
            Self::CreateFolder { .. } | Self::CopyFile { .. } => None,
        }
    }

    fn structural_expected_result_sha256(&self) -> Option<&str> {
        match self {
            Self::MoveObject {
                expected_sha256, ..
            } => Some(expected_sha256),
            Self::UpdateAdapter {
                expected_result_sha256,
                ..
            }
            | Self::UpdateIgnorePolicy {
                expected_result_sha256,
                ..
            }
            | Self::UpdatePolicy {
                expected_result_sha256,
                ..
            }
            | Self::ChangeKind {
                expected_result_sha256,
                ..
            }
            | Self::MarkCanonical {
                expected_result_sha256,
                ..
            }
            | Self::MarkSuperseded {
                expected_result_sha256,
                ..
            }
            | Self::ArchiveObject {
                expected_result_sha256,
                ..
            }
            | Self::AddRelationship {
                expected_result_sha256,
                ..
            } => Some(expected_result_sha256),
            Self::CreateFolder { .. } | Self::CopyFile { .. } => None,
        }
    }

    fn structural_snapshot(&self) -> Option<(&Path, &str)> {
        match self {
            Self::MoveObject {
                snapshot_path,
                snapshot_sha256,
                ..
            }
            | Self::UpdateAdapter {
                snapshot_path,
                snapshot_sha256,
                ..
            }
            | Self::UpdateIgnorePolicy {
                snapshot_path,
                snapshot_sha256,
                ..
            }
            | Self::UpdatePolicy {
                snapshot_path,
                snapshot_sha256,
                ..
            }
            | Self::ChangeKind {
                snapshot_path,
                snapshot_sha256,
                ..
            }
            | Self::MarkCanonical {
                snapshot_path,
                snapshot_sha256,
                ..
            }
            | Self::MarkSuperseded {
                snapshot_path,
                snapshot_sha256,
                ..
            }
            | Self::ArchiveObject {
                snapshot_path,
                snapshot_sha256,
                ..
            }
            | Self::AddRelationship {
                snapshot_path,
                snapshot_sha256,
                ..
            } => snapshot_path.as_deref().zip(snapshot_sha256.as_deref()),
            Self::CreateFolder { .. } | Self::CopyFile { .. } => None,
        }
    }

    fn set_structural_snapshot(&mut self, path: PathBuf, sha256: String) {
        match self {
            Self::MoveObject {
                snapshot_path,
                snapshot_sha256,
                ..
            }
            | Self::UpdateAdapter {
                snapshot_path,
                snapshot_sha256,
                ..
            }
            | Self::UpdateIgnorePolicy {
                snapshot_path,
                snapshot_sha256,
                ..
            }
            | Self::UpdatePolicy {
                snapshot_path,
                snapshot_sha256,
                ..
            }
            | Self::ChangeKind {
                snapshot_path,
                snapshot_sha256,
                ..
            }
            | Self::MarkCanonical {
                snapshot_path,
                snapshot_sha256,
                ..
            }
            | Self::MarkSuperseded {
                snapshot_path,
                snapshot_sha256,
                ..
            }
            | Self::ArchiveObject {
                snapshot_path,
                snapshot_sha256,
                ..
            }
            | Self::AddRelationship {
                snapshot_path,
                snapshot_sha256,
                ..
            } => {
                *snapshot_path = Some(path);
                *snapshot_sha256 = Some(sha256);
            }
            Self::CreateFolder { .. } | Self::CopyFile { .. } => {
                unreachable!("additive operation cannot receive a structural snapshot")
            }
        }
    }
}

fn enrich_structural_operation(root: &Path, operation: &mut MigrationOperation) -> Result<()> {
    let source_path = operation
        .structural_source_path()
        .expect("structural operation has a source")
        .to_path_buf();
    ensure_safe_relative(&source_path)?;
    let source = safe_join(root, &source_path)?;
    let bytes = if matches!(operation, MigrationOperation::MoveObject { .. }) {
        let metadata =
            fs::symlink_metadata(&source).map_err(|error| FolderbaseError::io(&source, error))?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(FolderbaseError::InvalidRecord {
                path: source.clone(),
                message: "structural move source must be a regular file".to_owned(),
            });
        }
        None
    } else {
        Some(read_bounded_regular(&source, MAX_MIGRATION_PLAN_BYTES)?)
    };
    let expected_sha256 = match bytes.as_deref() {
        Some(bytes) => sha256_bytes(bytes),
        None => sha256_path(&source)?,
    };

    match operation {
        MigrationOperation::MoveObject {
            source_path,
            destination_path,
            expected_sha256: expected,
            snapshot_path,
            snapshot_sha256,
        } => {
            ensure_move_content_path(source_path)?;
            ensure_move_content_path(destination_path)?;
            refuse_tracked_move_path(root, source_path)?;
            refuse_tracked_move_path(root, destination_path)?;
            if portable_path_key(source_path) == portable_path_key(destination_path) {
                return Err(FolderbaseError::InvalidRecord {
                    path: source,
                    message: "move_object source and destination must be distinct".to_owned(),
                });
            }
            let destination = safe_join(root, destination_path)?;
            if destination.exists() {
                return Err(FolderbaseError::WouldOverwrite(destination));
            }
            let parent = destination
                .parent()
                .ok_or_else(|| FolderbaseError::UnsafePath(destination_path.clone()))?;
            let parent_metadata = fs::symlink_metadata(parent)
                .map_err(|source| FolderbaseError::io(parent, source))?;
            if !parent_metadata.is_dir() || parent_metadata.file_type().is_symlink() {
                return Err(FolderbaseError::UnsafePath(parent.to_path_buf()));
            }
            *expected = expected_sha256;
            *snapshot_path = None;
            *snapshot_sha256 = None;
        }
        MigrationOperation::UpdateAdapter {
            path,
            managed_block,
            expected_sha256: expected,
            expected_result_sha256,
            snapshot_path,
            snapshot_sha256,
        } => {
            let bytes = bytes
                .as_deref()
                .expect("adapter updates require bounded source bytes");
            if !matches!(
                path.file_name().and_then(|name| name.to_str()),
                Some("AGENTS.md" | "CLAUDE.md")
            ) {
                return Err(FolderbaseError::InvalidRecord {
                    path: source,
                    message: "update_adapter is limited to AGENTS.md or CLAUDE.md".to_owned(),
                });
            }
            let current =
                std::str::from_utf8(bytes).map_err(|_| FolderbaseError::InvalidRecord {
                    path: source.clone(),
                    message: "agent adapter must be UTF-8 text".to_owned(),
                })?;
            let merged = merge_managed_block(current, managed_block, &source)?;
            *expected = expected_sha256;
            *expected_result_sha256 = sha256_bytes(merged.as_bytes());
            *snapshot_path = None;
            *snapshot_sha256 = None;
        }
        MigrationOperation::UpdateIgnorePolicy {
            path,
            content,
            expected_sha256: expected,
            expected_result_sha256,
            snapshot_path,
            snapshot_sha256,
        } => {
            if path != Path::new(".folderbaseignore")
                || content.len() as u64 > MAX_STRUCTURAL_TEXT_BYTES
                || content.contains('\0')
            {
                return Err(FolderbaseError::InvalidRecord {
                    path: source,
                    message: "ignore policy must be bounded UTF-8 for .folderbaseignore".to_owned(),
                });
            }
            *expected = expected_sha256;
            *expected_result_sha256 = sha256_bytes(content.as_bytes());
            *snapshot_path = None;
            *snapshot_sha256 = None;
        }
        MigrationOperation::UpdatePolicy {
            manifest_path,
            policy,
            value,
            expected_sha256: expected,
            expected_result_sha256,
            snapshot_path,
            snapshot_sha256,
        } => {
            let bytes = bytes
                .as_deref()
                .expect("policy updates require bounded source bytes");
            if manifest_path != Path::new(".folderbase/manifest.json")
                || !is_lowercase_protocol_token(policy)
            {
                return Err(FolderbaseError::InvalidRecord {
                    path: source,
                    message: "manifest policy key is invalid".to_owned(),
                });
            }
            let mut document = parse_structural_json(&source, bytes)?;
            let policies = document
                .get_mut("policies")
                .and_then(serde_json::Value::as_object_mut)
                .ok_or_else(|| FolderbaseError::InvalidRecord {
                    path: source.clone(),
                    message: "manifest is missing its policies object".to_owned(),
                })?;
            policies.insert(policy.clone(), value.clone());
            let result = pretty_json_bytes(&source, &document)?;
            *expected = expected_sha256;
            *expected_result_sha256 = sha256_bytes(&result);
            *snapshot_path = None;
            *snapshot_sha256 = None;
        }
        MigrationOperation::ChangeKind {
            manifest_path,
            new_kind,
            expected_sha256: expected,
            expected_result_sha256,
            snapshot_path,
            snapshot_sha256,
        } => {
            let bytes = bytes
                .as_deref()
                .expect("kind changes require bounded source bytes");
            if manifest_path != Path::new(".folderbase/manifest.json") {
                return Err(FolderbaseError::InvalidRecord {
                    path: source,
                    message: "kind changes must target the canonical manifest".to_owned(),
                });
            }
            let mut document = parse_structural_json(&source, bytes)?;
            let folderbase = document
                .get_mut("folderbase")
                .and_then(serde_json::Value::as_object_mut)
                .ok_or_else(|| FolderbaseError::InvalidRecord {
                    path: source.clone(),
                    message: "manifest is missing its folderbase object".to_owned(),
                })?;
            folderbase.insert(
                "kind".to_owned(),
                serde_json::Value::String(structural_folderbase_kind_name(*new_kind).to_owned()),
            );
            let result = pretty_json_bytes(&source, &document)?;
            *expected = expected_sha256;
            *expected_result_sha256 = sha256_bytes(&result);
            *snapshot_path = None;
            *snapshot_sha256 = None;
        }
        MigrationOperation::MarkCanonical {
            object_record_path,
            expected_sha256: expected,
            expected_result_sha256,
            snapshot_path,
            snapshot_sha256,
        } => {
            let bytes = bytes
                .as_deref()
                .expect("lifecycle changes require bounded source bytes");
            validate_object_record_path(object_record_path, &source)?;
            let mut document = parse_structural_json(&source, bytes)?;
            set_object_lifecycle(&source, &mut document, "canonical", None)?;
            let result = pretty_json_bytes(&source, &document)?;
            *expected = expected_sha256;
            *expected_result_sha256 = sha256_bytes(&result);
            *snapshot_path = None;
            *snapshot_sha256 = None;
        }
        MigrationOperation::ArchiveObject {
            object_record_path,
            expected_sha256: expected,
            expected_result_sha256,
            snapshot_path,
            snapshot_sha256,
        } => {
            let bytes = bytes
                .as_deref()
                .expect("lifecycle changes require bounded source bytes");
            validate_object_record_path(object_record_path, &source)?;
            let mut document = parse_structural_json(&source, bytes)?;
            set_object_lifecycle(&source, &mut document, "archived", None)?;
            validate_archive_lifecycle(&source, &document)?;
            let result = pretty_json_bytes(&source, &document)?;
            *expected = expected_sha256;
            *expected_result_sha256 = sha256_bytes(&result);
            *snapshot_path = None;
            *snapshot_sha256 = None;
        }
        MigrationOperation::MarkSuperseded {
            object_record_path,
            superseded_by,
            expected_sha256: expected,
            expected_result_sha256,
            snapshot_path,
            snapshot_sha256,
        } => {
            let bytes = bytes
                .as_deref()
                .expect("lifecycle changes require bounded source bytes");
            validate_object_record_path(object_record_path, &source)?;
            validate_object_id(&source, superseded_by)?;
            let mut document = parse_structural_json(&source, bytes)?;
            set_object_lifecycle(
                &source,
                &mut document,
                "superseded",
                Some(superseded_by.as_str()),
            )?;
            let result = pretty_json_bytes(&source, &document)?;
            *expected = expected_sha256;
            *expected_result_sha256 = sha256_bytes(&result);
            *snapshot_path = None;
            *snapshot_sha256 = None;
        }
        MigrationOperation::AddRelationship {
            object_record_path,
            relationship_type,
            target_object_id,
            expected_sha256: expected,
            expected_result_sha256,
            snapshot_path,
            snapshot_sha256,
        } => {
            let bytes = bytes
                .as_deref()
                .expect("relationship changes require bounded source bytes");
            validate_object_record_path(object_record_path, &source)?;
            if !is_lowercase_protocol_token(relationship_type) {
                return Err(FolderbaseError::InvalidRecord {
                    path: source,
                    message: "relationship type must be lowercase snake_case".to_owned(),
                });
            }
            validate_object_id(&source, target_object_id)?;
            let mut document = parse_structural_json(&source, bytes)?;
            let object =
                document
                    .as_object_mut()
                    .ok_or_else(|| FolderbaseError::InvalidRecord {
                        path: source.clone(),
                        message: "object record must be a JSON object".to_owned(),
                    })?;
            let relationships = object
                .entry("relationships")
                .or_insert_with(|| serde_json::Value::Array(Vec::new()))
                .as_array_mut()
                .ok_or_else(|| FolderbaseError::InvalidRecord {
                    path: source.clone(),
                    message: "object relationships must be an array".to_owned(),
                })?;
            let relationship = serde_json::json!({
                "type": relationship_type,
                "target": target_object_id,
            });
            if !relationships.contains(&relationship) {
                relationships.push(relationship);
            }
            let result = pretty_json_bytes(&source, &document)?;
            *expected = expected_sha256;
            *expected_result_sha256 = sha256_bytes(&result);
            *snapshot_path = None;
            *snapshot_sha256 = None;
        }
        MigrationOperation::CreateFolder { .. } | MigrationOperation::CopyFile { .. } => {
            unreachable!("additive operations are rejected before structural enrichment")
        }
    }
    Ok(())
}

fn read_bounded_regular(path: &Path, maximum_bytes: u64) -> Result<Vec<u8>> {
    let metadata =
        fs::symlink_metadata(path).map_err(|source| FolderbaseError::io(path, source))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > maximum_bytes {
        return Err(FolderbaseError::InvalidRecord {
            path: path.to_path_buf(),
            message: "structural source must be a bounded regular file".to_owned(),
        });
    }
    fs::read(path).map_err(|source| FolderbaseError::io(path, source))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn parse_structural_json(path: &Path, bytes: &[u8]) -> Result<serde_json::Value> {
    serde_json::from_slice(bytes).map_err(|source| FolderbaseError::json(path, source))
}

fn pretty_json_bytes(path: &Path, value: &serde_json::Value) -> Result<Vec<u8>> {
    let mut bytes =
        serde_json::to_vec_pretty(value).map_err(|source| FolderbaseError::json(path, source))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn structural_folderbase_kind_name(kind: FolderbaseKind) -> &'static str {
    match kind {
        FolderbaseKind::Person => "person",
        FolderbaseKind::Organization => "organization",
        FolderbaseKind::Engagement => "engagement",
        FolderbaseKind::Project => "project",
        FolderbaseKind::Customer => "customer",
        FolderbaseKind::Temporary => "temporary",
        FolderbaseKind::Custom => "custom",
    }
}

fn validate_object_record_path(path: &Path, absolute: &Path) -> Result<()> {
    if !path.starts_with(".folderbase/objects")
        || path.extension().and_then(|extension| extension.to_str()) != Some("json")
    {
        return Err(FolderbaseError::InvalidRecord {
            path: absolute.to_path_buf(),
            message: "lifecycle and relationship changes require an object record".to_owned(),
        });
    }
    Ok(())
}

fn validate_object_id(path: &Path, object_id: &str) -> Result<()> {
    if object_id
        .strip_prefix("obj_")
        .is_none_or(|value| Uuid::parse_str(value).is_err())
    {
        return Err(FolderbaseError::InvalidRecord {
            path: path.to_path_buf(),
            message: "object identifier is invalid".to_owned(),
        });
    }
    Ok(())
}

fn is_lowercase_protocol_token(value: &str) -> bool {
    value
        .chars()
        .next()
        .is_some_and(|first| first.is_ascii_lowercase())
        && value
            .chars()
            .all(|character| character.is_ascii_lowercase() || character == '_')
}

fn set_object_lifecycle(
    path: &Path,
    document: &mut serde_json::Value,
    status: &str,
    superseded_by: Option<&str>,
) -> Result<()> {
    let object = document
        .as_object_mut()
        .ok_or_else(|| FolderbaseError::InvalidRecord {
            path: path.to_path_buf(),
            message: "object record must be a JSON object".to_owned(),
        })?;
    let lifecycle = object
        .entry("lifecycle")
        .or_insert_with(|| serde_json::json!({}))
        .as_object_mut()
        .ok_or_else(|| FolderbaseError::InvalidRecord {
            path: path.to_path_buf(),
            message: "object lifecycle must be an object".to_owned(),
        })?;
    lifecycle.insert(
        "status".to_owned(),
        serde_json::Value::String(status.to_owned()),
    );
    if let Some(replacement) = superseded_by {
        lifecycle.insert(
            "superseded_by".to_owned(),
            serde_json::Value::String(replacement.to_owned()),
        );
    } else {
        lifecycle.remove("superseded_by");
    }
    Ok(())
}

fn validate_archive_lifecycle(path: &Path, document: &serde_json::Value) -> Result<()> {
    let lifecycle = document
        .get("lifecycle")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| FolderbaseError::InvalidRecord {
            path: path.to_path_buf(),
            message: "archived object requires lifecycle metadata".to_owned(),
        })?;
    if ["remote_size", "expected_restore_size"]
        .iter()
        .any(|field| !lifecycle.get(*field).is_some_and(serde_json::Value::is_u64))
    {
        return Err(FolderbaseError::InvalidRecord {
            path: path.to_path_buf(),
            message: "archiving requires remote_size and expected_restore_size recovery metadata"
                .to_owned(),
        });
    }
    Ok(())
}

fn merge_managed_block(current: &str, body: &str, path: &Path) -> Result<String> {
    validate_managed_block_body(body, path)?;
    let managed = format!(
        "{MANAGED_BLOCK_BEGIN}\n{}\n{MANAGED_BLOCK_END}",
        body.trim_end()
    );
    let begins = current
        .match_indices(MANAGED_BLOCK_BEGIN)
        .collect::<Vec<_>>();
    let ends = current.match_indices(MANAGED_BLOCK_END).collect::<Vec<_>>();
    match (begins.as_slice(), ends.as_slice()) {
        ([], []) => {
            let separator = if current.is_empty() || current.ends_with("\n\n") {
                ""
            } else if current.ends_with('\n') {
                "\n"
            } else {
                "\n\n"
            };
            Ok(format!("{current}{separator}{managed}\n"))
        }
        ([(begin, _)], [(end, _)]) if begin < end => {
            let after = end + MANAGED_BLOCK_END.len();
            Ok(format!(
                "{}{}{}",
                &current[..*begin],
                managed,
                &current[after..]
            ))
        }
        _ => Err(FolderbaseError::InvalidRecord {
            path: path.to_path_buf(),
            message: "adapter contains ambiguous Folderbase managed blocks".to_owned(),
        }),
    }
}

pub(crate) fn validate_managed_block_body(body: &str, path: &Path) -> Result<()> {
    if body.contains(MANAGED_BLOCK_BEGIN)
        || body.contains(MANAGED_BLOCK_END)
        || body.len() as u64 > MAX_STRUCTURAL_TEXT_BYTES
        || body.contains('\0')
    {
        return Err(FolderbaseError::InvalidRecord {
            path: path.to_path_buf(),
            message: "managed adapter body is invalid".to_owned(),
        });
    }
    Ok(())
}

pub(crate) fn validate_managed_block_body_syntax(body: &str, path: &Path) -> Result<()> {
    if body.contains("<!-- folderbase:") || body.contains('\0') {
        return Err(FolderbaseError::InvalidRecord {
            path: path.to_path_buf(),
            message: "managed adapter body is invalid".to_owned(),
        });
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MigrationExclusion {
    pub path: PathBuf,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MigrationPreview {
    pub migration_id: String,
    pub targets: Vec<MigrationTarget>,
    pub creates_directories: Vec<PathBuf>,
    pub copies: Vec<MigrationCopyPreview>,
    pub source_bytes: u64,
    pub additional_local_bytes: u64,
    pub source_files_remain: bool,
    #[serde(default)]
    pub structural_operations: Vec<MigrationOperation>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MigrationCopyPreview {
    pub source_path: PathBuf,
    pub destination_path: PathBuf,
    pub bytes: u64,
}

/// An approval token tied to a specific immutable plan digest.
#[derive(Debug)]
pub struct ApprovedMigration {
    plan: MigrationPlan,
    approval_digest: String,
}

impl ApprovedMigration {
    /// Reopen an approved durable plan as an apply-capable token.
    pub fn reopen(root: impl AsRef<Path>, migration_id: &str) -> Result<Self> {
        let plan = MigrationPlan::reopen(root, migration_id)?;
        require_state(plan.state, MigrationState::Approved)?;
        let approval_digest = plan
            .approval_digest
            .clone()
            .ok_or(FolderbaseError::MigrationApprovalMismatch)?;
        if plan_digest(&plan)? != approval_digest {
            return Err(FolderbaseError::MigrationApprovalMismatch);
        }
        Ok(Self {
            plan,
            approval_digest,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MigrationResult {
    pub migration_id: String,
    pub root: PathBuf,
    pub state: MigrationState,
    pub created_paths: Vec<PathBuf>,
    pub journal_path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RollbackResult {
    pub migration_id: String,
    pub removed_paths: Vec<PathBuf>,
    pub state: MigrationState,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct SourceFile {
    path: PathBuf,
    bytes: u64,
    sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MigrationJournal {
    protocol_version: String,
    id: String,
    root: PathBuf,
    state: MigrationState,
    approval_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    approval_scheme: Option<String>,
    source_inventory: SourceInventory,
    answers: Vec<MigrationAnswer>,
    #[serde(default)]
    template_references: Vec<String>,
    #[serde(default)]
    targets: Vec<MigrationTarget>,
    operations: Vec<MigrationOperation>,
    exclusions: Vec<MigrationExclusion>,
    #[serde(default)]
    plan_extensions: BTreeMap<String, serde_json::Value>,
    #[serde(default)]
    materialized_folderbases: Vec<MaterializedFolderbase>,
    #[serde(default)]
    materialized_workspace: Option<MaterializedWorkspace>,
    created_paths: Vec<PathBuf>,
    completed_operations: usize,
    in_flight_operation: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct SourceInventory {
    algorithm: String,
    digest: String,
    #[serde(default)]
    files: Vec<SourceFile>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct SourceTopologySnapshot {
    version: String,
    files: Vec<PathBuf>,
    reconstructable_trees: Vec<PathBuf>,
    nested_folderbases: Vec<NestedFolderbaseBoundary>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct MaterializedFolderbase {
    target_id: String,
    path: PathBuf,
    folderbase_id: String,
    name: String,
    template_reference: String,
    state: MaterializationState,
    created_directories: Vec<PathBuf>,
    created_files: BTreeMap<PathBuf, String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum MaterializationState {
    Planned,
    Verified,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct MaterializedWorkspace {
    path: PathBuf,
    workspace_id: String,
    name: String,
    state: MaterializationState,
    folderbases: Vec<WorkspaceFolderbaseLink>,
    created_files: BTreeMap<PathBuf, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct WorkspaceFolderbaseLink {
    folderbase_id: String,
    label: String,
    path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FolderbaseMaterializationSpec {
    target_id: String,
    name: String,
    path: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CanonicalScopeAnswer {
    OneFolderbase,
    ProposedBoundaries,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GeneratedContentAnswer {
    Exclude,
    Include,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedMigrationAnswers {
    canonical_scope: CanonicalScopeAnswer,
    generated_content: GeneratedContentAnswer,
    assignments: BTreeMap<PathBuf, ParsedAssignment>,
    grouped_assignments: Vec<GroupedAssignmentContract>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedAssignment {
    content_kind: MigrationContentKind,
    target_id: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum AssignmentSourceKind {
    #[serde(rename = "regular_file")]
    File,
    ReconstructableTree,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AssignmentGroupMember {
    path: PathBuf,
    kind: AssignmentSourceKind,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct GroupedAssignmentContract {
    question_id: String,
    rule_version: String,
    source_root: PathBuf,
    members: Vec<GroupedAssignmentMemberContract>,
    content_kind: MigrationContentKind,
    coverage_digest: String,
    default_target_id: String,
    exceptions: Vec<MigrationAnswerException>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct GroupedAssignmentMemberContract {
    source_path: PathBuf,
    source_kind: AssignmentSourceKind,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct GroupedAssignmentsExtension {
    version: String,
    groups: Vec<GroupedAssignmentContract>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct ExpandedReconstructableTreesExtension {
    version: String,
    trees: Vec<ExpandedReconstructableTreeMembership>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct ExpandedReconstructableTreeMembership {
    source_root: PathBuf,
    source_paths: Vec<PathBuf>,
}

impl ParsedMigrationAnswers {
    fn assignment_for(&self, path: &Path) -> Option<&ParsedAssignment> {
        self.assignments.get(path)
    }
}

/// Analyze a folder without changing it.
pub fn analyze_migration(root: impl AsRef<Path>) -> Result<MigrationAnalysis> {
    let root = canonical_root(root.as_ref())?;
    let root_identity = RetainedPhysicalIdentity::from_path(&root)
        .map_err(|source| FolderbaseError::io(&root, source))?;
    let folder = analyze_folder(&root)?;
    let files = folder.files;
    let mut proposed_boundaries = folder
        .boundary_hints
        .iter()
        .filter(|hint| {
            hint.kind == "permission" && hint.path.components().count() == 1
        })
        .map(|hint| {
            let name = hint.path.to_string_lossy();
            ProposedBoundary {
                path: hint.path.clone(),
                suggested_name: humanize_name(&name),
                reason: "Top-level content suggests a distinct project, client, commercial, or restricted scope.".to_owned(),
            }
        })
        .collect::<Vec<_>>();
    proposed_boundaries.sort_by(|left, right| left.path.cmp(&right.path));
    proposed_boundaries.dedup_by(|left, right| left.path == right.path);
    let mut proposed_targets = vec![
        MigrationTarget {
            id: "target_primary_folderbase".to_owned(),
            kind: MigrationTargetKind::Folderbase,
            path: PathBuf::from("."),
            suggested_name: root
                .file_name()
                .and_then(|name| name.to_str())
                .map(humanize_name)
                .unwrap_or_else(|| "Primary Folderbase".to_owned()),
            reason: "The ordinary folder can remain one explicit folderbase boundary.".to_owned(),
        },
        MigrationTarget {
            id: "target_retained_source".to_owned(),
            kind: MigrationTargetKind::RetainedFolder,
            path: PathBuf::from("."),
            suggested_name: "Retained source folder".to_owned(),
            reason: "Content may remain in the unmanaged source without being copied.".to_owned(),
        },
        MigrationTarget {
            id: "target_exclusion".to_owned(),
            kind: MigrationTargetKind::Exclusion,
            path: PathBuf::from("."),
            suggested_name: "Explicit exclusion".to_owned(),
            reason: "Content is left in the source and recorded as excluded from the proposal."
                .to_owned(),
        },
    ];
    for boundary in &proposed_boundaries {
        let suggested_kind = target_kind_for_boundary(&boundary.path);
        let suggested_prefix = match suggested_kind {
            MigrationTargetKind::Folderbase => "target_folderbase",
            MigrationTargetKind::Workspace => "target_workspace",
            MigrationTargetKind::ScopedView => "target_scoped_view",
            MigrationTargetKind::RetainedFolder | MigrationTargetKind::Exclusion => unreachable!(),
        };
        proposed_targets.push(MigrationTarget {
            id: stable_path_id(suggested_prefix, &boundary.path),
            kind: suggested_kind,
            path: boundary.path.clone(),
            suggested_name: boundary.suggested_name.clone(),
            reason: boundary.reason.clone(),
        });
        if suggested_kind != MigrationTargetKind::Folderbase {
            proposed_targets.push(MigrationTarget {
                id: stable_path_id("target_folderbase", &boundary.path),
                kind: MigrationTargetKind::Folderbase,
                path: boundary.path.clone(),
                suggested_name: boundary.suggested_name.clone(),
                reason: "Explicit alternative if the user confirms this folder needs its own durable permission boundary."
                    .to_owned(),
            });
        }
    }
    if proposed_targets
        .iter()
        .any(|target| target.kind == MigrationTargetKind::ScopedView)
        || proposed_targets
            .iter()
            .filter(|target| target.kind == MigrationTargetKind::Folderbase)
            .count()
            > 1
    {
        proposed_targets.push(MigrationTarget {
            id: "target_workspace".to_owned(),
            kind: MigrationTargetKind::Workspace,
            path: PathBuf::from("."),
            suggested_name: "Migration workspace".to_owned(),
            reason:
                "A workspace may compose approved folderbases and scoped views but never owns content."
                    .to_owned(),
        });
    }
    let inventory_digest = metadata_inventory_digest(
        &files,
        &folder.reconstructable_trees,
        &folder.nested_folderbases,
    );
    let total_bytes = folder.inventory.total_bytes;
    let captured_at = fs::metadata(&root)
        .and_then(|metadata| metadata.modified())
        .map(DateTime::<Utc>::from)
        .map_err(|source| FolderbaseError::io(&root, source))?;

    let mut questions = vec![
        MigrationQuestion {
            id: "question_canonical_scope".to_owned(),
            prompt: "Choose `one_folderbase` or `proposed_boundaries`.".to_owned(),
            context: "A proposed-boundaries plan stages each detected boundary as an independent folderbase-shaped root; folder nesting alone never grants access.".to_owned(),
            kind: MigrationQuestionKind::Decision,
            options: vec![
                MigrationOption {
                    id: "one_folderbase".to_owned(),
                    label: "One folderbase".to_owned(),
                    consequence: "Keep included canonical content under one permission boundary."
                        .to_owned(),
                },
                MigrationOption {
                    id: "proposed_boundaries".to_owned(),
                    label: "Review proposed boundaries".to_owned(),
                    consequence: "Stage only explicitly assigned folderbase targets as independent permission boundaries."
                        .to_owned(),
                },
            ],
            recommended_option_id: "one_folderbase".to_owned(),
        },
        MigrationQuestion {
            id: "question_generated_content".to_owned(),
            prompt: "Choose `exclude_generated` or `include_generated`.".to_owned(),
            context: "Dependencies such as node_modules should normally be reconstructed, while final generated deliverables may be canonical evidence worth including.".to_owned(),
            kind: MigrationQuestionKind::Decision,
            options: vec![
                MigrationOption {
                    id: "exclude_generated".to_owned(),
                    label: "Keep generated content out of the migration".to_owned(),
                    consequence: "Leave reconstructable trees in the source and record the exclusion in the proposal."
                        .to_owned(),
                },
                MigrationOption {
                    id: "include_generated".to_owned(),
                    label: "Include generated content".to_owned(),
                    consequence: "Expand reconstructable trees during planning and assign their files to an approved destination."
                        .to_owned(),
                },
            ],
            recommended_option_id: "exclude_generated".to_owned(),
        },
    ];
    if files.iter().any(AnalyzedFile::is_secret_shaped) {
        questions.push(MigrationQuestion {
            id: "question_secrets".to_owned(),
            prompt: "Secret-shaped files were detected. Confirm `local_only`.".to_owned(),
            context: "Folderbase never assumes a secret-shaped file is safe to copy into a shareable folderbase.".to_owned(),
            kind: MigrationQuestionKind::Decision,
            options: vec![MigrationOption {
                id: "local_only".to_owned(),
                label: "Keep secret-shaped content local".to_owned(),
                consequence:
                    "Retain secret-shaped files in the source and exclude them from the migration."
                        .to_owned(),
            }],
            recommended_option_id: "local_only".to_owned(),
        });
    }
    questions.extend(assignment_questions(
        &files,
        &folder.reconstructable_trees,
        &proposed_targets,
    ));

    Ok(MigrationAnalysis {
        id: format!("analysis_{inventory_digest}"),
        root,
        captured_at,
        inventory_digest,
        file_count: files.len() as u64,
        total_bytes,
        questions,
        proposed_boundaries,
        proposed_targets,
        reconstructable_trees: folder.reconstructable_trees,
        nested_folderbases: folder.nested_folderbases,
        files,
        root_identity: Some(root_identity),
    })
}

/// Turn a read-only analysis and founder answers into an explicit proposal.
///
/// The initial engine is deliberately conservative: generated and
/// secret-shaped content is excluded, while canonical source content may be
/// copied into a user-selected staging folder. Source bytes are never removed.
pub fn plan_migration(
    analysis: MigrationAnalysis,
    answers: Vec<MigrationAnswer>,
    destination_folder: impl AsRef<Path>,
) -> Result<MigrationPlan> {
    let destination_folder = destination_folder.as_ref().to_path_buf();
    ensure_safe_relative(&destination_folder)?;
    let current_root = PhysicalIdentity::from_path(&analysis.root)
        .map_err(|source| FolderbaseError::io(&analysis.root, source))?;
    if analysis.root_identity.as_ref().map(|root| root.identity()) != Some(current_root) {
        return Err(FolderbaseError::MigrationSourceChanged(
            analysis.root.clone(),
        ));
    }
    let refreshed = analyze_folder(&analysis.root)?;
    let refreshed_digest = metadata_inventory_digest(
        &refreshed.files,
        &refreshed.reconstructable_trees,
        &refreshed.nested_folderbases,
    );
    if refreshed_digest != analysis.inventory_digest {
        return Err(FolderbaseError::MigrationSourceChanged(
            analysis.root.clone(),
        ));
    }
    let parsed_answers = validate_answers(&analysis, &answers)?;

    let mut operations = vec![MigrationOperation::CreateFolder {
        path: destination_folder.clone(),
    }];
    let mut exclusions = Vec::new();
    let mut target_destinations = BTreeMap::new();
    let mut target_destination_keys = BTreeSet::new();
    let mut source_files = Vec::new();
    let mut candidate_files = analysis.files.clone();
    let mut expanded_tree_assignments = BTreeMap::new();
    let mut expanded_tree_memberships = Vec::new();
    if parsed_answers.generated_content == GeneratedContentAnswer::Include {
        for tree in &analysis.reconstructable_trees {
            let assignment = parsed_answers.assignment_for(&tree.path).ok_or_else(|| {
                FolderbaseError::InvalidRecord {
                    path: analysis.root.clone(),
                    message: format!(
                        "missing explicit migration assignment for {}",
                        tree.path.display()
                    ),
                }
            })?;
            let target = analysis
                .proposed_targets
                .iter()
                .find(|target| target.id == assignment.target_id)
                .ok_or_else(|| FolderbaseError::InvalidRecord {
                    path: analysis.root.clone(),
                    message: format!("unknown migration target: {}", assignment.target_id),
                })?;
            if matches!(
                target.kind,
                MigrationTargetKind::Exclusion | MigrationTargetKind::RetainedFolder
            ) {
                exclusions.push(MigrationExclusion {
                    path: tree.path.clone(),
                    reason: "Explicit generated-content destination".to_owned(),
                });
                continue;
            }
            let absolute = safe_join(&analysis.root, &tree.path)?;
            let expanded = expand_reconstructable_tree(&absolute)?;
            if !expanded.nested_folderbases.is_empty() {
                return Err(FolderbaseError::InvalidRecord {
                    path: analysis.root.clone(),
                    message: format!(
                        "expanded generated tree {} contains an unreviewed nested folderbase boundary",
                        tree.path.display()
                    ),
                });
            }
            if expanded.files.iter().any(AnalyzedFile::is_secret_shaped) {
                return Err(FolderbaseError::InvalidRecord {
                    path: analysis.root.clone(),
                    message: format!(
                        "expanded generated tree {} contains secret-shaped content and requires a new explicit local policy",
                        tree.path.display()
                    ),
                });
            }
            let mut expanded_files = expanded
                .files
                .into_iter()
                .map(|mut file| {
                    file.path = tree.path.join(file.path);
                    expanded_tree_assignments.insert(file.path.clone(), assignment.clone());
                    file
                })
                .collect::<Vec<_>>();
            expanded_files.sort_by(|left, right| left.path.cmp(&right.path));
            expanded_tree_memberships.push(ExpandedReconstructableTreeMembership {
                source_root: tree.path.clone(),
                source_paths: expanded_files
                    .iter()
                    .map(|file| file.path.clone())
                    .collect(),
            });
            candidate_files.extend(expanded_files);
        }
        candidate_files.sort_by(|left, right| left.path.cmp(&right.path));
    } else {
        exclusions.extend(
            analysis
                .reconstructable_trees
                .iter()
                .map(|tree| MigrationExclusion {
                    path: tree.path.clone(),
                    reason: "Explicit generated or reconstructable exclusion".to_owned(),
                }),
        );
    }

    if parsed_answers.canonical_scope == CanonicalScopeAnswer::ProposedBoundaries {
        let selected_folderbase_targets = parsed_answers
            .assignments
            .values()
            .filter_map(|assignment| {
                analysis
                    .proposed_targets
                    .iter()
                    .find(|target| {
                        target.id == assignment.target_id
                            && target.kind == MigrationTargetKind::Folderbase
                    })
                    .map(|target| target.id.as_str())
            })
            .collect::<BTreeSet<_>>();
        for target in analysis.proposed_targets.iter().filter(|target| {
            target.kind == MigrationTargetKind::Folderbase
                && selected_folderbase_targets.contains(target.id.as_str())
        }) {
            let folder_name = if target.id == "target_primary_folderbase" {
                "Primary.folderbase".to_owned()
            } else {
                format!("{}.folderbase", safe_boundary_name(&target.suggested_name))
            };
            let destination = destination_folder.join(folder_name);
            if !target_destination_keys.insert(portable_path_key(&destination)) {
                return Err(FolderbaseError::InvalidRecord {
                    path: analysis.root.clone(),
                    message: format!(
                        "multiple folderbase targets resolve to {}",
                        destination.display()
                    ),
                });
            }
            operations.push(MigrationOperation::CreateFolder {
                path: destination.clone(),
            });
            target_destinations.insert(target.id.clone(), destination);
        }
    }

    let mut planned_destination_keys = BTreeSet::new();
    for file in &candidate_files {
        let assignment = parsed_answers
            .assignment_for(&file.path)
            .or_else(|| expanded_tree_assignments.get(&file.path))
            .ok_or_else(|| FolderbaseError::InvalidRecord {
                path: analysis.root.clone(),
                message: format!(
                    "missing explicit migration assignment for {}",
                    file.path.display()
                ),
            })?;
        let target = analysis
            .proposed_targets
            .iter()
            .find(|target| target.id == assignment.target_id)
            .ok_or_else(|| FolderbaseError::InvalidRecord {
                path: analysis.root.clone(),
                message: format!("unknown migration target: {}", assignment.target_id),
            })?;
        if file.is_secret_shaped() && target.kind != MigrationTargetKind::RetainedFolder {
            return Err(FolderbaseError::InvalidRecord {
                path: analysis.root.clone(),
                message: format!(
                    "secret-shaped content requires an explicit retained-local target: {}",
                    file.path.display()
                ),
            });
        }
        if file.is_generated()
            && parsed_answers.generated_content == GeneratedContentAnswer::Exclude
            && target.kind == MigrationTargetKind::Folderbase
        {
            return Err(FolderbaseError::InvalidRecord {
                path: analysis.root.clone(),
                message: format!(
                    "excluded generated content cannot target a folderbase: {}",
                    file.path.display()
                ),
            });
        }
        if matches!(
            target.kind,
            MigrationTargetKind::RetainedFolder | MigrationTargetKind::Exclusion
        ) {
            exclusions.push(MigrationExclusion {
                path: file.path.clone(),
                reason: match target.kind {
                    MigrationTargetKind::RetainedFolder => {
                        "Explicitly retained in the source folder".to_owned()
                    }
                    MigrationTargetKind::Exclusion => "Explicit migration exclusion".to_owned(),
                    _ => unreachable!(),
                },
            });
            continue;
        }
        if !matches!(target.kind, MigrationTargetKind::Folderbase) {
            return Err(FolderbaseError::InvalidRecord {
                path: analysis.root.clone(),
                message: format!("navigation target cannot own content: {}", target.id),
            });
        }
        let absolute = safe_join(&analysis.root, &file.path)?;
        let metadata = fs::symlink_metadata(&absolute)
            .map_err(|_| FolderbaseError::MigrationSourceChanged(file.path.clone()))?;
        if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() != file.bytes
        {
            return Err(FolderbaseError::MigrationSourceChanged(file.path.clone()));
        }
        let source_file = SourceFile {
            path: file.path.clone(),
            bytes: file.bytes,
            sha256: sha256_path(&absolute)?,
        };
        let destination_path = match parsed_answers.canonical_scope {
            CanonicalScopeAnswer::OneFolderbase => destination_folder.join(&file.path),
            CanonicalScopeAnswer::ProposedBoundaries => {
                let destination = target_destinations.get(&target.id).ok_or_else(|| {
                    FolderbaseError::InvalidRecord {
                        path: analysis.root.clone(),
                        message: format!("folderbase target was not materialized: {}", target.id),
                    }
                })?;
                let relative = if target.id == "target_primary_folderbase" {
                    file.path.as_path()
                } else {
                    file.path
                        .strip_prefix(&target.path)
                        .unwrap_or(file.path.as_path())
                };
                destination.join(relative)
            }
        };
        let destination_key = portable_path_key(&destination_path);
        if planned_destination_keys.iter().any(|existing: &PathBuf| {
            destination_key.starts_with(existing) || existing.starts_with(&destination_key)
        }) {
            return Err(FolderbaseError::InvalidRecord {
                path: analysis.root.clone(),
                message: format!(
                    "multiple source objects resolve to {}",
                    destination_path.display()
                ),
            });
        }
        planned_destination_keys.insert(destination_key);
        operations.push(MigrationOperation::CopyFile {
            source_path: file.path.clone(),
            destination_path,
            expected_sha256: source_file.sha256.clone(),
        });
        source_files.push(source_file);
    }

    let destination_roots = additive_destination_roots(&operations);
    let source_topology = source_topology_snapshot(
        &analysis.files,
        &analysis.reconstructable_trees,
        &analysis.nested_folderbases,
        &destination_roots,
    );
    let mut extensions = BTreeMap::new();
    extensions.insert(
        SOURCE_TOPOLOGY_EXTENSION.to_owned(),
        serde_json::to_value(source_topology)
            .map_err(|source| FolderbaseError::json(&analysis.root, source))?,
    );
    if !parsed_answers.grouped_assignments.is_empty() {
        extensions.insert(
            GROUPED_ASSIGNMENTS_EXTENSION.to_owned(),
            serde_json::to_value(GroupedAssignmentsExtension {
                version: "1".to_owned(),
                groups: parsed_answers.grouped_assignments.clone(),
            })
            .map_err(|source| FolderbaseError::json(&analysis.root, source))?,
        );
    }
    if !expanded_tree_memberships.is_empty() {
        extensions.insert(
            EXPANDED_RECONSTRUCTABLE_TREES_EXTENSION.to_owned(),
            serde_json::to_value(ExpandedReconstructableTreesExtension {
                version: "1".to_owned(),
                trees: expanded_tree_memberships,
            })
            .map_err(|source| FolderbaseError::json(&analysis.root, source))?,
        );
    }
    let source_inventory_digest = inventory_digest(&source_files);
    let plan = MigrationPlan {
        protocol_version: "0.2.0".to_owned(),
        id: format!("migration_{}", Uuid::now_v7()),
        root: analysis.root,
        state: MigrationState::Proposed,
        source_inventory: SourceInventory {
            algorithm: "sha256".to_owned(),
            digest: source_inventory_digest,
            files: source_files,
        },
        answers,
        template_references: vec!["folderbase.project@0.2.2".to_owned()],
        targets: analysis.proposed_targets,
        operations,
        exclusions,
        approval_digest: None,
        extensions,
        root_identity: analysis.root_identity,
    };
    persist_new_plan(&plan)?;
    Ok(plan)
}

pub fn preview_migration(plan: &MigrationPlan) -> Result<MigrationPreview> {
    require_state(plan.state, MigrationState::Proposed)?;
    let mut creates_directories = Vec::new();
    let mut copies = Vec::new();
    let mut source_bytes = 0;
    let mut structural_operations = Vec::new();

    for operation in &plan.operations {
        match operation {
            MigrationOperation::CreateFolder { path } => {
                ensure_safe_relative(path)?;
                creates_directories.push(path.clone());
            }
            MigrationOperation::CopyFile {
                source_path,
                destination_path,
                ..
            } => {
                ensure_safe_relative(source_path)?;
                ensure_safe_relative(destination_path)?;
                let bytes = plan
                    .source_inventory
                    .files
                    .iter()
                    .find(|file| file.path == *source_path)
                    .map(|file| file.bytes)
                    .ok_or_else(|| FolderbaseError::MigrationSourceChanged(source_path.clone()))?;
                source_bytes += bytes;
                copies.push(MigrationCopyPreview {
                    source_path: source_path.clone(),
                    destination_path: destination_path.clone(),
                    bytes,
                });
            }
            operation if operation.is_structural() => {
                let source_path = operation
                    .structural_source_path()
                    .expect("structural operation has a source");
                source_bytes += plan
                    .source_inventory
                    .files
                    .iter()
                    .find(|file| file.path == source_path)
                    .map(|file| file.bytes)
                    .ok_or_else(|| {
                        FolderbaseError::MigrationSourceChanged(source_path.to_path_buf())
                    })?;
                structural_operations.push(operation.clone());
            }
            _ => unreachable!("all migration operations are additive or structural"),
        }
    }
    let source_files_remain = !structural_operations
        .iter()
        .any(|operation| matches!(operation, MigrationOperation::MoveObject { .. }));

    Ok(MigrationPreview {
        migration_id: plan.id.clone(),
        targets: plan.targets.clone(),
        creates_directories,
        copies,
        source_bytes,
        additional_local_bytes: source_bytes,
        source_files_remain,
        structural_operations,
    })
}

pub fn approve_migration(mut plan: MigrationPlan) -> Result<ApprovedMigration> {
    require_state(plan.state, MigrationState::Proposed)?;
    let stored = load_plan(&plan.root, &plan.id)?;
    require_state(stored.state, MigrationState::Proposed)?;
    if plan_digest(&plan)? != plan_digest(&stored)? {
        return Err(FolderbaseError::MigrationApprovalMismatch);
    }
    plan = stored;
    if is_structural_plan(&plan) {
        prepare_structural_snapshots(&mut plan)?;
    }
    plan.state = MigrationState::Approved;
    let approval_digest = plan_digest(&plan)?;
    plan.approval_digest = Some(approval_digest.clone());
    persist_plan(&plan)?;
    Ok(ApprovedMigration {
        plan,
        approval_digest,
    })
}

fn is_structural_plan(plan: &MigrationPlan) -> bool {
    plan.extensions.get("plan_kind")
        == Some(&serde_json::Value::String(STRUCTURAL_PLAN_KIND.to_owned()))
        && plan
            .extensions
            .get("snapshot_required")
            .and_then(serde_json::Value::as_bool)
            == Some(true)
}

fn is_structural_journal(journal: &MigrationJournal) -> bool {
    journal.plan_extensions.get("plan_kind")
        == Some(&serde_json::Value::String(STRUCTURAL_PLAN_KIND.to_owned()))
        && journal
            .plan_extensions
            .get("snapshot_required")
            .and_then(serde_json::Value::as_bool)
            == Some(true)
}

fn prepare_structural_snapshots(plan: &mut MigrationPlan) -> Result<()> {
    verify_root_identity(plan)?;
    verify_source_files(plan)?;
    let migration_relative = PathBuf::from(MIGRATIONS_DIR).join(&plan.id);
    let snapshots_relative = migration_relative.join("snapshots");
    let snapshots = safe_join(&plan.root, &snapshots_relative)?;
    if snapshots.exists() {
        return bind_existing_structural_snapshots(plan, &snapshots_relative, &snapshots);
    }
    let temporary_relative = migration_relative.join(format!("snapshots.{}.tmp", Uuid::now_v7()));
    let temporary = safe_join(&plan.root, &temporary_relative)?;
    fs::create_dir(&temporary).map_err(|source| FolderbaseError::io(&temporary, source))?;
    sync_parent(&temporary)?;

    let result = (|| -> Result<()> {
        for (index, operation) in plan.operations.iter_mut().enumerate() {
            let source_path = operation
                .structural_source_path()
                .ok_or_else(|| {
                    invalid_journal(&plan.root, "snapshot requested for additive operation")
                })?
                .to_path_buf();
            let expected = operation
                .structural_expected_sha256()
                .ok_or_else(|| invalid_journal(&plan.root, "structural digest is missing"))?
                .to_owned();
            let source = safe_join(&plan.root, &source_path)?;
            if sha256_path(&source)? != expected {
                return Err(FolderbaseError::MigrationSourceChanged(source_path));
            }
            let snapshot_name = format!("{index}.bin");
            let temporary_snapshot = temporary.join(&snapshot_name);
            copy_new(&source, &temporary_snapshot)?;
            if sha256_path(&temporary_snapshot)? != expected {
                return Err(FolderbaseError::MigrationVerificationFailed(
                    temporary_snapshot,
                ));
            }
            operation.set_structural_snapshot(snapshots_relative.join(snapshot_name), expected);
        }
        sync_directory(&temporary)?;
        fs::rename(&temporary, &snapshots)
            .map_err(|source| FolderbaseError::io(&snapshots, source))?;
        sync_parent(&snapshots)
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(&temporary);
    }
    result
}

fn bind_existing_structural_snapshots(
    plan: &mut MigrationPlan,
    snapshots_relative: &Path,
    snapshots: &Path,
) -> Result<()> {
    let metadata =
        fs::symlink_metadata(snapshots).map_err(|source| FolderbaseError::io(snapshots, source))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(FolderbaseError::MigrationVerificationFailed(
            snapshots.to_path_buf(),
        ));
    }
    let entries = fs::read_dir(snapshots)
        .map_err(|source| FolderbaseError::io(snapshots, source))?
        .collect::<std::io::Result<Vec<_>>>()
        .map_err(|source| FolderbaseError::io(snapshots, source))?;
    if entries.len() != plan.operations.len() {
        return Err(FolderbaseError::MigrationVerificationFailed(
            snapshots.to_path_buf(),
        ));
    }
    for (index, operation) in plan.operations.iter_mut().enumerate() {
        let expected = operation
            .structural_expected_sha256()
            .ok_or_else(|| invalid_journal(&plan.root, "structural digest is missing"))?
            .to_owned();
        let snapshot_name = format!("{index}.bin");
        let snapshot_relative = snapshots_relative.join(&snapshot_name);
        let snapshot = safe_join(&plan.root, &snapshot_relative)?;
        let metadata = fs::symlink_metadata(&snapshot)
            .map_err(|source| FolderbaseError::io(&snapshot, source))?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || sha256_path(&snapshot)? != expected
        {
            return Err(FolderbaseError::MigrationVerificationFailed(snapshot));
        }
        operation.set_structural_snapshot(snapshot_relative, expected);
    }
    Ok(())
}

/// Apply an approved plan using copy-and-verify semantics.
///
/// The applying journal is durable before the first operation and after every
/// completed operation. A failure triggers rollback of only verified paths
/// created by this migration. Pre-existing content is never overwritten or
/// removed.
pub fn apply_migration(approved: ApprovedMigration) -> Result<MigrationResult> {
    apply_migration_with_hook(approved, |_| {})
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ApplyCheckpoint {
    MigrationDirectoryPrepared,
    JournalStaged,
    JournalPrepared,
    JournalCreated,
    StagingCreated,
    OperationPlanned(usize),
    OperationApplied(usize),
    OperationCompleted(usize),
    MaterializationPlanned(usize),
    MaterializationVerified(usize),
    WorkspacePlanned,
    WorkspaceVerified,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StructuralRollbackCheckpoint {
    Started,
    OperationPlanned(usize),
    OperationApplied(usize),
    OperationCompleted(usize),
    Completed,
}

fn apply_migration_with_hook(
    approved: ApprovedMigration,
    mut checkpoint: impl FnMut(ApplyCheckpoint),
) -> Result<MigrationResult> {
    let in_memory_plan = approved.plan;
    require_state(in_memory_plan.state, MigrationState::Approved)?;
    if plan_digest(&in_memory_plan)? != approved.approval_digest {
        return Err(FolderbaseError::MigrationApprovalMismatch);
    }
    let _transaction_lock = acquire_existing_folderbase_transaction_lock(&in_memory_plan.root)?;
    let mut plan = load_plan(&in_memory_plan.root, &in_memory_plan.id)?;
    require_state(plan.state, MigrationState::Approved)?;
    if plan.approval_digest.as_deref() != Some(approved.approval_digest.as_str())
        || plan_digest(&plan)? != approved.approval_digest
    {
        return Err(FolderbaseError::MigrationApprovalMismatch);
    }
    verify_root_identity(&plan)?;
    verify_source_files(&plan)?;
    if is_structural_plan(&plan) {
        return apply_structural_migration(plan, approved.approval_digest, &mut checkpoint);
    }
    verify_additive_source_topology(&plan)?;
    verify_expanded_reconstructable_trees(&plan)?;

    let migration_dir = PathBuf::from(MIGRATIONS_DIR).join(&plan.id);
    let journal_path = migration_dir.join("result.json");
    let journal_absolute = prepare_migration_directory(&plan.root, &migration_dir, &journal_path)?;
    checkpoint(ApplyCheckpoint::MigrationDirectoryPrepared);
    let mut journal = MigrationJournal {
        protocol_version: "0.2.0".to_owned(),
        id: plan.id.clone(),
        root: plan.root.clone(),
        state: MigrationState::Applying,
        approval_digest: approved.approval_digest,
        approval_scheme: Some("migration_plan_v0.2".to_owned()),
        source_inventory: SourceInventory {
            algorithm: "sha256".to_owned(),
            digest: plan.source_inventory.digest.clone(),
            files: plan.source_inventory.files.clone(),
        },
        answers: plan.answers.clone(),
        template_references: plan.template_references.clone(),
        targets: plan.targets.clone(),
        operations: plan.operations.clone(),
        exclusions: plan.exclusions.clone(),
        plan_extensions: plan.extensions.clone(),
        materialized_folderbases: Vec::new(),
        materialized_workspace: None,
        created_paths: Vec::new(),
        completed_operations: 0,
        in_flight_operation: None,
    };
    write_json_new_with_hook(&journal_absolute, &journal, || {
        checkpoint(ApplyCheckpoint::JournalStaged);
    })?;
    checkpoint(ApplyCheckpoint::JournalPrepared);
    plan.state = MigrationState::Applying;
    persist_plan(&plan)?;
    checkpoint(ApplyCheckpoint::JournalCreated);
    if let Err(error) = create_migration_staging(&plan.root, &plan.id) {
        record_unstarted_additive_rollback(&mut plan, &journal_absolute, &mut journal)?;
        return Err(error);
    }
    checkpoint(ApplyCheckpoint::StagingCreated);

    for index in 0..journal.operations.len() {
        journal.in_flight_operation = Some(index);
        if let Err(error) = persist_journal(&journal_absolute, &journal) {
            let _ = rollback_journal(&plan.root, &journal_absolute, &mut journal);
            plan.state = MigrationState::Conflicted;
            let _ = persist_plan(&plan);
            return Err(error);
        }
        if let Err(error) = apply_operation(&plan.root, index, &journal_absolute, &mut journal) {
            let _ = rollback_journal(&plan.root, &journal_absolute, &mut journal);
            plan.state = MigrationState::Conflicted;
            let _ = persist_plan(&plan);
            return Err(error);
        }
        journal.completed_operations = index + 1;
        journal.in_flight_operation = None;
        if let Err(error) = persist_journal(&journal_absolute, &journal) {
            let _ = rollback_journal(&plan.root, &journal_absolute, &mut journal);
            plan.state = MigrationState::Conflicted;
            let _ = persist_plan(&plan);
            return Err(error);
        }
        checkpoint(ApplyCheckpoint::OperationCompleted(index));
    }

    if let Err(error) =
        materialize_folderbase_targets(&plan, &journal_absolute, &mut journal, &mut checkpoint)
    {
        let _ = rollback_journal(&plan.root, &journal_absolute, &mut journal);
        plan.state = MigrationState::Conflicted;
        let _ = persist_plan(&plan);
        return Err(error);
    }

    journal.state = MigrationState::Verified;
    persist_journal(&journal_absolute, &journal)?;
    plan.state = MigrationState::Verified;
    persist_plan(&plan)?;
    cleanup_staging(&plan.root, &plan.id);

    Ok(MigrationResult {
        migration_id: journal.id,
        root: plan.root,
        state: MigrationState::Verified,
        created_paths: journal.created_paths,
        journal_path,
    })
}

fn acquire_existing_folderbase_transaction_lock(
    root: &Path,
) -> Result<Option<crate::local_versions::StoreTransactionLock>> {
    if !has_nested_folderbase_marker(root)? {
        return Ok(None);
    }
    LocalVersionStore::open_read_only(root)?
        .acquire_transaction_lock()
        .map(Some)
}

fn record_unstarted_additive_rollback(
    plan: &mut MigrationPlan,
    journal_path: &Path,
    journal: &mut MigrationJournal,
) -> Result<()> {
    journal.state = MigrationState::RolledBack;
    if let Err(error) = persist_journal(journal_path, journal) {
        plan.state = MigrationState::Conflicted;
        let _ = persist_plan(plan);
        return Err(error);
    }
    plan.state = MigrationState::RolledBack;
    persist_plan(plan)
}

fn apply_structural_migration(
    mut plan: MigrationPlan,
    approval_digest: String,
    checkpoint: &mut impl FnMut(ApplyCheckpoint),
) -> Result<MigrationResult> {
    preflight_structural_operations(&plan)?;
    let migration_dir = PathBuf::from(MIGRATIONS_DIR).join(&plan.id);
    let journal_path = migration_dir.join("result.json");
    let journal_absolute = prepare_migration_directory(&plan.root, &migration_dir, &journal_path)?;
    let mut journal = MigrationJournal {
        protocol_version: "0.2.0".to_owned(),
        id: plan.id.clone(),
        root: plan.root.clone(),
        state: MigrationState::Applying,
        approval_digest,
        approval_scheme: Some("migration_plan_v0.2".to_owned()),
        source_inventory: plan.source_inventory.clone(),
        answers: plan.answers.clone(),
        template_references: plan.template_references.clone(),
        targets: plan.targets.clone(),
        operations: plan.operations.clone(),
        exclusions: plan.exclusions.clone(),
        plan_extensions: plan.extensions.clone(),
        materialized_folderbases: Vec::new(),
        materialized_workspace: None,
        created_paths: Vec::new(),
        completed_operations: 0,
        in_flight_operation: None,
    };
    if let Err(error) = write_json_new(&journal_absolute, &journal) {
        cleanup_staging(&plan.root, &plan.id);
        return Err(error);
    }
    checkpoint(ApplyCheckpoint::JournalPrepared);
    plan.state = MigrationState::Applying;
    persist_plan(&plan)?;
    checkpoint(ApplyCheckpoint::JournalCreated);

    for index in 0..journal.operations.len() {
        journal.in_flight_operation = Some(index);
        persist_journal(&journal_absolute, &journal)?;
        checkpoint(ApplyCheckpoint::OperationPlanned(index));
        if let Err(error) = apply_structural_operation(&plan.root, &journal.operations[index]) {
            let rollback_error =
                rollback_structural_journal(&plan.root, &journal_absolute, &mut journal).err();
            plan.state = if rollback_error.is_some() {
                MigrationState::Conflicted
            } else {
                MigrationState::RolledBack
            };
            let _ = persist_plan(&plan);
            return Err(rollback_error.unwrap_or(error));
        }
        checkpoint(ApplyCheckpoint::OperationApplied(index));
        journal.completed_operations = index + 1;
        journal.in_flight_operation = None;
        persist_journal(&journal_absolute, &journal)?;
        checkpoint(ApplyCheckpoint::OperationCompleted(index));
    }
    let verification =
        verify_structural_postconditions(&plan.root, &journal.operations).and_then(|()| {
            let report = validate(&plan.root, ValidationLevel::Shallow)?;
            if report.valid {
                Ok(())
            } else {
                Err(FolderbaseError::InvalidRecord {
                    path: plan.root.clone(),
                    message: format!(
                        "structural reorganization produced an invalid folderbase: {:?}",
                        report.findings
                    ),
                })
            }
        });
    if let Err(error) = verification {
        let rollback_error =
            rollback_structural_journal(&plan.root, &journal_absolute, &mut journal).err();
        plan.state = if rollback_error.is_some() {
            MigrationState::Conflicted
        } else {
            MigrationState::RolledBack
        };
        let _ = persist_plan(&plan);
        return Err(rollback_error.unwrap_or(error));
    }
    journal.state = MigrationState::Verified;
    persist_journal(&journal_absolute, &journal)?;
    plan.state = MigrationState::Verified;
    persist_plan(&plan)?;
    cleanup_staging(&plan.root, &plan.id);

    Ok(MigrationResult {
        migration_id: journal.id,
        root: plan.root,
        state: MigrationState::Verified,
        created_paths: Vec::new(),
        journal_path,
    })
}

fn preflight_structural_operations(plan: &MigrationPlan) -> Result<()> {
    if !is_structural_plan(plan)
        || plan.operations.is_empty()
        || plan
            .operations
            .iter()
            .any(|operation| !operation.is_structural())
    {
        return Err(invalid_journal(
            &plan.root,
            "structural plan metadata or operations are invalid",
        ));
    }
    for operation in &plan.operations {
        refuse_structural_operation_boundaries(&plan.root, operation)?;
        let source_path = operation
            .structural_source_path()
            .expect("structural operation has a source");
        let expected = operation
            .structural_expected_sha256()
            .filter(|digest| is_sha256(digest))
            .ok_or_else(|| invalid_journal(&plan.root, "structural source digest is invalid"))?;
        let source = safe_join(&plan.root, source_path)?;
        if sha256_path(&source)? != expected {
            return Err(FolderbaseError::MigrationSourceChanged(
                source_path.to_path_buf(),
            ));
        }
        let (snapshot_path, snapshot_sha256) =
            operation.structural_snapshot().ok_or_else(|| {
                invalid_journal(&plan.root, "verified structural snapshot is missing")
            })?;
        if snapshot_sha256 != expected {
            return Err(FolderbaseError::MigrationVerificationFailed(
                snapshot_path.to_path_buf(),
            ));
        }
        let snapshot = safe_join(&plan.root, snapshot_path)?;
        let snapshot_metadata = fs::symlink_metadata(&snapshot)
            .map_err(|source| FolderbaseError::io(&snapshot, source))?;
        if !snapshot_metadata.is_file()
            || snapshot_metadata.file_type().is_symlink()
            || sha256_path(&snapshot)? != expected
        {
            return Err(FolderbaseError::MigrationVerificationFailed(snapshot));
        }
        if let Some(destination_path) = operation.structural_destination_path() {
            let destination = safe_join(&plan.root, destination_path)?;
            if destination.exists() {
                return Err(FolderbaseError::WouldOverwrite(destination));
            }
        } else {
            let result = structural_result_bytes(&source, operation)?;
            let expected_result = operation
                .structural_expected_result_sha256()
                .filter(|digest| is_sha256(digest))
                .ok_or_else(|| {
                    invalid_journal(&plan.root, "structural result digest is invalid")
                })?;
            if sha256_bytes(&result) != expected_result {
                return Err(FolderbaseError::MigrationApprovalMismatch);
            }
        }
    }
    Ok(())
}

fn apply_structural_operation(root: &Path, operation: &MigrationOperation) -> Result<()> {
    refuse_structural_operation_boundaries(root, operation)?;
    match operation {
        MigrationOperation::MoveObject {
            source_path,
            destination_path,
            expected_sha256,
            ..
        } => {
            let source = safe_join(root, source_path)?;
            let destination = safe_join(root, destination_path)?;
            move_file_no_replace(&source, &destination, expected_sha256)
        }
        operation if operation.is_structural() => {
            let source_path = operation
                .structural_source_path()
                .expect("structural operation has a source");
            let source = safe_join(root, source_path)?;
            let expected = operation
                .structural_expected_sha256()
                .expect("structural operation has an expected digest");
            let result = structural_result_bytes(&source, operation)?;
            let result_digest = operation
                .structural_expected_result_sha256()
                .expect("structural mutation has a result digest");
            if sha256_bytes(&result) != result_digest {
                return Err(FolderbaseError::MigrationApprovalMismatch);
            }
            replace_file_atomically(&source, expected, &result)?;
            if sha256_path(&source)? != result_digest {
                return Err(FolderbaseError::MigrationVerificationFailed(source));
            }
            Ok(())
        }
        _ => Err(invalid_journal(
            root,
            "additive operation reached the structural apply path",
        )),
    }
}

fn structural_result_bytes(source: &Path, operation: &MigrationOperation) -> Result<Vec<u8>> {
    let current = read_bounded_regular(source, MAX_MIGRATION_PLAN_BYTES)?;
    match operation {
        MigrationOperation::UpdateAdapter { managed_block, .. } => {
            let current =
                std::str::from_utf8(&current).map_err(|_| FolderbaseError::InvalidRecord {
                    path: source.to_path_buf(),
                    message: "agent adapter must be UTF-8 text".to_owned(),
                })?;
            Ok(merge_managed_block(current, managed_block, source)?.into_bytes())
        }
        MigrationOperation::UpdateIgnorePolicy { content, .. } => Ok(content.as_bytes().to_vec()),
        MigrationOperation::UpdatePolicy { policy, value, .. } => {
            let mut document = parse_structural_json(source, &current)?;
            let policies = document
                .get_mut("policies")
                .and_then(serde_json::Value::as_object_mut)
                .ok_or_else(|| FolderbaseError::InvalidRecord {
                    path: source.to_path_buf(),
                    message: "manifest is missing its policies object".to_owned(),
                })?;
            policies.insert(policy.clone(), value.clone());
            pretty_json_bytes(source, &document)
        }
        MigrationOperation::ChangeKind { new_kind, .. } => {
            let mut document = parse_structural_json(source, &current)?;
            let folderbase = document
                .get_mut("folderbase")
                .and_then(serde_json::Value::as_object_mut)
                .ok_or_else(|| FolderbaseError::InvalidRecord {
                    path: source.to_path_buf(),
                    message: "manifest is missing its folderbase object".to_owned(),
                })?;
            folderbase.insert(
                "kind".to_owned(),
                serde_json::Value::String(structural_folderbase_kind_name(*new_kind).to_owned()),
            );
            pretty_json_bytes(source, &document)
        }
        MigrationOperation::MarkCanonical { .. } => {
            let mut document = parse_structural_json(source, &current)?;
            set_object_lifecycle(source, &mut document, "canonical", None)?;
            pretty_json_bytes(source, &document)
        }
        MigrationOperation::MarkSuperseded { superseded_by, .. } => {
            let mut document = parse_structural_json(source, &current)?;
            set_object_lifecycle(source, &mut document, "superseded", Some(superseded_by))?;
            pretty_json_bytes(source, &document)
        }
        MigrationOperation::ArchiveObject { .. } => {
            let mut document = parse_structural_json(source, &current)?;
            set_object_lifecycle(source, &mut document, "archived", None)?;
            validate_archive_lifecycle(source, &document)?;
            pretty_json_bytes(source, &document)
        }
        MigrationOperation::AddRelationship {
            relationship_type,
            target_object_id,
            ..
        } => {
            let mut document = parse_structural_json(source, &current)?;
            let object =
                document
                    .as_object_mut()
                    .ok_or_else(|| FolderbaseError::InvalidRecord {
                        path: source.to_path_buf(),
                        message: "object record must be a JSON object".to_owned(),
                    })?;
            let relationships = object
                .entry("relationships")
                .or_insert_with(|| serde_json::Value::Array(Vec::new()))
                .as_array_mut()
                .ok_or_else(|| FolderbaseError::InvalidRecord {
                    path: source.to_path_buf(),
                    message: "object relationships must be an array".to_owned(),
                })?;
            let relationship = serde_json::json!({
                "type": relationship_type,
                "target": target_object_id,
            });
            if !relationships.contains(&relationship) {
                relationships.push(relationship);
            }
            pretty_json_bytes(source, &document)
        }
        MigrationOperation::MoveObject { .. }
        | MigrationOperation::CreateFolder { .. }
        | MigrationOperation::CopyFile { .. } => Err(invalid_journal(
            source,
            "operation does not produce replacement bytes",
        )),
    }
}

fn replace_file_atomically(path: &Path, expected_sha256: &str, content: &[u8]) -> Result<()> {
    if sha256_path(path)? != expected_sha256 {
        return Err(FolderbaseError::MigrationSourceChanged(path.to_path_buf()));
    }
    let metadata =
        fs::symlink_metadata(path).map_err(|source| FolderbaseError::io(path, source))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(FolderbaseError::MigrationSourceChanged(path.to_path_buf()));
    }
    let parent = path
        .parent()
        .ok_or_else(|| FolderbaseError::UnsafePath(path.to_path_buf()))?;
    let temporary = parent.join(format!(".folderbase-structural-{}.tmp", Uuid::now_v7()));
    let result = (|| -> Result<()> {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|source| FolderbaseError::io(&temporary, source))?;
        file.set_permissions(metadata.permissions())
            .map_err(|source| FolderbaseError::io(&temporary, source))?;
        file.write_all(content)
            .and_then(|()| file.sync_all())
            .map_err(|source| FolderbaseError::io(&temporary, source))?;
        if sha256_path(path)? != expected_sha256 {
            return Err(FolderbaseError::MigrationSourceChanged(path.to_path_buf()));
        }
        fs::rename(&temporary, path).map_err(|source| FolderbaseError::io(path, source))?;
        sync_directory(parent)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn move_file_no_replace(source: &Path, destination: &Path, expected_sha256: &str) -> Result<()> {
    if destination.exists() {
        return Err(FolderbaseError::WouldOverwrite(destination.to_path_buf()));
    }
    if sha256_path(source)? != expected_sha256 {
        return Err(FolderbaseError::MigrationSourceChanged(
            source.to_path_buf(),
        ));
    }
    fs::hard_link(source, destination).map_err(|error| {
        if error.kind() == std::io::ErrorKind::AlreadyExists {
            FolderbaseError::WouldOverwrite(destination.to_path_buf())
        } else {
            FolderbaseError::io(destination, error)
        }
    })?;
    let linked = (|| -> Result<()> {
        if sha256_path(destination)? != expected_sha256 || sha256_path(source)? != expected_sha256 {
            return Err(FolderbaseError::MigrationSourceChanged(
                source.to_path_buf(),
            ));
        }
        sync_parent(destination)?;
        fs::remove_file(source).map_err(|error| FolderbaseError::io(source, error))?;
        sync_parent(source)?;
        if sha256_path(destination)? != expected_sha256 {
            return Err(FolderbaseError::MigrationVerificationFailed(
                destination.to_path_buf(),
            ));
        }
        Ok(())
    })();
    if linked.is_err() && source.exists() {
        let _ = fs::remove_file(destination);
        let _ = sync_parent(destination);
    }
    linked
}

fn verify_structural_postconditions(root: &Path, operations: &[MigrationOperation]) -> Result<()> {
    for operation in operations {
        match operation {
            MigrationOperation::MoveObject {
                source_path,
                destination_path,
                expected_sha256,
                ..
            } => {
                if safe_join(root, source_path)?.exists()
                    || sha256_path(&safe_join(root, destination_path)?)? != *expected_sha256
                {
                    return Err(FolderbaseError::MigrationVerificationFailed(
                        destination_path.clone(),
                    ));
                }
            }
            operation if operation.is_structural() => {
                let source_path = operation
                    .structural_source_path()
                    .expect("structural operation has a source");
                let source = safe_join(root, source_path)?;
                if sha256_path(&source)?
                    != operation
                        .structural_expected_result_sha256()
                        .expect("structural operation has a result digest")
                {
                    return Err(FolderbaseError::MigrationVerificationFailed(source));
                }
            }
            _ => {
                return Err(invalid_journal(
                    root,
                    "additive operation reached structural verification",
                ));
            }
        }
    }
    Ok(())
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn materialize_folderbase_targets(
    plan: &MigrationPlan,
    journal_path: &Path,
    journal: &mut MigrationJournal,
    checkpoint: &mut impl FnMut(ApplyCheckpoint),
) -> Result<()> {
    const TEMPLATE_ID: &str = "folderbase.project";
    const TEMPLATE_VERSION: &str = "0.2.2";
    const TEMPLATE_REFERENCE: &str = "folderbase.project@0.2.2";

    if !plan
        .template_references
        .iter()
        .any(|reference| reference == TEMPLATE_REFERENCE)
    {
        return Err(invalid_journal(
            journal_path,
            "migration plan does not bind the required folderbase template",
        ));
    }
    let (destination_root, materializations) = approved_materialization_specs(
        &plan.answers,
        &plan.targets,
        &plan.operations,
        journal_path,
    )?;
    let package = load_builtin_template(TEMPLATE_ID, TEMPLATE_VERSION)?;

    for (materialization_index, materialization) in materializations.iter().enumerate() {
        let path = materialization.path.clone();
        let absolute = safe_join(&plan.root, &path)?;
        let answers = BTreeMap::from([
            (
                "purpose".to_owned(),
                TemplateAnswerValue::Text(format!(
                    "Preserve and organize approved content for {}.",
                    materialization.name
                )),
            ),
            (
                "current_state".to_owned(),
                TemplateAnswerValue::Text(format!(
                    "Materialized from approved migration {} while preserving the source folder.",
                    plan.id
                )),
            ),
            (
                "next_action".to_owned(),
                TemplateAnswerValue::Text(
                    "Review the migrated files and refine this folderbase's executive summary."
                        .to_owned(),
                ),
            ),
        ]);
        let initialization = plan_template_initialization(
            &absolute,
            InitializationOptions {
                name: Some(materialization.name.clone()),
                kind: FolderbaseKind::Project,
                create_agent_adapters: true,
            },
            &package,
            &answers,
        )?;
        let created_directories = initialization
            .directories
            .iter()
            .map(|directory| path.join(&directory.path))
            .collect::<Vec<_>>();
        let created_files = initialization
            .writes
            .iter()
            .map(|write| {
                (
                    path.join(&write.path),
                    format!("{:x}", Sha256::digest(write.content.as_bytes())),
                )
            })
            .collect::<BTreeMap<_, _>>();
        journal
            .materialized_folderbases
            .push(MaterializedFolderbase {
                target_id: materialization.target_id.clone(),
                path: path.clone(),
                folderbase_id: initialization.folderbase_id.clone(),
                name: initialization.folderbase_name.clone(),
                template_reference: TEMPLATE_REFERENCE.to_owned(),
                state: MaterializationState::Planned,
                created_directories: created_directories.clone(),
                created_files: created_files.clone(),
            });
        for created in created_directories
            .iter()
            .cloned()
            .chain(created_files.keys().cloned())
        {
            if !journal.created_paths.contains(&created) {
                journal.created_paths.push(created);
            }
        }
        persist_journal(journal_path, journal)?;
        checkpoint(ApplyCheckpoint::MaterializationPlanned(
            materialization_index,
        ));

        let initialized = initialize(&initialization)?;
        if initialized.folderbase_id != initialization.folderbase_id {
            return Err(FolderbaseError::MigrationVerificationFailed(absolute));
        }
        for (relative, expected_sha256) in &created_files {
            let absolute = safe_join(&plan.root, relative)?;
            if sha256_path(&absolute)? != *expected_sha256 {
                return Err(FolderbaseError::MigrationVerificationFailed(absolute));
            }
        }
        let report = validate(&absolute, ValidationLevel::Shallow)?;
        if !report.valid {
            return Err(FolderbaseError::MigrationVerificationFailed(absolute));
        }
        journal
            .materialized_folderbases
            .last_mut()
            .expect("materialization record was just appended")
            .state = MaterializationState::Verified;
        persist_journal(journal_path, journal)?;
        checkpoint(ApplyCheckpoint::MaterializationVerified(
            materialization_index,
        ));
    }
    if journal.materialized_folderbases.len() > 1 {
        materialize_workspace(
            &plan.root,
            &destination_root,
            journal_path,
            journal,
            checkpoint,
        )?;
    }
    Ok(())
}

fn approved_materialization_specs(
    answers: &[MigrationAnswer],
    targets: &[MigrationTarget],
    operations: &[MigrationOperation],
    record_path: &Path,
) -> Result<(PathBuf, Vec<FolderbaseMaterializationSpec>)> {
    let canonical_scope = answers
        .iter()
        .find(|answer| answer.question_id == "question_canonical_scope")
        .map(|answer| answer.answer.as_str())
        .ok_or_else(|| {
            invalid_journal(
                record_path,
                "migration plan is missing its canonical-scope answer",
            )
        })?;
    let destination_root = operations
        .iter()
        .find_map(|operation| match operation {
            MigrationOperation::CreateFolder { path } => Some(path.clone()),
            MigrationOperation::CopyFile { .. } => None,
            _ => None,
        })
        .ok_or_else(|| {
            invalid_journal(
                record_path,
                "migration plan does not create a destination root",
            )
        })?;
    let selected_target_ids = answers
        .iter()
        .filter_map(|answer| {
            targets
                .iter()
                .find(|target| {
                    target.kind == MigrationTargetKind::Folderbase && target.id == answer.answer
                })
                .map(|target| target.id.as_str())
        })
        .collect::<BTreeSet<_>>();
    let mut materializations = Vec::new();
    for target in targets.iter().filter(|target| {
        target.kind == MigrationTargetKind::Folderbase
            && selected_target_ids.contains(target.id.as_str())
    }) {
        let path = match canonical_scope {
            "one_folderbase" if target.id == "target_primary_folderbase" => {
                destination_root.clone()
            }
            "proposed_boundaries" => {
                let folder_name = if target.id == "target_primary_folderbase" {
                    "Primary.folderbase".to_owned()
                } else {
                    format!("{}.folderbase", safe_boundary_name(&target.suggested_name))
                };
                destination_root.join(folder_name)
            }
            _ => {
                return Err(invalid_journal(
                    record_path,
                    "selected folderbase target is inconsistent with canonical scope",
                ));
            }
        };
        if !operations.iter().any(|operation| {
            matches!(
                operation,
                MigrationOperation::CreateFolder { path: planned } if planned == &path
            )
        }) {
            return Err(invalid_journal(
                record_path,
                format!(
                    "folderbase target {} has no approved destination operation",
                    target.id
                ),
            ));
        }
        materializations.push(FolderbaseMaterializationSpec {
            target_id: target.id.clone(),
            name: target.suggested_name.clone(),
            path,
        });
    }
    Ok((destination_root, materializations))
}

fn materialize_workspace(
    root: &Path,
    workspace_path: &Path,
    journal_path: &Path,
    journal: &mut MigrationJournal,
    checkpoint: &mut impl FnMut(ApplyCheckpoint),
) -> Result<()> {
    let name = materialized_workspace_name(workspace_path);
    let folderbases = journal
        .materialized_folderbases
        .iter()
        .map(|folderbase| {
            let relative = folderbase.path.strip_prefix(workspace_path).map_err(|_| {
                invalid_journal(
                    journal_path,
                    "materialized folderbase is outside the workspace root",
                )
            })?;
            ensure_safe_relative(relative)?;
            Ok(WorkspaceFolderbaseLink {
                folderbase_id: folderbase.folderbase_id.clone(),
                label: folderbase.name.clone(),
                path: relative.to_path_buf(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let workspace_id = format!("workspace_{}", Uuid::now_v7());
    let descriptor = serde_json::json!({
        "$schema": "https://folderbase.ai/protocol/0.1/workspace.schema.json",
        "protocol_version": "0.1.0",
        "id": workspace_id.clone(),
        "name": name.clone(),
        "folderbases": folderbases.iter().map(|folderbase| {
            serde_json::json!({
                "folderbase_id": folderbase.folderbase_id.clone(),
                "label": folderbase.label.clone(),
                "path": folderbase.path.clone(),
            })
        }).collect::<Vec<_>>(),
    });
    let mut descriptor_bytes = serde_json::to_vec_pretty(&descriptor)
        .map_err(|source| FolderbaseError::json(journal_path, source))?;
    descriptor_bytes.push(b'\n');
    let mut entry = format!(
        "# {name}\n\nThis workspace is navigation only. It does not grant access to any folderbase.\n\n## Folderbases\n"
    );
    for folderbase in &folderbases {
        entry.push_str(&format!(
            "- [{}]({}/FOLDERBASE.md)\n",
            folderbase.label,
            folderbase.path.display()
        ));
    }
    let entry_path = workspace_path.join("WORKSPACE.md");
    let descriptor_path = workspace_path.join(".folderbase-workspace.json");
    let created_files = BTreeMap::from([
        (
            entry_path.clone(),
            format!("{:x}", Sha256::digest(entry.as_bytes())),
        ),
        (
            descriptor_path.clone(),
            format!("{:x}", Sha256::digest(&descriptor_bytes)),
        ),
    ]);
    journal.materialized_workspace = Some(MaterializedWorkspace {
        path: workspace_path.to_path_buf(),
        workspace_id,
        name,
        state: MaterializationState::Planned,
        folderbases,
        created_files: created_files.clone(),
    });
    for path in created_files.keys() {
        if !journal.created_paths.contains(path) {
            journal.created_paths.push(path.clone());
        }
    }
    persist_journal(journal_path, journal)?;
    checkpoint(ApplyCheckpoint::WorkspacePlanned);

    let entry_absolute = safe_join(root, &entry_path)?;
    write_bytes_new(&entry_absolute, entry.as_bytes())?;
    let descriptor_absolute = safe_join(root, &descriptor_path)?;
    write_bytes_new(&descriptor_absolute, &descriptor_bytes)?;
    for (relative, expected_sha256) in &created_files {
        let absolute = safe_join(root, relative)?;
        if sha256_path(&absolute)? != *expected_sha256 {
            return Err(FolderbaseError::MigrationVerificationFailed(absolute));
        }
    }
    journal
        .materialized_workspace
        .as_mut()
        .expect("workspace materialization was just recorded")
        .state = MaterializationState::Verified;
    persist_journal(journal_path, journal)?;
    checkpoint(ApplyCheckpoint::WorkspaceVerified);
    Ok(())
}

/// Reopen a durable migration result by ID.
impl MigrationResult {
    pub fn reopen(root: impl AsRef<Path>, migration_id: &str) -> Result<Self> {
        let root = canonical_root(root.as_ref())?;
        let (journal_path, journal) = load_journal(&root, migration_id)?;
        Ok(result_from_journal(root, journal_path, &journal))
    }

    /// Recover an interrupted apply or rollback. Interrupted applies are
    /// conservatively rolled back; verified and rolled-back results are simply
    /// reopened.
    pub fn recover(root: impl AsRef<Path>, migration_id: &str) -> Result<Self> {
        recover_migration_with_hook(root, migration_id, || {})
    }

    /// Roll back a verified migration using only its durable ID.
    pub fn rollback_by_id(root: impl AsRef<Path>, migration_id: &str) -> Result<RollbackResult> {
        let root = canonical_root(root.as_ref())?;
        let (journal_path, mut journal) = load_journal(&root, migration_id)?;
        require_state(journal.state, MigrationState::Verified)?;
        let result = if is_structural_journal(&journal) {
            rollback_structural_journal(&root, &journal_path, &mut journal)?
        } else {
            rollback_journal(&root, &journal_path, &mut journal)?
        };
        persist_plan_transition(
            &root,
            migration_id,
            &[MigrationState::Verified],
            MigrationState::RolledBack,
        )?;
        Ok(result)
    }
}

fn recover_migration_with_hook(
    root: impl AsRef<Path>,
    migration_id: &str,
    after_transaction_coordinator: impl FnOnce(),
) -> Result<MigrationResult> {
    let root = canonical_root(root.as_ref())?;
    after_transaction_coordinator();
    let (journal_path, mut journal) = load_journal(&root, migration_id)?;
    if matches!(
        journal.state,
        MigrationState::Applying | MigrationState::RollingBack
    ) {
        if is_structural_journal(&journal) {
            rollback_structural_journal(&root, &journal_path, &mut journal)?;
        } else {
            rollback_journal(&root, &journal_path, &mut journal)?;
        }
        persist_plan_transition(
            &root,
            migration_id,
            &[
                MigrationState::Approved,
                MigrationState::Applying,
                MigrationState::Verified,
                MigrationState::RollingBack,
            ],
            MigrationState::RolledBack,
        )?;
    } else if journal.state == MigrationState::Verified {
        persist_plan_transition(
            &root,
            migration_id,
            &[MigrationState::Applying, MigrationState::Verified],
            MigrationState::Verified,
        )?;
        cleanup_staging(&root, migration_id);
    } else if journal.state == MigrationState::RolledBack {
        let plan = load_plan(&root, migration_id)?;
        if plan.state != MigrationState::Conflicted {
            persist_plan_transition(
                &root,
                migration_id,
                &[
                    MigrationState::Applying,
                    MigrationState::Verified,
                    MigrationState::RolledBack,
                ],
                MigrationState::RolledBack,
            )?;
        }
        cleanup_staging(&root, migration_id);
    }
    Ok(result_from_journal(root, journal_path, &journal))
}

/// Roll back only additive, unchanged paths recorded by a verified migration.
pub fn rollback_migration(result: &MigrationResult) -> Result<RollbackResult> {
    require_state(result.state, MigrationState::Verified)?;
    MigrationResult::rollback_by_id(&result.root, &result.migration_id)
}

fn prepare_migration_directory(
    root: &Path,
    migration_dir: &Path,
    journal_path: &Path,
) -> Result<PathBuf> {
    let state_dir = safe_join(root, Path::new(STATE_DIR))?;
    create_directory_if_missing(&state_dir)?;
    let migrations_dir = safe_join(root, Path::new(MIGRATIONS_DIR))?;
    create_directory_if_missing(&migrations_dir)?;
    let migration_dir = safe_join(root, migration_dir)?;
    let metadata = fs::symlink_metadata(&migration_dir)
        .map_err(|source| FolderbaseError::io(&migration_dir, source))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(FolderbaseError::WouldOverwrite(migration_dir));
    }
    safe_join(root, journal_path)
}

fn create_migration_staging(root: &Path, migration_id: &str) -> Result<()> {
    let staging_relative = PathBuf::from(MIGRATIONS_DIR)
        .join(migration_id)
        .join("staging");
    let staging = safe_join(root, &staging_relative)?;
    fs::create_dir(&staging).map_err(|source| {
        if source.kind() == std::io::ErrorKind::AlreadyExists {
            FolderbaseError::WouldOverwrite(staging.clone())
        } else {
            FolderbaseError::io(&staging, source)
        }
    })?;
    sync_parent(&staging)?;
    Ok(())
}

fn create_directory_if_missing(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => Ok(()),
        Ok(_) => Err(FolderbaseError::WouldOverwrite(path.to_path_buf())),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir(path).map_err(|source| FolderbaseError::io(path, source))?;
            sync_parent(path)
        }
        Err(source) => Err(FolderbaseError::io(path, source)),
    }
}

fn apply_operation(
    root: &Path,
    index: usize,
    journal_path: &Path,
    journal: &mut MigrationJournal,
) -> Result<()> {
    let operation = journal
        .operations
        .get(index)
        .cloned()
        .ok_or_else(|| invalid_journal(journal_path, "in-flight operation is out of range"))?;
    match operation {
        MigrationOperation::CreateFolder { path } => {
            ensure_safe_relative(&path)?;
            let destination = safe_join(root, &path)?;
            if destination.exists() {
                return Err(FolderbaseError::WouldOverwrite(destination));
            }
            create_output_directories(root, &path, journal_path, journal)?;
        }
        MigrationOperation::CopyFile {
            source_path,
            destination_path,
            expected_sha256,
        } => {
            ensure_safe_relative(&source_path)?;
            ensure_safe_relative(&destination_path)?;
            let source = safe_join(root, &source_path)?;
            let destination = safe_join(root, &destination_path)?;
            if destination.exists() {
                return Err(FolderbaseError::WouldOverwrite(destination));
            }
            if let Some(parent) = destination_path.parent()
                && !parent.as_os_str().is_empty()
            {
                create_output_directories(root, parent, journal_path, journal)?;
            }
            let staging_relative = PathBuf::from(MIGRATIONS_DIR)
                .join(&journal.id)
                .join("staging")
                .join(format!("{index}.tmp"));
            let staging = safe_join(root, &staging_relative)?;
            copy_new(&source, &staging)?;
            if sha256_path(&staging)? != expected_sha256 {
                return Err(FolderbaseError::MigrationVerificationFailed(staging));
            }
            fs::hard_link(&staging, &destination).map_err(|source| {
                if source.kind() == std::io::ErrorKind::AlreadyExists {
                    FolderbaseError::WouldOverwrite(destination.clone())
                } else {
                    FolderbaseError::io(&destination, source)
                }
            })?;
            sync_parent(&destination)?;
            record_created_path(journal_path, journal, destination_path)?;
            fs::remove_file(&staging).map_err(|source| FolderbaseError::io(&staging, source))?;
            sync_parent(&staging)?;
        }
        _ => {
            return Err(invalid_journal(
                journal_path,
                "structural operation reached the additive apply path",
            ));
        }
    }
    Ok(())
}

fn create_output_directories(
    root: &Path,
    relative: &Path,
    journal_path: &Path,
    journal: &mut MigrationJournal,
) -> Result<()> {
    let mut current = PathBuf::new();
    for component in relative.components() {
        let Component::Normal(component) = component else {
            return Err(FolderbaseError::UnsafePath(relative.to_path_buf()));
        };
        current.push(component);
        let absolute = safe_join(root, &current)?;
        match fs::symlink_metadata(&absolute) {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => continue,
            Ok(_) => return Err(FolderbaseError::WouldOverwrite(absolute)),
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir(&absolute).map_err(|source| {
                    if source.kind() == std::io::ErrorKind::AlreadyExists {
                        FolderbaseError::WouldOverwrite(absolute.clone())
                    } else {
                        FolderbaseError::io(&absolute, source)
                    }
                })?;
                sync_parent(&absolute)?;
                record_created_path(journal_path, journal, current.clone())?;
            }
            Err(source) => return Err(FolderbaseError::io(&absolute, source)),
        }
    }
    Ok(())
}

fn record_created_path(
    journal_path: &Path,
    journal: &mut MigrationJournal,
    path: PathBuf,
) -> Result<()> {
    if !journal.created_paths.contains(&path) {
        journal.created_paths.push(path);
        persist_journal(journal_path, journal)?;
    }
    Ok(())
}

fn load_journal(root: &Path, migration_id: &str) -> Result<(PathBuf, MigrationJournal)> {
    validate_migration_id(root, migration_id)?;
    let journal_relative = PathBuf::from(MIGRATIONS_DIR)
        .join(migration_id)
        .join("result.json");
    let journal_path = safe_join(root, &journal_relative)?;
    let bytes =
        fs::read(&journal_path).map_err(|source| FolderbaseError::io(&journal_path, source))?;
    let journal: MigrationJournal = serde_json::from_slice(&bytes)
        .map_err(|source| FolderbaseError::json(&journal_path, source))?;
    validate_journal(root, migration_id, &journal_path, &journal)?;
    if is_structural_journal(&journal) {
        let plan = load_plan(root, migration_id)?;
        validate_structural_recovery_invariants(root, &journal_path, &plan, &journal)?;
    }
    Ok((journal_path, journal))
}

fn validate_journal(
    root: &Path,
    migration_id: &str,
    journal_path: &Path,
    journal: &MigrationJournal,
) -> Result<()> {
    if journal.protocol_version != "0.2.0"
        || journal.id != migration_id
        || journal.root != root
        || journal.source_inventory.algorithm != "sha256"
        || journal.completed_operations > journal.operations.len()
        || journal
            .in_flight_operation
            .is_some_and(|index| index >= journal.operations.len())
    {
        return Err(invalid_journal(
            journal_path,
            "migration journal metadata is inconsistent",
        ));
    }
    if journal_plan_digest(journal)? != journal.approval_digest {
        return Err(FolderbaseError::MigrationApprovalMismatch);
    }
    if is_structural_journal(journal) {
        let progress_is_consistent = match journal.state {
            MigrationState::Applying => journal
                .in_flight_operation
                .is_none_or(|index| index == journal.completed_operations),
            MigrationState::RollingBack => journal.in_flight_operation.is_none_or(|index| {
                journal.completed_operations > 0 && index + 1 == journal.completed_operations
            }),
            MigrationState::Verified => {
                journal.completed_operations == journal.operations.len()
                    && journal.in_flight_operation.is_none()
            }
            MigrationState::RolledBack => {
                journal.completed_operations == 0 && journal.in_flight_operation.is_none()
            }
            _ => false,
        };
        if !progress_is_consistent {
            return Err(invalid_journal(
                journal_path,
                "structural journal state and progress are inconsistent",
            ));
        }
    }
    validate_materialization_records(journal_path, journal)?;
    for path in &journal.created_paths {
        ensure_safe_relative(path)?;
        if !journal_path_is_authorized(journal, path) {
            return Err(invalid_journal(
                journal_path,
                "journal contains a path outside the approved destination set",
            ));
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StructuralDiskState {
    Original,
    Applied,
    OriginalAndApplied,
    PartialSameInode,
    RestoredWithPreservedDestination,
    Unknown,
}

fn validate_structural_recovery_invariants(
    root: &Path,
    journal_path: &Path,
    plan: &MigrationPlan,
    journal: &MigrationJournal,
) -> Result<()> {
    let legal_state_pair = match plan.state {
        MigrationState::Approved => journal.state == MigrationState::Applying,
        MigrationState::Applying => matches!(
            journal.state,
            MigrationState::Applying
                | MigrationState::Verified
                | MigrationState::RollingBack
                | MigrationState::RolledBack
        ),
        MigrationState::Verified => matches!(
            journal.state,
            MigrationState::Verified | MigrationState::RollingBack | MigrationState::RolledBack
        ),
        MigrationState::Conflicted => matches!(
            journal.state,
            MigrationState::Applying | MigrationState::RollingBack | MigrationState::RolledBack
        ),
        MigrationState::RolledBack => journal.state == MigrationState::RolledBack,
        _ => false,
    };
    if !legal_state_pair {
        return Err(invalid_journal(
            journal_path,
            "structural plan and journal states are inconsistent",
        ));
    }

    for (index, operation) in journal.operations.iter().enumerate() {
        let observed = observe_structural_disk_state(root, operation)?;
        let valid = match journal.state {
            MigrationState::Applying => {
                if index < journal.completed_operations {
                    matches!(
                        observed,
                        StructuralDiskState::Applied | StructuralDiskState::OriginalAndApplied
                    )
                } else if journal.in_flight_operation == Some(index) {
                    matches!(
                        observed,
                        StructuralDiskState::Original
                            | StructuralDiskState::Applied
                            | StructuralDiskState::OriginalAndApplied
                            | StructuralDiskState::PartialSameInode
                    )
                } else {
                    matches!(
                        observed,
                        StructuralDiskState::Original | StructuralDiskState::OriginalAndApplied
                    )
                }
            }
            MigrationState::RollingBack => {
                if journal.in_flight_operation == Some(index) {
                    matches!(
                        observed,
                        StructuralDiskState::Original
                            | StructuralDiskState::Applied
                            | StructuralDiskState::OriginalAndApplied
                            | StructuralDiskState::PartialSameInode
                            | StructuralDiskState::RestoredWithPreservedDestination
                    )
                } else if index < journal.completed_operations {
                    matches!(
                        observed,
                        StructuralDiskState::Applied | StructuralDiskState::OriginalAndApplied
                    )
                } else {
                    matches!(
                        observed,
                        StructuralDiskState::Original
                            | StructuralDiskState::OriginalAndApplied
                            | StructuralDiskState::RestoredWithPreservedDestination
                    )
                }
            }
            MigrationState::RolledBack => matches!(
                observed,
                StructuralDiskState::Original
                    | StructuralDiskState::OriginalAndApplied
                    | StructuralDiskState::RestoredWithPreservedDestination
            ),
            MigrationState::Verified if plan.state == MigrationState::Applying => {
                matches!(
                    observed,
                    StructuralDiskState::Applied | StructuralDiskState::OriginalAndApplied
                )
            }
            MigrationState::Verified => true,
            _ => false,
        };
        if !valid {
            return Err(invalid_journal(
                journal_path,
                format!(
                    "structural operation {index} observed as {observed:?} does not match durable \
                     recovery state {:?}, completed prefix {}, or in-flight cursor {:?}",
                    journal.state, journal.completed_operations, journal.in_flight_operation
                ),
            ));
        }
    }
    Ok(())
}

fn observe_structural_disk_state(
    root: &Path,
    operation: &MigrationOperation,
) -> Result<StructuralDiskState> {
    match operation {
        MigrationOperation::MoveObject {
            source_path,
            destination_path,
            expected_sha256,
            ..
        } => {
            let source = safe_join(root, source_path)?;
            let destination = safe_join(root, destination_path)?;
            let source_digest = regular_file_digest_if_present(&source)?;
            let destination_digest = regular_file_digest_if_present(&destination)?;
            match (source_digest, destination_digest) {
                (Some(source_digest), None) if source_digest == *expected_sha256 => {
                    Ok(StructuralDiskState::Original)
                }
                (None, Some(_)) if !source.exists() => Ok(StructuralDiskState::Applied),
                (Some(source_digest), Some(destination_digest))
                    if source_digest == *expected_sha256
                        && destination_digest == *expected_sha256 =>
                {
                    let (source_capability, destination_capability) =
                        open_migration_leaf_pair(root, source_path, destination_path)?;
                    if source_capability.identity == destination_capability.identity {
                        Ok(StructuralDiskState::PartialSameInode)
                    } else {
                        Ok(StructuralDiskState::RestoredWithPreservedDestination)
                    }
                }
                (Some(source_digest), Some(_)) if source_digest == *expected_sha256 => {
                    Ok(StructuralDiskState::RestoredWithPreservedDestination)
                }
                _ => Ok(StructuralDiskState::Unknown),
            }
        }
        operation if operation.is_structural() => {
            let source_path = operation
                .structural_source_path()
                .expect("structural operation has a source");
            let source = safe_join(root, source_path)?;
            let expected = operation
                .structural_expected_sha256()
                .expect("structural operation has an approved source digest");
            let result = operation
                .structural_expected_result_sha256()
                .expect("structural mutation has an approved result digest");
            match regular_file_digest_if_present(&source)? {
                Some(digest) if digest == expected && digest == result => {
                    Ok(StructuralDiskState::OriginalAndApplied)
                }
                Some(digest) if digest == expected => Ok(StructuralDiskState::Original),
                Some(digest) if digest == result => Ok(StructuralDiskState::Applied),
                _ => Ok(StructuralDiskState::Unknown),
            }
        }
        _ => Ok(StructuralDiskState::Unknown),
    }
}

fn validate_materialization_records(journal_path: &Path, journal: &MigrationJournal) -> Result<()> {
    const TEMPLATE_REFERENCE: &str = "folderbase.project@0.2.2";

    let binds_template = journal
        .template_references
        .iter()
        .any(|reference| reference == TEMPLATE_REFERENCE);
    if !binds_template {
        if journal.materialized_folderbases.is_empty() && journal.materialized_workspace.is_none() {
            return Ok(());
        }
        return Err(invalid_journal(
            journal_path,
            "materialization records are not bound by the approved plan",
        ));
    }
    let (workspace_path, approved) = approved_materialization_specs(
        &journal.answers,
        &journal.targets,
        &journal.operations,
        journal_path,
    )?;
    if journal.materialized_folderbases.len() > approved.len() {
        return Err(invalid_journal(
            journal_path,
            "materialized folderbase count exceeds the approved target set",
        ));
    }
    let (allowed_directories, allowed_files) = approved_template_output_paths()?;
    for (index, materialized) in journal.materialized_folderbases.iter().enumerate() {
        let expected = &approved[index];
        if materialized.target_id != expected.target_id
            || materialized.path != expected.path
            || materialized.name != expected.name
            || materialized.template_reference != TEMPLATE_REFERENCE
            || !materialized.folderbase_id.starts_with("folderbase_")
        {
            return Err(invalid_journal(
                journal_path,
                "materialized folderbase does not match the approved target topology",
            ));
        }
        ensure_safe_relative(&materialized.path)?;
        let mut unique_directories = BTreeSet::new();
        for path in &materialized.created_directories {
            ensure_safe_relative(path)?;
            let relative = path.strip_prefix(&materialized.path).map_err(|_| {
                invalid_journal(
                    journal_path,
                    "materialized folderbase path escapes its approved folderbase root",
                )
            })?;
            if !unique_directories.insert(path) || !allowed_directories.contains(relative) {
                return Err(invalid_journal(
                    journal_path,
                    "materialized folderbase contains an unapproved template directory",
                ));
            }
        }
        for path in materialized.created_files.keys() {
            ensure_safe_relative(path)?;
            let relative = path.strip_prefix(&materialized.path).map_err(|_| {
                invalid_journal(
                    journal_path,
                    "materialized folderbase path escapes its approved folderbase root",
                )
            })?;
            if !allowed_files.contains(relative) {
                return Err(invalid_journal(
                    journal_path,
                    "materialized folderbase contains an unapproved template file",
                ));
            }
        }
        let manifest = materialized.path.join(".folderbase/manifest.json");
        if !materialized.created_files.contains_key(&manifest) {
            return Err(invalid_journal(
                journal_path,
                "materialized folderbase does not include its required manifest write",
            ));
        }
    }
    if journal.state == MigrationState::Verified
        && (journal.materialized_folderbases.len() != approved.len()
            || journal
                .materialized_folderbases
                .iter()
                .any(|folderbase| folderbase.state != MaterializationState::Verified))
    {
        return Err(invalid_journal(
            journal_path,
            "verified migration has incomplete folderbase materialization",
        ));
    }

    match &journal.materialized_workspace {
        Some(workspace) => {
            if approved.len() < 2
                || journal.materialized_folderbases.len() != approved.len()
                || workspace.path != workspace_path
                || workspace.name != materialized_workspace_name(&workspace_path)
                || !workspace.workspace_id.starts_with("workspace_")
            {
                return Err(invalid_journal(
                    journal_path,
                    "materialized workspace does not match the approved topology",
                ));
            }
            let expected_folderbases = journal
                .materialized_folderbases
                .iter()
                .map(|folderbase| {
                    let path = folderbase.path.strip_prefix(&workspace.path).map_err(|_| {
                        invalid_journal(
                            journal_path,
                            "materialized folderbase is outside its approved workspace",
                        )
                    })?;
                    ensure_safe_relative(path)?;
                    Ok(WorkspaceFolderbaseLink {
                        folderbase_id: folderbase.folderbase_id.clone(),
                        label: folderbase.name.clone(),
                        path: path.to_path_buf(),
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            let expected_files = BTreeSet::from([
                workspace.path.join("WORKSPACE.md"),
                workspace.path.join(".folderbase-workspace.json"),
            ]);
            if workspace.folderbases != expected_folderbases
                || workspace
                    .created_files
                    .keys()
                    .cloned()
                    .collect::<BTreeSet<_>>()
                    != expected_files
                || (journal.state == MigrationState::Verified
                    && workspace.state != MaterializationState::Verified)
            {
                return Err(invalid_journal(
                    journal_path,
                    "materialized workspace records exceed the approved navigation surface",
                ));
            }
        }
        None if journal.state == MigrationState::Verified && approved.len() > 1 => {
            return Err(invalid_journal(
                journal_path,
                "verified multi-folderbase migration is missing its workspace descriptor",
            ));
        }
        None => {}
    }
    Ok(())
}

fn approved_template_output_paths() -> Result<(BTreeSet<PathBuf>, BTreeSet<PathBuf>)> {
    let package = load_builtin_template("folderbase.project", "0.2.2")?;
    let mut directories = BTreeSet::new();
    let mut files = BTreeSet::from([
        PathBuf::from("FOLDERBASE.md"),
        PathBuf::from(".folderbaseignore"),
        PathBuf::from(".folderbase/manifest.json"),
        PathBuf::from("AGENTS.md"),
        PathBuf::from("CLAUDE.md"),
    ]);
    for artifact in &package.artifacts {
        match artifact.kind {
            TemplateArtifactKind::Directory => {
                directories.insert(artifact.target.clone());
            }
            TemplateArtifactKind::Text => {
                files.insert(artifact.target.clone());
            }
        }
    }
    let paths = directories
        .iter()
        .chain(files.iter())
        .cloned()
        .collect::<Vec<_>>();
    for path in paths {
        let mut parent = path.parent();
        while let Some(path) = parent {
            if path.as_os_str().is_empty() {
                break;
            }
            directories.insert(path.to_path_buf());
            parent = path.parent();
        }
    }
    Ok((directories, files))
}

fn materialized_workspace_name(path: &Path) -> String {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(humanize_name)
        .unwrap_or_else(|| "Migration Workspace".to_owned())
}

fn journal_plan_digest(journal: &MigrationJournal) -> Result<String> {
    let bytes = if journal.approval_scheme.as_deref() == Some("migration_plan_v0.2") {
        serde_json::to_vec(&(
            &journal.protocol_version,
            &journal.id,
            &journal.root,
            MigrationState::Approved,
            &journal.source_inventory,
            &journal.answers,
            &journal.template_references,
            &journal.targets,
            &journal.operations,
            &journal.exclusions,
            &journal.plan_extensions,
        ))
    } else if journal.targets.is_empty() {
        serde_json::to_vec(&(
            &journal.id,
            &journal.root,
            MigrationState::Approved,
            &journal.source_inventory.digest,
            &journal.answers,
            &journal.operations,
            &journal.exclusions,
        ))
    } else {
        serde_json::to_vec(&(
            &journal.id,
            &journal.root,
            MigrationState::Approved,
            &journal.source_inventory.digest,
            &journal.answers,
            &journal.targets,
            &journal.operations,
            &journal.exclusions,
        ))
    }
    .map_err(|source| FolderbaseError::json(&journal.root, source))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn journal_path_is_authorized(journal: &MigrationJournal, path: &Path) -> bool {
    journal.operations.iter().any(|operation| match operation {
        MigrationOperation::CreateFolder { path: destination } => {
            destination == path || destination.starts_with(path)
        }
        MigrationOperation::CopyFile {
            destination_path, ..
        } => destination_path == path || destination_path.starts_with(path),
        _ => false,
    }) || journal.materialized_folderbases.iter().any(|materialized| {
        materialized
            .created_directories
            .iter()
            .any(|candidate| candidate == path)
            || materialized.created_files.contains_key(path)
    }) || journal
        .materialized_workspace
        .as_ref()
        .is_some_and(|workspace| workspace.created_files.contains_key(path))
}

fn reconcile_in_flight(
    root: &Path,
    journal_path: &Path,
    journal: &mut MigrationJournal,
) -> Result<()> {
    let Some(index) = journal.in_flight_operation else {
        return Ok(());
    };
    let operation = journal
        .operations
        .get(index)
        .cloned()
        .ok_or_else(|| invalid_journal(journal_path, "in-flight operation is out of range"))?;
    match operation {
        MigrationOperation::CreateFolder { path } => {
            let absolute = safe_join(root, &path)?;
            if absolute.exists() && !journal.created_paths.contains(&path) {
                let metadata = fs::symlink_metadata(&absolute)
                    .map_err(|source| FolderbaseError::io(&absolute, source))?;
                if !metadata.is_dir() || metadata.file_type().is_symlink() {
                    return Err(FolderbaseError::MigrationVerificationFailed(absolute));
                }
                journal.created_paths.push(path);
            }
        }
        MigrationOperation::CopyFile {
            destination_path,
            expected_sha256,
            ..
        } => {
            let absolute = safe_join(root, &destination_path)?;
            if absolute.exists() && !journal.created_paths.contains(&destination_path) {
                let metadata = fs::symlink_metadata(&absolute)
                    .map_err(|source| FolderbaseError::io(&absolute, source))?;
                if !metadata.is_file()
                    || metadata.file_type().is_symlink()
                    || sha256_path(&absolute)? != expected_sha256
                {
                    return Err(FolderbaseError::MigrationVerificationFailed(absolute));
                }
                journal.created_paths.push(destination_path);
            }
        }
        _ => {
            return Err(invalid_journal(
                journal_path,
                "structural operation reached additive recovery",
            ));
        }
    }
    persist_journal(journal_path, journal)
}

fn reconcile_structural_in_flight(
    root: &Path,
    journal_path: &Path,
    journal: &mut MigrationJournal,
) -> Result<()> {
    reconcile_structural_in_flight_with_hook(root, journal_path, journal, |_| {})
}

fn reconcile_structural_in_flight_with_hook(
    root: &Path,
    journal_path: &Path,
    journal: &mut MigrationJournal,
    mut before_final_destination_revalidation: impl FnMut(&Path),
) -> Result<()> {
    let Some(index) = journal.in_flight_operation else {
        return Ok(());
    };
    let operation = journal
        .operations
        .get(index)
        .ok_or_else(|| invalid_journal(journal_path, "in-flight operation is out of range"))?;
    refuse_structural_operation_boundaries(root, operation)?;
    let applied = match operation {
        MigrationOperation::MoveObject {
            source_path,
            destination_path,
            expected_sha256,
            ..
        } => {
            let source = safe_join(root, source_path)?;
            let destination = safe_join(root, destination_path)?;
            if journal.state == MigrationState::RollingBack {
                match (
                    regular_file_digest_if_present(&source)?,
                    regular_file_digest_if_present(&destination)?,
                ) {
                    (Some(source_digest), Some(destination_digest))
                        if source_digest == *expected_sha256
                            && destination_digest == *expected_sha256 =>
                    {
                        let (source_capability, destination_capability) =
                            open_migration_leaf_pair(root, source_path, destination_path)?;
                        if source_capability.identity == destination_capability.identity {
                            remove_matching_destination_with(
                                source_capability,
                                destination_capability,
                                &mut before_final_destination_revalidation,
                            )?;
                        }
                        true
                    }
                    (Some(source_digest), _) if source_digest == *expected_sha256 => true,
                    (None, _) if !source.exists() => false,
                    _ => {
                        return Err(FolderbaseError::MigrationVerificationFailed(
                            source_path.clone(),
                        ));
                    }
                }
            } else {
                match (source.exists(), destination.exists()) {
                    (true, false) if sha256_path(&source)? == *expected_sha256 => false,
                    (false, true) if sha256_path(&destination)? == *expected_sha256 => true,
                    (true, true)
                        if sha256_path(&source)? == *expected_sha256
                            && sha256_path(&destination)? == *expected_sha256 =>
                    {
                        let (source_capability, destination_capability) =
                            open_migration_leaf_pair(root, source_path, destination_path)?;
                        if source_capability.identity != destination_capability.identity {
                            return Err(FolderbaseError::MigrationVerificationFailed(
                                destination_path.clone(),
                            ));
                        }
                        remove_matching_destination_with(
                            source_capability,
                            destination_capability,
                            &mut before_final_destination_revalidation,
                        )?;
                        false
                    }
                    _ => {
                        return Err(FolderbaseError::MigrationVerificationFailed(
                            destination_path.clone(),
                        ));
                    }
                }
            }
        }
        operation if operation.is_structural() => {
            let source_path = operation
                .structural_source_path()
                .expect("structural operation has a source");
            let source = safe_join(root, source_path)?;
            let current = sha256_path(&source)?;
            let expected = operation
                .structural_expected_sha256()
                .expect("structural operation has a source digest");
            let result = operation
                .structural_expected_result_sha256()
                .expect("structural operation has a result digest");
            if journal.state == MigrationState::RollingBack {
                if current == expected {
                    true
                } else if current == result {
                    false
                } else {
                    return Err(FolderbaseError::MigrationVerificationFailed(source));
                }
            } else if current == expected {
                false
            } else if current == result {
                true
            } else {
                return Err(FolderbaseError::MigrationVerificationFailed(source));
            }
        }
        _ => {
            return Err(invalid_journal(
                journal_path,
                "additive operation reached structural recovery",
            ));
        }
    };
    if journal.state == MigrationState::RollingBack && applied {
        journal.completed_operations = index;
    } else if applied {
        journal.completed_operations = journal.completed_operations.max(index + 1);
    }
    journal.in_flight_operation = None;
    persist_journal(journal_path, journal)
}

struct MigrationLeafCapability {
    root: Dir,
    root_display: PathBuf,
    _parent: Dir,
    parent_identity: PhysicalIdentity,
    parent_relative: PathBuf,
    name: OsString,
    display: PathBuf,
    identity: RetainedPhysicalIdentity,
}

fn open_migration_leaf_pair(
    root: &Path,
    source: &Path,
    destination: &Path,
) -> Result<(MigrationLeafCapability, MigrationLeafCapability)> {
    let root_capability = open_migration_root_nofollow(root)?;
    Ok((
        open_migration_leaf_from_root(&root_capability, root, source)?,
        open_migration_leaf_from_root(&root_capability, root, destination)?,
    ))
}

fn open_migration_leaf_from_root(
    root_capability: &Dir,
    root: &Path,
    relative: &Path,
) -> Result<MigrationLeafCapability> {
    let name = relative
        .file_name()
        .ok_or_else(|| FolderbaseError::UnsafePath(relative.to_path_buf()))?
        .to_os_string();
    let parent_relative = relative.parent().unwrap_or_else(|| Path::new(""));
    let parent = open_migration_directory_from_root(root_capability, parent_relative, root)?;
    let parent_identity = migration_directory_identity(&parent, &root.join(parent_relative))?;
    let display = root.join(relative);
    let identity = open_migration_regular_identity(&parent, &name, &display)?;
    Ok(MigrationLeafCapability {
        root: root_capability
            .try_clone()
            .map_err(|error| FolderbaseError::io(root, error))?,
        root_display: root.to_path_buf(),
        _parent: parent,
        parent_identity,
        parent_relative: parent_relative.to_path_buf(),
        name,
        display,
        identity,
    })
}

fn open_migration_root_nofollow(root: &Path) -> Result<Dir> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        options.custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE};
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
            FILE_SHARE_WRITE,
        };

        options
            .access_mode(GENERIC_READ | GENERIC_WRITE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE);
    }
    let file = options
        .open(root)
        .map_err(|error| FolderbaseError::io(root, error))?;
    let metadata = file
        .metadata()
        .map_err(|error| FolderbaseError::io(root, error))?;
    if metadata_is_link_or_reparse(&metadata) || !metadata.is_dir() {
        return Err(FolderbaseError::UnsafePath(root.to_path_buf()));
    }
    Ok(Dir::from_std_file(file))
}

fn open_migration_directory_from_root(
    root: &Dir,
    relative: &Path,
    root_display: &Path,
) -> Result<Dir> {
    let mut directory = root
        .try_clone()
        .map_err(|error| FolderbaseError::io(root_display, error))?;
    let mut current_display = root_display.to_path_buf();
    for component in relative.components() {
        let Component::Normal(name) = component else {
            return Err(FolderbaseError::UnsafePath(relative.to_path_buf()));
        };
        current_display.push(name);
        directory = open_migration_directory_nofollow(&directory, name, &current_display)
            .map_err(|error| FolderbaseError::io(&current_display, error))?;
    }
    Ok(directory)
}

#[cfg(not(windows))]
fn open_migration_directory_nofollow(
    parent: &Dir,
    name: &OsStr,
    _display: &Path,
) -> io::Result<Dir> {
    parent.open_dir_nofollow(name)
}

#[cfg(windows)]
fn open_migration_directory_nofollow(
    parent: &Dir,
    name: &OsStr,
    display: &Path,
) -> io::Result<Dir> {
    use cap_std::fs::OpenOptionsExt;
    use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    let mut options = CapOpenOptions::new();
    options
        .read(true)
        .write(true)
        .access_mode(GENERIC_READ | GENERIC_WRITE)
        .follow(FollowSymlinks::No)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE);
    let file = parent.open_with(name, &options)?.into_std();
    let metadata = file.metadata()?;
    if metadata_is_link_or_reparse(&metadata) || !metadata.is_dir() {
        return Err(io::Error::other(format!(
            "unsafe migration directory capability: {}",
            display.display()
        )));
    }
    Ok(Dir::from_std_file(file))
}

fn migration_directory_identity(directory: &Dir, display: &Path) -> Result<PhysicalIdentity> {
    let file = directory
        .try_clone()
        .map_err(|error| FolderbaseError::io(display, error))?
        .into_std_file();
    PhysicalIdentity::from_file(&file).map_err(|error| FolderbaseError::io(display, error))
}

fn open_migration_regular_identity(
    parent: &Dir,
    name: &OsStr,
    display: &Path,
) -> Result<RetainedPhysicalIdentity> {
    let mut options = CapOpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    #[cfg(windows)]
    {
        use cap_std::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
            FILE_SHARE_WRITE,
        };

        options
            .access_mode(0)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE);
    }
    let file = parent
        .open_with(name, &options)
        .map_err(|error| FolderbaseError::io(display, error))?
        .into_std();
    let metadata = file
        .metadata()
        .map_err(|error| FolderbaseError::io(display, error))?;
    if metadata_is_link_or_reparse(&metadata) || !metadata.is_file() {
        return Err(FolderbaseError::UnsafePath(display.to_path_buf()));
    }
    RetainedPhysicalIdentity::from_file(file).map_err(|error| FolderbaseError::io(display, error))
}

impl MigrationLeafCapability {
    fn reopen_parent(&self) -> Result<Dir> {
        let parent = open_migration_directory_from_root(
            &self.root,
            &self.parent_relative,
            &self.root_display,
        )?;
        if migration_directory_identity(
            &parent,
            self.display
                .parent()
                .ok_or_else(|| FolderbaseError::UnsafePath(self.display.clone()))?,
        )? != self.parent_identity
        {
            return Err(FolderbaseError::MigrationVerificationFailed(
                self.display.clone(),
            ));
        }
        Ok(parent)
    }
}

fn remove_matching_destination_with(
    source: MigrationLeafCapability,
    destination: MigrationLeafCapability,
    before_final_destination_revalidation: &mut impl FnMut(&Path),
) -> Result<()> {
    if source.identity != destination.identity {
        return Err(FolderbaseError::MigrationVerificationFailed(
            destination.display.clone(),
        ));
    }
    before_final_destination_revalidation(&destination.display);
    let destination_parent = destination.reopen_parent()?;
    let final_destination = open_migration_regular_identity(
        &destination_parent,
        &destination.name,
        &destination.display,
    )?;
    if final_destination != destination.identity {
        return Err(FolderbaseError::MigrationVerificationFailed(
            destination.display.clone(),
        ));
    }

    #[cfg(windows)]
    {
        // Windows child handles deny deletion. Relinquish them only after the
        // final capability-relative identity proof; retain both the root and
        // exact parent capabilities so ancestor substitution cannot redirect
        // the removal. The remaining leaf-name transition uses the same
        // cooperative namespace contract as ADR 0001.
        drop(final_destination);
        drop(destination.identity);
        drop(source.identity);
    }
    #[cfg(not(windows))]
    {
        // POSIX permits unlink through the retained parent while every child
        // authority remains live, eliminating identity-reuse authorization.
        let _ = (&final_destination, &destination.identity, &source.identity);
    }

    destination_parent
        .remove_file(&destination.name)
        .map_err(|error| FolderbaseError::io(&destination.display, error))?;
    sync_migration_directory(
        &destination_parent,
        destination
            .display
            .parent()
            .ok_or_else(|| FolderbaseError::UnsafePath(destination.display.clone()))?,
    )
}

#[cfg(unix)]
fn sync_migration_directory(directory: &Dir, display: &Path) -> Result<()> {
    let mut options = CapOpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    directory
        .open_with(Path::new("."), &options)
        .and_then(|file| file.into_std().sync_all())
        .map_err(|error| FolderbaseError::io(display, error))
}

#[cfg(windows)]
fn sync_migration_directory(_directory: &Dir, _display: &Path) -> Result<()> {
    // Windows exposes no documented POSIX directory-fsync equivalent. The
    // retained directory capability still confines and revalidates removal.
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn sync_migration_directory(directory: &Dir, display: &Path) -> Result<()> {
    directory
        .try_clone()
        .and_then(|directory| directory.into_std_file().sync_all())
        .map_err(|error| FolderbaseError::io(display, error))
}

fn rollback_structural_journal(
    root: &Path,
    journal_path: &Path,
    journal: &mut MigrationJournal,
) -> Result<RollbackResult> {
    rollback_structural_journal_with_hook(root, journal_path, journal, |_| {})
}

fn rollback_structural_journal_with_hook(
    root: &Path,
    journal_path: &Path,
    journal: &mut MigrationJournal,
    mut checkpoint: impl FnMut(StructuralRollbackCheckpoint),
) -> Result<RollbackResult> {
    if !matches!(
        journal.state,
        MigrationState::Applying | MigrationState::Verified | MigrationState::RollingBack
    ) || !is_structural_journal(journal)
    {
        return Err(FolderbaseError::InvalidMigrationState {
            expected: MigrationState::Verified.as_str(),
            actual: journal.state.as_str().to_owned(),
        });
    }
    reconcile_structural_in_flight(root, journal_path, journal)?;
    for operation in journal.operations.iter().take(journal.completed_operations) {
        verify_structural_rollback_precondition(root, operation)?;
    }
    journal.state = MigrationState::RollingBack;
    persist_journal(journal_path, journal)?;
    checkpoint(StructuralRollbackCheckpoint::Started);
    let mut affected_paths = Vec::new();

    while journal.completed_operations > 0 {
        let index = journal.completed_operations - 1;
        let operation = journal.operations[index].clone();
        refuse_structural_operation_boundaries(root, &operation)?;
        journal.in_flight_operation = Some(index);
        persist_journal(journal_path, journal)?;
        checkpoint(StructuralRollbackCheckpoint::OperationPlanned(index));
        match &operation {
            MigrationOperation::MoveObject {
                source_path,
                destination_path,
                expected_sha256,
                ..
            } => {
                let source = safe_join(root, source_path)?;
                let destination = safe_join(root, destination_path)?;
                let (snapshot_path, snapshot_sha256) =
                    operation.structural_snapshot().ok_or_else(|| {
                        invalid_journal(journal_path, "structural snapshot is missing")
                    })?;
                let snapshot = safe_join(root, snapshot_path)?;
                match regular_file_digest_if_present(&source)? {
                    Some(digest) if digest == *expected_sha256 => {}
                    Some(_) => {
                        return Err(FolderbaseError::MigrationVerificationFailed(source));
                    }
                    None => {
                        if regular_file_digest_if_present(&destination)?
                            .is_some_and(|digest| digest == *expected_sha256)
                        {
                            move_file_no_replace(&destination, &source, expected_sha256)?;
                            affected_paths.push(destination_path.clone());
                        } else {
                            restore_snapshot_no_clobber(
                                root,
                                &journal.id,
                                index,
                                &snapshot,
                                &source,
                                snapshot_sha256,
                            )?;
                            if sha256_path(&source)? != snapshot_sha256 {
                                return Err(FolderbaseError::MigrationVerificationFailed(source));
                            }
                        }
                    }
                }
            }
            operation if operation.is_structural() => {
                let source_path = operation
                    .structural_source_path()
                    .expect("structural operation has a source");
                let source = safe_join(root, source_path)?;
                let expected_result = operation
                    .structural_expected_result_sha256()
                    .expect("structural mutation has a result digest");
                let (snapshot_path, snapshot_sha256) =
                    operation.structural_snapshot().ok_or_else(|| {
                        invalid_journal(journal_path, "structural snapshot is missing")
                    })?;
                let snapshot = safe_join(root, snapshot_path)?;
                let snapshot_bytes = read_bounded_regular(&snapshot, MAX_MIGRATION_PLAN_BYTES)?;
                if sha256_bytes(&snapshot_bytes) != snapshot_sha256 {
                    return Err(FolderbaseError::MigrationVerificationFailed(snapshot));
                }
                replace_file_atomically(&source, expected_result, &snapshot_bytes)?;
                if sha256_path(&source)? != snapshot_sha256 {
                    return Err(FolderbaseError::MigrationVerificationFailed(source));
                }
                affected_paths.push(source_path.to_path_buf());
            }
            _ => {
                return Err(invalid_journal(
                    journal_path,
                    "additive operation reached structural rollback",
                ));
            }
        }
        checkpoint(StructuralRollbackCheckpoint::OperationApplied(index));
        journal.completed_operations = index;
        journal.in_flight_operation = None;
        persist_journal(journal_path, journal)?;
        checkpoint(StructuralRollbackCheckpoint::OperationCompleted(index));
    }

    journal.in_flight_operation = None;
    journal.state = MigrationState::RolledBack;
    persist_journal(journal_path, journal)?;
    checkpoint(StructuralRollbackCheckpoint::Completed);
    cleanup_staging(root, &journal.id);
    Ok(RollbackResult {
        migration_id: journal.id.clone(),
        removed_paths: affected_paths,
        state: MigrationState::RolledBack,
    })
}

fn verify_structural_rollback_precondition(
    root: &Path,
    operation: &MigrationOperation,
) -> Result<()> {
    refuse_structural_operation_boundaries(root, operation)?;
    let (snapshot_path, snapshot_sha256) = operation
        .structural_snapshot()
        .ok_or_else(|| invalid_journal(root, "structural snapshot is missing"))?;
    let snapshot = safe_join(root, snapshot_path)?;
    if sha256_path(&snapshot)? != snapshot_sha256 {
        return Err(FolderbaseError::MigrationVerificationFailed(snapshot));
    }
    match operation {
        MigrationOperation::MoveObject {
            source_path,
            destination_path,
            expected_sha256,
            ..
        } => {
            let source = safe_join(root, source_path)?;
            match regular_file_digest_if_present(&source)? {
                Some(digest) if digest == *expected_sha256 => {}
                Some(_) => return Err(FolderbaseError::MigrationVerificationFailed(source)),
                None => {
                    let _ = safe_join(root, destination_path)?;
                }
            }
        }
        operation if operation.is_structural() => {
            let source_path = operation
                .structural_source_path()
                .expect("structural operation has a source");
            if sha256_path(&safe_join(root, source_path)?)?
                != operation
                    .structural_expected_result_sha256()
                    .expect("structural operation has a result digest")
            {
                return Err(FolderbaseError::MigrationVerificationFailed(
                    source_path.to_path_buf(),
                ));
            }
        }
        _ => {
            return Err(invalid_journal(
                root,
                "additive operation reached structural rollback verification",
            ));
        }
    }
    Ok(())
}

fn refuse_structural_operation_boundaries(
    root: &Path,
    operation: &MigrationOperation,
) -> Result<()> {
    if let MigrationOperation::MoveObject {
        source_path,
        destination_path,
        ..
    } = operation
    {
        ensure_move_content_path(source_path)?;
        ensure_move_content_path(destination_path)?;
        refuse_tracked_move_path(root, source_path)?;
        refuse_tracked_move_path(root, destination_path)?;
    }
    let source_path = operation
        .structural_source_path()
        .expect("structural operation has a source");
    refuse_nested_folderbase_path(root, source_path)?;
    if let Some(destination_path) = operation.structural_destination_path() {
        refuse_nested_folderbase_path(root, destination_path)?;
    }
    Ok(())
}

fn refuse_tracked_move_path(root: &Path, path: &Path) -> Result<()> {
    if LocalVersionStore::open(root)?
        .tracked_object_id(path)?
        .is_some()
    {
        return Err(FolderbaseError::InvalidRecord {
            path: path.to_path_buf(),
            message: "ordinary moves cannot relocate a version-tracked object".to_owned(),
        });
    }
    Ok(())
}

fn ensure_move_content_path(path: &Path) -> Result<()> {
    ensure_safe_relative(path)?;
    if path.components().any(|component| {
        matches!(component, Component::Normal(name) if is_reserved_workspace_component(name))
    }) {
        return Err(FolderbaseError::UnsafePath(path.to_path_buf()));
    }
    if path.parent().is_none()
        && path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| {
                ["AGENTS.md", "CLAUDE.md", ".folderbaseignore"]
                    .iter()
                    .any(|reserved| name.eq_ignore_ascii_case(reserved))
            })
    {
        return Err(FolderbaseError::UnsafePath(path.to_path_buf()));
    }
    Ok(())
}

fn regular_file_digest_if_present(path: &Path) -> Result<Option<String>> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
            sha256_path(path).map(Some)
        }
        Ok(_) => Ok(None),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(FolderbaseError::io(path, source)),
    }
}

fn rollback_journal(
    root: &Path,
    journal_path: &Path,
    journal: &mut MigrationJournal,
) -> Result<RollbackResult> {
    if !matches!(
        journal.state,
        MigrationState::Applying | MigrationState::Verified | MigrationState::RollingBack
    ) {
        return Err(FolderbaseError::InvalidMigrationState {
            expected: MigrationState::Verified.as_str(),
            actual: journal.state.as_str().to_owned(),
        });
    }
    reconcile_in_flight(root, journal_path, journal)?;
    verify_rollback_paths(root, journal)?;
    journal.state = MigrationState::RollingBack;
    persist_journal(journal_path, journal)?;
    let mut removed_paths = Vec::new();

    while let Some(path) = journal.created_paths.last().cloned() {
        ensure_safe_relative(&path)?;
        let absolute = safe_join(root, &path)?;
        match fs::symlink_metadata(&absolute) {
            Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
                verify_rollback_file(journal, &path, &absolute)?;
                fs::remove_file(&absolute)
                    .map_err(|source| FolderbaseError::io(&absolute, source))?;
                sync_parent(&absolute)?;
                removed_paths.push(path.clone());
            }
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
                if fs::read_dir(&absolute)
                    .map_err(|source| FolderbaseError::io(&absolute, source))?
                    .next()
                    .is_none()
                {
                    fs::remove_dir(&absolute)
                        .map_err(|source| FolderbaseError::io(&absolute, source))?;
                    sync_parent(&absolute)?;
                    removed_paths.push(path.clone());
                }
            }
            Ok(_) => return Err(FolderbaseError::MigrationVerificationFailed(absolute)),
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => return Err(FolderbaseError::io(&absolute, source)),
        }
        journal.created_paths.pop();
        persist_journal(journal_path, journal)?;
    }

    journal.in_flight_operation = None;
    journal.state = MigrationState::RolledBack;
    persist_journal(journal_path, journal)?;
    cleanup_staging(root, &journal.id);
    Ok(RollbackResult {
        migration_id: journal.id.clone(),
        removed_paths,
        state: MigrationState::RolledBack,
    })
}

fn verify_rollback_paths(root: &Path, journal: &MigrationJournal) -> Result<()> {
    let approved_boundaries = journal
        .materialized_folderbases
        .iter()
        .map(|materialized| materialized.path.clone())
        .collect::<BTreeSet<_>>();
    for path in &journal.created_paths {
        refuse_unapproved_nested_folderbase_path(root, path, &approved_boundaries)?;
        let absolute = safe_join(root, path)?;
        match fs::symlink_metadata(&absolute) {
            Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
                verify_rollback_file(journal, path, &absolute)?;
            }
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
            Ok(_) => return Err(FolderbaseError::MigrationVerificationFailed(absolute)),
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => return Err(FolderbaseError::io(&absolute, source)),
        }
    }
    Ok(())
}

fn refuse_unapproved_nested_folderbase_path(
    root: &Path,
    relative: &Path,
    approved_boundaries: &BTreeSet<PathBuf>,
) -> Result<()> {
    ensure_safe_relative(relative)?;
    let mut prefix = PathBuf::new();
    for component in relative.components() {
        let Component::Normal(component) = component else {
            return Err(FolderbaseError::UnsafePath(relative.to_path_buf()));
        };
        prefix.push(component);
        let directory = safe_join(root, &prefix)?;
        match fs::symlink_metadata(&directory) {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
                if migration_nested_folderbase_marker(&directory, &prefix)?
                    && !approved_boundaries.contains(&prefix)
                {
                    return Err(FolderbaseError::UnsafePath(prefix));
                }
            }
            Ok(_) if prefix == relative => {}
            Ok(_) => return Err(FolderbaseError::UnsafePath(prefix)),
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => break,
            Err(source) => return Err(FolderbaseError::io(directory, source)),
        }
    }
    Ok(())
}

fn verify_rollback_file(
    journal: &MigrationJournal,
    relative: &Path,
    absolute: &Path,
) -> Result<()> {
    let expected = journal
        .operations
        .iter()
        .find_map(|operation| match operation {
            MigrationOperation::CopyFile {
                destination_path,
                expected_sha256,
                ..
            } if destination_path == relative => Some(expected_sha256),
            _ => None,
        })
        .or_else(|| {
            journal
                .materialized_folderbases
                .iter()
                .find_map(|materialized| materialized.created_files.get(relative))
        })
        .or_else(|| {
            journal
                .materialized_workspace
                .as_ref()
                .and_then(|workspace| workspace.created_files.get(relative))
        });
    match expected {
        Some(expected) if sha256_path(absolute)? == *expected => Ok(()),
        _ => Err(FolderbaseError::MigrationVerificationFailed(
            absolute.to_path_buf(),
        )),
    }
}

fn result_from_journal(
    root: PathBuf,
    journal_absolute: PathBuf,
    journal: &MigrationJournal,
) -> MigrationResult {
    let journal_path = journal_absolute
        .strip_prefix(&root)
        .unwrap_or(&journal_absolute)
        .to_path_buf();
    MigrationResult {
        migration_id: journal.id.clone(),
        root,
        state: journal.state,
        created_paths: journal.created_paths.clone(),
        journal_path,
    }
}

fn invalid_journal(path: impl Into<PathBuf>, message: impl Into<String>) -> FolderbaseError {
    FolderbaseError::InvalidRecord {
        path: path.into(),
        message: message.into(),
    }
}

fn validate_migration_id(root: &Path, migration_id: &str) -> Result<()> {
    ensure_safe_relative(Path::new(migration_id))?;
    if !migration_id.starts_with("migration_") {
        return Err(invalid_journal(
            root,
            "migration ID must start with `migration_`",
        ));
    }
    Ok(())
}

fn migration_plan_relative(migration_id: &str) -> PathBuf {
    PathBuf::from(MIGRATIONS_DIR)
        .join(migration_id)
        .join("plan.json")
}

fn persist_new_plan(plan: &MigrationPlan) -> Result<()> {
    validate_plan(&plan.root, &plan.id, Path::new("plan.json"), plan)?;
    let state_dir = safe_join(&plan.root, Path::new(STATE_DIR))?;
    create_directory_if_missing(&state_dir)?;
    let migrations_dir = safe_join(&plan.root, Path::new(MIGRATIONS_DIR))?;
    create_directory_if_missing(&migrations_dir)?;
    let migration_dir = safe_join(&plan.root, &PathBuf::from(MIGRATIONS_DIR).join(&plan.id))?;
    fs::create_dir(&migration_dir).map_err(|source| {
        if source.kind() == std::io::ErrorKind::AlreadyExists {
            FolderbaseError::WouldOverwrite(migration_dir.clone())
        } else {
            FolderbaseError::io(&migration_dir, source)
        }
    })?;
    sync_parent(&migration_dir)?;
    write_json_new(&migration_dir.join("plan.json"), plan)
}

fn persist_plan_transition(
    root: &Path,
    migration_id: &str,
    expected: &[MigrationState],
    next: MigrationState,
) -> Result<()> {
    let mut plan = load_plan(root, migration_id)?;
    if !expected.contains(&plan.state) {
        return Err(FolderbaseError::InvalidMigrationState {
            expected: expected.first().copied().unwrap_or(next).as_str(),
            actual: plan.state.as_str().to_owned(),
        });
    }
    plan.state = next;
    persist_plan(&plan)
}

fn load_plan(root: &Path, migration_id: &str) -> Result<MigrationPlan> {
    validate_migration_id(root, migration_id)?;
    let plan_path = safe_join(root, &migration_plan_relative(migration_id))?;
    let metadata = fs::symlink_metadata(&plan_path)
        .map_err(|source| FolderbaseError::io(&plan_path, source))?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > MAX_MIGRATION_PLAN_BYTES
    {
        return Err(invalid_journal(
            &plan_path,
            "migration plan must be a bounded regular file",
        ));
    }
    let bytes = fs::read(&plan_path).map_err(|source| FolderbaseError::io(&plan_path, source))?;
    let mut plan: MigrationPlan = serde_json::from_slice(&bytes)
        .map_err(|source| FolderbaseError::json(&plan_path, source))?;
    validate_plan(root, migration_id, &plan_path, &plan)?;
    plan.root_identity = Some(
        RetainedPhysicalIdentity::from_path(root)
            .map_err(|source| FolderbaseError::io(root, source))?,
    );
    Ok(plan)
}

fn validate_plan(
    root: &Path,
    migration_id: &str,
    plan_path: &Path,
    plan: &MigrationPlan,
) -> Result<()> {
    if plan.protocol_version != "0.2.0"
        || plan.id != migration_id
        || plan.root != root
        || plan.source_inventory.algorithm != "sha256"
        || inventory_digest(&plan.source_inventory.files) != plan.source_inventory.digest
        || !matches!(
            plan.state,
            MigrationState::Proposed
                | MigrationState::Approved
                | MigrationState::Applying
                | MigrationState::Verified
                | MigrationState::Conflicted
                | MigrationState::Rejected
                | MigrationState::RolledBack
        )
    {
        return Err(invalid_journal(
            plan_path,
            "migration plan metadata is inconsistent",
        ));
    }
    let approval_metadata_is_consistent = match plan.state {
        MigrationState::Proposed | MigrationState::Rejected => plan.approval_digest.is_none(),
        MigrationState::Approved
        | MigrationState::Applying
        | MigrationState::Verified
        | MigrationState::Conflicted
        | MigrationState::RolledBack => plan.approval_digest.is_some(),
        MigrationState::Analyzing | MigrationState::Questions | MigrationState::RollingBack => {
            false
        }
    };
    if !approval_metadata_is_consistent {
        return Err(invalid_journal(
            plan_path,
            "migration plan approval metadata is inconsistent with its state",
        ));
    }
    if let Some(approval_digest) = &plan.approval_digest
        && plan_digest(plan)? != *approval_digest
    {
        return Err(FolderbaseError::MigrationApprovalMismatch);
    }
    validate_grouped_assignments_extension(plan_path, plan)?;
    validate_expanded_reconstructable_trees_extension(plan_path, plan)?;
    for source in &plan.source_inventory.files {
        ensure_safe_relative(&source.path)?;
    }
    for operation in &plan.operations {
        match operation {
            MigrationOperation::CreateFolder { path } => ensure_safe_relative(path)?,
            MigrationOperation::CopyFile {
                source_path,
                destination_path,
                expected_sha256,
            } => {
                ensure_safe_relative(source_path)?;
                ensure_safe_relative(destination_path)?;
                if !plan
                    .source_inventory
                    .files
                    .iter()
                    .any(|source| source.path == *source_path && source.sha256 == *expected_sha256)
                {
                    return Err(invalid_journal(
                        plan_path,
                        "copy operation is not bound to the source inventory",
                    ));
                }
            }
            operation if operation.is_structural() => {
                let source_path = operation
                    .structural_source_path()
                    .expect("structural operation has a source");
                ensure_safe_relative(source_path)?;
                refuse_nested_folderbase_path(root, source_path)?;
                let expected = operation
                    .structural_expected_sha256()
                    .filter(|digest| is_sha256(digest))
                    .ok_or_else(|| {
                        invalid_journal(plan_path, "structural source digest is invalid")
                    })?;
                if !plan
                    .source_inventory
                    .files
                    .iter()
                    .any(|source| source.path == source_path && source.sha256 == expected)
                {
                    return Err(invalid_journal(
                        plan_path,
                        "structural operation is not bound to the source inventory",
                    ));
                }
                if let Some(destination) = operation.structural_destination_path() {
                    ensure_safe_relative(destination)?;
                    refuse_nested_folderbase_path(root, destination)?;
                } else if !operation
                    .structural_expected_result_sha256()
                    .is_some_and(is_sha256)
                {
                    return Err(invalid_journal(
                        plan_path,
                        "structural result digest is invalid",
                    ));
                }
                match operation.structural_snapshot() {
                    Some((snapshot_path, snapshot_sha256)) => {
                        ensure_safe_relative(snapshot_path)?;
                        if !is_sha256(snapshot_sha256) || snapshot_sha256 != expected {
                            return Err(invalid_journal(
                                plan_path,
                                "structural snapshot metadata is invalid",
                            ));
                        }
                    }
                    None if plan.state != MigrationState::Proposed => {
                        return Err(invalid_journal(
                            plan_path,
                            "approved structural operation requires a verified snapshot",
                        ));
                    }
                    None => {}
                }
            }
            _ => {
                return Err(invalid_journal(
                    plan_path,
                    "migration operation kind is invalid",
                ));
            }
        }
    }
    Ok(())
}

fn validate_grouped_assignments_extension(plan_path: &Path, plan: &MigrationPlan) -> Result<()> {
    let grouped_answers = plan
        .answers
        .iter()
        .filter(|answer| answer.question_id.starts_with("question_assignment_group_"))
        .collect::<Vec<_>>();
    if plan.answers.iter().any(|answer| {
        !answer.question_id.starts_with("question_assignment_group_")
            && !answer.exceptions.is_empty()
    }) {
        return Err(invalid_journal(
            plan_path,
            "only grouped migration answers may contain exceptions",
        ));
    }
    let Some(value) = plan.extensions.get(GROUPED_ASSIGNMENTS_EXTENSION) else {
        if grouped_answers.is_empty() {
            if plan
                .answers
                .iter()
                .any(|answer| !answer.exceptions.is_empty())
            {
                return Err(invalid_journal(
                    plan_path,
                    "only grouped migration answers may contain exceptions",
                ));
            }
            return Ok(());
        }
        return Err(invalid_journal(
            plan_path,
            "grouped migration answers require their normalized contract extension",
        ));
    };
    if grouped_answers.is_empty() {
        return Err(invalid_journal(
            plan_path,
            "grouped migration contract has no corresponding answers",
        ));
    }
    let contract: GroupedAssignmentsExtension = serde_json::from_value(value.clone())
        .map_err(|_| invalid_journal(plan_path, "grouped migration contract is invalid"))?;
    if contract.version != "1" || contract.groups.len() != grouped_answers.len() {
        return Err(invalid_journal(
            plan_path,
            "grouped migration contract version or coverage is invalid",
        ));
    }

    let one_folderbase = plan.answers.iter().any(|answer| {
        answer.question_id == "question_canonical_scope" && answer.answer == "one_folderbase"
    });
    let exclude_generated = plan.answers.iter().any(|answer| {
        answer.question_id == "question_generated_content" && answer.answer == "exclude_generated"
    });
    let mut question_ids = BTreeSet::new();
    let mut member_keys = BTreeSet::new();
    let source_topology_value =
        plan.extensions
            .get(SOURCE_TOPOLOGY_EXTENSION)
            .ok_or_else(|| {
                invalid_journal(
                    plan_path,
                    "grouped migration contract requires a source-topology snapshot",
                )
            })?;
    let source_topology: SourceTopologySnapshot =
        serde_json::from_value(source_topology_value.clone())
            .map_err(|_| invalid_journal(plan_path, "source-topology snapshot is invalid"))?;
    if source_topology.version != "1" {
        return Err(invalid_journal(
            plan_path,
            "source-topology snapshot version is unsupported",
        ));
    }
    let expected_members = source_topology
        .files
        .into_iter()
        .map(|path| (path, AssignmentSourceKind::File))
        .chain(
            source_topology
                .reconstructable_trees
                .into_iter()
                .map(|path| (path, AssignmentSourceKind::ReconstructableTree)),
        )
        .collect::<BTreeMap<_, _>>();
    let mut contract_members = BTreeMap::new();
    for group in &contract.groups {
        if group.rule_version != ASSIGNMENT_GROUP_RULE_VERSION
            || group.members.is_empty()
            || !question_ids.insert(group.question_id.as_str())
        {
            return Err(invalid_journal(
                plan_path,
                "grouped migration contract contains an unsupported or duplicate group",
            ));
        }
        if group.source_root != Path::new(".") {
            ensure_safe_relative(&group.source_root)?;
        }
        let mut members = Vec::with_capacity(group.members.len());
        let mut previous_path: Option<&Path> = None;
        for member in &group.members {
            ensure_safe_relative(&member.source_path)?;
            if previous_path.is_some_and(|previous| previous >= member.source_path.as_path())
                || assignment_source_root(&member.source_path, member.source_kind)
                    != group.source_root
                || !member_keys.insert(portable_path_key(&member.source_path))
            {
                return Err(invalid_journal(
                    plan_path,
                    "grouped migration members must be sorted, exact, and portable-case unique",
                ));
            }
            previous_path = Some(&member.source_path);
            if contract_members
                .insert(member.source_path.clone(), member.source_kind)
                .is_some()
            {
                return Err(invalid_journal(
                    plan_path,
                    "grouped migration member appears more than once",
                ));
            }
            members.push(AssignmentGroupMember {
                path: member.source_path.clone(),
                kind: member.source_kind,
            });
        }
        let digest =
            assignment_group_coverage_digest(&group.source_root, group.content_kind, &members);
        if group.coverage_digest != digest
            || group.question_id != format!("question_assignment_group_{digest}")
        {
            return Err(invalid_journal(
                plan_path,
                "grouped migration coverage digest is invalid",
            ));
        }
        let answer = grouped_answers
            .iter()
            .find(|answer| answer.question_id == group.question_id)
            .ok_or_else(|| {
                invalid_journal(
                    plan_path,
                    "grouped migration contract does not match its answer",
                )
            })?;
        let mut normalized_exceptions = answer.exceptions.clone();
        normalized_exceptions.sort_by(|left, right| {
            portable_path_key(&left.source_path).cmp(&portable_path_key(&right.source_path))
        });
        if answer.answer != group.default_target_id || normalized_exceptions != group.exceptions {
            return Err(invalid_journal(
                plan_path,
                "grouped migration defaults or exceptions are inconsistent",
            ));
        }
        validate_group_target(
            plan_path,
            plan,
            group.content_kind,
            &group.default_target_id,
            one_folderbase,
            exclude_generated,
        )?;
        let member_paths = group
            .members
            .iter()
            .map(|member| member.source_path.as_path())
            .collect::<BTreeSet<_>>();
        let mut exception_keys = BTreeSet::new();
        for exception in &group.exceptions {
            ensure_safe_relative(&exception.source_path)?;
            if !member_paths.contains(exception.source_path.as_path())
                || !exception_keys.insert(portable_path_key(&exception.source_path))
            {
                return Err(invalid_journal(
                    plan_path,
                    "grouped migration exception is duplicate or not an exact member",
                ));
            }
            validate_group_target(
                plan_path,
                plan,
                group.content_kind,
                &exception.target_id,
                one_folderbase,
                exclude_generated,
            )?;
        }
    }
    if question_ids
        != grouped_answers
            .iter()
            .map(|answer| answer.question_id.as_str())
            .collect()
    {
        return Err(invalid_journal(
            plan_path,
            "grouped migration answers and contract records must correspond exactly once",
        ));
    }
    if contract_members != expected_members {
        return Err(invalid_journal(
            plan_path,
            "grouped migration members do not match the approved source topology",
        ));
    }
    Ok(())
}

fn validate_group_target(
    plan_path: &Path,
    plan: &MigrationPlan,
    content_kind: MigrationContentKind,
    target_id: &str,
    one_folderbase: bool,
    exclude_generated: bool,
) -> Result<()> {
    let target = plan
        .targets
        .iter()
        .find(|target| target.id == target_id)
        .ok_or_else(|| invalid_journal(plan_path, "grouped migration target is unknown"))?;
    let allowed = match content_kind {
        MigrationContentKind::Canonical => matches!(
            target.kind,
            MigrationTargetKind::Folderbase | MigrationTargetKind::RetainedFolder
        ),
        MigrationContentKind::Generated | MigrationContentKind::Temporary => matches!(
            target.kind,
            MigrationTargetKind::Folderbase
                | MigrationTargetKind::RetainedFolder
                | MigrationTargetKind::Exclusion
        ),
        MigrationContentKind::SecretShaped => target.kind == MigrationTargetKind::RetainedFolder,
    };
    if !allowed
        || (one_folderbase
            && target.kind == MigrationTargetKind::Folderbase
            && target.id != "target_primary_folderbase")
        || (content_kind == MigrationContentKind::Generated
            && exclude_generated
            && target.kind == MigrationTargetKind::Folderbase)
    {
        return Err(invalid_journal(
            plan_path,
            "grouped migration target is not allowed for this content",
        ));
    }
    Ok(())
}

fn validate_expanded_reconstructable_trees_extension(
    plan_path: &Path,
    plan: &MigrationPlan,
) -> Result<()> {
    let Some(source_topology_value) = plan.extensions.get(SOURCE_TOPOLOGY_EXTENSION) else {
        if plan
            .extensions
            .contains_key(EXPANDED_RECONSTRUCTABLE_TREES_EXTENSION)
        {
            return Err(invalid_journal(
                plan_path,
                "expanded reconstructable trees require a source-topology snapshot",
            ));
        }
        return Ok(());
    };
    let source_topology: SourceTopologySnapshot =
        serde_json::from_value(source_topology_value.clone())
            .map_err(|_| invalid_journal(plan_path, "source-topology snapshot is invalid"))?;
    let required_roots =
        required_expanded_reconstructable_roots(plan_path, plan, &source_topology)?;
    let Some(value) = plan
        .extensions
        .get(EXPANDED_RECONSTRUCTABLE_TREES_EXTENSION)
    else {
        if required_roots.is_empty() {
            return Ok(());
        }
        return Err(invalid_journal(
            plan_path,
            "included reconstructable trees require exact expanded membership",
        ));
    };
    let contract: ExpandedReconstructableTreesExtension = serde_json::from_value(value.clone())
        .map_err(|_| {
            invalid_journal(
                plan_path,
                "expanded reconstructable-tree contract is invalid",
            )
        })?;
    if contract.version != "1" || contract.trees.is_empty() {
        return Err(invalid_journal(
            plan_path,
            "expanded reconstructable-tree contract version or coverage is invalid",
        ));
    }
    let reconstructable_roots = source_topology
        .reconstructable_trees
        .iter()
        .map(|path| portable_path_key(path))
        .collect::<BTreeSet<_>>();
    let mut tree_root_keys = BTreeSet::new();
    let mut tree_roots = BTreeSet::new();
    for tree in contract.trees {
        ensure_safe_relative(&tree.source_root)?;
        if !tree_root_keys.insert(portable_path_key(&tree.source_root))
            || !tree_roots.insert(tree.source_root.clone())
            || !reconstructable_roots.contains(&portable_path_key(&tree.source_root))
            || tree.source_paths.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(invalid_journal(
                plan_path,
                "expanded reconstructable-tree members must be sorted with unique source roots",
            ));
        }
        let mut source_path_keys = BTreeSet::new();
        for source_path in tree.source_paths {
            ensure_safe_relative(&source_path)?;
            if !source_path.starts_with(&tree.source_root)
                || !source_path_keys.insert(portable_path_key(&source_path))
                || !plan
                    .source_inventory
                    .files
                    .iter()
                    .any(|source| source.path == source_path)
            {
                return Err(invalid_journal(
                    plan_path,
                    "expanded reconstructable-tree member is not source-inventory bound",
                ));
            }
        }
    }
    if tree_roots != required_roots {
        return Err(invalid_journal(
            plan_path,
            "expanded reconstructable-tree coverage does not match included tree assignments",
        ));
    }
    Ok(())
}

fn required_expanded_reconstructable_roots(
    plan_path: &Path,
    plan: &MigrationPlan,
    source_topology: &SourceTopologySnapshot,
) -> Result<BTreeSet<PathBuf>> {
    let target_is_folderbase = |target_id: &str| {
        plan.targets
            .iter()
            .find(|target| target.id == target_id)
            .map(|target| target.kind == MigrationTargetKind::Folderbase)
            .ok_or_else(|| invalid_journal(plan_path, "migration assignment target is unknown"))
    };
    let mut required = BTreeSet::new();
    if let Some(value) = plan.extensions.get(GROUPED_ASSIGNMENTS_EXTENSION) {
        let grouped: GroupedAssignmentsExtension = serde_json::from_value(value.clone())
            .map_err(|_| invalid_journal(plan_path, "grouped migration contract is invalid"))?;
        for group in grouped.groups {
            for member in group
                .members
                .iter()
                .filter(|member| member.source_kind == AssignmentSourceKind::ReconstructableTree)
            {
                let target_id = group
                    .exceptions
                    .iter()
                    .find(|exception| exception.source_path == member.source_path)
                    .map(|exception| exception.target_id.as_str())
                    .unwrap_or(&group.default_target_id);
                if target_is_folderbase(target_id)? {
                    required.insert(member.source_path.clone());
                }
            }
        }
        return Ok(required);
    }

    for source_root in &source_topology.reconstructable_trees {
        let question_id = stable_path_id("question_assignment", source_root);
        let answer = plan
            .answers
            .iter()
            .find(|answer| answer.question_id == question_id)
            .ok_or_else(|| {
                invalid_journal(
                    plan_path,
                    "reconstructable tree is missing its exact assignment answer",
                )
            })?;
        if target_is_folderbase(&answer.answer)? {
            required.insert(source_root.clone());
        }
    }
    Ok(required)
}

fn canonical_root(path: &Path) -> Result<PathBuf> {
    if !path.is_dir() {
        return Err(FolderbaseError::InvalidRoot(path.to_path_buf()));
    }
    path.canonicalize()
        .map_err(|source| FolderbaseError::io(path, source))
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

fn safe_join(root: &Path, relative: &Path) -> Result<PathBuf> {
    ensure_safe_relative(relative)?;
    let destination = root.join(relative);
    let mut current = root.to_path_buf();
    if let Some(parent) = relative.parent() {
        for component in parent.components() {
            let Component::Normal(component) = component else {
                return Err(FolderbaseError::UnsafePath(relative.to_path_buf()));
            };
            current.push(component);
            if let Ok(metadata) = fs::symlink_metadata(&current)
                && metadata.file_type().is_symlink()
            {
                return Err(FolderbaseError::UnsafePath(current));
            }
        }
    }
    Ok(destination)
}

fn refuse_nested_folderbase_path(root: &Path, relative: &Path) -> Result<()> {
    ensure_safe_relative(relative)?;
    let mut prefix = PathBuf::new();
    for component in relative.parent().into_iter().flat_map(Path::components) {
        let Component::Normal(component) = component else {
            return Err(FolderbaseError::UnsafePath(relative.to_path_buf()));
        };
        prefix.push(component);
        let directory = safe_join(root, &prefix)?;
        match fs::symlink_metadata(&directory) {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
                if migration_nested_folderbase_marker(&directory, &prefix)? {
                    return Err(FolderbaseError::UnsafePath(prefix));
                }
            }
            Ok(_) => return Err(FolderbaseError::UnsafePath(prefix)),
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => return Err(FolderbaseError::io(directory, source)),
        }
    }
    Ok(())
}

fn migration_nested_folderbase_marker(directory: &Path, prefix: &Path) -> Result<bool> {
    has_nested_folderbase_marker(directory).map_err(|error| match error {
        FolderbaseError::UnsafePath(_) => FolderbaseError::UnsafePath(prefix.to_path_buf()),
        error => error,
    })
}

fn humanize_name(name: &str) -> String {
    name.replace(['-', '_'], " ")
        .split_whitespace()
        .map(|word| {
            let mut chars = word.chars();
            chars
                .next()
                .map(|first| first.to_uppercase().collect::<String>() + chars.as_str())
                .unwrap_or_default()
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn stable_path_id(prefix: &str, path: &Path) -> String {
    let digest = Sha256::digest(path.to_string_lossy().as_bytes());
    format!("{prefix}_{digest:x}")
}

fn portable_path_key(path: &Path) -> PathBuf {
    path.components()
        .map(|component| match component {
            Component::Normal(name) => name
                .to_string_lossy()
                .case_fold()
                .collect::<String>()
                .into(),
            _ => component.as_os_str().to_owned(),
        })
        .collect()
}

fn target_kind_for_boundary(path: &Path) -> MigrationTargetKind {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase()
        .replace(['_', ' '], "-");
    if name.contains("workspace") {
        MigrationTargetKind::Workspace
    } else if name.contains("shared")
        && (name.contains("client")
            || name.contains("customer")
            || name.contains("external")
            || name == "shared")
    {
        MigrationTargetKind::ScopedView
    } else {
        MigrationTargetKind::Folderbase
    }
}

fn assignment_questions(
    files: &[AnalyzedFile],
    reconstructable_trees: &[ReconstructableTree],
    targets: &[MigrationTarget],
) -> Vec<MigrationQuestion> {
    let mut assignments = files
        .iter()
        .map(|file| {
            let content_kind = if file.is_secret_shaped() {
                MigrationContentKind::SecretShaped
            } else if file.is_temporary() {
                MigrationContentKind::Temporary
            } else if file.is_generated() {
                MigrationContentKind::Generated
            } else {
                MigrationContentKind::Canonical
            };
            (file.path.clone(), content_kind, AssignmentSourceKind::File)
        })
        .chain(reconstructable_trees.iter().map(|tree| {
            (
                tree.path.clone(),
                MigrationContentKind::Generated,
                AssignmentSourceKind::ReconstructableTree,
            )
        }))
        .collect::<Vec<_>>();
    if assignments.len() <= GROUPED_ASSIGNMENT_THRESHOLD {
        return assignments
            .into_iter()
            .map(|(path, content_kind, _)| assignment_question(&path, content_kind, targets))
            .collect();
    }

    let mut groups = BTreeMap::<(PathBuf, MigrationContentKind), Vec<AssignmentGroupMember>>::new();
    for (path, content_kind, source_kind) in assignments.drain(..) {
        let source_root = assignment_source_root(&path, source_kind);
        groups
            .entry((source_root, content_kind))
            .or_default()
            .push(AssignmentGroupMember {
                path,
                kind: source_kind,
            });
    }

    groups
        .into_iter()
        .map(|((source_root, content_kind), mut members)| {
            members.sort_by(|left, right| left.path.cmp(&right.path));
            assignment_group_question(&source_root, members, content_kind, targets)
        })
        .collect()
}

fn assignment_source_root(path: &Path, source_kind: AssignmentSourceKind) -> PathBuf {
    if source_kind == AssignmentSourceKind::ReconstructableTree
        || path
            .parent()
            .is_some_and(|parent| !parent.as_os_str().is_empty())
    {
        path.components()
            .next()
            .map(|component| PathBuf::from(component.as_os_str()))
            .unwrap_or_else(|| PathBuf::from("."))
    } else {
        PathBuf::from(".")
    }
}

fn assignment_group_question(
    source_root: &Path,
    members: Vec<AssignmentGroupMember>,
    content_kind: MigrationContentKind,
    targets: &[MigrationTarget],
) -> MigrationQuestion {
    let coverage_digest = assignment_group_coverage_digest(source_root, content_kind, &members);
    let source_paths = members
        .into_iter()
        .map(|member| member.path)
        .collect::<Vec<_>>();
    let mut question = assignment_question(&source_paths[0], content_kind, targets);
    question.id = format!("question_assignment_group_{coverage_digest}");
    question.prompt = format!(
        "Choose an explicit destination for {} grouped items under `{}`.",
        source_paths.len(),
        source_root.display()
    );
    question.context = "The group is metadata-derived and lists every covered source path explicitly. Workspace and scoped-view targets remain navigation only."
        .to_owned();
    question.kind = MigrationQuestionKind::AssignmentGroup {
        rule_version: ASSIGNMENT_GROUP_RULE_VERSION.to_owned(),
        source_root: source_root.to_path_buf(),
        source_paths,
        content_kind,
        coverage_digest,
    };
    question
}

fn assignment_group_coverage_digest(
    source_root: &Path,
    content_kind: MigrationContentKind,
    members: &[AssignmentGroupMember],
) -> String {
    fn update_field(hasher: &mut Sha256, value: &[u8]) {
        hasher.update((value.len() as u64).to_le_bytes());
        hasher.update(value);
    }

    let mut hasher = Sha256::new();
    update_field(&mut hasher, ASSIGNMENT_GROUP_RULE_VERSION.as_bytes());
    update_field(&mut hasher, source_root.as_os_str().as_encoded_bytes());
    update_field(
        &mut hasher,
        match content_kind {
            MigrationContentKind::Canonical => b"canonical",
            MigrationContentKind::Generated => b"generated",
            MigrationContentKind::SecretShaped => b"secret_shaped",
            MigrationContentKind::Temporary => b"temporary",
        },
    );
    for member in members {
        update_field(
            &mut hasher,
            match member.kind {
                AssignmentSourceKind::File => b"file",
                AssignmentSourceKind::ReconstructableTree => b"reconstructable_tree",
            },
        );
        update_field(&mut hasher, member.path.as_os_str().as_encoded_bytes());
    }
    format!("{:x}", hasher.finalize())
}

fn assignment_question(
    source_path: &Path,
    content_kind: MigrationContentKind,
    targets: &[MigrationTarget],
) -> MigrationQuestion {
    let accepted_kinds: &[MigrationTargetKind] = match content_kind {
        MigrationContentKind::Canonical => &[
            MigrationTargetKind::Folderbase,
            MigrationTargetKind::RetainedFolder,
        ],
        MigrationContentKind::Generated | MigrationContentKind::Temporary => &[
            MigrationTargetKind::Folderbase,
            MigrationTargetKind::RetainedFolder,
            MigrationTargetKind::Exclusion,
        ],
        MigrationContentKind::SecretShaped => &[MigrationTargetKind::RetainedFolder],
    };
    let options = targets
        .iter()
        .filter(|target| accepted_kinds.contains(&target.kind))
        .map(|target| MigrationOption {
            id: target.id.clone(),
            label: target.suggested_name.clone(),
            consequence: match target.kind {
                MigrationTargetKind::Folderbase => {
                    "Copy this content into the selected folderbase's permission boundary."
                        .to_owned()
                }
                MigrationTargetKind::RetainedFolder => {
                    "Leave this content in the source folder and do not copy it.".to_owned()
                }
                MigrationTargetKind::Exclusion => {
                    "Record an explicit exclusion and leave the source unchanged.".to_owned()
                }
                MigrationTargetKind::Workspace | MigrationTargetKind::ScopedView => {
                    unreachable!("navigation targets cannot own canonical content")
                }
            },
        })
        .collect();
    let recommended_option_id = match content_kind {
        MigrationContentKind::Canonical => "target_primary_folderbase",
        MigrationContentKind::SecretShaped => "target_retained_source",
        MigrationContentKind::Generated | MigrationContentKind::Temporary => "target_exclusion",
    }
    .to_owned();

    MigrationQuestion {
        id: stable_path_id("question_assignment", source_path),
        prompt: format!(
            "Choose an explicit destination for `{}`.",
            source_path.display()
        ),
        context: "Workspace and scoped-view targets are navigation only and cannot own canonical content."
            .to_owned(),
        kind: MigrationQuestionKind::Assignment {
            source_path: source_path.to_path_buf(),
            content_kind,
        },
        options,
        recommended_option_id,
    }
}

fn safe_boundary_name(name: &str) -> String {
    let normalized = name
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_') {
                character
            } else {
                '-'
            }
        })
        .collect::<String>();
    let normalized = normalized.trim_matches('-');
    if normalized.is_empty() {
        "Boundary".to_owned()
    } else {
        normalized.to_owned()
    }
}

fn validate_answers(
    analysis: &MigrationAnalysis,
    answers: &[MigrationAnswer],
) -> Result<ParsedMigrationAnswers> {
    let expected_assignment_questions = assignment_questions(
        &analysis.files,
        &analysis.reconstructable_trees,
        &analysis.proposed_targets,
    );
    let actual_assignment_questions = analysis
        .questions
        .iter()
        .filter(|question| !matches!(question.kind, MigrationQuestionKind::Decision))
        .cloned()
        .collect::<Vec<_>>();
    if actual_assignment_questions != expected_assignment_questions {
        return Err(FolderbaseError::InvalidRecord {
            path: analysis.root.clone(),
            message: "migration assignment questions do not match the canonical analyzer output"
                .to_owned(),
        });
    }
    let known: BTreeSet<&str> = analysis
        .questions
        .iter()
        .map(|question| question.id.as_str())
        .collect();
    let supplied: BTreeSet<&str> = answers
        .iter()
        .filter(|answer| !answer.answer.trim().is_empty())
        .map(|answer| answer.question_id.as_str())
        .collect();
    if known != supplied || answers.len() != known.len() {
        return Err(FolderbaseError::InvalidRecord {
            path: analysis.root.clone(),
            message: "every migration question must have exactly one non-empty answer".to_owned(),
        });
    }
    for answer in answers {
        let question = analysis
            .questions
            .iter()
            .find(|question| question.id == answer.question_id)
            .ok_or_else(|| FolderbaseError::InvalidRecord {
                path: analysis.root.clone(),
                message: format!("unknown migration question: {}", answer.question_id),
            })?;
        if !question
            .options
            .iter()
            .any(|option| option.id == answer.answer)
        {
            return Err(FolderbaseError::InvalidRecord {
                path: analysis.root.clone(),
                message: format!(
                    "{} must use one of the question's accepted option IDs",
                    answer.question_id
                ),
            });
        }
    }

    let answer = |question_id: &str| {
        answers
            .iter()
            .find(|answer| answer.question_id == question_id)
            .map(|answer| answer.answer.as_str())
            .ok_or_else(|| FolderbaseError::InvalidRecord {
                path: analysis.root.clone(),
                message: format!("missing migration answer for {question_id}"),
            })
    };
    let canonical_scope = match answer("question_canonical_scope")? {
        "one_folderbase" => CanonicalScopeAnswer::OneFolderbase,
        "proposed_boundaries" => CanonicalScopeAnswer::ProposedBoundaries,
        _ => {
            return Err(FolderbaseError::InvalidRecord {
                path: analysis.root.clone(),
                message:
                    "question_canonical_scope must be `one_folderbase` or `proposed_boundaries`"
                        .to_owned(),
            });
        }
    };
    let generated_content = match answer("question_generated_content")? {
        "exclude_generated" => GeneratedContentAnswer::Exclude,
        "include_generated" => GeneratedContentAnswer::Include,
        _ => {
            return Err(FolderbaseError::InvalidRecord {
                path: analysis.root.clone(),
                message:
                    "question_generated_content must be `exclude_generated` or `include_generated`"
                        .to_owned(),
            });
        }
    };
    if known.contains("question_secrets") && !matches!(answer("question_secrets")?, "local_only") {
        return Err(FolderbaseError::InvalidRecord {
            path: analysis.root.clone(),
            message: "question_secrets must be `local_only`".to_owned(),
        });
    }
    let mut assignments = BTreeMap::new();
    let reconstructable_paths = analysis
        .reconstructable_trees
        .iter()
        .map(|tree| tree.path.as_path())
        .collect::<BTreeSet<_>>();
    let mut grouped_assignments = Vec::new();
    for question in &analysis.questions {
        let answered = answers
            .iter()
            .find(|answered| answered.question_id == question.id)
            .ok_or_else(|| FolderbaseError::InvalidRecord {
                path: analysis.root.clone(),
                message: format!("missing migration answer for {}", question.id),
            })?;
        let (source_paths, content_kind, is_group) = match &question.kind {
            MigrationQuestionKind::Assignment {
                source_path,
                content_kind,
            } => (std::slice::from_ref(source_path), *content_kind, false),
            MigrationQuestionKind::AssignmentGroup {
                rule_version,
                source_root,
                source_paths,
                content_kind,
                coverage_digest,
            } => {
                if rule_version != ASSIGNMENT_GROUP_RULE_VERSION
                    || source_paths.windows(2).any(|pair| pair[0] >= pair[1])
                {
                    return Err(FolderbaseError::InvalidRecord {
                        path: analysis.root.clone(),
                        message: format!(
                            "{} uses an unsupported or non-deterministic assignment group",
                            question.id
                        ),
                    });
                }
                let members = source_paths
                    .iter()
                    .map(|source_path| AssignmentGroupMember {
                        path: source_path.clone(),
                        kind: if reconstructable_paths.contains(source_path.as_path()) {
                            AssignmentSourceKind::ReconstructableTree
                        } else {
                            AssignmentSourceKind::File
                        },
                    })
                    .collect::<Vec<_>>();
                if assignment_group_coverage_digest(source_root, *content_kind, &members)
                    != *coverage_digest
                {
                    return Err(FolderbaseError::InvalidRecord {
                        path: analysis.root.clone(),
                        message: format!("{} has stale assignment group coverage", question.id),
                    });
                }
                let mut normalized_exceptions = answered.exceptions.clone();
                normalized_exceptions.sort_by(|left, right| {
                    portable_path_key(&left.source_path).cmp(&portable_path_key(&right.source_path))
                });
                grouped_assignments.push(GroupedAssignmentContract {
                    question_id: question.id.clone(),
                    rule_version: rule_version.clone(),
                    source_root: source_root.clone(),
                    members: members
                        .iter()
                        .map(|member| GroupedAssignmentMemberContract {
                            source_path: member.path.clone(),
                            source_kind: member.kind,
                        })
                        .collect(),
                    content_kind: *content_kind,
                    coverage_digest: coverage_digest.clone(),
                    default_target_id: answered.answer.clone(),
                    exceptions: normalized_exceptions,
                });
                (source_paths.as_slice(), *content_kind, true)
            }
            MigrationQuestionKind::Decision => continue,
        };
        if !is_group && !answered.exceptions.is_empty() {
            return Err(FolderbaseError::InvalidRecord {
                path: analysis.root.clone(),
                message: format!("{} does not accept grouped exceptions", question.id),
            });
        }
        for source_path in source_paths {
            if assignments.contains_key(source_path) {
                return Err(FolderbaseError::InvalidRecord {
                    path: analysis.root.clone(),
                    message: format!(
                        "migration assignment scopes must be unique: {}",
                        source_path.display()
                    ),
                });
            }
            assignments.insert(
                source_path.clone(),
                ParsedAssignment {
                    content_kind,
                    target_id: answer(&question.id)?.to_owned(),
                },
            );
        }
        let mut exception_paths = BTreeSet::new();
        for exception in &answered.exceptions {
            ensure_safe_relative(&exception.source_path)?;
            if !exception_paths.insert(portable_path_key(&exception.source_path)) {
                return Err(FolderbaseError::InvalidRecord {
                    path: analysis.root.clone(),
                    message: format!(
                        "{} contains a duplicate exception for {}",
                        question.id,
                        exception.source_path.display()
                    ),
                });
            }
            if !source_paths.contains(&exception.source_path) {
                return Err(FolderbaseError::InvalidRecord {
                    path: analysis.root.clone(),
                    message: format!(
                        "{} contains a nonmember exception for {}",
                        question.id,
                        exception.source_path.display()
                    ),
                });
            }
            if !question
                .options
                .iter()
                .any(|option| option.id == exception.target_id)
            {
                return Err(FolderbaseError::InvalidRecord {
                    path: analysis.root.clone(),
                    message: format!(
                        "{} exception must use one of the question's accepted option IDs",
                        question.id
                    ),
                });
            }
            assignments.insert(
                exception.source_path.clone(),
                ParsedAssignment {
                    content_kind,
                    target_id: exception.target_id.clone(),
                },
            );
        }
    }
    let expected_scopes = analysis
        .files
        .iter()
        .map(|file| file.path.as_path())
        .chain(
            analysis
                .reconstructable_trees
                .iter()
                .map(|tree| tree.path.as_path()),
        )
        .collect::<BTreeSet<_>>();
    let assigned_scopes = assignments
        .keys()
        .map(PathBuf::as_path)
        .collect::<BTreeSet<_>>();
    if assigned_scopes != expected_scopes {
        return Err(FolderbaseError::InvalidRecord {
            path: analysis.root.clone(),
            message: "migration assignments must cover every analyzed source scope exactly once"
                .to_owned(),
        });
    }
    for assignment in assignments.values() {
        let target = analysis
            .proposed_targets
            .iter()
            .find(|target| target.id == assignment.target_id)
            .ok_or_else(|| FolderbaseError::InvalidRecord {
                path: analysis.root.clone(),
                message: format!("unknown migration target: {}", assignment.target_id),
            })?;
        if matches!(
            target.kind,
            MigrationTargetKind::Workspace | MigrationTargetKind::ScopedView
        ) {
            return Err(FolderbaseError::InvalidRecord {
                path: analysis.root.clone(),
                message: format!("navigation target cannot own content: {}", target.id),
            });
        }
        if canonical_scope == CanonicalScopeAnswer::OneFolderbase
            && target.kind == MigrationTargetKind::Folderbase
            && target.id != "target_primary_folderbase"
        {
            return Err(FolderbaseError::InvalidRecord {
                path: analysis.root.clone(),
                message: "one_folderbase assignments must use target_primary_folderbase".to_owned(),
            });
        }
        if assignment.content_kind == MigrationContentKind::Generated
            && generated_content == GeneratedContentAnswer::Exclude
            && target.kind == MigrationTargetKind::Folderbase
        {
            return Err(FolderbaseError::InvalidRecord {
                path: analysis.root.clone(),
                message: "exclude_generated cannot assign generated content to a folderbase target"
                    .to_owned(),
            });
        }
        if assignment.content_kind == MigrationContentKind::SecretShaped
            && target.kind != MigrationTargetKind::RetainedFolder
        {
            return Err(FolderbaseError::InvalidRecord {
                path: analysis.root.clone(),
                message: "secret-shaped content requires an explicit retained-local target"
                    .to_owned(),
            });
        }
    }
    Ok(ParsedMigrationAnswers {
        canonical_scope,
        generated_content,
        assignments,
        grouped_assignments,
    })
}

fn inventory_digest(files: &[SourceFile]) -> String {
    let mut hasher = Sha256::new();
    for file in files {
        hasher.update(file.path.to_string_lossy().as_bytes());
        hasher.update([0]);
        hasher.update(file.bytes.to_le_bytes());
        hasher.update([0]);
        hasher.update(file.sha256.as_bytes());
        hasher.update([b'\n']);
    }
    format!("{:x}", hasher.finalize())
}

fn metadata_inventory_digest(
    files: &[AnalyzedFile],
    reconstructable_trees: &[ReconstructableTree],
    nested_folderbases: &[NestedFolderbaseBoundary],
) -> String {
    let mut hasher = Sha256::new();
    for file in files {
        hasher.update(file.path.to_string_lossy().as_bytes());
        hasher.update([0]);
        hasher.update(file.bytes.to_le_bytes());
        hasher.update([0]);
        hasher.update([file.classification_bits()]);
        hasher.update([b'\n']);
    }
    for tree in reconstructable_trees {
        hasher.update(b"reconstructable:");
        hasher.update(tree.path.to_string_lossy().as_bytes());
        hasher.update([b'\n']);
    }
    for boundary in nested_folderbases {
        hasher.update(b"nested:");
        hasher.update(boundary.path.to_string_lossy().as_bytes());
        hasher.update([boundary.state as u8, b'\n']);
    }
    format!("{:x}", hasher.finalize())
}

fn additive_destination_roots(operations: &[MigrationOperation]) -> Vec<PathBuf> {
    let mut roots = operations
        .iter()
        .filter_map(|operation| match operation {
            MigrationOperation::CreateFolder { path } => Some(path.clone()),
            _ => None,
        })
        .collect::<Vec<_>>();
    roots.sort();
    roots.dedup();
    roots
        .iter()
        .filter(|candidate| {
            !roots
                .iter()
                .any(|other| candidate != &other && candidate.starts_with(other))
        })
        .cloned()
        .collect()
}

fn source_topology_snapshot(
    files: &[AnalyzedFile],
    reconstructable_trees: &[ReconstructableTree],
    nested_folderbases: &[NestedFolderbaseBoundary],
    destination_roots: &[PathBuf],
) -> SourceTopologySnapshot {
    let is_destination = |path: &Path| {
        destination_roots
            .iter()
            .any(|destination| path == destination || path.starts_with(destination))
    };
    SourceTopologySnapshot {
        version: "1".to_owned(),
        files: files
            .iter()
            .filter(|file| !is_destination(&file.path))
            .map(|file| file.path.clone())
            .collect(),
        reconstructable_trees: reconstructable_trees
            .iter()
            .filter(|tree| !is_destination(&tree.path))
            .map(|tree| tree.path.clone())
            .collect(),
        nested_folderbases: nested_folderbases
            .iter()
            .filter(|boundary| !is_destination(&boundary.path))
            .cloned()
            .collect(),
    }
}

fn verify_additive_source_topology(plan: &MigrationPlan) -> Result<()> {
    let expected_value = plan
        .extensions
        .get(SOURCE_TOPOLOGY_EXTENSION)
        .ok_or_else(|| FolderbaseError::MigrationSourceChanged(plan.root.clone()))?;
    let expected: SourceTopologySnapshot = serde_json::from_value(expected_value.clone())
        .map_err(|_| FolderbaseError::MigrationSourceChanged(plan.root.clone()))?;
    if expected.version != "1" {
        return Err(FolderbaseError::MigrationSourceChanged(plan.root.clone()));
    }
    let current_analysis = analyze_folder(&plan.root)?;
    let current = source_topology_snapshot(
        &current_analysis.files,
        &current_analysis.reconstructable_trees,
        &current_analysis.nested_folderbases,
        &additive_destination_roots(&plan.operations),
    );
    if current == expected {
        return Ok(());
    }

    let expected_files = expected.files.iter().collect::<BTreeSet<_>>();
    let current_files = current.files.iter().collect::<BTreeSet<_>>();
    if let Some(path) = current_files.difference(&expected_files).next() {
        return Err(FolderbaseError::MigrationSourceChanged((*path).clone()));
    }
    if let Some(path) = expected_files.difference(&current_files).next() {
        return Err(FolderbaseError::MigrationSourceChanged((*path).clone()));
    }
    let expected_trees = expected
        .reconstructable_trees
        .iter()
        .collect::<BTreeSet<_>>();
    let current_trees = current
        .reconstructable_trees
        .iter()
        .collect::<BTreeSet<_>>();
    if let Some(path) = current_trees.difference(&expected_trees).next() {
        return Err(FolderbaseError::MigrationSourceChanged((*path).clone()));
    }
    if let Some(path) = expected_trees.difference(&current_trees).next() {
        return Err(FolderbaseError::MigrationSourceChanged((*path).clone()));
    }
    Err(FolderbaseError::MigrationSourceChanged(plan.root.clone()))
}

fn verify_expanded_reconstructable_trees(plan: &MigrationPlan) -> Result<()> {
    let Some(value) = plan
        .extensions
        .get(EXPANDED_RECONSTRUCTABLE_TREES_EXTENSION)
    else {
        return Ok(());
    };
    let expected: ExpandedReconstructableTreesExtension = serde_json::from_value(value.clone())
        .map_err(|_| FolderbaseError::MigrationSourceChanged(plan.root.clone()))?;
    if expected.version != "1" {
        return Err(FolderbaseError::MigrationSourceChanged(plan.root.clone()));
    }
    for tree in expected.trees {
        let absolute = safe_join(&plan.root, &tree.source_root)?;
        let expanded = expand_reconstructable_tree(&absolute)?;
        if !expanded.nested_folderbases.is_empty()
            || expanded.files.iter().any(AnalyzedFile::is_secret_shaped)
        {
            return Err(FolderbaseError::MigrationSourceChanged(tree.source_root));
        }
        let mut current_paths = expanded
            .files
            .into_iter()
            .map(|file| tree.source_root.join(file.path))
            .collect::<Vec<_>>();
        current_paths.sort();
        if current_paths != tree.source_paths {
            let expected_paths = tree.source_paths.iter().collect::<BTreeSet<_>>();
            let current = current_paths.iter().collect::<BTreeSet<_>>();
            let changed = current
                .symmetric_difference(&expected_paths)
                .next()
                .map(|path| (*path).clone())
                .unwrap_or(tree.source_root);
            return Err(FolderbaseError::MigrationSourceChanged(changed));
        }
    }
    Ok(())
}

fn verify_root_identity(plan: &MigrationPlan) -> Result<()> {
    let current = PhysicalIdentity::from_path(&plan.root)
        .map_err(|source| FolderbaseError::io(&plan.root, source))?;
    if plan.root_identity.as_ref().map(|root| root.identity()) != Some(current) {
        return Err(FolderbaseError::MigrationSourceChanged(plan.root.clone()));
    }
    Ok(())
}

fn verify_source_files(plan: &MigrationPlan) -> Result<()> {
    let mut current = Vec::new();
    for file in &plan.source_inventory.files {
        refuse_nested_folderbase_path(&plan.root, &file.path)?;
        let path = safe_join(&plan.root, &file.path)?;
        let metadata = fs::symlink_metadata(&path)
            .map_err(|_| FolderbaseError::MigrationSourceChanged(file.path.clone()))?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.len() != file.bytes
            || sha256_path(&path)? != file.sha256
        {
            return Err(FolderbaseError::MigrationSourceChanged(file.path.clone()));
        }
        current.push(file.clone());
    }
    if inventory_digest(&current) != plan.source_inventory.digest {
        return Err(FolderbaseError::MigrationSourceChanged(plan.root.clone()));
    }
    Ok(())
}

fn plan_digest(plan: &MigrationPlan) -> Result<String> {
    let bytes = serde_json::to_vec(&(
        &plan.protocol_version,
        &plan.id,
        &plan.root,
        MigrationState::Approved,
        &plan.source_inventory,
        &plan.answers,
        &plan.template_references,
        &plan.targets,
        &plan.operations,
        &plan.exclusions,
        &plan.extensions,
    ))
    .map_err(|source| FolderbaseError::json(&plan.root, source))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn require_state(actual: MigrationState, expected: MigrationState) -> Result<()> {
    if actual != expected {
        return Err(FolderbaseError::InvalidMigrationState {
            expected: expected.as_str(),
            actual: actual.as_str().to_owned(),
        });
    }
    Ok(())
}

fn sha256_path(path: &Path) -> Result<String> {
    let mut file = fs::File::open(path).map_err(|source| FolderbaseError::io(path, source))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|source| FolderbaseError::io(path, source))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn copy_new(source: &Path, destination: &Path) -> Result<()> {
    let source_metadata =
        fs::symlink_metadata(source).map_err(|error| FolderbaseError::io(source, error))?;
    if !source_metadata.is_file() || source_metadata.file_type().is_symlink() {
        return Err(FolderbaseError::MigrationSourceChanged(
            source.to_path_buf(),
        ));
    }
    let mut input = fs::File::open(source).map_err(|error| FolderbaseError::io(source, error))?;
    let mut output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                FolderbaseError::WouldOverwrite(destination.to_path_buf())
            } else {
                FolderbaseError::io(destination, error)
            }
        })?;
    output
        .set_permissions(source_metadata.permissions())
        .map_err(|error| FolderbaseError::io(destination, error))?;
    std::io::copy(&mut input, &mut output)
        .map_err(|error| FolderbaseError::io(destination, error))?;
    output
        .flush()
        .and_then(|()| output.sync_all())
        .map_err(|error| FolderbaseError::io(destination, error))
}

fn restore_snapshot_no_clobber(
    root: &Path,
    migration_id: &str,
    index: usize,
    snapshot: &Path,
    destination: &Path,
    expected_sha256: &str,
) -> Result<()> {
    let metadata =
        fs::symlink_metadata(snapshot).map_err(|error| FolderbaseError::io(snapshot, error))?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || sha256_path(snapshot)? != expected_sha256
    {
        return Err(FolderbaseError::MigrationVerificationFailed(
            snapshot.to_path_buf(),
        ));
    }

    if let Some(digest) = regular_file_digest_if_present(destination)? {
        if digest == expected_sha256 {
            return Ok(());
        }
        return Err(FolderbaseError::WouldOverwrite(destination.to_path_buf()));
    }

    let staging_relative = PathBuf::from(MIGRATIONS_DIR)
        .join(migration_id)
        .join("staging");
    let staging = safe_join(root, &staging_relative)?;
    create_directory_if_missing(&staging)?;
    let temporary = staging.join(format!("restore-{index}.tmp"));
    let temporary_ready = match fs::symlink_metadata(&temporary) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
            if sha256_path(&temporary)? == expected_sha256 {
                true
            } else {
                fs::remove_file(&temporary)
                    .map_err(|error| FolderbaseError::io(&temporary, error))?;
                sync_parent(&temporary)?;
                false
            }
        }
        Ok(_) => {
            return Err(FolderbaseError::MigrationVerificationFailed(temporary));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => return Err(FolderbaseError::io(&temporary, error)),
    };
    if !temporary_ready {
        copy_new(snapshot, &temporary)?;
        sync_parent(&temporary)?;
        if sha256_path(&temporary)? != expected_sha256 {
            return Err(FolderbaseError::MigrationVerificationFailed(temporary));
        }
    }

    fs::hard_link(&temporary, destination).map_err(|error| {
        if error.kind() == std::io::ErrorKind::AlreadyExists {
            FolderbaseError::WouldOverwrite(destination.to_path_buf())
        } else {
            FolderbaseError::io(destination, error)
        }
    })?;
    if sha256_path(destination)? != expected_sha256 {
        let _ = fs::remove_file(destination);
        return Err(FolderbaseError::MigrationVerificationFailed(
            destination.to_path_buf(),
        ));
    }
    sync_parent(destination)?;
    fs::remove_file(&temporary).map_err(|error| FolderbaseError::io(&temporary, error))?;
    sync_parent(&temporary)
}

fn write_bytes_new(path: &Path, content: &[u8]) -> Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|source| {
            if source.kind() == std::io::ErrorKind::AlreadyExists {
                FolderbaseError::WouldOverwrite(path.to_path_buf())
            } else {
                FolderbaseError::io(path, source)
            }
        })?;
    file.write_all(content)
        .and_then(|()| file.sync_all())
        .map_err(|source| FolderbaseError::io(path, source))?;
    sync_parent(path)
}

fn write_json_new(path: &Path, value: &impl Serialize) -> Result<()> {
    write_json_new_with_hook(path, value, || {})
}

fn write_json_new_with_hook(
    path: &Path,
    value: &impl Serialize,
    mut checkpoint: impl FnMut(),
) -> Result<()> {
    let content =
        serde_json::to_vec_pretty(value).map_err(|source| FolderbaseError::json(path, source))?;
    let parent = path.parent().ok_or_else(|| {
        invalid_journal(
            path,
            "new JSON record path does not have a parent directory",
        )
    })?;
    let temporary = parent.join(format!(".record-{}.tmp", Uuid::now_v7()));
    let write_result = (|| -> Result<()> {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|source| FolderbaseError::io(&temporary, source))?;
        file.write_all(&content)
            .and_then(|()| file.write_all(b"\n"))
            .and_then(|()| file.sync_all())
            .map_err(|source| FolderbaseError::io(&temporary, source))?;
        drop(file);
        checkpoint();
        fs::hard_link(&temporary, path).map_err(|source| {
            if source.kind() == std::io::ErrorKind::AlreadyExists {
                FolderbaseError::WouldOverwrite(path.to_path_buf())
            } else {
                FolderbaseError::io(path, source)
            }
        })?;
        sync_directory(parent)?;
        fs::remove_file(&temporary).map_err(|source| FolderbaseError::io(&temporary, source))?;
        sync_directory(parent)
    })();
    if write_result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    write_result
}

fn persist_plan(plan: &MigrationPlan) -> Result<()> {
    let path = safe_join(&plan.root, &migration_plan_relative(&plan.id))?;
    let content =
        serde_json::to_vec_pretty(plan).map_err(|source| FolderbaseError::json(&path, source))?;
    let parent = path.parent().ok_or_else(|| {
        invalid_journal(
            &path,
            "migration plan path does not have a parent directory",
        )
    })?;
    let temporary = parent.join(format!("plan.{}.tmp", Uuid::now_v7()));
    let write_result = (|| -> Result<()> {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|source| FolderbaseError::io(&temporary, source))?;
        file.write_all(&content)
            .and_then(|()| file.write_all(b"\n"))
            .and_then(|()| file.sync_all())
            .map_err(|source| FolderbaseError::io(&temporary, source))?;
        fs::rename(&temporary, &path).map_err(|source| FolderbaseError::io(&path, source))?;
        sync_directory(parent)
    })();
    if write_result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    write_result
}

fn persist_journal(path: &Path, journal: &MigrationJournal) -> Result<()> {
    let content =
        serde_json::to_vec_pretty(journal).map_err(|source| FolderbaseError::json(path, source))?;
    let parent = path.parent().ok_or_else(|| {
        invalid_journal(
            path,
            "migration journal path does not have a parent directory",
        )
    })?;
    let temporary = parent.join(format!("result.{}.tmp", Uuid::now_v7()));
    let write_result = (|| -> Result<()> {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|source| FolderbaseError::io(&temporary, source))?;
        file.write_all(&content)
            .and_then(|()| file.write_all(b"\n"))
            .and_then(|()| file.sync_all())
            .map_err(|source| FolderbaseError::io(&temporary, source))?;
        fs::rename(&temporary, path).map_err(|source| FolderbaseError::io(path, source))?;
        sync_directory(parent)
    })();
    if write_result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    write_result
}

fn sync_parent(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        sync_directory(parent)
    } else {
        Ok(())
    }
}

fn sync_directory(path: &Path) -> Result<()> {
    let directory = fs::File::open(path).map_err(|source| FolderbaseError::io(path, source))?;
    directory
        .sync_all()
        .map_err(|source| FolderbaseError::io(path, source))
}

fn cleanup_staging(root: &Path, migration_id: &str) {
    let staging_relative = PathBuf::from(MIGRATIONS_DIR)
        .join(migration_id)
        .join("staging");
    let Ok(staging) = safe_join(root, &staging_relative) else {
        return;
    };
    if let Ok(entries) = fs::read_dir(&staging) {
        for entry in entries.flatten() {
            if entry.file_type().is_ok_and(|file_type| file_type.is_file()) {
                let _ = fs::remove_file(entry.path());
            }
        }
    }
    let _ = fs::remove_dir(staging);
}

#[cfg(test)]
mod tests {
    use std::{
        panic::{AssertUnwindSafe, catch_unwind},
        sync::mpsc,
        thread,
    };

    use tempfile::TempDir;

    use super::*;

    const LEGACY_MANIFEST: &[u8] = br#"{
  "$schema": "https://folderbase.ai/protocol/0.1/folderbase.schema.json",
  "protocol_version": "0.1.0",
  "folderbase": {
    "id": "folderbase_019f9b75-4f42-7f65-a012-2bfecdd8c475",
    "name": "Legacy Migration Test",
    "kind": "project",
    "status": "active",
    "created_at": "2026-07-26T00:00:00Z",
    "entry": "FOLDERBASE.md"
  },
  "policies": {
    "availability": "keep_local",
    "structural_changes": "approve",
    "archive": "approve",
    "cloud_sync": "disabled"
  }
}
"#;

    #[test]
    fn protocol_upgrade_serializes_behind_existing_folderbase_migration_apply() {
        let root = legacy_structural_folderbase_fixture();
        fs::create_dir(root.path().join("Archive")).unwrap();
        fs::write(root.path().join("notes.md"), b"source\n").unwrap();
        let upgrade = crate::protocol_upgrade::plan_protocol_upgrade(root.path()).unwrap();
        let migration = MigrationPlan::propose_structural(
            root.path(),
            vec![MigrationOperation::move_object(
                "notes.md",
                "Archive/notes.md",
            )],
        )
        .unwrap();
        let approved = approve_migration(migration).unwrap();
        let (paused_sender, paused_receiver) = mpsc::sync_channel(0);
        let (resume_sender, resume_receiver) = mpsc::sync_channel(0);

        let apply = thread::spawn(move || {
            apply_migration_with_hook(approved, |checkpoint| {
                if checkpoint == ApplyCheckpoint::JournalPrepared {
                    paused_sender.send(()).unwrap();
                    resume_receiver.recv().unwrap();
                }
            })
        });
        if paused_receiver.recv().is_err() {
            panic!(
                "migration stopped before the lock checkpoint: {:?}",
                apply.join().unwrap()
            );
        }

        let lock_path = root.path().join(".folderbase/locks/transactions.lock");
        let transaction_is_locked = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&lock_path)
            .and_then(|file| match file.try_lock() {
                Err(std::fs::TryLockError::WouldBlock) => Ok(()),
                Err(std::fs::TryLockError::Error(source)) => Err(source),
                Ok(()) => {
                    let _ = file.unlock();
                    Err(io::Error::other(
                        "migration did not hold the transaction lock",
                    ))
                }
            })
            .is_ok();

        resume_sender.send(()).unwrap();
        assert_eq!(
            apply.join().unwrap().unwrap().state,
            MigrationState::Verified
        );
        assert!(
            transaction_is_locked,
            "an existing-Folderbase migration must exclude protocol activation for its full apply"
        );
        crate::protocol_upgrade::apply_protocol_upgrade(&upgrade, upgrade.plan_digest()).unwrap();
    }

    #[test]
    fn protocol_upgrade_serializes_behind_existing_folderbase_migration_recovery() {
        let root = legacy_structural_folderbase_fixture();
        fs::create_dir(root.path().join("Archive")).unwrap();
        fs::write(root.path().join("notes.md"), b"source\n").unwrap();
        let migration = MigrationPlan::propose_structural(
            root.path(),
            vec![MigrationOperation::move_object(
                "notes.md",
                "Archive/notes.md",
            )],
        )
        .unwrap();
        let migration_id = migration.id.clone();
        let interrupted = catch_unwind(AssertUnwindSafe(|| {
            apply_migration_with_hook(approve_migration(migration).unwrap(), |checkpoint| {
                if checkpoint == ApplyCheckpoint::OperationPlanned(0) {
                    panic!("leave a durable applying migration");
                }
            })
        }));
        assert!(interrupted.is_err());

        let recovery_root = root.path().to_path_buf();
        let recovery_id = migration_id.clone();
        let (paused_sender, paused_receiver) = mpsc::sync_channel(0);
        let (resume_sender, resume_receiver) = mpsc::sync_channel(0);
        let recovery = thread::spawn(move || {
            recover_migration_with_hook(recovery_root, &recovery_id, || {
                paused_sender.send(()).unwrap();
                resume_receiver.recv().unwrap();
            })
        });
        paused_receiver.recv().unwrap();

        let lock_path = root.path().join(".folderbase/locks/transactions.lock");
        let transaction_is_locked = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&lock_path)
            .and_then(|file| match file.try_lock() {
                Err(std::fs::TryLockError::WouldBlock) => Ok(()),
                Err(std::fs::TryLockError::Error(source)) => Err(source),
                Ok(()) => {
                    let _ = file.unlock();
                    Err(io::Error::other(
                        "migration recovery did not hold the transaction lock",
                    ))
                }
            })
            .is_ok();

        resume_sender.send(()).unwrap();
        assert_eq!(
            recovery.join().unwrap().unwrap().state,
            MigrationState::RolledBack
        );
        assert!(
            transaction_is_locked,
            "an existing-Folderbase migration recovery must exclude protocol activation"
        );
    }

    #[cfg(unix)]
    #[test]
    fn in_flight_reconcile_preserves_a_same_byte_substitution_before_final_revalidation() {
        let root = initialized_structural_folderbase_fixture();
        fs::create_dir(root.path().join("Archive")).unwrap();
        fs::write(root.path().join("notes.md"), b"source\n").unwrap();
        let plan = MigrationPlan::propose_structural(
            root.path(),
            vec![MigrationOperation::move_object(
                "notes.md",
                "Archive/notes.md",
            )],
        )
        .unwrap();
        let migration_id = plan.id.clone();
        let interrupted = catch_unwind(AssertUnwindSafe(|| {
            apply_migration_with_hook(approve_migration(plan).unwrap(), |checkpoint| {
                if checkpoint == ApplyCheckpoint::OperationPlanned(0) {
                    panic!("leave a durable in-flight move");
                }
            })
        }));
        assert!(interrupted.is_err());

        let source = root.path().join("notes.md");
        let destination = root.path().join("Archive/notes.md");
        fs::hard_link(&source, &destination).unwrap();
        let original_destination = PhysicalIdentity::from_path(&destination).unwrap();
        let canonical = canonical_root(root.path()).unwrap();
        let (journal_path, mut journal) = load_journal(&canonical, &migration_id).unwrap();

        let result = reconcile_structural_in_flight_with_hook(
            &canonical,
            &journal_path,
            &mut journal,
            |candidate| {
                fs::remove_file(candidate).unwrap();
                fs::write(candidate, b"source\n").unwrap();
            },
        );

        assert!(
            matches!(result, Err(FolderbaseError::MigrationVerificationFailed(ref path))
                if path == &canonical.join("Archive/notes.md")),
            "{result:?}"
        );
        assert!(source.exists());
        assert!(destination.exists());
        assert_eq!(fs::read(&destination).unwrap(), b"source\n");
        assert_ne!(
            PhysicalIdentity::from_path(&destination).unwrap(),
            original_destination
        );
        assert_ne!(
            PhysicalIdentity::from_path(&destination).unwrap(),
            PhysicalIdentity::from_path(&source).unwrap()
        );
        assert_eq!(journal.in_flight_operation, Some(0));
    }

    #[cfg(windows)]
    #[test]
    fn in_flight_reconcile_releases_child_handles_before_capability_relative_unlink() {
        let root = initialized_structural_folderbase_fixture();
        fs::create_dir(root.path().join("Archive")).unwrap();
        fs::write(root.path().join("notes.md"), b"source\n").unwrap();
        let plan = MigrationPlan::propose_structural(
            root.path(),
            vec![MigrationOperation::move_object(
                "notes.md",
                "Archive/notes.md",
            )],
        )
        .unwrap();
        let migration_id = plan.id.clone();
        let interrupted = catch_unwind(AssertUnwindSafe(|| {
            apply_migration_with_hook(approve_migration(plan).unwrap(), |checkpoint| {
                if checkpoint == ApplyCheckpoint::OperationPlanned(0) {
                    panic!("leave a durable in-flight move");
                }
            })
        }));
        assert!(interrupted.is_err());

        let source = root.path().join("notes.md");
        let destination = root.path().join("Archive/notes.md");
        fs::hard_link(&source, &destination).unwrap();
        let canonical = canonical_root(root.path()).unwrap();
        let (journal_path, mut journal) = load_journal(&canonical, &migration_id).unwrap();

        reconcile_structural_in_flight(&canonical, &journal_path, &mut journal)
            .expect("Windows child handles must be released before exact-name unlink");

        assert!(source.exists());
        assert!(!destination.exists());
        assert_eq!(journal.in_flight_operation, None);
        assert_eq!(journal.completed_operations, 0);
    }

    #[test]
    fn every_durable_apply_checkpoint_can_be_reopened_and_recovered() {
        for fault in [
            ApplyCheckpoint::JournalPrepared,
            ApplyCheckpoint::JournalCreated,
            ApplyCheckpoint::StagingCreated,
            ApplyCheckpoint::OperationCompleted(0),
            ApplyCheckpoint::OperationCompleted(1),
            ApplyCheckpoint::OperationCompleted(2),
            ApplyCheckpoint::MaterializationPlanned(0),
            ApplyCheckpoint::MaterializationVerified(0),
        ] {
            let root = migration_fixture();
            let analysis = analyze_migration(root.path()).unwrap();
            let answers = typed_answers(&analysis);
            let plan = plan_migration(analysis, answers, "Organized").unwrap();
            assert_eq!(plan.operations.len(), 3);
            let migration_id = plan.id.clone();
            let approved = approve_migration(plan).unwrap();

            let interrupted = catch_unwind(AssertUnwindSafe(|| {
                apply_migration_with_hook(approved, |checkpoint| {
                    if checkpoint == fault {
                        panic!("simulated process termination");
                    }
                })
            }));
            assert!(interrupted.is_err());

            let reopened = MigrationResult::reopen(root.path(), &migration_id).unwrap();
            assert_eq!(reopened.state, MigrationState::Applying);
            let (_, journal) =
                load_journal(&canonical_root(root.path()).unwrap(), &migration_id).unwrap();
            let expected_completed = match fault {
                ApplyCheckpoint::MigrationDirectoryPrepared
                | ApplyCheckpoint::JournalStaged
                | ApplyCheckpoint::JournalPrepared
                | ApplyCheckpoint::JournalCreated
                | ApplyCheckpoint::StagingCreated => 0,
                ApplyCheckpoint::OperationPlanned(index)
                | ApplyCheckpoint::OperationApplied(index) => index,
                ApplyCheckpoint::OperationCompleted(index) => index + 1,
                ApplyCheckpoint::MaterializationPlanned(_)
                | ApplyCheckpoint::MaterializationVerified(_)
                | ApplyCheckpoint::WorkspacePlanned
                | ApplyCheckpoint::WorkspaceVerified => journal.operations.len(),
            };
            assert_eq!(journal.completed_operations, expected_completed);

            let recovered = MigrationResult::recover(root.path(), &migration_id).unwrap();
            assert_eq!(recovered.state, MigrationState::RolledBack);
            assert!(!root.path().join("Organized").exists());
            assert_eq!(
                fs::read(root.path().join("README.md")).unwrap(),
                b"source\n"
            );
        }
    }

    #[test]
    fn interrupted_before_additive_journal_publication_can_retry_the_approved_plan() {
        for fault in [
            ApplyCheckpoint::MigrationDirectoryPrepared,
            ApplyCheckpoint::JournalStaged,
        ] {
            let root = migration_fixture();
            let analysis = analyze_migration(root.path()).unwrap();
            let answers = typed_answers(&analysis);
            let plan = plan_migration(analysis, answers, "Organized").unwrap();
            let migration_id = plan.id.clone();
            let approved = approve_migration(plan).unwrap();

            let interrupted = catch_unwind(AssertUnwindSafe(|| {
                apply_migration_with_hook(approved, |checkpoint| {
                    if checkpoint == fault {
                        panic!("simulated process termination");
                    }
                })
            }));
            assert!(interrupted.is_err());
            assert!(!root.path().join("Organized").exists());

            let approved = ApprovedMigration::reopen(root.path(), &migration_id).unwrap();
            let result = apply_migration(approved).unwrap();
            assert_eq!(result.state, MigrationState::Verified);
            assert_eq!(
                fs::read(root.path().join("Organized/README.md")).unwrap(),
                b"source\n"
            );
        }
    }

    #[test]
    fn additive_journal_collision_preserves_unowned_staging_bytes() {
        let root = migration_fixture();
        let analysis = analyze_migration(root.path()).unwrap();
        let answers = typed_answers(&analysis);
        let plan = plan_migration(analysis, answers, "Organized").unwrap();
        let migration_id = plan.id.clone();
        let approved = approve_migration(plan).unwrap();
        let migration_dir = root.path().join(MIGRATIONS_DIR).join(&migration_id);
        let staging = migration_dir.join("staging");
        fs::create_dir(&staging).unwrap();
        fs::write(staging.join("unowned.txt"), b"do not delete\n").unwrap();
        fs::write(migration_dir.join("result.json"), b"collision\n").unwrap();

        assert!(apply_migration(approved).is_err());
        assert_eq!(
            fs::read(staging.join("unowned.txt")).unwrap(),
            b"do not delete\n"
        );
    }

    #[test]
    fn additive_staging_collision_rolls_back_without_deleting_unowned_bytes() {
        let root = migration_fixture();
        let analysis = analyze_migration(root.path()).unwrap();
        let answers = typed_answers(&analysis);
        let plan = plan_migration(analysis, answers, "Organized").unwrap();
        let migration_id = plan.id.clone();
        let approved = approve_migration(plan).unwrap();
        let staging = root
            .path()
            .join(MIGRATIONS_DIR)
            .join(&migration_id)
            .join("staging");
        fs::create_dir(&staging).unwrap();
        fs::write(staging.join("unowned.txt"), b"do not delete\n").unwrap();

        assert!(apply_migration(approved).is_err());
        assert_eq!(
            MigrationResult::reopen(root.path(), &migration_id)
                .unwrap()
                .state,
            MigrationState::RolledBack
        );
        assert_eq!(
            MigrationPlan::reopen(root.path(), &migration_id)
                .unwrap()
                .state,
            MigrationState::RolledBack
        );
        assert_eq!(
            fs::read(staging.join("unowned.txt")).unwrap(),
            b"do not delete\n"
        );
        assert!(!root.path().join("Organized").exists());
    }

    #[test]
    fn every_structural_apply_checkpoint_reopens_and_recovers() {
        for operation in [
            MigrationOperation::move_object("notes.md", "Archive/notes.md"),
            MigrationOperation::update_policy("availability", serde_json::json!("keep_local")),
        ] {
            for fault in [
                ApplyCheckpoint::JournalPrepared,
                ApplyCheckpoint::JournalCreated,
                ApplyCheckpoint::OperationPlanned(0),
                ApplyCheckpoint::OperationApplied(0),
                ApplyCheckpoint::OperationCompleted(0),
            ] {
                let root = initialized_structural_folderbase_fixture();
                fs::create_dir(root.path().join("Archive")).unwrap();
                fs::write(root.path().join("notes.md"), "source\n").unwrap();
                let manifest_before =
                    fs::read(root.path().join(".folderbase/manifest.json")).unwrap();
                let plan = MigrationPlan::propose_structural(root.path(), vec![operation.clone()])
                    .unwrap();
                let migration_id = plan.id.clone();
                let approved = approve_migration(plan).unwrap();

                let interrupted = catch_unwind(AssertUnwindSafe(|| {
                    apply_migration_with_hook(approved, |checkpoint| {
                        if checkpoint == fault {
                            panic!("simulated process termination");
                        }
                    })
                }));
                assert!(interrupted.is_err());
                assert_eq!(
                    MigrationResult::reopen(root.path(), &migration_id)
                        .unwrap()
                        .state,
                    MigrationState::Applying
                );

                let recovered = MigrationResult::recover(root.path(), &migration_id).unwrap();
                assert_eq!(recovered.state, MigrationState::RolledBack);
                assert_eq!(
                    fs::read(root.path().join(".folderbase/manifest.json")).unwrap(),
                    manifest_before
                );
                assert_eq!(fs::read(root.path().join("notes.md")).unwrap(), b"source\n");
                assert!(!root.path().join("Archive/notes.md").exists());
                assert_eq!(
                    MigrationResult::recover(root.path(), &migration_id)
                        .unwrap()
                        .state,
                    MigrationState::RolledBack
                );
            }
        }
    }

    #[test]
    fn every_structural_rollback_checkpoint_reopens_and_recovers() {
        for fault in [
            StructuralRollbackCheckpoint::Started,
            StructuralRollbackCheckpoint::OperationPlanned(0),
            StructuralRollbackCheckpoint::OperationApplied(0),
            StructuralRollbackCheckpoint::OperationCompleted(0),
            StructuralRollbackCheckpoint::Completed,
        ] {
            let root = initialized_structural_folderbase_fixture();
            fs::create_dir(root.path().join("Archive")).unwrap();
            fs::write(root.path().join("notes.md"), "source\n").unwrap();
            let plan = MigrationPlan::propose_structural(
                root.path(),
                vec![MigrationOperation::move_object(
                    "notes.md",
                    "Archive/notes.md",
                )],
            )
            .unwrap();
            let migration_id = plan.id.clone();
            apply_migration(approve_migration(plan).unwrap()).unwrap();
            let canonical = canonical_root(root.path()).unwrap();
            let (journal_path, mut journal) = load_journal(&canonical, &migration_id).unwrap();

            let interrupted = catch_unwind(AssertUnwindSafe(|| {
                rollback_structural_journal_with_hook(
                    &canonical,
                    &journal_path,
                    &mut journal,
                    |checkpoint| {
                        if checkpoint == fault {
                            panic!("simulated process termination");
                        }
                    },
                )
            }));
            assert!(interrupted.is_err());

            let recovered = MigrationResult::recover(root.path(), &migration_id).unwrap();
            assert_eq!(recovered.state, MigrationState::RolledBack);
            assert_eq!(fs::read(root.path().join("notes.md")).unwrap(), b"source\n");
            assert!(!root.path().join("Archive/notes.md").exists());
            assert_eq!(
                MigrationResult::recover(root.path(), &migration_id)
                    .unwrap()
                    .state,
                MigrationState::RolledBack
            );
        }
    }

    #[test]
    fn multi_folderbase_materialization_checkpoints_recover_without_active_boundaries() {
        for fault in [
            ApplyCheckpoint::MaterializationPlanned(0),
            ApplyCheckpoint::MaterializationVerified(0),
            ApplyCheckpoint::MaterializationPlanned(1),
            ApplyCheckpoint::MaterializationVerified(1),
            ApplyCheckpoint::WorkspacePlanned,
            ApplyCheckpoint::WorkspaceVerified,
        ] {
            let root = migration_fixture();
            let analysis = analyze_migration(root.path()).unwrap();
            let client_target = analysis
                .proposed_targets
                .iter()
                .find(|target| {
                    target.kind == MigrationTargetKind::Folderbase
                        && target.path == Path::new("Client-Shared")
                })
                .unwrap()
                .id
                .clone();
            let answers = analysis
                .questions
                .iter()
                .map(|question| {
                    let answer = match (&question.kind, question.id.as_str()) {
                        (_, "question_canonical_scope") => "proposed_boundaries".to_owned(),
                        (MigrationQuestionKind::Assignment { source_path, .. }, _)
                            if source_path.starts_with("Client-Shared") =>
                        {
                            client_target.clone()
                        }
                        _ => question.recommended_option_id.clone(),
                    };
                    MigrationAnswer {
                        question_id: question.id.clone(),
                        answer,
                        exceptions: Vec::new(),
                    }
                })
                .collect();
            let plan = plan_migration(analysis, answers, "Organized").unwrap();
            let migration_id = plan.id.clone();
            let approved = approve_migration(plan).unwrap();

            let interrupted = catch_unwind(AssertUnwindSafe(|| {
                apply_migration_with_hook(approved, |checkpoint| {
                    if checkpoint == fault {
                        panic!("simulated process termination");
                    }
                })
            }));
            assert!(interrupted.is_err());
            assert_eq!(
                MigrationResult::recover(root.path(), &migration_id)
                    .unwrap()
                    .state,
                MigrationState::RolledBack
            );
            assert!(!root.path().join("Organized").exists());
            assert!(root.path().join("README.md").exists());
            assert!(root.path().join("Client-Shared/Overview.md").exists());
        }
    }

    fn migration_fixture() -> TempDir {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("Client-Shared")).unwrap();
        fs::write(root.path().join("README.md"), "source\n").unwrap();
        fs::write(root.path().join("Client-Shared/Overview.md"), "client\n").unwrap();
        root
    }

    fn initialized_structural_folderbase_fixture() -> TempDir {
        let root = tempfile::tempdir().unwrap();
        let initialization = crate::initialization::plan_initialization(
            root.path(),
            InitializationOptions {
                name: Some("Structural Recovery Test Folderbase".to_owned()),
                kind: FolderbaseKind::Project,
                create_agent_adapters: true,
            },
        )
        .unwrap();
        crate::initialization::initialize(&initialization).unwrap();
        root
    }

    fn legacy_structural_folderbase_fixture() -> TempDir {
        let root = initialized_structural_folderbase_fixture();
        fs::write(
            root.path().join(".folderbase/manifest.json"),
            LEGACY_MANIFEST,
        )
        .unwrap();
        fs::write(
            root.path().join("FOLDERBASE.md"),
            b"# Legacy Folderbase\n\n## Purpose\nTest migration serialization.\n\n## Current state\nReady.\n\n## Navigate\nUse ordinary files.\n\n## Operating rules\nPreserve bytes.\n\n## Unresolved work\nNone.\n",
        )
        .unwrap();
        fs::write(root.path().join(".folderbaseignore"), b"node_modules/\n").unwrap();
        root
    }

    fn typed_answers(analysis: &MigrationAnalysis) -> Vec<MigrationAnswer> {
        analysis
            .questions
            .iter()
            .map(|question| MigrationAnswer {
                question_id: question.id.clone(),
                answer: question.recommended_option_id.clone(),
                exceptions: Vec::new(),
            })
            .collect()
    }
}

mod transaction_v1;

use std::{
    cell::Cell,
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

#[cfg(test)]
use crate::InitializationOptions;
use crate::{
    FolderbaseError, FolderbaseKind, NestedFolderbaseBoundary, ReconstructableTree, Result,
    TemplateAnswerValue, TemplateArtifactKind, ValidationLevel,
    folder_analysis::{AnalyzedFile, analyze_folder, expand_reconstructable_tree},
    folderbase_capture::validate_folderbaseignore_content,
    folderbase_state::FolderbaseState,
    local_versions::{LocalVersionStore, StoreTransactionLock},
    migration_filesystem::{
        ExactDirectoryLeaf, ExactExistingClaimSource, ExactLeafClaimExpectation,
        ExactLeafClaimRequest, ExactLeafClaimResult, ExactRegularLeaf, MigrationFilesystem,
        MigrationRegularFact, VerifiedPrivateDirectory, VerifiedVisibleDirectory,
    },
    physical_identity::{PhysicalIdentity, RetainedPhysicalIdentity},
    protocol_upgrade::scan_pending_work,
    root_attestation::{DEFAULT_V05_CAPTURE_IGNORE_RULES, metadata_is_link_or_reparse},
    template::{
        load_builtin_template, render_template_for_capability_destination, template_package_sha256,
    },
    traversal_policy::{NestedFolderbaseBoundaryKind, classify_nested_folderbase_boundary},
    validation::validate,
    workspace::{has_nested_folderbase_marker, is_reserved_workspace_component},
};
use transaction_v1::{
    MAX_JOURNAL_GENERATION_BYTES, MAX_JOURNAL_GENERATIONS, MAX_PROGRAM_BYTES, MutationProgramV1,
    ProgramAbsentLeafV1, ProgramGeneratedFileV1, ProgramGeneratedRoleV1, ProgramMaterializationV1,
    ProgramPrivateBlobV1, ProgramStepV1, TRANSACTION_DIRECTORY, TransactionDirectionV1,
    TransactionJournalGenerationV1, TransactionPhaseV1, validate_append, validate_chain,
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
const JOURNAL_GENERATION_STAGING_NAME: &str = ".next-generation.preparing";

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MigrationAnalysis {
    pub id: String,
    #[serde(with = "crate::portable_wire_path::display")]
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
        #[serde(with = "crate::portable_wire_path::relative")]
        source_path: PathBuf,
        content_kind: MigrationContentKind,
    },
    AssignmentGroup {
        rule_version: String,
        #[serde(with = "crate::portable_wire_path::relative_or_current")]
        source_root: PathBuf,
        #[serde(with = "crate::portable_wire_path::relative::vec")]
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
    #[serde(with = "crate::portable_wire_path::relative")]
    pub path: PathBuf,
    pub suggested_name: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MigrationTarget {
    pub id: String,
    pub kind: MigrationTargetKind,
    #[serde(with = "crate::portable_wire_path::relative_or_current")]
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
    #[serde(with = "crate::portable_wire_path::relative")]
    pub source_path: PathBuf,
    pub target_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MigrationPlan {
    pub protocol_version: String,
    pub id: String,
    #[serde(with = "crate::portable_wire_path::display")]
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
    /// Return the immutable approval digest once this plan has been approved.
    pub fn approval_digest(&self) -> Option<&str> {
        self.approval_digest.as_deref()
    }

    /// Reopen a durable migration proposal by ID.
    pub fn reopen(root: impl AsRef<Path>, migration_id: &str) -> Result<Self> {
        let (root, retained_root) = canonical_root_with_identity(root.as_ref())?;
        let mut plan = load_plan(&root, migration_id)?;
        if plan
            .root_identity
            .as_ref()
            .map(|identity| identity.identity())
            != Some(retained_root.identity())
        {
            return Err(FolderbaseError::MigrationSourceChanged(root));
        }
        plan.root_identity = Some(retained_root);
        Ok(plan)
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
        let source_digest = inventory_digest(&source_files)?;
        let topology_analysis = analyze_folder(&root)?;
        let source_topology = source_topology_snapshot(
            &topology_analysis.files,
            &topology_analysis.reconstructable_trees,
            &topology_analysis.nested_folderbases,
            &[],
        );
        let mut extensions = BTreeMap::new();
        extensions.insert(
            SOURCE_TOPOLOGY_EXTENSION.to_owned(),
            serde_json::to_value(source_topology)
                .map_err(|source| FolderbaseError::json(&root, source))?,
        );
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
        #[serde(with = "crate::portable_wire_path::relative")]
        path: PathBuf,
    },
    CopyFile {
        #[serde(with = "crate::portable_wire_path::relative")]
        source_path: PathBuf,
        #[serde(with = "crate::portable_wire_path::relative")]
        destination_path: PathBuf,
        expected_sha256: String,
    },
    MoveObject {
        #[serde(with = "crate::portable_wire_path::relative")]
        source_path: PathBuf,
        #[serde(with = "crate::portable_wire_path::relative")]
        destination_path: PathBuf,
        #[serde(default)]
        expected_sha256: String,
        #[serde(default, with = "crate::portable_wire_path::relative::option")]
        snapshot_path: Option<PathBuf>,
        #[serde(default)]
        snapshot_sha256: Option<String>,
    },
    UpdateAdapter {
        #[serde(with = "crate::portable_wire_path::relative")]
        path: PathBuf,
        managed_block: String,
        #[serde(default)]
        expected_sha256: String,
        #[serde(default)]
        expected_result_sha256: String,
        #[serde(default, with = "crate::portable_wire_path::relative::option")]
        snapshot_path: Option<PathBuf>,
        #[serde(default)]
        snapshot_sha256: Option<String>,
    },
    UpdateIgnorePolicy {
        #[serde(with = "crate::portable_wire_path::relative")]
        path: PathBuf,
        content: String,
        #[serde(default)]
        expected_sha256: String,
        #[serde(default)]
        expected_result_sha256: String,
        #[serde(default, with = "crate::portable_wire_path::relative::option")]
        snapshot_path: Option<PathBuf>,
        #[serde(default)]
        snapshot_sha256: Option<String>,
    },
    UpdatePolicy {
        #[serde(with = "crate::portable_wire_path::relative")]
        manifest_path: PathBuf,
        policy: String,
        value: serde_json::Value,
        #[serde(default)]
        expected_sha256: String,
        #[serde(default)]
        expected_result_sha256: String,
        #[serde(default, with = "crate::portable_wire_path::relative::option")]
        snapshot_path: Option<PathBuf>,
        #[serde(default)]
        snapshot_sha256: Option<String>,
    },
    ChangeKind {
        #[serde(with = "crate::portable_wire_path::relative")]
        manifest_path: PathBuf,
        new_kind: FolderbaseKind,
        #[serde(default)]
        expected_sha256: String,
        #[serde(default)]
        expected_result_sha256: String,
        #[serde(default, with = "crate::portable_wire_path::relative::option")]
        snapshot_path: Option<PathBuf>,
        #[serde(default)]
        snapshot_sha256: Option<String>,
    },
    MarkCanonical {
        #[serde(with = "crate::portable_wire_path::relative")]
        object_record_path: PathBuf,
        #[serde(default)]
        expected_sha256: String,
        #[serde(default)]
        expected_result_sha256: String,
        #[serde(default, with = "crate::portable_wire_path::relative::option")]
        snapshot_path: Option<PathBuf>,
        #[serde(default)]
        snapshot_sha256: Option<String>,
    },
    MarkSuperseded {
        #[serde(with = "crate::portable_wire_path::relative")]
        object_record_path: PathBuf,
        superseded_by: String,
        #[serde(default)]
        expected_sha256: String,
        #[serde(default)]
        expected_result_sha256: String,
        #[serde(default, with = "crate::portable_wire_path::relative::option")]
        snapshot_path: Option<PathBuf>,
        #[serde(default)]
        snapshot_sha256: Option<String>,
    },
    ArchiveObject {
        #[serde(with = "crate::portable_wire_path::relative")]
        object_record_path: PathBuf,
        #[serde(default)]
        expected_sha256: String,
        #[serde(default)]
        expected_result_sha256: String,
        #[serde(default, with = "crate::portable_wire_path::relative::option")]
        snapshot_path: Option<PathBuf>,
        #[serde(default)]
        snapshot_sha256: Option<String>,
    },
    AddRelationship {
        #[serde(with = "crate::portable_wire_path::relative")]
        object_record_path: PathBuf,
        relationship_type: String,
        target_object_id: String,
        #[serde(default)]
        expected_sha256: String,
        #[serde(default)]
        expected_result_sha256: String,
        #[serde(default, with = "crate::portable_wire_path::relative::option")]
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
            validate_typed_ignore_policy_update(root, path, content, &source)?;
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

fn validate_typed_ignore_policy_update(
    root: &Path,
    path: &Path,
    content: &str,
    error_path: &Path,
) -> Result<()> {
    if path != Path::new(".folderbaseignore") || content.contains('\0') {
        return Err(FolderbaseError::InvalidRecord {
            path: error_path.to_path_buf(),
            message: "ignore policy must be capture-compatible UTF-8 for .folderbaseignore"
                .to_owned(),
        });
    }
    validate_folderbaseignore_content(root, content).map_err(|error| {
        FolderbaseError::InvalidRecord {
            path: error_path.to_path_buf(),
            message: format!("ignore policy is not capture-compatible: {error}"),
        }
    })
}

fn validate_typed_ignore_policy_updates(plan: &MigrationPlan) -> Result<()> {
    for operation in &plan.operations {
        if let MigrationOperation::UpdateIgnorePolicy { path, content, .. } = operation {
            let source = safe_join(&plan.root, path)?;
            validate_typed_ignore_policy_update(&plan.root, path, content, &source)?;
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MigrationExclusion {
    #[serde(with = "crate::portable_wire_path::relative")]
    pub path: PathBuf,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MigrationPreview {
    pub migration_id: String,
    pub targets: Vec<MigrationTarget>,
    #[serde(with = "crate::portable_wire_path::relative::vec")]
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
    #[serde(with = "crate::portable_wire_path::relative")]
    pub source_path: PathBuf,
    #[serde(with = "crate::portable_wire_path::relative")]
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
    /// Return the digest which binds this token to its immutable approved plan.
    pub fn approval_digest(&self) -> &str {
        &self.approval_digest
    }

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
    #[serde(with = "crate::portable_wire_path::display")]
    pub root: PathBuf,
    pub state: MigrationState,
    #[serde(with = "crate::portable_wire_path::relative::vec")]
    pub created_paths: Vec<PathBuf>,
    #[serde(with = "crate::portable_wire_path::relative")]
    pub journal_path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RollbackResult {
    pub migration_id: String,
    #[serde(with = "crate::portable_wire_path::relative::vec")]
    pub removed_paths: Vec<PathBuf>,
    pub state: MigrationState,
}

/// The caller-selected Folderbase root for one migration command.
///
/// `Current` is the public command boundary. The approval-carrying variant is
/// used only by the released `apply_migration` adapter so its already-retained
/// root authority is not weakened while that adapter moves behind
/// `MigrationExecution`.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum RootClaim<'a> {
    Current {
        display_root: &'a Path,
    },
    #[doc(hidden)]
    Approved {
        approved_migration: ApprovedMigration,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationCommand<'a> {
    Apply {
        migration_id: &'a str,
        approval_digest: &'a str,
    },
    Recover {
        migration_id: &'a str,
    },
    Rollback {
        migration_id: &'a str,
    },
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum MigrationConflictDirection {
    Apply,
    Rollback,
    /// A released legacy result recorded a conflict without durably recording
    /// which execution direction produced it.
    LegacyUnknown,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[non_exhaustive]
pub struct MigrationConflict {
    pub operation_index: Option<usize>,
    #[serde(with = "crate::portable_wire_path::relative::vec")]
    pub affected_paths: Vec<PathBuf>,
    pub expected: String,
    pub observed: String,
    pub phase: String,
    pub direction: MigrationConflictDirection,
    #[serde(with = "crate::portable_wire_path::relative::option")]
    pub preserved_artifact: Option<PathBuf>,
}

#[derive(Debug, Serialize)]
#[non_exhaustive]
pub enum MigrationOutcome {
    Applied(MigrationResult),
    RolledBack(RollbackResult),
    Conflicted {
        migration_id: String,
        conflicts: Vec<MigrationConflict>,
    },
    RecoveryRequired {
        migration_id: String,
        work: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExecutionFormat {
    None,
    PrePreparedTransactionV1,
    TransactionV1,
    LegacyResult,
}

/// The single semantic execution boundary for apply, recovery, and rollback.
pub struct MigrationExecution;

impl MigrationExecution {
    pub fn run(root: RootClaim<'_>, command: MigrationCommand<'_>) -> Result<MigrationOutcome> {
        let migration_id = migration_command_id(command).to_owned();
        match Self::run_inner(root, command) {
            Err(FolderbaseError::RecoveryRequired { work }) => {
                Ok(MigrationOutcome::RecoveryRequired { migration_id, work })
            }
            result => result,
        }
    }

    fn run_inner(root: RootClaim<'_>, command: MigrationCommand<'_>) -> Result<MigrationOutcome> {
        match (root, command) {
            (
                RootClaim::Current { display_root },
                MigrationCommand::Apply {
                    migration_id,
                    approval_digest,
                },
            ) => run_current_transaction_v1_apply_with_hooks(
                display_root,
                migration_id,
                approval_digest,
                || {},
                |_| {},
                |_| {},
            ),
            (
                RootClaim::Approved { approved_migration },
                MigrationCommand::Apply {
                    migration_id,
                    approval_digest,
                },
            ) => {
                if approved_migration.plan.id != migration_id
                    || approved_migration.approval_digest != approval_digest
                {
                    return Err(FolderbaseError::MigrationApprovalMismatch);
                }
                apply_transaction_v1_migration_outcome_with_hook(approved_migration, |_| {})
            }
            (RootClaim::Current { display_root }, MigrationCommand::Recover { migration_id }) => {
                run_current_migration_command_with_hooks(
                    display_root,
                    MigrationCommand::Recover { migration_id },
                    || {},
                    |_| {},
                )
            }
            (RootClaim::Current { display_root }, MigrationCommand::Rollback { migration_id }) => {
                run_current_migration_command_with_hooks(
                    display_root,
                    MigrationCommand::Rollback { migration_id },
                    || {},
                    |_| {},
                )
            }
            (
                RootClaim::Approved { .. },
                MigrationCommand::Recover { .. } | MigrationCommand::Rollback { .. },
            ) => Err(FolderbaseError::InvalidMigrationState {
                expected: "current_root_claim",
                actual: "approved_root_claim".to_owned(),
            }),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct SourceFile {
    #[serde(with = "crate::portable_wire_path::relative")]
    path: PathBuf,
    bytes: u64,
    sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MigrationJournal {
    protocol_version: String,
    id: String,
    #[serde(with = "crate::portable_wire_path::display")]
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
    #[serde(with = "crate::portable_wire_path::relative::vec")]
    created_paths: Vec<PathBuf>,
    completed_operations: usize,
    in_flight_operation: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    transaction_program_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    operation_precondition_identities: Vec<Option<String>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    operation_result_identities: Vec<Option<String>>,
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
    #[serde(with = "crate::portable_wire_path::relative::vec")]
    files: Vec<PathBuf>,
    #[serde(with = "crate::portable_wire_path::relative::vec")]
    reconstructable_trees: Vec<PathBuf>,
    nested_folderbases: Vec<NestedFolderbaseBoundary>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct MaterializedFolderbase {
    target_id: String,
    #[serde(with = "crate::portable_wire_path::relative")]
    path: PathBuf,
    folderbase_id: String,
    name: String,
    template_reference: String,
    state: MaterializationState,
    #[serde(with = "crate::portable_wire_path::relative::vec")]
    created_directories: Vec<PathBuf>,
    #[serde(with = "crate::portable_wire_path::relative::map")]
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
    #[serde(with = "crate::portable_wire_path::relative")]
    path: PathBuf,
    workspace_id: String,
    name: String,
    state: MaterializationState,
    folderbases: Vec<WorkspaceFolderbaseLink>,
    #[serde(with = "crate::portable_wire_path::relative::map")]
    created_files: BTreeMap<PathBuf, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct WorkspaceFolderbaseLink {
    folderbase_id: String,
    label: String,
    #[serde(with = "crate::portable_wire_path::relative")]
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
    #[serde(with = "crate::portable_wire_path::relative_or_current")]
    source_root: PathBuf,
    members: Vec<GroupedAssignmentMemberContract>,
    content_kind: MigrationContentKind,
    coverage_digest: String,
    default_target_id: String,
    exceptions: Vec<MigrationAnswerException>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct GroupedAssignmentMemberContract {
    #[serde(with = "crate::portable_wire_path::relative")]
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
    #[serde(with = "crate::portable_wire_path::relative")]
    source_root: PathBuf,
    #[serde(with = "crate::portable_wire_path::relative::vec")]
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
            id: stable_path_id(suggested_prefix, &boundary.path)?,
            kind: suggested_kind,
            path: boundary.path.clone(),
            suggested_name: boundary.suggested_name.clone(),
            reason: boundary.reason.clone(),
        });
        if suggested_kind != MigrationTargetKind::Folderbase {
            proposed_targets.push(MigrationTarget {
                id: stable_path_id("target_folderbase", &boundary.path)?,
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
    )?;
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
    )?);

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
    )?;
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
    let source_inventory_digest = inventory_digest(&source_files)?;
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
        validate_typed_ignore_policy_updates(&plan)?;
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
    create_private_directory_new(&temporary)?;
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

/// Compatibility adapter for applying an approved migration.
///
/// The adapter retains the released `ApprovedMigration` API and maps semantic
/// transaction conflicts into its legacy `Result` error shape. New callers
/// that need explicit `Conflicted` or `RecoveryRequired` outcomes should use
/// [`MigrationExecution::run`] with [`MigrationCommand::Apply`].
///
/// Core durably records execution before ordinary-folder mutation and never
/// overwrites pre-existing content. Recovery direction is selected through the
/// durable execution format rather than inferred from an adapter error.
pub fn apply_migration(approved: ApprovedMigration) -> Result<MigrationResult> {
    apply_migration_with_hook(approved, |_| {})
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ApplyCheckpoint {
    ExistingFolderbaseDetected,
    MutationAuthorityBound,
    JournalPrepared,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TransactionV1Checkpoint {
    ApplyIntentPersisted(usize),
    PrivatePublishClaimStaged(usize),
    ReplacePublishClaimPrepared(usize),
    ClaimComplete(usize),
    ParentsRevalidatedBeforePublish(usize),
    VisiblePublishComplete(usize),
    PrivateApplyReceiptPersisted(usize),
    JournalApplyReceiptPersisted(usize),
    RollbackRequested,
    InverseClaimComplete(usize),
    PrivateRollbackReceiptPersisted(usize),
    JournalRollbackReceiptPersisted(usize),
    PrivateAbortReceiptPersisted(usize),
    JournalAbortReceiptPersisted(usize),
    MoveAbortRollbackClaimRetired(usize),
    MoveAbortSourceClaimRetired(usize),
    ConflictRecorded(usize),
}

#[cfg(test)]
#[allow(dead_code)]
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
    checkpoint: impl FnMut(ApplyCheckpoint),
) -> Result<MigrationResult> {
    let migration_id = approved.plan.id.clone();
    let approval_digest = approved.approval_digest.clone();
    match MigrationExecution::run_apply_with_hook(
        RootClaim::Approved {
            approved_migration: approved,
        },
        MigrationCommand::Apply {
            migration_id: &migration_id,
            approval_digest: &approval_digest,
        },
        checkpoint,
    )? {
        MigrationOutcome::Applied(result) => Ok(result),
        MigrationOutcome::RolledBack(_) | MigrationOutcome::Conflicted { .. } => {
            Err(FolderbaseError::InvalidMigrationState {
                expected: MigrationState::Verified.as_str(),
                actual: MigrationState::Conflicted.as_str().to_owned(),
            })
        }
        MigrationOutcome::RecoveryRequired { work, .. } => {
            Err(FolderbaseError::RecoveryRequired { work })
        }
    }
}

impl MigrationExecution {
    fn run_apply_with_hook(
        root: RootClaim<'_>,
        command: MigrationCommand<'_>,
        checkpoint: impl FnMut(ApplyCheckpoint),
    ) -> Result<MigrationOutcome> {
        match (root, command) {
            (
                RootClaim::Approved { approved_migration },
                MigrationCommand::Apply {
                    migration_id,
                    approval_digest,
                },
            ) => {
                if approved_migration.plan.id != migration_id
                    || approved_migration.approval_digest != approval_digest
                {
                    return Err(FolderbaseError::MigrationApprovalMismatch);
                }
                apply_transaction_v1_migration_outcome_with_hook(approved_migration, checkpoint)
            }
            (
                RootClaim::Current { display_root },
                MigrationCommand::Apply {
                    migration_id,
                    approval_digest,
                },
            ) => run_current_transaction_v1_apply_with_hooks(
                display_root,
                migration_id,
                approval_digest,
                || {},
                checkpoint,
                |_| {},
            ),
            (_, _) => Err(FolderbaseError::InvalidMigrationState {
                expected: MigrationState::Approved.as_str(),
                actual: "non_apply_command".to_owned(),
            }),
        }
    }
}

fn apply_transaction_v1_migration_outcome_with_hook(
    approved: ApprovedMigration,
    checkpoint: impl FnMut(ApplyCheckpoint),
) -> Result<MigrationOutcome> {
    apply_transaction_v1_migration_outcome_with_hooks(approved, checkpoint, |_| {})
}

fn apply_transaction_v1_migration_outcome_with_hooks(
    approved: ApprovedMigration,
    mut checkpoint: impl FnMut(ApplyCheckpoint),
    transaction_checkpoint: impl FnMut(TransactionV1Checkpoint),
) -> Result<MigrationOutcome> {
    let in_memory_plan = approved.plan;
    require_state(in_memory_plan.state, MigrationState::Approved)?;
    if plan_digest(&in_memory_plan)? != approved.approval_digest {
        return Err(FolderbaseError::MigrationApprovalMismatch);
    }
    let approved_root_identity = in_memory_plan
        .root_identity
        .as_ref()
        .ok_or_else(|| FolderbaseError::MigrationSourceChanged(in_memory_plan.root.clone()))?
        .identity();
    let transaction_coordinator = acquire_existing_folderbase_transaction_lock_with_hook(
        &in_memory_plan.root,
        approved_root_identity,
        || {
            checkpoint(ApplyCheckpoint::ExistingFolderbaseDetected);
        },
    )?;
    require_no_pending_work_except(&transaction_coordinator.state, &in_memory_plan.id)?;
    let migration_filesystem =
        transaction_coordinator.migration_filesystem(&in_memory_plan.root)?;
    let execution_format = classify_execution_format(&migration_filesystem, &in_memory_plan.id)?;
    apply_transaction_v1_migration_in_with_hooks(
        &migration_filesystem,
        &in_memory_plan.id,
        &approved.approval_digest,
        approved_root_identity.stable_sha256(),
        execution_format,
        checkpoint,
        transaction_checkpoint,
    )
}

fn apply_transaction_v1_migration_in_with_hooks(
    migration_filesystem: &MigrationFilesystem,
    migration_id: &str,
    approval_digest: &str,
    root_identity_sha256: String,
    execution_format: ExecutionFormat,
    mut checkpoint: impl FnMut(ApplyCheckpoint),
    transaction_checkpoint: impl FnMut(TransactionV1Checkpoint),
) -> Result<MigrationOutcome> {
    match execution_format {
        ExecutionFormat::None
        | ExecutionFormat::PrePreparedTransactionV1
        | ExecutionFormat::TransactionV1 => {}
        ExecutionFormat::LegacyResult => {
            return Err(FolderbaseError::InvalidMigrationState {
                expected: MigrationState::Approved.as_str(),
                actual: "legacy_result".to_owned(),
            });
        }
    }
    let plan = load_plan_from(migration_filesystem, migration_id)?;
    require_state(plan.state, MigrationState::Approved)?;
    if plan.approval_digest.as_deref() != Some(approval_digest)
        || plan_digest(&plan)? != approval_digest
    {
        return Err(FolderbaseError::MigrationApprovalMismatch);
    }
    validate_typed_ignore_policy_updates(&plan)?;
    if matches!(
        execution_format,
        ExecutionFormat::None | ExecutionFormat::PrePreparedTransactionV1
    ) {
        let verification = (|| -> Result<()> {
            verify_source_files_in(migration_filesystem, &plan)?;
            if !is_structural_plan(&plan) {
                verify_additive_source_topology_in(migration_filesystem, &plan)?;
                verify_expanded_reconstructable_trees_in(migration_filesystem, &plan)?;
            }
            Ok(())
        })();
        if let Err(error) = verification {
            // A no-follow leaf rejection reports its concrete absolute display
            // path and is a durable migration conflict even before a journal
            // exists. Topology drift remains an Approved plan that the user may
            // restore and retry.
            if matches!(
                &error,
                FolderbaseError::UnsafePath(path) if path.is_absolute()
            ) {
                persist_plan_transition_in(
                    migration_filesystem,
                    &plan.id,
                    &[MigrationState::Approved],
                    MigrationState::Conflicted,
                )?;
            }
            return Err(error);
        }
    }
    checkpoint(ApplyCheckpoint::MutationAuthorityBound);
    let mut transaction = prepare_transaction_v1(
        migration_filesystem,
        &plan,
        approval_digest,
        root_identity_sha256,
    )?;
    checkpoint(ApplyCheckpoint::JournalPrepared);
    let migration_root = PathBuf::from(MIGRATIONS_DIR).join(&plan.id);
    let conflict_recorded = Cell::new(false);
    let mut transaction_checkpoint = transaction_checkpoint;
    let mut tracked_checkpoint = |checkpoint| {
        if matches!(checkpoint, TransactionV1Checkpoint::ConflictRecorded(_)) {
            conflict_recorded.set(true);
        }
        transaction_checkpoint(checkpoint);
    };
    let result = execute_transaction_v1_apply_with_hook(
        migration_filesystem,
        &mut transaction,
        &mut tracked_checkpoint,
    )
    .map(MigrationOutcome::Applied);
    map_durable_transaction_v1_conflict(
        migration_filesystem,
        &migration_root,
        &plan.id,
        result,
        conflict_recorded.get(),
    )
}

#[cfg(test)]
fn applied_result_from_outcome(outcome: MigrationOutcome) -> Result<MigrationResult> {
    match outcome {
        MigrationOutcome::Applied(result) => Ok(result),
        MigrationOutcome::RolledBack(_) | MigrationOutcome::Conflicted { .. } => {
            Err(FolderbaseError::InvalidMigrationState {
                expected: MigrationState::Verified.as_str(),
                actual: MigrationState::Conflicted.as_str().to_owned(),
            })
        }
        MigrationOutcome::RecoveryRequired { work, .. } => {
            Err(FolderbaseError::RecoveryRequired { work })
        }
    }
}

#[cfg(test)]
fn apply_migration_with_transaction_hook(
    approved: ApprovedMigration,
    checkpoint: impl FnMut(TransactionV1Checkpoint),
) -> Result<MigrationResult> {
    applied_result_from_outcome(apply_transaction_v1_migration_outcome_with_hooks(
        approved,
        |_| {},
        checkpoint,
    )?)
}

struct PreparedTransactionV1 {
    program: MutationProgramV1,
    program_digest: String,
    generations: Vec<TransactionJournalGenerationV1>,
    private: PrivateTransactionV1,
}

struct PrivateTransactionV1 {
    _transaction: VerifiedPrivateDirectory,
    journal: VerifiedPrivateDirectory,
    stages: VerifiedPrivateDirectory,
    claims: VerifiedPrivateDirectory,
    snapshots: VerifiedPrivateDirectory,
    receipts: VerifiedPrivateDirectory,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum PrivateReceiptDirectionV1 {
    Apply,
    Rollback,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct PrivateLeafReceiptV1 {
    format: String,
    transaction_id: String,
    program_digest: String,
    operation_index: usize,
    direction: PrivateReceiptDirectionV1,
    before_identity_sha256: Option<String>,
    after_identity_sha256: Option<String>,
    checksum: String,
}

impl PrivateLeafReceiptV1 {
    fn new(
        transaction: &PreparedTransactionV1,
        operation_index: usize,
        direction: PrivateReceiptDirectionV1,
        before_identity_sha256: Option<String>,
        after_identity_sha256: Option<String>,
    ) -> Result<Self> {
        let mut receipt = Self {
            format: "folderbase-private-leaf-receipt-v1".to_owned(),
            transaction_id: transaction.program.transaction_id().to_owned(),
            program_digest: transaction.program_digest.clone(),
            operation_index,
            direction,
            before_identity_sha256,
            after_identity_sha256,
            checksum: String::new(),
        };
        receipt.checksum = receipt.calculate_checksum()?;
        Ok(receipt)
    }

    fn calculate_checksum(&self) -> Result<String> {
        let controlled = (
            &self.format,
            &self.transaction_id,
            &self.program_digest,
            self.operation_index,
            self.direction,
            &self.before_identity_sha256,
            &self.after_identity_sha256,
        );
        let bytes = serde_json::to_vec(&controlled).map_err(|source| {
            FolderbaseError::json(Path::new("<private-leaf-receipt-v1>"), source)
        })?;
        Ok(sha256_bytes(
            [b"folderbase-private-leaf-receipt-v1\0".as_slice(), &bytes]
                .concat()
                .as_slice(),
        ))
    }

    fn encode(&self) -> Result<Vec<u8>> {
        if self.format != "folderbase-private-leaf-receipt-v1"
            || self.checksum != self.calculate_checksum()?
            || self
                .before_identity_sha256
                .as_deref()
                .is_some_and(|digest| !is_sha256(digest))
            || self
                .after_identity_sha256
                .as_deref()
                .is_some_and(|digest| !is_sha256(digest))
        {
            return Err(invalid_journal(
                Path::new("<private-leaf-receipt-v1>"),
                "private leaf receipt is invalid",
            ));
        }
        serde_json::to_vec(self)
            .map_err(|source| FolderbaseError::json(Path::new("<private-leaf-receipt-v1>"), source))
    }

    fn decode(path: &Path, bytes: &[u8]) -> Result<Self> {
        let receipt: Self =
            serde_json::from_slice(bytes).map_err(|source| FolderbaseError::json(path, source))?;
        if receipt.encode()? != bytes {
            return Err(invalid_journal(
                path,
                "private leaf receipt is not canonical",
            ));
        }
        Ok(receipt)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum PrivateAbortClaimV1 {
    Regular {
        name: String,
        physical_identity_sha256: String,
        device_sha256: String,
        bytes: u64,
        sha256: String,
        read_only: bool,
        executable: bool,
        link_count: u64,
    },
    Directory {
        name: String,
        physical_identity_sha256: String,
        device_sha256: String,
        read_only: bool,
        executable: bool,
        empty: bool,
    },
}

impl PrivateAbortClaimV1 {
    fn name(&self) -> &str {
        match self {
            Self::Regular { name, .. } | Self::Directory { name, .. } => name,
        }
    }

    fn is_directory(&self) -> bool {
        matches!(self, Self::Directory { .. })
    }

    fn exact_regular(&self) -> Option<ExactRegularLeaf<'_>> {
        match self {
            Self::Regular {
                physical_identity_sha256,
                device_sha256,
                bytes,
                sha256,
                read_only,
                executable,
                link_count,
                ..
            } => Some(ExactRegularLeaf {
                physical_identity_sha256,
                device_sha256,
                bytes: *bytes,
                sha256,
                read_only: *read_only,
                executable: *executable,
                link_count: *link_count,
            }),
            Self::Directory { .. } => None,
        }
    }

    fn exact_directory(&self) -> Option<ExactDirectoryLeaf<'_>> {
        match self {
            Self::Directory {
                physical_identity_sha256,
                device_sha256,
                read_only,
                executable,
                ..
            } => Some(ExactDirectoryLeaf {
                physical_identity_sha256,
                device_sha256,
                read_only: *read_only,
                executable: *executable,
            }),
            Self::Regular { .. } => None,
        }
    }

    fn validate(&self) -> bool {
        match self {
            Self::Regular {
                name,
                physical_identity_sha256,
                device_sha256,
                sha256,
                link_count,
                ..
            } => {
                !name.is_empty()
                    && Path::new(name).file_name() == Some(OsStr::new(name))
                    && is_sha256(physical_identity_sha256)
                    && is_sha256(device_sha256)
                    && is_sha256(sha256)
                    && *link_count > 0
            }
            Self::Directory {
                name,
                physical_identity_sha256,
                device_sha256,
                empty,
                ..
            } => {
                !name.is_empty()
                    && Path::new(name).file_name() == Some(OsStr::new(name))
                    && is_sha256(physical_identity_sha256)
                    && is_sha256(device_sha256)
                    && *empty
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct PrivateAbortWorkReceiptV1 {
    format: String,
    transaction_id: String,
    program_digest: String,
    operation_index: usize,
    visible_post_identity_sha256: Option<String>,
    claims: Vec<PrivateAbortClaimV1>,
    checksum: String,
}

impl PrivateAbortWorkReceiptV1 {
    fn new(
        transaction: &PreparedTransactionV1,
        operation_index: usize,
        visible_post_identity_sha256: Option<String>,
        mut claims: Vec<PrivateAbortClaimV1>,
    ) -> Result<Self> {
        claims.sort_by(|left, right| left.name().cmp(right.name()));
        let mut receipt = Self {
            format: "folderbase-private-abort-work-v1".to_owned(),
            transaction_id: transaction.program.transaction_id().to_owned(),
            program_digest: transaction.program_digest.clone(),
            operation_index,
            visible_post_identity_sha256,
            claims,
            checksum: String::new(),
        };
        receipt.checksum = receipt.calculate_checksum()?;
        receipt.validate(Path::new("<private-abort-work-receipt-v1>"))?;
        Ok(receipt)
    }

    fn calculate_checksum(&self) -> Result<String> {
        let controlled = (
            &self.format,
            &self.transaction_id,
            &self.program_digest,
            self.operation_index,
            &self.visible_post_identity_sha256,
            &self.claims,
        );
        let bytes = serde_json::to_vec(&controlled).map_err(|source| {
            FolderbaseError::json(Path::new("<private-abort-work-receipt-v1>"), source)
        })?;
        Ok(sha256_bytes(
            [b"folderbase-private-abort-work-v1\0".as_slice(), &bytes]
                .concat()
                .as_slice(),
        ))
    }

    fn validate(&self, path: &Path) -> Result<()> {
        let sorted_unique = self
            .claims
            .windows(2)
            .all(|pair| pair[0].name() < pair[1].name());
        if self.format != "folderbase-private-abort-work-v1"
            || self.checksum != self.calculate_checksum()?
            || self
                .visible_post_identity_sha256
                .as_deref()
                .is_some_and(|digest| !is_sha256(digest))
            || !sorted_unique
            || self.claims.iter().any(|claim| !claim.validate())
        {
            return Err(invalid_journal(
                path,
                "private abort-work receipt is invalid",
            ));
        }
        Ok(())
    }

    fn encode(&self) -> Result<Vec<u8>> {
        self.validate(Path::new("<private-abort-work-receipt-v1>"))?;
        serde_json::to_vec(self).map_err(|source| {
            FolderbaseError::json(Path::new("<private-abort-work-receipt-v1>"), source)
        })
    }

    fn decode(path: &Path, bytes: &[u8]) -> Result<Self> {
        let receipt: Self =
            serde_json::from_slice(bytes).map_err(|source| FolderbaseError::json(path, source))?;
        receipt.validate(path)?;
        if receipt.encode()? != bytes {
            return Err(invalid_journal(
                path,
                "private abort-work receipt is not canonical",
            ));
        }
        Ok(receipt)
    }

    fn encoded_sha256(&self) -> Result<String> {
        Ok(sha256_bytes(&self.encode()?))
    }
}

fn private_claim_name(operation_index: usize, kind: &str) -> String {
    format!("{operation_index:08}.{kind}.claim")
}

fn private_abort_receipt_name(operation_index: usize) -> String {
    format!("{operation_index:08}.abort.receipt")
}

fn private_receipt_name(operation_index: usize, direction: PrivateReceiptDirectionV1) -> String {
    let direction = match direction {
        PrivateReceiptDirectionV1::Apply => "apply",
        PrivateReceiptDirectionV1::Rollback => "rollback",
    };
    format!("{operation_index:08}.{direction}.receipt")
}

fn recoverable_receipt_final_name(name: &OsStr) -> Option<String> {
    name.to_str()?
        .strip_prefix('.')?
        .strip_suffix(".preparing")
        .map(str::to_owned)
}

fn persist_private_leaf_receipt(
    transaction: &PreparedTransactionV1,
    receipt: &PrivateLeafReceiptV1,
) -> Result<()> {
    let name = private_receipt_name(receipt.operation_index, receipt.direction);
    transaction.private.receipts.publish_recoverable_new(
        &name,
        &format!(".{name}.preparing"),
        &receipt.encode()?,
    )?;
    retire_private_publication_ownership_for_receipt(transaction, receipt)
}

fn retire_private_publication_ownership_for_receipt(
    transaction: &PreparedTransactionV1,
    receipt: &PrivateLeafReceiptV1,
) -> Result<()> {
    let kind = match receipt.direction {
        PrivateReceiptDirectionV1::Apply => "publish",
        PrivateReceiptDirectionV1::Rollback => "restore",
    };
    let claim_name = private_claim_name(receipt.operation_index, kind);
    transaction
        .private
        .claims
        .retire_private_publication_ownership(OsStr::new(&claim_name))
}

fn load_private_leaf_receipt(
    transaction: &PreparedTransactionV1,
    operation_index: usize,
    direction: PrivateReceiptDirectionV1,
) -> Result<Option<PrivateLeafReceiptV1>> {
    let name = private_receipt_name(operation_index, direction);
    let bytes = match transaction
        .private
        .receipts
        .read_regular_bounded(OsStr::new(&name), 16 * 1024)
    {
        Ok(bytes) => bytes,
        Err(FolderbaseError::Io { source, .. })
            if source.kind() == std::io::ErrorKind::NotFound =>
        {
            return Ok(None);
        }
        Err(error) => return Err(error),
    };
    let receipt_path = transaction.private.receipts.display_path(OsStr::new(&name));
    let receipt = PrivateLeafReceiptV1::decode(&receipt_path, &bytes)?;
    if receipt.transaction_id != transaction.program.transaction_id()
        || receipt.program_digest != transaction.program_digest
        || receipt.operation_index != operation_index
        || receipt.direction != direction
    {
        return Err(invalid_journal(
            &receipt_path,
            "private leaf receipt is bound to another transaction",
        ));
    }
    Ok(Some(receipt))
}

fn persist_private_abort_work_receipt(
    transaction: &PreparedTransactionV1,
    receipt: &PrivateAbortWorkReceiptV1,
) -> Result<()> {
    let name = private_abort_receipt_name(receipt.operation_index);
    transaction.private.receipts.publish_recoverable_new(
        &name,
        &format!(".{name}.preparing"),
        &receipt.encode()?,
    )
}

fn load_private_abort_work_receipt(
    transaction: &PreparedTransactionV1,
    operation_index: usize,
) -> Result<Option<PrivateAbortWorkReceiptV1>> {
    let name = private_abort_receipt_name(operation_index);
    let bytes = match transaction
        .private
        .receipts
        .read_regular_bounded(OsStr::new(&name), 64 * 1024)
    {
        Ok(bytes) => bytes,
        Err(FolderbaseError::Io { source, .. })
            if source.kind() == std::io::ErrorKind::NotFound =>
        {
            return Ok(None);
        }
        Err(error) => return Err(error),
    };
    let path = transaction.private.receipts.display_path(OsStr::new(&name));
    let receipt = PrivateAbortWorkReceiptV1::decode(&path, &bytes)?;
    if receipt.transaction_id != transaction.program.transaction_id()
        || receipt.program_digest != transaction.program_digest
        || receipt.operation_index != operation_index
    {
        return Err(invalid_journal(
            &path,
            "private abort-work receipt is bound to another transaction",
        ));
    }
    Ok(Some(receipt))
}

fn validate_staged_private_receipt_context(
    filesystem: &MigrationFilesystem,
    transaction: &PreparedTransactionV1,
    final_name: &str,
    bytes: &[u8],
) -> Result<()> {
    let current = transaction
        .generations
        .last()
        .ok_or_else(|| invalid_journal(Path::new("<transaction-v1>"), "journal is empty"))?;
    let in_flight = current.in_flight_operation();
    for operation_index in 0..transaction.program.operation_count() {
        for direction in [
            PrivateReceiptDirectionV1::Apply,
            PrivateReceiptDirectionV1::Rollback,
        ] {
            if final_name != private_receipt_name(operation_index, direction) {
                continue;
            }
            let path = transaction
                .private
                .receipts
                .display_path(OsStr::new(final_name));
            let receipt = PrivateLeafReceiptV1::decode(&path, bytes)?;
            if receipt.transaction_id != transaction.program.transaction_id()
                || receipt.program_digest != transaction.program_digest
                || receipt.operation_index != operation_index
                || receipt.direction != direction
                || in_flight != Some(operation_index)
            {
                return Err(invalid_journal(
                    &path,
                    "staged private leaf receipt is outside the exact in-flight context",
                ));
            }
            let expected_direction = match (
                current.direction(),
                current.phase(),
                current.receipt_identity(operation_index),
            ) {
                (TransactionDirectionV1::Rollback, TransactionPhaseV1::RollbackRequested, None) => {
                    PrivateReceiptDirectionV1::Apply
                }
                (TransactionDirectionV1::Apply, _, _) => PrivateReceiptDirectionV1::Apply,
                (TransactionDirectionV1::Rollback, _, _) => PrivateReceiptDirectionV1::Rollback,
            };
            if direction != expected_direction {
                return Err(invalid_journal(
                    &path,
                    "staged private leaf receipt has the wrong transaction direction",
                ));
            }
            match direction {
                PrivateReceiptDirectionV1::Apply => {
                    let expected_before = match transaction.program.step(operation_index)? {
                        ProgramStepV1::CreateDirectory { .. }
                        | ProgramStepV1::CreateFile { .. } => None,
                        ProgramStepV1::ReplaceFile { target, .. } => {
                            Some(target.physical_identity_sha256.to_owned())
                        }
                        ProgramStepV1::MoveFile { source, .. } => {
                            Some(source.physical_identity_sha256.to_owned())
                        }
                    };
                    if receipt.before_identity_sha256 != expected_before
                        || receipt.after_identity_sha256.is_none()
                    {
                        return Err(invalid_journal(
                            &path,
                            "staged private apply receipt tuple disagrees with the program",
                        ));
                    }
                    verify_apply_private_receipt(filesystem, transaction, operation_index, &receipt)
                }
                PrivateReceiptDirectionV1::Rollback => {
                    let expected_before = current
                        .apply_receipt_records()
                        .into_iter()
                        .find_map(|(index, identity)| {
                            (index == operation_index).then_some(identity)
                        })
                        .ok_or_else(|| {
                            invalid_journal(
                                &path,
                                "staged rollback receipt has no durable apply identity",
                            )
                        })?;
                    let after_shape_is_valid = match transaction.program.step(operation_index)? {
                        ProgramStepV1::CreateDirectory { .. } => {
                            receipt.after_identity_sha256.is_none()
                                || receipt.after_identity_sha256 == expected_before
                        }
                        ProgramStepV1::CreateFile { .. } => receipt.after_identity_sha256.is_none(),
                        ProgramStepV1::ReplaceFile { .. } | ProgramStepV1::MoveFile { .. } => {
                            receipt.after_identity_sha256.is_some()
                        }
                    };
                    if receipt.before_identity_sha256 != expected_before || !after_shape_is_valid {
                        return Err(invalid_journal(
                            &path,
                            "staged private rollback receipt tuple disagrees with the program",
                        ));
                    }
                    verify_rollback_private_receipt(
                        filesystem,
                        transaction,
                        operation_index,
                        &receipt,
                    )
                }
            }?;
            return Ok(());
        }

        if final_name == private_abort_receipt_name(operation_index) {
            let path = transaction
                .private
                .receipts
                .display_path(OsStr::new(final_name));
            let receipt = PrivateAbortWorkReceiptV1::decode(&path, bytes)?;
            if receipt.transaction_id != transaction.program.transaction_id()
                || receipt.program_digest != transaction.program_digest
                || receipt.operation_index != operation_index
                || current.direction() != TransactionDirectionV1::Rollback
                || current.phase() != TransactionPhaseV1::RollbackRequested
                || in_flight != Some(operation_index)
                || current.receipt_identity(operation_index).is_some()
                || current.abort_receipt_sha256(operation_index).is_some()
            {
                return Err(invalid_journal(
                    &path,
                    "staged abort receipt is outside the exact in-flight context",
                ));
            }
            return verify_private_abort_work_receipt(
                filesystem,
                transaction,
                operation_index,
                &receipt,
            );
        }
    }
    Err(invalid_journal(
        Path::new("<private-leaf-receipt-v1>"),
        "staged receipt name is not admitted by the program",
    ))
}

fn repair_recoverable_private_receipt_staging(
    filesystem: &MigrationFilesystem,
    transaction: &PreparedTransactionV1,
) -> Result<()> {
    let maximum_entries = transaction
        .program
        .operation_count()
        .saturating_mul(6)
        .saturating_add(1);
    let entries = transaction
        .private
        .receipts
        .closed_entries(maximum_entries)?;
    let names = entries
        .iter()
        .map(|(name, _)| name.clone())
        .collect::<BTreeSet<_>>();
    let staged_names = names
        .iter()
        .filter(|name| recoverable_receipt_final_name(name).is_some())
        .cloned()
        .collect::<Vec<_>>();
    for staged_name in staged_names {
        let final_name = recoverable_receipt_final_name(&staged_name)
            .expect("staged names were filtered by this parser");
        let final_name_os = OsStr::new(&final_name);
        let final_exists = names.contains(final_name_os);
        let maximum_bytes = if final_name.ends_with(".abort.receipt") {
            64 * 1024
        } else {
            16 * 1024
        };
        let staged_bytes = transaction
            .private
            .receipts
            .read_relaxed_regular_bounded(&staged_name, maximum_bytes)?;
        validate_staged_private_receipt_context(
            filesystem,
            transaction,
            &final_name,
            &staged_bytes,
        )?;
        let (staged_fact, staged_sha256) = transaction
            .private
            .receipts
            .relaxed_regular_fact_observed(&staged_name)?;
        if final_exists {
            let (final_fact, final_sha256) = transaction
                .private
                .receipts
                .relaxed_regular_fact_observed(final_name_os)?;
            if staged_fact.physical_identity_sha256 != final_fact.physical_identity_sha256
                || staged_fact.device_sha256 != final_fact.device_sha256
                || staged_fact.bytes != final_fact.bytes
                || staged_fact.link_count != 2
                || final_fact.link_count != 2
                || staged_sha256 != final_sha256
            {
                return Err(invalid_journal(
                    transaction.private.receipts.display_path(final_name_os),
                    "receipt final and staging are not one exact publication",
                ));
            }
            transaction
                .private
                .receipts
                .retire_exact_recoverable_regular(&staged_name, &staged_fact, &staged_sha256, 2)?;
        } else {
            if staged_fact.link_count != 1 {
                return Err(invalid_journal(
                    transaction.private.receipts.display_path(&staged_name),
                    "receipt staging has an unexpected alias topology",
                ));
            }
            transaction.private.receipts.install_recoverable_regular(
                &staged_name,
                final_name_os,
                &staged_sha256,
                staged_bytes.len() as u64,
            )?;
        }
        transaction.private.receipts.verify_regular(final_name_os)?;
    }
    Ok(())
}

fn validate_private_leaf_receipt_set(transaction: &PreparedTransactionV1) -> Result<()> {
    let current = transaction
        .generations
        .last()
        .ok_or_else(|| invalid_journal(Path::new("<transaction-v1>"), "journal is empty"))?;
    let apply_records = current
        .apply_receipt_records()
        .into_iter()
        .collect::<BTreeMap<_, _>>();
    let rollback_records = current
        .inverse_receipt_records()
        .into_iter()
        .collect::<BTreeMap<_, _>>();
    let mut admitted = BTreeSet::new();

    for (operation_index, expected_identity) in &apply_records {
        let receipt_name = private_receipt_name(*operation_index, PrivateReceiptDirectionV1::Apply);
        let receipt_path = transaction
            .private
            .receipts
            .display_path(OsStr::new(&receipt_name));
        let receipt = load_private_leaf_receipt(
            transaction,
            *operation_index,
            PrivateReceiptDirectionV1::Apply,
        )?
        .ok_or_else(|| {
            invalid_journal(
                &receipt_path,
                "journal apply receipt has no matching private receipt",
            )
        })?;
        let expected_before = match transaction.program.step(*operation_index)? {
            ProgramStepV1::CreateDirectory { .. } | ProgramStepV1::CreateFile { .. } => None,
            ProgramStepV1::ReplaceFile { target, .. } => {
                Some(target.physical_identity_sha256.to_owned())
            }
            ProgramStepV1::MoveFile { source, .. } => {
                Some(source.physical_identity_sha256.to_owned())
            }
        };
        if receipt.before_identity_sha256 != expected_before
            || receipt.after_identity_sha256 != *expected_identity
            || receipt.after_identity_sha256.is_none()
        {
            return Err(invalid_journal(
                Path::new("<private-leaf-receipt-v1>"),
                "private apply receipt tuple disagrees with the program or journal",
            ));
        }
        admitted.insert(OsString::from(private_receipt_name(
            *operation_index,
            PrivateReceiptDirectionV1::Apply,
        )));
    }
    for (operation_index, expected_identity) in &rollback_records {
        let receipt_name =
            private_receipt_name(*operation_index, PrivateReceiptDirectionV1::Rollback);
        let receipt_path = transaction
            .private
            .receipts
            .display_path(OsStr::new(&receipt_name));
        let receipt = load_private_leaf_receipt(
            transaction,
            *operation_index,
            PrivateReceiptDirectionV1::Rollback,
        )?
        .ok_or_else(|| {
            invalid_journal(
                &receipt_path,
                "journal rollback receipt has no matching private receipt",
            )
        })?;
        let expected_before = apply_records.get(operation_index).cloned().ok_or_else(|| {
            invalid_journal(
                Path::new("<private-leaf-receipt-v1>"),
                "private rollback receipt has no durable apply identity",
            )
        })?;
        let after_shape_is_valid = match transaction.program.step(*operation_index)? {
            ProgramStepV1::CreateDirectory { .. } => {
                expected_identity.is_none() || expected_identity == &expected_before
            }
            ProgramStepV1::CreateFile { .. } => expected_identity.is_none(),
            ProgramStepV1::ReplaceFile { .. } | ProgramStepV1::MoveFile { .. } => {
                expected_identity.is_some()
            }
        };
        if receipt.before_identity_sha256 != expected_before
            || receipt.after_identity_sha256 != *expected_identity
            || !after_shape_is_valid
        {
            return Err(invalid_journal(
                Path::new("<private-leaf-receipt-v1>"),
                "private rollback receipt tuple disagrees with the program or journal",
            ));
        }
        admitted.insert(OsString::from(private_receipt_name(
            *operation_index,
            PrivateReceiptDirectionV1::Rollback,
        )));
    }

    if let Some(operation_index) = current.in_flight_operation() {
        let direction = match (
            current.direction(),
            current.phase(),
            current.receipt_identity(operation_index),
        ) {
            (TransactionDirectionV1::Rollback, TransactionPhaseV1::RollbackRequested, None) => {
                PrivateReceiptDirectionV1::Apply
            }
            (TransactionDirectionV1::Apply, _, _) => PrivateReceiptDirectionV1::Apply,
            (TransactionDirectionV1::Rollback, _, _) => PrivateReceiptDirectionV1::Rollback,
        };
        if let Some(receipt) = load_private_leaf_receipt(transaction, operation_index, direction)? {
            let valid = match direction {
                PrivateReceiptDirectionV1::Apply => {
                    let expected_before = match transaction.program.step(operation_index)? {
                        ProgramStepV1::CreateDirectory { .. }
                        | ProgramStepV1::CreateFile { .. } => None,
                        ProgramStepV1::ReplaceFile { target, .. } => {
                            Some(target.physical_identity_sha256.to_owned())
                        }
                        ProgramStepV1::MoveFile { source, .. } => {
                            Some(source.physical_identity_sha256.to_owned())
                        }
                    };
                    receipt.before_identity_sha256 == expected_before
                        && receipt.after_identity_sha256.is_some()
                }
                PrivateReceiptDirectionV1::Rollback => {
                    let expected_before =
                        apply_records
                            .get(&operation_index)
                            .cloned()
                            .ok_or_else(|| {
                                invalid_journal(
                                    Path::new("<private-leaf-receipt-v1>"),
                                    "in-flight rollback receipt has no durable apply identity",
                                )
                            })?;
                    let after_shape_is_valid = match transaction.program.step(operation_index)? {
                        ProgramStepV1::CreateDirectory { .. } => {
                            receipt.after_identity_sha256.is_none()
                                || receipt.after_identity_sha256 == expected_before
                        }
                        ProgramStepV1::CreateFile { .. } => receipt.after_identity_sha256.is_none(),
                        ProgramStepV1::ReplaceFile { .. } | ProgramStepV1::MoveFile { .. } => {
                            receipt.after_identity_sha256.is_some()
                        }
                    };
                    receipt.before_identity_sha256 == expected_before && after_shape_is_valid
                }
            };
            if !valid {
                return Err(invalid_journal(
                    Path::new("<private-leaf-receipt-v1>"),
                    "in-flight private receipt tuple disagrees with the program or journal",
                ));
            }
            admitted.insert(OsString::from(private_receipt_name(
                operation_index,
                direction,
            )));
        }
    }

    for (operation_index, expected_sha256) in current.abort_receipt_records() {
        let name = private_abort_receipt_name(operation_index);
        let path = transaction.private.receipts.display_path(OsStr::new(&name));
        let receipt =
            load_private_abort_work_receipt(transaction, operation_index)?.ok_or_else(|| {
                invalid_journal(
                    &path,
                    "journal abort receipt has no matching private abort-work receipt",
                )
            })?;
        if receipt.encoded_sha256()? != expected_sha256 {
            return Err(invalid_journal(
                &path,
                "private abort-work receipt digest disagrees with the journal",
            ));
        }
        admitted.insert(OsString::from(name));
    }

    if current.direction() == TransactionDirectionV1::Rollback
        && current.phase() == TransactionPhaseV1::RollbackRequested
        && let Some(operation_index) = current.in_flight_operation()
        && current.receipt_identity(operation_index).is_none()
        && current.abort_receipt_sha256(operation_index).is_none()
        && let Some(_receipt) = load_private_abort_work_receipt(transaction, operation_index)?
    {
        admitted.insert(OsString::from(private_abort_receipt_name(operation_index)));
    }

    let actual = transaction
        .private
        .receipts
        .closed_regular_file_names(
            transaction
                .program
                .operation_count()
                .saturating_mul(3)
                .saturating_add(1),
        )?
        .into_iter()
        .collect::<BTreeSet<_>>();
    if actual != admitted {
        return Err(invalid_journal(
            Path::new("<private-leaf-receipt-v1>"),
            "private receipt set is ahead of or inconsistent with the durable journal",
        ));
    }
    Ok(())
}

fn validate_private_abort_work_receipts(
    filesystem: &MigrationFilesystem,
    transaction: &PreparedTransactionV1,
) -> Result<()> {
    let current = transaction
        .generations
        .last()
        .ok_or_else(|| invalid_journal(Path::new("<transaction-v1>"), "journal is empty"))?;
    for (operation_index, expected_sha256) in current.abort_receipt_records() {
        let name = private_abort_receipt_name(operation_index);
        let path = transaction.private.receipts.display_path(OsStr::new(&name));
        let receipt =
            load_private_abort_work_receipt(transaction, operation_index)?.ok_or_else(|| {
                invalid_journal(
                    &path,
                    "journal abort receipt has no matching private abort-work receipt",
                )
            })?;
        if receipt.encoded_sha256()? != expected_sha256 {
            return Err(invalid_journal(
                &path,
                "journal abort receipt disagrees with its private exact bytes",
            ));
        }
        verify_private_abort_work_receipt(filesystem, transaction, operation_index, &receipt)?;
    }
    if current.direction() == TransactionDirectionV1::Rollback
        && current.phase() == TransactionPhaseV1::RollbackRequested
        && let Some(operation_index) = current.in_flight_operation()
        && current.receipt_identity(operation_index).is_none()
        && current.abort_receipt_sha256(operation_index).is_none()
        && let Some(receipt) = load_private_abort_work_receipt(transaction, operation_index)?
    {
        verify_private_abort_work_receipt(filesystem, transaction, operation_index, &receipt)?;
    }
    Ok(())
}

fn append_transaction_v1_generation(
    filesystem: &MigrationFilesystem,
    transaction: &mut PreparedTransactionV1,
    generation: TransactionJournalGenerationV1,
) -> Result<()> {
    validate_append(
        &transaction.program,
        &transaction.program_digest,
        &transaction.generations,
        &generation,
    )?;
    let journal_root = PathBuf::from(MIGRATIONS_DIR)
        .join(transaction.program.transaction_id())
        .join(TRANSACTION_DIRECTORY)
        .join("journal");
    let generation_name = generation.file_name();
    let path = journal_root.join(&generation_name);
    let bytes = generation.encode(&filesystem.display(&path))?;
    transaction.private.journal.publish_recoverable_new(
        &generation_name,
        JOURNAL_GENERATION_STAGING_NAME,
        &bytes,
    )?;
    let reopened_bytes = transaction
        .private
        .journal
        .read_regular_bounded(OsStr::new(&generation_name), MAX_JOURNAL_GENERATION_BYTES)?;
    let reopened =
        TransactionJournalGenerationV1::decode(&filesystem.display(&path), &reopened_bytes)?;
    if reopened != generation {
        return Err(FolderbaseError::MigrationVerificationFailed(
            filesystem.display(&path),
        ));
    }
    transaction.generations.push(reopened);
    validate_chain(
        &transaction.program,
        &transaction.program_digest,
        &transaction.generations,
    )
}

fn transaction_v1_journal_path(migration_id: &str) -> PathBuf {
    PathBuf::from(MIGRATIONS_DIR)
        .join(migration_id)
        .join(TRANSACTION_DIRECTORY)
        .join("journal")
}

fn transaction_v1_result(
    filesystem: &MigrationFilesystem,
    transaction: &PreparedTransactionV1,
    state: MigrationState,
) -> MigrationResult {
    MigrationResult {
        migration_id: transaction.program.transaction_id().to_owned(),
        root: filesystem.display_root().to_path_buf(),
        state,
        created_paths: transaction.program.created_paths(),
        journal_path: transaction_v1_journal_path(transaction.program.transaction_id()),
    }
}

fn private_blob_directory<'a>(
    transaction: &'a PreparedTransactionV1,
    blob: &ProgramPrivateBlobV1<'_>,
) -> Result<&'a VerifiedPrivateDirectory> {
    match blob.directory {
        "stages" => Ok(&transaction.private.stages),
        "snapshots" => Ok(&transaction.private.snapshots),
        _ => Err(invalid_journal(
            Path::new("<mutation-program-v1>"),
            "program blob names an unsupported private directory",
        )),
    }
}

fn regular_fact_matches_program(
    filesystem: &MigrationFilesystem,
    path: &Path,
    expected_identity: Option<&str>,
    expected_bytes: u64,
    expected_sha256: &str,
    expected_read_only: bool,
    expected_executable: bool,
) -> Result<Option<String>> {
    let Some(metadata) = filesystem.metadata(path)? else {
        return Ok(None);
    };
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Ok(None);
    }
    let fact = match filesystem.regular_fact_with_sha256(path, Some(expected_sha256)) {
        Ok(fact) => fact,
        Err(FolderbaseError::MigrationSourceChanged(_)) => return Ok(None),
        Err(error) => return Err(error),
    };
    let fidelity = transaction_v1::ProgramFidelityV1 {
        read_only: fact.read_only,
        executable: regular_fact_executable(&fact),
    };
    if fact.bytes == expected_bytes
        && expected_identity.is_none_or(|identity| identity == fact.physical_identity_sha256)
        && fidelity.read_only == expected_read_only
        && fidelity.executable == expected_executable
    {
        Ok(Some(fact.physical_identity_sha256))
    } else {
        Ok(None)
    }
}

fn require_program_absent(
    filesystem: &MigrationFilesystem,
    target: ProgramAbsentLeafV1<'_>,
) -> Result<()> {
    if filesystem.metadata(target.path)?.is_some() {
        return Err(FolderbaseError::WouldOverwrite(
            filesystem.display(target.path),
        ));
    }
    let parent = target.path.parent().unwrap_or_else(|| Path::new(""));
    for name in filesystem.directory_entry_names(parent, 65_536)? {
        if portable_path_key(Path::new(&name))
            == portable_path_key(Path::new(target.path.file_name().ok_or_else(|| {
                invalid_journal(target.path, "program target has no leaf name")
            })?))
        {
            return Err(FolderbaseError::WouldOverwrite(
                filesystem.display(target.path),
            ));
        }
    }
    Ok(())
}

fn transaction_v1_environment_path(step: ProgramStepV1<'_>) -> Option<&Path> {
    let path = match step {
        ProgramStepV1::CreateDirectory { .. } => return None,
        ProgramStepV1::CreateFile { target, .. } => target.path,
        ProgramStepV1::ReplaceFile { target, .. } => target.path,
        ProgramStepV1::MoveFile { source, .. } => source.path,
    };
    matches!(
        path,
        path if path == Path::new(".folderbase/manifest.json")
            || path == Path::new(".folderbaseignore")
    )
    .then_some(path)
}

fn transaction_v1_post_environment_matches(
    filesystem: &MigrationFilesystem,
    step: ProgramStepV1<'_>,
    expected_identity: &str,
) -> Result<bool> {
    let (path, image) = match step {
        ProgramStepV1::CreateFile { target, image } => (target.path, image),
        ProgramStepV1::ReplaceFile { target, image, .. } => (target.path, image),
        _ => return Ok(false),
    };
    Ok(regular_fact_matches_program(
        filesystem,
        path,
        Some(expected_identity),
        image.bytes,
        image.sha256,
        image.fidelity.read_only,
        image.fidelity.executable,
    )?
    .is_some())
}

fn transaction_v1_pre_environment_matches(
    filesystem: &MigrationFilesystem,
    step: ProgramStepV1<'_>,
    expected_identity: &str,
) -> Result<bool> {
    let target = match step {
        ProgramStepV1::ReplaceFile { target, .. } => target,
        _ => return Ok(false),
    };
    Ok(regular_fact_matches_program(
        filesystem,
        target.path,
        Some(expected_identity),
        target.bytes,
        target.sha256,
        target.fidelity.read_only,
        target.fidelity.executable,
    )?
    .is_some())
}

fn transaction_v1_private_regular_claim(
    transaction: &PreparedTransactionV1,
    operation_index: usize,
    kind: &str,
    expected_sha256: &str,
    expected_bytes: u64,
) -> Result<Option<MigrationRegularFact>> {
    let name = private_claim_name(operation_index, kind);
    match transaction
        .private
        .claims
        .relaxed_regular_fact(OsStr::new(&name), expected_sha256)
    {
        Ok(fact) if fact.bytes == expected_bytes => Ok(Some(fact)),
        Ok(_) => Err(FolderbaseError::MigrationVerificationFailed(
            transaction.private.claims.display_path(OsStr::new(&name)),
        )),
        Err(FolderbaseError::Io { source, .. })
            if source.kind() == std::io::ErrorKind::NotFound =>
        {
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

fn validate_transaction_v1_environment_leaf(
    filesystem: &MigrationFilesystem,
    transaction: &PreparedTransactionV1,
    current: &TransactionJournalGenerationV1,
    path: &Path,
) -> Result<()> {
    let current_environment_operation = match current.in_flight_operation() {
        Some(index) => {
            let step = transaction.program.step(index)?;
            (transaction_v1_environment_path(step) == Some(path)).then_some((index, step))
        }
        None => None,
    };

    if let Some((operation_index, step)) = current_environment_operation {
        match (current.direction(), step) {
            (TransactionDirectionV1::Apply, ProgramStepV1::ReplaceFile { target, image, .. }) => {
                let source = transaction_v1_private_regular_claim(
                    transaction,
                    operation_index,
                    "source",
                    target.sha256,
                    target.bytes,
                )?;
                let Some(source) = source else {
                    return transaction
                        .program
                        .validate_initial_environment_leaf(filesystem, path);
                };
                if source.physical_identity_sha256 != target.physical_identity_sha256 {
                    return Err(FolderbaseError::MigrationVerificationFailed(
                        transaction
                            .private
                            .claims
                            .display_path(OsStr::new(&private_claim_name(
                                operation_index,
                                "source",
                            ))),
                    ));
                }
                let publish =
                    transaction_v1_private_regular_claim(
                        transaction,
                        operation_index,
                        "publish",
                        image.sha256,
                        image.bytes,
                    )?
                    .ok_or_else(|| {
                        FolderbaseError::MigrationVerificationFailed(
                            transaction.private.claims.display_path(OsStr::new(
                                &private_claim_name(operation_index, "publish"),
                            )),
                        )
                    })?;
                if let Some(receipt) = load_private_leaf_receipt(
                    transaction,
                    operation_index,
                    PrivateReceiptDirectionV1::Apply,
                )? {
                    if receipt.before_identity_sha256.as_deref()
                        != Some(target.physical_identity_sha256)
                        || receipt.after_identity_sha256.as_deref()
                            != Some(publish.physical_identity_sha256.as_str())
                    {
                        return Err(FolderbaseError::MigrationVerificationFailed(
                            transaction.private.receipts.display_path(OsStr::new(
                                &private_receipt_name(
                                    operation_index,
                                    PrivateReceiptDirectionV1::Apply,
                                ),
                            )),
                        ));
                    }
                    return require_environment_match(
                        filesystem,
                        path,
                        transaction_v1_post_environment_matches(
                            filesystem,
                            step,
                            &publish.physical_identity_sha256,
                        )?,
                    );
                }
                if filesystem.metadata(path)?.is_none() {
                    return Ok(());
                }
                return require_environment_match(
                    filesystem,
                    path,
                    transaction_v1_post_environment_matches(
                        filesystem,
                        step,
                        &publish.physical_identity_sha256,
                    )?,
                );
            }
            (
                TransactionDirectionV1::Rollback,
                ProgramStepV1::ReplaceFile { target, image, .. },
            ) => {
                let applied_identity =
                    current.receipt_identity(operation_index).ok_or_else(|| {
                        invalid_journal(path, "rollback environment step has no apply identity")
                    })?;
                if let Some(receipt) = load_private_leaf_receipt(
                    transaction,
                    operation_index,
                    PrivateReceiptDirectionV1::Rollback,
                )? {
                    let restored_identity =
                        receipt.after_identity_sha256.as_deref().ok_or_else(|| {
                            invalid_journal(
                                Path::new("<private-leaf-receipt-v1>"),
                                "environment rollback receipt has no restored identity",
                            )
                        })?;
                    if receipt.before_identity_sha256.as_deref() != Some(applied_identity) {
                        return Err(FolderbaseError::MigrationVerificationFailed(
                            transaction.private.receipts.display_path(OsStr::new(
                                &private_receipt_name(
                                    operation_index,
                                    PrivateReceiptDirectionV1::Rollback,
                                ),
                            )),
                        ));
                    }
                    return require_environment_match(
                        filesystem,
                        path,
                        transaction_v1_pre_environment_matches(
                            filesystem,
                            step,
                            restored_identity,
                        )?,
                    );
                }
                if let Some(restore) = transaction_v1_private_regular_claim(
                    transaction,
                    operation_index,
                    "restore",
                    target.sha256,
                    target.bytes,
                )? {
                    if filesystem.metadata(path)?.is_none() {
                        return Ok(());
                    }
                    return require_environment_match(
                        filesystem,
                        path,
                        transaction_v1_pre_environment_matches(
                            filesystem,
                            step,
                            &restore.physical_identity_sha256,
                        )?,
                    );
                }
                if let Some(rollback) = transaction_v1_private_regular_claim(
                    transaction,
                    operation_index,
                    "rollback",
                    image.sha256,
                    image.bytes,
                )? {
                    if rollback.physical_identity_sha256 != applied_identity {
                        return Err(FolderbaseError::MigrationVerificationFailed(
                            transaction.private.claims.display_path(OsStr::new(
                                &private_claim_name(operation_index, "rollback"),
                            )),
                        ));
                    }
                    return if filesystem.metadata(path)?.is_none() {
                        Ok(())
                    } else {
                        Err(FolderbaseError::MigrationSourceChanged(
                            filesystem.display(path),
                        ))
                    };
                }
                return require_environment_match(
                    filesystem,
                    path,
                    transaction_v1_post_environment_matches(filesystem, step, applied_identity)?,
                );
            }
            _ => {}
        }
        return Err(FolderbaseError::MigrationSourceChanged(
            filesystem.display(path),
        ));
    }

    let inverse_records = current.inverse_receipt_records();
    let inverse = inverse_records
        .iter()
        .map(|(index, _)| *index)
        .collect::<BTreeSet<_>>();
    for (operation_index, expected_identity) in current.apply_receipt_records().into_iter().rev() {
        if inverse.contains(&operation_index) {
            continue;
        }
        let step = transaction.program.step(operation_index)?;
        if transaction_v1_environment_path(step) != Some(path) {
            continue;
        }
        let expected_identity = expected_identity.ok_or_else(|| {
            invalid_journal(
                path,
                "environment replacement has no durable published identity",
            )
        })?;
        if transaction_v1_post_environment_matches(filesystem, step, &expected_identity)? {
            return Ok(());
        }
        return Err(FolderbaseError::MigrationSourceChanged(
            filesystem.display(path),
        ));
    }

    for (operation_index, restored_identity) in inverse_records.into_iter().rev() {
        let step = transaction.program.step(operation_index)?;
        if transaction_v1_environment_path(step) != Some(path) {
            continue;
        }
        let restored_identity = restored_identity.ok_or_else(|| {
            invalid_journal(
                path,
                "environment rollback has no durable restored identity",
            )
        })?;
        if transaction_v1_pre_environment_matches(filesystem, step, &restored_identity)? {
            return Ok(());
        }
        return Err(FolderbaseError::MigrationSourceChanged(
            filesystem.display(path),
        ));
    }

    transaction
        .program
        .validate_initial_environment_leaf(filesystem, path)
}

fn require_environment_match(
    filesystem: &MigrationFilesystem,
    path: &Path,
    matches: bool,
) -> Result<()> {
    if matches {
        Ok(())
    } else {
        Err(FolderbaseError::MigrationSourceChanged(
            filesystem.display(path),
        ))
    }
}

fn validate_transaction_v1_environment(
    filesystem: &MigrationFilesystem,
    transaction: &PreparedTransactionV1,
    current: &TransactionJournalGenerationV1,
) -> Result<()> {
    transaction.program.validate_root_and_state(filesystem)?;
    validate_transaction_v1_environment_leaf(
        filesystem,
        transaction,
        current,
        Path::new(".folderbase/manifest.json"),
    )?;
    validate_transaction_v1_environment_leaf(
        filesystem,
        transaction,
        current,
        Path::new(".folderbaseignore"),
    )
}

fn apply_transaction_v1_step(
    filesystem: &MigrationFilesystem,
    transaction: &PreparedTransactionV1,
    operation_index: usize,
    checkpoint: &mut impl FnMut(TransactionV1Checkpoint),
) -> Result<Option<String>> {
    let current = transaction
        .generations
        .last()
        .ok_or_else(|| invalid_journal(Path::new("<transaction-v1>"), "journal is empty"))?;
    validate_transaction_v1_environment(filesystem, transaction, current)?;
    let retained_parents =
        transaction
            .program
            .retain_step_parents(filesystem, operation_index, current)?;
    let validate_parents = || {
        let current = transaction
            .generations
            .last()
            .ok_or_else(|| invalid_journal(Path::new("<transaction-v1>"), "journal is empty"))?;
        validate_transaction_v1_environment(filesystem, transaction, current)?;
        transaction
            .program
            .validate_step_parents(filesystem, operation_index, current)
    };
    validate_parents()?;
    if let ProgramStepV1::CreateDirectory { target, fidelity } =
        transaction.program.step(operation_index)?
    {
        let claim_name = private_claim_name(operation_index, "publish");
        let receipt = match load_private_leaf_receipt(
            transaction,
            operation_index,
            PrivateReceiptDirectionV1::Apply,
        )? {
            Some(receipt) => receipt,
            None => {
                let claim = transaction.private.claims.prepare_directory_claim(
                    &claim_name,
                    fidelity.read_only,
                    fidelity.executable,
                )?;
                checkpoint(TransactionV1Checkpoint::ClaimComplete(operation_index));
                let receipt = PrivateLeafReceiptV1::new(
                    transaction,
                    operation_index,
                    PrivateReceiptDirectionV1::Apply,
                    None,
                    Some(claim.physical_identity_sha256),
                )?;
                persist_private_leaf_receipt(transaction, &receipt)?;
                receipt
            }
        };
        let expected_identity = receipt.after_identity_sha256.as_deref().ok_or_else(|| {
            invalid_journal(
                Path::new("<private-leaf-receipt-v1>"),
                "directory apply receipt has no published identity",
            )
        })?;
        let visible_matches = match filesystem.directory_fact(target.path) {
            Ok(fact) => fact.physical_identity_sha256 == expected_identity,
            Err(FolderbaseError::Io { source, .. })
                if source.kind() == std::io::ErrorKind::NotFound =>
            {
                false
            }
            Err(error) => return Err(error),
        };
        if !visible_matches {
            if filesystem.metadata(target.path)?.is_none() {
                require_program_absent(filesystem, target)?;
            }
            validate_parents()?;
            checkpoint(TransactionV1Checkpoint::ParentsRevalidatedBeforePublish(
                operation_index,
            ));
            let destination_name = target
                .path
                .file_name()
                .ok_or_else(|| invalid_journal(target.path, "program target has no leaf name"))?;
            filesystem.publish_private_directory_claim_new_through(
                &transaction.private.claims,
                OsStr::new(&claim_name),
                retained_parents.get(target.parent)?,
                destination_name,
                expected_identity,
            )?;
        }
        checkpoint(TransactionV1Checkpoint::VisiblePublishComplete(
            operation_index,
        ));
        validate_parents()?;
        let fact = filesystem.directory_fact(target.path)?;
        let read_only = fact.read_only;
        let executable = directory_fact_executable(&fact);
        if fact.physical_identity_sha256 != expected_identity
            || read_only != fidelity.read_only
            || executable != fidelity.executable
        {
            return Err(FolderbaseError::MigrationVerificationFailed(
                filesystem.display(target.path),
            ));
        }
        checkpoint(TransactionV1Checkpoint::PrivateApplyReceiptPersisted(
            operation_index,
        ));
        return Ok(receipt.after_identity_sha256);
    }
    if let Some(receipt) = load_private_leaf_receipt(
        transaction,
        operation_index,
        PrivateReceiptDirectionV1::Apply,
    )? {
        verify_apply_private_receipt(filesystem, transaction, operation_index, &receipt)?;
        return Ok(receipt.after_identity_sha256);
    }
    let (before_identity, after_identity) = match transaction.program.step(operation_index)? {
        ProgramStepV1::CreateDirectory { .. } => unreachable!("handled before regular leaves"),
        ProgramStepV1::CreateFile { target, image } => {
            let claim_name = private_claim_name(operation_index, "publish");
            let claim = filesystem.prepare_private_publish_claim(
                private_blob_directory(transaction, &image)?,
                image.name,
                &transaction.private.claims,
                &claim_name,
                image.sha256,
                image.bytes,
                image.fidelity.read_only,
                image.fidelity.executable,
                || {
                    checkpoint(TransactionV1Checkpoint::PrivatePublishClaimStaged(
                        operation_index,
                    ));
                },
            )?;
            checkpoint(TransactionV1Checkpoint::ClaimComplete(operation_index));
            if filesystem.metadata(target.path)?.is_none() {
                require_program_absent(filesystem, target)?;
            }
            validate_parents()?;
            checkpoint(TransactionV1Checkpoint::ParentsRevalidatedBeforePublish(
                operation_index,
            ));
            let destination_name = target
                .path
                .file_name()
                .ok_or_else(|| invalid_journal(target.path, "program target has no leaf name"))?;
            let published = filesystem.publish_private_claim_new_through(
                &transaction.private.claims,
                OsStr::new(&claim_name),
                retained_parents.get(target.parent)?,
                destination_name,
                &claim.physical_identity_sha256,
                image.sha256,
                image.bytes,
            )?;
            checkpoint(TransactionV1Checkpoint::VisiblePublishComplete(
                operation_index,
            ));
            validate_parents()?;
            (None, Some(published.physical_identity_sha256))
        }
        ProgramStepV1::ReplaceFile { target, image, .. } => {
            let publish_name = private_claim_name(operation_index, "publish");
            let publish_claim = filesystem.prepare_private_publish_claim(
                private_blob_directory(transaction, &image)?,
                image.name,
                &transaction.private.claims,
                &publish_name,
                image.sha256,
                image.bytes,
                image.fidelity.read_only,
                image.fidelity.executable,
                || {
                    checkpoint(TransactionV1Checkpoint::PrivatePublishClaimStaged(
                        operation_index,
                    ));
                },
            )?;
            checkpoint(TransactionV1Checkpoint::ReplacePublishClaimPrepared(
                operation_index,
            ));
            let source_name = private_claim_name(operation_index, "source");
            let source_leaf_name = target
                .path
                .file_name()
                .ok_or_else(|| invalid_journal(target.path, "program target has no leaf name"))?;
            let existing_source = if filesystem.metadata(target.path)?.is_some() {
                let published_link_count = target.link_count.checked_add(1).ok_or_else(|| {
                    FolderbaseError::MigrationSourceChanged(filesystem.display(target.path))
                })?;
                ExactExistingClaimSource::Regular(ExactRegularLeaf {
                    physical_identity_sha256: &publish_claim.physical_identity_sha256,
                    device_sha256: target.device_sha256,
                    bytes: image.bytes,
                    sha256: image.sha256,
                    read_only: image.fidelity.read_only,
                    executable: image.fidelity.executable,
                    link_count: published_link_count,
                })
            } else {
                ExactExistingClaimSource::Absent
            };
            validate_parents()?;
            let source_claim = match filesystem.claim_exact_leaf_through(ExactLeafClaimRequest {
                source_parent: retained_parents.get(target.parent)?,
                source_name: source_leaf_name,
                destination: &transaction.private.claims,
                destination_name: &source_name,
                expectation: ExactLeafClaimExpectation::Regular(ExactRegularLeaf {
                    physical_identity_sha256: target.physical_identity_sha256,
                    device_sha256: target.device_sha256,
                    bytes: target.bytes,
                    sha256: target.sha256,
                    read_only: target.fidelity.read_only,
                    executable: target.fidelity.executable,
                    link_count: target.link_count,
                }),
                existing_source,
            })? {
                ExactLeafClaimResult::Regular(fact) => fact,
                ExactLeafClaimResult::Directory(_) => {
                    return Err(FolderbaseError::MigrationVerificationFailed(
                        transaction
                            .private
                            .claims
                            .display_path(OsStr::new(&source_name)),
                    ));
                }
            };
            checkpoint(TransactionV1Checkpoint::ClaimComplete(operation_index));
            validate_parents()?;
            checkpoint(TransactionV1Checkpoint::ParentsRevalidatedBeforePublish(
                operation_index,
            ));
            let destination_name = target
                .path
                .file_name()
                .ok_or_else(|| invalid_journal(target.path, "program target has no leaf name"))?;
            let published = filesystem.publish_private_claim_new_through(
                &transaction.private.claims,
                OsStr::new(&publish_name),
                retained_parents.get(target.parent)?,
                destination_name,
                &publish_claim.physical_identity_sha256,
                image.sha256,
                image.bytes,
            )?;
            checkpoint(TransactionV1Checkpoint::VisiblePublishComplete(
                operation_index,
            ));
            validate_parents()?;
            (
                Some(source_claim.physical_identity_sha256),
                Some(published.physical_identity_sha256),
            )
        }
        ProgramStepV1::MoveFile {
            source,
            destination,
            ..
        } => {
            let source_name = private_claim_name(operation_index, "source");
            let source_leaf_name = source
                .path
                .file_name()
                .ok_or_else(|| invalid_journal(source.path, "program source has no leaf name"))?;
            let destination_is_published = regular_fact_matches_program(
                filesystem,
                destination.path,
                Some(source.physical_identity_sha256),
                source.bytes,
                source.sha256,
                source.fidelity.read_only,
                source.fidelity.executable,
            )?
            .is_some();
            let expected_claim_link_count = if destination_is_published {
                source.link_count.checked_add(1).ok_or_else(|| {
                    FolderbaseError::MigrationSourceChanged(filesystem.display(source.path))
                })?
            } else {
                source.link_count
            };
            if destination_is_published {
                transaction.private.claims.exact_regular_fact(
                    OsStr::new(&source_name),
                    ExactRegularLeaf {
                        physical_identity_sha256: source.physical_identity_sha256,
                        device_sha256: source.device_sha256,
                        bytes: source.bytes,
                        sha256: source.sha256,
                        read_only: source.fidelity.read_only,
                        executable: source.fidelity.executable,
                        link_count: expected_claim_link_count,
                    },
                )?;
            }
            validate_parents()?;
            let source_claim = match filesystem.claim_exact_leaf_through(ExactLeafClaimRequest {
                source_parent: retained_parents.get(source.parent)?,
                source_name: source_leaf_name,
                destination: &transaction.private.claims,
                destination_name: &source_name,
                expectation: ExactLeafClaimExpectation::Regular(ExactRegularLeaf {
                    physical_identity_sha256: source.physical_identity_sha256,
                    device_sha256: source.device_sha256,
                    bytes: source.bytes,
                    sha256: source.sha256,
                    read_only: source.fidelity.read_only,
                    executable: source.fidelity.executable,
                    link_count: expected_claim_link_count,
                }),
                existing_source: ExactExistingClaimSource::Absent,
            })? {
                ExactLeafClaimResult::Regular(fact) => fact,
                ExactLeafClaimResult::Directory(_) => {
                    return Err(FolderbaseError::MigrationVerificationFailed(
                        transaction
                            .private
                            .claims
                            .display_path(OsStr::new(&source_name)),
                    ));
                }
            };
            checkpoint(TransactionV1Checkpoint::ClaimComplete(operation_index));
            if filesystem.metadata(destination.path)?.is_none() {
                require_program_absent(filesystem, destination)?;
            }
            validate_parents()?;
            checkpoint(TransactionV1Checkpoint::ParentsRevalidatedBeforePublish(
                operation_index,
            ));
            let destination_name = destination.path.file_name().ok_or_else(|| {
                invalid_journal(destination.path, "program destination has no leaf name")
            })?;
            let published = filesystem.publish_private_claim_new_through(
                &transaction.private.claims,
                OsStr::new(&source_name),
                retained_parents.get(destination.parent)?,
                destination_name,
                &source_claim.physical_identity_sha256,
                source.sha256,
                source.bytes,
            )?;
            checkpoint(TransactionV1Checkpoint::VisiblePublishComplete(
                operation_index,
            ));
            validate_parents()?;
            (
                Some(source_claim.physical_identity_sha256),
                Some(published.physical_identity_sha256),
            )
        }
    };
    let receipt = PrivateLeafReceiptV1::new(
        transaction,
        operation_index,
        PrivateReceiptDirectionV1::Apply,
        before_identity,
        after_identity.clone(),
    )?;
    persist_private_leaf_receipt(transaction, &receipt)?;
    checkpoint(TransactionV1Checkpoint::PrivateApplyReceiptPersisted(
        operation_index,
    ));
    Ok(after_identity)
}

fn verify_apply_private_receipt(
    filesystem: &MigrationFilesystem,
    transaction: &PreparedTransactionV1,
    operation_index: usize,
    receipt: &PrivateLeafReceiptV1,
) -> Result<()> {
    let expected_identity = receipt.after_identity_sha256.as_deref().ok_or_else(|| {
        invalid_journal(
            Path::new("<private-leaf-receipt-v1>"),
            "apply receipt has no published identity",
        )
    })?;
    match transaction.program.step(operation_index)? {
        ProgramStepV1::CreateDirectory { target, fidelity } => {
            filesystem.exact_directory_fact(
                target.path,
                ExactDirectoryLeaf {
                    physical_identity_sha256: expected_identity,
                    device_sha256: target.device_sha256,
                    read_only: fidelity.read_only,
                    executable: fidelity.executable,
                },
                false,
            )?;
        }
        ProgramStepV1::CreateFile { target, image } => {
            let expected = ExactRegularLeaf {
                physical_identity_sha256: expected_identity,
                device_sha256: target.device_sha256,
                bytes: image.bytes,
                sha256: image.sha256,
                read_only: image.fidelity.read_only,
                executable: image.fidelity.executable,
                link_count: 2,
            };
            filesystem.exact_regular_fact(target.path, expected)?;
            transaction.private.claims.exact_regular_fact(
                OsStr::new(&private_claim_name(operation_index, "publish")),
                expected,
            )?;
        }
        ProgramStepV1::ReplaceFile { target, image, .. } => {
            let published_link_count = target.link_count.checked_add(1).ok_or_else(|| {
                FolderbaseError::MigrationVerificationFailed(filesystem.display(target.path))
            })?;
            let published = ExactRegularLeaf {
                physical_identity_sha256: expected_identity,
                device_sha256: target.device_sha256,
                bytes: image.bytes,
                sha256: image.sha256,
                read_only: image.fidelity.read_only,
                executable: image.fidelity.executable,
                link_count: published_link_count,
            };
            filesystem.exact_regular_fact(target.path, published)?;
            transaction.private.claims.exact_regular_fact(
                OsStr::new(&private_claim_name(operation_index, "publish")),
                published,
            )?;
            transaction.private.claims.exact_regular_fact(
                OsStr::new(&private_claim_name(operation_index, "source")),
                ExactRegularLeaf {
                    physical_identity_sha256: target.physical_identity_sha256,
                    device_sha256: target.device_sha256,
                    bytes: target.bytes,
                    sha256: target.sha256,
                    read_only: target.fidelity.read_only,
                    executable: target.fidelity.executable,
                    link_count: target.link_count,
                },
            )?;
        }
        ProgramStepV1::MoveFile {
            source,
            destination,
            ..
        } => {
            if filesystem.metadata(source.path)?.is_some() {
                return Err(FolderbaseError::MigrationVerificationFailed(
                    filesystem.display(source.path),
                ));
            }
            let published_link_count = source.link_count.checked_add(1).ok_or_else(|| {
                FolderbaseError::MigrationVerificationFailed(filesystem.display(destination.path))
            })?;
            let published = ExactRegularLeaf {
                physical_identity_sha256: expected_identity,
                device_sha256: source.device_sha256,
                bytes: source.bytes,
                sha256: source.sha256,
                read_only: source.fidelity.read_only,
                executable: source.fidelity.executable,
                link_count: published_link_count,
            };
            filesystem.exact_regular_fact(destination.path, published)?;
            transaction.private.claims.exact_regular_fact(
                OsStr::new(&private_claim_name(operation_index, "source")),
                published,
            )?;
        }
    }
    retire_private_publication_ownership_for_receipt(transaction, receipt)
}

fn is_exact_create_directory_prepublication_receipt(
    transaction: &PreparedTransactionV1,
    operation_index: usize,
    receipt: &PrivateLeafReceiptV1,
) -> Result<bool> {
    let ProgramStepV1::CreateDirectory { target, fidelity } =
        transaction.program.step(operation_index)?
    else {
        return Ok(false);
    };
    let expected_identity = receipt.after_identity_sha256.as_deref().ok_or_else(|| {
        invalid_journal(
            Path::new("<private-leaf-receipt-v1>"),
            "directory apply receipt has no intended identity",
        )
    })?;
    if receipt.before_identity_sha256.is_some() {
        return Err(invalid_journal(
            Path::new("<private-leaf-receipt-v1>"),
            "directory apply receipt has an impossible source identity",
        ));
    }
    match transaction.private.claims.exact_empty_directory_fact(
        OsStr::new(&private_claim_name(operation_index, "publish")),
        ExactDirectoryLeaf {
            physical_identity_sha256: expected_identity,
            device_sha256: target.device_sha256,
            read_only: fidelity.read_only,
            executable: fidelity.executable,
        },
    ) {
        Ok(_) => Ok(true),
        Err(FolderbaseError::Io { source, .. })
            if source.kind() == std::io::ErrorKind::NotFound =>
        {
            Ok(false)
        }
        Err(error) => Err(error),
    }
}

#[cfg(test)]
fn replace_abort_conflict_target_fact(
    filesystem: &MigrationFilesystem,
    target: transaction_v1::ProgramBoundRegularV1<'_>,
) -> Result<String> {
    filesystem
        .retained_nofollow_leaf_fingerprint(target.path)?
        .ok_or_else(|| FolderbaseError::MigrationSourceChanged(filesystem.display(target.path)))
}

fn record_transaction_v1_conflict(
    filesystem: &MigrationFilesystem,
    transaction: &mut PreparedTransactionV1,
    operation_index: usize,
    error: &FolderbaseError,
) -> Result<()> {
    let mut affected_paths = match transaction.program.step(operation_index)? {
        ProgramStepV1::CreateDirectory { target, .. }
        | ProgramStepV1::CreateFile { target, .. } => vec![target.path.to_path_buf()],
        ProgramStepV1::ReplaceFile { target, .. } => vec![target.path.to_path_buf()],
        ProgramStepV1::MoveFile {
            source,
            destination,
            ..
        } => vec![source.path.to_path_buf(), destination.path.to_path_buf()],
    };
    let observed_path = match error {
        FolderbaseError::UnsafePath(path)
        | FolderbaseError::MigrationSourceChanged(path)
        | FolderbaseError::MigrationVerificationFailed(path)
        | FolderbaseError::WouldOverwrite(path)
        | FolderbaseError::RestoreNamespaceRepairRequired(path)
        | FolderbaseError::InvalidRecord { path, .. }
        | FolderbaseError::Io { path, .. }
        | FolderbaseError::Json { path, .. } => Some(path),
        _ => None,
    };
    if let Some(path) =
        observed_path.and_then(|path| program_relative_conflict_path(filesystem, path))
        && !affected_paths.iter().any(|affected| affected == &path)
    {
        affected_paths.push(path);
    }
    let step = transaction.program.step(operation_index)?;
    let ordinary_paths = match step {
        ProgramStepV1::CreateDirectory { target, .. }
        | ProgramStepV1::CreateFile { target, .. } => vec![target.path],
        ProgramStepV1::ReplaceFile { target, .. } => vec![target.path],
        ProgramStepV1::MoveFile {
            source,
            destination,
            ..
        } => vec![source.path, destination.path],
    };
    let mut ordinary_fingerprints = Vec::new();
    for path in ordinary_paths {
        if let Some(fingerprint) = filesystem.retained_nofollow_leaf_fingerprint(path)? {
            ordinary_fingerprints.push(format!("{}={fingerprint}", path.display()));
        }
    }
    let current = transaction
        .generations
        .last()
        .expect("transaction-v1 has a validated generation")
        .clone();
    let deduplicable = !ordinary_fingerprints.is_empty();
    let claim_entries = transaction.private.claims.closed_entries(
        transaction
            .program
            .operation_count()
            .saturating_mul(12)
            .saturating_add(1),
    )?;
    let preserved_artifact = match (current.direction(), step) {
        (
            TransactionDirectionV1::Rollback,
            ProgramStepV1::ReplaceFile {
                rollback_snapshot, ..
            },
        )
        | (
            TransactionDirectionV1::Rollback,
            ProgramStepV1::MoveFile {
                rollback_snapshot, ..
            },
        ) => Some(
            PathBuf::from(MIGRATIONS_DIR)
                .join(transaction.program.transaction_id())
                .join(TRANSACTION_DIRECTORY)
                .join(rollback_snapshot.directory)
                .join(rollback_snapshot.name),
        ),
        (_, ProgramStepV1::CreateDirectory { .. })
        | (_, ProgramStepV1::CreateFile { .. })
        | (_, ProgramStepV1::ReplaceFile { .. })
        | (_, ProgramStepV1::MoveFile { .. }) => ["rollback", "source", "publish", "restore"]
            .into_iter()
            .find_map(|kind| {
                let name = private_claim_name(operation_index, kind);
                claim_entries
                    .iter()
                    .find(|(entry, _)| entry == OsStr::new(&name))
                    .map(|(_, is_directory)| (name, *is_directory))
            })
            .map(|(name, is_directory)| {
                if is_directory {
                    let _ = transaction
                        .private
                        .claims
                        .relaxed_directory_fact(OsStr::new(&name))?;
                } else {
                    transaction
                        .private
                        .claims
                        .verify_relaxed_regular(OsStr::new(&name))?;
                }
                Ok::<_, FolderbaseError>(
                    PathBuf::from(MIGRATIONS_DIR)
                        .join(transaction.program.transaction_id())
                        .join(TRANSACTION_DIRECTORY)
                        .join("claims")
                        .join(name),
                )
            })
            .transpose()?,
    };
    let expected = "program-bound leaf state".to_owned();
    let observed = if ordinary_fingerprints.is_empty() {
        error.to_string()
    } else {
        format!(
            "{} [retained ordinary leaves: {}]",
            error,
            ordinary_fingerprints.join(", ")
        )
    };
    if deduplicable && current.phase() == TransactionPhaseV1::Conflicted {
        let duplicate = current.conflict_records().last().is_some_and(|conflict| {
            conflict.operation_index == Some(operation_index)
                && conflict.affected_paths == affected_paths
                && conflict.expected == expected
                && conflict.observed == observed
                && conflict.preserved_artifact == preserved_artifact
        });
        if duplicate {
            reconcile_plan_terminal(filesystem, &transaction.program, MigrationState::Conflicted);
            return Ok(());
        }
    }
    if current.conflict_records().len() >= transaction_v1::MAX_RETAINED_CONFLICTS {
        // Conflict evidence is deliberately bounded. Once the admitted budget
        // is full, preserve the last exact durable evidence and reserve the
        // remaining journal generations for a successful Apply and complete
        // Rollback.
        reconcile_plan_terminal(filesystem, &transaction.program, MigrationState::Conflicted);
        return Ok(());
    }
    let conflicted = current.next_conflicted(
        &transaction.program,
        Some(operation_index),
        affected_paths,
        expected,
        observed,
        preserved_artifact,
    )?;
    append_transaction_v1_generation(filesystem, transaction, conflicted)?;
    reconcile_plan_terminal(filesystem, &transaction.program, MigrationState::Conflicted);
    Ok(())
}

fn program_relative_conflict_path(
    filesystem: &MigrationFilesystem,
    observed: &Path,
) -> Option<PathBuf> {
    let relative = if observed.is_absolute() {
        observed.strip_prefix(filesystem.display_root()).ok()?
    } else {
        observed
    };
    ensure_safe_relative(relative).ok()?;
    Some(relative.to_path_buf())
}

fn is_private_transaction_integrity_error(error: &FolderbaseError) -> bool {
    let private_path = match error {
        FolderbaseError::UnsafePath(path)
        | FolderbaseError::MigrationSourceChanged(path)
        | FolderbaseError::MigrationVerificationFailed(path)
        | FolderbaseError::WouldOverwrite(path)
        | FolderbaseError::RestoreNamespaceRepairRequired(path)
        | FolderbaseError::InvalidRecord { path, .. }
        | FolderbaseError::Io { path, .. }
        | FolderbaseError::Json { path, .. } => Some(path),
        _ => None,
    };
    private_path.is_some_and(|path| {
        path.components()
            .any(|component| component.as_os_str() == OsStr::new(TRANSACTION_DIRECTORY))
            || path
                .to_string_lossy()
                .starts_with("<private-leaf-receipt-v1>")
            || path
                .to_string_lossy()
                .starts_with("<private-abort-work-receipt-v1>")
    })
}

fn execute_transaction_v1_apply_with_hook(
    filesystem: &MigrationFilesystem,
    transaction: &mut PreparedTransactionV1,
    mut checkpoint: impl FnMut(TransactionV1Checkpoint),
) -> Result<MigrationResult> {
    filesystem.require_atomic_noreplace()?;
    loop {
        let current = transaction
            .generations
            .last()
            .expect("transaction-v1 has a validated generation")
            .clone();
        if current.direction() == TransactionDirectionV1::Rollback {
            return Err(FolderbaseError::InvalidMigrationState {
                expected: MigrationState::Applying.as_str(),
                actual: "rolling_back".to_owned(),
            });
        }
        if current.phase() == TransactionPhaseV1::Applied {
            validate_transaction_v1_environment(filesystem, transaction, &current)?;
            for (index, _) in current.apply_receipt_records() {
                let receipt = load_private_leaf_receipt(
                    transaction,
                    index,
                    PrivateReceiptDirectionV1::Apply,
                )?
                .ok_or_else(|| {
                    let name = private_receipt_name(index, PrivateReceiptDirectionV1::Apply);
                    invalid_journal(
                        transaction.private.receipts.display_path(OsStr::new(&name)),
                        "completed apply operation has no private receipt",
                    )
                })?;
                if let Err(error) =
                    verify_apply_private_receipt(filesystem, transaction, index, &receipt)
                {
                    if is_private_transaction_integrity_error(&error) {
                        return Err(error);
                    }
                    record_transaction_v1_conflict(filesystem, transaction, index, &error)?;
                    checkpoint(TransactionV1Checkpoint::ConflictRecorded(index));
                    return Err(error);
                }
            }
            reconcile_plan_terminal(filesystem, &transaction.program, MigrationState::Verified);
            return Ok(transaction_v1_result(
                filesystem,
                transaction,
                MigrationState::Verified,
            ));
        }
        if let Some(index) = current.in_flight_operation() {
            let identity =
                match apply_transaction_v1_step(filesystem, transaction, index, &mut checkpoint) {
                    Ok(identity) => identity,
                    Err(error) => {
                        if is_private_transaction_integrity_error(&error) {
                            return Err(error);
                        }
                        record_transaction_v1_conflict(filesystem, transaction, index, &error)?;
                        checkpoint(TransactionV1Checkpoint::ConflictRecorded(index));
                        return Err(error);
                    }
                };
            let receipt = current.next_apply_receipt(&transaction.program, index, identity)?;
            append_transaction_v1_generation(filesystem, transaction, receipt)?;
            checkpoint(TransactionV1Checkpoint::JournalApplyReceiptPersisted(index));
            continue;
        }
        if current.operation_cursor() == transaction.program.operation_count() {
            let applied = current.next_applied(&transaction.program)?;
            append_transaction_v1_generation(filesystem, transaction, applied)?;
            continue;
        }
        if current.operation_cursor() == 0
            && let Err(error) = transaction
                .program
                .validate_prepared_environment(filesystem)
        {
            if is_private_transaction_integrity_error(&error) {
                return Err(error);
            }
            record_transaction_v1_conflict(
                filesystem,
                transaction,
                current.operation_cursor(),
                &error,
            )?;
            checkpoint(TransactionV1Checkpoint::ConflictRecorded(
                current.operation_cursor(),
            ));
            return Err(error);
        }
        let index = current.operation_cursor();
        let intent = current.next_apply_intent(&transaction.program, index)?;
        append_transaction_v1_generation(filesystem, transaction, intent)?;
        checkpoint(TransactionV1Checkpoint::ApplyIntentPersisted(index));
    }
}

fn retains_preserved_aborted_create_descendant(
    filesystem: &MigrationFilesystem,
    transaction: &PreparedTransactionV1,
    directory: &Path,
) -> Result<bool> {
    let current = transaction
        .generations
        .last()
        .ok_or_else(|| invalid_journal(Path::new("<transaction-v1>"), "journal is empty"))?;
    for (operation_index, _) in current.abort_receipt_records() {
        let target = match transaction.program.step(operation_index)? {
            ProgramStepV1::CreateDirectory { target, .. }
            | ProgramStepV1::CreateFile { target, .. } => target.path,
            ProgramStepV1::ReplaceFile { .. } | ProgramStepV1::MoveFile { .. } => continue,
        };
        if target == directory || !target.starts_with(directory) {
            continue;
        }
        let receipt =
            load_private_abort_work_receipt(transaction, operation_index)?.ok_or_else(|| {
                invalid_journal(
                    Path::new("<private-abort-work-receipt-v1>"),
                    "journaled create abort has no private receipt",
                )
            })?;
        if receipt.visible_post_identity_sha256.is_none()
            && receipt.claims.is_empty()
            && filesystem.metadata(target)?.is_some()
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn rollback_transaction_v1_step(
    filesystem: &MigrationFilesystem,
    transaction: &PreparedTransactionV1,
    operation_index: usize,
    published_identity: Option<&str>,
    checkpoint: &mut impl FnMut(TransactionV1Checkpoint),
) -> Result<(Vec<PathBuf>, Option<String>)> {
    let mut removed = Vec::new();
    let current = transaction
        .generations
        .last()
        .ok_or_else(|| invalid_journal(Path::new("<transaction-v1>"), "journal is empty"))?;
    validate_transaction_v1_environment(filesystem, transaction, current)?;
    let retained_parents =
        transaction
            .program
            .retain_step_parents(filesystem, operation_index, current)?;
    let validate_authority = || {
        validate_transaction_v1_environment(filesystem, transaction, current)?;
        transaction
            .program
            .validate_step_parents(filesystem, operation_index, current)
    };
    if let Some(receipt) = load_private_leaf_receipt(
        transaction,
        operation_index,
        PrivateReceiptDirectionV1::Rollback,
    )? {
        verify_rollback_private_receipt(filesystem, transaction, operation_index, &receipt)?;
        return Ok((removed, receipt.after_identity_sha256));
    }
    let restored_identity = match transaction.program.step(operation_index)? {
        ProgramStepV1::CreateDirectory { target, fidelity } => {
            let expected_identity = published_identity.ok_or_else(|| {
                invalid_journal(
                    Path::new("<migration-journal-v1>"),
                    "created directory has no published identity",
                )
            })?;
            if retains_preserved_aborted_create_descendant(filesystem, transaction, target.path)? {
                validate_authority()?;
                filesystem.exact_directory_fact(
                    target.path,
                    ExactDirectoryLeaf {
                        physical_identity_sha256: expected_identity,
                        device_sha256: target.device_sha256,
                        read_only: fidelity.read_only,
                        executable: fidelity.executable,
                    },
                    false,
                )?;
                validate_authority()?;
                Some(expected_identity.to_owned())
            } else {
                let rollback_name = private_claim_name(operation_index, "rollback");
                let source_name = target.path.file_name().ok_or_else(|| {
                    invalid_journal(target.path, "program target has no leaf name")
                })?;
                validate_authority()?;
                let claim = match filesystem.claim_exact_leaf_through(ExactLeafClaimRequest {
                    source_parent: retained_parents.get(target.parent)?,
                    source_name,
                    destination: &transaction.private.claims,
                    destination_name: &rollback_name,
                    expectation: ExactLeafClaimExpectation::EmptyDirectory(ExactDirectoryLeaf {
                        physical_identity_sha256: expected_identity,
                        device_sha256: target.device_sha256,
                        read_only: fidelity.read_only,
                        executable: fidelity.executable,
                    }),
                    existing_source: ExactExistingClaimSource::Absent,
                })? {
                    ExactLeafClaimResult::Directory(fact) => fact,
                    ExactLeafClaimResult::Regular(_) => {
                        return Err(FolderbaseError::MigrationVerificationFailed(
                            transaction
                                .private
                                .claims
                                .display_path(OsStr::new(&rollback_name)),
                        ));
                    }
                };
                checkpoint(TransactionV1Checkpoint::InverseClaimComplete(
                    operation_index,
                ));
                validate_authority()?;
                if claim.physical_identity_sha256 != expected_identity {
                    return Err(FolderbaseError::MigrationVerificationFailed(
                        transaction
                            .private
                            .claims
                            .display_path(OsStr::new(&rollback_name)),
                    ));
                }
                removed.push(target.path.to_path_buf());
                None
            }
        }
        ProgramStepV1::CreateFile { target, image } => {
            let rollback_name = private_claim_name(operation_index, "rollback");
            let expected_identity = published_identity.ok_or_else(|| {
                invalid_journal(
                    Path::new("<migration-journal-v1>"),
                    "created file has no published identity",
                )
            })?;
            validate_authority()?;
            let claim = claim_transaction_v1_exact_rollback_output(
                filesystem,
                transaction,
                operation_index,
                target.path,
                retained_parents.get(target.parent)?,
                ExactRegularLeaf {
                    physical_identity_sha256: expected_identity,
                    device_sha256: target.device_sha256,
                    bytes: image.bytes,
                    sha256: image.sha256,
                    read_only: image.fidelity.read_only,
                    executable: image.fidelity.executable,
                    link_count: 2,
                },
                ExactExistingClaimSource::Absent,
            )?;
            checkpoint(TransactionV1Checkpoint::InverseClaimComplete(
                operation_index,
            ));
            validate_authority()?;
            if claim.physical_identity_sha256 != expected_identity {
                return Err(FolderbaseError::MigrationVerificationFailed(
                    transaction
                        .private
                        .claims
                        .display_path(OsStr::new(&rollback_name)),
                ));
            }
            removed.push(target.path.to_path_buf());
            None
        }
        ProgramStepV1::ReplaceFile {
            target,
            image,
            rollback_snapshot,
        } => {
            let rollback_name = private_claim_name(operation_index, "rollback");
            let expected_identity = published_identity.ok_or_else(|| {
                invalid_journal(
                    Path::new("<migration-journal-v1>"),
                    "replacement has no published identity",
                )
            })?;
            let applied_link_count = target.link_count.checked_add(1).ok_or_else(|| {
                FolderbaseError::MigrationSourceChanged(filesystem.display(target.path))
            })?;
            let applied = ExactRegularLeaf {
                physical_identity_sha256: expected_identity,
                device_sha256: target.device_sha256,
                bytes: image.bytes,
                sha256: image.sha256,
                read_only: image.fidelity.read_only,
                executable: image.fidelity.executable,
                link_count: applied_link_count,
            };
            let rollback_preexisted = match transaction
                .private
                .claims
                .exact_regular_fact(OsStr::new(&rollback_name), applied)
            {
                Ok(_) => true,
                Err(FolderbaseError::Io { source, .. })
                    if source.kind() == std::io::ErrorKind::NotFound =>
                {
                    false
                }
                Err(error) => return Err(error),
            };
            let restore_name = private_claim_name(operation_index, "restore");
            let existing_restore =
                if rollback_preexisted && filesystem.metadata(target.path)?.is_some() {
                    Some(
                        transaction
                            .private
                            .claims
                            .relaxed_regular_fact(OsStr::new(&restore_name), target.sha256)?,
                    )
                } else {
                    None
                };
            let existing_source = match existing_restore.as_ref() {
                Some(restore) => ExactExistingClaimSource::Regular(ExactRegularLeaf {
                    physical_identity_sha256: &restore.physical_identity_sha256,
                    device_sha256: target.device_sha256,
                    bytes: target.bytes,
                    sha256: target.sha256,
                    read_only: target.fidelity.read_only,
                    executable: target.fidelity.executable,
                    link_count: applied_link_count,
                }),
                None => ExactExistingClaimSource::Absent,
            };
            validate_authority()?;
            claim_transaction_v1_exact_rollback_output(
                filesystem,
                transaction,
                operation_index,
                target.path,
                retained_parents.get(target.parent)?,
                applied,
                existing_source,
            )?;
            checkpoint(TransactionV1Checkpoint::InverseClaimComplete(
                operation_index,
            ));
            validate_authority()?;
            if let Some(restore) = existing_restore {
                let restored = ExactRegularLeaf {
                    physical_identity_sha256: &restore.physical_identity_sha256,
                    device_sha256: target.device_sha256,
                    bytes: target.bytes,
                    sha256: target.sha256,
                    read_only: target.fidelity.read_only,
                    executable: target.fidelity.executable,
                    link_count: applied_link_count,
                };
                transaction
                    .private
                    .claims
                    .exact_regular_fact(OsStr::new(&restore_name), restored)?;
                filesystem.exact_regular_fact(target.path, restored)?;
                Some(restore.physical_identity_sha256)
            } else {
                let restore_claim = filesystem.prepare_private_publish_claim(
                    private_blob_directory(transaction, &rollback_snapshot)?,
                    rollback_snapshot.name,
                    &transaction.private.claims,
                    &restore_name,
                    rollback_snapshot.sha256,
                    rollback_snapshot.bytes,
                    rollback_snapshot.fidelity.read_only,
                    rollback_snapshot.fidelity.executable,
                    || {
                        checkpoint(TransactionV1Checkpoint::PrivatePublishClaimStaged(
                            operation_index,
                        ));
                    },
                )?;
                transaction.private.claims.exact_regular_fact(
                    OsStr::new(&restore_name),
                    ExactRegularLeaf {
                        physical_identity_sha256: &restore_claim.physical_identity_sha256,
                        device_sha256: target.device_sha256,
                        bytes: target.bytes,
                        sha256: target.sha256,
                        read_only: target.fidelity.read_only,
                        executable: target.fidelity.executable,
                        link_count: target.link_count,
                    },
                )?;
                validate_authority()?;
                let destination_name = target.path.file_name().ok_or_else(|| {
                    invalid_journal(target.path, "program target has no leaf name")
                })?;
                let restored = filesystem.publish_private_claim_new_through(
                    &transaction.private.claims,
                    OsStr::new(&restore_name),
                    retained_parents.get(target.parent)?,
                    destination_name,
                    &restore_claim.physical_identity_sha256,
                    target.sha256,
                    target.bytes,
                )?;
                validate_authority()?;
                let restored = ExactRegularLeaf {
                    physical_identity_sha256: &restored.physical_identity_sha256,
                    device_sha256: target.device_sha256,
                    bytes: target.bytes,
                    sha256: target.sha256,
                    read_only: target.fidelity.read_only,
                    executable: target.fidelity.executable,
                    link_count: applied_link_count,
                };
                transaction
                    .private
                    .claims
                    .exact_regular_fact(OsStr::new(&restore_name), restored)?;
                filesystem.exact_regular_fact(target.path, restored)?;
                Some(restored.physical_identity_sha256.to_owned())
            }
        }
        ProgramStepV1::MoveFile {
            source,
            destination,
            rollback_snapshot,
        } => {
            let rollback_name = private_claim_name(operation_index, "rollback");
            let expected_identity = published_identity.ok_or_else(|| {
                invalid_journal(
                    Path::new("<migration-journal-v1>"),
                    "move has no published identity",
                )
            })?;
            let applied_link_count = source.link_count.checked_add(1).ok_or_else(|| {
                FolderbaseError::MigrationSourceChanged(filesystem.display(destination.path))
            })?;
            let applied = ExactRegularLeaf {
                physical_identity_sha256: expected_identity,
                device_sha256: source.device_sha256,
                bytes: source.bytes,
                sha256: source.sha256,
                read_only: source.fidelity.read_only,
                executable: source.fidelity.executable,
                link_count: applied_link_count,
            };
            let rollback_preexisted = match transaction
                .private
                .claims
                .exact_regular_fact(OsStr::new(&rollback_name), applied)
            {
                Ok(_) => true,
                Err(FolderbaseError::Io { source, .. })
                    if source.kind() == std::io::ErrorKind::NotFound =>
                {
                    false
                }
                Err(error) => return Err(error),
            };
            if !rollback_preexisted && filesystem.metadata(source.path)?.is_some() {
                return Err(FolderbaseError::MigrationSourceChanged(
                    filesystem.display(source.path),
                ));
            }
            validate_authority()?;
            claim_transaction_v1_exact_rollback_output(
                filesystem,
                transaction,
                operation_index,
                destination.path,
                retained_parents.get(destination.parent)?,
                applied,
                ExactExistingClaimSource::Absent,
            )?;
            checkpoint(TransactionV1Checkpoint::InverseClaimComplete(
                operation_index,
            ));
            validate_authority()?;

            let restore_name = private_claim_name(operation_index, "restore");
            let existing_restore =
                if rollback_preexisted && filesystem.metadata(source.path)?.is_some() {
                    Some(
                        transaction
                            .private
                            .claims
                            .relaxed_regular_fact(OsStr::new(&restore_name), source.sha256)?,
                    )
                } else {
                    None
                };
            if let Some(restore) = existing_restore {
                let restored = ExactRegularLeaf {
                    physical_identity_sha256: &restore.physical_identity_sha256,
                    device_sha256: source.device_sha256,
                    bytes: source.bytes,
                    sha256: source.sha256,
                    read_only: source.fidelity.read_only,
                    executable: source.fidelity.executable,
                    link_count: applied_link_count,
                };
                transaction
                    .private
                    .claims
                    .exact_regular_fact(OsStr::new(&restore_name), restored)?;
                filesystem.exact_regular_fact(source.path, restored)?;
                Some(restore.physical_identity_sha256)
            } else {
                let restore_claim = filesystem.prepare_private_publish_claim(
                    private_blob_directory(transaction, &rollback_snapshot)?,
                    rollback_snapshot.name,
                    &transaction.private.claims,
                    &restore_name,
                    rollback_snapshot.sha256,
                    rollback_snapshot.bytes,
                    rollback_snapshot.fidelity.read_only,
                    rollback_snapshot.fidelity.executable,
                    || {
                        checkpoint(TransactionV1Checkpoint::PrivatePublishClaimStaged(
                            operation_index,
                        ));
                    },
                )?;
                transaction.private.claims.exact_regular_fact(
                    OsStr::new(&restore_name),
                    ExactRegularLeaf {
                        physical_identity_sha256: &restore_claim.physical_identity_sha256,
                        device_sha256: source.device_sha256,
                        bytes: source.bytes,
                        sha256: source.sha256,
                        read_only: source.fidelity.read_only,
                        executable: source.fidelity.executable,
                        link_count: source.link_count,
                    },
                )?;
                validate_authority()?;
                let destination_name = source.path.file_name().ok_or_else(|| {
                    invalid_journal(source.path, "program source has no leaf name")
                })?;
                let restored = filesystem.publish_private_claim_new_through(
                    &transaction.private.claims,
                    OsStr::new(&restore_name),
                    retained_parents.get(source.parent)?,
                    destination_name,
                    &restore_claim.physical_identity_sha256,
                    source.sha256,
                    source.bytes,
                )?;
                validate_authority()?;
                let restored = ExactRegularLeaf {
                    physical_identity_sha256: &restored.physical_identity_sha256,
                    device_sha256: source.device_sha256,
                    bytes: source.bytes,
                    sha256: source.sha256,
                    read_only: source.fidelity.read_only,
                    executable: source.fidelity.executable,
                    link_count: applied_link_count,
                };
                transaction
                    .private
                    .claims
                    .exact_regular_fact(OsStr::new(&restore_name), restored)?;
                filesystem.exact_regular_fact(source.path, restored)?;
                removed.push(destination.path.to_path_buf());
                Some(restored.physical_identity_sha256.to_owned())
            }
        }
    };
    validate_authority()?;
    let receipt = PrivateLeafReceiptV1::new(
        transaction,
        operation_index,
        PrivateReceiptDirectionV1::Rollback,
        published_identity.map(str::to_owned),
        restored_identity.clone(),
    )?;
    persist_private_leaf_receipt(transaction, &receipt)?;
    checkpoint(TransactionV1Checkpoint::PrivateRollbackReceiptPersisted(
        operation_index,
    ));
    Ok((removed, restored_identity))
}

fn verify_rollback_private_receipt(
    filesystem: &MigrationFilesystem,
    transaction: &PreparedTransactionV1,
    operation_index: usize,
    receipt: &PrivateLeafReceiptV1,
) -> Result<()> {
    let published_identity = receipt.before_identity_sha256.as_deref().ok_or_else(|| {
        invalid_journal(
            Path::new("<private-leaf-receipt-v1>"),
            "rollback receipt has no apply identity",
        )
    })?;
    let rollback_name = private_claim_name(operation_index, "rollback");
    match transaction.program.step(operation_index)? {
        ProgramStepV1::CreateDirectory { target, fidelity } => {
            if let Some(retained_identity) = receipt.after_identity_sha256.as_deref() {
                if retained_identity != published_identity {
                    return Err(FolderbaseError::MigrationVerificationFailed(
                        filesystem.display(target.path),
                    ));
                }
                filesystem.exact_directory_fact(
                    target.path,
                    ExactDirectoryLeaf {
                        physical_identity_sha256: retained_identity,
                        device_sha256: target.device_sha256,
                        read_only: fidelity.read_only,
                        executable: fidelity.executable,
                    },
                    false,
                )?;
                return retire_private_publication_ownership_for_receipt(transaction, receipt);
            }
            if filesystem.metadata(target.path)?.is_some() {
                return Err(FolderbaseError::MigrationVerificationFailed(
                    filesystem.display(target.path),
                ));
            }
            verify_create_directory_rollback_claim(
                transaction,
                operation_index,
                published_identity,
                target.device_sha256,
                fidelity.read_only,
                fidelity.executable,
            )?;
        }
        ProgramStepV1::CreateFile { target, image } => {
            if receipt.after_identity_sha256.is_some()
                || filesystem.metadata(target.path)?.is_some()
            {
                return Err(FolderbaseError::MigrationVerificationFailed(
                    filesystem.display(target.path),
                ));
            }
            let rolled_back = ExactRegularLeaf {
                physical_identity_sha256: published_identity,
                device_sha256: target.device_sha256,
                bytes: image.bytes,
                sha256: image.sha256,
                read_only: image.fidelity.read_only,
                executable: image.fidelity.executable,
                link_count: 2,
            };
            transaction.private.claims.exact_regular_fact(
                OsStr::new(&private_claim_name(operation_index, "publish")),
                rolled_back,
            )?;
            transaction
                .private
                .claims
                .exact_regular_fact(OsStr::new(&rollback_name), rolled_back)?;
        }
        ProgramStepV1::ReplaceFile { target, image, .. } => {
            let restored_identity = receipt.after_identity_sha256.as_deref().ok_or_else(|| {
                invalid_journal(
                    Path::new("<private-leaf-receipt-v1>"),
                    "replacement rollback receipt has no restored identity",
                )
            })?;
            let link_count = target.link_count.checked_add(1).ok_or_else(|| {
                FolderbaseError::MigrationVerificationFailed(filesystem.display(target.path))
            })?;
            let rolled_back = ExactRegularLeaf {
                physical_identity_sha256: published_identity,
                device_sha256: target.device_sha256,
                bytes: image.bytes,
                sha256: image.sha256,
                read_only: image.fidelity.read_only,
                executable: image.fidelity.executable,
                link_count,
            };
            transaction.private.claims.exact_regular_fact(
                OsStr::new(&private_claim_name(operation_index, "publish")),
                rolled_back,
            )?;
            transaction
                .private
                .claims
                .exact_regular_fact(OsStr::new(&rollback_name), rolled_back)?;
            let restored = ExactRegularLeaf {
                physical_identity_sha256: restored_identity,
                device_sha256: target.device_sha256,
                bytes: target.bytes,
                sha256: target.sha256,
                read_only: target.fidelity.read_only,
                executable: target.fidelity.executable,
                link_count,
            };
            transaction.private.claims.exact_regular_fact(
                OsStr::new(&private_claim_name(operation_index, "restore")),
                restored,
            )?;
            filesystem.exact_regular_fact(target.path, restored)?;
        }
        ProgramStepV1::MoveFile {
            source,
            destination,
            ..
        } => {
            let restored_identity = receipt.after_identity_sha256.as_deref().ok_or_else(|| {
                invalid_journal(
                    Path::new("<private-leaf-receipt-v1>"),
                    "move rollback receipt has no restored identity",
                )
            })?;
            if filesystem.metadata(destination.path)?.is_some() {
                return Err(FolderbaseError::MigrationVerificationFailed(
                    filesystem.display(destination.path),
                ));
            }
            let link_count = source.link_count.checked_add(1).ok_or_else(|| {
                FolderbaseError::MigrationVerificationFailed(filesystem.display(source.path))
            })?;
            let rolled_back = ExactRegularLeaf {
                physical_identity_sha256: published_identity,
                device_sha256: source.device_sha256,
                bytes: source.bytes,
                sha256: source.sha256,
                read_only: source.fidelity.read_only,
                executable: source.fidelity.executable,
                link_count,
            };
            transaction.private.claims.exact_regular_fact(
                OsStr::new(&private_claim_name(operation_index, "source")),
                rolled_back,
            )?;
            transaction
                .private
                .claims
                .exact_regular_fact(OsStr::new(&rollback_name), rolled_back)?;
            let restored = ExactRegularLeaf {
                physical_identity_sha256: restored_identity,
                device_sha256: source.device_sha256,
                bytes: source.bytes,
                sha256: source.sha256,
                read_only: source.fidelity.read_only,
                executable: source.fidelity.executable,
                link_count,
            };
            transaction.private.claims.exact_regular_fact(
                OsStr::new(&private_claim_name(operation_index, "restore")),
                restored,
            )?;
            filesystem.exact_regular_fact(source.path, restored)?;
        }
    }
    retire_private_publication_ownership_for_receipt(transaction, receipt)
}

fn claim_transaction_v1_exact_rollback_output(
    filesystem: &MigrationFilesystem,
    transaction: &PreparedTransactionV1,
    operation_index: usize,
    visible_path: &Path,
    visible_parent: &VerifiedVisibleDirectory,
    expected: ExactRegularLeaf<'_>,
    existing_source: ExactExistingClaimSource<'_>,
) -> Result<MigrationRegularFact> {
    let rollback_name = private_claim_name(operation_index, "rollback");
    let visible_name = visible_path
        .file_name()
        .ok_or_else(|| invalid_journal(visible_path, "program path has no leaf name"))?;
    match filesystem.claim_exact_leaf_through(ExactLeafClaimRequest {
        source_parent: visible_parent,
        source_name: visible_name,
        destination: &transaction.private.claims,
        destination_name: &rollback_name,
        expectation: ExactLeafClaimExpectation::Regular(expected),
        existing_source,
    })? {
        ExactLeafClaimResult::Regular(fact) => Ok(fact),
        ExactLeafClaimResult::Directory(_) => Err(FolderbaseError::MigrationVerificationFailed(
            transaction
                .private
                .claims
                .display_path(OsStr::new(&rollback_name)),
        )),
    }
}

fn private_regular_fact_if_present(
    directory: &VerifiedPrivateDirectory,
    name: &str,
    expected_sha256: &str,
) -> Result<Option<MigrationRegularFact>> {
    match directory.relaxed_regular_fact(OsStr::new(name), expected_sha256) {
        Ok(fact) => Ok(Some(fact)),
        Err(FolderbaseError::Io { source, .. })
            if source.kind() == std::io::ErrorKind::NotFound =>
        {
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

fn private_directory_fact_if_present(
    directory: &VerifiedPrivateDirectory,
    name: &str,
) -> Result<Option<crate::migration_filesystem::MigrationDirectoryFact>> {
    match directory.relaxed_directory_fact(OsStr::new(name)) {
        Ok(fact) => Ok(Some(fact)),
        Err(FolderbaseError::Io { source, .. })
            if source.kind() == std::io::ErrorKind::NotFound =>
        {
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

fn regular_fact_executable(fact: &MigrationRegularFact) -> bool {
    fact.unix_mode.is_some_and(|mode| mode & 0o111 != 0)
}

fn directory_fact_executable(fact: &crate::migration_filesystem::MigrationDirectoryFact) -> bool {
    fact.unix_mode.is_none_or(|mode| mode & 0o111 != 0)
}

fn require_move_abort_fact_shape(
    transaction: &PreparedTransactionV1,
    operation_index: usize,
    name: &str,
    fact: &MigrationRegularFact,
    source: transaction_v1::ProgramBoundRegularV1<'_>,
) -> Result<()> {
    let read_only = fact.read_only;
    let executable = regular_fact_executable(fact);
    if fact.physical_identity_sha256 != source.physical_identity_sha256
        || fact.device_sha256 != source.device_sha256
        || fact.bytes != source.bytes
        || read_only != source.fidelity.read_only
        || executable != source.fidelity.executable
    {
        return Err(FolderbaseError::MigrationVerificationFailed(
            transaction.private.claims.display_path(OsStr::new(name)),
        ));
    }
    if !matches!(
        name,
        value
            if value == private_claim_name(operation_index, "source")
                || value == private_claim_name(operation_index, "rollback")
    ) {
        return Err(invalid_journal(
            transaction.private.claims.display_path(OsStr::new(name)),
            "Move abort claim has an impossible name",
        ));
    }
    Ok(())
}

fn verify_private_abort_work_receipt(
    filesystem: &MigrationFilesystem,
    transaction: &PreparedTransactionV1,
    operation_index: usize,
    receipt: &PrivateAbortWorkReceiptV1,
) -> Result<()> {
    let receipt_name = private_abort_receipt_name(operation_index);
    let receipt_path = transaction
        .private
        .receipts
        .display_path(OsStr::new(&receipt_name));
    if receipt.operation_index != operation_index {
        return Err(invalid_journal(
            &receipt_path,
            "private abort-work receipt index disagrees with its path",
        ));
    }
    let prefix = format!("{operation_index:08}.");
    let actual_claims = transaction
        .private
        .claims
        .closed_entries(
            transaction
                .program
                .operation_count()
                .saturating_mul(4)
                .saturating_add(1),
        )?
        .into_iter()
        .filter_map(|(name, is_directory)| {
            let name = name.to_string_lossy().into_owned();
            name.starts_with(&prefix).then_some((name, is_directory))
        })
        .collect::<BTreeMap<_, _>>();
    let expected_claims = receipt
        .claims
        .iter()
        .map(|claim| (claim.name().to_owned(), claim.is_directory()))
        .collect::<BTreeMap<_, _>>();
    if let Some((name, _)) = actual_claims
        .iter()
        .find(|(name, kind)| expected_claims.get(*name) != Some(*kind))
    {
        return Err(invalid_journal(
            transaction.private.claims.display_path(OsStr::new(name)),
            "private abort-work receipt omits or misclassifies an exact claim",
        ));
    }
    if let Some((name, _)) = expected_claims
        .iter()
        .find(|(name, kind)| actual_claims.get(*name) != Some(*kind))
    {
        return Err(invalid_journal(
            transaction.private.claims.display_path(OsStr::new(name)),
            "private abort-work receipt names a missing exact claim",
        ));
    }

    match transaction.program.step(operation_index)? {
        ProgramStepV1::MoveFile { source, .. } => {
            if receipt.visible_post_identity_sha256.as_deref()
                != Some(source.physical_identity_sha256)
            {
                return Err(invalid_journal(
                    &receipt_path,
                    "Move abort receipt has the wrong visible post identity",
                ));
            }
            if !receipt.claims.is_empty() {
                return Err(invalid_journal(
                    &receipt_path,
                    "Move abort receipt retains live workspace authority",
                ));
            }
            let journaled = transaction.generations.last().is_some_and(|generation| {
                generation.abort_receipt_sha256(operation_index).is_some()
            });
            if !journaled {
                filesystem.exact_regular_fact(
                    source.path,
                    ExactRegularLeaf {
                        physical_identity_sha256: source.physical_identity_sha256,
                        device_sha256: source.device_sha256,
                        bytes: source.bytes,
                        sha256: source.sha256,
                        read_only: source.fidelity.read_only,
                        executable: source.fidelity.executable,
                        link_count: source.link_count,
                    },
                )?;
            }
            Ok(())
        }
        ProgramStepV1::CreateDirectory { target, fidelity } => {
            if receipt.visible_post_identity_sha256.is_some() {
                return Err(invalid_journal(
                    &receipt_path,
                    "CreateDirectory abort receipt has a visible post identity",
                ));
            }
            match receipt.claims.as_slice() {
                [] => Ok(()),
                [claim] if claim.name() == private_claim_name(operation_index, "publish") => {
                    let Some(exact) = claim.exact_directory() else {
                        return Err(invalid_journal(
                            &receipt_path,
                            "CreateDirectory abort receipt publish claim is not a directory",
                        ));
                    };
                    if exact.device_sha256 != target.device_sha256
                        || exact.read_only != fidelity.read_only
                        || exact.executable != fidelity.executable
                    {
                        return Err(invalid_journal(
                            &receipt_path,
                            "CreateDirectory abort receipt disagrees with the immutable program",
                        ));
                    }
                    transaction
                        .private
                        .claims
                        .exact_empty_directory_fact(OsStr::new(claim.name()), exact)?;
                    Ok(())
                }
                _ => Err(invalid_journal(
                    &receipt_path,
                    "CreateDirectory abort receipt has an impossible exact claim set",
                )),
            }
        }
        ProgramStepV1::CreateFile { target, image } => {
            if receipt.visible_post_identity_sha256.is_some() {
                return Err(invalid_journal(
                    &receipt_path,
                    "CreateFile abort receipt has a visible post identity",
                ));
            }
            match receipt.claims.as_slice() {
                [] => Ok(()),
                [publish, rollback]
                    if publish.name() == private_claim_name(operation_index, "publish")
                        && rollback.name() == private_claim_name(operation_index, "rollback") =>
                {
                    let (Some(rollback), Some(publish)) =
                        (rollback.exact_regular(), publish.exact_regular())
                    else {
                        return Err(invalid_journal(
                            &receipt_path,
                            "CreateFile abort receipt contains a directory claim",
                        ));
                    };
                    if rollback.physical_identity_sha256 != publish.physical_identity_sha256
                        || rollback.device_sha256 != publish.device_sha256
                        || rollback.bytes != publish.bytes
                        || rollback.sha256 != publish.sha256
                        || rollback.read_only != publish.read_only
                        || rollback.executable != publish.executable
                        || rollback.link_count != publish.link_count
                        || publish.device_sha256 != target.device_sha256
                        || publish.bytes != image.bytes
                        || publish.sha256 != image.sha256
                        || publish.read_only != image.fidelity.read_only
                        || publish.executable != image.fidelity.executable
                        || publish.link_count != 2
                    {
                        return Err(invalid_journal(
                            &receipt_path,
                            "CreateFile abort receipt disagrees with the immutable program",
                        ));
                    }
                    transaction.private.claims.exact_regular_fact(
                        OsStr::new(&private_claim_name(operation_index, "rollback")),
                        rollback,
                    )?;
                    transaction.private.claims.exact_regular_fact(
                        OsStr::new(&private_claim_name(operation_index, "publish")),
                        publish,
                    )?;
                    Ok(())
                }
                _ => Err(invalid_journal(
                    &receipt_path,
                    "CreateFile abort receipt has an impossible exact claim set",
                )),
            }
        }
        ProgramStepV1::ReplaceFile { target, image, .. } => {
            if receipt.visible_post_identity_sha256.as_deref()
                != Some(target.physical_identity_sha256)
            {
                return Err(invalid_journal(
                    &receipt_path,
                    "ReplaceFile abort receipt has the wrong visible post identity",
                ));
            }
            let rollback_name = private_claim_name(operation_index, "rollback");
            match receipt.claims.as_slice() {
                [] => {}
                [claim] if claim.name() == rollback_name => {
                    let Some(exact) = claim.exact_regular() else {
                        return Err(invalid_journal(
                            &receipt_path,
                            "ReplaceFile abort receipt contains a directory claim",
                        ));
                    };
                    if exact.device_sha256 != target.device_sha256
                        || exact.bytes != image.bytes
                        || exact.sha256 != image.sha256
                        || exact.read_only != image.fidelity.read_only
                        || exact.executable != image.fidelity.executable
                        || exact.link_count != 1
                    {
                        return Err(invalid_journal(
                            &receipt_path,
                            "ReplaceFile abort rollback claim disagrees with the immutable program",
                        ));
                    }
                    transaction
                        .private
                        .claims
                        .exact_regular_fact(OsStr::new(claim.name()), exact)?;
                }
                _ => {
                    return Err(invalid_journal(
                        &receipt_path,
                        "ReplaceFile abort receipt has an impossible exact claim set",
                    ));
                }
            }
            let journaled = transaction.generations.last().is_some_and(|generation| {
                generation.abort_receipt_sha256(operation_index).is_some()
            });
            if !journaled {
                filesystem.exact_regular_fact(
                    target.path,
                    ExactRegularLeaf {
                        physical_identity_sha256: target.physical_identity_sha256,
                        device_sha256: target.device_sha256,
                        bytes: target.bytes,
                        sha256: target.sha256,
                        read_only: target.fidelity.read_only,
                        executable: target.fidelity.executable,
                        link_count: target.link_count,
                    },
                )?;
            }
            Ok(())
        }
    }
}

fn finish_private_abort_work_receipt(
    filesystem: &MigrationFilesystem,
    transaction: &PreparedTransactionV1,
    operation_index: usize,
    receipt: PrivateAbortWorkReceiptV1,
    checkpoint: &mut impl FnMut(TransactionV1Checkpoint),
    validate_retained_authority: &impl Fn() -> Result<()>,
) -> Result<String> {
    persist_private_abort_work_receipt(transaction, &receipt)?;
    let reopened =
        load_private_abort_work_receipt(transaction, operation_index)?.ok_or_else(|| {
            let name = private_abort_receipt_name(operation_index);
            invalid_journal(
                transaction.private.receipts.display_path(OsStr::new(&name)),
                "persisted abort-work receipt is missing",
            )
        })?;
    if reopened != receipt {
        let name = private_abort_receipt_name(operation_index);
        return Err(invalid_journal(
            transaction.private.receipts.display_path(OsStr::new(&name)),
            "persisted abort-work receipt changed during reverify",
        ));
    }
    verify_private_abort_work_receipt(filesystem, transaction, operation_index, &reopened)?;
    validate_retained_authority()?;
    let digest = reopened.encoded_sha256()?;
    checkpoint(TransactionV1Checkpoint::PrivateAbortReceiptPersisted(
        operation_index,
    ));
    Ok(digest)
}

fn abort_transaction_v1_in_flight_apply(
    filesystem: &MigrationFilesystem,
    transaction: &PreparedTransactionV1,
    operation_index: usize,
    checkpoint: &mut impl FnMut(TransactionV1Checkpoint),
) -> Result<String> {
    let current = transaction
        .generations
        .last()
        .ok_or_else(|| invalid_journal(Path::new("<transaction-v1>"), "journal is empty"))?;
    validate_transaction_v1_environment(filesystem, transaction, current)?;
    let retained_parents =
        transaction
            .program
            .retain_step_parents(filesystem, operation_index, current)?;
    let validate_retained_authority = || -> Result<()> {
        validate_transaction_v1_environment(filesystem, transaction, current)?;
        transaction.program.validate_retained_step_parents(
            filesystem,
            operation_index,
            current,
            &retained_parents,
        )
    };
    validate_retained_authority()?;
    if let Some(receipt) = load_private_abort_work_receipt(transaction, operation_index)? {
        verify_private_abort_work_receipt(filesystem, transaction, operation_index, &receipt)?;
        validate_retained_authority()?;
        return receipt.encoded_sha256();
    }

    let receipt = match transaction.program.step(operation_index)? {
        ProgramStepV1::MoveFile {
            source,
            destination,
            ..
        } => {
            let source_name = private_claim_name(operation_index, "source");
            let rollback_name = private_claim_name(operation_index, "rollback");
            let mut source_claim = private_regular_fact_if_present(
                &transaction.private.claims,
                &source_name,
                source.sha256,
            )?;
            if let Some(fact) = source_claim.as_ref() {
                require_move_abort_fact_shape(
                    transaction,
                    operation_index,
                    &source_name,
                    fact,
                    source,
                )?;
            }
            let mut rollback_claim = private_regular_fact_if_present(
                &transaction.private.claims,
                &rollback_name,
                source.sha256,
            )?;
            if let Some(fact) = rollback_claim.as_ref() {
                require_move_abort_fact_shape(
                    transaction,
                    operation_index,
                    &rollback_name,
                    fact,
                    source,
                )?;
            }
            let destination_is_published = regular_fact_matches_program(
                filesystem,
                destination.path,
                Some(source.physical_identity_sha256),
                source.bytes,
                source.sha256,
                source.fidelity.read_only,
                source.fidelity.executable,
            )?
            .is_some();
            if source_claim.is_none() {
                if rollback_claim.is_some() || destination_is_published {
                    return Err(FolderbaseError::MigrationVerificationFailed(
                        transaction
                            .private
                            .claims
                            .display_path(OsStr::new(&source_name)),
                    ));
                }
                filesystem.exact_regular_fact(
                    source.path,
                    ExactRegularLeaf {
                        physical_identity_sha256: source.physical_identity_sha256,
                        device_sha256: source.device_sha256,
                        bytes: source.bytes,
                        sha256: source.sha256,
                        read_only: source.fidelity.read_only,
                        executable: source.fidelity.executable,
                        link_count: source.link_count,
                    },
                )?;
                PrivateAbortWorkReceiptV1::new(
                    transaction,
                    operation_index,
                    Some(source.physical_identity_sha256.to_owned()),
                    Vec::new(),
                )?
            } else {
                if destination_is_published && rollback_claim.is_some() {
                    return Err(FolderbaseError::MigrationVerificationFailed(
                        filesystem.display(destination.path),
                    ));
                }
                if destination_is_published {
                    let source_claim_fact = source_claim.as_ref().expect("source claim exists");
                    let expected_claim_link_count =
                        source.link_count.checked_add(1).ok_or_else(|| {
                            FolderbaseError::MigrationSourceChanged(
                                filesystem.display(destination.path),
                            )
                        })?;
                    if source_claim_fact.link_count != expected_claim_link_count {
                        return Err(FolderbaseError::MigrationVerificationFailed(
                            transaction
                                .private
                                .claims
                                .display_path(OsStr::new(&source_name)),
                        ));
                    }
                    let destination_name = destination.path.file_name().ok_or_else(|| {
                        invalid_journal(destination.path, "program destination has no leaf name")
                    })?;
                    validate_retained_authority()?;
                    match filesystem.claim_exact_leaf_through(ExactLeafClaimRequest {
                        source_parent: retained_parents.get(destination.parent)?,
                        source_name: destination_name,
                        destination: &transaction.private.claims,
                        destination_name: &rollback_name,
                        expectation: ExactLeafClaimExpectation::Regular(ExactRegularLeaf {
                            physical_identity_sha256: source.physical_identity_sha256,
                            device_sha256: source.device_sha256,
                            bytes: source.bytes,
                            sha256: source.sha256,
                            read_only: source.fidelity.read_only,
                            executable: source.fidelity.executable,
                            link_count: expected_claim_link_count,
                        }),
                        existing_source: ExactExistingClaimSource::Absent,
                    })? {
                        ExactLeafClaimResult::Regular(_) => {}
                        ExactLeafClaimResult::Directory(_) => {
                            return Err(FolderbaseError::MigrationVerificationFailed(
                                transaction
                                    .private
                                    .claims
                                    .display_path(OsStr::new(&rollback_name)),
                            ));
                        }
                    }
                    validate_retained_authority()?;
                }

                let source_is_restored = regular_fact_matches_program(
                    filesystem,
                    source.path,
                    Some(source.physical_identity_sha256),
                    source.bytes,
                    source.sha256,
                    source.fidelity.read_only,
                    source.fidelity.executable,
                )?
                .is_some();
                if !source_is_restored && filesystem.metadata(source.path)?.is_some() {
                    return Err(FolderbaseError::WouldOverwrite(
                        filesystem.display(source.path),
                    ));
                }
                if !source_is_restored {
                    let destination_name = source.path.file_name().ok_or_else(|| {
                        invalid_journal(source.path, "program source has no leaf name")
                    })?;
                    validate_retained_authority()?;
                    filesystem.publish_private_claim_new_through(
                        &transaction.private.claims,
                        OsStr::new(&source_name),
                        retained_parents.get(source.parent)?,
                        destination_name,
                        source.physical_identity_sha256,
                        source.sha256,
                        source.bytes,
                    )?;
                    validate_retained_authority()?;
                }

                source_claim = private_regular_fact_if_present(
                    &transaction.private.claims,
                    &source_name,
                    source.sha256,
                )?;
                let source_claim = source_claim.ok_or_else(|| {
                    FolderbaseError::MigrationVerificationFailed(
                        transaction
                            .private
                            .claims
                            .display_path(OsStr::new(&source_name)),
                    )
                })?;
                rollback_claim = private_regular_fact_if_present(
                    &transaction.private.claims,
                    &rollback_name,
                    source.sha256,
                )?;
                let final_link_count = source
                    .link_count
                    .checked_add(1 + usize::from(rollback_claim.is_some()) as u64)
                    .ok_or_else(|| {
                        FolderbaseError::MigrationSourceChanged(filesystem.display(source.path))
                    })?;
                let restored = ExactRegularLeaf {
                    physical_identity_sha256: source.physical_identity_sha256,
                    device_sha256: source.device_sha256,
                    bytes: source.bytes,
                    sha256: source.sha256,
                    read_only: source.fidelity.read_only,
                    executable: source.fidelity.executable,
                    link_count: final_link_count,
                };
                transaction
                    .private
                    .claims
                    .exact_regular_fact(OsStr::new(&source_name), restored)?;
                if let Some(rollback_claim) = rollback_claim.as_ref() {
                    require_move_abort_fact_shape(
                        transaction,
                        operation_index,
                        &rollback_name,
                        rollback_claim,
                        source,
                    )?;
                    transaction
                        .private
                        .claims
                        .exact_regular_fact(OsStr::new(&rollback_name), restored)?;
                }
                if source_claim.link_count != final_link_count {
                    return Err(FolderbaseError::MigrationVerificationFailed(
                        transaction
                            .private
                            .claims
                            .display_path(OsStr::new(&source_name)),
                    ));
                }
                filesystem.exact_regular_fact(source.path, restored)?;
                validate_retained_authority()?;

                if rollback_claim.is_some() {
                    transaction.private.claims.remove_exact_owned_regular(
                        OsStr::new(&rollback_name),
                        ExactRegularLeaf {
                            physical_identity_sha256: source.physical_identity_sha256,
                            device_sha256: source.device_sha256,
                            bytes: source.bytes,
                            sha256: source.sha256,
                            read_only: source.fidelity.read_only,
                            executable: source.fidelity.executable,
                            link_count: final_link_count,
                        },
                    )?;
                    validate_retained_authority()?;
                    checkpoint(TransactionV1Checkpoint::MoveAbortRollbackClaimRetired(
                        operation_index,
                    ));
                }

                let source_claim_link_count =
                    source.link_count.checked_add(1).ok_or_else(|| {
                        FolderbaseError::MigrationSourceChanged(filesystem.display(source.path))
                    })?;
                transaction.private.claims.remove_exact_owned_regular(
                    OsStr::new(&source_name),
                    ExactRegularLeaf {
                        physical_identity_sha256: source.physical_identity_sha256,
                        device_sha256: source.device_sha256,
                        bytes: source.bytes,
                        sha256: source.sha256,
                        read_only: source.fidelity.read_only,
                        executable: source.fidelity.executable,
                        link_count: source_claim_link_count,
                    },
                )?;
                validate_retained_authority()?;
                checkpoint(TransactionV1Checkpoint::MoveAbortSourceClaimRetired(
                    operation_index,
                ));
                filesystem.exact_regular_fact(
                    source.path,
                    ExactRegularLeaf {
                        physical_identity_sha256: source.physical_identity_sha256,
                        device_sha256: source.device_sha256,
                        bytes: source.bytes,
                        sha256: source.sha256,
                        read_only: source.fidelity.read_only,
                        executable: source.fidelity.executable,
                        link_count: source.link_count,
                    },
                )?;
                validate_retained_authority()?;
                PrivateAbortWorkReceiptV1::new(
                    transaction,
                    operation_index,
                    Some(source.physical_identity_sha256.to_owned()),
                    Vec::new(),
                )?
            }
        }
        ProgramStepV1::CreateDirectory { target, fidelity } => {
            let publish_name = private_claim_name(operation_index, "publish");
            let claim =
                private_directory_fact_if_present(&transaction.private.claims, &publish_name)?;
            let claims = if let Some(claim) = claim {
                let exact = ExactDirectoryLeaf {
                    physical_identity_sha256: &claim.physical_identity_sha256,
                    device_sha256: &claim.device_sha256,
                    read_only: claim.read_only,
                    executable: directory_fact_executable(&claim),
                };
                if exact.device_sha256 != target.device_sha256
                    || exact.read_only != fidelity.read_only
                    || exact.executable != fidelity.executable
                {
                    return Err(FolderbaseError::MigrationVerificationFailed(
                        transaction
                            .private
                            .claims
                            .display_path(OsStr::new(&publish_name)),
                    ));
                }
                transaction
                    .private
                    .claims
                    .exact_empty_directory_fact(OsStr::new(&publish_name), exact)?;
                if filesystem.metadata(target.path)?.is_some() {
                    validate_retained_authority()?;
                    transaction
                        .private
                        .claims
                        .remove_exact_empty_directory(OsStr::new(&publish_name), exact)?;
                    validate_retained_authority()?;
                    Vec::new()
                } else {
                    vec![PrivateAbortClaimV1::Directory {
                        name: publish_name,
                        physical_identity_sha256: claim.physical_identity_sha256.clone(),
                        device_sha256: claim.device_sha256.clone(),
                        read_only: exact.read_only,
                        executable: exact.executable,
                        empty: true,
                    }]
                }
            } else {
                Vec::new()
            };
            validate_retained_authority()?;
            PrivateAbortWorkReceiptV1::new(transaction, operation_index, None, claims)?
        }
        ProgramStepV1::CreateFile { target, image } => {
            let publish_name = private_claim_name(operation_index, "publish");
            let rollback_name = private_claim_name(operation_index, "rollback");
            let Some(mut publish) = private_regular_fact_if_present(
                &transaction.private.claims,
                &publish_name,
                image.sha256,
            )?
            else {
                validate_retained_authority()?;
                return finish_private_abort_work_receipt(
                    filesystem,
                    transaction,
                    operation_index,
                    PrivateAbortWorkReceiptV1::new(transaction, operation_index, None, Vec::new())?,
                    checkpoint,
                    &validate_retained_authority,
                );
            };
            let require_publish_shape = |fact: &MigrationRegularFact, link_count: u64| {
                if fact.device_sha256 != target.device_sha256
                    || fact.bytes != image.bytes
                    || fact.read_only != image.fidelity.read_only
                    || regular_fact_executable(fact) != image.fidelity.executable
                    || fact.link_count != link_count
                {
                    return Err(FolderbaseError::MigrationVerificationFailed(
                        transaction
                            .private
                            .claims
                            .display_path(OsStr::new(&publish_name)),
                    ));
                }
                Ok(())
            };
            let mut rollback = private_regular_fact_if_present(
                &transaction.private.claims,
                &rollback_name,
                image.sha256,
            )?;
            if rollback.is_none() {
                let visible_is_exact = regular_fact_matches_program(
                    filesystem,
                    target.path,
                    Some(&publish.physical_identity_sha256),
                    image.bytes,
                    image.sha256,
                    image.fidelity.read_only,
                    image.fidelity.executable,
                )?
                .is_some();
                if visible_is_exact {
                    require_publish_shape(&publish, 2)?;
                    let expected = ExactRegularLeaf {
                        physical_identity_sha256: &publish.physical_identity_sha256,
                        device_sha256: target.device_sha256,
                        bytes: image.bytes,
                        sha256: image.sha256,
                        read_only: image.fidelity.read_only,
                        executable: image.fidelity.executable,
                        link_count: 2,
                    };
                    filesystem.exact_regular_fact(target.path, expected)?;
                    let target_name = target.path.file_name().ok_or_else(|| {
                        invalid_journal(target.path, "program target has no leaf name")
                    })?;
                    validate_retained_authority()?;
                    match filesystem.claim_exact_leaf_through(ExactLeafClaimRequest {
                        source_parent: retained_parents.get(target.parent)?,
                        source_name: target_name,
                        destination: &transaction.private.claims,
                        destination_name: &rollback_name,
                        expectation: ExactLeafClaimExpectation::Regular(expected),
                        existing_source: ExactExistingClaimSource::Absent,
                    })? {
                        ExactLeafClaimResult::Regular(_) => {}
                        ExactLeafClaimResult::Directory(_) => {
                            return Err(FolderbaseError::MigrationVerificationFailed(
                                transaction
                                    .private
                                    .claims
                                    .display_path(OsStr::new(&rollback_name)),
                            ));
                        }
                    }
                    validate_retained_authority()?;
                    rollback = private_regular_fact_if_present(
                        &transaction.private.claims,
                        &rollback_name,
                        image.sha256,
                    )?;
                } else {
                    require_publish_shape(&publish, 1)?;
                    let expected = ExactRegularLeaf {
                        physical_identity_sha256: &publish.physical_identity_sha256,
                        device_sha256: target.device_sha256,
                        bytes: image.bytes,
                        sha256: image.sha256,
                        read_only: image.fidelity.read_only,
                        executable: image.fidelity.executable,
                        link_count: 1,
                    };
                    validate_retained_authority()?;
                    transaction
                        .private
                        .claims
                        .remove_exact_owned_regular(OsStr::new(&publish_name), expected)?;
                    validate_retained_authority()?;
                    return finish_private_abort_work_receipt(
                        filesystem,
                        transaction,
                        operation_index,
                        PrivateAbortWorkReceiptV1::new(
                            transaction,
                            operation_index,
                            None,
                            Vec::new(),
                        )?,
                        checkpoint,
                        &validate_retained_authority,
                    );
                }
            }
            let rollback = rollback.ok_or_else(|| {
                FolderbaseError::MigrationVerificationFailed(
                    transaction
                        .private
                        .claims
                        .display_path(OsStr::new(&rollback_name)),
                )
            })?;
            publish = private_regular_fact_if_present(
                &transaction.private.claims,
                &publish_name,
                image.sha256,
            )?
            .ok_or_else(|| {
                FolderbaseError::MigrationVerificationFailed(
                    transaction
                        .private
                        .claims
                        .display_path(OsStr::new(&publish_name)),
                )
            })?;
            require_publish_shape(&publish, 2)?;
            if rollback.physical_identity_sha256 != publish.physical_identity_sha256
                || rollback.device_sha256 != publish.device_sha256
                || rollback.bytes != publish.bytes
                || rollback.unix_mode != publish.unix_mode
                || rollback.link_count != 2
            {
                return Err(FolderbaseError::MigrationVerificationFailed(
                    transaction
                        .private
                        .claims
                        .display_path(OsStr::new(&rollback_name)),
                ));
            }
            let claims = [&publish_name, &rollback_name]
                .into_iter()
                .map(|name| PrivateAbortClaimV1::Regular {
                    name: name.to_owned(),
                    physical_identity_sha256: publish.physical_identity_sha256.clone(),
                    device_sha256: publish.device_sha256.clone(),
                    bytes: image.bytes,
                    sha256: image.sha256.to_owned(),
                    read_only: image.fidelity.read_only,
                    executable: image.fidelity.executable,
                    link_count: 2,
                })
                .collect();
            validate_retained_authority()?;
            PrivateAbortWorkReceiptV1::new(transaction, operation_index, None, claims)?
        }
        ProgramStepV1::ReplaceFile { target, image, .. } => {
            let source_name = private_claim_name(operation_index, "source");
            let publish_name = private_claim_name(operation_index, "publish");
            let rollback_name = private_claim_name(operation_index, "rollback");
            let mut source = private_regular_fact_if_present(
                &transaction.private.claims,
                &source_name,
                target.sha256,
            )?;
            let publish = private_regular_fact_if_present(
                &transaction.private.claims,
                &publish_name,
                image.sha256,
            )?;
            let mut rollback = private_regular_fact_if_present(
                &transaction.private.claims,
                &rollback_name,
                image.sha256,
            )?;

            if source.is_none() {
                filesystem.exact_regular_fact(
                    target.path,
                    ExactRegularLeaf {
                        physical_identity_sha256: target.physical_identity_sha256,
                        device_sha256: target.device_sha256,
                        bytes: target.bytes,
                        sha256: target.sha256,
                        read_only: target.fidelity.read_only,
                        executable: target.fidelity.executable,
                        link_count: target.link_count,
                    },
                )?;
                if let Some(rollback_fact) = rollback.as_ref() {
                    let exact = ExactRegularLeaf {
                        physical_identity_sha256: &rollback_fact.physical_identity_sha256,
                        device_sha256: target.device_sha256,
                        bytes: image.bytes,
                        sha256: image.sha256,
                        read_only: image.fidelity.read_only,
                        executable: image.fidelity.executable,
                        link_count: 1 + u64::from(publish.is_some()),
                    };
                    transaction
                        .private
                        .claims
                        .exact_regular_fact(OsStr::new(&rollback_name), exact)?;
                }
                if let Some(publish_fact) = publish.as_ref() {
                    if rollback.as_ref().is_some_and(|rollback| {
                        rollback.physical_identity_sha256 != publish_fact.physical_identity_sha256
                    }) {
                        return Err(FolderbaseError::MigrationVerificationFailed(
                            transaction
                                .private
                                .claims
                                .display_path(OsStr::new(&rollback_name)),
                        ));
                    }
                    validate_retained_authority()?;
                    transaction.private.claims.remove_exact_owned_regular(
                        OsStr::new(&publish_name),
                        ExactRegularLeaf {
                            physical_identity_sha256: &publish_fact.physical_identity_sha256,
                            device_sha256: target.device_sha256,
                            bytes: image.bytes,
                            sha256: image.sha256,
                            read_only: image.fidelity.read_only,
                            executable: image.fidelity.executable,
                            link_count: 1 + u64::from(rollback.is_some()),
                        },
                    )?;
                    validate_retained_authority()?;
                }
                let claims = if let Some(rollback_fact) = rollback.take() {
                    let exact = ExactRegularLeaf {
                        physical_identity_sha256: &rollback_fact.physical_identity_sha256,
                        device_sha256: target.device_sha256,
                        bytes: image.bytes,
                        sha256: image.sha256,
                        read_only: image.fidelity.read_only,
                        executable: image.fidelity.executable,
                        link_count: 1,
                    };
                    transaction
                        .private
                        .claims
                        .exact_regular_fact(OsStr::new(&rollback_name), exact)?;
                    vec![PrivateAbortClaimV1::Regular {
                        name: rollback_name,
                        physical_identity_sha256: rollback_fact.physical_identity_sha256,
                        device_sha256: target.device_sha256.to_owned(),
                        bytes: image.bytes,
                        sha256: image.sha256.to_owned(),
                        read_only: image.fidelity.read_only,
                        executable: image.fidelity.executable,
                        link_count: 1,
                    }]
                } else {
                    Vec::new()
                };
                PrivateAbortWorkReceiptV1::new(
                    transaction,
                    operation_index,
                    Some(target.physical_identity_sha256.to_owned()),
                    claims,
                )?
            } else {
                let visible_original = regular_fact_matches_program(
                    filesystem,
                    target.path,
                    Some(target.physical_identity_sha256),
                    target.bytes,
                    target.sha256,
                    target.fidelity.read_only,
                    target.fidelity.executable,
                )?
                .is_some();
                let visible_publish_identity = publish
                    .as_ref()
                    .map(|fact| fact.physical_identity_sha256.as_str());
                let visible_replacement = visible_publish_identity.is_some()
                    && regular_fact_matches_program(
                        filesystem,
                        target.path,
                        visible_publish_identity,
                        image.bytes,
                        image.sha256,
                        image.fidelity.read_only,
                        image.fidelity.executable,
                    )?
                    .is_some();
                if !visible_original
                    && !visible_replacement
                    && filesystem.metadata(target.path)?.is_some()
                {
                    return Err(FolderbaseError::WouldOverwrite(
                        filesystem.display(target.path),
                    ));
                }
                if visible_replacement && rollback.is_some() {
                    return Err(FolderbaseError::MigrationVerificationFailed(
                        transaction
                            .private
                            .claims
                            .display_path(OsStr::new(&rollback_name)),
                    ));
                }

                let original_link_count = target
                    .link_count
                    .checked_add(u64::from(visible_original))
                    .ok_or_else(|| {
                        FolderbaseError::MigrationSourceChanged(filesystem.display(target.path))
                    })?;
                let original = ExactRegularLeaf {
                    physical_identity_sha256: target.physical_identity_sha256,
                    device_sha256: target.device_sha256,
                    bytes: target.bytes,
                    sha256: target.sha256,
                    read_only: target.fidelity.read_only,
                    executable: target.fidelity.executable,
                    link_count: original_link_count,
                };
                transaction
                    .private
                    .claims
                    .exact_regular_fact(OsStr::new(&source_name), original)?;
                if visible_original {
                    filesystem.exact_regular_fact(target.path, original)?;
                }

                if let Some(publish_fact) = publish.as_ref() {
                    let expected_link_count =
                        1 + u64::from(visible_replacement || rollback.is_some());
                    let exact = ExactRegularLeaf {
                        physical_identity_sha256: &publish_fact.physical_identity_sha256,
                        device_sha256: target.device_sha256,
                        bytes: image.bytes,
                        sha256: image.sha256,
                        read_only: image.fidelity.read_only,
                        executable: image.fidelity.executable,
                        link_count: expected_link_count,
                    };
                    transaction
                        .private
                        .claims
                        .exact_regular_fact(OsStr::new(&publish_name), exact)?;
                    if visible_replacement {
                        filesystem.exact_regular_fact(target.path, exact)?;
                    }
                } else if visible_replacement {
                    return Err(FolderbaseError::MigrationVerificationFailed(
                        transaction
                            .private
                            .claims
                            .display_path(OsStr::new(&publish_name)),
                    ));
                }
                if let Some(rollback_fact) = rollback.as_ref() {
                    let expected_link_count = 1 + u64::from(publish.is_some());
                    let exact = ExactRegularLeaf {
                        physical_identity_sha256: &rollback_fact.physical_identity_sha256,
                        device_sha256: target.device_sha256,
                        bytes: image.bytes,
                        sha256: image.sha256,
                        read_only: image.fidelity.read_only,
                        executable: image.fidelity.executable,
                        link_count: expected_link_count,
                    };
                    transaction
                        .private
                        .claims
                        .exact_regular_fact(OsStr::new(&rollback_name), exact)?;
                    if publish.as_ref().is_some_and(|publish| {
                        publish.physical_identity_sha256 != rollback_fact.physical_identity_sha256
                    }) {
                        return Err(FolderbaseError::MigrationVerificationFailed(
                            transaction
                                .private
                                .claims
                                .display_path(OsStr::new(&rollback_name)),
                        ));
                    }
                }

                if visible_replacement {
                    let publish_fact = publish.as_ref().ok_or_else(|| {
                        FolderbaseError::MigrationVerificationFailed(
                            transaction
                                .private
                                .claims
                                .display_path(OsStr::new(&publish_name)),
                        )
                    })?;
                    let target_name = target.path.file_name().ok_or_else(|| {
                        invalid_journal(target.path, "program target has no leaf name")
                    })?;
                    let expected = ExactRegularLeaf {
                        physical_identity_sha256: &publish_fact.physical_identity_sha256,
                        device_sha256: target.device_sha256,
                        bytes: image.bytes,
                        sha256: image.sha256,
                        read_only: image.fidelity.read_only,
                        executable: image.fidelity.executable,
                        link_count: 2,
                    };
                    validate_retained_authority()?;
                    match filesystem.claim_exact_leaf_through(ExactLeafClaimRequest {
                        source_parent: retained_parents.get(target.parent)?,
                        source_name: target_name,
                        destination: &transaction.private.claims,
                        destination_name: &rollback_name,
                        expectation: ExactLeafClaimExpectation::Regular(expected),
                        existing_source: ExactExistingClaimSource::Absent,
                    })? {
                        ExactLeafClaimResult::Regular(_) => {}
                        ExactLeafClaimResult::Directory(_) => {
                            return Err(FolderbaseError::MigrationVerificationFailed(
                                transaction
                                    .private
                                    .claims
                                    .display_path(OsStr::new(&rollback_name)),
                            ));
                        }
                    }
                    validate_retained_authority()?;
                    rollback = private_regular_fact_if_present(
                        &transaction.private.claims,
                        &rollback_name,
                        image.sha256,
                    )?;
                }

                if let Some(publish_fact) = publish.as_ref() {
                    let expected_link_count = 1 + u64::from(rollback.is_some());
                    let expected = ExactRegularLeaf {
                        physical_identity_sha256: &publish_fact.physical_identity_sha256,
                        device_sha256: target.device_sha256,
                        bytes: image.bytes,
                        sha256: image.sha256,
                        read_only: image.fidelity.read_only,
                        executable: image.fidelity.executable,
                        link_count: expected_link_count,
                    };
                    if rollback.as_ref().is_some_and(|rollback| {
                        rollback.physical_identity_sha256 != publish_fact.physical_identity_sha256
                    }) {
                        return Err(FolderbaseError::MigrationVerificationFailed(
                            transaction
                                .private
                                .claims
                                .display_path(OsStr::new(&rollback_name)),
                        ));
                    }
                    validate_retained_authority()?;
                    transaction
                        .private
                        .claims
                        .remove_exact_owned_regular(OsStr::new(&publish_name), expected)?;
                    validate_retained_authority()?;
                }

                if filesystem.metadata(target.path)?.is_none() {
                    let target_name = target.path.file_name().ok_or_else(|| {
                        invalid_journal(target.path, "program target has no leaf name")
                    })?;
                    validate_retained_authority()?;
                    transaction.private.claims.restore_exact_regular_through(
                        OsStr::new(&source_name),
                        retained_parents.get(target.parent)?,
                        target_name,
                        ExactRegularLeaf {
                            physical_identity_sha256: target.physical_identity_sha256,
                            device_sha256: target.device_sha256,
                            bytes: target.bytes,
                            sha256: target.sha256,
                            read_only: target.fidelity.read_only,
                            executable: target.fidelity.executable,
                            link_count: target.link_count,
                        },
                    )?;
                    validate_retained_authority()?;
                } else {
                    validate_retained_authority()?;
                    transaction.private.claims.remove_exact_owned_regular(
                        OsStr::new(&source_name),
                        ExactRegularLeaf {
                            physical_identity_sha256: target.physical_identity_sha256,
                            device_sha256: target.device_sha256,
                            bytes: target.bytes,
                            sha256: target.sha256,
                            read_only: target.fidelity.read_only,
                            executable: target.fidelity.executable,
                            link_count: target.link_count.checked_add(1).ok_or_else(|| {
                                FolderbaseError::MigrationSourceChanged(
                                    filesystem.display(target.path),
                                )
                            })?,
                        },
                    )?;
                    validate_retained_authority()?;
                }

                let final_original = ExactRegularLeaf {
                    physical_identity_sha256: target.physical_identity_sha256,
                    device_sha256: target.device_sha256,
                    bytes: target.bytes,
                    sha256: target.sha256,
                    read_only: target.fidelity.read_only,
                    executable: target.fidelity.executable,
                    link_count: target.link_count,
                };
                filesystem.exact_regular_fact(target.path, final_original)?;
                source = private_regular_fact_if_present(
                    &transaction.private.claims,
                    &source_name,
                    target.sha256,
                )?;
                if source.is_some() {
                    return Err(FolderbaseError::MigrationVerificationFailed(
                        transaction
                            .private
                            .claims
                            .display_path(OsStr::new(&source_name)),
                    ));
                }

                let mut claims = Vec::new();
                if let Some(rollback) = rollback {
                    let exact = ExactRegularLeaf {
                        physical_identity_sha256: &rollback.physical_identity_sha256,
                        device_sha256: target.device_sha256,
                        bytes: image.bytes,
                        sha256: image.sha256,
                        read_only: image.fidelity.read_only,
                        executable: image.fidelity.executable,
                        link_count: 1,
                    };
                    transaction
                        .private
                        .claims
                        .exact_regular_fact(OsStr::new(&rollback_name), exact)?;
                    claims.push(PrivateAbortClaimV1::Regular {
                        name: rollback_name,
                        physical_identity_sha256: rollback.physical_identity_sha256,
                        device_sha256: target.device_sha256.to_owned(),
                        bytes: image.bytes,
                        sha256: image.sha256.to_owned(),
                        read_only: image.fidelity.read_only,
                        executable: image.fidelity.executable,
                        link_count: 1,
                    });
                }
                validate_retained_authority()?;
                PrivateAbortWorkReceiptV1::new(
                    transaction,
                    operation_index,
                    Some(target.physical_identity_sha256.to_owned()),
                    claims,
                )?
            }
        }
    };
    finish_private_abort_work_receipt(
        filesystem,
        transaction,
        operation_index,
        receipt,
        checkpoint,
        &validate_retained_authority,
    )
}

fn preflight_transaction_v1_rollback_scope(
    filesystem: &MigrationFilesystem,
    transaction: &PreparedTransactionV1,
    current: &TransactionJournalGenerationV1,
) -> std::result::Result<(), (usize, FolderbaseError)> {
    let mut upper_bound = current.operation_cursor();
    if let Some(in_flight) = current.in_flight_operation() {
        upper_bound = upper_bound.max(in_flight.saturating_add(1));
    }
    for operation_index in (0..upper_bound).rev() {
        if let Err(error) =
            transaction
                .program
                .retain_step_parents(filesystem, operation_index, current)
        {
            return Err((operation_index, error));
        }
    }
    Ok(())
}

fn execute_transaction_v1_rollback_with_hook(
    filesystem: &MigrationFilesystem,
    transaction: &mut PreparedTransactionV1,
    mut checkpoint: impl FnMut(TransactionV1Checkpoint),
) -> Result<RollbackResult> {
    filesystem.require_atomic_noreplace()?;
    let mut removed_paths = Vec::new();
    loop {
        let current = transaction
            .generations
            .last()
            .expect("transaction-v1 has a validated generation")
            .clone();
        if current.phase() == TransactionPhaseV1::RolledBack {
            validate_transaction_v1_environment(filesystem, transaction, &current)?;
            reconcile_plan_terminal(filesystem, &transaction.program, MigrationState::RolledBack);
            return Ok(RollbackResult {
                migration_id: transaction.program.transaction_id().to_owned(),
                removed_paths,
                state: MigrationState::RolledBack,
            });
        }
        if current.direction() == TransactionDirectionV1::Apply {
            if let Some(index) = current.in_flight_operation()
                && let Some(receipt) =
                    load_private_leaf_receipt(transaction, index, PrivateReceiptDirectionV1::Apply)?
                && !is_exact_create_directory_prepublication_receipt(transaction, index, &receipt)?
            {
                if let Err(error) =
                    verify_apply_private_receipt(filesystem, transaction, index, &receipt)
                {
                    if is_private_transaction_integrity_error(&error) {
                        return Err(error);
                    }
                    record_transaction_v1_conflict(filesystem, transaction, index, &error)?;
                    checkpoint(TransactionV1Checkpoint::ConflictRecorded(index));
                    return Err(error);
                }
                let journal_receipt = current.next_apply_receipt(
                    &transaction.program,
                    index,
                    receipt.after_identity_sha256,
                )?;
                append_transaction_v1_generation(filesystem, transaction, journal_receipt)?;
                checkpoint(TransactionV1Checkpoint::JournalApplyReceiptPersisted(index));
                continue;
            }
            let requested = current.next_rollback_requested(&transaction.program)?;
            append_transaction_v1_generation(filesystem, transaction, requested)?;
            checkpoint(TransactionV1Checkpoint::RollbackRequested);
            continue;
        }
        if let Err((operation_index, error)) =
            preflight_transaction_v1_rollback_scope(filesystem, transaction, &current)
        {
            if is_private_transaction_integrity_error(&error) {
                return Err(error);
            }
            record_transaction_v1_conflict(filesystem, transaction, operation_index, &error)?;
            checkpoint(TransactionV1Checkpoint::ConflictRecorded(operation_index));
            return Err(error);
        }
        if let Some(index) = current.in_flight_operation() {
            if current.receipt_identity(index).is_none() {
                let private_receipt_sha256 = match abort_transaction_v1_in_flight_apply(
                    filesystem,
                    transaction,
                    index,
                    &mut checkpoint,
                ) {
                    Ok(digest) => digest,
                    Err(error) => {
                        if is_private_transaction_integrity_error(&error) {
                            return Err(error);
                        }
                        record_transaction_v1_conflict(filesystem, transaction, index, &error)?;
                        checkpoint(TransactionV1Checkpoint::ConflictRecorded(index));
                        return Err(error);
                    }
                };
                let aborted =
                    current.next_aborted_apply(&transaction.program, private_receipt_sha256)?;
                append_transaction_v1_generation(filesystem, transaction, aborted)?;
                checkpoint(TransactionV1Checkpoint::JournalAbortReceiptPersisted(index));
                continue;
            }
            let (removed, restored_identity) = match rollback_transaction_v1_step(
                filesystem,
                transaction,
                index,
                current.receipt_identity(index),
                &mut checkpoint,
            ) {
                Ok(outcome) => outcome,
                Err(error) => {
                    if is_private_transaction_integrity_error(&error) {
                        return Err(error);
                    }
                    record_transaction_v1_conflict(filesystem, transaction, index, &error)?;
                    checkpoint(TransactionV1Checkpoint::ConflictRecorded(index));
                    return Err(error);
                }
            };
            removed_paths.extend(removed);
            let receipt =
                current.next_rollback_receipt(&transaction.program, index, restored_identity)?;
            append_transaction_v1_generation(filesystem, transaction, receipt)?;
            checkpoint(TransactionV1Checkpoint::JournalRollbackReceiptPersisted(
                index,
            ));
            continue;
        }
        if current.operation_cursor() == 0 {
            let rolled_back = current.next_rolled_back(&transaction.program)?;
            append_transaction_v1_generation(filesystem, transaction, rolled_back)?;
            continue;
        }
        let index = current.operation_cursor() - 1;
        let intent = current.next_rollback_intent(&transaction.program, index)?;
        append_transaction_v1_generation(filesystem, transaction, intent)?;
    }
}

fn reconcile_plan_terminal(
    filesystem: &MigrationFilesystem,
    program: &MutationProgramV1,
    state: MigrationState,
) {
    let migration_id = program.transaction_id();
    let plan_relative = migration_plan_relative(migration_id);
    let Ok(bytes) = filesystem.read_regular_bounded(&plan_relative, MAX_MIGRATION_PLAN_BYTES)
    else {
        return;
    };
    let Ok(mut plan) = serde_json::from_slice::<MigrationPlan>(&bytes) else {
        return;
    };
    if plan.protocol_version != "0.2.0"
        || plan.id != migration_id
        || plan.root != filesystem.display_root()
        || plan.approval_digest.as_deref() != Some(program.approval_digest())
        || plan_digest(&plan).ok().as_deref() != Some(program.approval_digest())
    {
        return;
    }
    plan.state = state;
    let Ok(mut content) = serde_json::to_vec_pretty(&plan) else {
        return;
    };
    content.push(b'\n');
    let _ = filesystem.replace(&plan_relative, &content);
}

fn is_provable_prepared_transaction_v1_prefix(
    filesystem: &MigrationFilesystem,
    transaction_root: &Path,
) -> Result<bool> {
    let transaction = filesystem.open_private_directory(transaction_root)?;
    let entries = transaction.closed_entries(8)?;
    let directory_names = BTreeSet::from([
        OsString::from("journal"),
        OsString::from("stages"),
        OsString::from("claims"),
        OsString::from("snapshots"),
        OsString::from("receipts"),
    ]);
    for (name, is_directory) in &entries {
        let admitted = if directory_names.contains(name) {
            *is_directory
        } else {
            !*is_directory
                && matches!(
                    name.to_str(),
                    Some("program.json" | ".program.json.preparing")
                )
        };
        if !admitted {
            return Err(FolderbaseError::InvalidRecord {
                path: filesystem.display(&transaction_root.join(name)),
                message: "transaction-v1 contains an ambiguous pre-Prepared artifact".to_owned(),
            });
        }
    }

    if entries
        .iter()
        .any(|(name, _)| name == OsStr::new("journal"))
    {
        let journal = transaction.open_directory("journal")?;
        let journal_entries = journal.closed_entries(MAX_JOURNAL_GENERATIONS.saturating_add(1))?;
        for (name, is_directory) in &journal_entries {
            if name == OsStr::new(JOURNAL_GENERATION_STAGING_NAME) && !*is_directory {
                continue;
            }
            if !*is_directory
                && name
                    .to_str()
                    .is_some_and(|name| name.len() == 25 && name.ends_with(".json"))
            {
                return Ok(false);
            }
            return Err(FolderbaseError::InvalidRecord {
                path: filesystem.display(&transaction_root.join("journal").join(name)),
                message: "transaction journal contains an ambiguous pre-Prepared artifact"
                    .to_owned(),
            });
        }
    }
    for directory_name in ["claims", "receipts"] {
        if entries
            .iter()
            .any(|(name, _)| name == OsStr::new(directory_name))
        {
            let directory = transaction.open_directory(directory_name)?;
            if !directory.closed_entries(1)?.is_empty() {
                return Err(FolderbaseError::InvalidRecord {
                    path: filesystem.display(&transaction_root.join(directory_name)),
                    message: "pre-Prepared transaction contains execution evidence".to_owned(),
                });
            }
        }
    }
    Ok(true)
}

fn prepare_transaction_v1(
    filesystem: &MigrationFilesystem,
    plan: &MigrationPlan,
    approval_digest: &str,
    root_identity_sha256: String,
) -> Result<PreparedTransactionV1> {
    let migration_root = PathBuf::from(MIGRATIONS_DIR).join(&plan.id);
    let snapshots = migration_root.join("snapshots");
    filesystem.ensure_directory(Path::new(STATE_DIR))?;
    filesystem.ensure_directory(Path::new(MIGRATIONS_DIR))?;
    filesystem.ensure_directory(&migration_root)?;
    if filesystem.metadata(&snapshots)?.is_some() {
        filesystem.ensure_directory(&snapshots)?;
        let _ = filesystem
            .closed_regular_file_names(&snapshots, plan.operations.len().saturating_add(1))?;
    }
    let transaction_root = migration_root.join(TRANSACTION_DIRECTORY);
    let program_path = transaction_root.join("program.json");
    let journal_root = transaction_root.join("journal");
    let transaction_exists = filesystem.metadata(&transaction_root)?.is_some();
    if transaction_exists {
        match reopen_transaction_v1(filesystem, &migration_root, None) {
            Ok(reopened) => {
                if !reopened.program.matches_approval(
                    &plan.id,
                    approval_digest,
                    &root_identity_sha256,
                ) {
                    return Err(FolderbaseError::MigrationApprovalMismatch);
                }
                return Ok(reopened);
            }
            Err(reopen_error) => {
                if !is_provable_prepared_transaction_v1_prefix(filesystem, &transaction_root)? {
                    return Err(reopen_error);
                }
            }
        }
    }
    let materialization = compile_program_materialization(filesystem, plan)?;

    for directory in [
        transaction_root.clone(),
        journal_root.clone(),
        transaction_root.join("stages"),
        transaction_root.join("claims"),
        transaction_root.join("snapshots"),
        transaction_root.join("receipts"),
    ] {
        filesystem.ensure_private_directory(&directory)?;
    }
    let private = filesystem.open_private_directory(&transaction_root)?;
    let private_journal = private.open_directory("journal")?;
    let private_stages = private.open_directory("stages")?;
    let private_snapshots = private.open_directory("snapshots")?;
    let program = MutationProgramV1::compile(
        plan,
        approval_digest,
        root_identity_sha256,
        filesystem,
        &private_stages,
        &private_snapshots,
        materialization,
        |operation, current| {
            structural_result_bytes_from(
                &filesystem.display(
                    operation
                        .structural_source_path()
                        .unwrap_or_else(|| Path::new("<mutation-program-v1>")),
                ),
                current,
                operation,
            )
        },
    )?;
    let program_bytes = program.encode(&filesystem.display(&program_path))?;
    private.publish_recoverable_new("program.json", ".program.json.preparing", &program_bytes)?;
    let reopened_bytes =
        private.read_regular_bounded(OsStr::new("program.json"), MAX_PROGRAM_BYTES)?;
    let reopened = MutationProgramV1::decode(&filesystem.display(&program_path), &reopened_bytes)?;
    if reopened != program {
        return Err(FolderbaseError::MigrationVerificationFailed(
            filesystem.display(&program_path),
        ));
    }
    let program_digest = reopened.digest(&filesystem.display(&program_path))?;
    let initial = TransactionJournalGenerationV1::prepared(&reopened, program_digest.clone())?;
    let initial_path = journal_root.join(initial.file_name());
    let initial_bytes = initial.encode(&filesystem.display(&initial_path))?;
    private_journal.publish_recoverable_new(
        &initial.file_name(),
        JOURNAL_GENERATION_STAGING_NAME,
        &initial_bytes,
    )?;
    let prepared = reopen_transaction_v1(filesystem, &migration_root, Some(&reopened))?;
    prepared.program.validate_prepared_environment(filesystem)?;
    Ok(prepared)
}

fn validate_private_claim_set(
    filesystem: &MigrationFilesystem,
    transaction_root: &Path,
    transaction: &PreparedTransactionV1,
    observed_entries: &[(OsString, bool)],
) -> Result<()> {
    let current = transaction
        .generations
        .last()
        .ok_or_else(|| invalid_journal(Path::new("<transaction-v1>"), "journal is empty"))?;
    let apply_receipts = current
        .apply_receipt_records()
        .into_iter()
        .map(|(index, _)| index)
        .collect::<BTreeSet<_>>();
    let inverse_receipts = current
        .inverse_receipt_records()
        .into_iter()
        .map(|(index, _)| index)
        .collect::<BTreeSet<_>>();
    let mut allowed = BTreeMap::<OsString, bool>::new();
    let mut required = BTreeSet::<OsString>::new();
    let mut admit = |index: usize, kind: &str, is_directory: bool, must_exist: bool| {
        let name = OsString::from(private_claim_name(index, kind));
        allowed.insert(name.clone(), is_directory);
        if !is_directory {
            allowed.insert(
                OsString::from(format!(".{}.preparing", name.to_string_lossy())),
                false,
            );
            let ownership = OsString::from(format!(".{}.ownership.json", name.to_string_lossy()));
            allowed.insert(ownership.clone(), false);
            allowed.insert(
                OsString::from(format!(".{}.preparing", ownership.to_string_lossy())),
                false,
            );
        }
        if must_exist {
            required.insert(name);
        }
    };

    for index in 0..transaction.program.operation_count() {
        let apply_complete = apply_receipts.contains(&index);
        let apply_in_flight = !apply_complete && current.in_flight_operation() == Some(index);
        let apply_private_receipt =
            load_private_leaf_receipt(transaction, index, PrivateReceiptDirectionV1::Apply)?
                .is_some();
        let abort_private_receipt = load_private_abort_work_receipt(transaction, index)?;
        match transaction.program.step(index)? {
            ProgramStepV1::CreateDirectory { .. } => {
                if apply_in_flight {
                    admit(index, "publish", true, false);
                }
            }
            ProgramStepV1::CreateFile { .. } => {
                if apply_complete || apply_in_flight {
                    admit(
                        index,
                        "publish",
                        false,
                        apply_complete || apply_private_receipt,
                    );
                }
            }
            ProgramStepV1::ReplaceFile { .. } => {
                if apply_complete || apply_in_flight {
                    let must_exist = apply_complete || apply_private_receipt;
                    admit(index, "publish", false, must_exist);
                    admit(index, "source", false, must_exist);
                }
            }
            ProgramStepV1::MoveFile { .. } => {
                if apply_complete || apply_in_flight {
                    admit(
                        index,
                        "source",
                        false,
                        apply_complete || apply_private_receipt,
                    );
                }
            }
        }

        let rollback_complete = inverse_receipts.contains(&index);
        let rollback_in_flight = current.direction() == TransactionDirectionV1::Rollback
            && current.in_flight_operation() == Some(index)
            && apply_complete;
        let abort_in_flight = current.direction() == TransactionDirectionV1::Rollback
            && current.in_flight_operation() == Some(index)
            && !apply_complete;
        let rollback_private_receipt =
            load_private_leaf_receipt(transaction, index, PrivateReceiptDirectionV1::Rollback)?;
        let inverse_must_exist = rollback_complete || rollback_private_receipt.is_some();
        let unreceipted_abort_transition = abort_in_flight && abort_private_receipt.is_none();
        match transaction.program.step(index)? {
            ProgramStepV1::CreateDirectory { .. } => {
                if rollback_complete || rollback_in_flight || unreceipted_abort_transition {
                    let retained = rollback_private_receipt
                        .as_ref()
                        .is_some_and(|receipt| receipt.after_identity_sha256.is_some());
                    if !retained {
                        admit(index, "rollback", true, inverse_must_exist);
                    }
                }
            }
            ProgramStepV1::CreateFile { .. } => {
                if rollback_complete || rollback_in_flight || unreceipted_abort_transition {
                    admit(index, "rollback", false, inverse_must_exist);
                }
            }
            ProgramStepV1::ReplaceFile { .. } | ProgramStepV1::MoveFile { .. } => {
                if rollback_complete || rollback_in_flight || unreceipted_abort_transition {
                    admit(index, "rollback", false, inverse_must_exist);
                    admit(index, "restore", false, inverse_must_exist);
                }
            }
        }
        if let Some(receipt) = abort_private_receipt {
            for claim in receipt.claims {
                let kind = if claim.name() == private_claim_name(index, "source") {
                    "source"
                } else if claim.name() == private_claim_name(index, "publish") {
                    "publish"
                } else if claim.name() == private_claim_name(index, "rollback") {
                    "rollback"
                } else {
                    return Err(invalid_journal(
                        transaction
                            .private
                            .claims
                            .display_path(OsStr::new(claim.name())),
                        "abort receipt contains an impossible claim name",
                    ));
                };
                admit(index, kind, claim.is_directory(), true);
            }
        }
    }

    let claims_root = transaction_root.join("claims");
    let observed = observed_entries
        .iter()
        .map(|(name, is_directory)| (name.clone(), *is_directory))
        .collect::<BTreeMap<_, _>>();
    for (name, is_directory) in observed_entries {
        match allowed.get(name) {
            Some(expected_directory) if expected_directory == is_directory => {}
            Some(_) => {
                return Err(FolderbaseError::InvalidRecord {
                    path: filesystem.display(&claims_root.join(name)),
                    message: "private claim has the wrong artifact kind for this step".to_owned(),
                });
            }
            None => {
                return Err(FolderbaseError::InvalidRecord {
                    path: filesystem.display(&claims_root.join(name)),
                    message: "private claim is impossible in the durable transaction state"
                        .to_owned(),
                });
            }
        }
    }
    for name in required {
        if !observed.contains_key(&name) {
            return Err(FolderbaseError::InvalidRecord {
                path: filesystem.display(&claims_root.join(&name)),
                message: "durable transaction state is missing its exact private claim".to_owned(),
            });
        }
    }
    Ok(())
}

fn verify_create_directory_rollback_claim(
    transaction: &PreparedTransactionV1,
    operation_index: usize,
    published_identity: &str,
    device_sha256: &str,
    read_only: bool,
    executable: bool,
) -> Result<()> {
    transaction.private.claims.exact_empty_directory_fact(
        OsStr::new(&private_claim_name(operation_index, "rollback")),
        ExactDirectoryLeaf {
            physical_identity_sha256: published_identity,
            device_sha256,
            read_only,
            executable,
        },
    )?;
    Ok(())
}

fn validate_create_directory_rollback_dispositions(
    filesystem: &MigrationFilesystem,
    transaction: &PreparedTransactionV1,
) -> Result<()> {
    let current = transaction
        .generations
        .last()
        .ok_or_else(|| invalid_journal(Path::new("<transaction-v1>"), "journal is empty"))?;
    let terminal = current.phase() == TransactionPhaseV1::RolledBack;
    let mut operation_indices = current
        .inverse_receipt_records()
        .into_iter()
        .map(|(operation_index, _)| operation_index)
        .collect::<BTreeSet<_>>();
    if current.direction() == TransactionDirectionV1::Rollback
        && let Some(operation_index) = current.in_flight_operation()
        && load_private_leaf_receipt(
            transaction,
            operation_index,
            PrivateReceiptDirectionV1::Rollback,
        )?
        .is_some()
    {
        operation_indices.insert(operation_index);
    }
    for operation_index in operation_indices {
        let ProgramStepV1::CreateDirectory { target, fidelity } =
            transaction.program.step(operation_index)?
        else {
            continue;
        };
        let receipt = load_private_leaf_receipt(
            transaction,
            operation_index,
            PrivateReceiptDirectionV1::Rollback,
        )?
        .ok_or_else(|| {
            invalid_journal(
                Path::new("<private-leaf-receipt-v1>"),
                "durable directory inverse has no private receipt",
            )
        })?;
        if terminal {
            // Terminal history releases the ordinary pathname, so the user may
            // recreate it. Removed transaction-owned directories remain exact
            // immutable private evidence, however.
            if receipt.after_identity_sha256.is_none() {
                let published_identity =
                    receipt.before_identity_sha256.as_deref().ok_or_else(|| {
                        invalid_journal(
                            Path::new("<private-leaf-receipt-v1>"),
                            "rollback receipt has no apply identity",
                        )
                    })?;
                verify_create_directory_rollback_claim(
                    transaction,
                    operation_index,
                    published_identity,
                    target.device_sha256,
                    fidelity.read_only,
                    fidelity.executable,
                )?;
            }
            continue;
        }
        verify_rollback_private_receipt(filesystem, transaction, operation_index, &receipt)?;
    }
    Ok(())
}

fn reopen_transaction_v1(
    filesystem: &MigrationFilesystem,
    migration_root: &Path,
    expected_program: Option<&MutationProgramV1>,
) -> Result<PreparedTransactionV1> {
    let transaction_root = migration_root.join(TRANSACTION_DIRECTORY);
    let program_path = transaction_root.join("program.json");
    let transaction = filesystem.open_private_directory(&transaction_root)?;
    let journal = transaction.open_directory("journal")?;
    let stages = transaction.open_directory("stages")?;
    let claims = transaction.open_directory("claims")?;
    let snapshots = transaction.open_directory("snapshots")?;
    let receipts = transaction.open_directory("receipts")?;
    let expected_root_entries = BTreeSet::from([
        (OsString::from("claims"), true),
        (OsString::from("journal"), true),
        (OsString::from("program.json"), false),
        (OsString::from("receipts"), true),
        (OsString::from("snapshots"), true),
        (OsString::from("stages"), true),
    ]);
    let actual_root_entries = transaction
        .closed_entries(expected_root_entries.len())?
        .into_iter()
        .collect::<BTreeSet<_>>();
    if actual_root_entries != expected_root_entries {
        return Err(FolderbaseError::InvalidRecord {
            path: filesystem.display(&transaction_root),
            message: "transaction-v1 root contains missing or unknown entries".to_owned(),
        });
    }
    let (program_fact, _) =
        transaction.relaxed_regular_fact_observed(OsStr::new("program.json"))?;
    let program_bytes =
        transaction.read_relaxed_regular_bounded(OsStr::new("program.json"), MAX_PROGRAM_BYTES)?;
    let program = MutationProgramV1::decode(&filesystem.display(&program_path), &program_bytes)?;
    if expected_program.is_some_and(|expected| expected != &program) {
        return Err(FolderbaseError::MigrationApprovalMismatch);
    }
    let program_digest = program.digest(&filesystem.display(&program_path))?;
    let mut observed_claim_entries = Vec::new();
    for (directory, private_directory) in [
        ("stages", &stages),
        ("claims", &claims),
        ("snapshots", &snapshots),
        ("receipts", &receipts),
    ] {
        let relative = transaction_root.join(directory);
        let maximum_entries = match directory {
            "claims" => program
                .operation_count()
                .saturating_mul(12)
                .saturating_add(1),
            "receipts" => program
                .operation_count()
                .saturating_mul(6)
                .saturating_add(1),
            _ => program.operation_count().saturating_add(1),
        };
        let allowed = program.allowed_private_file_names(directory);
        if directory == "claims" {
            private_directory
                .repair_orphaned_private_publication_ownership(maximum_entries, &allowed)?;
        }
        let entries = private_directory.closed_entries(maximum_entries)?;
        if directory == "claims" {
            observed_claim_entries = entries.clone();
        }
        let names = entries
            .iter()
            .map(|(name, _)| name.clone())
            .collect::<BTreeSet<_>>();
        if matches!(directory, "stages" | "snapshots") && names != allowed {
            return Err(FolderbaseError::InvalidRecord {
                path: filesystem.display(&relative),
                message: "transaction-v1 contains missing or unknown immutable blobs".to_owned(),
            });
        }
        for (name, is_directory) in &entries {
            let receipt_staging_is_allowed = directory == "receipts"
                && recoverable_receipt_final_name(name)
                    .is_some_and(|final_name| allowed.contains(OsStr::new(&final_name)));
            if !allowed.contains(name) && !receipt_staging_is_allowed {
                return Err(FolderbaseError::InvalidRecord {
                    path: filesystem.display(&relative.join(name)),
                    message: "transaction-v1 contains an unknown private artifact".to_owned(),
                });
            }
            if *is_directory {
                let admitted_directory_claim = directory == "claims"
                    && (0..program.operation_count()).any(|index| {
                        (name == OsStr::new(&private_claim_name(index, "publish"))
                            || name == OsStr::new(&private_claim_name(index, "rollback")))
                            && matches!(
                                program.step(index),
                                Ok(ProgramStepV1::CreateDirectory { .. })
                            )
                    });
                if !admitted_directory_claim {
                    return Err(FolderbaseError::InvalidRecord {
                        path: filesystem.display(&relative.join(name)),
                        message: "transaction-v1 contains an unknown private directory artifact"
                            .to_owned(),
                    });
                }
                let _ = private_directory.relaxed_directory_fact(name)?;
            } else if directory == "claims" {
                let (fact, _) = private_directory.relaxed_regular_fact_observed(name)?;
                if fact.physical_identity_sha256 == program_fact.physical_identity_sha256 {
                    return Err(FolderbaseError::InvalidRecord {
                        path: filesystem.display(&relative.join(name)),
                        message: "private claim aliases the immutable program".to_owned(),
                    });
                }
            } else if directory == "receipts" {
                let fact = private_directory.relaxed_regular_fact_observed(name)?.0;
                if fact.physical_identity_sha256 == program_fact.physical_identity_sha256 {
                    return Err(FolderbaseError::InvalidRecord {
                        path: filesystem.display(&relative.join(name)),
                        message: "private receipt aliases the immutable program".to_owned(),
                    });
                }
                private_directory.verify_relaxed_regular(name)?;
            } else {
                private_directory.verify_regular(name)?;
            }
        }
    }
    if program_fact.link_count != 1 {
        return Err(FolderbaseError::InvalidRecord {
            path: filesystem.display(&program_path),
            message: "immutable program has a hard-link alias".to_owned(),
        });
    }
    transaction.verify_regular(OsStr::new("program.json"))?;
    program.validate_private_blobs(&stages, &snapshots)?;
    let journal_root = transaction_root.join("journal");
    repair_recoverable_journal_staging(
        filesystem,
        &journal,
        &journal_root,
        &program,
        &program_digest,
    )?;
    let mut generation_names =
        journal.closed_regular_file_names(program.maximum_journal_generations())?;
    generation_names.sort();
    let mut generations = Vec::with_capacity(generation_names.len());
    for (index, name) in generation_names.into_iter().enumerate() {
        let expected_name = format!("{index:020}.json");
        if name != OsStr::new(&expected_name) {
            return Err(FolderbaseError::InvalidRecord {
                path: filesystem.display(&journal_root.join(name)),
                message: "transaction journal contains an unknown or gapped generation".to_owned(),
            });
        }
        let path = journal_root.join(&expected_name);
        let bytes = journal
            .read_regular_bounded(OsStr::new(&expected_name), MAX_JOURNAL_GENERATION_BYTES)?;
        generations.push(TransactionJournalGenerationV1::decode(
            &filesystem.display(&path),
            &bytes,
        )?);
    }
    validate_chain(&program, &program_digest, &generations)?;
    let prepared = PreparedTransactionV1 {
        program,
        program_digest,
        generations,
        private: PrivateTransactionV1 {
            _transaction: transaction,
            journal,
            stages,
            claims,
            snapshots,
            receipts,
        },
    };
    repair_recoverable_private_receipt_staging(filesystem, &prepared)?;
    validate_private_leaf_receipt_set(&prepared)?;
    validate_private_claim_set(
        filesystem,
        &transaction_root,
        &prepared,
        &observed_claim_entries,
    )?;
    validate_create_directory_rollback_dispositions(filesystem, &prepared)?;
    validate_private_abort_work_receipts(filesystem, &prepared)?;
    Ok(prepared)
}

fn repair_recoverable_journal_staging(
    filesystem: &MigrationFilesystem,
    journal: &VerifiedPrivateDirectory,
    journal_root: &Path,
    program: &MutationProgramV1,
    program_digest: &str,
) -> Result<()> {
    let staging_name = OsStr::new(JOURNAL_GENERATION_STAGING_NAME);
    let entries =
        journal.closed_entries(program.maximum_journal_generations().saturating_add(1))?;
    let Some((_, staging_is_directory)) = entries.iter().find(|(name, _)| name == staging_name)
    else {
        return Ok(());
    };
    if *staging_is_directory {
        return Err(FolderbaseError::InvalidRecord {
            path: filesystem.display(&journal_root.join(staging_name)),
            message: "journal generation staging is not a regular file".to_owned(),
        });
    }

    let (staged_fact, staged_sha256) = journal.relaxed_regular_fact_observed(staging_name)?;
    let staged_bytes =
        journal.read_relaxed_regular_bounded(staging_name, MAX_JOURNAL_GENERATION_BYTES)?;
    let staging_path = journal_root.join(staging_name);
    let staged =
        TransactionJournalGenerationV1::decode(&filesystem.display(&staging_path), &staged_bytes)?;
    let destination_name = staged.file_name();
    let destination_name_os = OsStr::new(&destination_name);
    let final_exists = entries
        .iter()
        .any(|(name, is_directory)| name == destination_name_os && !is_directory);
    let mut generation_names = entries
        .iter()
        .filter(|(name, _)| name != staging_name && !(final_exists && name == destination_name_os))
        .map(|(name, _)| name.clone())
        .collect::<Vec<_>>();
    generation_names.sort();
    let mut generations = Vec::with_capacity(generation_names.len());
    for (index, name) in generation_names.into_iter().enumerate() {
        let expected_name = format!("{index:020}.json");
        if name != OsStr::new(&expected_name) {
            return Err(FolderbaseError::InvalidRecord {
                path: filesystem.display(&journal_root.join(name)),
                message: "transaction journal contains an unknown or gapped generation".to_owned(),
            });
        }
        let path = journal_root.join(&expected_name);
        let bytes = journal
            .read_regular_bounded(OsStr::new(&expected_name), MAX_JOURNAL_GENERATION_BYTES)?;
        generations.push(TransactionJournalGenerationV1::decode(
            &filesystem.display(&path),
            &bytes,
        )?);
    }
    let staged_is_valid = if generations.is_empty() {
        validate_chain(program, program_digest, std::slice::from_ref(&staged)).is_ok()
    } else {
        validate_chain(program, program_digest, &generations)?;
        validate_append(program, program_digest, &generations, &staged).is_ok()
    };
    if !staged_is_valid {
        return Err(FolderbaseError::InvalidRecord {
            path: filesystem.display(&staging_path),
            message: "recoverable journal staging is not the next admitted generation".to_owned(),
        });
    }

    if final_exists {
        let (final_fact, final_sha256) =
            journal.relaxed_regular_fact_observed(destination_name_os)?;
        if staged_fact.physical_identity_sha256 != final_fact.physical_identity_sha256
            || staged_fact.device_sha256 != final_fact.device_sha256
            || staged_fact.bytes != final_fact.bytes
            || staged_fact.bytes != staged_bytes.len() as u64
            || staged_fact.link_count != 2
            || final_fact.link_count != 2
            || staged_sha256 != final_sha256
        {
            return Err(FolderbaseError::InvalidRecord {
                path: filesystem.display(&journal_root.join(destination_name_os)),
                message: "journal final and recoverable staging are not one exact publication"
                    .to_owned(),
            });
        }
        journal.retire_exact_recoverable_regular(staging_name, &staged_fact, &staged_sha256, 2)?;
        journal.verify_regular(destination_name_os)?;
        return Ok(());
    }
    if staged_fact.link_count != 1 || staged_fact.bytes != staged_bytes.len() as u64 {
        return Err(FolderbaseError::InvalidRecord {
            path: filesystem.display(&staging_path),
            message: "journal generation staging has an unexpected alias topology".to_owned(),
        });
    }
    journal.install_recoverable_regular(
        staging_name,
        destination_name_os,
        &staged_sha256,
        staged_bytes.len() as u64,
    )
}

fn migration_command_id(command: MigrationCommand<'_>) -> &str {
    match command {
        MigrationCommand::Apply { migration_id, .. }
        | MigrationCommand::Recover { migration_id }
        | MigrationCommand::Rollback { migration_id } => migration_id,
    }
}

fn classify_execution_format(
    filesystem: &MigrationFilesystem,
    migration_id: &str,
) -> Result<ExecutionFormat> {
    let migration_root = PathBuf::from(MIGRATIONS_DIR).join(migration_id);
    let transaction_present = filesystem
        .metadata(&migration_root.join(TRANSACTION_DIRECTORY))?
        .is_some();
    let legacy_present = filesystem
        .metadata(&migration_root.join("result.json"))?
        .is_some();
    match (transaction_present, legacy_present) {
        (false, false) => Ok(ExecutionFormat::None),
        (true, false) => {
            let transaction_root = migration_root.join(TRANSACTION_DIRECTORY);
            if !is_provable_prepared_transaction_v1_prefix(filesystem, &transaction_root)? {
                return Ok(ExecutionFormat::TransactionV1);
            }
            match reopen_transaction_v1(filesystem, &migration_root, None) {
                Ok(_) => Ok(ExecutionFormat::TransactionV1),
                Err(_) => Ok(ExecutionFormat::PrePreparedTransactionV1),
            }
        }
        (false, true) => Ok(ExecutionFormat::LegacyResult),
        (true, true) => Err(FolderbaseError::InvalidRecord {
            path: filesystem.display(&migration_root),
            message:
                "migration contains both transaction-v1 and legacy result.json execution state"
                    .to_owned(),
        }),
    }
}

fn map_durable_transaction_v1_conflict(
    filesystem: &MigrationFilesystem,
    migration_root: &Path,
    migration_id: &str,
    result: Result<MigrationOutcome>,
    conflict_is_causal: bool,
) -> Result<MigrationOutcome> {
    let Err(error) = result else {
        return result;
    };
    if !conflict_is_causal {
        return Err(error);
    }
    if let Ok(transaction) = reopen_transaction_v1(filesystem, migration_root, None)
        && let Some(current) = transaction.generations.last()
        && current.phase() == TransactionPhaseV1::Conflicted
    {
        let direction = match current.direction() {
            TransactionDirectionV1::Apply => MigrationConflictDirection::Apply,
            TransactionDirectionV1::Rollback => MigrationConflictDirection::Rollback,
        };
        let conflicts = current
            .conflict_records()
            .into_iter()
            .map(|conflict| MigrationConflict {
                operation_index: conflict.operation_index,
                affected_paths: conflict.affected_paths,
                expected: conflict.expected,
                observed: conflict.observed,
                phase: "conflicted".to_owned(),
                direction,
                preserved_artifact: conflict.preserved_artifact,
            })
            .collect();
        return Ok(MigrationOutcome::Conflicted {
            migration_id: migration_id.to_owned(),
            conflicts,
        });
    }
    Err(error)
}

fn run_transaction_v1_in(
    filesystem: &MigrationFilesystem,
    command: MigrationCommand<'_>,
    checkpoint: impl FnMut(TransactionV1Checkpoint),
) -> Result<MigrationOutcome> {
    let migration_id = migration_command_id(command);
    let migration_root = PathBuf::from(MIGRATIONS_DIR).join(migration_id);
    let mut transaction = reopen_transaction_v1(filesystem, &migration_root, None)?;
    if let MigrationCommand::Apply {
        approval_digest, ..
    } = command
    {
        let root_identity_sha256 = filesystem
            .directory_fact(Path::new(""))?
            .physical_identity_sha256;
        if !transaction.program.matches_approval(
            migration_id,
            approval_digest,
            &root_identity_sha256,
        ) {
            return Err(FolderbaseError::MigrationApprovalMismatch);
        }
    }
    let conflict_recorded = Cell::new(false);
    let mut checkpoint = checkpoint;
    let mut tracked_checkpoint = |transaction_checkpoint| {
        if matches!(
            transaction_checkpoint,
            TransactionV1Checkpoint::ConflictRecorded(_)
        ) {
            conflict_recorded.set(true);
        }
        checkpoint(transaction_checkpoint);
    };
    let result = match command {
        MigrationCommand::Apply { .. } | MigrationCommand::Recover { .. }
            if transaction.generations.last().is_some_and(|generation| {
                generation.direction() == TransactionDirectionV1::Apply
            }) =>
        {
            execute_transaction_v1_apply_with_hook(
                filesystem,
                &mut transaction,
                &mut tracked_checkpoint,
            )
            .map(MigrationOutcome::Applied)
        }
        MigrationCommand::Recover { .. } | MigrationCommand::Rollback { .. } => {
            execute_transaction_v1_rollback_with_hook(
                filesystem,
                &mut transaction,
                &mut tracked_checkpoint,
            )
            .map(MigrationOutcome::RolledBack)
        }
        MigrationCommand::Apply { .. } => Err(FolderbaseError::InvalidMigrationState {
            expected: MigrationState::Applying.as_str(),
            actual: "rolling_back".to_owned(),
        }),
    };
    map_durable_transaction_v1_conflict(
        filesystem,
        &migration_root,
        migration_id,
        result,
        conflict_recorded.get(),
    )
}

fn run_current_transaction_v1_apply_with_hooks(
    display_root: &Path,
    migration_id: &str,
    approval_digest: &str,
    after_transaction_coordinator: impl FnOnce(),
    mut checkpoint: impl FnMut(ApplyCheckpoint),
    transaction_checkpoint: impl FnMut(TransactionV1Checkpoint),
) -> Result<MigrationOutcome> {
    let (root, root_identity) = canonical_root_with_identity(display_root)?;
    let coordinator = acquire_existing_folderbase_transaction_lock_with_hook(
        &root,
        root_identity.identity(),
        || checkpoint(ApplyCheckpoint::ExistingFolderbaseDetected),
    )?;
    require_no_pending_work_except(&coordinator.state, migration_id)?;
    let filesystem = coordinator.migration_filesystem(&root)?;
    let execution_format = classify_execution_format(&filesystem, migration_id)?;
    after_transaction_coordinator();
    match execution_format {
        ExecutionFormat::TransactionV1 => run_transaction_v1_in(
            &filesystem,
            MigrationCommand::Apply {
                migration_id,
                approval_digest,
            },
            transaction_checkpoint,
        ),
        ExecutionFormat::None | ExecutionFormat::PrePreparedTransactionV1 => {
            apply_transaction_v1_migration_in_with_hooks(
                &filesystem,
                migration_id,
                approval_digest,
                root_identity.identity().stable_sha256(),
                execution_format,
                checkpoint,
                transaction_checkpoint,
            )
        }
        ExecutionFormat::LegacyResult => Err(FolderbaseError::InvalidMigrationState {
            expected: MigrationState::Approved.as_str(),
            actual: "legacy_result".to_owned(),
        }),
    }
}

#[cfg(test)]
fn run_existing_transaction_v1_apply_with_root_hook(
    display_root: &Path,
    migration_id: &str,
    approval_digest: &str,
    after_initial_root_open: impl FnOnce(),
    transaction_checkpoint: impl FnMut(TransactionV1Checkpoint),
) -> Result<Option<MigrationOutcome>> {
    let (root, root_identity) =
        canonical_root_with_identity_with_hook(display_root, after_initial_root_open)?;
    let coordinator =
        acquire_existing_folderbase_transaction_lock(&root, root_identity.identity())?;
    require_no_pending_work_except(&coordinator.state, migration_id)?;
    let filesystem = coordinator.migration_filesystem(&root)?;
    match classify_execution_format(&filesystem, migration_id)? {
        ExecutionFormat::TransactionV1 => run_transaction_v1_in(
            &filesystem,
            MigrationCommand::Apply {
                migration_id,
                approval_digest,
            },
            transaction_checkpoint,
        )
        .map(Some),
        ExecutionFormat::None | ExecutionFormat::PrePreparedTransactionV1 => Ok(None),
        ExecutionFormat::LegacyResult => Err(FolderbaseError::InvalidMigrationState {
            expected: MigrationState::Approved.as_str(),
            actual: "legacy_result".to_owned(),
        }),
    }
}

fn run_current_migration_command_with_hooks(
    display_root: &Path,
    command: MigrationCommand<'_>,
    after_transaction_coordinator: impl FnOnce(),
    transaction_checkpoint: impl FnMut(TransactionV1Checkpoint),
) -> Result<MigrationOutcome> {
    run_current_migration_command_with_root_hook(
        display_root,
        command,
        || {},
        after_transaction_coordinator,
        transaction_checkpoint,
    )
}

fn run_current_migration_command_with_root_hook(
    display_root: &Path,
    command: MigrationCommand<'_>,
    after_initial_root_open: impl FnOnce(),
    after_transaction_coordinator: impl FnOnce(),
    transaction_checkpoint: impl FnMut(TransactionV1Checkpoint),
) -> Result<MigrationOutcome> {
    let (root, root_identity) =
        canonical_root_with_identity_with_hook(display_root, after_initial_root_open)?;
    let coordinator =
        acquire_existing_folderbase_transaction_lock(&root, root_identity.identity())?;
    let migration_id = migration_command_id(command);
    require_no_pending_work_except(&coordinator.state, migration_id)?;
    let filesystem = coordinator.migration_filesystem(&root)?;
    let format = classify_execution_format(&filesystem, migration_id)?;
    after_transaction_coordinator();
    match format {
        ExecutionFormat::TransactionV1 => {
            run_transaction_v1_in(&filesystem, command, transaction_checkpoint)
        }
        ExecutionFormat::None | ExecutionFormat::PrePreparedTransactionV1 => {
            Err(FolderbaseError::InvalidMigrationState {
                expected: MigrationState::Approved.as_str(),
                actual: "missing_execution_state".to_owned(),
            })
        }
        ExecutionFormat::LegacyResult => match command {
            MigrationCommand::Recover { .. } => {
                let result = legacy_recover_migration_in(&root, &filesystem, migration_id)?;
                legacy_recovery_outcome(result)
            }
            MigrationCommand::Rollback { .. } => {
                legacy_rollback_migration_by_id_in(&filesystem, migration_id)
                    .map(MigrationOutcome::RolledBack)
            }
            MigrationCommand::Apply { .. } => Err(FolderbaseError::InvalidMigrationState {
                expected: MigrationState::Approved.as_str(),
                actual: "missing_transaction_v1".to_owned(),
            }),
        },
    }
}

fn legacy_recovery_outcome(result: MigrationResult) -> Result<MigrationOutcome> {
    match result.state {
        MigrationState::Verified => Ok(MigrationOutcome::Applied(result)),
        MigrationState::RolledBack => Ok(MigrationOutcome::RolledBack(RollbackResult {
            migration_id: result.migration_id,
            removed_paths: Vec::new(),
            state: result.state,
        })),
        MigrationState::Conflicted => Ok(MigrationOutcome::Conflicted {
            migration_id: result.migration_id,
            conflicts: vec![MigrationConflict {
                operation_index: None,
                affected_paths: result.created_paths,
                expected: "released migration recovery to be resolved".to_owned(),
                observed: "released result.json remains conflicted".to_owned(),
                phase: "legacy_conflicted".to_owned(),
                direction: MigrationConflictDirection::LegacyUnknown,
                preserved_artifact: Some(result.journal_path),
            }],
        }),
        state => Err(invalid_journal(
            &result.journal_path,
            format!(
                "released migration recovery ended in unsupported execution state {}",
                state.as_str()
            ),
        )),
    }
}

#[cfg(test)]
fn run_transaction_v1_with_hook(
    display_root: &Path,
    command: MigrationCommand<'_>,
    checkpoint: impl FnMut(TransactionV1Checkpoint),
) -> Result<MigrationOutcome> {
    run_current_migration_command_with_hooks(display_root, command, || {}, checkpoint)
}

struct ExistingFolderbaseTransactionCoordinator {
    state: FolderbaseState,
    _lock: StoreTransactionLock,
}

impl ExistingFolderbaseTransactionCoordinator {
    fn migration_filesystem(&self, display_root: &Path) -> Result<MigrationFilesystem> {
        MigrationFilesystem::from_state(&self.state, display_root)
    }
}

fn acquire_existing_folderbase_transaction_lock(
    root: &Path,
    expected_root_identity: PhysicalIdentity,
) -> Result<ExistingFolderbaseTransactionCoordinator> {
    acquire_existing_folderbase_transaction_lock_with_hook(root, expected_root_identity, || {})
}

fn acquire_existing_folderbase_transaction_lock_with_hook(
    root: &Path,
    expected_root_identity: PhysicalIdentity,
    after_marker_probe: impl FnOnce(),
) -> Result<ExistingFolderbaseTransactionCoordinator> {
    let state = FolderbaseState::open_existing(root)?;
    state.verify_root_identity(&expected_root_identity)?;
    match state.classify_attached_root_boundary()? {
        NestedFolderbaseBoundaryKind::None | NestedFolderbaseBoundaryKind::ExactBoundary => {}
        NestedFolderbaseBoundaryKind::UnsafeAliasShape => {
            return Err(FolderbaseError::UnsafePath(root.to_path_buf()));
        }
    }
    after_marker_probe();
    state.verify_root_identity(&expected_root_identity)?;
    let lock = LocalVersionStore::acquire_transaction_lock_for_state(root, &state)?;
    state.verify_still_attached()?;
    Ok(ExistingFolderbaseTransactionCoordinator { state, _lock: lock })
}

fn require_no_pending_work_except(state: &FolderbaseState, migration_id: &str) -> Result<()> {
    match scan_pending_work(state, Some(migration_id)) {
        Ok(None) => Ok(()),
        Ok(Some(work)) => Err(FolderbaseError::RecoveryRequired {
            work: work.description(),
        }),
        Err(_) => Err(FolderbaseError::RecoveryRequired {
            work: "unreadable or unsafe transaction state".to_owned(),
        }),
    }
}

pub(crate) fn durable_migration_execution_is_terminal(
    state: &FolderbaseState,
    migration_id: &str,
) -> Result<Option<bool>> {
    let filesystem = MigrationFilesystem::from_state(state, state.display_root())?;
    match classify_execution_format(&filesystem, migration_id)? {
        ExecutionFormat::None => Ok(None),
        ExecutionFormat::PrePreparedTransactionV1 => Ok(Some(false)),
        ExecutionFormat::TransactionV1 => {
            let migration_root = PathBuf::from(MIGRATIONS_DIR).join(migration_id);
            let transaction = reopen_transaction_v1(&filesystem, &migration_root, None)?;
            let current = transaction.generations.last().ok_or_else(|| {
                invalid_journal(
                    Path::new("<transaction-v1>"),
                    "transaction journal has no generation",
                )
            })?;
            Ok(Some(matches!(
                current.phase(),
                TransactionPhaseV1::Applied | TransactionPhaseV1::RolledBack
            )))
        }
        ExecutionFormat::LegacyResult => {
            let (_, journal) = load_journal_from(&filesystem, migration_id)?;
            Ok(Some(matches!(
                journal.state,
                MigrationState::Verified | MigrationState::RolledBack
            )))
        }
    }
}

fn structural_visible_result_path(operation: &MigrationOperation) -> &Path {
    operation
        .structural_destination_path()
        .or_else(|| operation.structural_source_path())
        .expect("structural operation has one visible result path")
}

#[cfg(test)]
fn structural_result_bytes(source: &Path, operation: &MigrationOperation) -> Result<Vec<u8>> {
    let current = read_bounded_regular(source, MAX_MIGRATION_PLAN_BYTES)?;
    structural_result_bytes_from(source, &current, operation)
}

fn structural_result_bytes_from(
    source: &Path,
    current: &[u8],
    operation: &MigrationOperation,
) -> Result<Vec<u8>> {
    match operation {
        MigrationOperation::UpdateAdapter { managed_block, .. } => {
            let current =
                std::str::from_utf8(current).map_err(|_| FolderbaseError::InvalidRecord {
                    path: source.to_path_buf(),
                    message: "agent adapter must be UTF-8 text".to_owned(),
                })?;
            Ok(merge_managed_block(current, managed_block, source)?.into_bytes())
        }
        MigrationOperation::UpdateIgnorePolicy { content, .. } => Ok(content.as_bytes().to_vec()),
        MigrationOperation::UpdatePolicy { policy, value, .. } => {
            let mut document = parse_structural_json(source, current)?;
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
            let mut document = parse_structural_json(source, current)?;
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
            let mut document = parse_structural_json(source, current)?;
            set_object_lifecycle(source, &mut document, "canonical", None)?;
            pretty_json_bytes(source, &document)
        }
        MigrationOperation::MarkSuperseded { superseded_by, .. } => {
            let mut document = parse_structural_json(source, current)?;
            set_object_lifecycle(source, &mut document, "superseded", Some(superseded_by))?;
            pretty_json_bytes(source, &document)
        }
        MigrationOperation::ArchiveObject { .. } => {
            let mut document = parse_structural_json(source, current)?;
            set_object_lifecycle(source, &mut document, "archived", None)?;
            validate_archive_lifecycle(source, &document)?;
            pretty_json_bytes(source, &document)
        }
        MigrationOperation::AddRelationship {
            relationship_type,
            target_object_id,
            ..
        } => {
            let mut document = parse_structural_json(source, current)?;
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

fn replace_file_atomically_in(
    filesystem: &MigrationFilesystem,
    path: &Path,
    expected_sha256: &str,
    content: &[u8],
) -> Result<()> {
    if filesystem.sha256_regular(path)? != expected_sha256 {
        return Err(FolderbaseError::MigrationSourceChanged(
            filesystem.display(path),
        ));
    }
    filesystem.replace(path, content)?;
    if filesystem.sha256_regular(path)? != sha256_bytes(content) {
        return Err(FolderbaseError::MigrationVerificationFailed(
            filesystem.display(path),
        ));
    }
    Ok(())
}

#[cfg(test)]
#[allow(dead_code)]
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

#[cfg(test)]
#[allow(dead_code)]
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

fn move_file_no_replace_in(
    filesystem: &MigrationFilesystem,
    source: &Path,
    destination: &Path,
    expected_sha256: &str,
) -> Result<()> {
    if filesystem.metadata(destination)?.is_some() {
        return Err(FolderbaseError::WouldOverwrite(
            filesystem.display(destination),
        ));
    }
    if filesystem.sha256_regular(source)? != expected_sha256 {
        return Err(FolderbaseError::MigrationSourceChanged(
            filesystem.display(source),
        ));
    }
    filesystem.hard_link(source, destination)?;
    let linked = (|| -> Result<()> {
        if filesystem.sha256_regular(destination)? != expected_sha256
            || filesystem.sha256_regular(source)? != expected_sha256
        {
            return Err(FolderbaseError::MigrationSourceChanged(
                filesystem.display(source),
            ));
        }
        filesystem.remove_file(source)?;
        if filesystem.sha256_regular(destination)? != expected_sha256 {
            return Err(FolderbaseError::MigrationVerificationFailed(
                filesystem.display(destination),
            ));
        }
        Ok(())
    })();
    if linked.is_err()
        && filesystem
            .metadata(source)
            .is_ok_and(|value| value.is_some())
    {
        let _ = filesystem.remove_file_if_present(destination);
    }
    linked
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn compile_program_materialization(
    filesystem: &MigrationFilesystem,
    plan: &MigrationPlan,
) -> Result<ProgramMaterializationV1> {
    const TEMPLATE_ID: &str = "folderbase.project";
    const TEMPLATE_VERSION: &str = "0.2.2";
    const TEMPLATE_REFERENCE: &str = "folderbase.project@0.2.2";

    if is_structural_plan(plan) {
        return Ok(ProgramMaterializationV1 {
            directories: Vec::new(),
            files: Vec::new(),
            template_packages_sha256: sha256_bytes(b"folderbase-template-packages-v1\0"),
        });
    }
    if !plan
        .template_references
        .iter()
        .any(|reference| reference == TEMPLATE_REFERENCE)
    {
        return Err(invalid_journal(
            filesystem.display_root(),
            "migration plan does not bind the required folderbase template",
        ));
    }
    let (workspace_path, materializations) = approved_materialization_specs(
        &plan.answers,
        &plan.targets,
        &plan.operations,
        filesystem.display_root(),
    )?;
    let package = load_builtin_template(TEMPLATE_ID, TEMPLATE_VERSION)?;
    let package_digest = template_package_sha256(&package)?;
    let template_packages_sha256 = sha256_bytes(
        format!("folderbase-template-packages-v1\0{TEMPLATE_REFERENCE}\0{package_digest}")
            .as_bytes(),
    );
    let planned_directories = plan
        .operations
        .iter()
        .filter_map(|operation| match operation {
            MigrationOperation::CreateFolder { path } => Some(path.clone()),
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    let planned_files = plan
        .operations
        .iter()
        .filter_map(|operation| match operation {
            MigrationOperation::CopyFile {
                destination_path, ..
            } => Some(destination_path.clone()),
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    let mut directories = BTreeSet::new();
    let mut files = Vec::new();
    let mut materialized = Vec::new();

    for materialization in materializations {
        let path = materialization.path;
        let mut answers = BTreeMap::from([
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
        answers.insert(
            "folderbase_name".to_owned(),
            TemplateAnswerValue::Text(materialization.name.clone()),
        );
        let rendered = render_template_for_capability_destination(
            &package,
            &filesystem.display(&path),
            &answers,
        )?;
        let mut preserved = BTreeSet::new();
        for artifact in &package.artifacts {
            let relative = path.join(&artifact.target);
            if planned_directories.contains(&relative) || planned_files.contains(&relative) {
                let compatible = match artifact.kind {
                    TemplateArtifactKind::Directory => planned_directories.contains(&relative),
                    TemplateArtifactKind::Text => planned_files.contains(&relative),
                };
                if !compatible {
                    return Err(FolderbaseError::InvalidRecord {
                        path: filesystem.display(&relative),
                        message:
                            "approved destination kind is incompatible with its template artifact"
                                .to_owned(),
                    });
                }
                preserved.insert(relative);
                continue;
            }
            let Some(metadata) = filesystem.metadata(&relative)? else {
                continue;
            };
            let compatible = match artifact.kind {
                TemplateArtifactKind::Directory => {
                    metadata.is_dir() && !metadata.file_type().is_symlink()
                }
                TemplateArtifactKind::Text => {
                    metadata.is_file() && !metadata.file_type().is_symlink()
                }
            };
            if !compatible {
                return Err(FolderbaseError::InvalidRecord {
                    path: filesystem.display(&relative),
                    message: "template target exists with an incompatible filesystem kind"
                        .to_owned(),
                });
            }
            preserved.insert(relative);
        }
        for adapter_path in ["AGENTS.md", "CLAUDE.md"] {
            let relative = path.join(adapter_path);
            if planned_files.contains(&relative) {
                preserved.insert(relative);
                continue;
            }
            let Some(metadata) = filesystem.metadata(&relative)? else {
                continue;
            };
            if !metadata.is_file() || metadata.file_type().is_symlink() {
                return Err(FolderbaseError::InvalidRecord {
                    path: filesystem.display(&relative),
                    message: "agent adapter exists with an incompatible filesystem kind".to_owned(),
                });
            }
            preserved.insert(relative);
        }

        let identity_seed = serde_json::to_vec(&(plan.id.as_str(), &path))
            .map_err(|source| FolderbaseError::json(filesystem.display(&path), source))?;
        let identity_digest = Sha256::digest(&identity_seed);
        let mut identity_bytes = [0_u8; 16];
        identity_bytes.copy_from_slice(&identity_digest[..16]);
        identity_bytes[6] = (identity_bytes[6] & 0x0f) | 0x70;
        identity_bytes[8] = (identity_bytes[8] & 0x3f) | 0x80;
        let folderbase_id = format!("folderbase_{}", Uuid::from_bytes(identity_bytes));
        let migration_uuid = Uuid::parse_str(
            plan.id
                .strip_prefix("migration_")
                .ok_or_else(|| invalid_journal(&path, "migration ID has no UUID payload"))?,
        )
        .map_err(|_| invalid_journal(&path, "migration ID has an invalid UUID payload"))?;
        let timestamp = migration_uuid
            .get_timestamp()
            .ok_or_else(|| invalid_journal(&path, "migration ID has no timestamp"))?;
        let (seconds, nanos) = timestamp.to_unix();
        let created_at = DateTime::<Utc>::from_timestamp(seconds as i64, nanos)
            .ok_or_else(|| invalid_journal(&path, "migration timestamp is out of range"))?
            .to_rfc3339();
        let manifest_path = path.join(".folderbase/manifest.json");
        if planned_files.contains(&manifest_path) {
            return Err(invalid_journal(
                &manifest_path,
                "a materialized manifest must be compiler-generated",
            ));
        }
        let manifest = serde_json::json!({
            "$schema": "https://folderbase.ai/protocol/0.5/folderbase.schema.json",
            "protocol_version": "0.5.0",
            "folderbase": {
                "id": folderbase_id.clone(),
                "name": materialization.name.clone(),
                "kind": "project",
                "status": "active",
                "created_at": created_at.clone(),
                "template_provenance": {
                    "id": TEMPLATE_ID,
                    "version": TEMPLATE_VERSION,
                    "applied_at": created_at,
                    "package_digest": {
                        "algorithm": "sha256",
                        "digest": package_digest.clone()
                    }
                }
            },
            "adapters": [
                { "agent": "codex", "path": "AGENTS.md" },
                { "agent": "claude", "path": "CLAUDE.md" }
            ],
            "policies": {
                "availability": "keep_local",
                "structural_changes": "approve",
                "archive": "approve",
                "cloud_sync": "disabled",
                "capture_ignore": {
                    "format": "folderbase-capture-ignore-v1",
                    "rules": DEFAULT_V05_CAPTURE_IGNORE_RULES
                }
            }
        });
        let mut manifest_bytes = serde_json::to_vec_pretty(&manifest)
            .map_err(|source| FolderbaseError::json(&manifest_path, source))?;
        manifest_bytes.push(b'\n');

        for addition in rendered.additions {
            let relative = path.join(&addition.path);
            if preserved.contains(&relative) {
                continue;
            }
            match addition.kind {
                TemplateArtifactKind::Directory => {
                    directories.insert(relative);
                }
                TemplateArtifactKind::Text => files.push(ProgramGeneratedFileV1 {
                    role: if addition.path == Path::new("FOLDERBASE.md") {
                        ProgramGeneratedRoleV1::OrdinaryNarrative
                    } else {
                        ProgramGeneratedRoleV1::GeneratedGuidance
                    },
                    path: relative,
                    bytes: addition.content.unwrap_or_default().into_bytes(),
                }),
            }
        }
        directories.insert(path.join(".folderbase"));
        files.push(ProgramGeneratedFileV1 {
            path: manifest_path,
            bytes: manifest_bytes,
            role: ProgramGeneratedRoleV1::FolderbaseManifest,
        });
        let adapter = migration_agent_adapter().into_bytes();
        for adapter_path in ["AGENTS.md", "CLAUDE.md"] {
            let relative = path.join(adapter_path);
            if !preserved.contains(&relative) && !files.iter().any(|file| file.path == relative) {
                files.push(ProgramGeneratedFileV1 {
                    path: relative,
                    bytes: adapter.clone(),
                    role: ProgramGeneratedRoleV1::AgentAdapter,
                });
            }
        }
        materialized.push((path, folderbase_id, materialization.name));
    }

    if materialized.len() > 1 {
        let workspace_id = format!("workspace_{}", Uuid::now_v7());
        let name = materialized_workspace_name(&workspace_path);
        let links = materialized
            .iter()
            .map(|(path, folderbase_id, label)| {
                let relative = path.strip_prefix(&workspace_path).map_err(|_| {
                    invalid_journal(
                        filesystem.display_root(),
                        "materialized folderbase is outside its approved workspace",
                    )
                })?;
                ensure_safe_relative(relative)?;
                Ok((relative.to_path_buf(), folderbase_id.clone(), label.clone()))
            })
            .collect::<Result<Vec<_>>>()?;
        let descriptor = serde_json::json!({
            "$schema": "https://folderbase.ai/protocol/0.1/workspace.schema.json",
            "protocol_version": "0.1.0",
            "id": workspace_id,
            "name": name,
            "folderbases": links.iter().map(|(path, folderbase_id, label)| {
                serde_json::json!({
                    "folderbase_id": folderbase_id,
                    "label": label,
                    "path": path,
                })
            }).collect::<Vec<_>>(),
        });
        let descriptor_path = workspace_path.join(".folderbase-workspace.json");
        let mut descriptor_bytes = serde_json::to_vec_pretty(&descriptor)
            .map_err(|source| FolderbaseError::json(&descriptor_path, source))?;
        descriptor_bytes.push(b'\n');
        files.push(ProgramGeneratedFileV1 {
            path: descriptor_path,
            bytes: descriptor_bytes,
            role: ProgramGeneratedRoleV1::WorkspaceDescriptor,
        });

        let mut guidance = format!(
            "# {name}\n\nThis workspace is navigation only. It does not grant access to any folderbase.\n\n## Folderbases\n"
        );
        for (path, _, label) in &links {
            guidance.push_str(&format!(
                "- [{label}]({}/.folderbase/manifest.json)\n",
                path.display()
            ));
        }
        files.push(ProgramGeneratedFileV1 {
            path: workspace_path.join("WORKSPACE.md"),
            bytes: guidance.into_bytes(),
            role: ProgramGeneratedRoleV1::GeneratedGuidance,
        });
    }

    for operation in &plan.operations {
        let destination = match operation {
            MigrationOperation::CreateFolder { path } => path,
            MigrationOperation::CopyFile {
                destination_path, ..
            } => destination_path,
            _ => continue,
        };
        compile_missing_directory_parents(
            filesystem,
            destination,
            &planned_directories,
            &planned_files,
            &mut directories,
        )?;
    }
    for file in &files {
        compile_missing_directory_parents(
            filesystem,
            &file.path,
            &planned_directories,
            &planned_files,
            &mut directories,
        )?;
    }
    for planned in &planned_directories {
        directories.remove(planned);
    }
    validate_program_materialization_namespace(
        filesystem,
        &planned_directories,
        &planned_files,
        &directories,
        &files,
    )?;
    let mut directories = directories.into_iter().collect::<Vec<_>>();
    directories.sort_by(|left, right| {
        left.components()
            .count()
            .cmp(&right.components().count())
            .then_with(|| left.cmp(right))
    });
    files.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(ProgramMaterializationV1 {
        directories,
        files,
        template_packages_sha256,
    })
}

fn compile_missing_directory_parents(
    filesystem: &MigrationFilesystem,
    leaf: &Path,
    planned_directories: &BTreeSet<PathBuf>,
    planned_files: &BTreeSet<PathBuf>,
    generated_directories: &mut BTreeSet<PathBuf>,
) -> Result<()> {
    ensure_safe_relative(leaf)?;
    let mut parent = leaf.parent();
    while let Some(path) = parent {
        if path.as_os_str().is_empty() {
            break;
        }
        ensure_safe_relative(path)?;
        let parent_key = portable_path_key(path);
        if planned_files
            .iter()
            .any(|planned| portable_path_key(planned) == parent_key)
        {
            return Err(invalid_journal(
                filesystem.display(path),
                "a required parent directory collides with an approved file destination",
            ));
        }
        if !planned_directories.contains(path) {
            match filesystem.metadata(path)? {
                Some(metadata) if !metadata.is_dir() || metadata.file_type().is_symlink() => {
                    return Err(FolderbaseError::InvalidRecord {
                        path: filesystem.display(path),
                        message: "a required materialization parent is not a regular directory"
                            .to_owned(),
                    });
                }
                Some(_) => {}
                None => {
                    generated_directories.insert(path.to_path_buf());
                }
            }
        }
        parent = path.parent();
    }
    Ok(())
}

fn validate_program_materialization_namespace(
    filesystem: &MigrationFilesystem,
    planned_directories: &BTreeSet<PathBuf>,
    planned_files: &BTreeSet<PathBuf>,
    generated_directories: &BTreeSet<PathBuf>,
    generated_files: &[ProgramGeneratedFileV1],
) -> Result<()> {
    let mut namespace = BTreeMap::<PathBuf, (&'static str, PathBuf)>::new();
    let mut insert = |path: &Path,
                      kind: &'static str,
                      allow_exact_directory_duplicate: bool|
     -> Result<()> {
        ensure_safe_relative(path)?;
        let key = portable_path_key(path);
        if let Some((existing_kind, existing_path)) = namespace.get(&key) {
            if allow_exact_directory_duplicate
                && kind == "directory"
                && *existing_kind == "directory"
                && existing_path == path
            {
                return Ok(());
            }
            return Err(invalid_journal(
                filesystem.display(path),
                format!(
                    "materialization namespace collision between {existing_kind} {} and {kind} {}",
                    existing_path.display(),
                    path.display()
                ),
            ));
        }
        namespace.insert(key, (kind, path.to_path_buf()));
        Ok(())
    };

    for path in planned_directories {
        insert(path, "directory", true)?;
    }
    for path in generated_directories {
        insert(path, "directory", true)?;
    }
    for path in planned_files {
        insert(path, "file", false)?;
    }
    for file in generated_files {
        insert(&file.path, "file", false)?;
    }

    for (_, (_, path)) in namespace.iter() {
        let mut parent = path.parent();
        while let Some(candidate) = parent {
            if candidate.as_os_str().is_empty() {
                break;
            }
            if namespace
                .get(&portable_path_key(candidate))
                .is_some_and(|(kind, _)| *kind == "file")
            {
                return Err(invalid_journal(
                    filesystem.display(path),
                    format!(
                        "materialization path {} is nested beneath a file destination",
                        path.display()
                    ),
                ));
            }
            parent = candidate.parent();
        }
    }
    let mut admitted_parent_entries = BTreeMap::<PathBuf, Vec<OsString>>::new();
    for (_, (_, path)) in namespace.iter() {
        let parent = path.parent().unwrap_or_else(|| Path::new(""));
        if !parent.as_os_str().is_empty() {
            let Some(parent_metadata) = filesystem.metadata(parent)? else {
                continue;
            };
            if !parent_metadata.is_dir() || parent_metadata.file_type().is_symlink() {
                return Err(FolderbaseError::InvalidRecord {
                    path: filesystem.display(parent),
                    message: "materialization parent is not an admitted directory".to_owned(),
                });
            }
        }
        if !admitted_parent_entries.contains_key(parent) {
            admitted_parent_entries.insert(
                parent.to_path_buf(),
                filesystem.directory_entry_names(parent, 65_536)?,
            );
        }
        let target_name = path
            .file_name()
            .ok_or_else(|| invalid_journal(path, "materialization target has no file name"))?;
        let target_key = portable_path_key(Path::new(target_name));
        if admitted_parent_entries[parent]
            .iter()
            .any(|name| portable_path_key(Path::new(name)) == target_key)
        {
            return Err(invalid_journal(
                filesystem.display(path),
                "materialization target collides with an existing admitted sibling",
            ));
        }
    }
    Ok(())
}

fn migration_agent_adapter() -> String {
    "<!-- folderbase:begin -->\n\
     # Folderbase\n\n\
     Confirm this root through `.folderbase/manifest.json`, then work with its ordinary \
     files using Folderbase Core context and boundary rules. Treat summaries and questions \
     as optional hints, never as mutation or sharing authority.\n\
     <!-- folderbase:end -->\n"
        .to_owned()
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

/// Reopen a durable migration result by ID.
impl MigrationResult {
    pub fn reopen(root: impl AsRef<Path>, migration_id: &str) -> Result<Self> {
        reopen_migration_result(root.as_ref(), migration_id)
    }

    /// Recover an interrupted released migration.
    ///
    /// Legacy `result.json` executions retain their exact released Recover
    /// semantics. Transaction-v1 executions retain this adapter's conservative
    /// rollback behavior. Terminal results are reopened without rewriting.
    pub fn recover(root: impl AsRef<Path>, migration_id: &str) -> Result<Self> {
        let root = root.as_ref();
        let (current, format) = match reopen_migration_result_with_format(root, migration_id) {
            Ok(current) => current,
            Err(FolderbaseError::InvalidMigrationState { actual, .. })
                if actual == "missing_execution_state" =>
            {
                return Err(FolderbaseError::InvalidMigrationState {
                    expected: MigrationState::Approved.as_str(),
                    actual,
                });
            }
            Err(error) => return Err(error),
        };
        if matches!(
            current.state,
            MigrationState::Verified | MigrationState::Conflicted | MigrationState::RolledBack
        ) {
            return Ok(current);
        }
        let command = match format {
            ExecutionFormat::LegacyResult => MigrationCommand::Recover { migration_id },
            ExecutionFormat::TransactionV1 => MigrationCommand::Rollback { migration_id },
            ExecutionFormat::None | ExecutionFormat::PrePreparedTransactionV1 => {
                return Err(FolderbaseError::InvalidMigrationState {
                    expected: MigrationState::Approved.as_str(),
                    actual: "missing_execution_state".to_owned(),
                });
            }
        };
        match MigrationExecution::run(RootClaim::Current { display_root: root }, command)? {
            MigrationOutcome::RolledBack(_) => Self::reopen(root, migration_id),
            MigrationOutcome::Applied(result) if format == ExecutionFormat::LegacyResult => {
                Ok(result)
            }
            MigrationOutcome::Conflicted { .. } if format == ExecutionFormat::LegacyResult => {
                Self::reopen(root, migration_id)
            }
            MigrationOutcome::Applied(_) | MigrationOutcome::Conflicted { .. } => {
                Err(FolderbaseError::InvalidMigrationState {
                    expected: MigrationState::RolledBack.as_str(),
                    actual: MigrationState::Conflicted.as_str().to_owned(),
                })
            }
            MigrationOutcome::RecoveryRequired { work, .. } => {
                Err(FolderbaseError::RecoveryRequired { work })
            }
        }
    }

    /// Roll back a verified migration using only its durable ID.
    pub fn rollback_by_id(root: impl AsRef<Path>, migration_id: &str) -> Result<RollbackResult> {
        let root = root.as_ref();
        match MigrationExecution::run(
            RootClaim::Current { display_root: root },
            MigrationCommand::Rollback { migration_id },
        )? {
            MigrationOutcome::RolledBack(result) => Ok(result),
            MigrationOutcome::Applied(_) | MigrationOutcome::Conflicted { .. } => {
                Err(FolderbaseError::InvalidMigrationState {
                    expected: MigrationState::RolledBack.as_str(),
                    actual: MigrationState::Conflicted.as_str().to_owned(),
                })
            }
            MigrationOutcome::RecoveryRequired { work, .. } => {
                Err(FolderbaseError::RecoveryRequired { work })
            }
        }
    }
}

fn reopen_migration_result(root: &Path, migration_id: &str) -> Result<MigrationResult> {
    reopen_migration_result_with_root_hook(root, migration_id, || {})
}

fn reopen_migration_result_with_format(
    root: &Path,
    migration_id: &str,
) -> Result<(MigrationResult, ExecutionFormat)> {
    reopen_migration_result_with_format_and_root_hook(root, migration_id, || {})
}

fn reopen_migration_result_with_root_hook(
    root: &Path,
    migration_id: &str,
    after_initial_root_open: impl FnOnce(),
) -> Result<MigrationResult> {
    reopen_migration_result_with_format_and_root_hook(root, migration_id, after_initial_root_open)
        .map(|(result, _)| result)
}

fn reopen_migration_result_with_format_and_root_hook(
    root: &Path,
    migration_id: &str,
    after_initial_root_open: impl FnOnce(),
) -> Result<(MigrationResult, ExecutionFormat)> {
    let (root, root_identity) =
        canonical_root_with_identity_with_hook(root, after_initial_root_open)?;
    let coordinator =
        acquire_existing_folderbase_transaction_lock(&root, root_identity.identity())?;
    let filesystem = coordinator.migration_filesystem(&root)?;
    match classify_execution_format(&filesystem, migration_id)? {
        ExecutionFormat::TransactionV1 => {
            let migration_root = PathBuf::from(MIGRATIONS_DIR).join(migration_id);
            let transaction = reopen_transaction_v1(&filesystem, &migration_root, None)?;
            let current = transaction.generations.last().ok_or_else(|| {
                invalid_journal(
                    Path::new("<transaction-v1>"),
                    "transaction journal has no generation",
                )
            })?;
            let state = match current.phase() {
                TransactionPhaseV1::Prepared | TransactionPhaseV1::Applying => {
                    MigrationState::Applying
                }
                TransactionPhaseV1::Applied => MigrationState::Verified,
                TransactionPhaseV1::RollbackRequested | TransactionPhaseV1::RollingBack => {
                    MigrationState::RollingBack
                }
                TransactionPhaseV1::RolledBack => MigrationState::RolledBack,
                TransactionPhaseV1::Conflicted => MigrationState::Conflicted,
            };
            Ok((
                transaction_v1_result(&filesystem, &transaction, state),
                ExecutionFormat::TransactionV1,
            ))
        }
        ExecutionFormat::LegacyResult => {
            let (journal_path, journal) = load_journal_from(&filesystem, migration_id)?;
            Ok((
                result_from_journal(root, journal_path, &journal),
                ExecutionFormat::LegacyResult,
            ))
        }
        ExecutionFormat::None => Err(FolderbaseError::InvalidMigrationState {
            expected: MigrationState::Applying.as_str(),
            actual: "missing_execution_state".to_owned(),
        }),
        ExecutionFormat::PrePreparedTransactionV1 => Err(FolderbaseError::InvalidMigrationState {
            expected: MigrationState::Applying.as_str(),
            actual: "pre_prepared_execution_state".to_owned(),
        }),
    }
}

fn legacy_recover_migration_in(
    root: &Path,
    migration_filesystem: &MigrationFilesystem,
    migration_id: &str,
) -> Result<MigrationResult> {
    let (journal_path, mut journal) = load_journal_from(migration_filesystem, migration_id)?;
    if matches!(
        journal.state,
        MigrationState::Applying | MigrationState::RollingBack
    ) {
        if is_structural_journal(&journal) {
            rollback_structural_journal_in(migration_filesystem, &journal_path, &mut journal)?;
        } else {
            rollback_journal_in(migration_filesystem, &journal_path, &mut journal)?;
        }
        persist_plan_transition_in(
            migration_filesystem,
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
        persist_plan_transition_in(
            migration_filesystem,
            migration_id,
            &[MigrationState::Applying, MigrationState::Verified],
            MigrationState::Verified,
        )?;
        cleanup_staging_in(migration_filesystem, migration_id);
    } else if journal.state == MigrationState::RolledBack {
        let plan = load_plan_from(migration_filesystem, migration_id)?;
        if plan.state != MigrationState::Conflicted {
            persist_plan_transition_in(
                migration_filesystem,
                migration_id,
                &[
                    MigrationState::Applying,
                    MigrationState::Verified,
                    MigrationState::RolledBack,
                ],
                MigrationState::RolledBack,
            )?;
        }
        cleanup_staging_in(migration_filesystem, migration_id);
    }
    Ok(result_from_journal(
        root.to_path_buf(),
        journal_path,
        &journal,
    ))
}

fn legacy_rollback_migration_by_id_in(
    migration_filesystem: &MigrationFilesystem,
    migration_id: &str,
) -> Result<RollbackResult> {
    let (journal_path, mut journal) = load_journal_from(migration_filesystem, migration_id)?;
    if journal.state == MigrationState::RolledBack {
        return Ok(RollbackResult {
            migration_id: journal.id,
            removed_paths: Vec::new(),
            state: MigrationState::RolledBack,
        });
    }
    require_state(journal.state, MigrationState::Verified)?;
    let result = if is_structural_journal(&journal) {
        rollback_structural_journal_in(migration_filesystem, &journal_path, &mut journal)?
    } else {
        rollback_journal_in(migration_filesystem, &journal_path, &mut journal)?
    };
    persist_plan_transition_in(
        migration_filesystem,
        migration_id,
        &[MigrationState::Verified],
        MigrationState::RolledBack,
    )?;
    Ok(result)
}

/// Roll back only additive, unchanged paths recorded by a verified migration.
pub fn rollback_migration(result: &MigrationResult) -> Result<RollbackResult> {
    require_state(result.state, MigrationState::Verified)?;
    MigrationResult::rollback_by_id(&result.root, &result.migration_id)
}

#[cfg(test)]
#[allow(dead_code)]
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

fn create_private_directory_if_missing(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => Ok(()),
        Ok(_) => Err(FolderbaseError::WouldOverwrite(path.to_path_buf())),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
            create_private_directory_new(path)
        }
        Err(source) => Err(FolderbaseError::io(path, source)),
    }
}

fn create_private_directory_new(path: &Path) -> Result<()> {
    let builder = fs::DirBuilder::new();
    #[cfg(unix)]
    let builder = {
        use std::os::unix::fs::DirBuilderExt;

        let mut builder = builder;
        builder.mode(0o700);
        builder
    };
    builder.create(path).map_err(|source| {
        if source.kind() == std::io::ErrorKind::AlreadyExists {
            FolderbaseError::WouldOverwrite(path.to_path_buf())
        } else {
            FolderbaseError::io(path, source)
        }
    })?;
    let metadata =
        fs::symlink_metadata(path).map_err(|source| FolderbaseError::io(path, source))?;
    validate_private_directory_mode(path, &metadata)?;
    sync_parent(path)
}

fn validate_private_directory_mode(path: &Path, metadata: &fs::Metadata) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        if metadata.permissions().mode() & 0o777 != 0o700 {
            return Err(FolderbaseError::InvalidRecord {
                path: path.to_path_buf(),
                message: "private migration directory is not owner-only".to_owned(),
            });
        }
    }
    #[cfg(not(unix))]
    let _ = (path, metadata);
    Ok(())
}

#[cfg(test)]
#[allow(dead_code)]
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

fn load_journal_from(
    filesystem: &MigrationFilesystem,
    migration_id: &str,
) -> Result<(PathBuf, MigrationJournal)> {
    validate_migration_id(filesystem.display_root(), migration_id)?;
    let journal_relative = PathBuf::from(MIGRATIONS_DIR)
        .join(migration_id)
        .join("result.json");
    let journal_path = filesystem.display(&journal_relative);
    let bytes = filesystem.read_regular_bounded(&journal_relative, MAX_MIGRATION_PLAN_BYTES)?;
    let journal: MigrationJournal = serde_json::from_slice(&bytes)
        .map_err(|source| FolderbaseError::json(&journal_path, source))?;
    validate_journal(
        filesystem.display_root(),
        migration_id,
        &journal_path,
        &journal,
    )?;
    if is_structural_journal(&journal) {
        let plan = load_plan_from(filesystem, migration_id)?;
        validate_structural_recovery_invariants_in(filesystem, &journal_path, &plan, &journal)?;
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
    if !matches!(
        journal.state,
        MigrationState::Applying
            | MigrationState::Verified
            | MigrationState::Conflicted
            | MigrationState::RollingBack
            | MigrationState::RolledBack
    ) {
        return Err(invalid_journal(
            journal_path,
            format!(
                "released migration journal has unsupported execution state {}",
                journal.state.as_str()
            ),
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

#[cfg(test)]
#[allow(dead_code)]
fn validate_structural_recovery_invariants(
    root: &Path,
    journal_path: &Path,
    plan: &MigrationPlan,
    journal: &MigrationJournal,
) -> Result<()> {
    validate_structural_recovery_invariants_with(journal_path, plan, journal, |operation| {
        observe_structural_disk_state(root, operation)
    })
}

fn validate_structural_recovery_invariants_in(
    filesystem: &MigrationFilesystem,
    journal_path: &Path,
    plan: &MigrationPlan,
    journal: &MigrationJournal,
) -> Result<()> {
    validate_structural_recovery_invariants_with(journal_path, plan, journal, |operation| {
        observe_structural_disk_state_in(filesystem, operation)
    })
}

fn validate_structural_recovery_invariants_with(
    journal_path: &Path,
    plan: &MigrationPlan,
    journal: &MigrationJournal,
    mut observe: impl FnMut(&MigrationOperation) -> Result<StructuralDiskState>,
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
        let observed = observe(operation)?;
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

#[cfg(test)]
#[allow(dead_code)]
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

fn observe_structural_disk_state_in(
    filesystem: &MigrationFilesystem,
    operation: &MigrationOperation,
) -> Result<StructuralDiskState> {
    match operation {
        MigrationOperation::MoveObject {
            source_path,
            destination_path,
            expected_sha256,
            ..
        } => {
            let source_digest = filesystem.sha256_regular_if_present(source_path)?;
            let destination_digest = filesystem.sha256_regular_if_present(destination_path)?;
            match (source_digest, destination_digest) {
                (Some(source_digest), None) if source_digest == *expected_sha256 => {
                    Ok(StructuralDiskState::Original)
                }
                (None, Some(_)) => Ok(StructuralDiskState::Applied),
                (Some(source_digest), Some(destination_digest))
                    if source_digest == *expected_sha256
                        && destination_digest == *expected_sha256 =>
                {
                    let (source_capability, destination_capability) =
                        open_migration_leaf_pair_in(filesystem, source_path, destination_path)?;
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
            let expected = operation
                .structural_expected_sha256()
                .expect("structural operation has an approved source digest");
            let result = operation
                .structural_expected_result_sha256()
                .expect("structural mutation has an approved result digest");
            match filesystem.sha256_regular_if_present(source_path)? {
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

#[cfg(test)]
#[allow(dead_code)]
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

fn reconcile_in_flight_in(
    filesystem: &MigrationFilesystem,
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
            if let Some(metadata) = filesystem.metadata(&path)?
                && !journal.created_paths.contains(&path)
            {
                if !metadata.is_dir() || metadata.file_type().is_symlink() {
                    return Err(FolderbaseError::MigrationVerificationFailed(
                        filesystem.display(&path),
                    ));
                }
                journal.created_paths.push(path);
            }
        }
        MigrationOperation::CopyFile {
            destination_path,
            expected_sha256,
            ..
        } => {
            if let Some(metadata) = filesystem.metadata(&destination_path)?
                && !journal.created_paths.contains(&destination_path)
            {
                if !metadata.is_file()
                    || metadata.file_type().is_symlink()
                    || filesystem.sha256_regular(&destination_path)? != expected_sha256
                {
                    return Err(FolderbaseError::MigrationVerificationFailed(
                        filesystem.display(&destination_path),
                    ));
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
    persist_journal_in(filesystem, journal)
}

#[cfg(test)]
#[allow(dead_code)]
fn reconcile_structural_in_flight(
    root: &Path,
    journal_path: &Path,
    journal: &mut MigrationJournal,
) -> Result<()> {
    reconcile_structural_in_flight_with_hook(root, journal_path, journal, |_| {})
}

fn reconcile_structural_in_flight_in(
    filesystem: &MigrationFilesystem,
    journal_path: &Path,
    journal: &mut MigrationJournal,
) -> Result<()> {
    let Some(index) = journal.in_flight_operation else {
        return Ok(());
    };
    let operation = journal
        .operations
        .get(index)
        .ok_or_else(|| invalid_journal(journal_path, "in-flight operation is out of range"))?;
    let expected_precondition_identity = journal
        .operation_precondition_identities
        .get(index)
        .and_then(|identity| identity.as_deref());
    let expected_result_identity = journal
        .operation_result_identities
        .get(index)
        .and_then(|identity| identity.as_deref());
    let verify_identity = |path: &Path, expected: Option<&str>| -> Result<()> {
        if let Some(expected) = expected
            && filesystem.physical_identity_sha256(path)? != expected
        {
            return Err(FolderbaseError::MigrationVerificationFailed(
                filesystem.display(path),
            ));
        }
        Ok(())
    };
    refuse_structural_operation_boundaries_in(filesystem, operation)?;
    let applied = match operation {
        MigrationOperation::MoveObject {
            source_path,
            destination_path,
            expected_sha256,
            ..
        } => {
            let source_digest = filesystem.sha256_regular_if_present(source_path)?;
            let destination_digest = filesystem.sha256_regular_if_present(destination_path)?;
            if journal.state == MigrationState::RollingBack {
                match (source_digest, destination_digest) {
                    (Some(source_digest), Some(destination_digest))
                        if source_digest == *expected_sha256
                            && destination_digest == *expected_sha256 =>
                    {
                        verify_identity(source_path, expected_precondition_identity)?;
                        verify_identity(destination_path, expected_result_identity)?;
                        let (source_capability, destination_capability) =
                            open_migration_leaf_pair_in(filesystem, source_path, destination_path)?;
                        if source_capability.identity == destination_capability.identity {
                            remove_matching_destination_with(
                                source_capability,
                                destination_capability,
                                &mut |_| {},
                            )?;
                        }
                        true
                    }
                    (Some(source_digest), _) if source_digest == *expected_sha256 => {
                        verify_identity(source_path, expected_precondition_identity)?;
                        true
                    }
                    (None, _) => false,
                    _ => {
                        return Err(FolderbaseError::MigrationVerificationFailed(
                            filesystem.display(source_path),
                        ));
                    }
                }
            } else {
                match (source_digest, destination_digest) {
                    (Some(source_digest), None) if source_digest == *expected_sha256 => {
                        verify_identity(source_path, expected_precondition_identity)?;
                        false
                    }
                    (None, Some(destination_digest)) if destination_digest == *expected_sha256 => {
                        verify_identity(destination_path, expected_result_identity)?;
                        true
                    }
                    (Some(source_digest), Some(destination_digest))
                        if source_digest == *expected_sha256
                            && destination_digest == *expected_sha256 =>
                    {
                        verify_identity(source_path, expected_precondition_identity)?;
                        verify_identity(destination_path, expected_result_identity)?;
                        let (source_capability, destination_capability) =
                            open_migration_leaf_pair_in(filesystem, source_path, destination_path)?;
                        if source_capability.identity != destination_capability.identity {
                            return Err(FolderbaseError::MigrationVerificationFailed(
                                filesystem.display(destination_path),
                            ));
                        }
                        remove_matching_destination_with(
                            source_capability,
                            destination_capability,
                            &mut |_| {},
                        )?;
                        false
                    }
                    _ => {
                        return Err(FolderbaseError::MigrationVerificationFailed(
                            filesystem.display(destination_path),
                        ));
                    }
                }
            }
        }
        operation if operation.is_structural() => {
            let source_path = operation
                .structural_source_path()
                .expect("structural operation has a source");
            let current = filesystem.sha256_regular(source_path)?;
            let expected = operation
                .structural_expected_sha256()
                .expect("structural operation has a source digest");
            let result = operation
                .structural_expected_result_sha256()
                .expect("structural operation has a result digest");
            if journal.state == MigrationState::RollingBack {
                if current == expected {
                    verify_identity(source_path, expected_precondition_identity)?;
                    true
                } else if current == result {
                    verify_identity(source_path, expected_result_identity)?;
                    false
                } else {
                    return Err(FolderbaseError::MigrationVerificationFailed(
                        filesystem.display(source_path),
                    ));
                }
            } else if current == expected {
                verify_identity(source_path, expected_precondition_identity)?;
                false
            } else if current == result {
                verify_identity(source_path, expected_result_identity)?;
                true
            } else {
                return Err(FolderbaseError::MigrationVerificationFailed(
                    filesystem.display(source_path),
                ));
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
    persist_journal_in(filesystem, journal)
}

#[cfg(test)]
#[allow(dead_code)]
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

#[cfg(test)]
#[allow(dead_code)]
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

fn open_migration_leaf_pair_in(
    filesystem: &MigrationFilesystem,
    source: &Path,
    destination: &Path,
) -> Result<(MigrationLeafCapability, MigrationLeafCapability)> {
    let root_capability = filesystem.open_directory(Path::new(""))?;
    Ok((
        open_migration_leaf_from_root(&root_capability, filesystem.display_root(), source)?,
        open_migration_leaf_from_root(&root_capability, filesystem.display_root(), destination)?,
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

#[cfg(test)]
#[allow(dead_code)]
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
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
            FILE_SHARE_WRITE,
        };

        options
            .access_mode(0)
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
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    let mut options = CapOpenOptions::new();
    options
        .access_mode(0)
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

#[cfg(test)]
#[allow(dead_code)]
fn rollback_structural_journal(
    root: &Path,
    journal_path: &Path,
    journal: &mut MigrationJournal,
) -> Result<RollbackResult> {
    rollback_structural_journal_with_hook(root, journal_path, journal, |_| {})
}

fn rollback_structural_journal_in(
    filesystem: &MigrationFilesystem,
    journal_path: &Path,
    journal: &mut MigrationJournal,
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
    reconcile_structural_in_flight_in(filesystem, journal_path, journal)?;
    for operation in journal.operations.iter().take(journal.completed_operations) {
        verify_structural_rollback_precondition_in(filesystem, operation)?;
    }
    journal.state = MigrationState::RollingBack;
    persist_journal_in(filesystem, journal)?;
    let mut affected_paths = Vec::new();

    while journal.completed_operations > 0 {
        let index = journal.completed_operations - 1;
        let operation = journal.operations[index].clone();
        refuse_structural_operation_boundaries_in(filesystem, &operation)?;
        journal.in_flight_operation = Some(index);
        persist_journal_in(filesystem, journal)?;
        if let Some(expected_identity) = journal
            .operation_result_identities
            .get(index)
            .and_then(|identity| identity.as_deref())
        {
            let result_path = structural_visible_result_path(&operation);
            if filesystem.physical_identity_sha256(result_path)? != expected_identity {
                return Err(FolderbaseError::MigrationVerificationFailed(
                    filesystem.display(result_path),
                ));
            }
        }
        match &operation {
            MigrationOperation::MoveObject {
                source_path,
                destination_path,
                expected_sha256,
                ..
            } => {
                let (snapshot_path, snapshot_sha256) =
                    operation.structural_snapshot().ok_or_else(|| {
                        invalid_journal(journal_path, "structural snapshot is missing")
                    })?;
                match filesystem.sha256_regular_if_present(source_path)? {
                    Some(digest) if digest == *expected_sha256 => {}
                    Some(_) => {
                        return Err(FolderbaseError::MigrationVerificationFailed(
                            filesystem.display(source_path),
                        ));
                    }
                    None => {
                        if filesystem
                            .sha256_regular_if_present(destination_path)?
                            .is_some_and(|digest| digest == *expected_sha256)
                        {
                            move_file_no_replace_in(
                                filesystem,
                                destination_path,
                                source_path,
                                expected_sha256,
                            )?;
                            affected_paths.push(destination_path.clone());
                        } else {
                            let snapshot = filesystem
                                .read_regular_bounded(snapshot_path, MAX_MIGRATION_PLAN_BYTES)?;
                            if sha256_bytes(&snapshot) != snapshot_sha256 {
                                return Err(FolderbaseError::MigrationVerificationFailed(
                                    filesystem.display(snapshot_path),
                                ));
                            }
                            filesystem.publish_new(source_path, &snapshot)?;
                        }
                    }
                }
                if filesystem.sha256_regular(source_path)? != snapshot_sha256 {
                    return Err(FolderbaseError::MigrationVerificationFailed(
                        filesystem.display(source_path),
                    ));
                }
            }
            operation if operation.is_structural() => {
                let source_path = operation
                    .structural_source_path()
                    .expect("structural operation has a source");
                let expected_result = operation
                    .structural_expected_result_sha256()
                    .expect("structural mutation has a result digest");
                let (snapshot_path, snapshot_sha256) =
                    operation.structural_snapshot().ok_or_else(|| {
                        invalid_journal(journal_path, "structural snapshot is missing")
                    })?;
                let snapshot =
                    filesystem.read_regular_bounded(snapshot_path, MAX_MIGRATION_PLAN_BYTES)?;
                if sha256_bytes(&snapshot) != snapshot_sha256 {
                    return Err(FolderbaseError::MigrationVerificationFailed(
                        filesystem.display(snapshot_path),
                    ));
                }
                replace_file_atomically_in(filesystem, source_path, expected_result, &snapshot)?;
                affected_paths.push(source_path.to_path_buf());
            }
            _ => {
                return Err(invalid_journal(
                    journal_path,
                    "additive operation reached structural rollback",
                ));
            }
        }
        journal.completed_operations = index;
        journal.in_flight_operation = None;
        persist_journal_in(filesystem, journal)?;
    }

    journal.in_flight_operation = None;
    journal.state = MigrationState::RolledBack;
    persist_journal_in(filesystem, journal)?;
    cleanup_staging_in(filesystem, &journal.id);
    Ok(RollbackResult {
        migration_id: journal.id.clone(),
        removed_paths: affected_paths,
        state: MigrationState::RolledBack,
    })
}

#[cfg(test)]
#[allow(dead_code)]
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
        if let Some(expected_identity) = journal
            .operation_result_identities
            .get(index)
            .and_then(|identity| identity.as_deref())
        {
            let result_path = safe_join(root, structural_visible_result_path(&operation))?;
            let current_identity = PhysicalIdentity::from_path(&result_path)
                .map(PhysicalIdentity::stable_sha256)
                .map_err(|source| FolderbaseError::io(&result_path, source))?;
            if current_identity != expected_identity {
                return Err(FolderbaseError::MigrationVerificationFailed(result_path));
            }
        }
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

#[cfg(test)]
#[allow(dead_code)]
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

fn verify_structural_rollback_precondition_in(
    filesystem: &MigrationFilesystem,
    operation: &MigrationOperation,
) -> Result<()> {
    refuse_structural_operation_boundaries_in(filesystem, operation)?;
    let (snapshot_path, snapshot_sha256) = operation.structural_snapshot().ok_or_else(|| {
        invalid_journal(filesystem.display_root(), "structural snapshot is missing")
    })?;
    if filesystem.sha256_regular(snapshot_path)? != snapshot_sha256 {
        return Err(FolderbaseError::MigrationVerificationFailed(
            filesystem.display(snapshot_path),
        ));
    }
    match operation {
        MigrationOperation::MoveObject {
            source_path,
            destination_path,
            expected_sha256,
            ..
        } => match filesystem.sha256_regular_if_present(source_path)? {
            Some(digest) if digest == *expected_sha256 => {}
            Some(_) => {
                return Err(FolderbaseError::MigrationVerificationFailed(
                    filesystem.display(source_path),
                ));
            }
            None => {
                let _ = filesystem.metadata(destination_path)?;
            }
        },
        operation if operation.is_structural() => {
            let source_path = operation
                .structural_source_path()
                .expect("structural operation has a source");
            if filesystem.sha256_regular(source_path)?
                != operation
                    .structural_expected_result_sha256()
                    .expect("structural operation has a result digest")
            {
                return Err(FolderbaseError::MigrationVerificationFailed(
                    filesystem.display(source_path),
                ));
            }
        }
        _ => {
            return Err(invalid_journal(
                filesystem.display_root(),
                "additive operation reached structural rollback verification",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(dead_code)]
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

fn refuse_structural_operation_boundaries_in(
    filesystem: &MigrationFilesystem,
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
        refuse_tracked_move_path_in(filesystem, source_path)?;
        refuse_tracked_move_path_in(filesystem, destination_path)?;
    }
    let source_path = operation
        .structural_source_path()
        .expect("structural operation has a source");
    refuse_nested_folderbase_path_in(filesystem, source_path)?;
    if let Some(destination_path) = operation.structural_destination_path() {
        refuse_nested_folderbase_path_in(filesystem, destination_path)?;
    }
    Ok(())
}

fn refuse_tracked_move_path_in(filesystem: &MigrationFilesystem, path: &Path) -> Result<()> {
    let objects = Path::new(".folderbase/objects");
    let Some(metadata) = filesystem.metadata(objects)? else {
        return Ok(());
    };
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(FolderbaseError::UnsafePath(filesystem.display(objects)));
    }
    for name in filesystem.closed_regular_file_names(objects, 65_536)? {
        if Path::new(&name)
            .extension()
            .and_then(|value| value.to_str())
            != Some("json")
        {
            continue;
        }
        let record_path = objects.join(&name);
        let bytes = filesystem.read_regular_bounded(&record_path, MAX_MIGRATION_PLAN_BYTES)?;
        let value: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|source| FolderbaseError::json(filesystem.display(&record_path), source))?;
        let Some(stored) = value.get("path").and_then(serde_json::Value::as_str) else {
            return Err(invalid_journal(
                filesystem.display(&record_path),
                "tracked object record is missing its path",
            ));
        };
        let portable_path = portable_migration_wire_path(path)?;
        if stored.eq_ignore_ascii_case(&portable_path) {
            return Err(FolderbaseError::InvalidRecord {
                path: path.to_path_buf(),
                message: "ordinary moves cannot relocate a version-tracked object".to_owned(),
            });
        }
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

#[cfg(test)]
#[allow(dead_code)]
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

#[cfg(test)]
#[allow(dead_code)]
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

fn rollback_journal_in(
    filesystem: &MigrationFilesystem,
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
    reconcile_in_flight_in(filesystem, journal_path, journal)?;
    verify_rollback_paths_in(filesystem, journal)?;
    journal.state = MigrationState::RollingBack;
    persist_journal_in(filesystem, journal)?;
    let mut removed_paths = Vec::new();

    while let Some(path) = journal.created_paths.last().cloned() {
        ensure_safe_relative(&path)?;
        match filesystem.metadata(&path)? {
            Some(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
                verify_rollback_file_in(filesystem, journal, &path)?;
                filesystem.remove_file(&path)?;
                removed_paths.push(path.clone());
            }
            Some(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
                if filesystem.remove_empty_directory_if_present(&path)? {
                    removed_paths.push(path.clone());
                }
            }
            Some(_) => {
                return Err(FolderbaseError::MigrationVerificationFailed(
                    filesystem.display(&path),
                ));
            }
            None => {}
        }
        journal.created_paths.pop();
        persist_journal_in(filesystem, journal)?;
    }

    journal.in_flight_operation = None;
    journal.state = MigrationState::RolledBack;
    persist_journal_in(filesystem, journal)?;
    cleanup_staging_in(filesystem, &journal.id);
    Ok(RollbackResult {
        migration_id: journal.id.clone(),
        removed_paths,
        state: MigrationState::RolledBack,
    })
}

#[cfg(test)]
#[allow(dead_code)]
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

fn verify_rollback_paths_in(
    filesystem: &MigrationFilesystem,
    journal: &MigrationJournal,
) -> Result<()> {
    let approved_boundaries = journal
        .materialized_folderbases
        .iter()
        .map(|materialized| materialized.path.clone())
        .collect::<BTreeSet<_>>();
    for path in &journal.created_paths {
        ensure_safe_relative(path)?;
        refuse_unapproved_nested_folderbase_path_in(filesystem, path, &approved_boundaries)?;
        match filesystem.metadata(path)? {
            Some(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
                verify_rollback_file_in(filesystem, journal, path)?;
            }
            Some(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
            Some(_) => {
                return Err(FolderbaseError::MigrationVerificationFailed(
                    filesystem.display(path),
                ));
            }
            None => {}
        }
    }
    Ok(())
}

fn refuse_unapproved_nested_folderbase_path_in(
    filesystem: &MigrationFilesystem,
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
        match filesystem.metadata(&prefix)? {
            Some(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
                let directory = filesystem.open_directory(&prefix)?;
                if classify_nested_folderbase_boundary(&directory, &filesystem.display(&prefix))?
                    != NestedFolderbaseBoundaryKind::None
                    && !approved_boundaries.contains(&prefix)
                {
                    return Err(FolderbaseError::UnsafePath(prefix));
                }
            }
            Some(_) if prefix == relative => {}
            Some(_) => return Err(FolderbaseError::UnsafePath(prefix)),
            None => break,
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(dead_code)]
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

#[cfg(test)]
#[allow(dead_code)]
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

fn verify_rollback_file_in(
    filesystem: &MigrationFilesystem,
    journal: &MigrationJournal,
    relative: &Path,
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
        Some(expected) if filesystem.sha256_regular(relative)? == *expected => Ok(()),
        _ => Err(FolderbaseError::MigrationVerificationFailed(
            filesystem.display(relative),
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
    create_private_directory_if_missing(&state_dir)?;
    let migrations_dir = safe_join(&plan.root, Path::new(MIGRATIONS_DIR))?;
    create_private_directory_if_missing(&migrations_dir)?;
    let migration_dir = safe_join(&plan.root, &PathBuf::from(MIGRATIONS_DIR).join(&plan.id))?;
    create_private_directory_new(&migration_dir)?;
    sync_parent(&migration_dir)?;
    write_json_new(&migration_dir.join("plan.json"), plan)
}

#[cfg(test)]
#[allow(dead_code)]
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

fn persist_plan_transition_in(
    filesystem: &MigrationFilesystem,
    migration_id: &str,
    expected: &[MigrationState],
    next: MigrationState,
) -> Result<()> {
    let mut plan = load_plan_from(filesystem, migration_id)?;
    if !expected.contains(&plan.state) {
        return Err(FolderbaseError::InvalidMigrationState {
            expected: expected.first().copied().unwrap_or(next).as_str(),
            actual: plan.state.as_str().to_owned(),
        });
    }
    plan.state = next;
    persist_plan_in(filesystem, &plan)
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

fn load_plan_from(filesystem: &MigrationFilesystem, migration_id: &str) -> Result<MigrationPlan> {
    let root = filesystem.display_root();
    validate_migration_id(root, migration_id)?;
    let plan_relative = migration_plan_relative(migration_id);
    let plan_path = filesystem.display(&plan_relative);
    let bytes = filesystem.read_regular_bounded(&plan_relative, MAX_MIGRATION_PLAN_BYTES)?;
    let plan: MigrationPlan = serde_json::from_slice(&bytes)
        .map_err(|source| FolderbaseError::json(&plan_path, source))?;
    validate_plan(root, migration_id, &plan_path, &plan)?;
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
        || inventory_digest(&plan.source_inventory.files)? != plan.source_inventory.digest
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
            assignment_group_coverage_digest(&group.source_root, group.content_kind, &members)?;
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
        let question_id = stable_path_id("question_assignment", source_root)?;
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

fn canonical_root_with_identity_with_hook(
    path: &Path,
    after_initial_nofollow_open: impl FnOnce(),
) -> Result<(PathBuf, RetainedPhysicalIdentity)> {
    let retained = match RetainedPhysicalIdentity::from_path(path) {
        Ok(retained) => retained,
        Err(source) => {
            if fs::symlink_metadata(path)
                .is_ok_and(|metadata| metadata_is_link_or_reparse(&metadata))
            {
                return Err(FolderbaseError::UnsafePath(path.to_path_buf()));
            }
            return Err(FolderbaseError::io(path, source));
        }
    };
    let retained_metadata = retained
        .metadata()
        .map_err(|source| FolderbaseError::io(path, source))?;
    if metadata_is_link_or_reparse(&retained_metadata) {
        return Err(FolderbaseError::UnsafePath(path.to_path_buf()));
    }
    if !retained_metadata.is_dir() {
        return Err(FolderbaseError::InvalidRoot(path.to_path_buf()));
    }
    after_initial_nofollow_open();
    let canonical = path
        .canonicalize()
        .map_err(|source| FolderbaseError::io(path, source))?;
    let canonical_retained = RetainedPhysicalIdentity::from_path(&canonical)
        .map_err(|source| FolderbaseError::io(&canonical, source))?;
    let canonical_metadata = canonical_retained
        .metadata()
        .map_err(|source| FolderbaseError::io(&canonical, source))?;
    if metadata_is_link_or_reparse(&canonical_metadata)
        || !canonical_metadata.is_dir()
        || canonical_retained.identity() != retained.identity()
    {
        return Err(FolderbaseError::UnsafePath(path.to_path_buf()));
    }
    let display_root = caller_visible_canonical_path(path, canonical)
        .map_err(|source| FolderbaseError::io(path, source))?;
    Ok((display_root, retained))
}

#[cfg(not(windows))]
fn caller_visible_canonical_path(
    _caller_path: &Path,
    canonical: PathBuf,
) -> std::io::Result<PathBuf> {
    Ok(canonical)
}

#[cfg(windows)]
fn caller_visible_canonical_path(
    caller_path: &Path,
    _canonical: PathBuf,
) -> std::io::Result<PathBuf> {
    std::path::absolute(caller_path)
}

fn canonical_root_with_identity(path: &Path) -> Result<(PathBuf, RetainedPhysicalIdentity)> {
    canonical_root_with_identity_with_hook(path, || {})
}

fn canonical_root(path: &Path) -> Result<PathBuf> {
    canonical_root_with_identity(path).map(|(canonical, _retained)| canonical)
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

fn portable_migration_wire_path(path: &Path) -> Result<String> {
    crate::portable_wire_path::relative_to_wire(path).map_err(|message| {
        FolderbaseError::InvalidRecord {
            path: path.to_path_buf(),
            message: message.to_owned(),
        }
    })
}

fn portable_migration_wire_scope(path: &Path) -> Result<String> {
    if path == Path::new(".") {
        Ok(".".to_owned())
    } else {
        portable_migration_wire_path(path)
    }
}

fn stable_path_id(prefix: &str, path: &Path) -> Result<String> {
    let portable = portable_migration_wire_path(path)?;
    let digest = Sha256::digest(portable.as_bytes());
    Ok(format!("{prefix}_{digest:x}"))
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
) -> Result<Vec<MigrationQuestion>> {
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
) -> Result<MigrationQuestion> {
    let coverage_digest = assignment_group_coverage_digest(source_root, content_kind, &members)?;
    let source_paths = members
        .into_iter()
        .map(|member| member.path)
        .collect::<Vec<_>>();
    let mut question = assignment_question(&source_paths[0], content_kind, targets)?;
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
    Ok(question)
}

fn assignment_group_coverage_digest(
    source_root: &Path,
    content_kind: MigrationContentKind,
    members: &[AssignmentGroupMember],
) -> Result<String> {
    fn update_field(hasher: &mut Sha256, value: &[u8]) {
        hasher.update((value.len() as u64).to_le_bytes());
        hasher.update(value);
    }

    let mut hasher = Sha256::new();
    update_field(&mut hasher, ASSIGNMENT_GROUP_RULE_VERSION.as_bytes());
    update_field(
        &mut hasher,
        portable_migration_wire_scope(source_root)?.as_bytes(),
    );
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
        update_field(
            &mut hasher,
            portable_migration_wire_path(&member.path)?.as_bytes(),
        );
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn assignment_question(
    source_path: &Path,
    content_kind: MigrationContentKind,
    targets: &[MigrationTarget],
) -> Result<MigrationQuestion> {
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

    Ok(MigrationQuestion {
        id: stable_path_id("question_assignment", source_path)?,
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
    })
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
    )?;
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
                if assignment_group_coverage_digest(source_root, *content_kind, &members)?
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

fn inventory_digest(files: &[SourceFile]) -> Result<String> {
    let mut hasher = Sha256::new();
    for file in files {
        let portable = portable_migration_wire_path(&file.path)?;
        hasher.update(portable.as_bytes());
        hasher.update([0]);
        hasher.update(file.bytes.to_le_bytes());
        hasher.update([0]);
        hasher.update(file.sha256.as_bytes());
        hasher.update([b'\n']);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn metadata_inventory_digest(
    files: &[AnalyzedFile],
    reconstructable_trees: &[ReconstructableTree],
    nested_folderbases: &[NestedFolderbaseBoundary],
) -> Result<String> {
    let mut hasher = Sha256::new();
    for file in files {
        let portable = portable_migration_wire_path(&file.path)?;
        hasher.update(portable.as_bytes());
        hasher.update([0]);
        hasher.update(file.bytes.to_le_bytes());
        hasher.update([0]);
        hasher.update([file.classification_bits()]);
        hasher.update([b'\n']);
    }
    for tree in reconstructable_trees {
        hasher.update(b"reconstructable:");
        let portable = portable_migration_wire_path(&tree.path)?;
        hasher.update(portable.as_bytes());
        hasher.update([b'\n']);
    }
    for boundary in nested_folderbases {
        hasher.update(b"nested:");
        let portable = portable_migration_wire_path(&boundary.path)?;
        hasher.update(portable.as_bytes());
        hasher.update([boundary.state as u8, b'\n']);
    }
    Ok(format!("{:x}", hasher.finalize()))
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

fn verify_additive_source_topology_in(
    filesystem: &MigrationFilesystem,
    plan: &MigrationPlan,
) -> Result<()> {
    let expected_value = plan
        .extensions
        .get(SOURCE_TOPOLOGY_EXTENSION)
        .ok_or_else(|| FolderbaseError::MigrationSourceChanged(plan.root.clone()))?;
    let expected: SourceTopologySnapshot = serde_json::from_value(expected_value.clone())
        .map_err(|_| FolderbaseError::MigrationSourceChanged(plan.root.clone()))?;
    if expected.version != "1" {
        return Err(FolderbaseError::MigrationSourceChanged(plan.root.clone()));
    }
    let current_analysis = filesystem.analyze_retained_root()?;
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

fn verify_expanded_reconstructable_trees_in(
    filesystem: &MigrationFilesystem,
    plan: &MigrationPlan,
) -> Result<()> {
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
        let expanded = filesystem.expand_retained_tree(&tree.source_root)?;
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
    if inventory_digest(&current)? != plan.source_inventory.digest {
        return Err(FolderbaseError::MigrationSourceChanged(plan.root.clone()));
    }
    Ok(())
}

fn verify_source_files_in(filesystem: &MigrationFilesystem, plan: &MigrationPlan) -> Result<()> {
    let mut current = Vec::new();
    for file in &plan.source_inventory.files {
        refuse_nested_folderbase_path_in(filesystem, &file.path)?;
        let metadata = filesystem
            .metadata(&file.path)?
            .ok_or_else(|| FolderbaseError::MigrationSourceChanged(file.path.clone()))?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.len() != file.bytes
            || filesystem.sha256_regular(&file.path)? != file.sha256
        {
            return Err(FolderbaseError::MigrationSourceChanged(file.path.clone()));
        }
        current.push(file.clone());
    }
    if inventory_digest(&current)? != plan.source_inventory.digest {
        return Err(FolderbaseError::MigrationSourceChanged(
            filesystem.display_root().to_path_buf(),
        ));
    }
    Ok(())
}

fn refuse_nested_folderbase_path_in(
    filesystem: &MigrationFilesystem,
    relative: &Path,
) -> Result<()> {
    ensure_safe_relative(relative)?;
    let mut prefix = PathBuf::new();
    let mut components = relative.components().peekable();
    while let Some(component) = components.next() {
        let Component::Normal(component) = component else {
            return Err(FolderbaseError::UnsafePath(relative.to_path_buf()));
        };
        if components.peek().is_none() {
            break;
        }
        prefix.push(component);
        let directory = filesystem.open_directory(&prefix)?;
        if classify_nested_folderbase_boundary(&directory, &filesystem.display(&prefix))?
            != NestedFolderbaseBoundaryKind::None
        {
            return Err(FolderbaseError::UnsafePath(prefix));
        }
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

#[cfg(test)]
#[allow(dead_code)]
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

#[cfg(test)]
#[allow(dead_code)]
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

fn persist_plan_in(filesystem: &MigrationFilesystem, plan: &MigrationPlan) -> Result<()> {
    validate_plan(
        filesystem.display_root(),
        &plan.id,
        &filesystem.display(&migration_plan_relative(&plan.id)),
        plan,
    )?;
    let mut content = serde_json::to_vec_pretty(plan)
        .map_err(|source| FolderbaseError::json(filesystem.display_root(), source))?;
    content.push(b'\n');
    filesystem.replace(&migration_plan_relative(&plan.id), &content)
}

#[cfg(test)]
#[allow(dead_code)]
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

fn migration_journal_relative(migration_id: &str) -> PathBuf {
    PathBuf::from(MIGRATIONS_DIR)
        .join(migration_id)
        .join("result.json")
}

fn journal_bytes(path: &Path, journal: &MigrationJournal) -> Result<Vec<u8>> {
    let mut content =
        serde_json::to_vec_pretty(journal).map_err(|source| FolderbaseError::json(path, source))?;
    content.push(b'\n');
    Ok(content)
}

fn persist_journal_in(filesystem: &MigrationFilesystem, journal: &MigrationJournal) -> Result<()> {
    let relative = migration_journal_relative(&journal.id);
    let bytes = journal_bytes(&filesystem.display(&relative), journal)?;
    filesystem.replace(&relative, &bytes)
}

fn sync_parent(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        sync_directory(parent)
    } else {
        Ok(())
    }
}

#[cfg(not(windows))]
fn sync_directory(path: &Path) -> Result<()> {
    let directory = fs::File::open(path).map_err(|source| FolderbaseError::io(path, source))?;
    directory
        .sync_all()
        .map_err(|source| FolderbaseError::io(path, source))
}

#[cfg(windows)]
fn sync_directory(_path: &Path) -> Result<()> {
    // Windows does not provide the POSIX directory-fsync contract, and
    // FlushFileBuffers rejects directory handles with ERROR_ACCESS_DENIED.
    // Migration publication still flushes each staged regular file before
    // its namespace transition.
    Ok(())
}

#[cfg(test)]
#[allow(dead_code)]
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

fn cleanup_staging_in(filesystem: &MigrationFilesystem, migration_id: &str) {
    let staging_relative = PathBuf::from(MIGRATIONS_DIR)
        .join(migration_id)
        .join("staging");
    if let Ok(names) = filesystem.closed_regular_file_names(&staging_relative, 65_536) {
        for name in names {
            let _ = filesystem.remove_file_if_present(&staging_relative.join(name));
        }
    }
    let _ = filesystem.remove_empty_directory_if_present(&staging_relative);
}

#[cfg(test)]
#[path = "migration_transaction_red_tests.rs"]
mod migration_transaction_red_tests;

#[cfg(test)]
mod tests {
    use std::{sync::mpsc, thread};

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
    fn typed_ignore_policy_proposal_rejects_content_above_the_capture_bound_without_mutation() {
        assert_ignore_policy_proposal_rejected(
            &"a".repeat(crate::MAX_FOLDERBASEIGNORE_BYTES as usize + 1),
        );
    }

    #[test]
    fn typed_ignore_policy_approval_rejects_content_above_the_capture_bound_without_mutation() {
        assert_ignore_policy_approval_rejected(
            &"a".repeat(crate::MAX_FOLDERBASEIGNORE_BYTES as usize + 1),
        );
    }

    #[test]
    fn typed_ignore_policy_apply_rejects_content_above_the_capture_bound_without_mutation() {
        assert_ignore_policy_apply_rejected(
            &"a".repeat(crate::MAX_FOLDERBASEIGNORE_BYTES as usize + 1),
        );
    }

    #[test]
    fn typed_ignore_policy_proposal_rejects_invalid_gitignore_syntax_without_mutation() {
        assert_ignore_policy_proposal_rejected("{a,b\n");
    }

    #[test]
    fn typed_ignore_policy_approval_rejects_invalid_gitignore_syntax_without_mutation() {
        assert_ignore_policy_approval_rejected("{a,b\n");
    }

    #[test]
    fn typed_ignore_policy_apply_rejects_invalid_gitignore_syntax_without_mutation() {
        assert_ignore_policy_apply_rejected("{a,b\n");
    }

    fn assert_ignore_policy_proposal_rejected(content: &str) {
        let root = initialized_structural_folderbase_fixture();
        let policy_path = root.path().join(".folderbaseignore");
        fs::write(&policy_path, b"node_modules/\n").unwrap();
        let before = snapshot_regular_files(root.path());

        let error = match MigrationPlan::propose_structural(
            root.path(),
            vec![MigrationOperation::update_ignore_policy(content)],
        ) {
            Err(error) => error,
            Ok(_) => panic!("capture-incompatible policy must fail during proposal"),
        };

        assert_invalid_ignore_policy(error);
        assert_eq!(snapshot_regular_files(root.path()), before);
    }

    fn assert_ignore_policy_approval_rejected(content: &str) {
        let root = initialized_structural_folderbase_fixture();
        let policy_path = root.path().join(".folderbaseignore");
        fs::write(&policy_path, b"node_modules/\n").unwrap();
        let mut plan = MigrationPlan::propose_structural(
            root.path(),
            vec![MigrationOperation::update_ignore_policy("Derived/\n")],
        )
        .unwrap();
        set_ignore_policy_content(&mut plan.operations[0], content);
        let migration_directory = root.path().join(MIGRATIONS_DIR).join(&plan.id);
        let plan_path = migration_directory.join("plan.json");
        fs::write(
            &plan_path,
            serde_json::to_vec_pretty(&plan).expect("tampered proposal"),
        )
        .unwrap();
        let policy_before = fs::read(&policy_path).unwrap();
        let plan_before = fs::read(&plan_path).unwrap();

        let error = match approve_migration(plan) {
            Err(error) => error,
            Ok(_) => panic!("capture-incompatible policy must not be approved"),
        };

        assert_invalid_ignore_policy(error);
        assert_eq!(fs::read(&policy_path).unwrap(), policy_before);
        assert_eq!(fs::read(&plan_path).unwrap(), plan_before);
        assert!(!migration_directory.join("snapshots").exists());
    }

    fn assert_ignore_policy_apply_rejected(content: &str) {
        let root = initialized_structural_folderbase_fixture();
        let policy_path = root.path().join(".folderbaseignore");
        fs::write(&policy_path, b"node_modules/\n").unwrap();
        let plan = MigrationPlan::propose_structural(
            root.path(),
            vec![MigrationOperation::update_ignore_policy("Derived/\n")],
        )
        .unwrap();
        let migration_id = plan.id.clone();
        let mut approved = approve_migration(plan).unwrap();
        set_ignore_policy_content(&mut approved.plan.operations[0], content);
        let result_sha256 = sha256_bytes(content.as_bytes());
        match &mut approved.plan.operations[0] {
            MigrationOperation::UpdateIgnorePolicy {
                expected_result_sha256,
                ..
            } => *expected_result_sha256 = result_sha256,
            operation => panic!("unexpected operation: {operation:?}"),
        }
        approved.approval_digest = plan_digest(&approved.plan).unwrap();
        approved.plan.approval_digest = Some(approved.approval_digest.clone());
        persist_plan(&approved.plan).unwrap();
        let migration_directory = root.path().join(MIGRATIONS_DIR).join(migration_id);
        let plan_path = migration_directory.join("plan.json");
        let policy_before = fs::read(&policy_path).unwrap();
        let plan_before = fs::read(&plan_path).unwrap();

        let error = match apply_migration(approved) {
            Err(error) => error,
            Ok(_) => panic!("capture-incompatible policy must not be applied"),
        };

        assert_invalid_ignore_policy(error);
        assert_eq!(fs::read(&policy_path).unwrap(), policy_before);
        assert_eq!(fs::read(&plan_path).unwrap(), plan_before);
        assert!(!migration_directory.join("result.json").exists());
    }

    fn set_ignore_policy_content(operation: &mut MigrationOperation, content: &str) {
        match operation {
            MigrationOperation::UpdateIgnorePolicy {
                content: proposed, ..
            } => proposed.clone_from(&content.to_owned()),
            operation => panic!("unexpected operation: {operation:?}"),
        }
    }

    fn assert_invalid_ignore_policy(error: FolderbaseError) {
        assert!(
            matches!(
                error,
                FolderbaseError::InvalidRecord {
                    ref message,
                    ..
                } if message.contains("ignore policy")
            ),
            "{error:?}"
        );
    }

    fn snapshot_regular_files(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
        fn collect(root: &Path, directory: &Path, files: &mut BTreeMap<PathBuf, Vec<u8>>) {
            for entry in fs::read_dir(directory).unwrap() {
                let entry = entry.unwrap();
                let path = entry.path();
                let metadata = fs::symlink_metadata(&path).unwrap();
                if metadata.is_dir() && !metadata.file_type().is_symlink() {
                    collect(root, &path, files);
                } else if metadata.is_file() && !metadata.file_type().is_symlink() {
                    files.insert(
                        path.strip_prefix(root).unwrap().to_path_buf(),
                        fs::read(path).unwrap(),
                    );
                }
            }
        }

        let mut files = BTreeMap::new();
        collect(root, root, &mut files);
        files
    }

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

    #[cfg(unix)]
    #[test]
    fn migration_apply_never_publishes_a_lock_into_a_replacement_root_after_detection() {
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
        let approved = approve_migration(migration).unwrap();
        let visible_root = root.path().to_path_buf();
        let detached_root =
            visible_root.with_file_name(format!(".folderbase-detached-{}", Uuid::now_v7()));

        let result = apply_migration_with_hook(approved, |checkpoint| {
            if checkpoint == ApplyCheckpoint::ExistingFolderbaseDetected {
                fs::rename(&visible_root, &detached_root).unwrap();
                fs::create_dir(&visible_root).unwrap();
                fs::create_dir(visible_root.join(".folderbase")).unwrap();
            }
        });
        let foreign_state_is_empty = fs::read_dir(visible_root.join(".folderbase"))
            .unwrap()
            .next()
            .is_none();
        fs::remove_dir_all(&visible_root).unwrap();
        fs::rename(&detached_root, &visible_root).unwrap();

        assert!(
            result.is_err(),
            "the replaced root must lose apply authority"
        );
        assert!(
            foreign_state_is_empty,
            "migration detection must not publish protocol state into a foreign replacement root"
        );
    }

    #[cfg(unix)]
    #[test]
    fn migration_apply_never_mutates_a_replacement_root_after_authority_is_bound() {
        let root = legacy_structural_folderbase_fixture();
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
        let approved = approve_migration(plan).unwrap();
        let visible_root = root.path().to_path_buf();
        let detached_root =
            visible_root.with_file_name(format!(".folderbase-detached-{}", Uuid::now_v7()));

        let result = apply_migration_with_hook(approved, |checkpoint| {
            if checkpoint == ApplyCheckpoint::MutationAuthorityBound {
                fs::rename(&visible_root, &detached_root).unwrap();
                copy_directory_tree(&detached_root, &visible_root);
            }
        });
        let foreign_source = fs::read(visible_root.join("notes.md")).ok();
        let foreign_destination = fs::read(visible_root.join("Archive/notes.md")).ok();
        fs::remove_dir_all(&visible_root).unwrap();
        fs::rename(&detached_root, &visible_root).unwrap();

        assert_eq!(result.unwrap().state, MigrationState::Verified);
        assert_eq!(
            foreign_source.as_deref(),
            Some(b"source\n".as_slice()),
            "apply must not remove a file from the foreign replacement"
        );
        assert_eq!(
            foreign_destination, None,
            "apply must not publish a file into the foreign replacement"
        );
    }

    #[cfg(unix)]
    fn copy_directory_tree(source: &Path, destination: &Path) {
        fs::create_dir(destination).unwrap();
        for entry in fs::read_dir(source).unwrap() {
            let entry = entry.unwrap();
            let source_path = entry.path();
            let destination_path = destination.join(entry.file_name());
            let file_type = entry.file_type().unwrap();
            if file_type.is_dir() {
                copy_directory_tree(&source_path, &destination_path);
            } else if file_type.is_file() {
                fs::copy(&source_path, &destination_path).unwrap();
            } else {
                panic!("race fixture contains an unsupported filesystem object");
            }
        }
    }

    #[allow(dead_code)]
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

    #[allow(dead_code)]
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

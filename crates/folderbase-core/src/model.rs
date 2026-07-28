use std::collections::BTreeMap;
use std::path::PathBuf;

use same_file::Handle;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TemplateDescriptor {
    pub(crate) id: String,
    pub(crate) version: String,
    pub(crate) name: String,
}

impl TemplateDescriptor {
    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn version(&self) -> &str {
        &self.version
    }

    pub fn name(&self) -> &str {
        &self.name
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TemplatePackage {
    #[serde(rename = "$schema")]
    pub(crate) schema: Option<String>,
    pub(crate) protocol_version: String,
    pub(crate) id: String,
    pub(crate) version: String,
    pub(crate) name: String,
    pub(crate) description: Option<String>,
    pub(crate) suggested_folderbase_kind: FolderbaseKind,
    #[serde(default)]
    pub(crate) questions: Vec<TemplateQuestion>,
    pub(crate) artifacts: Vec<TemplateArtifact>,
    #[serde(default)]
    pub(crate) upgrade_edges: Vec<TemplateUpgradeEdge>,
    #[serde(flatten)]
    pub(crate) extensions: BTreeMap<String, Value>,
}

impl TemplatePackage {
    pub fn protocol_version(&self) -> &str {
        &self.protocol_version
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn version(&self) -> &str {
        &self.version
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn questions(&self) -> &[TemplateQuestion] {
        &self.questions
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TemplateQuestion {
    pub(crate) id: String,
    pub(crate) prompt: String,
    #[serde(default)]
    pub(crate) answer_type: TemplateAnswerType,
    #[serde(default)]
    pub(crate) required: bool,
    #[serde(flatten)]
    pub(crate) extensions: BTreeMap<String, Value>,
}

impl TemplateQuestion {
    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn prompt(&self) -> &str {
        &self.prompt
    }

    pub fn answer_type(&self) -> TemplateAnswerType {
        self.answer_type
    }

    pub fn required(&self) -> bool {
        self.required
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TemplateAnswerType {
    #[default]
    Text,
    Boolean,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum TemplateAnswerValue {
    Text(String),
    Boolean(bool),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TemplateArtifactKind {
    Directory,
    Text,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct TemplateArtifact {
    pub(crate) target: PathBuf,
    pub(crate) kind: TemplateArtifactKind,
    pub(crate) content: Option<String>,
    pub(crate) install: String,
    #[serde(flatten)]
    pub(crate) extensions: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct TemplateUpgradeEdge {
    pub(crate) from: String,
    pub(crate) to: String,
    pub(crate) notes: Option<String>,
    #[serde(flatten)]
    pub(crate) extensions: BTreeMap<String, Value>,
}

#[derive(Debug, Serialize)]
pub struct TemplateRenderPlan {
    pub(crate) template_id: String,
    pub(crate) template_version: String,
    pub(crate) additions: Vec<PlannedTemplateAddition>,
    pub(crate) existing_paths: Vec<PathBuf>,
}

impl TemplateRenderPlan {
    pub fn template_id(&self) -> &str {
        &self.template_id
    }

    pub fn template_version(&self) -> &str {
        &self.template_version
    }

    pub fn additions(&self) -> &[PlannedTemplateAddition] {
        &self.additions
    }

    pub fn existing_paths(&self) -> &[PathBuf] {
        &self.existing_paths
    }
}

#[derive(Debug, Serialize)]
pub struct PlannedTemplateAddition {
    pub(crate) path: PathBuf,
    pub(crate) kind: TemplateArtifactKind,
    pub(crate) content: Option<String>,
}

impl PlannedTemplateAddition {
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    pub fn kind(&self) -> TemplateArtifactKind {
        self.kind
    }

    pub fn content(&self) -> Option<&str> {
        self.content.as_deref()
    }
}

/// A read-only preview of one template version's guidance against a folderbase.
///
/// Callers cannot construct or mutate the plan. This keeps application behind
/// the core's no-clobber and stale-plan checks.
#[derive(Debug, Serialize)]
pub struct TemplateExpansionPlan {
    pub(crate) root: PathBuf,
    pub(crate) folderbase_id: String,
    pub(crate) template_id: String,
    pub(crate) comparison_version: String,
    pub(crate) comparison_source: TemplateComparisonSource,
    pub(crate) comparison_application_id: Option<String>,
    pub(crate) comparison_package_digest: TemplatePlanDigest,
    pub(crate) template_version: String,
    pub(crate) template_package_digest: TemplatePlanDigest,
    pub(crate) additions: Vec<PlannedTemplateAddition>,
    pub(crate) preserved_paths: Vec<PathBuf>,
    pub(crate) blocked_paths: Vec<PathBuf>,
    pub(crate) structural_changes: Vec<TemplateStructuralChange>,
    pub(crate) plan_digest: TemplatePlanDigest,
    pub(crate) manifest_sha256: String,
    pub(crate) history_sha256: String,
    pub(crate) preserved_preconditions: Vec<TemplateExpansionPrecondition>,
    #[serde(skip_serializing)]
    pub(crate) root_handle: Handle,
}

impl TemplateExpansionPlan {
    pub fn template_id(&self) -> &str {
        &self.template_id
    }

    pub fn comparison_version(&self) -> &str {
        &self.comparison_version
    }

    pub fn template_version(&self) -> &str {
        &self.template_version
    }

    pub fn additions(&self) -> &[PlannedTemplateAddition] {
        &self.additions
    }

    pub fn preserved_paths(&self) -> &[PathBuf] {
        &self.preserved_paths
    }

    pub fn blocked_paths(&self) -> &[PathBuf] {
        &self.blocked_paths
    }

    pub fn structural_changes(&self) -> &[TemplateStructuralChange] {
        &self.structural_changes
    }

    pub fn plan_digest(&self) -> &TemplatePlanDigest {
        &self.plan_digest
    }

    pub fn is_noop(&self) -> bool {
        self.template_version == self.comparison_version
            && self.additions.is_empty()
            && self.blocked_paths.is_empty()
            && self.structural_changes.is_empty()
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum TemplateStructuralChangeKind {
    Downgrade,
    Lineage,
    UnsupportedTransition,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TemplateStructuralChange {
    pub(crate) kind: TemplateStructuralChangeKind,
    pub(crate) path: Option<PathBuf>,
    pub(crate) reason: String,
}

impl TemplateStructuralChange {
    pub fn kind(&self) -> TemplateStructuralChangeKind {
        self.kind
    }

    pub fn path(&self) -> Option<&std::path::Path> {
        self.path.as_deref()
    }

    pub fn reason(&self) -> &str {
        &self.reason
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TemplatePlanDigest {
    pub(crate) algorithm: String,
    pub(crate) digest: String,
}

impl TemplatePlanDigest {
    pub fn algorithm(&self) -> &str {
        &self.algorithm
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct TemplateExpansionPrecondition {
    pub(crate) path: PathBuf,
    pub(crate) kind: TemplateArtifactKind,
    pub(crate) sha256: Option<String>,
    #[serde(skip_serializing)]
    pub(crate) handle: Handle,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TemplateApplicationRecord {
    #[serde(rename = "$schema")]
    pub(crate) schema: String,
    pub(crate) protocol_version: String,
    pub(crate) id: String,
    pub(crate) folderbase_id: String,
    pub(crate) state: TemplateApplicationState,
    pub(crate) template: AppliedTemplate,
    pub(crate) comparison: TemplateApplicationComparison,
    pub(crate) applied_at: String,
    pub(crate) created_paths: Vec<TemplateApplicationCreatedPath>,
    pub(crate) preserved_targets: Vec<TemplateApplicationPreservedTarget>,
    pub(crate) plan_digest: TemplatePlanDigest,
    pub(crate) record_digest: TemplatePlanDigest,
}

impl TemplateApplicationRecord {
    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn folderbase_id(&self) -> &str {
        &self.folderbase_id
    }

    pub fn state(&self) -> TemplateApplicationState {
        self.state
    }

    pub fn template_id(&self) -> &str {
        &self.template.id
    }

    pub fn template_version(&self) -> &str {
        &self.template.version
    }

    pub fn comparison_version(&self) -> &str {
        &self.comparison.version
    }

    pub fn applied_at(&self) -> &str {
        &self.applied_at
    }

    pub fn created_paths(&self) -> &[TemplateApplicationCreatedPath] {
        &self.created_paths
    }

    pub fn preserved_targets(&self) -> &[TemplateApplicationPreservedTarget] {
        &self.preserved_targets
    }

    pub fn plan_digest(&self) -> &TemplatePlanDigest {
        &self.plan_digest
    }

    pub fn record_digest(&self) -> &TemplatePlanDigest {
        &self.record_digest
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct AppliedTemplate {
    pub(crate) id: String,
    pub(crate) version: String,
    pub(crate) package_digest: TemplatePlanDigest,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TemplateApplicationState {
    Verified,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TemplateComparisonSource {
    Origin,
    Application,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct TemplateApplicationComparison {
    pub(crate) source: TemplateComparisonSource,
    pub(crate) version: String,
    pub(crate) application_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TemplateApplicationCreatedPath {
    pub(crate) path: PathBuf,
    pub(crate) kind: TemplateArtifactKind,
    pub(crate) bytes: Option<u64>,
    pub(crate) sha256: Option<String>,
}

impl TemplateApplicationCreatedPath {
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    pub fn kind(&self) -> TemplateArtifactKind {
        self.kind
    }

    pub fn bytes(&self) -> Option<u64> {
        self.bytes
    }

    pub fn sha256(&self) -> Option<&str> {
        self.sha256.as_deref()
    }
}

impl AsRef<std::path::Path> for TemplateApplicationCreatedPath {
    fn as_ref(&self) -> &std::path::Path {
        &self.path
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TemplateApplicationPreservedTarget {
    pub(crate) path: PathBuf,
    pub(crate) kind: TemplateArtifactKind,
    pub(crate) bytes: Option<u64>,
    pub(crate) sha256: Option<String>,
}

impl TemplateApplicationPreservedTarget {
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    pub fn kind(&self) -> TemplateArtifactKind {
        self.kind
    }

    pub fn bytes(&self) -> Option<u64> {
        self.bytes
    }

    pub fn sha256(&self) -> Option<&str> {
        self.sha256.as_deref()
    }
}

impl AsRef<std::path::Path> for TemplateApplicationPreservedTarget {
    fn as_ref(&self) -> &std::path::Path {
        &self.path
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TemplateApplicationResult {
    pub(crate) created_paths: Vec<PathBuf>,
    pub(crate) preserved_paths: Vec<PathBuf>,
    pub(crate) application_record: Option<PathBuf>,
}

impl TemplateApplicationResult {
    pub fn created_paths(&self) -> &[PathBuf] {
        &self.created_paths
    }

    pub fn preserved_paths(&self) -> &[PathBuf] {
        &self.preserved_paths
    }

    pub fn application_record(&self) -> Option<&std::path::Path> {
        self.application_record.as_deref()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InspectionReport {
    pub root: PathBuf,
    pub inventory: InventorySummary,
    pub classified_paths: Vec<ClassifiedPath>,
    pub git_repositories: Vec<PathBuf>,
    pub context_files: Vec<PathBuf>,
    pub boundary_hints: Vec<BoundaryHint>,
    #[serde(default)]
    pub reconstructable_trees: Vec<ReconstructableTree>,
    #[serde(default)]
    pub nested_folderbases: Vec<NestedFolderbaseBoundary>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct InventorySummary {
    pub file_count: u64,
    pub total_bytes: u64,
    pub generated_file_count: u64,
    #[serde(default)]
    pub reconstructable_tree_count: u64,
    pub secret_shaped_file_count: u64,
    pub temporary_file_count: u64,
    pub large_file_count: u64,
    pub versioned_file_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClassifiedPath {
    pub path: PathBuf,
    pub classification: Classification,
    pub reason: String,
    pub bytes: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Classification {
    Generated,
    SecretShaped,
    Temporary,
    Large,
    Versioned,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BoundaryHint {
    pub path: PathBuf,
    pub kind: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReconstructableTree {
    pub path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NestedFolderbaseBoundary {
    pub path: PathBuf,
    pub state: NestedFolderbaseState,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NestedFolderbaseState {
    Unchecked,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FolderbaseKind {
    Person,
    Organization,
    Engagement,
    #[default]
    Project,
    Customer,
    Temporary,
    Custom,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InitializationOptions {
    pub name: Option<String>,
    pub kind: FolderbaseKind,
    pub create_agent_adapters: bool,
}

impl Default for InitializationOptions {
    fn default() -> Self {
        Self {
            name: None,
            kind: FolderbaseKind::Project,
            create_agent_adapters: true,
        }
    }
}

/// An opaque, Core-owned commitment to every semantically relevant decision
/// in an initialization plan.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InitializationPlanDigest {
    pub(crate) algorithm: String,
    pub(crate) digest: String,
}

impl InitializationPlanDigest {
    pub fn parse_sha256(digest: impl Into<String>) -> crate::Result<Self> {
        let digest = digest.into();
        if !Self::is_valid_sha256(&digest) {
            return Err(crate::FolderbaseError::InvalidInitializationPlanDigest);
        }
        Ok(Self {
            algorithm: "sha256".to_owned(),
            digest,
        })
    }

    pub fn algorithm(&self) -> &str {
        &self.algorithm
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }

    pub(crate) fn validate(&self) -> crate::Result<()> {
        if self.algorithm != "sha256" || !Self::is_valid_sha256(&self.digest) {
            return Err(crate::FolderbaseError::InvalidInitializationPlanDigest);
        }
        Ok(())
    }

    fn is_valid_sha256(digest: &str) -> bool {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }
}

#[derive(Clone)]
pub(crate) enum InitializationRequest {
    Ordinary {
        options: InitializationOptions,
    },
    Template {
        options: InitializationOptions,
        package: Box<TemplatePackage>,
        answers: BTreeMap<String, TemplateAnswerValue>,
    },
}

impl std::fmt::Debug for InitializationRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ordinary { options } => formatter
                .debug_struct("Ordinary")
                .field("options", options)
                .finish(),
            Self::Template {
                options,
                package,
                answers,
            } => formatter
                .debug_struct("Template")
                .field("options", options)
                .field("template_id", &package.id)
                .field("template_version", &package.version)
                .field("answer_ids", &answers.keys().collect::<Vec<_>>())
                .finish(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct InitializationDestinationEntry {
    pub(crate) path: PathBuf,
    pub(crate) kind: InitializationDestinationKind,
    pub(crate) bytes: Option<u64>,
    pub(crate) sha256: Option<String>,
    pub(crate) symlink_target: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InitializationDestinationKind {
    Directory,
    File,
    Symlink,
    ReconstructableDirectory,
    NestedFolderbase,
    Other,
}

/// A previewable initialization plan that can only be created by the core.
///
/// Its fields are intentionally read-only to callers. Applying arbitrary
/// caller-constructed writes would break the module's no-overwrite invariant.
#[derive(Debug, Serialize)]
pub struct InitializationPlan {
    pub(crate) root: PathBuf,
    pub(crate) folderbase_id: String,
    pub(crate) folderbase_name: String,
    pub(crate) folderbase_kind: FolderbaseKind,
    pub(crate) directories: Vec<PlannedDirectory>,
    pub(crate) writes: Vec<PlannedWrite>,
    pub(crate) template_preconditions: Vec<TemplateArtifactPrecondition>,
    pub(crate) preserved_paths: Vec<PreservedPath>,
    pub(crate) warnings: Vec<String>,
    pub(crate) plan_digest: InitializationPlanDigest,
    #[serde(skip_serializing)]
    pub(crate) root_handle: Handle,
    #[serde(skip_serializing)]
    pub(crate) request: InitializationRequest,
    #[serde(skip_serializing)]
    pub(crate) destination_inventory: Vec<InitializationDestinationEntry>,
}

impl InitializationPlan {
    pub fn root(&self) -> &std::path::Path {
        &self.root
    }

    pub fn folderbase_id(&self) -> &str {
        &self.folderbase_id
    }

    pub fn folderbase_name(&self) -> &str {
        &self.folderbase_name
    }

    pub fn folderbase_kind(&self) -> FolderbaseKind {
        self.folderbase_kind
    }

    pub fn writes(&self) -> &[PlannedWrite] {
        &self.writes
    }

    pub fn directories(&self) -> &[PlannedDirectory] {
        &self.directories
    }

    pub fn template_preconditions(&self) -> &[TemplateArtifactPrecondition] {
        &self.template_preconditions
    }

    pub fn preserved_paths(&self) -> &[PreservedPath] {
        &self.preserved_paths
    }

    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    pub fn plan_digest(&self) -> &InitializationPlanDigest {
        &self.plan_digest
    }
}

#[derive(Debug, Serialize)]
pub struct TemplateArtifactPrecondition {
    pub(crate) path: PathBuf,
    pub(crate) kind: TemplateArtifactKind,
    #[serde(skip_serializing)]
    pub(crate) handle: Handle,
}

impl TemplateArtifactPrecondition {
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    pub fn kind(&self) -> TemplateArtifactKind {
        self.kind
    }
}

#[derive(Debug, Serialize)]
pub struct PlannedDirectory {
    pub(crate) path: PathBuf,
    pub(crate) purpose: String,
}

impl PlannedDirectory {
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    pub fn purpose(&self) -> &str {
        &self.purpose
    }
}

#[derive(Debug, Serialize)]
pub struct PlannedWrite {
    pub(crate) path: PathBuf,
    pub(crate) purpose: String,
    pub(crate) content: String,
}

impl PlannedWrite {
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    pub fn purpose(&self) -> &str {
        &self.purpose
    }
}

#[derive(Debug, Serialize)]
pub struct PreservedPath {
    pub(crate) path: PathBuf,
    pub(crate) sha256: String,
}

impl PreservedPath {
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InitializationResult {
    pub root: PathBuf,
    pub folderbase_id: String,
    pub created_paths: Vec<PathBuf>,
    pub preserved_paths: Vec<PathBuf>,
    pub applied_plan_digest: InitializationPlanDigest,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ValidationLevel {
    Shallow,
    ContentIntegrity,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValidationReport {
    pub root: PathBuf,
    pub level: ValidationLevel,
    pub valid: bool,
    pub findings: Vec<ValidationFinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValidationFinding {
    pub code: String,
    pub severity: ValidationSeverity,
    pub path: Option<PathBuf>,
    pub message: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ValidationSeverity {
    Error,
    Warning,
}

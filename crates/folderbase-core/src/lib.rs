//! Portable implementation of the Folderbase filesystem protocol.
//!
//! The four functions exported here form the external seam used by the CLI
//! and, later, the native Mac application. Filesystem traversal, protocol
//! layout, preservation rules, and validation stay behind this interface.

pub mod availability;
pub mod chunk_transfer;
mod error;
mod folder_analysis;
pub mod guide_policy;
mod initialization;
mod inspection;
mod local_versions;
mod migration;
mod model;
mod sharing;
mod sync;
mod template;
mod template_expansion;
pub mod transfer_manifest;
mod traversal_policy;
mod validation;
mod workspace;

pub use error::{FolderbaseError, InitializationInventoryLimitKind, Result};
pub use initialization::{
    initialize, initialize_with_expected_plan_digest, plan_initialization,
    plan_template_initialization,
};
pub use inspection::inspect;
pub use local_versions::{
    ApprovedHistoryTransfer, CaptureResult, ContentDigest, HistoryTransferPlan,
    HistoryTransferResult, HistoryTransferState, JournalAction, LocalObjectRecord,
    LocalVersionRecord, LocalVersionStore, ObjectId, ObjectJournalEvent, RestoreResult, VersionId,
    apply_history_transfer, approve_history_transfer,
};
pub use migration::{
    ApprovedMigration, MigrationAnalysis, MigrationAnswer, MigrationAnswerException,
    MigrationContentKind, MigrationCopyPreview, MigrationExclusion, MigrationOperation,
    MigrationOption, MigrationPlan, MigrationPreview, MigrationQuestion, MigrationQuestionKind,
    MigrationResult, MigrationState, MigrationTarget, MigrationTargetKind, ProposedBoundary,
    RollbackResult, analyze_migration, apply_migration, approve_migration, plan_migration,
    preview_migration, rollback_migration,
};
pub use model::{
    BoundaryHint, Classification, ClassifiedPath, FolderbaseKind, InitializationOptions,
    InitializationPlan, InitializationPlanDigest, InitializationResult, InspectionReport,
    InventorySummary, NestedFolderbaseBoundary, NestedFolderbaseState, PlannedDirectory,
    PlannedTemplateAddition, PlannedWrite, PreservedPath, ReconstructableTree, TemplateAnswerType,
    TemplateAnswerValue, TemplateApplicationCreatedPath, TemplateApplicationPreservedTarget,
    TemplateApplicationRecord, TemplateApplicationResult, TemplateApplicationState,
    TemplateArtifactKind, TemplateArtifactPrecondition, TemplateComparisonSource,
    TemplateDescriptor, TemplateExpansionPlan, TemplatePackage, TemplatePlanDigest,
    TemplateQuestion, TemplateRenderPlan, TemplateStructuralChange, TemplateStructuralChangeKind,
    ValidationFinding, ValidationLevel, ValidationReport, ValidationSeverity,
};
pub use sharing::{
    AccessDecision, AccessReason, AccessRequest, FolderbaseRegistration, ShareGrant,
    SharePermission, ShareScope, SharingControlPlane,
};
pub use sync::{
    ConflictClassification, ContentKind, MemorySyncCloud, SyncConflict, SyncEvent, SyncReplica,
    SyncReport, SyncVersion,
};
pub use template::{
    list_templates, load_builtin_template, load_template, render_template, template_package_sha256,
};
pub use template_expansion::{
    apply_template_expansion, plan_template_expansion, template_application_history,
};
pub use validation::validate;
pub use workspace::{
    MAX_WORKSPACE_TEXT_BYTES, WorkspaceDocumentState, WorkspaceEntry, WorkspaceEntryKind,
    WorkspaceListing, WorkspaceSaveResult, WorkspaceTextDocument, list_workspace,
    read_workspace_text, save_workspace_text,
};

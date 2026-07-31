//! Portable implementation of the Folderbase filesystem protocol.
//!
//! The four functions exported here form the external seam used by the CLI
//! and, later, the native Mac application. Filesystem traversal, protocol
//! layout, preservation rules, and validation stay behind this interface.

pub mod availability;
pub mod chunk_transfer;
mod error;
mod folder_analysis;
mod folderbase_capture;
mod folderbase_restore_authority;
mod folderbase_seal;
mod folderbase_state;
pub mod folderbase_version;
#[cfg(test)]
mod folderbase_version_producer_tests;
pub mod guide_policy;
mod initialization;
mod inspection;
mod local_versions;
mod migration;
#[cfg(test)]
mod migration_execution_contract_red_tests;
mod migration_filesystem;
mod model;
mod physical_identity;
mod portable_wire_path;
mod protocol_upgrade;
mod reorganization;
mod root_attestation;
mod sharing;
mod sync;
mod template;
mod template_expansion;
pub mod transfer_manifest;
pub mod transfer_receiver;
pub mod transfer_source;
mod traversal_policy;
mod validation;
mod workspace;

pub use error::{FolderbaseError, InitializationInventoryLimitKind, Result};
pub use folderbase_capture::{
    CaptureEntryKind, CaptureExclusionKind, CaptureExclusionReason, CaptureIgnoredPath,
    CaptureLocalHead, CapturePlan, CapturePlanEntry, CapturePlanExclusion, CapturePlanLimitKind,
    FolderbaseCaptureError, FolderbaseVersionStore, LocalHeadAuthority, MAX_CAPTURE_PLAN_RECORDS,
    MAX_FOLDERBASEIGNORE_BYTES, MAX_LOCAL_HEAD_BYTES,
};
pub use folderbase_seal::{RestoredTombstone, SealedCapture};
pub use folderbase_version::PathBindingKind;
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
    MigrationCommand, MigrationConflict, MigrationConflictDirection, MigrationContentKind,
    MigrationCopyPreview, MigrationExclusion, MigrationExecution, MigrationOperation,
    MigrationOption, MigrationOutcome, MigrationPlan, MigrationPreview, MigrationQuestion,
    MigrationQuestionKind, MigrationResult, MigrationState, MigrationTarget, MigrationTargetKind,
    ProposedBoundary, RollbackResult, RootClaim, analyze_migration, apply_migration,
    approve_migration, plan_migration, preview_migration, rollback_migration,
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
pub use protocol_upgrade::{
    ProtocolUpgradePlan, ProtocolUpgradePlanDigest, ProtocolUpgradeResult, apply_protocol_upgrade,
    plan_protocol_upgrade,
};
pub use reorganization::{
    AnalysisScope, ConsequentialAnswer, ConsequentialAnswerType, ConsequentialQuestion,
    MAX_CANONICAL_JSON_INTEGER, MAX_REORGANIZATION_RECORD_BYTES, NestedBoundary, PathProfile,
    ReorganizationDraft, ReorganizationOperation, ReorganizationPlan, ScopeEntry,
    StructuralChangesPolicy, decode_reorganization_draft, decode_reorganization_draft_slice,
    decode_reorganization_plan, decode_reorganization_plan_slice,
    reorganization_analysis_scope_sha256, reorganization_plan_sha256, seal_reorganization_draft,
    validate_reorganization_draft, validate_reorganization_plan,
};
pub use root_attestation::{
    FolderbaseRootAttestation, FolderbaseRootMarker, MAX_FOLDERBASE_MANIFEST_BYTES,
    ROOT_INSTANCE_FORMAT_V1, ROOT_INSTANCE_FORMAT_V2, RootAttestationError, attest_folderbase_root,
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
pub use transfer_source::{
    ChunkTransferProfile, ChunkTransferSource, MANAGED_LARGE_PROFILE_THRESHOLD_BYTES,
    TRANSFER_IO_BUFFER_BYTES, TransferSourceError, VerifiedChunk,
};
pub use validation::validate;
pub use workspace::{
    MAX_WORKSPACE_TEXT_BYTES, WorkspaceDocumentState, WorkspaceEntry, WorkspaceEntryKind,
    WorkspaceListing, WorkspaceSaveResult, WorkspaceTextDocument, list_workspace,
    read_workspace_text, save_workspace_text,
};

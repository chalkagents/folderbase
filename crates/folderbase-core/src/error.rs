use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitializationInventoryLimitKind {
    Entries,
    Depth,
    PathBytes,
    EncodedInventoryBytes,
    PathComponentWork,
    DirectoryEntryWork,
}

impl std::fmt::Display for InitializationInventoryLimitKind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Entries => "entries",
            Self::Depth => "depth",
            Self::PathBytes => "path_bytes",
            Self::EncodedInventoryBytes => "encoded_inventory_bytes",
            Self::PathComponentWork => "path_component_work",
            Self::DirectoryEntryWork => "directory_entry_work",
        })
    }
}

/// Errors that prevent an operation from producing a trustworthy result.
#[derive(Debug, thiserror::Error)]
pub enum FolderbaseError {
    #[error("folderbase root does not exist or is not a directory: {0}")]
    InvalidRoot(PathBuf),

    #[error("path escapes the folderbase root: {0}")]
    UnsafePath(PathBuf),

    #[error("folder appears to be controlled by another file provider: {0}")]
    ProviderControlled(PathBuf),

    #[error("initialization plan was created for {planned_root}, not {actual_root}")]
    PlanRootMismatch {
        planned_root: PathBuf,
        actual_root: PathBuf,
    },

    #[error("folderbase root changed after the initialization plan was created: {0}")]
    PlanRootIdentityChanged(PathBuf),

    #[error("preserved path changed after the initialization plan was created: {0}")]
    PlanPreconditionChanged(PathBuf),

    #[error(
        "initialization plan digest must be exactly 64 lowercase hexadecimal SHA-256 characters"
    )]
    InvalidInitializationPlanDigest,

    #[error(
        "initialization plan changed after approval: expected {expected}, current plan is {actual}"
    )]
    InitializationPlanChanged { expected: String, actual: String },

    #[error(
        "protocol upgrade plan digest must be exactly 64 lowercase hexadecimal SHA-256 characters"
    )]
    InvalidProtocolUpgradePlanDigest,

    #[error(
        "protocol upgrade plan changed after approval: expected {expected}, current plan is {actual}"
    )]
    ProtocolUpgradePlanChanged { expected: String, actual: String },

    #[error("protocol upgrade is blocked by pending work: {0}")]
    ProtocolUpgradeBlocked(&'static str),

    #[error("initialization destination changed after approval: {0}")]
    InitializationDestinationChanged(PathBuf),

    #[error("initialization inventory exceeded the {limit} limit of {maximum}")]
    InitializationInventoryLimitExceeded {
        limit: InitializationInventoryLimitKind,
        maximum: u64,
    },

    #[error(
        "nested Folderbase boundary inspection exceeded the shared entry-work limit of {maximum} at: {path}"
    )]
    NestedBoundaryWorkLimitExceeded { path: PathBuf, maximum: u64 },

    #[error("migration is not in the required state: expected {expected}, found {actual}")]
    InvalidMigrationState {
        expected: &'static str,
        actual: String,
    },

    #[error("migration approval does not match the planned migration")]
    MigrationApprovalMismatch,

    #[error("migration source changed after analysis: {0}")]
    MigrationSourceChanged(PathBuf),

    #[error("migration verification failed at: {0}")]
    MigrationVerificationFailed(PathBuf),

    #[error("refusing to overwrite existing path: {0}")]
    WouldOverwrite(PathBuf),

    #[error("restore namespace repair is required before retrying at: {0}")]
    RestoreNamespaceRepairRequired(PathBuf),

    #[error("template expansion contains structural changes that require an approved migration")]
    StructuralTemplateChangeRequiresApproval,

    #[error("template expansion contains blocked paths")]
    TemplateExpansionBlocked,

    #[error("workspace content changed: {0}")]
    WorkspaceContentChanged(PathBuf),

    #[error("invalid protocol record at {path}: {message}")]
    InvalidRecord { path: PathBuf, message: String },

    #[error("filesystem operation failed at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("JSON operation failed at {path}: {source}")]
    Json {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

impl FolderbaseError {
    pub(crate) fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }

    pub(crate) fn json(path: impl Into<PathBuf>, source: serde_json::Error) -> Self {
        Self::Json {
            path: path.into(),
            source,
        }
    }
}

pub type Result<T> = std::result::Result<T, FolderbaseError>;

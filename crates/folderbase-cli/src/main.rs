use std::collections::BTreeMap;
use std::fmt;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
#[cfg(not(windows))]
use folderbase_core::ROOT_INSTANCE_FORMAT_V1 as CURRENT_ROOT_INSTANCE_FORMAT;
#[cfg(windows)]
use folderbase_core::ROOT_INSTANCE_FORMAT_V2 as CURRENT_ROOT_INSTANCE_FORMAT;
use folderbase_core::folderbase_version::FolderbaseVersion;
use folderbase_core::transfer_manifest::ChunkManifest;
use folderbase_core::{
    FolderbaseCaptureError, FolderbaseError, FolderbaseKind, FolderbaseVersionStore,
    InitializationOptions, InitializationPlan, InitializationPlanDigest, InitializationResult,
    InspectionReport, LocalVersionStore, MAX_WORKSPACE_TEXT_BYTES, MigrationAnalysis,
    MigrationAnswer, MigrationCommand, MigrationConflict, MigrationExecution, MigrationOutcome,
    MigrationPlan, MigrationPreview, MigrationResult, MigrationState, ProtocolUpgradePlanDigest,
    RollbackResult, RootAttestationError, RootClaim, TemplateAnswerType, TemplateAnswerValue,
    TemplateExpansionPlan, TemplatePackage, ValidationLevel, ValidationReport, ValidationSeverity,
    VersionId, analyze_migration, apply_migration, apply_protocol_upgrade,
    apply_template_expansion_with_expected_plan_digest, approve_migration, attest_folderbase_root,
    initialize, initialize_with_expected_plan_digest, inspect, list_workspace,
    load_builtin_template, plan_initialization, plan_migration, plan_protocol_upgrade,
    plan_template_expansion, plan_template_initialization, preview_migration, read_workspace_text,
    save_workspace_text, validate,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

mod change_set_capability;
mod query_capability;

const EXIT_SUCCESS: u8 = 0;
const EXIT_INVALID: u8 = 1;
const EXIT_OPERATIONAL_ERROR: u8 = 2;
const MAX_MIGRATION_ANSWERS_BYTES: u64 = 2 * 1024 * 1024;
const MAX_TEMPLATE_EXPANSION_REQUEST_BYTES: u64 = 4 * 1024 * 1024;
const CAPABILITY_REGISTRY: &str = include_str!("../assets/capability-registry-v1.json");

#[derive(Debug, Deserialize)]
struct EmbeddedCapabilityRegistry {
    capabilities: Vec<CapabilityProfile>,
}

#[derive(Debug, Deserialize, Serialize)]
struct CapabilityProfile {
    name: String,
    version: String,
    stability: String,
    #[serde(rename = "conformance_runner", skip_serializing)]
    _conformance_runner: String,
}

#[derive(Debug, Parser)]
#[command(
    name = "folderbase",
    version,
    about = "Inspect, initialize, migrate, version, and validate Folderbase workspaces"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Inspect a folder without changing it.
    Inspect {
        path: PathBuf,

        /// Emit the inspection report as JSON.
        #[arg(long)]
        json: bool,
    },

    /// Attest one exact Folderbase root without changing it.
    Attest {
        path: PathBuf,

        /// Emit the flat attestation receipt as JSON.
        #[arg(long)]
        json: bool,
    },

    /// Transform an existing folder into a folderbase.
    Init {
        path: PathBuf,

        /// Print the initialization plan without writing files.
        #[arg(long)]
        dry_run: bool,

        /// Set the folderbase's display name.
        #[arg(long)]
        name: Option<String>,

        /// Set the folderbase template kind.
        #[arg(long, value_enum, default_value_t = FolderbaseKindArg::Project)]
        kind: FolderbaseKindArg,

        /// Create bootstrap adapters for supported agents.
        #[arg(long)]
        agent_adapters: bool,

        /// Adopt with one exact built-in template, such as folderbase.project@0.2.2.
        #[arg(long)]
        template: Option<String>,

        /// Answer a template question as QUESTION_ID=ANSWER. Repeat as needed.
        #[arg(long = "answer")]
        answers: Vec<String>,

        /// Emit the plan or initialization result as JSON.
        #[arg(long)]
        json: bool,

        /// Apply only if Core replans to this approved SHA-256 digest.
        #[arg(long, conflicts_with = "dry_run")]
        expected_plan_digest: Option<String>,
    },

    /// Plan or apply additive Template Protocol 0.2 guidance.
    Template {
        #[command(subcommand)]
        command: TemplateCommand,
    },

    /// Review or apply the explicit legacy-root transition to protocol 0.5.
    Upgrade {
        path: PathBuf,

        /// Print the upgrade plan without changing the manifest.
        #[arg(long)]
        dry_run: bool,

        /// Apply only the exact reviewed protocol-upgrade plan digest.
        #[arg(long, conflicts_with = "dry_run")]
        expected_plan_digest: Option<String>,

        /// Emit the plan or result as JSON.
        #[arg(long)]
        json: bool,
    },

    /// Validate a folderbase without repairing it.
    Validate {
        path: PathBuf,

        /// Choose how deeply content should be checked.
        #[arg(long, value_enum, default_value_t = ValidationLevelArg::Shallow)]
        level: ValidationLevelArg,

        /// Emit the validation report as JSON.
        #[arg(long)]
        json: bool,
    },

    /// Analyze and safely stage a disorganized folder migration.
    Migrate {
        path: PathBuf,

        /// Additive destination folder for the organized copy.
        #[arg(long)]
        destination: PathBuf,

        /// Answer a migration question as QUESTION_ID=ANSWER. Repeat for every question.
        #[arg(long = "answer")]
        answers: Vec<String>,

        /// Read a JSON array of typed migration answers from stdin.
        #[arg(long, conflicts_with = "answers")]
        answers_stdin: bool,

        /// Apply the approved additive plan. Without this flag, only a preview is shown.
        #[arg(long)]
        apply: bool,

        /// Emit the analysis, preview, or result as JSON.
        #[arg(long)]
        json: bool,
    },

    /// Run a durable folder-to-folderbase transform across separate processes.
    Transform {
        #[command(subcommand)]
        command: TransformCommand,
    },

    /// Capture, inspect, and restore immutable local file versions.
    Version {
        #[command(subcommand)]
        command: VersionCommand,
    },

    /// Navigate and edit the ordinary files in a folderbase.
    Workspace {
        #[command(subcommand)]
        command: WorkspaceCommand,
    },

    /// Query one exact Folderbase observation through the optional query capability.
    Query {
        #[command(subcommand)]
        command: QueryCommand,
    },

    /// Inspect or explicitly rebuild the disposable private query index.
    Index {
        #[command(subcommand)]
        command: IndexCommand,
    },

    /// Check portable protocol records through a bounded implementation-neutral interface.
    Protocol {
        #[command(subcommand)]
        command: ProtocolCommand,
    },

    /// Materialize scoped ordinary-folder checkouts and publish immutable Change Sets.
    ChangeSet {
        #[command(subcommand)]
        command: ChangeSetCommand,
    },
}

#[derive(Debug, Subcommand)]
enum ChangeSetCommand {
    /// Materialize one least-authority ordinary-folder projection.
    Checkout {
        root: PathBuf,
        destination: PathBuf,
        #[arg(long, required = true)]
        stdin: bool,
        #[arg(long, required = true)]
        json: bool,
    },
    /// Propose one immutable Change Set and provider-neutral staging tree.
    Propose {
        checkout: PathBuf,
        staging: PathBuf,
        #[arg(long, required = true)]
        json: bool,
    },
    /// Assess one immutable Change Set without mutating source state.
    Assess {
        root: PathBuf,
        staging: PathBuf,
        #[arg(long, required = true)]
        stdin: bool,
        #[arg(long, required = true)]
        json: bool,
    },
    /// Atomically publish one clean immutable Change Set.
    Apply {
        root: PathBuf,
        staging: PathBuf,
        #[arg(long, required = true)]
        stdin: bool,
        #[arg(long, required = true)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
enum TemplateCommand {
    /// Preview one exact data-only template package without writing files.
    Plan {
        root: PathBuf,
        #[arg(long, required = true)]
        stdin: bool,
        #[arg(long, required = true)]
        json: bool,
    },
    /// Re-plan and apply only the exact approved additive expansion.
    Apply {
        root: PathBuf,
        #[arg(long, required = true)]
        expected_plan_digest: String,
        #[arg(long, required = true)]
        stdin: bool,
        #[arg(long, required = true)]
        json: bool,
    },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TemplateExpansionRequest {
    format: String,
    template: TemplatePackage,
    answers: BTreeMap<String, TemplateAnswerValue>,
}

#[derive(Debug, Subcommand)]
enum ProtocolCommand {
    /// Print the stable compatibility contract implemented by this executable.
    Contract {
        #[arg(long)]
        json: bool,
    },

    /// Validate and digest one portable JSON artifact read from standard input.
    Check {
        #[arg(value_enum)]
        artifact: ProtocolArtifactArg,
        #[arg(long, required = true)]
        stdin: bool,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ProtocolArtifactArg {
    FolderbaseVersion,
    ChunkManifest,
}

#[derive(Debug, Subcommand)]
enum VersionCommand {
    /// Capture the current bytes of a file inside a folderbase.
    Capture {
        folderbase: PathBuf,
        path: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Restore an immutable version to a new, unoccupied path.
    Restore {
        folderbase: PathBuf,
        version: String,
        destination: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Restore the exact ordinary-file bytes named by the current Local Head Tombstone.
    RestoreTombstone {
        folderbase: PathBuf,
        path: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Print the append-only local object journal.
    History {
        folderbase: PathBuf,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
enum WorkspaceCommand {
    /// List visible folderbase entries as a flat deterministic projection.
    List {
        folderbase: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Read one editable UTF-8 document.
    Read {
        folderbase: PathBuf,
        path: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Save UTF-8 content read from standard input with optimistic concurrency.
    Save {
        folderbase: PathBuf,
        path: PathBuf,
        #[arg(long)]
        expected_sha256: String,
        #[arg(long)]
        stdin: bool,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
enum QueryCommand {
    /// Run one bounded metadata query read from standard input.
    Run {
        root: PathBuf,
        #[arg(long, required = true)]
        json: bool,
    },
    /// Explain one bounded metadata query read from standard input.
    Explain {
        root: PathBuf,
        #[arg(long, required = true)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
enum IndexCommand {
    /// Inspect index freshness without changing state.
    Status {
        root: PathBuf,
        #[arg(long, required = true)]
        json: bool,
    },
    /// Explicitly replace only the disposable query-index namespace.
    Rebuild {
        root: PathBuf,
        #[arg(long, required = true)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
enum TransformCommand {
    /// Analyze a folder without creating protocol state.
    Analyze {
        path: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Persist a proposed transform plan using typed answers from stdin.
    Plan {
        path: PathBuf,
        #[arg(long)]
        destination: PathBuf,
        #[arg(long)]
        answers_stdin: bool,
        #[arg(long)]
        json: bool,
    },
    /// Reopen and preview a proposed transform plan.
    Preview {
        path: PathBuf,
        migration_id: String,
        #[arg(long)]
        json: bool,
    },
    /// Explicitly approve a persisted transform plan.
    Approve {
        path: PathBuf,
        migration_id: String,
        #[arg(long)]
        json: bool,
    },
    /// Apply an approved transform plan.
    Apply {
        path: PathBuf,
        migration_id: String,
        #[arg(long)]
        json: bool,
    },
    /// Reopen the durable transform result without changing it.
    Reopen {
        path: PathBuf,
        migration_id: String,
        #[arg(long)]
        json: bool,
    },
    /// Recover an interrupted apply or rollback.
    Recover {
        path: PathBuf,
        migration_id: String,
        #[arg(long)]
        json: bool,
    },
    /// Roll back unchanged additive outputs; repeated calls are idempotent.
    Rollback {
        path: PathBuf,
        migration_id: String,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum FolderbaseKindArg {
    Person,
    Organization,
    Engagement,
    Project,
    Customer,
    Temporary,
    Custom,
}

impl From<FolderbaseKindArg> for FolderbaseKind {
    fn from(value: FolderbaseKindArg) -> Self {
        match value {
            FolderbaseKindArg::Person => Self::Person,
            FolderbaseKindArg::Organization => Self::Organization,
            FolderbaseKindArg::Engagement => Self::Engagement,
            FolderbaseKindArg::Project => Self::Project,
            FolderbaseKindArg::Customer => Self::Customer,
            FolderbaseKindArg::Temporary => Self::Temporary,
            FolderbaseKindArg::Custom => Self::Custom,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ValidationLevelArg {
    Shallow,
    ContentIntegrity,
}

#[derive(Debug)]
enum CliError {
    Folderbase(FolderbaseError),
    Capture(FolderbaseCaptureError),
    RootAttestation(RootAttestationError),
    OutputSerialization(serde_json::Error),
    OutputWrite {
        stream: &'static str,
        source: std::io::Error,
    },
}

impl fmt::Display for CliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Folderbase(source) => source.fmt(formatter),
            Self::Capture(source) => source.fmt(formatter),
            Self::RootAttestation(source) => source.fmt(formatter),
            Self::OutputSerialization(source) => {
                write!(formatter, "failed to serialize command output: {source}")
            }
            Self::OutputWrite { stream, source } => {
                write!(formatter, "failed to write command {stream}: {source}")
            }
        }
    }
}

impl std::error::Error for CliError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Folderbase(source) => Some(source),
            Self::Capture(source) => Some(source),
            Self::RootAttestation(source) => Some(source),
            Self::OutputSerialization(source) => Some(source),
            Self::OutputWrite { source, .. } => Some(source),
        }
    }
}

impl From<FolderbaseError> for CliError {
    fn from(source: FolderbaseError) -> Self {
        Self::Folderbase(source)
    }
}

impl From<FolderbaseCaptureError> for CliError {
    fn from(source: FolderbaseCaptureError) -> Self {
        Self::Capture(source)
    }
}

impl From<RootAttestationError> for CliError {
    fn from(source: RootAttestationError) -> Self {
        Self::RootAttestation(source)
    }
}

impl From<ValidationLevelArg> for ValidationLevel {
    fn from(value: ValidationLevelArg) -> Self {
        match value {
            ValidationLevelArg::Shallow => Self::Shallow,
            ValidationLevelArg::ContentIntegrity => Self::ContentIntegrity,
        }
    }
}

fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) if error.exit_code() != 0 && argv_selects_query_capability() => {
            let transport = query_capability::invalid_invocation(error.to_string());
            return match write_query_transport(transport) {
                Ok(code) => ExitCode::from(code),
                Err(error) => {
                    write_stderr_best_effort(format_args!("error: {error}"));
                    ExitCode::from(EXIT_OPERATIONAL_ERROR)
                }
            };
        }
        Err(error) if error.exit_code() != 0 && argv_selects_template_capability() => {
            return write_template_invocation_error(error.to_string());
        }
        Err(error) if error.exit_code() != 0 && argv_selects_change_set_capability() => {
            let transport = change_set_capability::invalid_invocation(error.to_string());
            return match write_change_set_transport(transport) {
                Ok(code) => ExitCode::from(code),
                Err(error) => {
                    write_stderr_best_effort(format_args!("error: {error}"));
                    ExitCode::from(EXIT_OPERATIONAL_ERROR)
                }
            };
        }
        Err(error) => {
            let exit_code = error.exit_code();
            return match error.print() {
                Ok(()) => ExitCode::from(u8::try_from(exit_code).unwrap_or(EXIT_OPERATIONAL_ERROR)),
                Err(source) => {
                    write_stderr_best_effort(format_args!(
                        "error: failed to write command output: {source}"
                    ));
                    ExitCode::from(EXIT_OPERATIONAL_ERROR)
                }
            };
        }
    };
    let json_errors = command_emits_json_errors(&cli.command);
    let template_json_errors = matches!(cli.command, Command::Template { .. });

    match run(cli) {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            if json_errors {
                let envelope = serde_json::json!({
                    "format": template_json_errors.then_some("folderbase-template-expansion-error-v1"),
                    "error": {
                        "code": error_code(&error),
                        "message": error.to_string(),
                    }
                });
                let envelope = if template_json_errors {
                    envelope
                } else {
                    let mut envelope = envelope;
                    envelope
                        .as_object_mut()
                        .expect("error envelope is an object")
                        .remove("format");
                    envelope
                };
                match serde_json::to_string_pretty(&envelope) {
                    Ok(encoded) => write_stderr_best_effort(format_args!("{encoded}")),
                    Err(serialization) => {
                        write_stderr_best_effort(format_args!(
                            "error: {error} (JSON serialization failed: {serialization})"
                        ));
                    }
                }
            } else {
                write_stderr_best_effort(format_args!("error: {error}"));
            }
            ExitCode::from(EXIT_OPERATIONAL_ERROR)
        }
    }
}

fn write_stderr_best_effort(arguments: fmt::Arguments<'_>) {
    let stderr = std::io::stderr();
    let mut stderr = stderr.lock();
    let _ = stderr.write_fmt(arguments);
    let _ = stderr.write_all(b"\n");
}

fn argv_selects_query_capability() -> bool {
    matches!(
        std::env::args_os()
            .nth(1)
            .and_then(|argument| argument.into_string().ok())
            .as_deref(),
        Some("query" | "index")
    )
}

fn argv_selects_template_capability() -> bool {
    matches!(
        std::env::args_os()
            .nth(1)
            .and_then(|argument| argument.into_string().ok())
            .as_deref(),
        Some("template")
    )
}

fn argv_selects_change_set_capability() -> bool {
    matches!(
        std::env::args_os()
            .nth(1)
            .and_then(|argument| argument.into_string().ok())
            .as_deref(),
        Some("change-set")
    )
}

fn write_template_invocation_error(message: String) -> ExitCode {
    let envelope = serde_json::json!({
        "format": "folderbase-template-expansion-error-v1",
        "error": {
            "code": "invalid_template_request",
            "message": message,
        }
    });
    let mut encoded = match serde_json::to_vec_pretty(&envelope) {
        Ok(encoded) => encoded,
        Err(source) => {
            write_stderr_best_effort(format_args!(
                "error: failed to serialize template invocation error: {source}"
            ));
            return ExitCode::from(EXIT_OPERATIONAL_ERROR);
        }
    };
    encoded.push(b'\n');

    let stderr = std::io::stderr();
    if let Err(error) = write_transport_stream(&mut stderr.lock(), &encoded, "stderr") {
        write_stderr_best_effort(format_args!("error: {error}"));
    }
    ExitCode::from(EXIT_OPERATIONAL_ERROR)
}

fn run(cli: Cli) -> Result<u8, CliError> {
    match cli.command {
        Command::Inspect { path, json } => {
            let report = inspect(&path)?;
            if json {
                print_json(&report)?;
            } else {
                print_inspection(&report);
            }
            Ok(EXIT_SUCCESS)
        }
        Command::Attest { path, json } => {
            let receipt = attest_folderbase_root(path)?;
            if json {
                print_json(&receipt)?;
            } else {
                println!("Attested Folderbase root: {}", receipt.root.display());
                println!("Folderbase ID: {}", receipt.folderbase_id);
                println!("Protocol version: {}", receipt.protocol_version);
                println!("Manifest SHA-256: {}", receipt.manifest_sha256);
                println!(
                    "Physical root instance ({CURRENT_ROOT_INSTANCE_FORMAT}): {}",
                    receipt.root_instance_sha256
                );
            }
            Ok(EXIT_SUCCESS)
        }
        Command::Init {
            path,
            dry_run,
            name,
            kind,
            agent_adapters,
            template,
            answers,
            json,
            expected_plan_digest,
        } => {
            let options = InitializationOptions {
                name,
                kind: kind.into(),
                create_agent_adapters: agent_adapters,
            };
            let plan = if let Some(template) = template {
                let (id, version) = parse_template_selector(&template)?;
                let package = load_builtin_template(id, version)?;
                let answers = parse_template_answers(&package, &answers)?;
                plan_template_initialization(&path, options, &package, &answers)?
            } else {
                if !answers.is_empty() {
                    return Err(folderbase_core::FolderbaseError::InvalidRecord {
                        path,
                        message: "template answers require --template".to_owned(),
                    }
                    .into());
                }
                plan_initialization(&path, options)?
            };

            if dry_run {
                if json {
                    print_json(&plan)?;
                } else {
                    print_initialization_plan(&plan);
                }
            } else {
                let result = match expected_plan_digest {
                    Some(digest) => {
                        let expected = InitializationPlanDigest::parse_sha256(digest)?;
                        initialize_with_expected_plan_digest(&plan, &expected)?
                    }
                    None => initialize(&plan)?,
                };
                if json {
                    print_json(&result)?;
                } else {
                    print_initialization_result(&result);
                }
            }
            Ok(EXIT_SUCCESS)
        }
        Command::Template { command } => {
            let (root, expected) = match &command {
                TemplateCommand::Plan { root, .. } => (root.clone(), None),
                TemplateCommand::Apply {
                    root,
                    expected_plan_digest,
                    ..
                } => (root.clone(), Some(expected_plan_digest.clone())),
            };
            let request = parse_template_expansion_request_stdin()?;
            let reviewed = plan_template_expansion(&root, &request.template, &request.answers)
                .map_err(map_template_request_error)?;
            let plan_document = template_plan_document(&reviewed);

            if expected.is_none() {
                print_json(&plan_document)?;
                return Ok(EXIT_SUCCESS);
            }

            let expected = expected.expect("apply has an expected digest");
            if reviewed.plan_digest().digest() != expected {
                print_json(&template_attention_document(
                    &root,
                    "expected_plan_digest_mismatch",
                    "the live template expansion plan no longer matches the reviewed digest",
                    Some((&expected, reviewed.plan_digest().digest())),
                    Some(plan_document),
                ))?;
                return Ok(EXIT_INVALID);
            }
            if !reviewed.structural_changes().is_empty() {
                print_json(&template_attention_document(
                    &root,
                    "reorganization_required",
                    "this change is structural and must use the Reorganization workflow",
                    None,
                    Some(plan_document),
                ))?;
                return Ok(EXIT_INVALID);
            }
            if !reviewed.blocked_paths().is_empty() {
                print_json(&template_attention_document(
                    &root,
                    "template_expansion_blocked",
                    "one or more template targets cannot be preserved safely",
                    None,
                    Some(plan_document),
                ))?;
                return Ok(EXIT_INVALID);
            }

            let (applied_plan, result) = apply_template_expansion_with_expected_plan_digest(
                &root,
                &request.template,
                &request.answers,
                &expected,
            )?;
            print_json(&template_apply_document(&applied_plan, &result))?;
            Ok(EXIT_SUCCESS)
        }
        Command::Upgrade {
            path,
            dry_run,
            expected_plan_digest,
            json,
        } => {
            let plan = plan_protocol_upgrade(path)?;
            if dry_run {
                if json {
                    print_json(&plan)?;
                } else {
                    println!(
                        "Upgrade {} from legacy protocol to 0.5.0",
                        plan.root().display()
                    );
                    println!(
                        "Plan digest {}:{}",
                        plan.plan_digest().algorithm(),
                        plan.plan_digest().digest()
                    );
                }
            } else {
                let expected =
                    expected_plan_digest.ok_or_else(|| FolderbaseError::InvalidRecord {
                        path: plan.root().to_path_buf(),
                        message:
                            "protocol upgrade apply requires --expected-plan-digest after review"
                                .to_owned(),
                    })?;
                let expected = ProtocolUpgradePlanDigest::parse_sha256(expected)?;
                let result = apply_protocol_upgrade(&plan, &expected)?;
                if json {
                    print_json(&result)?;
                } else {
                    println!(
                        "Upgraded {} from {} to {}",
                        result.root.display(),
                        result.from_protocol_version,
                        result.to_protocol_version
                    );
                }
            }
            Ok(EXIT_SUCCESS)
        }
        Command::Validate { path, level, json } => {
            let report = validate(&path, level.into())?;
            if json {
                print_json(&report)?;
            } else {
                print_validation(&report);
            }

            Ok(if report.valid {
                EXIT_SUCCESS
            } else {
                EXIT_INVALID
            })
        }
        Command::Migrate {
            path,
            destination,
            answers,
            answers_stdin,
            apply,
            json,
        } => {
            let analysis = analyze_migration(&path)?;
            let answers = if answers_stdin {
                parse_migration_answers_stdin()?
            } else {
                parse_migration_answers(&answers)?
            };
            let answered = answers
                .iter()
                .map(|answer| answer.question_id.as_str())
                .collect::<std::collections::BTreeSet<_>>();
            let missing = analysis
                .questions
                .iter()
                .filter(|question| !answered.contains(question.id.as_str()))
                .collect::<Vec<_>>();
            if !missing.is_empty() {
                if json {
                    print_json(&analysis)?;
                } else {
                    print_migration_questions(&analysis);
                }
                return Ok(EXIT_INVALID);
            }

            let plan = plan_migration(analysis, answers, destination)?;
            if apply {
                let result = apply_migration(approve_migration(plan)?)?;
                if json {
                    print_json(&result)?;
                } else {
                    print_migration_result(&result);
                }
            } else {
                let preview = preview_migration(&plan)?;
                if json {
                    print_json(&preview)?;
                } else {
                    print_migration_preview(&preview);
                }
            }
            Ok(EXIT_SUCCESS)
        }
        Command::Transform { command } => {
            match command {
                TransformCommand::Analyze { path, json } => {
                    let analysis = analyze_migration(path)?;
                    if json {
                        print_json(&analysis)?;
                    } else {
                        print_migration_questions(&analysis);
                    }
                }
                TransformCommand::Plan {
                    path,
                    destination,
                    answers_stdin,
                    json,
                } => {
                    if !answers_stdin {
                        return Err(FolderbaseError::InvalidRecord {
                            path: PathBuf::from("migration-answers-stdin"),
                            message: "transform plan requires --answers-stdin".to_owned(),
                        }
                        .into());
                    }
                    let analysis = analyze_migration(&path)?;
                    let answers = parse_migration_answers_stdin()?;
                    let plan = plan_migration(analysis, answers, destination)?;
                    if json {
                        print_json(&plan)?;
                    } else {
                        print_migration_preview(&preview_migration(&plan)?);
                    }
                }
                TransformCommand::Preview {
                    path,
                    migration_id,
                    json,
                } => {
                    let plan = MigrationPlan::reopen(path, &migration_id)?;
                    let preview = preview_migration(&plan)?;
                    if json {
                        print_json(&preview)?;
                    } else {
                        print_migration_preview(&preview);
                    }
                }
                TransformCommand::Approve {
                    path,
                    migration_id,
                    json,
                } => {
                    let plan = MigrationPlan::reopen(&path, &migration_id)?;
                    drop(approve_migration(plan)?);
                    let approved = MigrationPlan::reopen(path, &migration_id)?;
                    if json {
                        print_json(&approved)?;
                    } else {
                        println!("Approved transform {}", approved.id);
                    }
                }
                TransformCommand::Apply {
                    path,
                    migration_id,
                    json,
                } => {
                    let plan = MigrationPlan::reopen(&path, &migration_id)?;
                    let approval_digest = plan.approval_digest().ok_or_else(|| {
                        FolderbaseError::InvalidMigrationState {
                            expected: "approved",
                            actual: format!("{:?}", plan.state).to_ascii_lowercase(),
                        }
                    })?;
                    let outcome = MigrationExecution::run(
                        RootClaim::Current {
                            display_root: &path,
                        },
                        MigrationCommand::Apply {
                            migration_id: &migration_id,
                            approval_digest,
                        },
                    )?;
                    return render_migration_outcome(outcome, json);
                }
                TransformCommand::Reopen {
                    path,
                    migration_id,
                    json,
                } => {
                    let result = MigrationResult::reopen(path, &migration_id)?;
                    if json {
                        print_json(&result)?;
                    } else {
                        print_migration_result(&result);
                    }
                }
                TransformCommand::Recover {
                    path,
                    migration_id,
                    json,
                } => {
                    let outcome = MigrationExecution::run(
                        RootClaim::Current {
                            display_root: &path,
                        },
                        MigrationCommand::Recover {
                            migration_id: &migration_id,
                        },
                    )?;
                    return render_migration_outcome(outcome, json);
                }
                TransformCommand::Rollback {
                    path,
                    migration_id,
                    json,
                } => {
                    let outcome = MigrationExecution::run(
                        RootClaim::Current {
                            display_root: &path,
                        },
                        MigrationCommand::Rollback {
                            migration_id: &migration_id,
                        },
                    )?;
                    return render_migration_outcome(outcome, json);
                }
            }
            Ok(EXIT_SUCCESS)
        }
        Command::Version { command } => {
            match command {
                VersionCommand::Capture {
                    folderbase,
                    path,
                    json,
                } => {
                    let result = LocalVersionStore::open(folderbase)?.capture_file(path)?;
                    if json {
                        print_json(&result)?;
                    } else {
                        println!(
                            "Captured {} as {} ({})",
                            result.object.path, result.version.id, result.version.content.digest
                        );
                    }
                }
                VersionCommand::Restore {
                    folderbase,
                    version,
                    destination,
                    json,
                } => {
                    let version = VersionId::parse(version)?;
                    let result = LocalVersionStore::open(folderbase)?
                        .restore_version(&version, destination)?;
                    if json {
                        print_json(&result)?;
                    } else {
                        println!(
                            "Restored {} to {} ({} bytes)",
                            result.version_id,
                            result.path.display(),
                            result.content.bytes
                        );
                    }
                }
                VersionCommand::RestoreTombstone {
                    folderbase,
                    path,
                    json,
                } => {
                    let portable_path = path
                        .to_str()
                        .ok_or_else(|| FolderbaseError::UnsafePath(path.clone()))?;
                    let result = FolderbaseVersionStore::open(folderbase)?
                        .restore_tombstone(portable_path)?;
                    if json {
                        print_json(&result)?;
                    } else {
                        println!(
                            "Restored Tombstone {} as {} in {}",
                            result.path().display(),
                            result.object_version_id(),
                            result.version_id()
                        );
                    }
                }
                VersionCommand::History { folderbase, json } => {
                    let events = LocalVersionStore::open(folderbase)?.journal_events()?;
                    if json {
                        print_json(&events)?;
                    } else if events.is_empty() {
                        println!("No local version history.");
                    } else {
                        for event in events {
                            println!(
                                "{} {} {} {}",
                                event.at,
                                serde_json::to_value(event.action)
                                    .ok()
                                    .and_then(|value| value.as_str().map(ToOwned::to_owned))
                                    .unwrap_or_else(|| "unknown".to_owned()),
                                event.object_id,
                                event.path
                            );
                        }
                    }
                }
            }
            Ok(EXIT_SUCCESS)
        }
        Command::Workspace { command } => {
            match command {
                WorkspaceCommand::List { folderbase, json } => {
                    let listing = list_workspace(folderbase)?;
                    if json {
                        print_json(&listing)?;
                    } else {
                        for entry in listing.entries {
                            println!("{}\t{:?}", entry.path, entry.kind);
                        }
                    }
                }
                WorkspaceCommand::Read {
                    folderbase,
                    path,
                    json,
                } => {
                    let document = read_workspace_text(folderbase, path)?;
                    if json {
                        print_json(&document)?;
                    } else {
                        print!("{}", document.content);
                    }
                }
                WorkspaceCommand::Save {
                    folderbase,
                    path,
                    expected_sha256,
                    stdin,
                    json,
                } => {
                    if !stdin {
                        return Err(folderbase_core::FolderbaseError::InvalidRecord {
                            path: PathBuf::from("stdin"),
                            message: "workspace save requires --stdin".to_owned(),
                        }
                        .into());
                    }
                    let mut bytes = Vec::new();
                    std::io::stdin()
                        .take(MAX_WORKSPACE_TEXT_BYTES + 1)
                        .read_to_end(&mut bytes)
                        .map_err(|source| folderbase_core::FolderbaseError::Io {
                            path: PathBuf::from("stdin"),
                            source,
                        })?;
                    if bytes.len() as u64 > MAX_WORKSPACE_TEXT_BYTES {
                        return Err(folderbase_core::FolderbaseError::InvalidRecord {
                            path: PathBuf::from("stdin"),
                            message: format!(
                                "workspace text exceeds the {MAX_WORKSPACE_TEXT_BYTES} byte limit"
                            ),
                        }
                        .into());
                    }
                    let content = String::from_utf8(bytes).map_err(|_| {
                        folderbase_core::FolderbaseError::InvalidRecord {
                            path: PathBuf::from("stdin"),
                            message: "workspace save input is not UTF-8".to_owned(),
                        }
                    })?;
                    let result = save_workspace_text(folderbase, path, &expected_sha256, &content)?;
                    if json {
                        print_json(&result)?;
                    } else {
                        println!(
                            "Saved {} as {} ({})",
                            result.path, result.version_id, result.document.sha256
                        );
                    }
                }
            }
            Ok(EXIT_SUCCESS)
        }
        Command::Query { command } => {
            let (root, operation) = match command {
                QueryCommand::Run { root, json: _ } => {
                    (root, query_capability::QueryOperation::Run)
                }
                QueryCommand::Explain { root, json: _ } => {
                    (root, query_capability::QueryOperation::Explain)
                }
            };
            let transport =
                query_capability::execute_query(operation, root, std::io::stdin().lock());
            write_query_transport(transport)
        }
        Command::Index { command } => {
            let (root, operation) = match command {
                IndexCommand::Status { root, json: _ } => {
                    (root, query_capability::IndexOperation::Status)
                }
                IndexCommand::Rebuild { root, json: _ } => {
                    (root, query_capability::IndexOperation::Rebuild)
                }
            };
            write_query_transport(query_capability::execute_index(operation, root))
        }
        Command::Protocol { command } => match command {
            ProtocolCommand::Contract { json } => {
                if json {
                    let registry: EmbeddedCapabilityRegistry =
                        serde_json::from_str(CAPABILITY_REGISTRY)
                            .expect("embedded capability registry must be valid JSON");
                    print_json(&serde_json::json!({
                        "format": "folderbase-compatibility-contract-v1",
                        "contract_version": "1.0.0",
                        "cli_json": "folderbase-cli-json-v1",
                        "protocol_profiles": {
                            "root_manifest": ["0.5.0"],
                            "folderbase_version": ["0.4", "0.5"],
                            "chunk_manifest": ["folderbase-chunk-manifest-v1"],
                        },
                        "capabilities": registry.capabilities,
                    }))?;
                } else {
                    println!("Folderbase Compatibility Contract v1.0.0");
                    println!("CLI JSON: folderbase-cli-json-v1");
                }
                Ok(EXIT_SUCCESS)
            }
            ProtocolCommand::Check {
                artifact,
                stdin: _,
                json,
            } => run_protocol_check(artifact, json),
        },
        Command::ChangeSet { command } => {
            let operation = match command {
                ChangeSetCommand::Checkout {
                    root,
                    destination,
                    stdin: _,
                    json: _,
                } => change_set_capability::ChangeSetOperation::Checkout { root, destination },
                ChangeSetCommand::Propose {
                    checkout,
                    staging,
                    json: _,
                } => change_set_capability::ChangeSetOperation::Propose { checkout, staging },
                ChangeSetCommand::Assess {
                    root,
                    staging,
                    stdin: _,
                    json: _,
                } => change_set_capability::ChangeSetOperation::Assess { root, staging },
                ChangeSetCommand::Apply {
                    root,
                    staging,
                    stdin: _,
                    json: _,
                } => change_set_capability::ChangeSetOperation::Apply { root, staging },
            };
            write_change_set_transport(change_set_capability::execute(
                operation,
                std::io::stdin().lock(),
            ))
        }
    }
}

fn write_change_set_transport(
    transport: change_set_capability::ChangeSetTransport,
) -> Result<u8, CliError> {
    let stdout = std::io::stdout();
    let stderr = std::io::stderr();
    write_transport_stream(&mut stdout.lock(), &transport.stdout, "stdout")?;
    write_transport_stream(&mut stderr.lock(), &transport.stderr, "stderr")?;
    Ok(transport.exit_code)
}

fn write_query_transport(transport: query_capability::QueryTransport) -> Result<u8, CliError> {
    let stdout = std::io::stdout();
    let stderr = std::io::stderr();
    write_query_transport_to(transport, &mut stdout.lock(), &mut stderr.lock())
}

fn write_query_transport_to(
    transport: query_capability::QueryTransport,
    stdout: &mut impl Write,
    stderr: &mut impl Write,
) -> Result<u8, CliError> {
    write_transport_stream(stdout, &transport.stdout, "stdout")?;
    write_transport_stream(stderr, &transport.stderr, "stderr")?;
    Ok(transport.exit_code)
}

fn write_transport_stream(
    stream: &mut impl Write,
    bytes: &[u8],
    name: &'static str,
) -> Result<(), CliError> {
    if bytes.is_empty() {
        return Ok(());
    }
    stream
        .write_all(bytes)
        .and_then(|()| stream.flush())
        .map_err(|source| CliError::OutputWrite {
            stream: name,
            source,
        })
}

fn run_protocol_check(artifact: ProtocolArtifactArg, json: bool) -> Result<u8, CliError> {
    let (artifact_name, result): (&str, Result<(String, String), String>) = match artifact {
        ProtocolArtifactArg::FolderbaseVersion => {
            let result = FolderbaseVersion::decode_bounded(std::io::stdin().lock())
                .and_then(|version| {
                    let profile = version.protocol_version().to_owned();
                    let canonical_digest = version.canonical_digest()?;
                    Ok((profile, canonical_digest))
                })
                .map_err(|error| error.to_string());
            ("folderbase-version", result)
        }
        ProtocolArtifactArg::ChunkManifest => {
            let result = ChunkManifest::decode_bounded(std::io::stdin().lock())
                .and_then(|manifest| {
                    let profile = manifest.profile.clone();
                    let canonical_digest = manifest.canonical_digest()?;
                    Ok((profile, canonical_digest))
                })
                .map_err(|error| error.to_string());
            ("chunk-manifest", result)
        }
    };

    match result {
        Ok((profile, canonical_digest)) => {
            if json {
                print_json(&serde_json::json!({
                    "artifact": artifact_name,
                    "profile": profile,
                    "valid": true,
                    "canonical_digest": canonical_digest,
                }))?;
            } else {
                println!("Valid {artifact_name} ({profile})");
                println!("Canonical SHA-256: {canonical_digest}");
            }
            Ok(EXIT_SUCCESS)
        }
        Err(message) => {
            if json {
                print_json(&serde_json::json!({
                    "artifact": artifact_name,
                    "valid": false,
                    "error": {
                        "code": "invalid_artifact",
                        "message": message,
                    },
                }))?;
            } else {
                println!("Invalid {artifact_name}: {message}");
            }
            Ok(EXIT_INVALID)
        }
    }
}

fn print_json(value: &impl serde::Serialize) -> Result<(), CliError> {
    let mut encoded = serde_json::to_vec_pretty(value).map_err(CliError::OutputSerialization)?;
    encoded.push(b'\n');
    let stdout = std::io::stdout();
    write_transport_stream(&mut stdout.lock(), &encoded, "stdout")
}

fn parse_template_expansion_request_stdin() -> Result<TemplateExpansionRequest, CliError> {
    let mut bytes = Vec::new();
    std::io::stdin()
        .lock()
        .take(MAX_TEMPLATE_EXPANSION_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| {
            FolderbaseError::InvalidTemplateRequest(format!(
                "failed to read template request from stdin: {source}"
            ))
        })?;
    if bytes.len() as u64 > MAX_TEMPLATE_EXPANSION_REQUEST_BYTES {
        return Err(FolderbaseError::TemplateRequestTooLarge.into());
    }
    let request: TemplateExpansionRequest = serde_json::from_slice(&bytes).map_err(|source| {
        FolderbaseError::InvalidTemplateRequest(format!("request is not valid JSON: {source}"))
    })?;
    if request.format != "folderbase-template-expansion-request-v1" {
        return Err(FolderbaseError::InvalidTemplateRequest(
            "format must be folderbase-template-expansion-request-v1".to_owned(),
        )
        .into());
    }
    Ok(request)
}

fn map_template_request_error(error: FolderbaseError) -> CliError {
    match error {
        FolderbaseError::InvalidRecord { .. } | FolderbaseError::UnsafePath(_) => {
            FolderbaseError::InvalidTemplateRequest(error.to_string()).into()
        }
        error => error.into(),
    }
}

fn template_plan_document(plan: &TemplateExpansionPlan) -> serde_json::Value {
    let additions = plan
        .additions()
        .iter()
        .map(|addition| {
            let content = addition.content().map(str::as_bytes);
            serde_json::json!({
                "path": template_wire_path(addition.path()),
                "kind": addition.kind(),
                "bytes": content.map(|bytes| bytes.len() as u64),
                "sha256": content.map(|bytes| format!("{:x}", Sha256::digest(bytes))),
            })
        })
        .collect::<Vec<_>>();
    let structural_changes = plan
        .structural_changes()
        .iter()
        .map(|change| {
            serde_json::json!({
                "kind": change.kind(),
                "path": change.path().map(template_wire_path),
                "reason": change.reason(),
            })
        })
        .collect::<Vec<_>>();
    let disposition = if !plan.structural_changes().is_empty() {
        "reorganization_required"
    } else if !plan.blocked_paths().is_empty() {
        "blocked"
    } else if plan.is_noop() {
        "noop"
    } else {
        "ready"
    };
    serde_json::json!({
        "format": "folderbase-template-expansion-plan-v1",
        "root": plan.root(),
        "folderbase_id": plan.folderbase_id(),
        "template": {
            "id": plan.template_id(),
            "version": plan.template_version(),
            "package_digest": {
                "algorithm": plan.template_package_digest().algorithm(),
                "digest": plan.template_package_digest().digest(),
            },
        },
        "comparison": {
            "source": plan.comparison_source(),
            "version": plan.comparison_version(),
            "application_id": plan.comparison_application_id(),
        },
        "disposition": disposition,
        "additions": additions,
        "preserved_paths": plan.preserved_paths().iter().map(|path| template_wire_path(path)).collect::<Vec<_>>(),
        "blocked_paths": plan.blocked_paths().iter().map(|path| template_wire_path(path)).collect::<Vec<_>>(),
        "structural_changes": structural_changes,
        "plan_digest": {
            "algorithm": plan.plan_digest().algorithm(),
            "digest": plan.plan_digest().digest(),
        },
    })
}

fn template_apply_document(
    plan: &TemplateExpansionPlan,
    result: &folderbase_core::TemplateApplicationResult,
) -> serde_json::Value {
    serde_json::json!({
        "format": "folderbase-template-expansion-apply-result-v1",
        "root": plan.root(),
        "folderbase_id": plan.folderbase_id(),
        "template": {
            "id": plan.template_id(),
            "version": plan.template_version(),
            "package_digest": {
                "algorithm": plan.template_package_digest().algorithm(),
                "digest": plan.template_package_digest().digest(),
            },
        },
        "status": if result.application_record().is_some() { "applied" } else { "noop" },
        "created_paths": result.created_paths().iter().map(|path| template_wire_path(path)).collect::<Vec<_>>(),
        "preserved_paths": result.preserved_paths().iter().map(|path| template_wire_path(path)).collect::<Vec<_>>(),
        "application_record": result.application_record().map(template_wire_path),
        "plan_digest": {
            "algorithm": plan.plan_digest().algorithm(),
            "digest": plan.plan_digest().digest(),
        },
    })
}

fn template_attention_document(
    root: &Path,
    code: &str,
    message: &str,
    digests: Option<(&str, &str)>,
    plan: Option<serde_json::Value>,
) -> serde_json::Value {
    let mut attention = serde_json::json!({
        "code": code,
        "message": message,
    });
    if let Some((provided, current)) = digests {
        attention["provided_plan_digest"] = serde_json::json!({
            "algorithm": "sha256",
            "digest": provided,
        });
        attention["expected_plan_digest"] = serde_json::json!({
            "algorithm": "sha256",
            "digest": current,
        });
    }
    if let Some(plan) = plan {
        attention["plan"] = plan;
    }
    serde_json::json!({
        "format": "folderbase-template-expansion-attention-v1",
        "root": root,
        "attention": attention,
    })
}

fn template_wire_path(path: &Path) -> String {
    path.components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

fn command_emits_json_errors(command: &Command) -> bool {
    match command {
        Command::Inspect { json, .. }
        | Command::Attest { json, .. }
        | Command::Init { json, .. }
        | Command::Upgrade { json, .. }
        | Command::Validate { json, .. }
        | Command::Migrate { json, .. } => *json,
        Command::Template { command } => match command {
            TemplateCommand::Plan { json, .. } | TemplateCommand::Apply { json, .. } => *json,
        },
        Command::Version { command } => match command {
            VersionCommand::Capture { json, .. }
            | VersionCommand::Restore { json, .. }
            | VersionCommand::RestoreTombstone { json, .. }
            | VersionCommand::History { json, .. } => *json,
        },
        Command::Transform { command } => match command {
            TransformCommand::Analyze { json, .. }
            | TransformCommand::Plan { json, .. }
            | TransformCommand::Preview { json, .. }
            | TransformCommand::Approve { json, .. }
            | TransformCommand::Apply { json, .. }
            | TransformCommand::Reopen { json, .. }
            | TransformCommand::Recover { json, .. }
            | TransformCommand::Rollback { json, .. } => *json,
        },
        Command::Workspace { command } => match command {
            WorkspaceCommand::List { json, .. }
            | WorkspaceCommand::Read { json, .. }
            | WorkspaceCommand::Save { json, .. } => *json,
        },
        Command::Query { command } => match command {
            QueryCommand::Run { json, .. } | QueryCommand::Explain { json, .. } => *json,
        },
        Command::Index { command } => match command {
            IndexCommand::Status { json, .. } | IndexCommand::Rebuild { json, .. } => *json,
        },
        Command::Protocol { command } => match command {
            ProtocolCommand::Contract { json } | ProtocolCommand::Check { json, .. } => *json,
        },
        Command::ChangeSet { .. } => false,
    }
}

fn error_code(error: &CliError) -> &'static str {
    let error = match error {
        CliError::Folderbase(error) => error,
        CliError::Capture(error) => {
            return match error {
                FolderbaseCaptureError::MissingLocalHead => "missing_local_head",
                FolderbaseCaptureError::TombstoneNotFound(_) => "tombstone_not_found",
                FolderbaseCaptureError::UnsupportedTombstoneKind(_) => "unsupported_tombstone_kind",
                FolderbaseCaptureError::RestoreTargetOccupied(_) => "restore_target_occupied",
                FolderbaseCaptureError::InvalidRestoreAncestry(_) => "invalid_restore_ancestry",
                FolderbaseCaptureError::InvalidRestoreTransaction(_) => {
                    "invalid_restore_transaction"
                }
                FolderbaseCaptureError::RestoreAuthorityMaintenanceRequired { .. } => {
                    "restore_authority_maintenance_required"
                }
                FolderbaseCaptureError::RestoreNamespaceRepairRequired(_) => {
                    "restore_namespace_repair_required"
                }
                FolderbaseCaptureError::ConflictingTransaction(_) => "conflicting_transaction",
                _ => "capture_error",
            };
        }
        CliError::RootAttestation(error) => return error.code(),
        CliError::OutputSerialization(_) => return "output_serialization",
        CliError::OutputWrite { .. } => return "output_write_failed",
    };
    match error {
        FolderbaseError::InvalidRoot(_) => "invalid_root",
        FolderbaseError::UnsafePath(_) => "unsafe_path",
        FolderbaseError::ProviderControlled(_) => "provider_controlled",
        FolderbaseError::PlanRootMismatch { .. } => "plan_root_mismatch",
        FolderbaseError::PlanRootIdentityChanged(_) => "plan_root_identity_changed",
        FolderbaseError::PlanPreconditionChanged(_) => "plan_precondition_changed",
        FolderbaseError::InvalidInitializationPlanDigest => "invalid_initialization_plan_digest",
        FolderbaseError::InitializationPlanChanged { .. } => "initialization_plan_changed",
        FolderbaseError::InitializationDestinationChanged(_) => "initialization_plan_changed",
        FolderbaseError::InvalidProtocolUpgradePlanDigest => "invalid_protocol_upgrade_plan_digest",
        FolderbaseError::ProtocolUpgradePlanChanged { .. } => "protocol_upgrade_plan_changed",
        FolderbaseError::ProtocolUpgradeBlocked(_) => "protocol_upgrade_blocked",
        FolderbaseError::RecoveryRequired { .. } => "recovery_required",
        FolderbaseError::InitializationInventoryLimitExceeded { .. } => {
            "initialization_inventory_limit_exceeded"
        }
        FolderbaseError::NestedBoundaryWorkLimitExceeded { .. } => {
            "nested_boundary_work_limit_exceeded"
        }
        FolderbaseError::InvalidMigrationState { .. } => "invalid_migration_state",
        FolderbaseError::MigrationApprovalMismatch => "migration_approval_mismatch",
        FolderbaseError::MigrationSourceChanged(_) => "migration_source_changed",
        FolderbaseError::MigrationVerificationFailed(_) => "migration_verification_failed",
        FolderbaseError::WouldOverwrite(_) => "would_overwrite",
        FolderbaseError::RestoreNamespaceRepairRequired(_) => "restore_namespace_repair_required",
        FolderbaseError::UnsupportedMigrationFilesystem { .. } => {
            "unsupported_migration_filesystem"
        }
        FolderbaseError::StructuralTemplateChangeRequiresApproval => {
            "structural_template_change_requires_approval"
        }
        FolderbaseError::TemplateExpansionBlocked => "template_expansion_blocked",
        FolderbaseError::TemplateRequestTooLarge => "template_request_too_large",
        FolderbaseError::InvalidTemplateRequest(_) => "invalid_template_request",
        FolderbaseError::InvalidTemplateExpansionPlanDigest => {
            "invalid_template_expansion_plan_digest"
        }
        FolderbaseError::TemplateExpansionPlanChanged { .. } => "expected_plan_digest_mismatch",
        FolderbaseError::WorkspaceContentChanged(_) => "workspace_content_changed",
        FolderbaseError::InvalidRecord { .. } => "invalid_record",
        FolderbaseError::Io { .. } => "io_error",
        FolderbaseError::Json { .. } => "json_error",
    }
}

fn print_inspection(report: &InspectionReport) {
    println!("Inspected {}", report.root.display());
    println!(
        "{} enumerated files · {} enumerated · {} collapsed reconstructable trees",
        report.inventory.file_count,
        human_bytes(report.inventory.total_bytes),
        report.inventory.reconstructable_tree_count
    );
    println!(
        "Classified: {} generated · {} secret-shaped · {} temporary · {} large · {} versioned",
        report.inventory.generated_file_count,
        report.inventory.secret_shaped_file_count,
        report.inventory.temporary_file_count,
        report.inventory.large_file_count,
        report.inventory.versioned_file_count
    );
    println!(
        "{} Git repositories · {} context files · {} boundary hints",
        report.git_repositories.len(),
        report.context_files.len(),
        report.boundary_hints.len()
    );
    print_warnings(&report.warnings);
}

fn print_initialization_plan(plan: &InitializationPlan) {
    println!("Initialization plan for {}", plan.root().display());
    println!(
        "{} ({}) · folderbase {}",
        plan.folderbase_name(),
        folderbase_kind_label(plan.folderbase_kind()),
        plan.folderbase_id()
    );
    println!(
        "{} directories · {} writes · {} existing template targets · {} preserved",
        plan.directories().len(),
        plan.writes().len(),
        plan.template_preconditions().len(),
        plan.preserved_paths().len()
    );
    println!(
        "Plan digest {}:{}",
        plan.plan_digest().algorithm(),
        plan.plan_digest().digest()
    );
    for directory in plan.directories() {
        println!(
            "  create directory {} — {}",
            display_relative(plan.root(), directory.path()),
            directory.purpose()
        );
    }
    for write in plan.writes() {
        println!(
            "  create {} — {}",
            display_relative(plan.root(), write.path()),
            write.purpose()
        );
    }
    for precondition in plan.template_preconditions() {
        println!(
            "  preserve existing {} {} — template target",
            match precondition.kind() {
                folderbase_core::TemplateArtifactKind::Directory => "directory",
                folderbase_core::TemplateArtifactKind::Text => "file",
            },
            display_relative(plan.root(), precondition.path())
        );
    }
    print_warnings(plan.warnings());
}

fn print_initialization_result(result: &InitializationResult) {
    println!("Initialized {}", result.root.display());
    println!("Folderbase {}", result.folderbase_id);
    println!(
        "Applied plan {}:{}",
        result.applied_plan_digest.algorithm(),
        result.applied_plan_digest.digest()
    );
    println!(
        "{} paths created · {} preserved",
        result.created_paths.len(),
        result.preserved_paths.len()
    );
}

fn print_validation(report: &ValidationReport) {
    let status = if report.valid { "Valid" } else { "Invalid" };
    println!(
        "{status}: {} ({})",
        report.root.display(),
        validation_level_label(report.level)
    );

    if report.findings.is_empty() {
        println!("No findings.");
        return;
    }

    for finding in &report.findings {
        let path = finding
            .path
            .as_deref()
            .map(|path| format!(" [{}]", display_relative(&report.root, path)))
            .unwrap_or_default();
        println!(
            "{} {}{path}: {}",
            validation_severity_label(finding.severity),
            finding.code,
            finding.message
        );
    }
}

fn parse_migration_answers(values: &[String]) -> folderbase_core::Result<Vec<MigrationAnswer>> {
    let mut answers = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for value in values {
        let (question_id, answer) = value.split_once('=').ok_or_else(|| {
            folderbase_core::FolderbaseError::InvalidRecord {
                path: PathBuf::from("migration-answer"),
                message: format!("answer must use QUESTION_ID=ANSWER: {value}"),
            }
        })?;
        if question_id.trim().is_empty()
            || answer.trim().is_empty()
            || !seen.insert(question_id.to_owned())
        {
            return Err(folderbase_core::FolderbaseError::InvalidRecord {
                path: PathBuf::from("migration-answer"),
                message: "answers require unique non-empty question ids and values".to_owned(),
            });
        }
        answers.push(MigrationAnswer {
            question_id: question_id.to_owned(),
            answer: answer.to_owned(),
            exceptions: Vec::new(),
        });
    }
    Ok(answers)
}

fn parse_migration_answers_stdin() -> folderbase_core::Result<Vec<MigrationAnswer>> {
    let mut bytes = Vec::new();
    std::io::stdin()
        .lock()
        .take(MAX_MIGRATION_ANSWERS_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| folderbase_core::FolderbaseError::InvalidRecord {
            path: PathBuf::from("migration-answers-stdin"),
            message: format!("failed to read migration answers from stdin: {source}"),
        })?;
    if bytes.len() as u64 > MAX_MIGRATION_ANSWERS_BYTES {
        return Err(folderbase_core::FolderbaseError::InvalidRecord {
            path: PathBuf::from("migration-answers-stdin"),
            message: format!("migration answer JSON exceeds {MAX_MIGRATION_ANSWERS_BYTES} bytes"),
        });
    }
    serde_json::from_slice(&bytes).map_err(|source| {
        folderbase_core::FolderbaseError::InvalidRecord {
            path: PathBuf::from("migration-answers-stdin"),
            message: format!("invalid migration answer JSON: {source}"),
        }
    })
}

fn parse_template_selector(value: &str) -> folderbase_core::Result<(&str, &str)> {
    let (id, version) =
        value
            .rsplit_once('@')
            .ok_or_else(|| folderbase_core::FolderbaseError::InvalidRecord {
                path: PathBuf::from("template"),
                message: format!("template must use ID@VERSION: {value}"),
            })?;
    if id.is_empty() || version.is_empty() {
        return Err(folderbase_core::FolderbaseError::InvalidRecord {
            path: PathBuf::from("template"),
            message: "template requires a non-empty ID and exact version".to_owned(),
        });
    }
    Ok((id, version))
}

fn parse_template_answers(
    package: &TemplatePackage,
    values: &[String],
) -> folderbase_core::Result<BTreeMap<String, TemplateAnswerValue>> {
    let question_types = package
        .questions()
        .iter()
        .map(|question| (question.id(), question.answer_type()))
        .collect::<BTreeMap<_, _>>();
    let mut answers = BTreeMap::new();
    for value in values {
        let (question_id, answer) = value.split_once('=').ok_or_else(|| {
            folderbase_core::FolderbaseError::InvalidRecord {
                path: PathBuf::from("template-answer"),
                message: format!("answer must use QUESTION_ID=ANSWER: {value}"),
            }
        })?;
        let answer_type = question_types.get(question_id).ok_or_else(|| {
            folderbase_core::FolderbaseError::InvalidRecord {
                path: PathBuf::from("template-answer"),
                message: format!("unknown template answer: {question_id}"),
            }
        })?;
        let answer = match answer_type {
            TemplateAnswerType::Text => TemplateAnswerValue::Text(answer.to_owned()),
            TemplateAnswerType::Boolean => {
                TemplateAnswerValue::Boolean(answer.parse::<bool>().map_err(|_| {
                    folderbase_core::FolderbaseError::InvalidRecord {
                        path: PathBuf::from("template-answer"),
                        message: format!("boolean answer must be true or false: {question_id}"),
                    }
                })?)
            }
        };
        if answers.insert(question_id.to_owned(), answer).is_some() {
            return Err(folderbase_core::FolderbaseError::InvalidRecord {
                path: PathBuf::from("template-answer"),
                message: format!("duplicate template answer: {question_id}"),
            });
        }
    }
    Ok(answers)
}

fn print_migration_questions(analysis: &MigrationAnalysis) {
    println!("Migration analysis for {}", analysis.root.display());
    println!(
        "{} files · {} · {} proposed boundaries",
        analysis.file_count,
        human_bytes(analysis.total_bytes),
        analysis.proposed_boundaries.len()
    );
    println!("Answer every question and rerun with --answer QUESTION_ID=ANSWER:");
    for question in &analysis.questions {
        println!("  {} — {}", question.id, question.prompt);
        println!("    {}", question.context);
        for option in &question.options {
            let recommended = if option.id == question.recommended_option_id {
                " (recommended)"
            } else {
                ""
            };
            println!("    {}{recommended} — {}", option.id, option.label);
            println!("      {}", option.consequence);
        }
    }
    println!(
        "For large folders, pass the complete JSON answer array on stdin with --answers-stdin."
    );
}

fn print_migration_preview(preview: &MigrationPreview) {
    println!("Migration preview {}", preview.migration_id);
    println!(
        "{} directories · {} copies · {} additional local",
        preview.creates_directories.len(),
        preview.copies.len(),
        human_bytes(preview.additional_local_bytes)
    );
    println!("Source files remain unchanged.");
    for copy in &preview.copies {
        println!(
            "  copy {} → {}",
            copy.source_path.display(),
            copy.destination_path.display()
        );
    }
    println!("Rerun with the same answers and --apply to execute.");
}

fn print_migration_result(result: &MigrationResult) {
    match result.state {
        MigrationState::Analyzing => {
            println!("Migration analyzing {}", result.migration_id);
        }
        MigrationState::Questions => {
            println!("Migration awaiting answers {}", result.migration_id);
        }
        MigrationState::Proposed => {
            println!("Migration proposed {}", result.migration_id);
        }
        MigrationState::Approved => {
            println!("Migration approved {}", result.migration_id);
        }
        MigrationState::Applying => {
            println!("Migration applying {}", result.migration_id);
            println!(
                "Durable progress is recorded at {}",
                result.journal_path.display()
            );
        }
        MigrationState::Verified => {
            println!("Migration verified {}", result.migration_id);
            println!(
                "{} additive paths created · journal {}",
                result.created_paths.len(),
                result.journal_path.display()
            );
            println!("Original source files were preserved.");
        }
        MigrationState::Conflicted => {
            println!("Migration conflicted {}", result.migration_id);
            println!(
                "Inspect or recover durable state at {}",
                result.journal_path.display()
            );
        }
        MigrationState::RollingBack => {
            println!("Migration rolling back {}", result.migration_id);
            println!(
                "Durable progress is recorded at {}",
                result.journal_path.display()
            );
        }
        MigrationState::Rejected => {
            println!("Migration rejected {}", result.migration_id);
        }
        MigrationState::RolledBack => {
            println!("Migration rolled back {}", result.migration_id);
            println!("Original source files were preserved.");
        }
    }
}

fn print_migration_conflicts(migration_id: &str, conflicts: &[MigrationConflict]) {
    println!("Migration conflicted {migration_id}");
    for conflict in conflicts {
        let paths = conflict
            .affected_paths
            .iter()
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>()
            .join(", ");
        println!(
            "  {}: expected {}; observed {}",
            paths, conflict.expected, conflict.observed
        );
        if let Some(preserved) = &conflict.preserved_artifact {
            println!("    preserved at {}", preserved.display());
        }
    }
}

fn render_migration_outcome(outcome: MigrationOutcome, json: bool) -> Result<u8, CliError> {
    match outcome {
        MigrationOutcome::Applied(result) => {
            if json {
                print_json(&result)?;
            } else {
                print_migration_result(&result);
            }
            Ok(EXIT_SUCCESS)
        }
        MigrationOutcome::RolledBack(result) => {
            if json {
                print_json(&result)?;
            } else {
                print_rollback_result(&result);
            }
            Ok(EXIT_SUCCESS)
        }
        MigrationOutcome::Conflicted {
            migration_id,
            conflicts,
        } => {
            if json {
                print_json(&serde_json::json!({
                    "migration_id": migration_id,
                    "state": "conflicted",
                    "conflicts": conflicts,
                }))?;
            } else {
                print_migration_conflicts(&migration_id, &conflicts);
            }
            Ok(EXIT_INVALID)
        }
        MigrationOutcome::RecoveryRequired { migration_id, work } => {
            if json {
                print_json(&serde_json::json!({
                    "migration_id": migration_id,
                    "state": "recovery_required",
                    "work": work,
                }))?;
            } else {
                println!("Migration recovery required {migration_id}");
                println!("  Finish or recover: {work}");
            }
            Ok(EXIT_INVALID)
        }
        _ => Err(FolderbaseError::InvalidMigrationState {
            expected: "supported_migration_outcome",
            actual: "unsupported_migration_outcome".to_owned(),
        }
        .into()),
    }
}

fn print_rollback_result(result: &RollbackResult) {
    println!("Migration rolled back {}", result.migration_id);
    println!(
        "{} unchanged additive paths removed.",
        result.removed_paths.len()
    );
    println!("Original source files were preserved.");
}

fn print_warnings(warnings: &[String]) {
    for warning in warnings {
        println!("Warning: {warning}");
    }
}

fn display_relative<'a>(root: &Path, path: &'a Path) -> std::borrow::Cow<'a, str> {
    path.strip_prefix(root).unwrap_or(path).to_string_lossy()
}

fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }

    if unit == 0 {
        format!("{bytes} {}", UNITS[unit])
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

fn folderbase_kind_label(kind: FolderbaseKind) -> &'static str {
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

fn validation_level_label(level: ValidationLevel) -> &'static str {
    match level {
        ValidationLevel::Shallow => "shallow",
        ValidationLevel::ContentIntegrity => "content-integrity",
    }
}

fn validation_severity_label(severity: ValidationSeverity) -> &'static str {
    match severity {
        ValidationSeverity::Error => "error",
        ValidationSeverity::Warning => "warning",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    struct RejectsWrites;

    impl Write for RejectsWrites {
        fn write(&mut self, _buffer: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "closed test stream",
            ))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn query_transport_stdout_write_failure_is_operational() {
        let transport = query_capability::QueryTransport {
            exit_code: EXIT_SUCCESS,
            stdout: b"success document\n".to_vec(),
            stderr: Vec::new(),
        };
        let mut stdout = RejectsWrites;
        let mut stderr = Vec::new();

        let error = write_query_transport_to(transport, &mut stdout, &mut stderr)
            .expect_err("a closed stdout must not report success");

        assert_eq!(error_code(&error), "output_write_failed");
    }

    #[test]
    fn query_transport_stderr_write_failure_is_operational() {
        let transport = query_capability::QueryTransport {
            exit_code: EXIT_OPERATIONAL_ERROR,
            stdout: Vec::new(),
            stderr: b"error document\n".to_vec(),
        };
        let mut stdout = Vec::new();
        let mut stderr = RejectsWrites;

        let error = write_query_transport_to(transport, &mut stdout, &mut stderr)
            .expect_err("a closed stderr must remain an operational failure");

        assert_eq!(error_code(&error), "output_write_failed");
    }

    #[test]
    fn reports_the_shared_nested_boundary_work_limit() {
        let error = CliError::Folderbase(FolderbaseError::NestedBoundaryWorkLimitExceeded {
            path: PathBuf::from("nested"),
            maximum: 16_384,
        });

        assert_eq!(error_code(&error), "nested_boundary_work_limit_exceeded");
    }

    #[test]
    fn reports_an_unsupported_migration_filesystem() {
        let error = CliError::Folderbase(FolderbaseError::UnsupportedMigrationFilesystem {
            path: PathBuf::from("workspace"),
            reason: "atomic no-replace rename is unavailable".to_owned(),
        });

        assert_eq!(error_code(&error), "unsupported_migration_filesystem");
    }

    #[test]
    fn parses_supported_init_options() {
        let cli = Cli::try_parse_from([
            "folderbase",
            "init",
            "/tmp/example",
            "--dry-run",
            "--name",
            "Example",
            "--kind",
            "organization",
            "--agent-adapters",
            "--json",
        ])
        .expect("valid CLI");

        let Command::Init {
            path,
            dry_run,
            name,
            kind,
            agent_adapters,
            template,
            answers,
            json,
            expected_plan_digest,
        } = cli.command
        else {
            panic!("expected init command");
        };

        assert_eq!(path, PathBuf::from("/tmp/example"));
        assert!(dry_run);
        assert_eq!(name.as_deref(), Some("Example"));
        assert!(matches!(kind, FolderbaseKindArg::Organization));
        assert!(agent_adapters);
        assert!(template.is_none());
        assert!(answers.is_empty());
        assert!(json);
        assert!(expected_plan_digest.is_none());
    }

    #[test]
    fn parses_content_integrity_validation() {
        let cli = Cli::try_parse_from([
            "folderbase",
            "validate",
            "/tmp/example",
            "--level",
            "content-integrity",
            "--json",
        ])
        .expect("valid CLI");

        let Command::Validate { level, json, path } = cli.command else {
            panic!("expected validate command");
        };

        assert_eq!(path, PathBuf::from("/tmp/example"));
        assert!(matches!(level, ValidationLevelArg::ContentIntegrity));
        assert!(json);
    }

    #[test]
    fn parses_migration_answers_and_apply_flag() {
        let cli = Cli::try_parse_from([
            "folderbase",
            "migrate",
            "/tmp/example",
            "--destination",
            "Organized",
            "--answer",
            "question_scope=one_folderbase",
            "--apply",
            "--json",
        ])
        .expect("valid CLI");

        let Command::Migrate {
            path,
            destination,
            answers,
            answers_stdin,
            apply,
            json,
        } = cli.command
        else {
            panic!("expected migrate command");
        };
        assert_eq!(path, PathBuf::from("/tmp/example"));
        assert_eq!(destination, PathBuf::from("Organized"));
        assert_eq!(answers, vec!["question_scope=one_folderbase"]);
        assert!(!answers_stdin);
        assert!(apply);
        assert!(json);
    }

    #[test]
    fn parses_version_restore() {
        let cli = Cli::try_parse_from([
            "folderbase",
            "version",
            "restore",
            "/tmp/folderbase",
            "version_019f9b77-fdfa-78fb-8ca5-4ff25e6cc4b1",
            "Restored/file.md",
            "--json",
        ])
        .expect("valid CLI");

        let Command::Version {
            command:
                VersionCommand::Restore {
                    folderbase,
                    version,
                    destination,
                    json,
                },
        } = cli.command
        else {
            panic!("expected version restore command");
        };
        assert_eq!(folderbase, PathBuf::from("/tmp/folderbase"));
        assert!(version.starts_with("version_"));
        assert_eq!(destination, PathBuf::from("Restored/file.md"));
        assert!(json);
    }

    #[test]
    fn formats_binary_units() {
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(1024), "1.0 KiB");
        assert_eq!(human_bytes(1_572_864), "1.5 MiB");
    }
}

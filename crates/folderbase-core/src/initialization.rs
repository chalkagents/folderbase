use std::{
    collections::BTreeMap,
    ffi::OsStr,
    fs,
    io::{Read, Write},
    path::{Component, Path, PathBuf},
};

use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt};
use cap_std::fs::{Dir, OpenOptions};
use chrono::Utc;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use unicode_casefold::UnicodeCaseFold;
use uuid::Uuid;

use crate::model::{
    InitializationDestinationEntry, InitializationDestinationKind, InitializationRequest,
};
use crate::physical_identity::{PhysicalIdentity, RetainedPhysicalIdentity};
use crate::root_attestation::{DEFAULT_V05_CAPTURE_IGNORE_RULES, metadata_is_link_or_reparse};
use crate::template::template_package_sha256;
use crate::traversal_policy::{
    NestedFolderbaseBoundaryKind, classify_nested_folderbase_boundary_with_observer,
    is_git_metadata_component, is_reconstructable_directory,
};
use crate::{
    FolderbaseError, FolderbaseKind, InitializationInventoryLimitKind, InitializationOptions,
    InitializationPlan, InitializationPlanDigest, InitializationResult, PlannedDirectory,
    PlannedWrite, PreservedPath, Result, TemplateAnswerValue, TemplateArtifactKind,
    TemplateArtifactPrecondition, TemplatePackage, TemplateRenderPlan, render_template,
};

const MANIFEST: &str = ".folderbase/manifest.json";
#[cfg(test)]
const FOLDERBASE_ENTRY: &str = "FOLDERBASE.md";
const CODEX_ADAPTER: &str = "AGENTS.md";
const CLAUDE_ADAPTER: &str = "CLAUDE.md";
const MAX_INITIALIZATION_INVENTORY_ENTRIES: usize = 50_000;
const MAX_INITIALIZATION_DEPTH: usize = 64;
const MAX_INITIALIZATION_PATH_BYTES: usize = 4_096;
const MAX_INITIALIZATION_ENCODED_INVENTORY_BYTES: usize = 16 * 1024 * 1024;
const MAX_INITIALIZATION_PATH_COMPONENT_WORK: usize = 2_000_000;
const MAX_INITIALIZATION_DIRECTORY_ENTRY_WORK: usize = 2_000_000;

/// Produce a complete, read-only plan for adopting an existing folder.
pub fn plan_initialization(
    root: impl AsRef<Path>,
    options: InitializationOptions,
) -> Result<InitializationPlan> {
    plan_initialization_with_template(
        root.as_ref(),
        options.clone(),
        None,
        InitializationRequest::Ordinary { options },
        InitializationInventoryBudget::default(),
    )
}

/// Produce a complete, read-only plan for adopting an ordinary folder with a
/// validated, exact-version template package and typed answers.
pub fn plan_template_initialization(
    root: impl AsRef<Path>,
    mut options: InitializationOptions,
    package: &TemplatePackage,
    answers: &BTreeMap<String, TemplateAnswerValue>,
) -> Result<InitializationPlan> {
    let request = InitializationRequest::Template {
        options: options.clone(),
        package: Box::new(package.clone()),
        answers: answers.clone(),
    };
    refuse_symlink_root(root.as_ref())?;
    let root = canonical_directory(root.as_ref())?;
    let mut inventory_budget = InitializationInventoryBudget::default();
    refuse_nested_target(&root, &mut inventory_budget)?;
    let folderbase_name = resolve_folderbase_name(&root, options.name.as_deref())?;
    let mut rendered_answers = answers.clone();
    if package
        .questions()
        .iter()
        .any(|question| question.id() == "folderbase_name")
    {
        match rendered_answers.get("folderbase_name") {
            Some(TemplateAnswerValue::Text(value)) if value == &folderbase_name => {}
            Some(_) => {
                return Err(FolderbaseError::InvalidRecord {
                    path: root,
                    message: "template folderbase_name must match the initialized folderbase name"
                        .to_owned(),
                });
            }
            None => {
                rendered_answers.insert(
                    "folderbase_name".to_owned(),
                    TemplateAnswerValue::Text(folderbase_name.clone()),
                );
            }
        }
    }
    options.name = Some(folderbase_name);
    let rendered = render_template(package, &root, &rendered_answers)?;
    let preconditions = template_preconditions(&root, package, &rendered, &mut inventory_budget)?;
    let package_digest = template_package_sha256(package)?;
    plan_initialization_with_template(
        &root,
        options,
        Some((rendered, preconditions, package_digest)),
        request,
        inventory_budget,
    )
}

fn plan_initialization_with_template(
    root: &Path,
    options: InitializationOptions,
    rendered_template: Option<(
        TemplateRenderPlan,
        Vec<TemplateArtifactPrecondition>,
        String,
    )>,
    request: InitializationRequest,
    mut inventory_budget: InitializationInventoryBudget,
) -> Result<InitializationPlan> {
    let root = canonical_directory(root)?;
    refuse_nested_target(&root, &mut inventory_budget)?;
    if is_provider_controlled(&root) {
        return Err(FolderbaseError::ProviderControlled(root));
    }
    let OpenedRootCapability {
        directory: root_dir,
        identity: root_identity_guard,
        digest_identity: root_identity,
    } = open_root_capability(&root)?;

    let manifest_path = safe_destination(&root, Path::new(MANIFEST))?;
    match fs::symlink_metadata(&manifest_path) {
        Ok(_) => return Err(FolderbaseError::WouldOverwrite(manifest_path)),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {}
        Err(source) => return Err(FolderbaseError::io(manifest_path, source)),
    }

    let folderbase_name = resolve_folderbase_name(&root, options.name.as_deref())?;
    let folderbase_id = format!("folderbase_{}", Uuid::now_v7());
    let created_at = Utc::now().to_rfc3339();

    let mut directories = Vec::new();
    let mut writes = Vec::new();
    let mut template_preconditions = Vec::new();
    let destination_inventory =
        snapshot_destination_inventory(&root_dir, &root, &mut inventory_budget)?;
    let mut preserved_paths = destination_inventory
        .iter()
        .filter(|entry| entry.kind == InitializationDestinationKind::File)
        .map(|entry| PreservedPath {
            path: entry.path.clone(),
        })
        .collect::<Vec<_>>();
    let mut warnings = Vec::new();

    let template_provenance =
        if let Some((rendered, preconditions, package_digest)) = rendered_template {
            template_preconditions = preconditions;
            for path in rendered
                .additions
                .iter()
                .map(|addition| addition.path.as_path())
                .chain(rendered.existing_paths.iter().map(PathBuf::as_path))
            {
                refuse_template_target_inside_nested_folderbase_capability(
                    &root_dir,
                    &root,
                    path,
                    &mut inventory_budget,
                )?;
            }
            for addition in rendered.additions {
                match addition.kind {
                    TemplateArtifactKind::Directory => {
                        let destination = safe_destination(&root, &addition.path)?;
                        match fs::symlink_metadata(&destination) {
                            Ok(_) => return Err(FolderbaseError::WouldOverwrite(destination)),
                            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                                directories.push(PlannedDirectory {
                                    path: addition.path,
                                    purpose: "Template-proposed additive directory".to_owned(),
                                });
                            }
                            Err(source) => return Err(FolderbaseError::io(destination, source)),
                        }
                    }
                    TemplateArtifactKind::Text => {
                        plan_file(
                            &root,
                            &addition.path,
                            "Template-rendered additive file",
                            addition.content.unwrap_or_default(),
                            &mut writes,
                            &mut preserved_paths,
                        )?;
                    }
                }
            }
            Some((
                rendered.template_id,
                rendered.template_version,
                package_digest,
            ))
        } else {
            None
        };

    let adapter_paths = if options.create_agent_adapters {
        vec![
            json!({ "agent": "codex", "path": CODEX_ADAPTER }),
            json!({ "agent": "claude", "path": CLAUDE_ADAPTER }),
        ]
    } else {
        Vec::new()
    };
    let mut folderbase = json!({
            "id": folderbase_id,
            "name": folderbase_name,
            "kind": folderbase_kind_name(options.kind),
            "status": "active",
            "created_at": created_at
    });
    if let Some((id, version, package_digest)) = template_provenance {
        folderbase["template_provenance"] = json!({
            "id": id,
            "version": version,
            "applied_at": created_at,
            "package_digest": {
                "algorithm": "sha256",
                "digest": package_digest
            }
        });
    }
    let manifest = json!({
        "$schema": "https://folderbase.ai/protocol/0.5/folderbase.schema.json",
        "protocol_version": "0.5.0",
        "folderbase": folderbase,
        "adapters": adapter_paths,
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
    let manifest = serde_json::to_string_pretty(&manifest)
        .map(|json| format!("{json}\n"))
        .map_err(|source| FolderbaseError::json(manifest_path.clone(), source))?;
    writes.push(PlannedWrite {
        path: PathBuf::from(MANIFEST),
        purpose: "Machine-readable folderbase root record".to_owned(),
        content: manifest,
    });

    if options.create_agent_adapters {
        plan_agent_adapter_unless_template_owned(
            &root,
            Path::new(CODEX_ADAPTER),
            "Codex bootstrap adapter",
            agent_adapter(),
            &mut writes,
            &mut preserved_paths,
        )?;
        plan_agent_adapter_unless_template_owned(
            &root,
            Path::new(CLAUDE_ADAPTER),
            "Claude bootstrap adapter",
            agent_adapter(),
            &mut writes,
            &mut preserved_paths,
        )?;
    } else {
        warnings.push("Agent adapters were disabled for this initialization.".to_owned());
    }

    let planned_paths = directories
        .iter()
        .map(|directory| directory.path.clone())
        .chain(writes.iter().map(|write| write.path.clone()))
        .collect::<Vec<_>>();
    for path in planned_paths {
        plan_missing_parent_directories(&root, &path, &mut directories)?;
    }
    validate_planned_path_collisions(&root, &directories, &writes)?;
    validate_planned_paths_against_existing(&root, &directories, &writes)?;

    directories.sort_by(|left, right| {
        left.path
            .components()
            .count()
            .cmp(&right.path.components().count())
            .then_with(|| left.path.cmp(&right.path))
    });
    writes.sort_by(|left, right| {
        let left_is_manifest = left.path == Path::new(MANIFEST);
        let right_is_manifest = right.path == Path::new(MANIFEST);
        left_is_manifest
            .cmp(&right_is_manifest)
            .then_with(|| left.path.cmp(&right.path))
    });
    preserved_paths.sort_by(|left, right| left.path.cmp(&right.path));
    warnings.sort();

    let plan_digest = initialization_plan_digest(InitializationDigestInput {
        root: &root,
        root_identity: &root_identity,
        request: &request,
        folderbase_kind: options.kind,
        directories: &directories,
        writes: &writes,
        template_preconditions: &template_preconditions,
        preserved_paths: &preserved_paths,
        warnings: &warnings,
        destination_inventory: &destination_inventory,
    })?;

    Ok(InitializationPlan {
        root,
        folderbase_id,
        folderbase_name,
        folderbase_kind: options.kind,
        directories,
        writes,
        template_preconditions,
        preserved_paths,
        warnings,
        plan_digest,
        root_identity: root_identity_guard,
        destination_inventory,
    })
}

struct InitializationDigestInput<'a> {
    root: &'a Path,
    root_identity: &'a [u8],
    request: &'a InitializationRequest,
    folderbase_kind: FolderbaseKind,
    directories: &'a [PlannedDirectory],
    writes: &'a [PlannedWrite],
    template_preconditions: &'a [TemplateArtifactPrecondition],
    preserved_paths: &'a [PreservedPath],
    warnings: &'a [String],
    destination_inventory: &'a [InitializationDestinationEntry],
}

fn initialization_plan_digest(
    input: InitializationDigestInput<'_>,
) -> Result<InitializationPlanDigest> {
    let mut hasher = Sha256::new();
    digest_bytes(&mut hasher, b"domain", b"folderbase.initialization-plan.v1");
    digest_path(&mut hasher, b"root", input.root);
    digest_bytes(&mut hasher, b"root_identity", input.root_identity);
    digest_text(
        &mut hasher,
        b"resolved_folderbase_kind",
        folderbase_kind_name(input.folderbase_kind),
    );
    digest_request(&mut hasher, input.request)?;

    digest_u64(
        &mut hasher,
        b"directory_count",
        input.directories.len() as u64,
    );
    for directory in input.directories {
        digest_path(&mut hasher, b"directory_path", &directory.path);
        digest_text(
            &mut hasher,
            b"directory_purpose",
            directory.purpose.as_str(),
        );
    }

    digest_u64(&mut hasher, b"write_count", input.writes.len() as u64);
    for write in input.writes {
        digest_path(&mut hasher, b"write_path", &write.path);
        digest_text(&mut hasher, b"write_purpose", write.purpose.as_str());
        if write.path == Path::new(MANIFEST) {
            let mut manifest = serde_json::from_str::<Value>(&write.content)
                .map_err(|source| FolderbaseError::json(input.root.join(MANIFEST), source))?;
            for pointer in [
                "/folderbase/id",
                "/folderbase/created_at",
                "/folderbase/template_provenance/applied_at",
            ] {
                if let Some(value) = manifest.pointer_mut(pointer) {
                    *value = Value::String("<volatile>".to_owned());
                }
            }
            digest_json_value(&mut hasher, b"write_manifest_semantics", &manifest);
        } else {
            digest_bytes(&mut hasher, b"write_content", write.content.as_bytes());
        }
    }

    digest_u64(
        &mut hasher,
        b"template_precondition_count",
        input.template_preconditions.len() as u64,
    );
    for precondition in input.template_preconditions {
        digest_path(
            &mut hasher,
            b"template_precondition_path",
            &precondition.path,
        );
        digest_text(
            &mut hasher,
            b"template_precondition_kind",
            template_artifact_kind_name(precondition.kind),
        );
    }

    digest_u64(
        &mut hasher,
        b"preserved_path_count",
        input.preserved_paths.len() as u64,
    );
    for preserved in input.preserved_paths {
        digest_path(&mut hasher, b"preserved_path", &preserved.path);
    }

    digest_u64(&mut hasher, b"warning_count", input.warnings.len() as u64);
    for warning in input.warnings {
        digest_text(&mut hasher, b"warning", warning);
    }

    digest_u64(
        &mut hasher,
        b"destination_inventory_count",
        input.destination_inventory.len() as u64,
    );
    for entry in input.destination_inventory {
        digest_path(&mut hasher, b"destination_path", &entry.path);
        digest_text(
            &mut hasher,
            b"destination_kind",
            destination_kind_name(entry.kind),
        );
    }

    Ok(InitializationPlanDigest {
        algorithm: "sha256".to_owned(),
        digest: format!("{:x}", hasher.finalize()),
    })
}

fn digest_request(hasher: &mut Sha256, request: &InitializationRequest) -> Result<()> {
    let options = match request {
        InitializationRequest::Ordinary { options } => {
            digest_text(hasher, b"request_type", "ordinary");
            options
        }
        InitializationRequest::Template {
            options,
            package,
            answers,
        } => {
            digest_text(hasher, b"request_type", "template");
            digest_text(hasher, b"template_id", package.id());
            digest_text(hasher, b"template_version", package.version());
            digest_text(
                hasher,
                b"template_package_sha256",
                &template_package_sha256(package)?,
            );
            digest_u64(hasher, b"template_answer_count", answers.len() as u64);
            for (id, answer) in answers {
                digest_text(hasher, b"template_answer_id", id);
                match answer {
                    TemplateAnswerValue::Text(value) => {
                        digest_text(hasher, b"template_answer_type", "text");
                        digest_text(hasher, b"template_answer_value", value);
                    }
                    TemplateAnswerValue::Boolean(value) => {
                        digest_text(hasher, b"template_answer_type", "boolean");
                        digest_text(
                            hasher,
                            b"template_answer_value",
                            if *value { "true" } else { "false" },
                        );
                    }
                }
            }
            options
        }
    };
    match &options.name {
        Some(name) => {
            digest_text(hasher, b"request_name_present", "true");
            digest_text(hasher, b"request_name", name);
        }
        None => digest_text(hasher, b"request_name_present", "false"),
    }
    digest_text(hasher, b"request_kind", folderbase_kind_name(options.kind));
    digest_text(
        hasher,
        b"request_create_agent_adapters",
        if options.create_agent_adapters {
            "true"
        } else {
            "false"
        },
    );
    Ok(())
}

fn digest_json_value(hasher: &mut Sha256, label: &[u8], value: &Value) {
    digest_bytes(hasher, b"json_label", label);
    match value {
        Value::Null => digest_text(hasher, b"json_type", "null"),
        Value::Bool(value) => {
            digest_text(hasher, b"json_type", "boolean");
            digest_text(
                hasher,
                b"json_boolean",
                if *value { "true" } else { "false" },
            );
        }
        Value::Number(value) => {
            digest_text(hasher, b"json_type", "number");
            digest_text(hasher, b"json_number", &value.to_string());
        }
        Value::String(value) => {
            digest_text(hasher, b"json_type", "string");
            digest_text(hasher, b"json_string", value);
        }
        Value::Array(values) => {
            digest_text(hasher, b"json_type", "array");
            digest_u64(hasher, b"json_array_length", values.len() as u64);
            for value in values {
                digest_json_value(hasher, b"json_array_value", value);
            }
        }
        Value::Object(values) => {
            digest_text(hasher, b"json_type", "object");
            digest_u64(hasher, b"json_object_length", values.len() as u64);
            let mut keys = values.keys().collect::<Vec<_>>();
            keys.sort();
            for key in keys {
                digest_text(hasher, b"json_object_key", key);
                digest_json_value(hasher, b"json_object_value", &values[key]);
            }
        }
    }
}

fn digest_path(hasher: &mut Sha256, label: &[u8], path: &Path) {
    digest_bytes(hasher, b"path_label", label);
    digest_os_str(hasher, b"path_value", path.as_os_str());
}

fn digest_os_str(hasher: &mut Sha256, label: &[u8], value: &std::ffi::OsStr) {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        digest_bytes(hasher, label, value.as_bytes());
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        let bytes = value
            .encode_wide()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        digest_bytes(hasher, label, &bytes);
    }
    #[cfg(not(any(unix, windows)))]
    digest_bytes(hasher, label, value.as_encoded_bytes());
}

fn digest_text(hasher: &mut Sha256, label: &[u8], value: &str) {
    digest_bytes(hasher, label, value.as_bytes());
}

fn digest_u64(hasher: &mut Sha256, label: &[u8], value: u64) {
    digest_bytes(hasher, label, &value.to_be_bytes());
}

fn digest_bytes(hasher: &mut Sha256, label: &[u8], value: &[u8]) {
    hasher.update((label.len() as u64).to_be_bytes());
    hasher.update(label);
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

fn template_artifact_kind_name(kind: TemplateArtifactKind) -> &'static str {
    match kind {
        TemplateArtifactKind::Directory => "directory",
        TemplateArtifactKind::Text => "text",
    }
}

fn destination_kind_name(kind: InitializationDestinationKind) -> &'static str {
    match kind {
        InitializationDestinationKind::Directory => "directory",
        InitializationDestinationKind::File => "file",
        InitializationDestinationKind::Symlink => "symlink",
        InitializationDestinationKind::ReconstructableDirectory => "reconstructable_directory",
        InitializationDestinationKind::GitMetadata => "git_metadata",
        InitializationDestinationKind::NestedFolderbase => "nested_folderbase",
        InitializationDestinationKind::Other => "other",
    }
}

fn resolve_folderbase_name(root: &Path, requested: Option<&str>) -> Result<String> {
    let name = requested
        .filter(|name| !name.trim().is_empty())
        .map(str::trim)
        .map(ToOwned::to_owned)
        .or_else(|| {
            root.file_name()
                .and_then(|name| name.to_str())
                .map(str::trim)
                .map(ToOwned::to_owned)
        })
        .unwrap_or_else(|| "Untitled Folderbase".to_owned());
    if name.is_empty()
        || name.chars().count() > 120
        || name
            .chars()
            .any(|character| character.is_control() || matches!(character, '\u{2028}' | '\u{2029}'))
    {
        return Err(FolderbaseError::InvalidRecord {
            path: root.to_path_buf(),
            message: "folderbase name must be nonblank, single-line text of at most 120 characters"
                .to_owned(),
        });
    }
    Ok(name)
}

/// Apply an approved initialization plan without overwriting user-owned files.
///
/// Each file is staged beside its destination and installed with no-clobber
/// semantics. The manifest is installed last, so a failure leaves no active
/// folderbase marker. Completed additive files remain recoverable input for a retry;
/// existing content is never deleted during error handling.
pub fn initialize(plan: &InitializationPlan) -> Result<InitializationResult> {
    let root = canonical_directory(&plan.root)?;
    if root != plan.root {
        return Err(FolderbaseError::PlanRootMismatch {
            planned_root: plan.root.clone(),
            actual_root: root,
        });
    }

    let root_file = fs::File::open(&root).map_err(|source| FolderbaseError::io(&root, source))?;
    let current_identity = PhysicalIdentity::from_file(&root_file)
        .map_err(|source| FolderbaseError::io(&root, source))?;
    if current_identity != plan.root_identity.identity() {
        return Err(FolderbaseError::PlanRootIdentityChanged(root));
    }
    let mut preflight_budget = InitializationInventoryBudget::default();
    refuse_nested_target(&root, &mut preflight_budget)?;
    let root_dir = Dir::from_std_file(root_file);

    verify_template_preconditions(&root_dir, plan, &mut preflight_budget)?;
    validate_planned_paths_against_existing(&plan.root, &plan.directories, &plan.writes)?;
    verify_destinations_absent(&root_dir, plan, &mut preflight_budget)?;
    if snapshot_destination_inventory(&root_dir, &root, &mut preflight_budget)?
        != plan.destination_inventory
    {
        return Err(FolderbaseError::InitializationDestinationChanged(root));
    }

    for directory in &plan.directories {
        create_directory_no_clobber(&root_dir, &plan.root, &directory.path)?;
    }

    let mut created_paths = plan
        .directories
        .iter()
        .map(|directory| directory.path.clone())
        .collect::<Vec<_>>();
    for write in &plan.writes {
        install_text_no_clobber(
            &root_dir,
            &plan.root,
            &write.path,
            write.content.as_bytes(),
            "init",
        )?;
        created_paths.push(write.path.clone());
    }

    Ok(InitializationResult {
        root: plan.root.clone(),
        folderbase_id: plan.folderbase_id.clone(),
        created_paths,
        preserved_paths: plan
            .preserved_paths
            .iter()
            .map(|preserved| preserved.path.clone())
            .collect(),
        applied_plan_digest: plan.plan_digest.clone(),
    })
}

/// Apply the exact read-only Core plan only when its digest is the one the
/// caller approved.
pub fn initialize_with_expected_plan_digest(
    plan: &InitializationPlan,
    expected: &InitializationPlanDigest,
) -> Result<InitializationResult> {
    expected.validate()?;
    if plan.plan_digest != *expected {
        return Err(FolderbaseError::InitializationPlanChanged {
            expected: expected.digest.clone(),
            actual: plan.plan_digest.digest.clone(),
        });
    }
    initialize(plan)
}

pub(crate) fn create_directory_no_clobber(root_dir: &Dir, root: &Path, path: &Path) -> Result<()> {
    ensure_safe_relative(path)?;
    let (parent, name) = open_parent_dir_nofollow(root_dir, root, path)?;
    let builder = cap_std::fs::DirBuilder::new();
    #[cfg(unix)]
    let builder = {
        use cap_std::fs::DirBuilderExt;

        let mut builder = builder;
        if path.starts_with(".folderbase") {
            builder.mode(0o700);
        }
        builder
    };
    if let Err(source) = parent.create_dir_with(&name, &builder) {
        return Err(if source.kind() == std::io::ErrorKind::AlreadyExists {
            FolderbaseError::WouldOverwrite(root.join(path))
        } else {
            FolderbaseError::io(root.join(path), source)
        });
    }
    Ok(())
}

pub(crate) fn install_text_no_clobber(
    root_dir: &Dir,
    root: &Path,
    path: &Path,
    content: &[u8],
    staging_label: &str,
) -> Result<()> {
    ensure_safe_relative(path)?;
    let (destination_parent, destination_name) = open_parent_dir_nofollow(root_dir, root, path)?;

    let staged_path = PathBuf::from(format!(
        ".folderbase/.{staging_label}-{}.tmp",
        Uuid::now_v7()
    ));
    let (staging_parent, staging_name) = open_parent_dir_nofollow(root_dir, root, &staged_path)?;
    let mut options = OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .follow(FollowSymlinks::No);
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt;

        if path.starts_with(".folderbase") {
            options.mode(0o600);
        }
    }
    let mut staged = staging_parent
        .open_with(&staging_name, &options)
        .map_err(|source| FolderbaseError::io(root.join(&staged_path), source))?;
    if let Err(source) = staged.write_all(content).and_then(|()| staged.sync_all()) {
        drop(staged);
        let _ = staging_parent.remove_file(&staging_name);
        return Err(FolderbaseError::io(root.join(&staged_path), source));
    }
    drop(staged);

    if let Err(source) =
        staging_parent.hard_link(&staging_name, &destination_parent, &destination_name)
    {
        let _ = staging_parent.remove_file(&staging_name);
        return Err(if source.kind() == std::io::ErrorKind::AlreadyExists {
            FolderbaseError::WouldOverwrite(root.join(path))
        } else {
            FolderbaseError::io(root.join(path), source)
        });
    }
    let _ = staging_parent.remove_file(&staging_name);
    Ok(())
}

fn open_parent_dir_nofollow(
    root_dir: &Dir,
    root: &Path,
    path: &Path,
) -> Result<(Dir, std::ffi::OsString)> {
    ensure_safe_relative(path)?;
    let name = path
        .file_name()
        .ok_or_else(|| FolderbaseError::UnsafePath(path.to_path_buf()))?
        .to_os_string();
    let mut current = root_dir
        .try_clone()
        .map_err(|source| FolderbaseError::io(root, source))?;
    if let Some(parent) = path.parent() {
        let mut traversed = PathBuf::new();
        for component in parent.components() {
            let Component::Normal(component) = component else {
                return Err(FolderbaseError::UnsafePath(path.to_path_buf()));
            };
            traversed.push(component);
            current = current
                .open_dir_nofollow(component)
                .map_err(|source| FolderbaseError::io(root.join(&traversed), source))?;
        }
    }
    Ok((current, name))
}

pub(crate) fn canonical_directory(path: &Path) -> Result<PathBuf> {
    if !path.is_dir() {
        return Err(FolderbaseError::InvalidRoot(path.to_path_buf()));
    }
    path.canonicalize()
        .map_err(|source| FolderbaseError::io(path, source))
}

pub(crate) fn refuse_symlink_root(root: &Path) -> Result<()> {
    let metadata =
        fs::symlink_metadata(root).map_err(|source| FolderbaseError::io(root, source))?;
    if metadata.file_type().is_symlink() {
        return Err(FolderbaseError::InvalidRecord {
            path: root.to_path_buf(),
            message: "template adoption destination root is a symlink".to_owned(),
        });
    }
    if !metadata.is_dir() {
        return Err(FolderbaseError::InvalidRoot(root.to_path_buf()));
    }
    Ok(())
}

fn template_preconditions(
    root: &Path,
    package: &TemplatePackage,
    rendered: &TemplateRenderPlan,
    boundary_budget: &mut InitializationInventoryBudget,
) -> Result<Vec<TemplateArtifactPrecondition>> {
    let root_dir = open_root_capability(root)?.directory;
    let mut preconditions = Vec::new();
    for path in &rendered.existing_paths {
        let artifact = package
            .artifacts
            .iter()
            .find(|artifact| artifact.target == *path)
            .ok_or_else(|| FolderbaseError::InvalidRecord {
                path: path.clone(),
                message: "rendered existing target is not declared by its template".to_owned(),
            })?;
        let destination = safe_destination(root, path)?;
        let metadata = root_dir
            .symlink_metadata(path)
            .map_err(|source| FolderbaseError::io(&destination, source))?;
        let expected_type = match artifact.kind {
            TemplateArtifactKind::Directory => metadata.is_dir(),
            TemplateArtifactKind::Text => metadata.is_file(),
        };
        if metadata.file_type().is_symlink() || !expected_type {
            return Err(FolderbaseError::InvalidRecord {
                path: destination,
                message: format!(
                    "existing template target has the wrong type; expected {:?}",
                    artifact.kind
                ),
            });
        }
        let identity = match artifact.kind {
            TemplateArtifactKind::Directory => {
                let directory = root_dir
                    .open_dir_nofollow(path)
                    .map_err(|source| FolderbaseError::io(&destination, source))?;
                if has_nested_folderbase_marker_capability(
                    &directory,
                    destination.clone(),
                    boundary_budget,
                )? {
                    return Err(FolderbaseError::InvalidRecord {
                        path: destination,
                        message: "existing template directory is already a nested folderbase"
                            .to_owned(),
                    });
                }
                RetainedPhysicalIdentity::from_file(
                    directory
                        .try_clone()
                        .map_err(|source| FolderbaseError::io(&destination, source))?
                        .into_std_file(),
                )
                .map_err(|source| FolderbaseError::io(&destination, source))?
            }
            TemplateArtifactKind::Text => {
                let mut options = OpenOptions::new();
                options.read(true).follow(FollowSymlinks::No);
                let file = root_dir
                    .open_with(path, &options)
                    .map_err(|source| FolderbaseError::io(&destination, source))?;
                RetainedPhysicalIdentity::from_file(file.into_std())
                    .map_err(|source| FolderbaseError::io(&destination, source))?
            }
        };
        preconditions.push(TemplateArtifactPrecondition {
            path: path.clone(),
            kind: artifact.kind,
            identity,
        });
    }
    preconditions.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(preconditions)
}

fn verify_template_preconditions(
    root_dir: &Dir,
    plan: &InitializationPlan,
    boundary_budget: &mut InitializationInventoryBudget,
) -> Result<()> {
    for precondition in &plan.template_preconditions {
        let changed = || FolderbaseError::PlanPreconditionChanged(precondition.path.clone());
        ensure_safe_relative(&precondition.path).map_err(|_| changed())?;
        let destination =
            safe_destination(&plan.root, &precondition.path).map_err(|_| changed())?;
        let metadata = root_dir
            .symlink_metadata(&precondition.path)
            .map_err(|_| changed())?;
        let expected_type = match precondition.kind {
            TemplateArtifactKind::Directory => metadata.is_dir(),
            TemplateArtifactKind::Text => metadata.is_file(),
        };
        if metadata.file_type().is_symlink() || !expected_type {
            return Err(changed());
        }
        let current_identity = match precondition.kind {
            TemplateArtifactKind::Directory => {
                let directory = root_dir
                    .open_dir_nofollow(&precondition.path)
                    .map_err(|_| changed())?;
                let is_nested = match has_nested_folderbase_marker_capability(
                    &directory,
                    destination.clone(),
                    boundary_budget,
                ) {
                    Ok(is_nested) => is_nested,
                    Err(error @ FolderbaseError::InitializationInventoryLimitExceeded { .. }) => {
                        return Err(error);
                    }
                    Err(_) => return Err(changed()),
                };
                if is_nested {
                    return Err(changed());
                }
                let file = directory
                    .try_clone()
                    .map_err(|_| changed())?
                    .into_std_file();
                PhysicalIdentity::from_file(&file).map_err(|_| changed())?
            }
            TemplateArtifactKind::Text => {
                let mut options = OpenOptions::new();
                options.read(true).follow(FollowSymlinks::No);
                let file = root_dir
                    .open_with(&precondition.path, &options)
                    .map_err(|_| changed())?;
                PhysicalIdentity::from_file(&file.into_std()).map_err(|_| changed())?
            }
        };
        if current_identity != precondition.identity.identity() {
            return Err(changed());
        }
    }
    Ok(())
}

fn refuse_nested_target(root: &Path, budget: &mut InitializationInventoryBudget) -> Result<()> {
    for ancestor in root.ancestors().skip(1) {
        let metadata = fs::symlink_metadata(ancestor)
            .map_err(|source| FolderbaseError::io(ancestor, source))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            continue;
        }
        let directory = open_root_capability(ancestor)?.directory;
        if has_nested_folderbase_marker_capability(&directory, ancestor.to_path_buf(), budget)? {
            return Err(FolderbaseError::InvalidRecord {
                path: root.to_path_buf(),
                message: format!(
                    "initialization target is nested inside another folderbase at {}",
                    ancestor.display()
                ),
            });
        }
    }
    Ok(())
}

pub(crate) fn refuse_template_target_inside_nested_folderbase(
    root: &Path,
    target: &Path,
) -> Result<()> {
    let root_dir = open_root_capability(root)?.directory;
    let mut budget = InitializationInventoryBudget::default();
    refuse_template_target_inside_nested_folderbase_capability(&root_dir, root, target, &mut budget)
}

fn refuse_template_target_inside_nested_folderbase_capability(
    root_dir: &Dir,
    root: &Path,
    target: &Path,
    budget: &mut InitializationInventoryBudget,
) -> Result<()> {
    ensure_safe_relative(target)?;
    let mut current_dir = root_dir
        .try_clone()
        .map_err(|source| FolderbaseError::io(root, source))?;
    let mut current_path = root.to_path_buf();
    if let Some(parent) = target.parent() {
        for component in parent.components() {
            let Component::Normal(component) = component else {
                return Err(FolderbaseError::UnsafePath(target.to_path_buf()));
            };
            current_path.push(component);
            let metadata = match current_dir.symlink_metadata(component) {
                Ok(metadata) => metadata,
                Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(()),
                Err(source) => return Err(FolderbaseError::io(&current_path, source)),
            };
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(FolderbaseError::UnsafePath(current_path));
            }
            current_dir = current_dir
                .open_dir_nofollow(component)
                .map_err(|source| FolderbaseError::io(&current_path, source))?;
            if has_nested_folderbase_marker_capability(&current_dir, current_path.clone(), budget)?
            {
                return Err(FolderbaseError::InvalidRecord {
                    path: target.to_path_buf(),
                    message: format!(
                        "template target is inside nested folderbase at {}",
                        current_path.display()
                    ),
                });
            }
        }
    }
    Ok(())
}

struct OpenedRootCapability {
    directory: Dir,
    identity: RetainedPhysicalIdentity,
    digest_identity: Vec<u8>,
}

fn open_root_capability(root: &Path) -> Result<OpenedRootCapability> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        options.custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE,
            FILE_SHARE_READ, FILE_SHARE_WRITE,
        };

        options
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE);
    }
    let file = options
        .open(root)
        .map_err(|source| FolderbaseError::io(root, source))?;
    let metadata = file
        .metadata()
        .map_err(|source| FolderbaseError::io(root, source))?;
    if metadata_is_link_or_reparse(&metadata) || !metadata.is_dir() {
        return Err(FolderbaseError::InvalidRoot(root.to_path_buf()));
    }
    let digest_identity = root_digest_identity(&file, &metadata, root)?;
    let identity = RetainedPhysicalIdentity::from_file(
        file.try_clone()
            .map_err(|source| FolderbaseError::io(root, source))?,
    )
    .map_err(|source| FolderbaseError::io(root, source))?;
    Ok(OpenedRootCapability {
        directory: Dir::from_std_file(file),
        identity,
        digest_identity,
    })
}

#[cfg(unix)]
fn root_digest_identity(
    _file: &fs::File,
    metadata: &fs::Metadata,
    _root: &Path,
) -> Result<Vec<u8>> {
    use std::os::unix::fs::MetadataExt;

    let mut identity = Vec::with_capacity(16);
    identity.extend_from_slice(&metadata.dev().to_be_bytes());
    identity.extend_from_slice(&metadata.ino().to_be_bytes());
    Ok(identity)
}

#[cfg(windows)]
fn root_digest_identity(file: &fs::File, _metadata: &fs::Metadata, root: &Path) -> Result<Vec<u8>> {
    let information =
        winapi_util::file::information(file).map_err(|source| FolderbaseError::io(root, source))?;
    let mut identity = Vec::with_capacity(12);
    identity.extend_from_slice(&(information.volume_serial_number() as u32).to_be_bytes());
    identity.extend_from_slice(&information.file_index().to_be_bytes());
    Ok(identity)
}

#[cfg(not(any(unix, windows)))]
fn root_digest_identity(
    _file: &fs::File,
    _metadata: &fs::Metadata,
    root: &Path,
) -> Result<Vec<u8>> {
    Err(FolderbaseError::InvalidRecord {
        path: root.to_path_buf(),
        message: "filesystem does not expose a supported stable root identity".to_owned(),
    })
}

struct InitializationInventoryBudget {
    entries: usize,
    encoded_bytes: usize,
    path_component_work: usize,
    directory_entry_work: usize,
}

impl Default for InitializationInventoryBudget {
    fn default() -> Self {
        Self {
            entries: 0,
            encoded_bytes: digest_frame_len(b"destination_inventory_count", 8),
            path_component_work: 0,
            directory_entry_work: 0,
        }
    }
}

impl InitializationInventoryBudget {
    fn record_path(&mut self, path: &Path, depth: usize) -> Result<()> {
        if depth > MAX_INITIALIZATION_DEPTH {
            return Err(inventory_limit(
                InitializationInventoryLimitKind::Depth,
                MAX_INITIALIZATION_DEPTH as u64,
            ));
        }
        let path_bytes = digest_os_str_len(path.as_os_str());
        if path_bytes > MAX_INITIALIZATION_PATH_BYTES {
            return Err(inventory_limit(
                InitializationInventoryLimitKind::PathBytes,
                MAX_INITIALIZATION_PATH_BYTES as u64,
            ));
        }
        self.entries = self.entries.saturating_add(1);
        if self.entries > MAX_INITIALIZATION_INVENTORY_ENTRIES {
            return Err(inventory_limit(
                InitializationInventoryLimitKind::Entries,
                MAX_INITIALIZATION_INVENTORY_ENTRIES as u64,
            ));
        }
        self.encoded_bytes = self
            .encoded_bytes
            .saturating_add(digest_frame_len(b"path_label", b"destination_path".len()))
            .saturating_add(digest_frame_len(b"path_value", path_bytes));
        if self.encoded_bytes > MAX_INITIALIZATION_ENCODED_INVENTORY_BYTES {
            return Err(inventory_limit(
                InitializationInventoryLimitKind::EncodedInventoryBytes,
                MAX_INITIALIZATION_ENCODED_INVENTORY_BYTES as u64,
            ));
        }
        self.path_component_work = self.path_component_work.saturating_add(depth);
        if self.path_component_work > MAX_INITIALIZATION_PATH_COMPONENT_WORK {
            return Err(inventory_limit(
                InitializationInventoryLimitKind::PathComponentWork,
                MAX_INITIALIZATION_PATH_COMPONENT_WORK as u64,
            ));
        }
        Ok(())
    }

    fn record_kind(&mut self, kind: InitializationDestinationKind) -> Result<()> {
        self.encoded_bytes = self.encoded_bytes.saturating_add(digest_frame_len(
            b"destination_kind",
            destination_kind_name(kind).len(),
        ));
        if self.encoded_bytes > MAX_INITIALIZATION_ENCODED_INVENTORY_BYTES {
            return Err(inventory_limit(
                InitializationInventoryLimitKind::EncodedInventoryBytes,
                MAX_INITIALIZATION_ENCODED_INVENTORY_BYTES as u64,
            ));
        }
        Ok(())
    }

    fn observe_directory_entry(&mut self) -> Result<()> {
        self.directory_entry_work = self.directory_entry_work.saturating_add(1);
        if self.directory_entry_work > MAX_INITIALIZATION_DIRECTORY_ENTRY_WORK {
            return Err(inventory_limit(
                InitializationInventoryLimitKind::DirectoryEntryWork,
                MAX_INITIALIZATION_DIRECTORY_ENTRY_WORK as u64,
            ));
        }
        Ok(())
    }
}

fn digest_frame_len(label: &[u8], value_len: usize) -> usize {
    16usize
        .saturating_add(label.len())
        .saturating_add(value_len)
}

fn digest_os_str_len(value: &OsStr) -> usize {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        value.as_bytes().len()
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        value.encode_wide().count().saturating_mul(2)
    }
    #[cfg(not(any(unix, windows)))]
    value.as_encoded_bytes().len()
}

fn inventory_limit(limit: InitializationInventoryLimitKind, maximum: u64) -> FolderbaseError {
    FolderbaseError::InitializationInventoryLimitExceeded { limit, maximum }
}

fn snapshot_destination_inventory(
    root_dir: &Dir,
    root: &Path,
    budget: &mut InitializationInventoryBudget,
) -> Result<Vec<InitializationDestinationEntry>> {
    fn visit(
        root: &Path,
        current_dir: &Dir,
        relative_parent: &Path,
        depth: usize,
        budget: &mut InitializationInventoryBudget,
        inventory: &mut Vec<InitializationDestinationEntry>,
    ) -> Result<()> {
        let entries = current_dir
            .read_dir(".")
            .map_err(|source| FolderbaseError::io(root.join(relative_parent), source))?;
        let mut names = Vec::new();
        for entry in entries {
            let entry =
                entry.map_err(|source| FolderbaseError::io(root.join(relative_parent), source))?;
            budget.observe_directory_entry()?;
            let name = entry.file_name();
            let relative = relative_parent.join(&name);
            budget.record_path(&relative, depth)?;
            names.push(name);
        }
        names.sort();

        for name in names {
            let relative = relative_parent.join(&name);
            let metadata = current_dir
                .symlink_metadata(&name)
                .map_err(|source| FolderbaseError::io(root.join(&relative), source))?;
            let kind = if metadata.file_type().is_symlink() {
                InitializationDestinationKind::Symlink
            } else if metadata.is_dir() {
                if is_git_metadata_component(&name) {
                    InitializationDestinationKind::GitMetadata
                } else if is_reconstructable_directory(&name) {
                    InitializationDestinationKind::ReconstructableDirectory
                } else {
                    let child = current_dir
                        .open_dir_nofollow(&name)
                        .map_err(|source| FolderbaseError::io(root.join(&relative), source))?;
                    if has_nested_folderbase_marker_capability(
                        &child,
                        root.join(&relative),
                        budget,
                    )? {
                        InitializationDestinationKind::NestedFolderbase
                    } else {
                        budget.record_kind(InitializationDestinationKind::Directory)?;
                        inventory.push(InitializationDestinationEntry {
                            path: relative.clone(),
                            kind: InitializationDestinationKind::Directory,
                        });
                        visit(root, &child, &relative, depth + 1, budget, inventory)?;
                        continue;
                    }
                }
            } else if metadata.is_file() {
                InitializationDestinationKind::File
            } else {
                InitializationDestinationKind::Other
            };
            budget.record_kind(kind)?;
            inventory.push(InitializationDestinationEntry {
                path: relative,
                kind,
            });
        }
        Ok(())
    }

    let mut inventory = Vec::new();
    visit(root, root_dir, Path::new(""), 1, budget, &mut inventory)?;
    inventory.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(inventory)
}

fn has_nested_folderbase_marker_capability(
    directory: &Dir,
    display_path: PathBuf,
    budget: &mut InitializationInventoryBudget,
) -> Result<bool> {
    match classify_nested_folderbase_boundary_with_observer(directory, &display_path, || {
        budget.observe_directory_entry()
    })? {
        NestedFolderbaseBoundaryKind::ExactBoundary => Ok(true),
        NestedFolderbaseBoundaryKind::None => Ok(false),
        NestedFolderbaseBoundaryKind::UnsafeAliasShape => {
            Err(FolderbaseError::UnsafePath(display_path))
        }
    }
}

fn plan_missing_parent_directories(
    root: &Path,
    relative_path: &Path,
    directories: &mut Vec<PlannedDirectory>,
) -> Result<()> {
    ensure_safe_relative(relative_path)?;
    let mut current = root.to_path_buf();
    let Some(parent) = relative_path.parent() else {
        return Ok(());
    };
    let mut relative = PathBuf::new();
    for component in parent.components() {
        let Component::Normal(component) = component else {
            return Err(FolderbaseError::UnsafePath(relative_path.to_path_buf()));
        };
        current.push(component);
        relative.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(FolderbaseError::UnsafePath(current));
            }
            Ok(metadata) if !metadata.is_dir() => {
                return Err(FolderbaseError::WouldOverwrite(current));
            }
            Ok(_) => {}
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                if !directories
                    .iter()
                    .any(|directory| directory.path == relative)
                {
                    directories.push(PlannedDirectory {
                        path: relative.clone(),
                        purpose: "Parent directory for an additive protocol file".to_owned(),
                    });
                }
            }
            Err(source) => return Err(FolderbaseError::io(current, source)),
        }
    }
    Ok(())
}

fn validate_planned_path_collisions(
    root: &Path,
    directories: &[PlannedDirectory],
    writes: &[PlannedWrite],
) -> Result<()> {
    validate_template_path_collisions(
        root,
        directories
            .iter()
            .map(|directory| (directory.path.as_path(), true))
            .chain(writes.iter().map(|write| (write.path.as_path(), false))),
    )
}

pub(crate) fn validate_template_path_collisions<'a>(
    root: &Path,
    planned_paths: impl IntoIterator<Item = (&'a Path, bool)>,
) -> Result<()> {
    let mut planned = planned_paths
        .into_iter()
        .map(|(path, is_directory)| {
            let text = path
                .to_str()
                .ok_or_else(|| FolderbaseError::UnsafePath(path.to_path_buf()))?;
            Ok((path, text.case_fold().collect::<String>(), is_directory))
        })
        .collect::<Result<Vec<_>>>()?;
    planned.sort_by(|left, right| left.1.cmp(&right.1));

    let mut seen = BTreeMap::<String, (&Path, bool)>::new();
    for (path, folded, is_directory) in planned {
        if let Some((existing, _)) = seen.get(&folded) {
            return planned_collision(root, existing, path);
        }
        for (index, character) in folded.char_indices() {
            if character != '/' {
                continue;
            }
            if let Some((ancestor, ancestor_is_directory)) = seen.get(&folded[..index])
                && !ancestor_is_directory
            {
                return planned_collision(root, ancestor, path);
            }
        }
        seen.insert(folded, (path, is_directory));
    }
    Ok(())
}

fn validate_planned_paths_against_existing(
    root: &Path,
    directories: &[PlannedDirectory],
    writes: &[PlannedWrite],
) -> Result<()> {
    validate_template_paths_against_existing_casefold(
        root,
        directories
            .iter()
            .map(|directory| directory.path.as_path())
            .chain(writes.iter().map(|write| write.path.as_path())),
        false,
    )
}

pub(crate) fn validate_template_paths_against_existing_casefold<'a>(
    root: &Path,
    planned_paths: impl IntoIterator<Item = &'a Path>,
    allow_exact_target: bool,
) -> Result<()> {
    for planned in planned_paths {
        let mut parent = root.to_path_buf();
        let component_count = planned.components().count();
        for (index, component) in planned.components().enumerate() {
            let Component::Normal(component) = component else {
                return Err(FolderbaseError::UnsafePath(planned.to_path_buf()));
            };
            let component_text = component
                .to_str()
                .ok_or_else(|| FolderbaseError::UnsafePath(planned.to_path_buf()))?;
            let folded_component = component_text.case_fold().collect::<String>();
            let mut exact = None;
            for entry in
                fs::read_dir(&parent).map_err(|source| FolderbaseError::io(&parent, source))?
            {
                let entry = entry.map_err(|source| FolderbaseError::io(&parent, source))?;
                let name = entry.file_name();
                let Some(name_text) = name.to_str() else {
                    // Planned protocol/template components are UTF-8. An
                    // unrelated non-UTF-8 sibling cannot be their case-folded
                    // alias and remains preserved as ordinary user content.
                    continue;
                };
                if name_text.case_fold().collect::<String>() != folded_component {
                    continue;
                }
                if name == component {
                    exact = Some(entry);
                } else {
                    return Err(FolderbaseError::InvalidRecord {
                        path: root.to_path_buf(),
                        message: format!(
                            "planned path collision: {} aliases existing {}",
                            planned.display(),
                            entry.path().display()
                        ),
                    });
                }
            }

            let Some(entry) = exact else {
                break;
            };
            if index + 1 == component_count {
                if allow_exact_target {
                    break;
                }
                return Err(FolderbaseError::WouldOverwrite(entry.path()));
            }
            let file_type = entry
                .file_type()
                .map_err(|source| FolderbaseError::io(entry.path(), source))?;
            if file_type.is_symlink() || !file_type.is_dir() {
                return Err(FolderbaseError::InvalidRecord {
                    path: root.to_path_buf(),
                    message: format!(
                        "planned path collision: ancestor {} is not a safe directory",
                        entry.path().display()
                    ),
                });
            }
            parent = entry.path();
        }
    }
    Ok(())
}

fn planned_collision(root: &Path, left: &Path, right: &Path) -> Result<()> {
    Err(FolderbaseError::InvalidRecord {
        path: root.to_path_buf(),
        message: format!(
            "template/core planned path collision: {} and {}",
            left.display(),
            right.display()
        ),
    })
}

fn is_provider_controlled(root: &Path) -> bool {
    root.components().any(|component| {
        let Component::Normal(value) = component else {
            return false;
        };
        matches!(
            value.to_str(),
            Some("Mobile Documents" | "CloudStorage" | "File Provider Storage")
        )
    })
}

pub(crate) fn ensure_safe_relative(path: &Path) -> Result<()> {
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

pub(crate) fn safe_destination(root: &Path, relative_path: &Path) -> Result<PathBuf> {
    ensure_safe_relative(relative_path)?;
    let mut current = root.to_path_buf();
    if let Some(parent) = relative_path.parent() {
        for component in parent.components() {
            let Component::Normal(component) = component else {
                return Err(FolderbaseError::UnsafePath(relative_path.to_path_buf()));
            };
            current.push(component);
            match fs::symlink_metadata(&current) {
                Ok(metadata) if metadata.file_type().is_symlink() => {
                    return Err(FolderbaseError::UnsafePath(current));
                }
                Ok(metadata) if !metadata.is_dir() => {
                    return Err(FolderbaseError::WouldOverwrite(current));
                }
                Ok(_) => {}
                Err(source) if source.kind() == std::io::ErrorKind::NotFound => {}
                Err(source) => return Err(FolderbaseError::io(current, source)),
            }
        }
    }
    Ok(root.join(relative_path))
}

fn plan_agent_adapter_unless_template_owned(
    root: &Path,
    relative_path: &Path,
    purpose: &str,
    content: String,
    writes: &mut Vec<PlannedWrite>,
    preserved_paths: &mut Vec<PreservedPath>,
) -> Result<()> {
    if writes.iter().any(|write| write.path == relative_path) {
        return Ok(());
    }
    plan_file(
        root,
        relative_path,
        purpose,
        content,
        writes,
        preserved_paths,
    )
}

fn plan_file(
    root: &Path,
    relative_path: &Path,
    purpose: &str,
    content: String,
    writes: &mut Vec<PlannedWrite>,
    preserved_paths: &mut Vec<PreservedPath>,
) -> Result<()> {
    let destination = safe_destination(root, relative_path)?;
    match fs::symlink_metadata(&destination) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(FolderbaseError::UnsafePath(destination));
        }
        Ok(metadata) if metadata.is_file() => {
            if !preserved_paths
                .iter()
                .any(|preserved| preserved.path == relative_path)
            {
                preserved_paths.push(PreservedPath {
                    path: relative_path.to_path_buf(),
                });
            }
        }
        Ok(_) => return Err(FolderbaseError::WouldOverwrite(destination)),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
            writes.push(PlannedWrite {
                path: relative_path.to_path_buf(),
                purpose: purpose.to_owned(),
                content,
            });
        }
        Err(source) => return Err(FolderbaseError::io(destination, source)),
    }
    Ok(())
}

fn verify_destinations_absent(
    root_dir: &Dir,
    plan: &InitializationPlan,
    budget: &mut InitializationInventoryBudget,
) -> Result<()> {
    for path in plan
        .directories
        .iter()
        .map(|directory| &directory.path)
        .chain(plan.writes.iter().map(|write| &write.path))
    {
        ensure_safe_relative(path)?;
        safe_destination(&plan.root, path)?;
        refuse_template_target_inside_nested_folderbase_capability(
            root_dir, &plan.root, path, budget,
        )?;
        match root_dir.symlink_metadata(path) {
            Ok(_) => return Err(FolderbaseError::WouldOverwrite(plan.root.join(path))),
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => return Err(FolderbaseError::io(plan.root.join(path), source)),
        }
    }
    Ok(())
}

pub(crate) fn sha256_path(path: &Path) -> Result<String> {
    let mut file = fs::File::open(path).map_err(|source| FolderbaseError::io(path, source))?;
    sha256_reader(&mut file).map_err(|source| FolderbaseError::io(path, source))
}

pub(crate) fn sha256_reader(reader: &mut impl Read) -> std::io::Result<String> {
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn folderbase_kind_name(kind: FolderbaseKind) -> &'static str {
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

fn agent_adapter() -> String {
    "<!-- folderbase:begin -->\n\
     # Folderbase\n\n\
     Confirm this root through `.folderbase/manifest.json`, then work with its ordinary \
     files using Folderbase Core context and boundary rules. Treat summaries and questions \
     as optional hints, never as mutation or sharing authority.\n\
     <!-- folderbase:end -->\n"
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn planning_is_read_only_and_initialize_creates_a_folderbase() {
        let temp = tempfile::tempdir().unwrap();

        let plan = plan_initialization(temp.path(), InitializationOptions::default()).unwrap();
        assert!(!temp.path().join(FOLDERBASE_ENTRY).exists());
        assert!(!temp.path().join(MANIFEST).exists());

        let result = initialize(&plan).unwrap();
        assert_eq!(result.folderbase_id, plan.folderbase_id);
        assert!(temp.path().join(MANIFEST).exists());
        assert!(!temp.path().join(CODEX_ADAPTER).exists());
        assert!(!temp.path().join(CLAUDE_ADAPTER).exists());
    }

    #[test]
    fn existing_entry_and_adapters_are_preserved() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join(FOLDERBASE_ENTRY), "# Existing\n").unwrap();
        fs::write(temp.path().join(CODEX_ADAPTER), "user owned\n").unwrap();

        let plan = plan_initialization(temp.path(), InitializationOptions::default()).unwrap();
        assert!(
            plan.preserved_paths
                .iter()
                .any(|preserved| preserved.path == Path::new(FOLDERBASE_ENTRY))
        );
        assert!(
            plan.preserved_paths
                .iter()
                .any(|preserved| preserved.path == Path::new(CODEX_ADAPTER))
        );

        initialize(&plan).unwrap();
        assert_eq!(
            fs::read_to_string(temp.path().join(FOLDERBASE_ENTRY)).unwrap(),
            "# Existing\n"
        );
        assert_eq!(
            fs::read_to_string(temp.path().join(CODEX_ADAPTER)).unwrap(),
            "user owned\n"
        );
    }

    #[test]
    fn applying_a_stale_plan_never_overwrites() {
        let temp = tempfile::tempdir().unwrap();
        let plan = plan_initialization(temp.path(), InitializationOptions::default()).unwrap();
        fs::write(temp.path().join(FOLDERBASE_ENTRY), "# Arrived later\n").unwrap();

        let error = initialize(&plan).unwrap_err();
        assert!(matches!(
            error,
            FolderbaseError::InitializationDestinationChanged(_)
        ));
        assert_eq!(
            fs::read_to_string(temp.path().join(FOLDERBASE_ENTRY)).unwrap(),
            "# Arrived later\n"
        );
        assert!(!temp.path().join(MANIFEST).exists());
    }

    #[test]
    fn deleting_a_preserved_entry_invalidates_the_plan_before_writes() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join(FOLDERBASE_ENTRY), "# Existing\n").unwrap();
        let plan = plan_initialization(temp.path(), InitializationOptions::default()).unwrap();
        fs::remove_file(temp.path().join(FOLDERBASE_ENTRY)).unwrap();

        let error = initialize(&plan).unwrap_err();
        assert!(matches!(
            error,
            FolderbaseError::InitializationDestinationChanged(_)
        ));
        assert!(!temp.path().join(MANIFEST).exists());
        assert!(!temp.path().join(CODEX_ADAPTER).exists());
    }

    #[cfg(unix)]
    #[test]
    fn dangling_symlink_from_a_stale_plan_is_never_removed() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let plan = plan_initialization(temp.path(), InitializationOptions::default()).unwrap();
        let entry = temp.path().join(FOLDERBASE_ENTRY);
        symlink("missing-user-target.md", &entry).unwrap();

        let error = initialize(&plan).unwrap_err();
        assert!(matches!(
            error,
            FolderbaseError::InitializationDestinationChanged(_)
        ));
        assert!(
            fs::symlink_metadata(&entry)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert!(!temp.path().join(MANIFEST).exists());
    }

    #[test]
    fn provider_controlled_folder_is_refused() {
        let temp = tempfile::tempdir().unwrap();
        let provider_root = temp.path().join("CloudStorage/project");
        fs::create_dir_all(&provider_root).unwrap();

        let error =
            plan_initialization(&provider_root, InitializationOptions::default()).unwrap_err();
        assert!(matches!(error, FolderbaseError::ProviderControlled(_)));
        assert!(!provider_root.join(MANIFEST).exists());
    }

    #[cfg(unix)]
    #[test]
    fn template_parent_probe_never_follows_a_symlink_outside_the_root() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        symlink(outside.path(), root.path().join("Nested")).unwrap();

        let error = refuse_template_target_inside_nested_folderbase(
            root.path(),
            Path::new("Nested/file.md"),
        )
        .expect_err("a template parent symlink must fail closed");

        assert!(matches!(error, FolderbaseError::UnsafePath(_)));
        assert!(fs::read_dir(outside.path()).unwrap().next().is_none());
    }
}

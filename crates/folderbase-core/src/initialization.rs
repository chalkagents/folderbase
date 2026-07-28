use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    path::{Component, Path, PathBuf},
};

use cap_std::fs::{Dir, OpenOptions};
use chrono::Utc;
use same_file::Handle;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use unicode_casefold::UnicodeCaseFold;
use uuid::Uuid;

use crate::model::{
    InitializationDestinationEntry, InitializationDestinationKind, InitializationRequest,
};
use crate::template::template_package_sha256;
use crate::workspace::has_nested_folderbase_marker;
use crate::{
    FolderbaseError, FolderbaseKind, InitializationOptions, InitializationPlan,
    InitializationPlanDigest, InitializationResult, PlannedDirectory, PlannedWrite, PreservedPath,
    Result, TemplateAnswerValue, TemplateArtifactKind, TemplateArtifactPrecondition,
    TemplatePackage, TemplateRenderPlan, render_template,
};

const FOLDERBASE_ENTRY: &str = "FOLDERBASE.md";
const MANIFEST: &str = ".folderbase/manifest.json";
const IGNORE_FILE: &str = ".folderbaseignore";
const CODEX_ADAPTER: &str = "AGENTS.md";
const CLAUDE_ADAPTER: &str = "CLAUDE.md";

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
    refuse_nested_target(&root)?;
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
    let preconditions = template_preconditions(&root, package, &rendered)?;
    let package_digest = template_package_sha256(package)?;
    plan_initialization_with_template(
        &root,
        options,
        Some((rendered, preconditions, package_digest)),
        request,
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
) -> Result<InitializationPlan> {
    let root = canonical_directory(root)?;
    refuse_nested_target(&root)?;
    if is_provider_controlled(&root) {
        return Err(FolderbaseError::ProviderControlled(root));
    }
    let root_handle =
        Handle::from_path(&root).map_err(|source| FolderbaseError::io(&root, source))?;

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
    let destination_inventory = snapshot_destination_inventory(&root)?;
    let mut preserved_paths = destination_inventory
        .iter()
        .filter_map(|entry| {
            entry.sha256.as_ref().map(|sha256| PreservedPath {
                path: entry.path.clone(),
                sha256: sha256.clone(),
            })
        })
        .collect::<Vec<_>>();
    let mut warnings = Vec::new();

    let template_provenance = if let Some((rendered, preconditions, package_digest)) =
        rendered_template
    {
        template_preconditions = preconditions;
        for path in rendered
            .additions
            .iter()
            .map(|addition| addition.path.as_path())
            .chain(rendered.existing_paths.iter().map(PathBuf::as_path))
        {
            refuse_template_target_inside_nested_folderbase(&root, path)?;
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
        let folderbase_entry_path = safe_destination(&root, Path::new(FOLDERBASE_ENTRY))?;
        match fs::symlink_metadata(&folderbase_entry_path) {
            Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {}
            Ok(_) => return Err(FolderbaseError::WouldOverwrite(folderbase_entry_path)),
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                if !writes
                    .iter()
                    .any(|write| write.path == Path::new(FOLDERBASE_ENTRY))
                {
                    return Err(FolderbaseError::InvalidRecord {
                        path: root.clone(),
                        message: "template adoption must provide a FOLDERBASE.md folderbase entry"
                            .to_owned(),
                    });
                }
            }
            Err(source) => return Err(FolderbaseError::io(folderbase_entry_path, source)),
        }
        Some((
            rendered.template_id,
            rendered.template_version,
            package_digest,
        ))
    } else {
        plan_file(
            &root,
            Path::new(FOLDERBASE_ENTRY),
            "Canonical human and agent entry point",
            folderbase_entry(&folderbase_name),
            &mut writes,
            &mut preserved_paths,
        )?;
        None
    };
    plan_file(
        &root,
        Path::new(IGNORE_FILE),
        "Default local inventory and synchronization exclusions",
        default_ignore(),
        &mut writes,
        &mut preserved_paths,
    )?;

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
            "created_at": created_at,
            "entry": FOLDERBASE_ENTRY
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
    let is_template_adoption = folderbase.get("template_provenance").is_some();
    let manifest = json!({
        "$schema": if is_template_adoption {
            "https://folderbase.ai/protocol/0.2/folderbase.schema.json"
        } else {
            "https://folderbase.ai/protocol/0.1/folderbase.schema.json"
        },
        "protocol_version": if is_template_adoption { "0.2.0" } else { "0.1.0" },
        "folderbase": folderbase,
        "adapters": adapter_paths,
        "policies": {
            "availability": "keep_local",
            "structural_changes": "approve",
            "archive": "approve",
            "cloud_sync": "disabled"
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
        plan_file(
            &root,
            Path::new(CODEX_ADAPTER),
            "Codex bootstrap adapter",
            agent_adapter(),
            &mut writes,
            &mut preserved_paths,
        )?;
        plan_file(
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
        root_handle,
        request,
        destination_inventory,
    })
}

struct InitializationDigestInput<'a> {
    root: &'a Path,
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
        digest_text(&mut hasher, b"preserved_sha256", preserved.sha256.as_str());
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
        digest_optional_u64(&mut hasher, b"destination_bytes", entry.bytes);
        digest_optional_text(&mut hasher, b"destination_sha256", entry.sha256.as_deref());
        match &entry.symlink_target {
            Some(target) => {
                digest_text(&mut hasher, b"destination_symlink_present", "true");
                digest_path(&mut hasher, b"destination_symlink_target", target);
            }
            None => digest_text(&mut hasher, b"destination_symlink_present", "false"),
        }
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

fn digest_optional_text(hasher: &mut Sha256, label: &[u8], value: Option<&str>) {
    match value {
        Some(value) => {
            digest_bytes(hasher, b"optional_present", label);
            digest_text(hasher, label, value);
        }
        None => digest_bytes(hasher, b"optional_absent", label),
    }
}

fn digest_optional_u64(hasher: &mut Sha256, label: &[u8], value: Option<u64>) {
    match value {
        Some(value) => {
            digest_bytes(hasher, b"optional_present", label);
            digest_u64(hasher, label, value);
        }
        None => digest_bytes(hasher, b"optional_absent", label),
    }
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
    let current_handle = Handle::from_file(
        root_file
            .try_clone()
            .map_err(|source| FolderbaseError::io(&root, source))?,
    )
    .map_err(|source| FolderbaseError::io(&root, source))?;
    if current_handle != plan.root_handle {
        return Err(FolderbaseError::PlanRootIdentityChanged(root));
    }
    refuse_nested_target(&root)?;
    let root_dir = Dir::from_std_file(root_file);

    verify_template_preconditions(&root_dir, plan)?;
    verify_preserved_paths(&root_dir, plan)?;
    validate_planned_paths_against_existing(&plan.root, &plan.directories, &plan.writes)?;
    verify_destinations_absent(&root_dir, plan)?;
    if snapshot_destination_inventory(&root)? != plan.destination_inventory {
        return Err(FolderbaseError::PlanPreconditionChanged(root));
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

/// Replan the exact Core request against the current destination and apply it
/// only when its digest is the one the caller approved.
pub fn initialize_with_expected_plan_digest(
    plan: &InitializationPlan,
    expected: &InitializationPlanDigest,
) -> Result<InitializationResult> {
    expected.validate()?;
    let current = match &plan.request {
        InitializationRequest::Ordinary { options } => {
            plan_initialization(&plan.root, options.clone())?
        }
        InitializationRequest::Template {
            options,
            package,
            answers,
        } => plan_template_initialization(&plan.root, options.clone(), package, answers)?,
    };
    if current.plan_digest != *expected {
        return Err(FolderbaseError::InitializationPlanChanged {
            expected: expected.digest.clone(),
            actual: current.plan_digest.digest.clone(),
        });
    }
    initialize(&current)
}

pub(crate) fn create_directory_no_clobber(root_dir: &Dir, root: &Path, path: &Path) -> Result<()> {
    ensure_safe_relative(path)?;
    if let Err(source) = root_dir.create_dir(path) {
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
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        let metadata = root_dir
            .symlink_metadata(parent)
            .map_err(|source| FolderbaseError::io(root.join(parent), source))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(FolderbaseError::UnsafePath(root.join(parent)));
        }
    }

    let staged_path = PathBuf::from(format!(
        ".folderbase/.{staging_label}-{}.tmp",
        Uuid::now_v7()
    ));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    let mut staged = root_dir
        .open_with(&staged_path, &options)
        .map_err(|source| FolderbaseError::io(root.join(&staged_path), source))?;
    if let Err(source) = staged.write_all(content).and_then(|()| staged.sync_all()) {
        drop(staged);
        let _ = root_dir.remove_file(&staged_path);
        return Err(FolderbaseError::io(root.join(&staged_path), source));
    }
    drop(staged);

    if let Err(source) = root_dir.hard_link(&staged_path, root_dir, path) {
        let _ = root_dir.remove_file(&staged_path);
        return Err(if source.kind() == std::io::ErrorKind::AlreadyExists {
            FolderbaseError::WouldOverwrite(root.join(path))
        } else {
            FolderbaseError::io(root.join(path), source)
        });
    }
    let _ = root_dir.remove_file(&staged_path);
    Ok(())
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
) -> Result<Vec<TemplateArtifactPrecondition>> {
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
        let metadata = fs::symlink_metadata(&destination)
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
        if artifact.kind == TemplateArtifactKind::Directory
            && has_nested_folderbase_marker(&destination)?
        {
            return Err(FolderbaseError::InvalidRecord {
                path: destination,
                message: "existing template directory is already a nested folderbase".to_owned(),
            });
        }
        let handle = Handle::from_path(&destination)
            .map_err(|source| FolderbaseError::io(&destination, source))?;
        preconditions.push(TemplateArtifactPrecondition {
            path: path.clone(),
            kind: artifact.kind,
            handle,
        });
    }
    preconditions.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(preconditions)
}

fn verify_template_preconditions(root_dir: &Dir, plan: &InitializationPlan) -> Result<()> {
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
        if precondition.kind == TemplateArtifactKind::Directory
            && has_nested_folderbase_marker(&destination).map_err(|_| changed())?
        {
            return Err(changed());
        }
        let current_handle = Handle::from_path(&destination).map_err(|_| changed())?;
        if current_handle != precondition.handle {
            return Err(changed());
        }
    }
    Ok(())
}

fn refuse_nested_target(root: &Path) -> Result<()> {
    for ancestor in root.ancestors().skip(1) {
        if ancestor.is_dir() && has_nested_folderbase_marker(ancestor)? {
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
    let mut current = root.to_path_buf();
    if let Some(parent) = target.parent() {
        for component in parent.components() {
            let Component::Normal(component) = component else {
                return Err(FolderbaseError::UnsafePath(target.to_path_buf()));
            };
            current.push(component);
            if current.is_dir() && has_nested_folderbase_marker(&current)? {
                return Err(FolderbaseError::InvalidRecord {
                    path: target.to_path_buf(),
                    message: format!(
                        "template target is inside nested folderbase at {}",
                        current.display()
                    ),
                });
            }
        }
    }
    Ok(())
}

fn snapshot_destination_inventory(root: &Path) -> Result<Vec<InitializationDestinationEntry>> {
    fn visit(
        root: &Path,
        current: &Path,
        inventory: &mut Vec<InitializationDestinationEntry>,
    ) -> Result<()> {
        let entries =
            fs::read_dir(current).map_err(|source| FolderbaseError::io(current, source))?;
        for entry in entries {
            let entry = entry.map_err(|source| FolderbaseError::io(current, source))?;
            let path = entry.path();
            let relative = path
                .strip_prefix(root)
                .expect("walked path stays under root")
                .to_path_buf();
            let metadata =
                fs::symlink_metadata(&path).map_err(|source| FolderbaseError::io(&path, source))?;
            if metadata.file_type().is_symlink() {
                inventory.push(InitializationDestinationEntry {
                    path: relative,
                    kind: InitializationDestinationKind::Symlink,
                    bytes: None,
                    sha256: None,
                    symlink_target: Some(
                        fs::read_link(&path)
                            .map_err(|source| FolderbaseError::io(&path, source))?,
                    ),
                });
                continue;
            }
            if metadata.is_dir() {
                let name = entry.file_name();
                if is_expensive_reconstructable_directory(&name) {
                    inventory.push(InitializationDestinationEntry {
                        path: relative,
                        kind: InitializationDestinationKind::ReconstructableDirectory,
                        bytes: None,
                        sha256: None,
                        symlink_target: None,
                    });
                    continue;
                }
                if path != root && has_nested_folderbase_marker(&path)? {
                    inventory.push(InitializationDestinationEntry {
                        path: relative,
                        kind: InitializationDestinationKind::NestedFolderbase,
                        bytes: None,
                        sha256: None,
                        symlink_target: None,
                    });
                    continue;
                }
                inventory.push(InitializationDestinationEntry {
                    path: relative,
                    kind: InitializationDestinationKind::Directory,
                    bytes: None,
                    sha256: None,
                    symlink_target: None,
                });
                visit(root, &path, inventory)?;
            } else if metadata.is_file() {
                inventory.push(InitializationDestinationEntry {
                    path: relative,
                    kind: InitializationDestinationKind::File,
                    bytes: Some(metadata.len()),
                    sha256: Some(sha256_path(&path)?),
                    symlink_target: None,
                });
            } else {
                inventory.push(InitializationDestinationEntry {
                    path: relative,
                    kind: InitializationDestinationKind::Other,
                    bytes: None,
                    sha256: None,
                    symlink_target: None,
                });
            }
        }
        Ok(())
    }

    let mut inventory = Vec::new();
    visit(root, root, &mut inventory)?;
    inventory.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(inventory)
}

fn is_expensive_reconstructable_directory(name: &std::ffi::OsStr) -> bool {
    [
        ".git",
        "node_modules",
        ".next",
        "dist",
        "build",
        "coverage",
        ".venv",
        "__pycache__",
        ".dart_tool",
        "Pods",
    ]
    .iter()
    .any(|candidate| name == std::ffi::OsStr::new(candidate))
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
                    sha256: sha256_path(&destination)?,
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

fn verify_preserved_paths(root_dir: &Dir, plan: &InitializationPlan) -> Result<()> {
    for preserved in &plan.preserved_paths {
        ensure_safe_relative(&preserved.path)?;
        safe_destination(&plan.root, &preserved.path)
            .map_err(|_| FolderbaseError::PlanPreconditionChanged(preserved.path.clone()))?;
        let metadata = root_dir
            .symlink_metadata(&preserved.path)
            .map_err(|_| FolderbaseError::PlanPreconditionChanged(preserved.path.clone()))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(FolderbaseError::PlanPreconditionChanged(
                preserved.path.clone(),
            ));
        }
        let mut file = root_dir
            .open(&preserved.path)
            .map_err(|_| FolderbaseError::PlanPreconditionChanged(preserved.path.clone()))?;
        let digest = sha256_reader(&mut file)
            .map_err(|_| FolderbaseError::PlanPreconditionChanged(preserved.path.clone()))?;
        if digest != preserved.sha256 {
            return Err(FolderbaseError::PlanPreconditionChanged(
                preserved.path.clone(),
            ));
        }
    }
    Ok(())
}

fn verify_destinations_absent(root_dir: &Dir, plan: &InitializationPlan) -> Result<()> {
    for path in plan
        .directories
        .iter()
        .map(|directory| &directory.path)
        .chain(plan.writes.iter().map(|write| &write.path))
    {
        ensure_safe_relative(path)?;
        safe_destination(&plan.root, path)?;
        refuse_template_target_inside_nested_folderbase(&plan.root, path)?;
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

fn folderbase_entry(name: &str) -> String {
    format!(
        "# {name}\n\n\
         ## Purpose\n\n\
         Describe why this folderbase exists and who it serves.\n\n\
         ## Current state\n\n\
         This folder was initialized as a Folderbase. Review its files and update this summary.\n\n\
         ## Navigate\n\n\
         - Add links to the canonical documents and folders a new collaborator should read.\n\n\
         ## Operating rules\n\n\
         - Read this file before changing the folderbase.\n\
         - Preserve ordinary file compatibility.\n\
         - Propose structural migrations before moving canonical knowledge.\n\n\
         ## Unresolved work\n\n\
         - Replace the starter text with the folderbase's real current state.\n"
    )
}

fn default_ignore() -> String {
    [
        "node_modules/",
        ".next/",
        "dist/",
        "build/",
        "coverage/",
        ".venv/",
        "__pycache__/",
        ".dart_tool/",
        "Pods/",
        ".DS_Store",
        "*.tmp",
        "~$*",
        "",
    ]
    .join("\n")
}

fn agent_adapter() -> String {
    "<!-- folderbase:begin -->\n\
     # Folderbase\n\n\
     Read `FOLDERBASE.md` before working in this directory. Follow its navigation and \
     operating rules. Record durable project context in the folderbase rather than \
     only in the current conversation.\n\
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
        assert!(temp.path().join(FOLDERBASE_ENTRY).exists());
        assert!(temp.path().join(MANIFEST).exists());
        assert!(temp.path().join(CODEX_ADAPTER).exists());
        assert!(temp.path().join(CLAUDE_ADAPTER).exists());
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
        assert!(matches!(error, FolderbaseError::WouldOverwrite(_)));
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
        assert!(matches!(error, FolderbaseError::PlanPreconditionChanged(_)));
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
        assert!(matches!(error, FolderbaseError::WouldOverwrite(_)));
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
}

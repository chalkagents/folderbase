use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::ErrorKind;
use std::path::{Component, Path, PathBuf};

use cap_std::fs::Dir;
use chrono::{DateTime, Utc};
use semver::Version;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use unicode_casefold::UnicodeCaseFold;
use uuid::Uuid;

use crate::initialization::{
    canonical_directory, create_directory_no_clobber, ensure_safe_relative,
    install_text_no_clobber, refuse_symlink_root, refuse_template_target_inside_nested_folderbase,
    safe_destination, sha256_path, validate_template_path_collisions,
    validate_template_paths_against_existing_casefold,
};
use crate::model::{AppliedTemplate, TemplateApplicationComparison, TemplateExpansionPrecondition};
use crate::physical_identity::{PhysicalIdentity, RetainedPhysicalIdentity};
use crate::template::{template_package_sha256, validate_runtime_package};
use crate::{
    FolderbaseError, PlannedTemplateAddition, Result, TemplateAnswerValue,
    TemplateApplicationCreatedPath, TemplateApplicationRecord, TemplateApplicationResult,
    TemplateApplicationState, TemplateArtifactKind, TemplateComparisonSource,
    TemplateExpansionPlan, TemplatePackage, TemplatePlanDigest, TemplateStructuralChange,
    TemplateStructuralChangeKind, attest_folderbase_root, render_template,
};

const MANIFEST: &str = ".folderbase/manifest.json";
const APPLICATIONS: &str = ".folderbase/template-applications";
const APPLICATION_SCHEMA: &str =
    "https://folderbase.ai/protocol/0.2/template-application.schema.json";

pub fn plan_template_expansion(
    root: impl AsRef<Path>,
    target: &TemplatePackage,
    answers: &BTreeMap<String, TemplateAnswerValue>,
) -> Result<TemplateExpansionPlan> {
    refuse_symlink_root(root.as_ref())?;
    let root = canonical_directory(root.as_ref())?;
    validate_folderbase_root(&root)?;
    validate_runtime_package(&root, target)?;

    let root_identity = RetainedPhysicalIdentity::from_path(&root)
        .map_err(|source| FolderbaseError::io(&root, source))?;
    let manifest_path = root.join(MANIFEST);
    let manifest_bytes =
        fs::read(&manifest_path).map_err(|source| FolderbaseError::io(&manifest_path, source))?;
    let manifest_sha256 = sha256_bytes(&manifest_bytes);
    let manifest: Value = serde_json::from_slice(&manifest_bytes)
        .map_err(|source| FolderbaseError::json(&manifest_path, source))?;
    let folderbase_id =
        required_string(&manifest, &["folderbase", "id"], &manifest_path)?.to_owned();

    let (history, history_sha256) = read_history_with_snapshot(&root, Some(&folderbase_id))?;
    validate_application_history_chain(&manifest, &history, &manifest_path)?;
    let package_digest = TemplatePlanDigest {
        algorithm: "sha256".to_owned(),
        digest: template_package_sha256(target)?,
    };
    let comparison = derive_comparison(&manifest, &history, target.id(), &manifest_path)?;

    if comparison.template_id != target.id() {
        return build_plan(
            root,
            root_identity,
            folderbase_id,
            target,
            package_digest,
            comparison,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            vec![TemplateStructuralChange {
                kind: TemplateStructuralChangeKind::Lineage,
                path: None,
                reason: format!(
                    "template lineage changes from {} to {}",
                    manifest
                        .pointer("/folderbase/template_provenance/id")
                        .and_then(Value::as_str)
                        .unwrap_or("unknown"),
                    target.id()
                ),
            }],
            manifest_sha256,
            history_sha256,
        );
    }

    if comparison.version == target.version() {
        if comparison.package_digest.digest != package_digest.digest {
            return Err(FolderbaseError::InvalidRecord {
                path: root,
                message: format!(
                    "same template version {} has a different package digest",
                    target.version()
                ),
            });
        }
        return build_plan(
            root,
            root_identity,
            folderbase_id,
            target,
            package_digest,
            comparison,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            manifest_sha256,
            history_sha256,
        );
    }

    let comparison_version =
        Version::parse(&comparison.version).map_err(|_| FolderbaseError::InvalidRecord {
            path: manifest_path.clone(),
            message: format!(
                "invalid comparison template version: {}",
                comparison.version
            ),
        })?;
    let target_version =
        Version::parse(target.version()).map_err(|_| FolderbaseError::InvalidRecord {
            path: root.clone(),
            message: format!("invalid target template version: {}", target.version()),
        })?;

    let mut structural_changes = Vec::new();
    if target_version < comparison_version {
        structural_changes.push(TemplateStructuralChange {
            kind: TemplateStructuralChangeKind::Downgrade,
            path: None,
            reason: format!(
                "template downgrade {} -> {}",
                comparison.version,
                target.version()
            ),
        });
    } else if comparison.source != TemplateComparisonSource::Unmanaged
        && !target
            .upgrade_edges
            .iter()
            .any(|edge| edge.from == comparison.version && edge.to == target.version())
    {
        structural_changes.push(TemplateStructuralChange {
            kind: TemplateStructuralChangeKind::UnsupportedTransition,
            path: None,
            reason: format!(
                "template does not declare an additive edge {} -> {}",
                comparison.version,
                target.version()
            ),
        });
    }

    if !structural_changes.is_empty() {
        return build_plan(
            root,
            root_identity,
            folderbase_id,
            target,
            package_digest,
            comparison,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            structural_changes,
            manifest_sha256,
            history_sha256,
        );
    }

    validate_template_paths_against_existing_casefold(
        &root,
        target
            .artifacts
            .iter()
            .map(|artifact| artifact.target.as_path()),
        true,
    )?;
    let rendered = render_template(target, &root, answers)?;
    let mut additions = rendered.additions;
    add_missing_parent_directories(&root, &mut additions)?;
    validate_template_path_collisions(
        &root,
        additions.iter().map(|addition| {
            (
                addition.path.as_path(),
                addition.kind == TemplateArtifactKind::Directory,
            )
        }),
    )?;
    additions.sort_by(|left, right| left.path.cmp(&right.path));
    additions.dedup_by(|left, right| left.path == right.path);

    let mut preserved_paths = Vec::new();
    let mut preserved_preconditions = Vec::new();
    let mut blocked_paths = Vec::new();
    for path in rendered.existing_paths {
        let artifact = target
            .artifacts
            .iter()
            .find(|artifact| artifact.target == path)
            .expect("rendered target belongs to validated package");
        let destination = safe_destination(&root, &path)?;
        refuse_template_target_inside_nested_folderbase(&root, &path)?;
        let metadata = fs::symlink_metadata(&destination)
            .map_err(|source| FolderbaseError::io(&destination, source))?;
        let type_matches = match artifact.kind {
            TemplateArtifactKind::Directory => metadata.is_dir(),
            TemplateArtifactKind::Text => metadata.is_file(),
        };
        if metadata.file_type().is_symlink() || !type_matches {
            blocked_paths.push(path);
            continue;
        }
        let identity = RetainedPhysicalIdentity::from_path(&destination)
            .map_err(|source| FolderbaseError::io(&destination, source))?;
        let sha256 = if artifact.kind == TemplateArtifactKind::Text {
            Some(sha256_path(&destination)?)
        } else {
            None
        };
        preserved_paths.push(path.clone());
        preserved_preconditions.push(TemplateExpansionPrecondition {
            path,
            kind: artifact.kind,
            sha256,
            identity,
        });
    }
    preserved_paths.sort();
    preserved_preconditions.sort_by(|left, right| left.path.cmp(&right.path));
    blocked_paths.sort();

    build_plan(
        root,
        root_identity,
        folderbase_id,
        target,
        package_digest,
        comparison,
        additions,
        preserved_paths,
        blocked_paths,
        structural_changes,
        manifest_sha256,
        history_sha256,
    )
    .map(|mut plan| {
        plan.preserved_preconditions = preserved_preconditions;
        plan.plan_digest = digest_plan(&plan);
        plan
    })
}

pub fn apply_template_expansion(plan: &TemplateExpansionPlan) -> Result<TemplateApplicationResult> {
    if !plan.structural_changes.is_empty() {
        return Err(FolderbaseError::StructuralTemplateChangeRequiresApproval);
    }
    if !plan.blocked_paths.is_empty() {
        return Err(FolderbaseError::TemplateExpansionBlocked);
    }

    let root = canonical_directory(&plan.root)?;
    let current_identity =
        PhysicalIdentity::from_path(&root).map_err(|source| FolderbaseError::io(&root, source))?;
    if root != plan.root || current_identity != plan.root_identity.identity() {
        return Err(FolderbaseError::PlanRootIdentityChanged(root));
    }
    validate_folderbase_root(&root)?;

    let manifest_path = root.join(MANIFEST);
    let manifest_bytes =
        fs::read(&manifest_path).map_err(|source| FolderbaseError::io(&manifest_path, source))?;
    if sha256_bytes(&manifest_bytes) != plan.manifest_sha256 {
        return Err(FolderbaseError::PlanPreconditionChanged(PathBuf::from(
            MANIFEST,
        )));
    }
    let (_, history_sha256) = read_history_with_snapshot(&root, Some(&plan.folderbase_id))?;
    if history_sha256 != plan.history_sha256 {
        return Err(FolderbaseError::PlanPreconditionChanged(PathBuf::from(
            APPLICATIONS,
        )));
    }
    validate_template_paths_against_existing_casefold(
        &root,
        plan.additions
            .iter()
            .map(|addition| addition.path.as_path())
            .chain(plan.preserved_paths.iter().map(PathBuf::as_path)),
        true,
    )?;
    verify_preserved_preconditions(plan)?;
    verify_additions_absent(plan)?;

    if plan.is_noop() {
        return Ok(TemplateApplicationResult {
            created_paths: Vec::new(),
            preserved_paths: Vec::new(),
            application_record: None,
        });
    }

    let root_file = fs::File::open(&root).map_err(|source| FolderbaseError::io(&root, source))?;
    let root_dir = Dir::from_std_file(root_file);
    let mut ordered = plan.additions.iter().collect::<Vec<_>>();
    ordered.sort_by(|left, right| {
        let left_directory = left.kind == TemplateArtifactKind::Directory;
        let right_directory = right.kind == TemplateArtifactKind::Directory;
        right_directory
            .cmp(&left_directory)
            .then_with(|| {
                left.path
                    .components()
                    .count()
                    .cmp(&right.path.components().count())
            })
            .then_with(|| left.path.cmp(&right.path))
    });

    for addition in &ordered {
        match addition.kind {
            TemplateArtifactKind::Directory => {
                create_directory_no_clobber(&root_dir, &root, &addition.path)?;
            }
            TemplateArtifactKind::Text => {
                install_text_no_clobber(
                    &root_dir,
                    &root,
                    &addition.path,
                    addition.content.as_deref().unwrap_or_default().as_bytes(),
                    "template-expansion",
                )?;
            }
        }
    }

    let created_paths = verify_created_additions(&root, &plan.additions)?;
    verify_preserved_preconditions(plan)?;
    let preserved_targets = materialize_preserved_targets(&root, plan)?;

    let application_id = format!("template_application_{}", Uuid::now_v7());
    let mut record = TemplateApplicationRecord {
        schema: APPLICATION_SCHEMA.to_owned(),
        protocol_version: "0.2.0".to_owned(),
        id: application_id.clone(),
        folderbase_id: plan.folderbase_id.clone(),
        state: TemplateApplicationState::Verified,
        template: AppliedTemplate {
            id: plan.template_id.clone(),
            version: plan.template_version.clone(),
            package_digest: plan.template_package_digest.clone(),
        },
        comparison: TemplateApplicationComparison {
            source: plan.comparison_source,
            version: plan.comparison_version.clone(),
            application_id: plan.comparison_application_id.clone(),
        },
        applied_at: Utc::now().to_rfc3339(),
        created_paths,
        preserved_targets,
        plan_digest: plan.plan_digest.clone(),
        record_digest: TemplatePlanDigest {
            algorithm: "sha256".to_owned(),
            digest: String::new(),
        },
    };
    record.record_digest = digest_application_record(&record);
    validate_application_record(&record, Some(&plan.folderbase_id), &root)?;

    ensure_history_directory(&root_dir, &root)?;
    let record_path = PathBuf::from(APPLICATIONS).join(format!("{application_id}.json"));
    let mut bytes = serde_json::to_vec_pretty(&record)
        .map_err(|source| FolderbaseError::json(root.join(&record_path), source))?;
    bytes.push(b'\n');
    install_text_no_clobber(
        &root_dir,
        &root,
        &record_path,
        &bytes,
        "template-application",
    )?;
    let installed: TemplateApplicationRecord = serde_json::from_slice(
        &fs::read(root.join(&record_path))
            .map_err(|source| FolderbaseError::io(root.join(&record_path), source))?,
    )
    .map_err(|source| FolderbaseError::json(root.join(&record_path), source))?;
    validate_application_record(&installed, Some(&plan.folderbase_id), &root)?;
    if installed != record {
        return Err(FolderbaseError::InvalidRecord {
            path: root.join(&record_path),
            message: "installed template application record failed verification".to_owned(),
        });
    }

    Ok(TemplateApplicationResult {
        created_paths: plan
            .additions
            .iter()
            .map(|addition| addition.path.clone())
            .collect(),
        preserved_paths: plan.preserved_paths.clone(),
        application_record: Some(record_path),
    })
}

pub fn template_application_history(
    root: impl AsRef<Path>,
) -> Result<Vec<TemplateApplicationRecord>> {
    refuse_symlink_root(root.as_ref())?;
    let root = canonical_directory(root.as_ref())?;
    validate_folderbase_root(&root)?;
    let manifest_path = root.join(MANIFEST);
    let manifest: Value = serde_json::from_slice(
        &fs::read(&manifest_path).map_err(|source| FolderbaseError::io(&manifest_path, source))?,
    )
    .map_err(|source| FolderbaseError::json(&manifest_path, source))?;
    let folderbase_id = required_string(&manifest, &["folderbase", "id"], &manifest_path)?;
    let (history, _) = read_history_with_snapshot(&root, Some(folderbase_id))?;
    validate_application_history_chain(&manifest, &history, &manifest_path)?;
    Ok(history)
}

struct Comparison {
    template_id: String,
    version: String,
    package_digest: TemplatePlanDigest,
    source: TemplateComparisonSource,
    application_id: Option<String>,
}

fn derive_comparison(
    manifest: &Value,
    history: &[TemplateApplicationRecord],
    template_id: &str,
    manifest_path: &Path,
) -> Result<Comparison> {
    let predecessor_ids = history
        .iter()
        .filter_map(|record| record.comparison.application_id.as_deref())
        .collect::<BTreeSet<_>>();
    let terminals = history
        .iter()
        .filter(|record| {
            record.template.id == template_id && !predecessor_ids.contains(record.id.as_str())
        })
        .collect::<Vec<_>>();
    match terminals.as_slice() {
        [record] => {
            return Ok(Comparison {
                template_id: record.template.id.clone(),
                version: record.template.version.clone(),
                package_digest: record.template.package_digest.clone(),
                source: TemplateComparisonSource::Application,
                application_id: Some(record.id.clone()),
            });
        }
        [] if history
            .iter()
            .all(|record| record.template.id != template_id) => {}
        _ => {
            return Err(FolderbaseError::InvalidRecord {
                path: manifest_path.to_path_buf(),
                message: format!(
                    "template application history does not have one terminal for {template_id}"
                ),
            });
        }
    }

    let Some(provenance) = manifest
        .pointer("/folderbase/template_provenance")
        .and_then(Value::as_object)
    else {
        if history.is_empty() {
            require_native_unmanaged_lineage(manifest, manifest_path)?;
            return Ok(Comparison {
                template_id: template_id.to_owned(),
                version: "0.0.0".to_owned(),
                package_digest: TemplatePlanDigest {
                    algorithm: "sha256".to_owned(),
                    digest: format!(
                        "{:x}",
                        Sha256::digest(b"folderbase-unmanaged-template-origin-v1\0")
                    ),
                },
                source: TemplateComparisonSource::Unmanaged,
                application_id: None,
            });
        }
        return Err(FolderbaseError::InvalidRecord {
            path: manifest_path.to_path_buf(),
            message: "template history has no immutable origin".to_owned(),
        });
    };
    let origin_id = provenance
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| FolderbaseError::InvalidRecord {
            path: manifest_path.to_path_buf(),
            message: "template origin is missing id".to_owned(),
        })?;
    let version = provenance
        .get("version")
        .and_then(Value::as_str)
        .ok_or_else(|| FolderbaseError::InvalidRecord {
            path: manifest_path.to_path_buf(),
            message: "template origin is missing version".to_owned(),
        })?;
    let package_digest =
        provenance
            .get("package_digest")
            .ok_or_else(|| FolderbaseError::InvalidRecord {
                path: manifest_path.to_path_buf(),
                message: "template origin is missing package digest".to_owned(),
            })?;
    let package_digest: TemplatePlanDigest = serde_json::from_value(package_digest.clone())
        .map_err(|source| FolderbaseError::json(manifest_path, source))?;
    validate_digest(&package_digest, manifest_path)?;
    Ok(Comparison {
        template_id: origin_id.to_owned(),
        version: version.to_owned(),
        package_digest,
        source: TemplateComparisonSource::Origin,
        application_id: None,
    })
}

fn validate_application_history_chain(
    manifest: &Value,
    history: &[TemplateApplicationRecord],
    manifest_path: &Path,
) -> Result<()> {
    if history.is_empty() {
        return Ok(());
    }

    let provenance = manifest
        .pointer("/folderbase/template_provenance")
        .and_then(Value::as_object);
    let origin = provenance
        .map(|_| {
            Ok::<_, FolderbaseError>((
                required_string(
                    manifest,
                    &["folderbase", "template_provenance", "id"],
                    manifest_path,
                )?,
                required_string(
                    manifest,
                    &["folderbase", "template_provenance", "version"],
                    manifest_path,
                )?,
            ))
        })
        .transpose()?;
    let records_by_id = history
        .iter()
        .map(|record| (record.id.as_str(), record))
        .collect::<BTreeMap<_, _>>();
    let mut origin_roots = BTreeSet::new();
    let mut predecessor_ids = BTreeSet::new();

    for record in history {
        let target_version =
            Version::parse(&record.template.version).expect("validated application version");
        let comparison_version =
            Version::parse(&record.comparison.version).expect("validated comparison version");
        if target_version <= comparison_version {
            return Err(FolderbaseError::InvalidRecord {
                path: manifest_path.to_path_buf(),
                message: format!(
                    "template application {} does not advance its comparison version",
                    record.id
                ),
            });
        }

        match record.comparison.source {
            TemplateComparisonSource::Unmanaged => {
                if !manifest_is_native_v05(manifest)
                    || provenance.is_some()
                    || record.comparison.version != "0.0.0"
                    || !origin_roots.insert(record.template.id.as_str())
                {
                    return Err(FolderbaseError::InvalidRecord {
                        path: manifest_path.to_path_buf(),
                        message: if !manifest_is_native_v05(manifest) {
                            "unmanaged template lineage requires native protocol 0.5.0".to_owned()
                        } else {
                            format!(
                                "template application {} has invalid unmanaged origin",
                                record.id
                            )
                        },
                    });
                }
            }
            TemplateComparisonSource::Origin => {
                if let Some((origin_id, origin_version)) = origin {
                    if record.template.id != origin_id
                        || record.comparison.version != origin_version
                    {
                        return Err(FolderbaseError::InvalidRecord {
                            path: manifest_path.to_path_buf(),
                            message: format!(
                                "template application {} does not extend the active template origin",
                                record.id
                            ),
                        });
                    }
                } else {
                    return Err(FolderbaseError::InvalidRecord {
                        path: manifest_path.to_path_buf(),
                        message: format!(
                            "template application {} claims a missing manifest origin",
                            record.id
                        ),
                    });
                }
                if !origin_roots.insert(record.template.id.as_str()) {
                    return Err(FolderbaseError::InvalidRecord {
                        path: manifest_path.to_path_buf(),
                        message: format!(
                            "template application history has multiple origin roots for {}",
                            record.template.id
                        ),
                    });
                }
            }
            TemplateComparisonSource::Application => {
                let predecessor_id = record
                    .comparison
                    .application_id
                    .as_deref()
                    .expect("validated application comparison id");
                let predecessor = records_by_id.get(predecessor_id).ok_or_else(|| {
                    FolderbaseError::InvalidRecord {
                        path: manifest_path.to_path_buf(),
                        message: format!("comparison application does not exist: {predecessor_id}"),
                    }
                })?;
                if predecessor.folderbase_id != record.folderbase_id
                    || predecessor.template.id != record.template.id
                    || predecessor.template.version != record.comparison.version
                {
                    return Err(FolderbaseError::InvalidRecord {
                        path: manifest_path.to_path_buf(),
                        message: format!(
                            "comparison application does not match {} template lineage and version",
                            record.id
                        ),
                    });
                }
                if parsed_application_time(predecessor) > parsed_application_time(record) {
                    return Err(FolderbaseError::InvalidRecord {
                        path: manifest_path.to_path_buf(),
                        message: format!("comparison application does not precede {}", record.id),
                    });
                }
                if !predecessor_ids.insert(predecessor_id) {
                    return Err(FolderbaseError::InvalidRecord {
                        path: manifest_path.to_path_buf(),
                        message: format!("template application history forks at {predecessor_id}"),
                    });
                }
            }
        }
    }

    Ok(())
}

fn require_native_unmanaged_lineage(manifest: &Value, manifest_path: &Path) -> Result<()> {
    if manifest_is_native_v05(manifest) {
        return Ok(());
    }
    Err(FolderbaseError::InvalidRecord {
        path: manifest_path.to_path_buf(),
        message: "unmanaged template lineage requires native protocol 0.5.0".to_owned(),
    })
}

fn manifest_is_native_v05(manifest: &Value) -> bool {
    manifest.get("protocol_version").and_then(Value::as_str) == Some("0.5.0")
}

#[allow(clippy::too_many_arguments)]
fn build_plan(
    root: PathBuf,
    root_identity: RetainedPhysicalIdentity,
    folderbase_id: String,
    target: &TemplatePackage,
    template_package_digest: TemplatePlanDigest,
    comparison: Comparison,
    additions: Vec<PlannedTemplateAddition>,
    preserved_paths: Vec<PathBuf>,
    blocked_paths: Vec<PathBuf>,
    mut structural_changes: Vec<TemplateStructuralChange>,
    manifest_sha256: String,
    history_sha256: String,
) -> Result<TemplateExpansionPlan> {
    structural_changes.sort_by(|left, right| {
        left.kind
            .cmp(&right.kind)
            .then_with(|| left.path.cmp(&right.path))
    });
    let mut plan = TemplateExpansionPlan {
        root,
        folderbase_id,
        template_id: target.id().to_owned(),
        comparison_version: comparison.version,
        comparison_source: comparison.source,
        comparison_application_id: comparison.application_id,
        comparison_package_digest: comparison.package_digest,
        template_version: target.version().to_owned(),
        template_package_digest,
        additions,
        preserved_paths,
        blocked_paths,
        structural_changes,
        plan_digest: TemplatePlanDigest {
            algorithm: "sha256".to_owned(),
            digest: String::new(),
        },
        manifest_sha256,
        history_sha256,
        preserved_preconditions: Vec::new(),
        root_identity,
    };
    plan.plan_digest = digest_plan(&plan);
    Ok(plan)
}

fn digest_plan(plan: &TemplateExpansionPlan) -> TemplatePlanDigest {
    let additions = plan
        .additions
        .iter()
        .map(|addition| {
            let bytes = addition.content.as_deref().map(str::as_bytes);
            json!({
                "path": path_text(&addition.path),
                "kind": addition.kind,
                "bytes": bytes.map(|bytes| bytes.len() as u64),
                "sha256": bytes.map(sha256_bytes),
            })
        })
        .collect::<Vec<_>>();
    let preserved = plan
        .preserved_preconditions
        .iter()
        .map(|precondition| {
            json!({
                "path": path_text(&precondition.path),
                "kind": precondition.kind,
                "sha256": precondition.sha256,
            })
        })
        .collect::<Vec<_>>();
    let structural = plan
        .structural_changes
        .iter()
        .map(|change| {
            json!({
                "kind": change.kind,
                "path": change.path.as_ref().map(|path| path_text(path)),
                "reason": change.reason,
            })
        })
        .collect::<Vec<_>>();
    let dto = json!({
        "folderbase_id": plan.folderbase_id,
        "manifest_sha256": plan.manifest_sha256,
        "history_sha256": plan.history_sha256,
        "comparison": {
            "source": plan.comparison_source,
            "version": plan.comparison_version,
            "application_id": plan.comparison_application_id,
            "package_digest": plan.comparison_package_digest,
        },
        "target": {
            "id": plan.template_id,
            "version": plan.template_version,
            "package_digest": plan.template_package_digest,
        },
        "additions": additions,
        "preserved": preserved,
        "blocked": plan.blocked_paths.iter().map(|path| path_text(path)).collect::<Vec<_>>(),
        "structural": structural,
    });
    TemplatePlanDigest {
        algorithm: "sha256".to_owned(),
        digest: sha256_bytes(
            &serde_json::to_vec(&dto).expect("canonical expansion plan DTO serializes"),
        ),
    }
}

fn add_missing_parent_directories(
    root: &Path,
    additions: &mut Vec<PlannedTemplateAddition>,
) -> Result<()> {
    let planned = additions
        .iter()
        .map(|addition| addition.path.clone())
        .collect::<Vec<_>>();
    let mut extra = BTreeSet::new();
    for path in planned {
        let Some(parent) = path.parent() else {
            continue;
        };
        let mut relative = PathBuf::new();
        let mut destination = root.to_path_buf();
        for component in parent.components() {
            let Component::Normal(component) = component else {
                return Err(FolderbaseError::UnsafePath(path));
            };
            relative.push(component);
            destination.push(component);
            match fs::symlink_metadata(&destination) {
                Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                    return Err(FolderbaseError::UnsafePath(destination));
                }
                Ok(_) => {}
                Err(source) if source.kind() == ErrorKind::NotFound => {
                    extra.insert(relative.clone());
                }
                Err(source) => return Err(FolderbaseError::io(destination, source)),
            }
        }
    }
    for path in extra {
        if additions.iter().all(|addition| addition.path != path) {
            additions.push(PlannedTemplateAddition {
                path,
                kind: TemplateArtifactKind::Directory,
                content: None,
            });
        }
    }
    Ok(())
}

fn validate_folderbase_root(root: &Path) -> Result<()> {
    attest_folderbase_root(root)
        .map(drop)
        .map_err(|source| FolderbaseError::InvalidRecord {
            path: root.join(MANIFEST),
            message: source.to_string(),
        })
}

fn verify_preserved_preconditions(plan: &TemplateExpansionPlan) -> Result<()> {
    for precondition in &plan.preserved_preconditions {
        refuse_template_target_inside_nested_folderbase(&plan.root, &precondition.path)?;
        let destination = safe_destination(&plan.root, &precondition.path)?;
        let metadata = fs::symlink_metadata(&destination)
            .map_err(|_| FolderbaseError::PlanPreconditionChanged(precondition.path.clone()))?;
        let type_matches = match precondition.kind {
            TemplateArtifactKind::Directory => metadata.is_dir(),
            TemplateArtifactKind::Text => metadata.is_file(),
        };
        if metadata.file_type().is_symlink() || !type_matches {
            return Err(FolderbaseError::PlanPreconditionChanged(
                precondition.path.clone(),
            ));
        }
        let identity = PhysicalIdentity::from_path(&destination)
            .map_err(|_| FolderbaseError::PlanPreconditionChanged(precondition.path.clone()))?;
        if identity != precondition.identity.identity() {
            return Err(FolderbaseError::PlanPreconditionChanged(
                precondition.path.clone(),
            ));
        }
        if let Some(expected) = &precondition.sha256
            && sha256_path(&destination)
                .map_err(|_| FolderbaseError::PlanPreconditionChanged(precondition.path.clone()))?
                != *expected
        {
            return Err(FolderbaseError::PlanPreconditionChanged(
                precondition.path.clone(),
            ));
        }
    }
    Ok(())
}

fn verify_additions_absent(plan: &TemplateExpansionPlan) -> Result<()> {
    for addition in &plan.additions {
        ensure_safe_relative(&addition.path)?;
        refuse_template_target_inside_nested_folderbase(&plan.root, &addition.path)?;
        let destination = safe_destination(&plan.root, &addition.path)?;
        match fs::symlink_metadata(&destination) {
            Ok(_) => return Err(FolderbaseError::WouldOverwrite(destination)),
            Err(source) if source.kind() == ErrorKind::NotFound => {}
            Err(source) => return Err(FolderbaseError::io(destination, source)),
        }
    }
    Ok(())
}

fn verify_created_additions(
    root: &Path,
    additions: &[PlannedTemplateAddition],
) -> Result<Vec<TemplateApplicationCreatedPath>> {
    let mut created = Vec::new();
    for addition in additions {
        let destination = safe_destination(root, &addition.path)?;
        let metadata = fs::symlink_metadata(&destination)
            .map_err(|source| FolderbaseError::io(&destination, source))?;
        let type_matches = match addition.kind {
            TemplateArtifactKind::Directory => metadata.is_dir(),
            TemplateArtifactKind::Text => metadata.is_file(),
        };
        if metadata.file_type().is_symlink() || !type_matches {
            return Err(FolderbaseError::InvalidRecord {
                path: destination,
                message: "template addition failed post-write verification".to_owned(),
            });
        }
        let (bytes, sha256) = if addition.kind == TemplateArtifactKind::Text {
            let bytes = metadata.len();
            let digest = sha256_path(&destination)?;
            let expected = sha256_bytes(addition.content.as_deref().unwrap_or_default().as_bytes());
            if digest != expected {
                return Err(FolderbaseError::InvalidRecord {
                    path: destination,
                    message: "template addition content digest mismatch".to_owned(),
                });
            }
            (Some(bytes), Some(digest))
        } else {
            (None, None)
        };
        created.push(TemplateApplicationCreatedPath {
            path: addition.path.clone(),
            kind: addition.kind,
            bytes,
            sha256,
        });
    }
    created.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(created)
}

fn materialize_preserved_targets(
    root: &Path,
    plan: &TemplateExpansionPlan,
) -> Result<Vec<crate::TemplateApplicationPreservedTarget>> {
    let mut preserved = Vec::new();
    for precondition in &plan.preserved_preconditions {
        let destination = safe_destination(root, &precondition.path)?;
        let metadata = fs::symlink_metadata(&destination)
            .map_err(|source| FolderbaseError::io(&destination, source))?;
        let sha256 = if precondition.kind == TemplateArtifactKind::Text {
            let digest = sha256_path(&destination)?;
            if precondition.sha256.as_ref() != Some(&digest) {
                return Err(FolderbaseError::PlanPreconditionChanged(
                    precondition.path.clone(),
                ));
            }
            Some(digest)
        } else {
            None
        };
        preserved.push(crate::TemplateApplicationPreservedTarget {
            path: precondition.path.clone(),
            kind: precondition.kind,
            bytes: (precondition.kind == TemplateArtifactKind::Text).then_some(metadata.len()),
            sha256,
        });
    }
    preserved.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(preserved)
}

fn ensure_history_directory(root_dir: &Dir, root: &Path) -> Result<()> {
    validate_history_path(root)?;
    let relative = Path::new(APPLICATIONS);
    match root_dir.symlink_metadata(relative) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => Ok(()),
        Ok(_) => Err(FolderbaseError::UnsafePath(root.join(relative))),
        Err(source) if source.kind() == ErrorKind::NotFound => {
            create_directory_no_clobber(root_dir, root, relative)
        }
        Err(source) => Err(FolderbaseError::io(root.join(relative), source)),
    }
}

fn validate_history_path(root: &Path) -> Result<()> {
    let protocol_dir = root.join(".folderbase");
    let metadata = fs::symlink_metadata(&protocol_dir)
        .map_err(|source| FolderbaseError::io(&protocol_dir, source))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(FolderbaseError::UnsafePath(protocol_dir));
    }
    let expected = "template-applications".case_fold().collect::<String>();
    for entry in
        fs::read_dir(&protocol_dir).map_err(|source| FolderbaseError::io(&protocol_dir, source))?
    {
        let entry = entry.map_err(|source| FolderbaseError::io(&protocol_dir, source))?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if name.case_fold().collect::<String>() == expected && name != "template-applications" {
            return Err(FolderbaseError::UnsafePath(entry.path()));
        }
    }
    let history = root.join(APPLICATIONS);
    match fs::symlink_metadata(&history) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => Ok(()),
        Ok(_) => Err(FolderbaseError::UnsafePath(history)),
        Err(source) if source.kind() == ErrorKind::NotFound => Ok(()),
        Err(source) => Err(FolderbaseError::io(history, source)),
    }
}

fn read_history_with_snapshot(
    root: &Path,
    expected_folderbase_id: Option<&str>,
) -> Result<(Vec<TemplateApplicationRecord>, String)> {
    validate_history_path(root)?;
    let history_dir = root.join(APPLICATIONS);
    if !history_dir.exists() {
        return Ok((Vec::new(), sha256_bytes(b"absent")));
    }

    let mut paths = fs::read_dir(&history_dir)
        .map_err(|source| FolderbaseError::io(&history_dir, source))?
        .map(|entry| {
            entry
                .map(|entry| entry.path())
                .map_err(|source| FolderbaseError::io(&history_dir, source))
        })
        .collect::<Result<Vec<_>>>()?;
    paths.sort();
    let mut snapshot = Sha256::new();
    let mut history = Vec::new();
    let mut ids = BTreeSet::new();
    for path in paths {
        let metadata =
            fs::symlink_metadata(&path).map_err(|source| FolderbaseError::io(&path, source))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(FolderbaseError::UnsafePath(path));
        }
        if path.extension().and_then(|extension| extension.to_str()) != Some("json") {
            return Err(FolderbaseError::InvalidRecord {
                path,
                message: "template application history contains a non-JSON entry".to_owned(),
            });
        }
        let bytes = fs::read(&path).map_err(|source| FolderbaseError::io(&path, source))?;
        snapshot.update(
            path.file_name()
                .expect("history entry name")
                .as_encoded_bytes(),
        );
        snapshot.update([0]);
        snapshot.update(&bytes);
        snapshot.update([0]);
        let record: TemplateApplicationRecord = serde_json::from_slice(&bytes)
            .map_err(|source| FolderbaseError::json(&path, source))?;
        validate_application_record(&record, expected_folderbase_id, &path)?;
        if path.file_stem().and_then(|stem| stem.to_str()) != Some(record.id.as_str()) {
            return Err(FolderbaseError::InvalidRecord {
                path,
                message: "template application filename does not match record id".to_owned(),
            });
        }
        if !ids.insert(record.id.clone()) {
            return Err(FolderbaseError::InvalidRecord {
                path,
                message: "duplicate template application id".to_owned(),
            });
        }
        history.push(record);
    }
    history.sort_by(|left, right| {
        parsed_application_time(left)
            .cmp(&parsed_application_time(right))
            .then_with(|| left.id.cmp(&right.id))
    });
    Ok((history, format!("{:x}", snapshot.finalize())))
}

fn parsed_application_time(record: &TemplateApplicationRecord) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(&record.applied_at)
        .expect("application time was validated")
        .with_timezone(&Utc)
}

fn validate_application_record(
    record: &TemplateApplicationRecord,
    expected_folderbase_id: Option<&str>,
    path: &Path,
) -> Result<()> {
    if record.schema != APPLICATION_SCHEMA
        || record.protocol_version != "0.2.0"
        || record.state != TemplateApplicationState::Verified
        || !record.id.starts_with("template_application_")
        || Uuid::parse_str(record.id.trim_start_matches("template_application_"))
            .ok()
            .is_none_or(|id| id.get_version_num() != 7)
    {
        return Err(FolderbaseError::InvalidRecord {
            path: path.to_path_buf(),
            message: "invalid template application identity or state".to_owned(),
        });
    }
    if expected_folderbase_id.is_some_and(|expected| expected != record.folderbase_id) {
        return Err(FolderbaseError::InvalidRecord {
            path: path.to_path_buf(),
            message: "template application folderbase_id does not match active manifest".to_owned(),
        });
    }
    Version::parse(&record.template.version).map_err(|_| FolderbaseError::InvalidRecord {
        path: path.to_path_buf(),
        message: "invalid applied template version".to_owned(),
    })?;
    Version::parse(&record.comparison.version).map_err(|_| FolderbaseError::InvalidRecord {
        path: path.to_path_buf(),
        message: "invalid comparison template version".to_owned(),
    })?;
    DateTime::parse_from_rfc3339(&record.applied_at).map_err(|_| {
        FolderbaseError::InvalidRecord {
            path: path.to_path_buf(),
            message: "invalid template application time".to_owned(),
        }
    })?;
    validate_digest(&record.template.package_digest, path)?;
    validate_digest(&record.plan_digest, path)?;
    validate_digest(&record.record_digest, path)?;
    if digest_application_record(record) != record.record_digest {
        return Err(FolderbaseError::InvalidRecord {
            path: path.to_path_buf(),
            message: "template application record digest mismatch".to_owned(),
        });
    }
    if (record.comparison.source == TemplateComparisonSource::Application)
        != record.comparison.application_id.is_some()
    {
        return Err(FolderbaseError::InvalidRecord {
            path: path.to_path_buf(),
            message: "comparison source and application id disagree".to_owned(),
        });
    }
    let mut seen = BTreeSet::new();
    for created in &record.created_paths {
        validate_record_path(&created.path, &mut seen, path)?;
        match created.kind {
            TemplateArtifactKind::Directory
                if created.bytes.is_none() && created.sha256.is_none() => {}
            TemplateArtifactKind::Text
                if created.bytes.is_some()
                    && created.sha256.as_deref().is_some_and(valid_sha256) => {}
            _ => {
                return Err(FolderbaseError::InvalidRecord {
                    path: path.to_path_buf(),
                    message: "created path metadata does not match its type".to_owned(),
                });
            }
        }
    }
    for preserved in &record.preserved_targets {
        validate_record_path(&preserved.path, &mut seen, path)?;
        match preserved.kind {
            TemplateArtifactKind::Directory
                if preserved.bytes.is_none() && preserved.sha256.is_none() => {}
            TemplateArtifactKind::Text
                if preserved.bytes.is_some()
                    && preserved.sha256.as_deref().is_some_and(valid_sha256) => {}
            _ => {
                return Err(FolderbaseError::InvalidRecord {
                    path: path.to_path_buf(),
                    message: "preserved target metadata does not match its type".to_owned(),
                });
            }
        }
    }
    Ok(())
}

fn validate_record_path(
    relative: &Path,
    seen: &mut BTreeSet<String>,
    record_path: &Path,
) -> Result<()> {
    ensure_safe_relative(relative).map_err(|_| FolderbaseError::InvalidRecord {
        path: record_path.to_path_buf(),
        message: format!("unsafe application path: {}", relative.display()),
    })?;
    let text = path_text(relative);
    if !seen.insert(text.case_fold().collect::<String>()) {
        return Err(FolderbaseError::InvalidRecord {
            path: record_path.to_path_buf(),
            message: format!("duplicate application path: {text}"),
        });
    }
    Ok(())
}

fn validate_digest(digest: &TemplatePlanDigest, path: &Path) -> Result<()> {
    if digest.algorithm != "sha256" || !valid_sha256(&digest.digest) {
        return Err(FolderbaseError::InvalidRecord {
            path: path.to_path_buf(),
            message: "invalid sha256 digest".to_owned(),
        });
    }
    Ok(())
}

fn valid_sha256(digest: &str) -> bool {
    digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn required_string<'a>(value: &'a Value, path: &[&str], source: &Path) -> Result<&'a str> {
    let mut current = value;
    for component in path {
        current = current
            .get(*component)
            .ok_or_else(|| FolderbaseError::InvalidRecord {
                path: source.to_path_buf(),
                message: format!("missing manifest field {}", path.join(".")),
            })?;
    }
    current
        .as_str()
        .ok_or_else(|| FolderbaseError::InvalidRecord {
            path: source.to_path_buf(),
            message: format!("manifest field {} is not a string", path.join(".")),
        })
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn digest_application_record(record: &TemplateApplicationRecord) -> TemplatePlanDigest {
    let dto = json!({
        "$schema": record.schema,
        "protocol_version": record.protocol_version,
        "id": record.id,
        "folderbase_id": record.folderbase_id,
        "state": record.state,
        "template": record.template,
        "comparison": record.comparison,
        "applied_at": record.applied_at,
        "created_paths": record.created_paths,
        "preserved_targets": record.preserved_targets,
        "plan_digest": record.plan_digest,
    });
    TemplatePlanDigest {
        algorithm: "sha256".to_owned(),
        digest: sha256_bytes(
            &serde_json::to_vec(&dto).expect("canonical application record DTO serializes"),
        ),
    }
}

fn path_text(path: &Path) -> String {
    path.to_str()
        .expect("validated template paths are UTF-8")
        .to_owned()
}

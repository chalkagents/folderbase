use std::{
    collections::HashMap,
    fs,
    io::Read,
    path::{Path, PathBuf},
};

use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt};
use cap_std::fs::{Dir, OpenOptions};
use chrono::DateTime;
use serde_json::Value;
use sha2::{Digest, Sha256};
use uuid::Uuid;
use walkdir::WalkDir;

use crate::{
    FolderbaseError, Result, ValidationFinding, ValidationLevel, ValidationReport,
    ValidationSeverity,
    root_attestation::{
        MAX_FOLDERBASE_MANIFEST_BYTES, ManifestProtocolProfile, attest_folderbase_root,
        decode_manifest_protocol_profile,
    },
};

const MANIFEST: &str = ".folderbase/manifest.json";

/// Validate a folderbase without modifying or repairing it.
pub fn validate(root: impl AsRef<Path>, level: ValidationLevel) -> Result<ValidationReport> {
    let root = canonical_directory(root.as_ref())?;
    let root_file = fs::File::open(&root).map_err(|source| FolderbaseError::io(&root, source))?;
    let root_dir = Dir::from_std_file(root_file);
    let mut findings = Findings::default();

    let manifest_path = Path::new(MANIFEST);
    let manifest = match safe_discovery_file(&root, &root_dir, manifest_path)? {
        DiscoveryFile::Missing => {
            findings.error(
                "missing_manifest",
                Some(PathBuf::from(MANIFEST)),
                "A folderbase root must contain .folderbase/manifest.json.",
            );
            None
        }
        DiscoveryFile::Symlink => {
            findings.error(
                "discovery_file_symlink",
                Some(PathBuf::from(MANIFEST)),
                "The manifest must be a regular file inside the folderbase root, not a symlink.",
            );
            None
        }
        DiscoveryFile::Regular => {
            let encoded = read_cap_bytes_bounded(
                &root,
                &root_dir,
                manifest_path,
                MAX_FOLDERBASE_MANIFEST_BYTES,
            )?;
            match decode_manifest_protocol_profile(&encoded) {
                Ok((manifest, _, _, profile)) => match attest_folderbase_root(&root) {
                    Ok(attestation)
                        if attestation.manifest_sha256
                            == format!("{:x}", Sha256::digest(&encoded)) =>
                    {
                        Some((manifest, profile))
                    }
                    Ok(_) => {
                        findings.error(
                            "manifest_changed_during_validation",
                            Some(PathBuf::from(MANIFEST)),
                            "The manifest changed while validation was reading it.",
                        );
                        None
                    }
                    Err(source) => {
                        findings.error(
                            source.code(),
                            Some(PathBuf::from(MANIFEST)),
                            source.to_string(),
                        );
                        None
                    }
                },
                Err(source) => {
                    findings.error(
                        source.code(),
                        Some(PathBuf::from(MANIFEST)),
                        source.to_string(),
                    );
                    None
                }
            }
        }
    };

    if let Some((manifest, profile)) = manifest.as_ref() {
        if profile.requires_legacy_root_files() {
            validate_legacy_root_files(&root, &root_dir, &mut findings)?;
        }
        validate_manifest(&root, &root_dir, manifest, profile, &mut findings);
    }

    let known_objects = validate_objects(&root, &root_dir, level, &mut findings)?;
    validate_relationships(&known_objects, &mut findings);
    validate_record_states(
        &root,
        &root_dir,
        ".folderbase/migrations",
        "plan.json",
        &[
            "analyzing",
            "questions",
            "proposed",
            "approved",
            "applying",
            "verified",
            "rejected",
            "rolled_back",
        ],
        "migration",
        &mut findings,
    )?;
    validate_record_states(
        &root,
        &root_dir,
        ".folderbase/changesets",
        ".json",
        &[
            "proposed",
            "approved",
            "applying",
            "applied",
            "conflicted",
            "rejected",
        ],
        "change_set",
        &mut findings,
    )?;

    findings.sort();
    let valid = !findings
        .items
        .iter()
        .any(|finding| finding.severity == ValidationSeverity::Error);

    Ok(ValidationReport {
        root,
        level,
        valid,
        findings: findings.items,
    })
}

fn validate_legacy_root_files(root: &Path, root_dir: &Dir, findings: &mut Findings) -> Result<()> {
    let entry_path = Path::new("FOLDERBASE.md");
    match safe_discovery_file(root, root_dir, entry_path)? {
        DiscoveryFile::Missing => findings.error(
            "missing_folderbase_entry",
            Some(entry_path.to_path_buf()),
            "A legacy Folderbase root must contain FOLDERBASE.md.",
        ),
        DiscoveryFile::Symlink => findings.error(
            "discovery_file_symlink",
            Some(entry_path.to_path_buf()),
            "Legacy FOLDERBASE.md must be a regular file inside the Folderbase root.",
        ),
        DiscoveryFile::Regular => match read_cap_string(root, root_dir, entry_path) {
            Ok(contents) => validate_folderbase_entry(&contents, findings),
            Err(source) => findings.error(
                "folderbase_entry_not_utf8",
                Some(entry_path.to_path_buf()),
                format!("Legacy FOLDERBASE.md must be readable UTF-8 Markdown: {source}"),
            ),
        },
    }
    let ignore_path = Path::new(".folderbaseignore");
    match safe_discovery_file(root, root_dir, ignore_path)? {
        DiscoveryFile::Missing => findings.error(
            "missing_ignore_file",
            Some(ignore_path.to_path_buf()),
            "A legacy Folderbase root must contain .folderbaseignore.",
        ),
        DiscoveryFile::Symlink => findings.error(
            "discovery_file_symlink",
            Some(ignore_path.to_path_buf()),
            "Legacy .folderbaseignore must be a regular file inside the Folderbase root.",
        ),
        DiscoveryFile::Regular => {}
    }
    Ok(())
}

fn canonical_directory(path: &Path) -> Result<PathBuf> {
    if !path.is_dir() {
        return Err(FolderbaseError::InvalidRoot(path.to_path_buf()));
    }
    path.canonicalize()
        .map_err(|source| FolderbaseError::io(path, source))
}

enum DiscoveryFile {
    Missing,
    Symlink,
    Regular,
}

fn safe_discovery_file(root: &Path, root_dir: &Dir, path: &Path) -> Result<DiscoveryFile> {
    match root_dir.symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Ok(DiscoveryFile::Symlink),
        Ok(metadata) if metadata.is_file() => Ok(DiscoveryFile::Regular),
        Ok(_) => Ok(DiscoveryFile::Missing),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(DiscoveryFile::Missing),
        Err(source) => Err(FolderbaseError::io(root.join(path), source)),
    }
}

fn read_cap_string(root: &Path, root_dir: &Dir, path: &Path) -> Result<String> {
    let mut file = root_dir
        .open(path)
        .map_err(|source| FolderbaseError::io(root.join(path), source))?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .map_err(|source| FolderbaseError::io(root.join(path), source))?;
    Ok(contents)
}

fn read_cap_bytes_bounded(
    root: &Path,
    root_dir: &Dir,
    path: &Path,
    maximum_bytes: u64,
) -> Result<Vec<u8>> {
    let display = root.join(path);
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    let mut file = root_dir
        .open_with(path, &options)
        .map_err(|source| FolderbaseError::io(&display, source))?;
    let before = file
        .metadata()
        .map_err(|source| FolderbaseError::io(&display, source))?;
    if !before.is_file() || before.len() > maximum_bytes {
        return Err(FolderbaseError::InvalidRecord {
            path: display,
            message: "manifest is not a bounded regular file".to_owned(),
        });
    }
    let mut contents = Vec::new();
    file.by_ref()
        .take(maximum_bytes + 1)
        .read_to_end(&mut contents)
        .map_err(|source| FolderbaseError::io(&display, source))?;
    let after = file
        .metadata()
        .map_err(|source| FolderbaseError::io(&display, source))?;
    if contents.len() as u64 > maximum_bytes || before.len() != after.len() {
        return Err(FolderbaseError::InvalidRecord {
            path: display,
            message: "manifest exceeded its bound or changed while validation read it".to_owned(),
        });
    }
    Ok(contents)
}

fn read_json_record(
    root: &Path,
    root_dir: &Dir,
    path: &Path,
    code: &str,
    findings: &mut Findings,
) -> Result<Option<Value>> {
    let contents = read_cap_string(root, root_dir, path)?;
    match serde_json::from_str(&contents) {
        Ok(value) => Ok(Some(value)),
        Err(source) => {
            findings.error(
                code,
                Some(path.to_path_buf()),
                format!("JSON could not be parsed: {source}"),
            );
            Ok(None)
        }
    }
}

fn validate_folderbase_entry(contents: &str, findings: &mut Findings) {
    if !contents
        .lines()
        .find(|line| !line.trim().is_empty())
        .is_some_and(|line| line.trim_start().starts_with("# "))
    {
        findings.error(
            "missing_folderbase_title",
            Some(PathBuf::from("FOLDERBASE.md")),
            "FOLDERBASE.md must begin with a human-readable title.",
        );
    }

    for heading in [
        "## Purpose",
        "## Current state",
        "## Navigate",
        "## Operating rules",
        "## Unresolved work",
    ] {
        if !contents.lines().any(|line| line.trim() == heading) {
            findings.error(
                "missing_folderbase_entry_section",
                Some(PathBuf::from("FOLDERBASE.md")),
                format!("FOLDERBASE.md is missing the required {heading} section."),
            );
        }
    }
}

fn validate_manifest(
    root: &Path,
    root_dir: &Dir,
    manifest: &Value,
    profile: &ManifestProtocolProfile,
    findings: &mut Findings,
) {
    let Some(record) = manifest.as_object() else {
        findings.error(
            "manifest_not_object",
            Some(PathBuf::from(MANIFEST)),
            "The manifest root must be a JSON object.",
        );
        return;
    };

    match record
        .get("protocol_version")
        .and_then(Value::as_str)
        .map(protocol_compatibility)
    {
        Some(ProtocolCompatibility::Supported) => {}
        Some(ProtocolCompatibility::FutureMinor) => findings.warning(
            "future_protocol_minor",
            Some(PathBuf::from(MANIFEST)),
            "This folderbase uses a newer 0.x protocol minor. Known 0.1 fields were validated and unknown fields were preserved.",
        ),
        Some(ProtocolCompatibility::Unsupported) => findings.error(
            "unsupported_protocol_version",
            Some(PathBuf::from(MANIFEST)),
            "protocol_version must be a supported semantic 0.x version.",
        ),
        None => findings.error(
            "missing_protocol_version",
            Some(PathBuf::from(MANIFEST)),
            "protocol_version is required.",
        ),
    }

    let Some(folderbase) = record.get("folderbase").and_then(Value::as_object) else {
        findings.error(
            "missing_folderbase_record",
            Some(PathBuf::from(MANIFEST)),
            "folderbase must be a JSON object.",
        );
        return;
    };

    match folderbase.get("id").and_then(Value::as_str) {
        Some(id)
            if id
                .strip_prefix("folderbase_")
                .is_some_and(|uuid| Uuid::parse_str(uuid).is_ok()) => {}
        _ => findings.error(
            "invalid_folderbase_id",
            Some(PathBuf::from(MANIFEST)),
            "folderbase.id must be a non-empty identifier prefixed with folderbase_.",
        ),
    }
    require_nonempty_string(folderbase, "name", "missing_folderbase_name", findings);
    require_enum(
        folderbase,
        "kind",
        &[
            "person",
            "organization",
            "engagement",
            "project",
            "customer",
            "temporary",
            "custom",
        ],
        "invalid_folderbase_kind",
        findings,
    );
    require_enum(
        folderbase,
        "status",
        &["active", "paused", "archived"],
        "invalid_folderbase_status",
        findings,
    );

    match folderbase.get("created_at").and_then(Value::as_str) {
        Some(created_at) if DateTime::parse_from_rfc3339(created_at).is_ok() => {}
        _ => findings.error(
            "invalid_created_at",
            Some(PathBuf::from(MANIFEST)),
            "folderbase.created_at must be an RFC 3339 timestamp.",
        ),
    }

    if profile.requires_legacy_root_files() {
        match folderbase.get("entry").and_then(Value::as_str) {
            Some(entry) => {
                if entry != "FOLDERBASE.md" {
                    findings.error(
                        "noncanonical_folderbase_entry",
                        Some(PathBuf::from(MANIFEST)),
                        "folderbase.entry must point to the canonical FOLDERBASE.md entry point.",
                    );
                }
                validate_declared_path(
                    root,
                    root_dir,
                    entry,
                    true,
                    true,
                    "folderbase.entry",
                    findings,
                );
            }
            None => findings.error(
                "missing_folderbase_entry_field",
                Some(PathBuf::from(MANIFEST)),
                "folderbase.entry is required.",
            ),
        }
    }

    if let Some(adapters) = record.get("adapters") {
        let Some(adapters) = adapters.as_array() else {
            findings.error(
                "invalid_adapters",
                Some(PathBuf::from(MANIFEST)),
                "adapters must be an array when present.",
            );
            return;
        };
        for (index, adapter) in adapters.iter().enumerate() {
            if adapter
                .get("agent")
                .and_then(Value::as_str)
                .is_none_or(|agent| agent.trim().is_empty())
            {
                findings.error(
                    "invalid_adapter_agent",
                    Some(PathBuf::from(MANIFEST)),
                    format!("adapters[{index}].agent must be a non-empty string."),
                );
            }
            match adapter.get("path").and_then(Value::as_str) {
                Some(path) => {
                    validate_declared_path(
                        root,
                        root_dir,
                        path,
                        true,
                        true,
                        &format!("adapters[{index}].path"),
                        findings,
                    );
                }
                None => findings.error(
                    "missing_adapter_path",
                    Some(PathBuf::from(MANIFEST)),
                    format!("adapters[{index}].path is required."),
                ),
            }
        }
    }

    let Some(policies) = record.get("policies").and_then(Value::as_object) else {
        findings.error(
            "missing_policies",
            Some(PathBuf::from(MANIFEST)),
            "policies must be a JSON object.",
        );
        return;
    };
    require_enum_at(
        policies,
        "availability",
        &["keep_local", "managed", "cloud_only"],
        "invalid_availability_policy",
        findings,
    );
    require_enum_at(
        policies,
        "structural_changes",
        &["suggest", "approve", "autonomous"],
        "invalid_structural_policy",
        findings,
    );
    require_enum_at(
        policies,
        "archive",
        &["manual", "approve", "automatic"],
        "invalid_archive_policy",
        findings,
    );
    require_enum_at(
        policies,
        "cloud_sync",
        &["disabled", "enabled"],
        "invalid_cloud_sync_policy",
        findings,
    );
}

#[derive(Default)]
struct KnownObjects {
    ids: HashMap<String, PathBuf>,
    relationships: Vec<PendingRelationship>,
}

struct PendingRelationship {
    record_path: PathBuf,
    target: String,
}

fn validate_objects(
    root: &Path,
    root_dir: &Dir,
    level: ValidationLevel,
    findings: &mut Findings,
) -> Result<KnownObjects> {
    let relative_object_root = Path::new(".folderbase/objects");
    match root_dir.symlink_metadata(relative_object_root) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            findings.error(
                "protocol_directory_invalid",
                Some(relative_object_root.to_path_buf()),
                ".folderbase/objects must be a directory inside the folderbase root, not a symlink.",
            );
            return Ok(KnownObjects::default());
        }
        Ok(_) => {}
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
            return Ok(KnownObjects::default());
        }
        Err(source) => return Err(FolderbaseError::io(root.join(relative_object_root), source)),
    }
    let object_root = root.join(relative_object_root);

    let mut records = collect_files(&object_root, |path| {
        path.extension().and_then(|extension| extension.to_str()) == Some("json")
    })?;
    records.sort();

    let mut known = KnownObjects::default();
    for record_path in records {
        let Some(relative_record) = relative_to(root, &record_path) else {
            findings.error(
                "protocol_record_escapes_root",
                None,
                "An object metadata record was discovered outside the folderbase root.",
            );
            continue;
        };
        let Some(record) = read_json_record(
            root,
            root_dir,
            &relative_record,
            "object_json_invalid",
            findings,
        )?
        else {
            continue;
        };
        let Some(object) = record.as_object() else {
            findings.error(
                "object_not_object",
                Some(relative_record),
                "Object metadata must be a JSON object.",
            );
            continue;
        };

        let id = match object.get("id").and_then(Value::as_str) {
            Some(id) if valid_prefixed_uuid(id, "obj_") => {
                if let Some(first_path) = known.ids.insert(id.to_owned(), relative_record.clone()) {
                    findings.error(
                        "duplicate_object_id",
                        Some(relative_record.clone()),
                        format!(
                            "Object ID {id} is already declared in {}.",
                            first_path.display()
                        ),
                    );
                }
                Some(id.to_owned())
            }
            _ => {
                findings.error(
                    "invalid_object_id",
                    Some(relative_record.clone()),
                    "Object id must be a non-empty identifier prefixed with obj_.",
                );
                None
            }
        };

        if !object
            .get("type")
            .and_then(Value::as_str)
            .is_some_and(is_protocol_token)
        {
            findings.error(
                "invalid_object_type",
                Some(relative_record.clone()),
                "Object type must be a non-empty lowercase protocol token.",
            );
        }

        let lifecycle = object.get("lifecycle").and_then(Value::as_object);
        let status = lifecycle
            .and_then(|lifecycle| lifecycle.get("status"))
            .and_then(Value::as_str);
        if !matches!(
            status,
            Some("draft" | "canonical" | "superseded" | "archived" | "deleted")
        ) {
            findings.error(
                "invalid_object_lifecycle",
                Some(relative_record.clone()),
                "lifecycle.status must be a supported object lifecycle.",
            );
        }
        if let Some(superseded_by) = lifecycle
            .and_then(|lifecycle| lifecycle.get("superseded_by"))
            .and_then(Value::as_str)
            && !valid_prefixed_uuid(superseded_by, "obj_")
        {
            findings.error(
                "invalid_superseded_by",
                Some(relative_record.clone()),
                "lifecycle.superseded_by must be an object identifier.",
            );
        }
        if status == Some("superseded")
            && lifecycle
                .and_then(|value| value.get("superseded_by"))
                .is_none()
        {
            findings.error(
                "missing_superseded_by",
                Some(relative_record.clone()),
                "A superseded object must identify its replacement.",
            );
        }
        if status == Some("archived") {
            for field in ["remote_size", "expected_restore_size"] {
                if lifecycle
                    .and_then(|value| value.get(field))
                    .and_then(Value::as_u64)
                    .is_none()
                {
                    findings.error(
                        "missing_archive_size",
                        Some(relative_record.clone()),
                        format!("An archived object requires lifecycle.{field}."),
                    );
                }
            }
        }

        let provenance = object.get("provenance").and_then(Value::as_object);
        if provenance.is_none() {
            findings.error(
                "missing_object_provenance",
                Some(relative_record.clone()),
                "Object provenance must be a JSON object.",
            );
        } else {
            let created_at = provenance
                .and_then(|value| value.get("created_at"))
                .and_then(Value::as_str);
            if created_at.is_none_or(|value| DateTime::parse_from_rfc3339(value).is_err()) {
                findings.error(
                    "invalid_object_created_at",
                    Some(relative_record.clone()),
                    "provenance.created_at must be an RFC 3339 timestamp.",
                );
            }
            if provenance
                .and_then(|value| value.get("source"))
                .and_then(Value::as_str)
                .is_none_or(|source| source.trim().is_empty())
            {
                findings.error(
                    "invalid_object_source",
                    Some(relative_record.clone()),
                    "provenance.source must be a non-empty string.",
                );
            }
            if let Some(source_path) = provenance
                .and_then(|value| value.get("source_path"))
                .and_then(Value::as_str)
            {
                validate_declared_path(
                    root,
                    root_dir,
                    source_path,
                    false,
                    false,
                    "provenance.source_path",
                    findings,
                );
            }
        }

        let object_path = object.get("path").and_then(Value::as_str);
        if let Some(path) = object_path {
            let materialized = validate_declared_path(
                root,
                root_dir,
                path,
                !matches!(status, Some("archived" | "deleted")),
                false,
                "object.path",
                findings,
            );
            if materialized && level == ValidationLevel::ContentIntegrity {
                validate_content_digest(root, root_dir, path, object, &relative_record, findings)?;
            }
        } else {
            findings.error(
                "missing_object_path",
                Some(relative_record.clone()),
                "Object path is required.",
            );
        }

        if let Some(relationships) = object.get("relationships") {
            if let Some(relationships) = relationships.as_array() {
                for (index, relationship) in relationships.iter().enumerate() {
                    if !relationship
                        .get("type")
                        .and_then(Value::as_str)
                        .is_some_and(is_protocol_token)
                    {
                        findings.error(
                            "invalid_relationship_type",
                            Some(relative_record.clone()),
                            format!(
                                "relationships[{index}].type must be a lowercase protocol token."
                            ),
                        );
                    }

                    let target = relationship.get("target").and_then(Value::as_str);
                    let external = relationship.get("external").and_then(Value::as_object);
                    match (target, external) {
                        (Some(target), None) if valid_prefixed_uuid(target, "obj_") => {
                            known.relationships.push(PendingRelationship {
                                record_path: relative_record.clone(),
                                target: target.to_owned(),
                            });
                        }
                        (Some(_), None) => findings.error(
                            "invalid_relationship_target",
                            Some(relative_record.clone()),
                            format!(
                                "relationships[{index}].target must be an object identifier."
                            ),
                        ),
                        (None, Some(external))
                            if external
                                .get("kind")
                                .and_then(Value::as_str)
                                .is_some_and(|value| !value.trim().is_empty())
                                && external
                                    .get("id")
                                    .and_then(Value::as_str)
                                    .is_some_and(|value| !value.trim().is_empty()) =>
                        {
                            // External relationships are informational and
                            // never grant local access or require resolution.
                        }
                        (None, Some(_)) => findings.error(
                            "invalid_external_relationship",
                            Some(relative_record.clone()),
                            format!(
                                "relationships[{index}].external requires non-empty kind and id."
                            ),
                        ),
                        _ => findings.error(
                            "ambiguous_relationship_target",
                            Some(relative_record.clone()),
                            format!(
                                "relationships[{index}] must contain exactly one of target or external."
                            ),
                        ),
                    }
                }
            } else {
                findings.error(
                    "invalid_relationships",
                    Some(relative_record.clone()),
                    "relationships must be an array.",
                );
            }
        }

        let _ = id;
    }
    Ok(known)
}

fn validate_relationships(known: &KnownObjects, findings: &mut Findings) {
    for relationship in &known.relationships {
        if !known.ids.contains_key(&relationship.target) {
            findings.error(
                "unresolved_relationship_target",
                Some(relationship.record_path.clone()),
                format!(
                    "Relationship target {} does not name a local object or an explicit external target.",
                    relationship.target
                ),
            );
        }
    }
}

fn valid_prefixed_uuid(value: &str, prefix: &str) -> bool {
    value
        .strip_prefix(prefix)
        .is_some_and(|uuid| Uuid::parse_str(uuid).is_ok())
}

fn is_protocol_token(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes.next().is_some_and(|byte| byte.is_ascii_lowercase())
        && bytes.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

fn validate_content_digest(
    root: &Path,
    root_dir: &Dir,
    relative_path: &str,
    object: &serde_json::Map<String, Value>,
    record_path: &Path,
    findings: &mut Findings,
) -> Result<()> {
    let Some(content) = object.get("content").and_then(Value::as_object) else {
        findings.error(
            "missing_content_digest",
            Some(record_path.to_path_buf()),
            "Content-integrity validation requires content metadata with a sha256 digest.",
        );
        return Ok(());
    };
    let algorithm = content.get("algorithm").and_then(Value::as_str);
    let digest = content.get("digest").and_then(Value::as_str);
    match (algorithm, digest) {
        (Some("sha256"), Some(expected)) => {
            let actual = sha256_file(root, root_dir, Path::new(relative_path))?;
            if !actual.eq_ignore_ascii_case(expected) {
                findings.error(
                    "content_digest_mismatch",
                    Some(PathBuf::from(relative_path)),
                    format!("Expected sha256 {expected}, found {actual}."),
                );
            }
        }
        (Some(other), _) => findings.error(
            "unsupported_digest_algorithm",
            Some(record_path.to_path_buf()),
            format!("Digest algorithm {other:?} is not supported."),
        ),
        _ => findings.error(
            "missing_content_digest",
            Some(record_path.to_path_buf()),
            "Content-integrity validation requires a sha256 digest.",
        ),
    }
    Ok(())
}

fn sha256_file(root: &Path, root_dir: &Dir, path: &Path) -> Result<String> {
    let mut file = root_dir
        .open(path)
        .map_err(|source| FolderbaseError::io(root.join(path), source))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|source| FolderbaseError::io(root.join(path), source))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn validate_record_states(
    root: &Path,
    root_dir: &Dir,
    relative_root: &str,
    filename_match: &str,
    allowed: &[&str],
    record_kind: &str,
    findings: &mut Findings,
) -> Result<()> {
    let relative_root_path = Path::new(relative_root);
    match root_dir.symlink_metadata(relative_root_path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            findings.error(
                "protocol_directory_invalid",
                Some(relative_root_path.to_path_buf()),
                format!(
                    "{relative_root} must be a directory inside the folderbase root, not a symlink."
                ),
            );
            return Ok(());
        }
        Ok(_) => {}
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(source) => return Err(FolderbaseError::io(root.join(relative_root_path), source)),
    }

    let records_root = root.join(relative_root);
    let mut records = collect_files(&records_root, |path| {
        if filename_match.starts_with('.') {
            path.extension().and_then(|extension| extension.to_str())
                == Some(filename_match.trim_start_matches('.'))
        } else {
            path.file_name().and_then(|name| name.to_str()) == Some(filename_match)
        }
    })?;
    records.sort();

    for record_path in records {
        let Some(relative_record) = relative_to(root, &record_path) else {
            findings.error(
                "protocol_record_escapes_root",
                None,
                format!("A {record_kind} record was discovered outside the folderbase root."),
            );
            continue;
        };
        let Some(record) = read_json_record(
            root,
            root_dir,
            &relative_record,
            "state_record_json_invalid",
            findings,
        )?
        else {
            continue;
        };
        let Some(record) = record.as_object() else {
            findings.error(
                "state_record_not_object",
                Some(relative_record),
                format!("{record_kind} metadata must be a JSON object."),
            );
            continue;
        };
        let required = if record_kind == "migration" {
            &[
                "protocol_version",
                "id",
                "state",
                "source_inventory",
                "base_folderbase_version",
                "questions",
                "proposed_folderbases",
                "operations",
                "exclusions",
                "storage_impact",
                "rollback",
            ][..]
        } else {
            &["id", "checkout_id", "base_version", "operations", "status"][..]
        };
        for field in required {
            if !record.contains_key(*field) {
                findings.error(
                    "missing_record_field",
                    Some(relative_record.clone()),
                    format!("{record_kind}.{field} is required."),
                );
            }
        }
        if record
            .get("operations")
            .is_some_and(|value| !value.is_array())
        {
            findings.error(
                "invalid_record_operations",
                Some(relative_record.clone()),
                format!("{record_kind}.operations must be an array."),
            );
        }

        let state_field = if record_kind == "migration" {
            "state"
        } else {
            "status"
        };
        let status = record.get(state_field).and_then(Value::as_str);
        if !status.is_some_and(|status| allowed.contains(&status)) {
            findings.error(
                "invalid_record_state",
                Some(relative_record),
                format!(
                    "{record_kind}.{state_field} must be one of {}.",
                    allowed.join(", ")
                ),
            );
        }
    }
    Ok(())
}

fn collect_files(root: &Path, include: impl Fn(&Path) -> bool) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    for entry in WalkDir::new(root).follow_links(false) {
        let entry = entry.map_err(|source| {
            let path = source
                .path()
                .map(Path::to_path_buf)
                .unwrap_or_else(|| root.to_path_buf());
            FolderbaseError::io(path, std::io::Error::other(source.to_string()))
        })?;
        if entry.file_type().is_file() && include(entry.path()) {
            files.push(entry.path().to_path_buf());
        }
    }
    Ok(files)
}

fn validate_declared_path(
    root: &Path,
    root_dir: &Dir,
    declared: &str,
    require_materialized: bool,
    require_regular_file: bool,
    field: &str,
    findings: &mut Findings,
) -> bool {
    let relative = PathBuf::from(declared);
    if !is_safe_protocol_path(declared) {
        findings.error(
            "unsafe_protocol_path",
            Some(relative),
            format!(
                "{field} must be a portable relative path that cannot escape the folderbase root."
            ),
        );
        return false;
    }

    match root_dir.symlink_metadata(&relative) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            findings.error(
                "declared_path_symlink",
                Some(relative.clone()),
                format!("{field} must not resolve through a symlink."),
            );
            false
        }
        Ok(metadata) if require_regular_file && !metadata.is_file() => {
            findings.error(
                "declared_path_not_file",
                Some(relative.clone()),
                format!("{field} must resolve to a regular file."),
            );
            false
        }
        Ok(_) => true,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
            if require_materialized {
                findings.error(
                    "declared_path_missing",
                    Some(relative),
                    format!("{field} does not resolve to materialized content."),
                );
            }
            false
        }
        Err(source) => {
            findings.error(
                "declared_path_unreadable",
                Some(relative),
                format!(
                    "{field} could not be resolved within {}: {source}",
                    root.display()
                ),
            );
            false
        }
    }
}

fn is_safe_protocol_path(path: &str) -> bool {
    if path.is_empty()
        || path.starts_with('/')
        || path.starts_with('\\')
        || path.contains('\\')
        || path.contains('\0')
    {
        return false;
    }
    let mut segments = path.split('/');
    let Some(first) = segments.next() else {
        return false;
    };
    if first.ends_with(':') || first.is_empty() || matches!(first, "." | "..") {
        return false;
    }
    segments.all(|segment| !segment.is_empty() && !matches!(segment, "." | ".."))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProtocolCompatibility {
    Supported,
    FutureMinor,
    Unsupported,
}

fn protocol_compatibility(version: &str) -> ProtocolCompatibility {
    let mut version_parts = version.splitn(2, ['-', '+']);
    let numeric = version_parts.next().unwrap_or_default();
    if version_parts.next().is_some_and(|suffix| {
        suffix.is_empty()
            || !suffix
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
    }) {
        return ProtocolCompatibility::Unsupported;
    }

    let mut parts = numeric.split('.');
    let (Some(major), Some(minor), Some(patch), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return ProtocolCompatibility::Unsupported;
    };
    if [major, minor, patch]
        .iter()
        .any(|part| part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return ProtocolCompatibility::Unsupported;
    }
    let Ok(major) = major.parse::<u64>() else {
        return ProtocolCompatibility::Unsupported;
    };
    let Ok(minor) = minor.parse::<u64>() else {
        return ProtocolCompatibility::Unsupported;
    };
    match (major, minor) {
        (0, 1 | 5) => ProtocolCompatibility::Supported,
        (0, minor) if minor > 1 => ProtocolCompatibility::FutureMinor,
        _ => ProtocolCompatibility::Unsupported,
    }
}

fn require_nonempty_string(
    record: &serde_json::Map<String, Value>,
    field: &str,
    code: &str,
    findings: &mut Findings,
) {
    if record
        .get(field)
        .and_then(Value::as_str)
        .is_none_or(|value| value.trim().is_empty())
    {
        findings.error(
            code,
            Some(PathBuf::from(MANIFEST)),
            format!("folderbase.{field} must be a non-empty string."),
        );
    }
}

fn require_enum(
    record: &serde_json::Map<String, Value>,
    field: &str,
    allowed: &[&str],
    code: &str,
    findings: &mut Findings,
) {
    if !record
        .get(field)
        .and_then(Value::as_str)
        .is_some_and(|value| allowed.contains(&value))
    {
        findings.error(
            code,
            Some(PathBuf::from(MANIFEST)),
            format!("folderbase.{field} must be one of {}.", allowed.join(", ")),
        );
    }
}

fn require_enum_at(
    record: &serde_json::Map<String, Value>,
    field: &str,
    allowed: &[&str],
    code: &str,
    findings: &mut Findings,
) {
    if !record
        .get(field)
        .and_then(Value::as_str)
        .is_some_and(|value| allowed.contains(&value))
    {
        findings.error(
            code,
            Some(PathBuf::from(MANIFEST)),
            format!("policies.{field} must be one of {}.", allowed.join(", ")),
        );
    }
}

fn relative_to(root: &Path, path: &Path) -> Option<PathBuf> {
    path.strip_prefix(root).ok().map(Path::to_path_buf)
}

#[derive(Default)]
struct Findings {
    items: Vec<ValidationFinding>,
}

impl Findings {
    fn error(
        &mut self,
        code: impl Into<String>,
        path: Option<PathBuf>,
        message: impl Into<String>,
    ) {
        self.push(ValidationSeverity::Error, code, path, message);
    }

    fn warning(
        &mut self,
        code: impl Into<String>,
        path: Option<PathBuf>,
        message: impl Into<String>,
    ) {
        self.push(ValidationSeverity::Warning, code, path, message);
    }

    fn push(
        &mut self,
        severity: ValidationSeverity,
        code: impl Into<String>,
        path: Option<PathBuf>,
        message: impl Into<String>,
    ) {
        self.items.push(ValidationFinding {
            code: code.into(),
            severity,
            path,
            message: message.into(),
        });
    }

    fn sort(&mut self) {
        self.items.sort_by(|left, right| {
            left.code
                .cmp(&right.code)
                .then_with(|| left.path.cmp(&right.path))
                .then_with(|| left.message.cmp(&right.message))
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{InitializationOptions, initialize, plan_initialization};

    fn initialized_folderbase() -> tempfile::TempDir {
        let temp = tempfile::tempdir().unwrap();
        let plan = plan_initialization(temp.path(), InitializationOptions::default()).unwrap();
        initialize(&plan).unwrap();
        temp
    }

    #[test]
    fn initialized_folderbase_is_shallow_valid() {
        let temp = initialized_folderbase();
        let report = validate(temp.path(), ValidationLevel::Shallow).unwrap();
        assert!(report.valid, "{:?}", report.findings);
        assert!(
            report.findings.is_empty(),
            "the exact native 0.5 profile is supported without compatibility warnings: {:?}",
            report.findings
        );
    }

    #[test]
    fn v05_entry_extension_has_no_protocol_path_authority() {
        let temp = initialized_folderbase();
        let manifest_path = temp.path().join(MANIFEST);
        let mut manifest: Value =
            serde_json::from_str(&fs::read_to_string(&manifest_path).unwrap()).unwrap();
        manifest["folderbase"]["entry"] = Value::String("../outside.md".to_owned());
        fs::write(
            &manifest_path,
            serde_json::to_string_pretty(&manifest).unwrap(),
        )
        .unwrap();

        let report = validate(temp.path(), ValidationLevel::Shallow).unwrap();
        assert!(report.valid, "{:?}", report.findings);
    }

    #[test]
    fn content_integrity_reports_a_digest_mismatch() {
        let temp = initialized_folderbase();
        fs::create_dir_all(temp.path().join(".folderbase/objects")).unwrap();
        fs::write(temp.path().join("note.md"), "changed bytes").unwrap();
        fs::write(
            temp.path().join(".folderbase/objects/obj_test.json"),
            serde_json::to_string_pretty(&serde_json::json!({
                "id": "obj_019f9b75-4f42-7f65-a012-2bfecdd8c473",
                "type": "file",
                "path": "note.md",
                "content": {
                    "algorithm": "sha256",
                    "digest": "000000"
                },
                "lifecycle": {
                    "status": "canonical"
                },
                "provenance": {
                    "created_at": "2026-07-25T00:00:00Z",
                    "source": "test"
                },
                "relationships": []
            }))
            .unwrap(),
        )
        .unwrap();

        let report = validate(temp.path(), ValidationLevel::ContentIntegrity).unwrap();
        assert!(!report.valid);
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.code == "content_digest_mismatch")
        );
    }

    #[test]
    fn content_integrity_requires_a_digest() {
        let temp = initialized_folderbase();
        fs::create_dir_all(temp.path().join(".folderbase/objects")).unwrap();
        fs::write(temp.path().join("note.md"), "durable knowledge").unwrap();
        fs::write(
            temp.path().join(".folderbase/objects/obj_test.json"),
            serde_json::to_string_pretty(&serde_json::json!({
                "id": "obj_019f9b75-4f42-7f65-a012-2bfecdd8c474",
                "type": "file",
                "path": "note.md",
                "lifecycle": {
                    "status": "canonical"
                },
                "provenance": {
                    "created_at": "2026-07-25T00:00:00Z",
                    "source": "test"
                },
                "relationships": []
            }))
            .unwrap(),
        )
        .unwrap();

        let report = validate(temp.path(), ValidationLevel::ContentIntegrity).unwrap();
        assert!(!report.valid);
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.code == "missing_content_digest")
        );
    }

    #[test]
    fn optional_v05_folderbase_md_has_no_required_sections() {
        let temp = initialized_folderbase();
        let entry_path = temp.path().join("FOLDERBASE.md");
        fs::write(entry_path, "# Any user narrative\n").unwrap();

        let report = validate(temp.path(), ValidationLevel::Shallow).unwrap();
        assert!(report.valid, "{:?}", report.findings);
    }

    #[cfg(unix)]
    #[test]
    fn declared_symlink_is_invalid() {
        use std::os::unix::fs::symlink;

        let temp = initialized_folderbase();
        fs::create_dir_all(temp.path().join(".folderbase/objects")).unwrap();
        symlink("FOLDERBASE.md", temp.path().join("linked.md")).unwrap();
        fs::write(
            temp.path().join(".folderbase/objects/obj_test.json"),
            serde_json::to_string_pretty(&serde_json::json!({
                "id": "obj_019f9b75-4f42-7f65-a012-2bfecdd8c475",
                "type": "file",
                "path": "linked.md",
                "lifecycle": {
                    "status": "canonical"
                },
                "provenance": {
                    "created_at": "2026-07-25T00:00:00Z",
                    "source": "test"
                },
                "relationships": []
            }))
            .unwrap(),
        )
        .unwrap();

        let report = validate(temp.path(), ValidationLevel::Shallow).unwrap();
        assert!(!report.valid);
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.code == "declared_path_symlink")
        );
    }

    #[test]
    fn external_relationship_does_not_require_a_local_target() {
        let temp = initialized_folderbase();
        fs::create_dir_all(temp.path().join(".folderbase/objects")).unwrap();
        fs::write(temp.path().join("note.md"), "durable knowledge").unwrap();
        fs::write(
            temp.path().join(".folderbase/objects/obj_test.json"),
            serde_json::to_string_pretty(&serde_json::json!({
                "id": "obj_019f9b75-4f42-7f65-a012-2bfecdd8c476",
                "type": "file",
                "path": "note.md",
                "lifecycle": {
                    "status": "canonical"
                },
                "provenance": {
                    "created_at": "2026-07-25T00:00:00Z",
                    "source": "test"
                },
                "relationships": [{
                    "type": "belongs_to",
                    "external": {
                        "kind": "folderbase",
                        "id": "folderbase_remote"
                    }
                }]
            }))
            .unwrap(),
        )
        .unwrap();

        let report = validate(temp.path(), ValidationLevel::Shallow).unwrap();
        assert!(report.valid, "{:?}", report.findings);
    }

    #[test]
    fn future_minor_protocol_is_valid_with_a_warning() {
        let temp = initialized_folderbase();
        let manifest_path = temp.path().join(MANIFEST);
        let mut manifest: Value =
            serde_json::from_str(&fs::read_to_string(&manifest_path).unwrap()).unwrap();
        manifest["protocol_version"] = Value::String("0.2.0".to_owned());
        manifest["folderbase"]["entry"] = Value::String("FOLDERBASE.md".to_owned());
        fs::write(
            temp.path().join("FOLDERBASE.md"),
            "# Legacy Folderbase\n\n## Purpose\nTest compatibility.\n\n## Current state\nReady.\n\n## Navigate\nUse ordinary files.\n\n## Operating rules\nPreserve bytes.\n\n## Unresolved work\nNone.\n",
        )
        .unwrap();
        fs::write(temp.path().join(".folderbaseignore"), "").unwrap();
        fs::write(
            &manifest_path,
            serde_json::to_string_pretty(&manifest).unwrap(),
        )
        .unwrap();

        let report = validate(temp.path(), ValidationLevel::Shallow).unwrap();
        assert!(report.valid, "{:?}", report.findings);
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.code == "future_protocol_minor")
        );
    }

    #[test]
    fn migration_uses_state_and_requires_protocol_fields() {
        let temp = initialized_folderbase();
        let migration_root = temp.path().join(".folderbase/migrations/migration_test");
        fs::create_dir_all(&migration_root).unwrap();
        fs::write(
            migration_root.join("plan.json"),
            serde_json::to_string_pretty(&serde_json::json!({
                "state": "approved",
                "operations": []
            }))
            .unwrap(),
        )
        .unwrap();

        let report = validate(temp.path(), ValidationLevel::Shallow).unwrap();
        assert!(!report.valid);
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.code == "missing_record_field")
        );
        assert!(!report.findings.iter().any(|finding| {
            finding.code == "invalid_record_state" && finding.message.starts_with("migration.state")
        }));
    }

    #[test]
    fn validation_does_not_rewrite_unknown_manifest_fields() {
        let temp = initialized_folderbase();
        let manifest_path = temp.path().join(MANIFEST);
        let mut manifest: Value =
            serde_json::from_str(&fs::read_to_string(&manifest_path).unwrap()).unwrap();
        manifest["future_extension"] = serde_json::json!({ "kept": true });
        let original = serde_json::to_string_pretty(&manifest).unwrap();
        fs::write(&manifest_path, &original).unwrap();

        let report = validate(temp.path(), ValidationLevel::Shallow).unwrap();
        assert!(report.valid, "{:?}", report.findings);
        assert_eq!(fs::read_to_string(&manifest_path).unwrap(), original);
    }
}

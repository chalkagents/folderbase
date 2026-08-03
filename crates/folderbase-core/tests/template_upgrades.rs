use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use folderbase_core::{
    FolderbaseError, FolderbaseKind, InitializationOptions, TemplatePackage,
    TemplateStructuralChangeKind, apply_template_expansion,
    apply_template_expansion_with_expected_plan_digest, initialize, load_template,
    plan_initialization, plan_template_expansion, plan_template_initialization,
    template_application_history,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

fn write_package(
    registry: &Path,
    directory: &str,
    version: &str,
    kind: &str,
    artifacts: Vec<Value>,
    from: Option<&str>,
) -> TemplatePackage {
    write_package_with_id(
        registry,
        directory,
        "example.project",
        version,
        kind,
        artifacts,
        from,
    )
}

fn write_package_with_id(
    registry: &Path,
    directory: &str,
    id: &str,
    version: &str,
    kind: &str,
    artifacts: Vec<Value>,
    from: Option<&str>,
) -> TemplatePackage {
    let package_dir = registry.join(directory);
    fs::create_dir_all(&package_dir).expect("template package directory");
    let mut package = json!({
        "protocol_version": "0.2.0",
        "id": id,
        "version": version,
        "name": "Example project",
        "suggested_folderbase_kind": kind,
        "questions": [],
        "artifacts": artifacts,
        "upgrade_edges": []
    });
    if let Some(from) = from {
        package["upgrade_edges"] = json!([{ "from": from, "to": version }]);
    }
    fs::write(
        package_dir.join("template.json"),
        serde_json::to_vec_pretty(&package).expect("template JSON"),
    )
    .expect("write template");
    load_template(registry, id, version).expect("load template")
}

fn base_artifacts() -> Vec<Value> {
    vec![
        json!({
            "target": "FOLDERBASE.md",
            "kind": "text",
            "content": "# Example folderbase\n",
            "install": "create_if_missing"
        }),
        json!({
            "target": "Decisions",
            "kind": "directory",
            "install": "create_if_missing"
        }),
        json!({
            "target": "AGENTS.md",
            "kind": "text",
            "content": "Read FOLDERBASE.md before working here.\n",
            "install": "create_if_missing"
        }),
        json!({
            "target": ".folderbase/objects/project.json",
            "kind": "text",
            "content": "{\"relationships\":[{\"type\":\"references\",\"target\":\"FOLDERBASE.md\"}]}\n",
            "install": "create_if_missing"
        }),
    ]
}

fn additive_artifacts() -> Vec<Value> {
    let mut artifacts = base_artifacts();
    artifacts.extend([
        json!({
            "target": "Notes",
            "kind": "directory",
            "install": "create_if_missing"
        }),
        json!({
            "target": "References",
            "kind": "directory",
            "install": "create_if_missing"
        }),
        json!({
            "target": "References/README.md",
            "kind": "text",
            "content": "# References\n",
            "install": "create_if_missing"
        }),
    ]);
    artifacts
}

fn initialize_from_template(root: &Path, package: &TemplatePackage) {
    let plan = plan_template_initialization(
        root,
        InitializationOptions {
            name: Some("Example".to_owned()),
            kind: FolderbaseKind::Project,
            create_agent_adapters: false,
        },
        package,
        &BTreeMap::new(),
    )
    .expect("plan template adoption");
    initialize(&plan).expect("initialize template");
}

fn paths(paths: impl IntoIterator<Item = impl AsRef<Path>>) -> Vec<PathBuf> {
    let mut paths = paths
        .into_iter()
        .map(|path| path.as_ref().to_path_buf())
        .collect::<Vec<_>>();
    paths.sort();
    paths
}

fn copy_directory(source: &Path, destination: &Path) {
    fs::create_dir(destination).expect("copy destination");
    for entry in fs::read_dir(source).expect("copy source") {
        let entry = entry.expect("copy entry");
        let target = destination.join(entry.file_name());
        if entry.file_type().expect("copy entry type").is_dir() {
            copy_directory(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), target).expect("copy file");
        }
    }
}

fn rewrite_root_as_legacy_v01(root: &Path) {
    let manifest_path = root.join(".folderbase/manifest.json");
    let mut manifest: Value = serde_json::from_slice(&fs::read(&manifest_path).expect("manifest"))
        .expect("manifest JSON");
    manifest["$schema"] = json!("https://folderbase.ai/protocol/0.1/folderbase.schema.json");
    manifest["protocol_version"] = json!("0.1.0");
    manifest["folderbase"]["entry"] = json!("FOLDERBASE.md");
    manifest["policies"]
        .as_object_mut()
        .expect("policies")
        .remove("capture_ignore");
    fs::write(
        &manifest_path,
        format!("{}\n", serde_json::to_string_pretty(&manifest).unwrap()),
    )
    .expect("legacy manifest");
    fs::write(root.join("FOLDERBASE.md"), b"# Legacy narrative\n").expect("legacy entry");
    fs::write(root.join(".folderbaseignore"), b"node_modules/\n").expect("legacy ignore");
}

#[test]
fn default_v05_root_can_expand_a_template_without_a_root_narrative_prerequisite() {
    let folderbase = tempfile::tempdir().expect("ordinary Folderbase");
    let plan = plan_initialization(folderbase.path(), InitializationOptions::default())
        .expect("default initialization");
    initialize(&plan).expect("initialize ordinary root");
    assert!(!folderbase.path().join("FOLDERBASE.md").exists());

    let registry = tempfile::tempdir().expect("template registry");
    let target = write_package(
        registry.path(),
        "example-1.0.0",
        "1.0.0",
        "project",
        base_artifacts(),
        None,
    );
    let expansion = plan_template_expansion(folderbase.path(), &target, &BTreeMap::new())
        .expect("manifest-only 0.5 root can expand");
    let result = apply_template_expansion(&expansion).expect("apply expansion");

    assert_eq!(
        fs::read(folderbase.path().join("FOLDERBASE.md")).expect("template narrative"),
        b"# Example folderbase\n"
    );
    let record_path = folderbase
        .path()
        .join(result.application_record().expect("application record"));
    let mut record: Value =
        serde_json::from_slice(&fs::read(&record_path).expect("record")).expect("record JSON");
    assert_eq!(record["comparison"]["source"], "unmanaged");
    assert_eq!(record["comparison"]["version"], "0.0.0");
    assert!(record["comparison"]["application_id"].is_null());

    record["comparison"]["source"] = json!("origin");
    rewrite_record_digest(&mut record);
    fs::write(
        &record_path,
        serde_json::to_vec_pretty(&record).expect("forged origin"),
    )
    .expect("write forged record");
    let error = template_application_history(folderbase.path()).expect_err("forged origin");
    assert!(
        error.to_string().contains("missing manifest origin"),
        "only explicit unmanaged may root an untemplated lineage: {error}"
    );
}

#[test]
fn reviewed_template_digest_rejects_an_identical_root_replacement_between_processes() {
    let owner = tempfile::tempdir().expect("root owner");
    let root = owner.path().join("active");
    fs::create_dir(&root).expect("active root");
    let initialization =
        plan_initialization(&root, InitializationOptions::default()).expect("initialization plan");
    initialize(&initialization).expect("initialize active root");

    let registry = tempfile::tempdir().expect("template registry");
    let target = write_package(
        registry.path(),
        "replacement-proof",
        "1.0.0",
        "project",
        vec![json!({
            "target": "Notes/README.md",
            "kind": "text",
            "content": "# Notes\n",
            "install": "create_if_missing"
        })],
        None,
    );
    let reviewed =
        plan_template_expansion(&root, &target, &BTreeMap::new()).expect("review original root");

    let replacement = owner.path().join("replacement");
    copy_directory(&root, &replacement);
    fs::rename(&root, owner.path().join("detached")).expect("detach reviewed root");
    fs::rename(&replacement, &root).expect("install byte-identical replacement");

    let error = apply_template_expansion_with_expected_plan_digest(
        &root,
        &target,
        &BTreeMap::new(),
        reviewed.plan_digest().digest(),
    )
    .expect_err("a reviewed digest must not authorize a replacement root");

    assert!(matches!(
        error,
        FolderbaseError::TemplateExpansionPlanChanged { .. }
    ));
    assert!(!root.join("Notes/README.md").exists());
}

#[test]
fn legacy_roots_require_existing_provenance_instead_of_starting_unmanaged_lineage() {
    let registry = tempfile::tempdir().expect("template registry");
    let target = write_package(
        registry.path(),
        "example-1.0.0",
        "1.0.0",
        "project",
        base_artifacts(),
        None,
    );

    let untemplated = tempfile::tempdir().expect("untemplated legacy Folderbase");
    initialize(
        &plan_initialization(untemplated.path(), InitializationOptions::default())
            .expect("initialization"),
    )
    .expect("initialize");
    rewrite_root_as_legacy_v01(untemplated.path());
    let error = plan_template_expansion(untemplated.path(), &target, &BTreeMap::new())
        .expect_err("legacy roots cannot invent unmanaged lineage");
    assert!(
        error.to_string().contains("native protocol 0.5.0"),
        "legacy refusal should name the exact adoption boundary: {error}"
    );

    let originated = tempfile::tempdir().expect("templated legacy Folderbase");
    initialize_from_template(originated.path(), &target);
    rewrite_root_as_legacy_v01(originated.path());
    let next = write_package(
        registry.path(),
        "example-2.0.0",
        "2.0.0",
        "project",
        additive_artifacts(),
        Some("1.0.0"),
    );
    plan_template_expansion(originated.path(), &next, &BTreeMap::new())
        .expect("legacy roots retain explicit provenance-based expansion");
}

#[test]
fn legacy_roots_reject_an_existing_unmanaged_application_chain() {
    let folderbase = tempfile::tempdir().expect("ordinary Folderbase");
    initialize(
        &plan_initialization(folderbase.path(), InitializationOptions::default())
            .expect("initialization"),
    )
    .expect("initialize");
    let registry = tempfile::tempdir().expect("template registry");
    let target = write_package(
        registry.path(),
        "example-1.0.0",
        "1.0.0",
        "project",
        base_artifacts(),
        None,
    );
    let expansion = plan_template_expansion(folderbase.path(), &target, &BTreeMap::new())
        .expect("native unmanaged expansion");
    apply_template_expansion(&expansion).expect("native unmanaged application");

    rewrite_root_as_legacy_v01(folderbase.path());
    let error = template_application_history(folderbase.path())
        .expect_err("legacy profile cannot validate unmanaged-rooted history");
    assert!(
        error.to_string().contains("native protocol 0.5.0"),
        "legacy history refusal should name the exact adoption boundary: {error}"
    );
}

fn rewrite_record_digest(document: &mut Value) {
    let digest_input = json!({
        "$schema": document["$schema"],
        "protocol_version": document["protocol_version"],
        "id": document["id"],
        "folderbase_id": document["folderbase_id"],
        "state": document["state"],
        "template": document["template"],
        "comparison": document["comparison"],
        "applied_at": document["applied_at"],
        "created_paths": document["created_paths"],
        "preserved_targets": document["preserved_targets"],
        "plan_digest": document["plan_digest"],
    });
    let digest = format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&digest_input).expect("digest input"))
    );
    document["record_digest"]["digest"] = json!(digest);
}

#[test]
fn additive_upgrade_creates_only_absent_paths() {
    let registry = tempfile::tempdir().expect("registry");
    let folderbase = tempfile::tempdir().expect("folderbase");
    let origin = write_package(
        registry.path(),
        "v1",
        "1.0.0",
        "project",
        base_artifacts(),
        None,
    );
    let target = write_package(
        registry.path(),
        "v2",
        "1.1.0",
        "project",
        additive_artifacts(),
        Some("1.0.0"),
    );
    initialize_from_template(folderbase.path(), &origin);
    let manifest_before =
        fs::read(folderbase.path().join(".folderbase/manifest.json")).expect("origin manifest");

    let plan = plan_template_expansion(folderbase.path(), &target, &BTreeMap::new())
        .expect("plan additive expansion");

    assert_eq!(plan.comparison_version(), "1.0.0");
    assert_eq!(
        paths(plan.additions().iter().map(|addition| addition.path())),
        paths(["Notes", "References", "References/README.md"])
    );
    assert!(plan.blocked_paths().is_empty());
    assert!(plan.structural_changes().is_empty());
    assert!(
        !folderbase.path().join("Notes").exists(),
        "planning is read-only"
    );

    let applied = apply_template_expansion(&plan).expect("apply additive expansion");

    assert_eq!(
        paths(applied.created_paths()),
        paths(["Notes", "References", "References/README.md"])
    );
    assert!(applied.application_record().is_some());
    assert_eq!(
        fs::read(folderbase.path().join(".folderbase/manifest.json")).expect("manifest after"),
        manifest_before,
        "Template Origin must remain immutable"
    );
    let history = template_application_history(folderbase.path()).expect("application history");
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].template_id(), "example.project");
    assert_eq!(history[0].template_version(), "1.1.0");
    assert_eq!(history[0].comparison_version(), "1.0.0");
    assert_eq!(
        paths(history[0].created_paths()),
        paths(["Notes", "References", "References/README.md"])
    );
    assert_eq!(history[0].plan_digest().algorithm(), "sha256");
    assert_eq!(history[0].plan_digest().digest().len(), 64);
}

#[test]
fn additive_upgrade_preserves_conflicting_user_file_byte_for_byte() {
    let registry = tempfile::tempdir().expect("registry");
    let folderbase = tempfile::tempdir().expect("folderbase");
    let origin = write_package(
        registry.path(),
        "v1",
        "1.0.0",
        "project",
        base_artifacts(),
        None,
    );
    let target = write_package(
        registry.path(),
        "v2",
        "1.1.0",
        "project",
        additive_artifacts(),
        Some("1.0.0"),
    );
    initialize_from_template(folderbase.path(), &origin);
    fs::create_dir(folderbase.path().join("References")).expect("user References");
    let user_bytes = b"# My private references\nDo not replace this.\n";
    fs::write(folderbase.path().join("References/README.md"), user_bytes).expect("user file");

    let plan = plan_template_expansion(folderbase.path(), &target, &BTreeMap::new())
        .expect("plan around user file");

    assert_eq!(
        paths(plan.preserved_paths()),
        paths([
            ".folderbase/objects/project.json",
            "AGENTS.md",
            "FOLDERBASE.md",
            "Decisions",
            "References",
            "References/README.md",
        ])
    );
    apply_template_expansion(&plan).expect("apply non-conflicting additions");
    assert_eq!(
        fs::read(folderbase.path().join("References/README.md")).expect("preserved user file"),
        user_bytes
    );
}

#[test]
fn additive_upgrade_blocks_a_large_existing_template_target_without_reading_its_bytes() {
    let registry = tempfile::tempdir().expect("registry");
    let folderbase = tempfile::tempdir().expect("folderbase");
    let origin = write_package(
        registry.path(),
        "v1",
        "1.0.0",
        "project",
        base_artifacts(),
        None,
    );
    let target = write_package(
        registry.path(),
        "v2",
        "1.1.0",
        "project",
        additive_artifacts(),
        Some("1.0.0"),
    );
    initialize_from_template(folderbase.path(), &origin);
    fs::create_dir(folderbase.path().join("References")).expect("user References");
    let large_user_bytes = vec![b'x'; 1024 * 1024 + 1];
    fs::write(
        folderbase.path().join("References/README.md"),
        &large_user_bytes,
    )
    .expect("large user file");

    let plan = plan_template_expansion(folderbase.path(), &target, &BTreeMap::new())
        .expect("metadata-first plan around large user file");
    assert!(
        plan.blocked_paths()
            .contains(&PathBuf::from("References/README.md"))
    );
    assert!(matches!(
        apply_template_expansion(&plan),
        Err(FolderbaseError::TemplateExpansionBlocked)
    ));
    assert!(
        template_application_history(folderbase.path())
            .expect("no false application history")
            .is_empty()
    );
    assert_eq!(
        fs::metadata(folderbase.path().join("References/README.md"))
            .expect("large user file metadata")
            .len(),
        large_user_bytes.len() as u64
    );
}

#[test]
fn expansion_rejects_existing_case_folded_path_aliases() {
    let registry = tempfile::tempdir().expect("registry");
    let folderbase = tempfile::tempdir().expect("folderbase");
    let origin = write_package(
        registry.path(),
        "v1",
        "1.0.0",
        "project",
        base_artifacts(),
        None,
    );
    let target = write_package(
        registry.path(),
        "v2",
        "1.1.0",
        "project",
        additive_artifacts(),
        Some("1.0.0"),
    );
    initialize_from_template(folderbase.path(), &origin);
    fs::create_dir(folderbase.path().join("references")).expect("case-folded user directory");

    let error = plan_template_expansion(folderbase.path(), &target, &BTreeMap::new()).unwrap_err();

    assert!(matches!(error, FolderbaseError::InvalidRecord { .. }));
    assert!(error.to_string().contains("aliases existing"));
    assert!(!folderbase.path().join("references/README.md").exists());
}

#[test]
fn expansion_rejects_a_text_target_that_is_another_target_parent() {
    let registry = tempfile::tempdir().expect("registry");
    let folderbase = tempfile::tempdir().expect("folderbase");
    let origin = write_package(
        registry.path(),
        "v1",
        "1.0.0",
        "project",
        base_artifacts(),
        None,
    );
    let mut invalid_artifacts = additive_artifacts();
    invalid_artifacts.extend([
        json!({
            "target": "Docs",
            "kind": "text",
            "content": "not a directory\n",
            "install": "create_if_missing"
        }),
        json!({
            "target": "Docs/readme.md",
            "kind": "text",
            "content": "# Nested\n",
            "install": "create_if_missing"
        }),
    ]);
    let target = write_package(
        registry.path(),
        "v2",
        "1.1.0",
        "project",
        invalid_artifacts,
        Some("1.0.0"),
    );
    initialize_from_template(folderbase.path(), &origin);

    let error = plan_template_expansion(folderbase.path(), &target, &BTreeMap::new()).unwrap_err();

    assert!(matches!(error, FolderbaseError::InvalidRecord { .. }));
    assert!(error.to_string().contains("planned path collision"));
    assert!(!folderbase.path().join("Docs").exists());
}

#[test]
fn reapplying_same_upgrade_is_noop() {
    let registry = tempfile::tempdir().expect("registry");
    let folderbase = tempfile::tempdir().expect("folderbase");
    let origin = write_package(
        registry.path(),
        "v1",
        "1.0.0",
        "project",
        base_artifacts(),
        None,
    );
    let target = write_package(
        registry.path(),
        "v2",
        "1.1.0",
        "project",
        additive_artifacts(),
        Some("1.0.0"),
    );
    initialize_from_template(folderbase.path(), &origin);
    let first =
        plan_template_expansion(folderbase.path(), &target, &BTreeMap::new()).expect("plan");
    apply_template_expansion(&first).expect("first application");

    let second =
        plan_template_expansion(folderbase.path(), &target, &BTreeMap::new()).expect("replan");

    assert!(second.is_noop());
    let reapplied = apply_template_expansion(&second).expect("reapply no-op");
    assert!(reapplied.created_paths().is_empty());
    assert!(reapplied.application_record().is_none());
    assert_eq!(
        template_application_history(folderbase.path())
            .expect("history")
            .len(),
        1
    );

    let mutated_registry = tempfile::tempdir().expect("mutated registry");
    let changed_same_version = write_package(
        mutated_registry.path(),
        "v2-mutated",
        "1.1.0",
        "project",
        {
            let mut artifacts = additive_artifacts();
            artifacts.push(json!({
                "target": "Unexpected",
                "kind": "directory",
                "install": "create_if_missing"
            }));
            artifacts
        },
        Some("1.0.0"),
    );
    let error = plan_template_expansion(folderbase.path(), &changed_same_version, &BTreeMap::new())
        .unwrap_err();
    assert!(matches!(error, FolderbaseError::InvalidRecord { .. }));
    assert!(error.to_string().contains("package digest"));
}

#[test]
fn additive_upgrade_does_not_duplicate_relationships_or_adapters() {
    let registry = tempfile::tempdir().expect("registry");
    let folderbase = tempfile::tempdir().expect("folderbase");
    let origin = write_package(
        registry.path(),
        "v1",
        "1.0.0",
        "project",
        base_artifacts(),
        None,
    );
    let target = write_package(
        registry.path(),
        "v2",
        "1.1.0",
        "project",
        additive_artifacts(),
        Some("1.0.0"),
    );
    initialize_from_template(folderbase.path(), &origin);
    let adapter_before = fs::read(folderbase.path().join("AGENTS.md")).expect("adapter");
    let relationships_before = fs::read(folderbase.path().join(".folderbase/objects/project.json"))
        .expect("relationships");

    let manifest_before =
        fs::read(folderbase.path().join(".folderbase/manifest.json")).expect("manifest");
    let plan = plan_template_expansion(folderbase.path(), &target, &BTreeMap::new()).expect("plan");
    apply_template_expansion(&plan).expect("apply");
    let noop =
        plan_template_expansion(folderbase.path(), &target, &BTreeMap::new()).expect("replan");
    apply_template_expansion(&noop).expect("reapply");

    assert_eq!(
        fs::read(folderbase.path().join("AGENTS.md")).expect("adapter after"),
        adapter_before
    );
    assert_eq!(
        fs::read(folderbase.path().join(".folderbase/objects/project.json"))
            .expect("relationships after"),
        relationships_before
    );
    let relationship_document: Value =
        serde_json::from_slice(&relationships_before).expect("relationship JSON");
    assert_eq!(
        relationship_document["relationships"]
            .as_array()
            .expect("relationships")
            .len(),
        1
    );
    assert_eq!(
        template_application_history(folderbase.path())
            .expect("history")
            .len(),
        1
    );
    assert_eq!(
        fs::read(folderbase.path().join(".folderbase/manifest.json")).expect("manifest after"),
        manifest_before,
        "manifest adapters and Template Origin remain immutable"
    );
}

#[test]
fn policy_ignore_adapter_and_canonical_changes_are_structural() {
    let registry = tempfile::tempdir().expect("registry");
    let folderbase = tempfile::tempdir().expect("folderbase");
    let origin = write_package(
        registry.path(),
        "v1",
        "1.0.0",
        "project",
        base_artifacts(),
        None,
    );
    let mut changed = base_artifacts();
    changed[0]["content"] = json!("# Template suggestion that cannot replace the entry\n");
    changed[2]["content"] = json!("Template suggestion that cannot replace the adapter.\n");
    changed.push(json!({
        "target": ".folderbaseignore",
        "kind": "text",
        "content": "private/\n",
        "install": "create_if_missing"
    }));
    let target = write_package(
        registry.path(),
        "v2",
        "1.1.0",
        "project",
        changed,
        Some("1.0.0"),
    );
    initialize_from_template(folderbase.path(), &origin);
    fs::write(
        folderbase.path().join(".folderbaseignore"),
        "node_modules/\n",
    )
    .expect("optional ignore policy");
    let folderbase_before =
        fs::read(folderbase.path().join("FOLDERBASE.md")).expect("folderbase entry");
    let adapter_before = fs::read(folderbase.path().join("AGENTS.md")).expect("adapter");
    let ignore_before = fs::read(folderbase.path().join(".folderbaseignore")).expect("ignore");

    let plan =
        plan_template_expansion(folderbase.path(), &target, &BTreeMap::new()).expect("preview");

    // Protocol 0.2 templates can only say create_if_missing. They cannot
    // express adapter, canonical, ignore, or policy update operations, so the
    // planner preserves these existing targets instead of synthesizing a
    // structural proposal from different suggested bytes.
    assert!(plan.structural_changes().is_empty());
    assert!(plan.blocked_paths().is_empty());
    assert!(
        plan.preserved_paths()
            .contains(&PathBuf::from("FOLDERBASE.md"))
    );
    assert!(plan.preserved_paths().contains(&PathBuf::from("AGENTS.md")));
    assert!(
        plan.preserved_paths()
            .contains(&PathBuf::from(".folderbaseignore"))
    );
    apply_template_expansion(&plan).expect("record preserved suggestions");
    assert_eq!(
        fs::read(folderbase.path().join("FOLDERBASE.md")).unwrap(),
        folderbase_before
    );
    assert_eq!(
        fs::read(folderbase.path().join("AGENTS.md")).unwrap(),
        adapter_before
    );
    assert_eq!(
        fs::read(folderbase.path().join(".folderbaseignore")).unwrap(),
        ignore_before
    );
}

#[test]
fn downgrade_and_kind_change_require_structural_migration() {
    let registry = tempfile::tempdir().expect("registry");
    let folderbase = tempfile::tempdir().expect("folderbase");
    let origin = write_package(
        registry.path(),
        "v1",
        "1.0.0",
        "project",
        base_artifacts(),
        None,
    );
    let current = write_package(
        registry.path(),
        "v2",
        "1.1.0",
        "project",
        additive_artifacts(),
        Some("1.0.0"),
    );
    let changed_kind = write_package(
        registry.path(),
        "v3",
        "1.2.0",
        "organization",
        additive_artifacts(),
        Some("1.1.0"),
    );
    initialize_from_template(folderbase.path(), &current);

    let downgrade = plan_template_expansion(folderbase.path(), &origin, &BTreeMap::new())
        .expect("downgrade preview");
    assert_eq!(
        downgrade.structural_changes()[0].kind(),
        TemplateStructuralChangeKind::Downgrade
    );

    let manifest_before =
        fs::read(folderbase.path().join(".folderbase/manifest.json")).expect("manifest");
    let kind_change = plan_template_expansion(folderbase.path(), &changed_kind, &BTreeMap::new())
        .expect("suggested-kind preview");
    assert!(
        kind_change.structural_changes().is_empty(),
        "suggested_folderbase_kind is guidance, not a request to change folderbase.kind"
    );
    apply_template_expansion(&kind_change).expect("apply additive guidance");
    assert_eq!(
        fs::read(folderbase.path().join(".folderbase/manifest.json")).expect("manifest after"),
        manifest_before,
        "template guidance cannot rewrite the current folderbase kind"
    );
}

#[test]
fn same_version_different_lineage_is_a_structural_preview() {
    let registry = tempfile::tempdir().expect("registry");
    let folderbase = tempfile::tempdir().expect("folderbase");
    let origin = write_package(
        registry.path(),
        "origin",
        "1.0.0",
        "project",
        base_artifacts(),
        None,
    );
    let other_lineage = write_package_with_id(
        registry.path(),
        "other",
        "other.project",
        "1.0.0",
        "project",
        base_artifacts(),
        None,
    );
    initialize_from_template(folderbase.path(), &origin);

    let plan = plan_template_expansion(folderbase.path(), &other_lineage, &BTreeMap::new())
        .expect("cross-lineage preview");

    assert_eq!(
        plan.structural_changes()[0].kind(),
        TemplateStructuralChangeKind::Lineage
    );
    assert!(matches!(
        apply_template_expansion(&plan).unwrap_err(),
        FolderbaseError::StructuralTemplateChangeRequiresApproval
    ));
}

#[test]
fn stale_manifest_or_history_fails_before_template_writes() {
    let registry = tempfile::tempdir().expect("registry");
    let folderbase = tempfile::tempdir().expect("folderbase");
    let origin = write_package(
        registry.path(),
        "v1",
        "1.0.0",
        "project",
        base_artifacts(),
        None,
    );
    let target = write_package(
        registry.path(),
        "v2",
        "1.1.0",
        "project",
        additive_artifacts(),
        Some("1.0.0"),
    );
    initialize_from_template(folderbase.path(), &origin);

    let stale_manifest =
        plan_template_expansion(folderbase.path(), &target, &BTreeMap::new()).expect("plan");
    let manifest_path = folderbase.path().join(".folderbase/manifest.json");
    let mut manifest = fs::read(&manifest_path).expect("manifest");
    manifest.push(b'\n');
    fs::write(&manifest_path, manifest).expect("external manifest edit");
    assert!(matches!(
        apply_template_expansion(&stale_manifest).unwrap_err(),
        FolderbaseError::PlanPreconditionChanged(_)
    ));
    assert!(!folderbase.path().join("Notes").exists());

    let fresh =
        plan_template_expansion(folderbase.path(), &target, &BTreeMap::new()).expect("fresh plan");
    fs::create_dir(folderbase.path().join(".folderbase/template-applications"))
        .expect("concurrent empty history");
    assert!(matches!(
        apply_template_expansion(&fresh).unwrap_err(),
        FolderbaseError::PlanPreconditionChanged(_)
    ));
    assert!(!folderbase.path().join("Notes").exists());
}

#[cfg(unix)]
#[test]
fn symlinked_template_application_history_is_refused() {
    use std::os::unix::fs::symlink;

    let registry = tempfile::tempdir().expect("registry");
    let folderbase = tempfile::tempdir().expect("folderbase");
    let outside = tempfile::tempdir().expect("outside");
    let origin = write_package(
        registry.path(),
        "v1",
        "1.0.0",
        "project",
        base_artifacts(),
        None,
    );
    let target = write_package(
        registry.path(),
        "v2",
        "1.1.0",
        "project",
        additive_artifacts(),
        Some("1.0.0"),
    );
    initialize_from_template(folderbase.path(), &origin);
    symlink(
        outside.path(),
        folderbase.path().join(".folderbase/template-applications"),
    )
    .expect("history symlink");

    assert!(matches!(
        plan_template_expansion(folderbase.path(), &target, &BTreeMap::new()).unwrap_err(),
        FolderbaseError::UnsafePath(_)
    ));
}

#[test]
fn retry_after_safe_partial_addition_records_it_as_preserved() {
    let registry = tempfile::tempdir().expect("registry");
    let folderbase = tempfile::tempdir().expect("folderbase");
    let origin = write_package(
        registry.path(),
        "v1",
        "1.0.0",
        "project",
        base_artifacts(),
        None,
    );
    let target = write_package(
        registry.path(),
        "v2",
        "1.1.0",
        "project",
        additive_artifacts(),
        Some("1.0.0"),
    );
    initialize_from_template(folderbase.path(), &origin);
    let first =
        plan_template_expansion(folderbase.path(), &target, &BTreeMap::new()).expect("first plan");
    fs::create_dir(folderbase.path().join("Notes")).expect("safe partial addition");

    assert!(matches!(
        apply_template_expansion(&first).unwrap_err(),
        FolderbaseError::WouldOverwrite(_)
    ));
    assert!(
        template_application_history(folderbase.path())
            .expect("no false record")
            .is_empty()
    );

    let retry =
        plan_template_expansion(folderbase.path(), &target, &BTreeMap::new()).expect("retry plan");
    assert!(retry.preserved_paths().contains(&PathBuf::from("Notes")));
    apply_template_expansion(&retry).expect("retry applies remaining additions");
    let history = template_application_history(folderbase.path()).expect("verified history");
    assert_eq!(history.len(), 1);
    assert!(
        history[0]
            .preserved_targets()
            .iter()
            .any(|target| target.path() == Path::new("Notes"))
    );
    assert!(
        history[0]
            .created_paths()
            .iter()
            .all(|target| target.path() != Path::new("Notes"))
    );
}

#[test]
fn tampered_application_history_is_never_a_comparison_source() {
    let registry = tempfile::tempdir().expect("registry");
    let folderbase = tempfile::tempdir().expect("folderbase");
    let origin = write_package(
        registry.path(),
        "v1",
        "1.0.0",
        "project",
        base_artifacts(),
        None,
    );
    let target = write_package(
        registry.path(),
        "v2",
        "1.1.0",
        "project",
        additive_artifacts(),
        Some("1.0.0"),
    );
    initialize_from_template(folderbase.path(), &origin);
    let plan = plan_template_expansion(folderbase.path(), &target, &BTreeMap::new())
        .expect("expansion plan");
    let result = apply_template_expansion(&plan).expect("verified application");
    let record = folderbase
        .path()
        .join(result.application_record().expect("application record"));
    let mut document: Value =
        serde_json::from_slice(&fs::read(&record).expect("record")).expect("record JSON");
    document["plan_digest"]["digest"] =
        json!("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    fs::write(
        &record,
        serde_json::to_vec_pretty(&document).expect("tampered JSON"),
    )
    .expect("tamper record");

    let error = template_application_history(folderbase.path()).unwrap_err();
    assert!(matches!(error, FolderbaseError::InvalidRecord { .. }));
    assert!(error.to_string().contains("record digest mismatch"));
}

#[test]
fn self_consistent_orphan_application_is_not_a_verified_history_chain() {
    let registry = tempfile::tempdir().expect("registry");
    let folderbase = tempfile::tempdir().expect("folderbase");
    let origin = write_package(
        registry.path(),
        "v1",
        "1.0.0",
        "project",
        base_artifacts(),
        None,
    );
    let target = write_package(
        registry.path(),
        "v2",
        "1.1.0",
        "project",
        additive_artifacts(),
        Some("1.0.0"),
    );
    initialize_from_template(folderbase.path(), &origin);
    let plan = plan_template_expansion(folderbase.path(), &target, &BTreeMap::new())
        .expect("expansion plan");
    let result = apply_template_expansion(&plan).expect("verified application");
    let record_path = folderbase
        .path()
        .join(result.application_record().expect("application record"));
    let mut document: Value =
        serde_json::from_slice(&fs::read(&record_path).expect("template application record"))
            .expect("record JSON");
    document["comparison"]["source"] = json!("application");
    document["comparison"]["application_id"] =
        json!("template_application_019f9b75-0b22-7a18-8f40-3f29f1438b62");
    rewrite_record_digest(&mut document);
    fs::write(
        &record_path,
        serde_json::to_vec_pretty(&document).expect("orphan record JSON"),
    )
    .expect("write self-consistent orphan record");

    let error = template_application_history(folderbase.path()).unwrap_err();

    assert!(matches!(error, FolderbaseError::InvalidRecord { .. }));
    assert!(
        error
            .to_string()
            .contains("comparison application does not exist")
    );
}

#[test]
fn history_orders_rfc3339_offsets_by_instant_and_preserves_chain() {
    let registry = tempfile::tempdir().expect("registry");
    let folderbase = tempfile::tempdir().expect("folderbase");
    let origin = write_package(
        registry.path(),
        "v1",
        "1.0.0",
        "project",
        base_artifacts(),
        None,
    );
    let first_target = write_package(
        registry.path(),
        "v2",
        "1.1.0",
        "project",
        additive_artifacts(),
        Some("1.0.0"),
    );
    let second_target = write_package(
        registry.path(),
        "v3",
        "1.2.0",
        "project",
        additive_artifacts(),
        Some("1.1.0"),
    );
    initialize_from_template(folderbase.path(), &origin);

    let first_plan = plan_template_expansion(folderbase.path(), &first_target, &BTreeMap::new())
        .expect("first expansion plan");
    let first_result = apply_template_expansion(&first_plan).expect("first application");
    let second_plan = plan_template_expansion(folderbase.path(), &second_target, &BTreeMap::new())
        .expect("second expansion plan");
    let second_result = apply_template_expansion(&second_plan).expect("second application");
    let first_path = folderbase
        .path()
        .join(first_result.application_record().expect("first record"));
    let second_path = folderbase
        .path()
        .join(second_result.application_record().expect("second record"));

    let mut first_document: Value =
        serde_json::from_slice(&fs::read(&first_path).expect("first record bytes"))
            .expect("first record JSON");
    first_document["applied_at"] = json!("2026-07-26T10:00:00+14:00");
    rewrite_record_digest(&mut first_document);
    fs::write(
        &first_path,
        serde_json::to_vec_pretty(&first_document).expect("first record JSON bytes"),
    )
    .expect("rewrite first record");

    let mut second_document: Value =
        serde_json::from_slice(&fs::read(&second_path).expect("second record bytes"))
            .expect("second record JSON");
    second_document["applied_at"] = json!("2026-07-26T00:30:00Z");
    rewrite_record_digest(&mut second_document);
    fs::write(
        &second_path,
        serde_json::to_vec_pretty(&second_document).expect("second record JSON bytes"),
    )
    .expect("rewrite second record");

    let history =
        template_application_history(folderbase.path()).expect("verified ordered history");

    assert_eq!(history[0].template_version(), "1.1.0");
    assert_eq!(history[1].template_version(), "1.2.0");
    assert_eq!(history[1].comparison_version(), "1.1.0");
}

#[test]
fn comparison_uses_the_chain_terminal_when_timestamps_are_equal() {
    let registry = tempfile::tempdir().expect("registry");
    let folderbase = tempfile::tempdir().expect("folderbase");
    let origin = write_package(
        registry.path(),
        "v1",
        "1.0.0",
        "project",
        base_artifacts(),
        None,
    );
    let first_target = write_package(
        registry.path(),
        "v2",
        "1.1.0",
        "project",
        additive_artifacts(),
        Some("1.0.0"),
    );
    let second_target = write_package(
        registry.path(),
        "v3",
        "1.2.0",
        "project",
        additive_artifacts(),
        Some("1.1.0"),
    );
    let next_target = write_package(
        registry.path(),
        "v4",
        "1.3.0",
        "project",
        additive_artifacts(),
        Some("1.2.0"),
    );
    initialize_from_template(folderbase.path(), &origin);
    let first = apply_template_expansion(
        &plan_template_expansion(folderbase.path(), &first_target, &BTreeMap::new())
            .expect("first plan"),
    )
    .expect("first application");
    let second = apply_template_expansion(
        &plan_template_expansion(folderbase.path(), &second_target, &BTreeMap::new())
            .expect("second plan"),
    )
    .expect("second application");
    let first_path = folderbase
        .path()
        .join(first.application_record().expect("first record"));
    let second_path = folderbase
        .path()
        .join(second.application_record().expect("second record"));
    let predecessor_id = "template_application_019f9b75-0b22-7fff-bfff-ffffffffffff";
    let successor_id = "template_application_019f9b75-0b22-7000-8000-000000000000";
    let shared_time = "2026-07-26T00:30:00Z";

    let mut first_document: Value =
        serde_json::from_slice(&fs::read(&first_path).expect("first record bytes"))
            .expect("first record JSON");
    first_document["id"] = json!(predecessor_id);
    first_document["applied_at"] = json!(shared_time);
    rewrite_record_digest(&mut first_document);
    let first_rewritten = first_path.with_file_name(format!("{predecessor_id}.json"));
    fs::rename(&first_path, &first_rewritten).expect("rename predecessor record");
    fs::write(
        &first_rewritten,
        serde_json::to_vec_pretty(&first_document).expect("predecessor JSON bytes"),
    )
    .expect("rewrite predecessor record");

    let mut second_document: Value =
        serde_json::from_slice(&fs::read(&second_path).expect("second record bytes"))
            .expect("second record JSON");
    second_document["id"] = json!(successor_id);
    second_document["comparison"]["application_id"] = json!(predecessor_id);
    second_document["applied_at"] = json!(shared_time);
    rewrite_record_digest(&mut second_document);
    let second_rewritten = second_path.with_file_name(format!("{successor_id}.json"));
    fs::rename(&second_path, &second_rewritten).expect("rename successor record");
    fs::write(
        &second_rewritten,
        serde_json::to_vec_pretty(&second_document).expect("successor JSON bytes"),
    )
    .expect("rewrite successor record");

    let plan = plan_template_expansion(folderbase.path(), &next_target, &BTreeMap::new())
        .expect("next expansion plan");

    assert_eq!(plan.comparison_version(), "1.2.0");
    assert!(plan.structural_changes().is_empty());
}

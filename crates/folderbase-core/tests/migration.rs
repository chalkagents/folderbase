use std::{fs, path::Path};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};

use folderbase_core::{
    FolderbaseError, FolderbaseKind, InitializationOptions, LocalVersionStore, MigrationAnswer,
    MigrationCommand, MigrationContentKind, MigrationExecution, MigrationOperation,
    MigrationOption, MigrationOutcome, MigrationPlan, MigrationQuestionKind, MigrationResult,
    MigrationState, MigrationTargetKind, NestedFolderbaseState, RootClaim, ValidationLevel,
    analyze_migration, apply_migration, approve_migration, initialize, plan_initialization,
    plan_migration, preview_migration, rollback_migration, validate,
};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

fn answer_all(analysis: &folderbase_core::MigrationAnalysis) -> Vec<MigrationAnswer> {
    analysis
        .questions
        .iter()
        .map(|question| MigrationAnswer {
            question_id: question.id.clone(),
            answer: question.recommended_option_id.clone(),
            exceptions: Vec::new(),
        })
        .collect()
}

fn fixture() -> TempDir {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir_all(root.path().join("Client-Shared")).unwrap();
    fs::create_dir_all(root.path().join("dashboard/node_modules/pkg")).unwrap();
    fs::create_dir_all(root.path().join("config")).unwrap();
    fs::write(root.path().join("README.md"), "source of truth\n").unwrap();
    fs::write(
        root.path().join("Client-Shared/Overview.md"),
        "client-safe\n",
    )
    .unwrap();
    fs::write(
        root.path().join("dashboard/node_modules/pkg/index.js"),
        "generated\n",
    )
    .unwrap();
    fs::write(root.path().join("config/api_key.txt"), "fake\n").unwrap();
    root
}

fn multi_boundary_answers(analysis: &folderbase_core::MigrationAnalysis) -> Vec<MigrationAnswer> {
    let client_folderbase = analysis
        .proposed_targets
        .iter()
        .find(|target| {
            target.kind == MigrationTargetKind::Folderbase
                && target.path == Path::new("Client-Shared")
        })
        .expect("client folderbase target")
        .id
        .clone();
    analysis
        .questions
        .iter()
        .map(|question| {
            let answer = match (&question.kind, question.id.as_str()) {
                (_, "question_canonical_scope") => "proposed_boundaries".to_owned(),
                (MigrationQuestionKind::Assignment { source_path, .. }, _)
                    if source_path.starts_with("Client-Shared") =>
                {
                    client_folderbase.clone()
                }
                _ => question.recommended_option_id.clone(),
            };
            MigrationAnswer {
                question_id: question.id.clone(),
                answer,
                exceptions: Vec::new(),
            }
        })
        .collect()
}

#[test]
fn approved_plan_creates_multiple_valid_folderbase_roots() {
    let root = fixture();
    let analysis = analyze_migration(root.path()).unwrap();
    let answers = multi_boundary_answers(&analysis);
    let plan = plan_migration(analysis, answers, "Organized").unwrap();

    apply_migration(approve_migration(plan).unwrap()).unwrap();

    for relative in [
        "Organized/Primary.folderbase",
        "Organized/Client-Shared.folderbase",
    ] {
        let report = validate(root.path().join(relative), ValidationLevel::Shallow).unwrap();
        assert!(
            report.valid,
            "{relative} must be an independently valid folderbase: {:?}",
            report.findings
        );
    }
}

#[test]
fn workspace_composes_folderbases_without_membership_or_grants() {
    let root = fixture();
    let analysis = analyze_migration(root.path()).unwrap();
    let answers = multi_boundary_answers(&analysis);
    let plan = plan_migration(analysis, answers, "Organized").unwrap();
    apply_migration(approve_migration(plan).unwrap()).unwrap();

    let descriptor_path = root.path().join("Organized/.folderbase-workspace.json");
    let descriptor: serde_json::Value =
        serde_json::from_slice(&fs::read(&descriptor_path).unwrap()).unwrap();
    let schema_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../protocol/schemas/0.1/workspace.schema.json");
    let schema: serde_json::Value =
        serde_json::from_slice(&fs::read(&schema_path).unwrap()).unwrap();
    assert!(
        jsonschema::draft202012::options()
            .should_validate_formats(true)
            .build(&schema)
            .unwrap()
            .is_valid(&descriptor)
    );
    assert_eq!(descriptor["folderbases"].as_array().unwrap().len(), 2);
    assert_eq!(
        descriptor["folderbases"]
            .as_array()
            .unwrap()
            .iter()
            .map(|folderbase| folderbase["path"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["Primary.folderbase", "Client-Shared.folderbase"]
    );
    for forbidden in ["members", "membership", "permissions", "grants", "shares"] {
        assert!(
            descriptor.get(forbidden).is_none(),
            "workspace descriptor must not confer {forbidden}"
        );
    }
    let entry = fs::read_to_string(root.path().join("Organized/WORKSPACE.md")).unwrap();
    assert!(entry.contains("navigation"));
    assert!(entry.contains("does not grant access"));
}

#[test]
fn each_target_has_unique_identity_and_template_provenance() {
    let root = fixture();
    let analysis = analyze_migration(root.path()).unwrap();
    let answers = multi_boundary_answers(&analysis);
    let plan = plan_migration(analysis, answers, "Organized").unwrap();
    apply_migration(approve_migration(plan).unwrap()).unwrap();

    let manifests = [
        "Organized/Primary.folderbase",
        "Organized/Client-Shared.folderbase",
    ]
    .map(|relative| {
        serde_json::from_slice::<serde_json::Value>(
            &fs::read(root.path().join(relative).join(".folderbase/manifest.json")).unwrap(),
        )
        .unwrap()
    });
    let identities = manifests
        .iter()
        .map(|manifest| manifest["folderbase"]["id"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert_ne!(identities[0], identities[1]);
    assert!(identities.iter().all(|id| id.starts_with("folderbase_")));
    for manifest in manifests {
        assert_eq!(
            manifest["folderbase"]["template_provenance"]["id"],
            "folderbase.project"
        );
        assert_eq!(
            manifest["folderbase"]["template_provenance"]["version"],
            "0.2.2"
        );
    }
}

#[test]
fn every_copy_matches_approved_digest() {
    let root = fixture();
    let analysis = analyze_migration(root.path()).unwrap();
    let answers = multi_boundary_answers(&analysis);
    let plan = plan_migration(analysis, answers, "Organized").unwrap();
    let expected = plan
        .operations
        .iter()
        .filter_map(|operation| match operation {
            MigrationOperation::CopyFile {
                destination_path,
                expected_sha256,
                ..
            } => Some((destination_path.clone(), expected_sha256.clone())),
            MigrationOperation::CreateFolder { .. } => None,
            _ => None,
        })
        .collect::<Vec<_>>();
    apply_migration(approve_migration(plan).unwrap()).unwrap();

    for (relative, expected_sha256) in expected {
        assert_eq!(
            format!(
                "{:x}",
                Sha256::digest(fs::read(root.path().join(relative)).unwrap())
            ),
            expected_sha256
        );
    }
}

#[test]
fn source_folder_remains_unchanged() {
    let root = fixture();
    let before = [
        (
            "README.md",
            fs::read(root.path().join("README.md")).unwrap(),
        ),
        (
            "Client-Shared/Overview.md",
            fs::read(root.path().join("Client-Shared/Overview.md")).unwrap(),
        ),
        (
            "dashboard/node_modules/pkg/index.js",
            fs::read(root.path().join("dashboard/node_modules/pkg/index.js")).unwrap(),
        ),
        (
            "config/api_key.txt",
            fs::read(root.path().join("config/api_key.txt")).unwrap(),
        ),
    ];
    let analysis = analyze_migration(root.path()).unwrap();
    let answers = multi_boundary_answers(&analysis);
    let plan = plan_migration(analysis, answers, "Organized").unwrap();
    apply_migration(approve_migration(plan).unwrap()).unwrap();

    for (relative, expected) in before {
        assert_eq!(fs::read(root.path().join(relative)).unwrap(), expected);
    }
}

#[test]
fn partial_apply_recovers_without_active_invalid_folderbase() {
    let root = fixture();
    fs::write(
        root.path().join("Decisions"),
        "user-owned file conflicts with template directory\n",
    )
    .unwrap();
    let analysis = analyze_migration(root.path()).unwrap();
    let answers = multi_boundary_answers(&analysis);
    let plan = plan_migration(analysis, answers, "Organized").unwrap();
    let migration_id = plan.id.clone();

    let error = apply_migration(approve_migration(plan).unwrap()).unwrap_err();
    assert!(matches!(error, FolderbaseError::InvalidRecord { .. }));
    let recovery = MigrationResult::recover(root.path(), &migration_id).unwrap_err();
    assert!(matches!(
        recovery,
        FolderbaseError::InvalidMigrationState {
            expected: "approved",
            ref actual,
        } if actual == "missing_execution_state"
    ));
    assert!(
        !tree(root.path()).iter().any(|path| {
            path.starts_with("Organized/") && path.ends_with(".folderbase/manifest.json")
        }),
        "a failed materialization must never leave an active invalid folderbase"
    );
    assert_eq!(
        fs::read(root.path().join("Decisions")).unwrap(),
        b"user-owned file conflicts with template directory\n"
    );
}

#[test]
fn proposal_round_trips_through_v02_schema() {
    let root = fixture();
    let analysis = analyze_migration(root.path()).unwrap();
    let plan = plan_migration(analysis, answer_all_for(root.path()), "Organized").unwrap();
    let encoded = serde_json::to_value(&plan).unwrap();
    let decoded: folderbase_core::MigrationPlan = serde_json::from_value(encoded.clone()).unwrap();

    assert_eq!(decoded, plan);
    assert_eq!(encoded["protocol_version"], "0.2.0");
    assert_eq!(encoded["state"], "proposed");
    assert_eq!(encoded["source_inventory"]["algorithm"], "sha256");
    assert!(
        encoded["source_inventory"]["files"]
            .as_array()
            .is_some_and(|files| !files.is_empty())
    );

    let schema_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../protocol/schemas/0.2/migration.schema.json");
    let schema: serde_json::Value =
        serde_json::from_slice(&fs::read(&schema_path).unwrap()).unwrap();
    let validator = jsonschema::draft202012::options()
        .should_validate_formats(true)
        .build(&schema)
        .unwrap();
    assert!(
        validator.is_valid(&encoded),
        "serialized proposal must conform to Migration Protocol 0.2"
    );
}

#[test]
fn reopen_returns_same_plan_after_process_restart() {
    let root = fixture();
    let analysis = analyze_migration(root.path()).unwrap();
    let plan = plan_migration(analysis, answer_all_for(root.path()), "Organized").unwrap();
    let migration_id = plan.id.clone();
    let expected = serde_json::to_value(&plan).unwrap();
    drop(plan);

    let reopened = folderbase_core::MigrationPlan::reopen(root.path(), &migration_id).unwrap();

    assert_eq!(serde_json::to_value(&reopened).unwrap(), expected);
    assert_eq!(preview_migration(&reopened).unwrap().copies.len(), 2);
    assert!(
        root.path()
            .join(".folderbase/migrations")
            .join(migration_id)
            .join("plan.json")
            .is_file()
    );
}

#[test]
fn apply_refuses_unapproved_or_tampered_plan_without_writes() {
    let stale_root = fixture();
    let stale_analysis = analyze_migration(stale_root.path()).unwrap();
    let stale_plan = plan_migration(
        stale_analysis,
        answer_all_for(stale_root.path()),
        "Organized",
    )
    .unwrap();
    let stale_path = stale_root
        .path()
        .join(".folderbase/migrations")
        .join(&stale_plan.id)
        .join("plan.json");
    let mut stale_stored: serde_json::Value =
        serde_json::from_slice(&fs::read(&stale_path).unwrap()).unwrap();
    stale_stored["answers"][0]["answer"] = serde_json::json!("changed-out-of-process");
    fs::write(
        &stale_path,
        serde_json::to_vec_pretty(&stale_stored).unwrap(),
    )
    .unwrap();
    let stale_approval = approve_migration(stale_plan).unwrap_err();
    assert!(matches!(
        stale_approval,
        FolderbaseError::MigrationApprovalMismatch
    ));
    assert!(!stale_root.path().join("Organized").exists());

    let root = fixture();
    let analysis = analyze_migration(root.path()).unwrap();
    let plan = plan_migration(analysis, answer_all_for(root.path()), "Organized").unwrap();
    let migration_id = plan.id.clone();

    let unapproved =
        folderbase_core::ApprovedMigration::reopen(root.path(), &migration_id).unwrap_err();
    assert!(matches!(
        unapproved,
        FolderbaseError::InvalidMigrationState { .. }
    ));
    assert!(!root.path().join("Organized").exists());

    let approved = approve_migration(plan).unwrap();
    let plan_path = root
        .path()
        .join(".folderbase/migrations")
        .join(&migration_id)
        .join("plan.json");
    let mut stored: serde_json::Value =
        serde_json::from_slice(&fs::read(&plan_path).unwrap()).unwrap();
    stored["answers"][0]["answer"] = serde_json::json!("tampered");
    fs::write(&plan_path, serde_json::to_vec_pretty(&stored).unwrap()).unwrap();

    let tampered = apply_migration(approved).unwrap_err();
    assert!(matches!(
        tampered,
        FolderbaseError::MigrationApprovalMismatch
    ));
    assert!(!root.path().join("Organized").exists());
    assert!(!plan_path.with_file_name("result.json").exists());
}

#[test]
fn unknown_plan_fields_survive_round_trip() {
    let root = fixture();
    let analysis = analyze_migration(root.path()).unwrap();
    let plan = plan_migration(analysis, answer_all_for(root.path()), "Organized").unwrap();
    let migration_id = plan.id.clone();
    let plan_path = root
        .path()
        .join(".folderbase/migrations")
        .join(&migration_id)
        .join("plan.json");
    let mut stored: serde_json::Value =
        serde_json::from_slice(&fs::read(&plan_path).unwrap()).unwrap();
    stored["x-folderbase-test"] = serde_json::json!({
        "trace_id": "trace_forward_compatible",
        "policy": {"mode": "observe"}
    });
    fs::write(&plan_path, serde_json::to_vec_pretty(&stored).unwrap()).unwrap();

    let reopened = folderbase_core::MigrationPlan::reopen(root.path(), &migration_id).unwrap();
    approve_migration(reopened).unwrap();

    let persisted: serde_json::Value =
        serde_json::from_slice(&fs::read(&plan_path).unwrap()).unwrap();
    assert_eq!(persisted["x-folderbase-test"], stored["x-folderbase-test"]);
}

#[test]
fn unsupported_state_transition_is_rejected() {
    let root = fixture();
    let analysis = analyze_migration(root.path()).unwrap();
    let plan = plan_migration(analysis, answer_all_for(root.path()), "Organized").unwrap();
    let migration_id = plan.id.clone();

    let rejected = plan.reject().unwrap();
    assert_eq!(rejected.state, MigrationState::Rejected);
    assert_eq!(
        folderbase_core::MigrationPlan::reopen(root.path(), &migration_id)
            .unwrap()
            .state,
        MigrationState::Rejected
    );

    let error = approve_migration(rejected).unwrap_err();
    assert!(matches!(
        error,
        FolderbaseError::InvalidMigrationState {
            expected: "proposed",
            ..
        }
    ));
    assert!(!root.path().join("Organized").exists());
}

#[test]
fn answer_operation_template_or_inventory_change_invalidates_approval() {
    for consequential_input in ["answer", "operation", "template"] {
        let root = fixture();
        let analysis = analyze_migration(root.path()).unwrap();
        let plan = plan_migration(analysis, answer_all_for(root.path()), "Organized").unwrap();
        let migration_id = plan.id.clone();
        approve_migration(plan).unwrap();
        let plan_path = root
            .path()
            .join(".folderbase/migrations")
            .join(&migration_id)
            .join("plan.json");
        let mut stored: serde_json::Value =
            serde_json::from_slice(&fs::read(&plan_path).unwrap()).unwrap();
        match consequential_input {
            "answer" => stored["answers"][0]["answer"] = serde_json::json!("changed"),
            "operation" => stored["operations"][0]["path"] = serde_json::json!("Changed"),
            "template" => {
                stored["template_references"] = serde_json::json!(["folderbase.custom@0.2.0"])
            }
            _ => unreachable!(),
        }
        fs::write(&plan_path, serde_json::to_vec_pretty(&stored).unwrap()).unwrap();

        let error =
            folderbase_core::ApprovedMigration::reopen(root.path(), &migration_id).unwrap_err();
        assert!(
            matches!(error, FolderbaseError::MigrationApprovalMismatch),
            "{consequential_input} changes must invalidate approval"
        );
        assert!(!root.path().join("Organized").exists());
    }

    let root = fixture();
    let analysis = analyze_migration(root.path()).unwrap();
    let plan = plan_migration(analysis, answer_all_for(root.path()), "Organized").unwrap();
    let approved = approve_migration(plan).unwrap();
    fs::write(root.path().join("README.md"), "inventory changed\n").unwrap();

    let error = apply_migration(approved).unwrap_err();
    assert!(matches!(error, FolderbaseError::MigrationSourceChanged(_)));
    assert!(!root.path().join("Organized").exists());
}

#[test]
fn analysis_is_read_only_and_finds_boundaries() {
    let root = fixture();
    let before = tree(root.path());
    let analysis = analyze_migration(root.path()).unwrap();
    let after = tree(root.path());

    assert_eq!(before, after);
    assert_eq!(analysis.file_count, 3);
    assert_eq!(analysis.reconstructable_trees.len(), 1);
    assert!(
        analysis
            .proposed_boundaries
            .iter()
            .any(|boundary| boundary.path == Path::new("Client-Shared"))
    );
    assert!(
        analysis
            .questions
            .iter()
            .any(|question| question.id == "question_secrets")
    );
}

#[test]
fn migration_analysis_json_is_deterministic() {
    let root = fixture();

    let first = serde_json::to_string_pretty(&analyze_migration(root.path()).unwrap()).unwrap();
    let second = serde_json::to_string_pretty(&analyze_migration(root.path()).unwrap()).unwrap();

    assert_eq!(first, second);
}

#[test]
fn reserved_protocol_and_git_directories_are_actually_pruned() {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir_all(root.path().join(".folderbase/private")).unwrap();
    fs::create_dir_all(root.path().join(".git")).unwrap();
    fs::write(root.path().join("README.md"), "canonical\n").unwrap();
    fs::write(
        root.path().join(".folderbase/private/internal-record.json"),
        "PRIVATE_PROTOCOL_STATE",
    )
    .unwrap();
    fs::write(root.path().join(".git/config"), "PRIVATE_GIT_STATE").unwrap();

    let analysis = analyze_migration(root.path()).unwrap();
    let report = serde_json::to_string_pretty(&analysis).unwrap();

    assert_eq!(analysis.file_count, 1);
    assert!(!report.contains("internal-record.json"));
    assert!(!report.contains("PRIVATE_PROTOCOL_STATE"));
    assert!(!report.contains("PRIVATE_GIT_STATE"));
}

#[cfg(unix)]
#[test]
fn metadata_analysis_succeeds_when_generated_tree_is_unreadable() {
    let root = tempfile::tempdir().unwrap();
    let generated = root.path().join("node_modules/pkg/index.js");
    fs::create_dir_all(generated.parent().unwrap()).unwrap();
    fs::write(root.path().join("README.md"), "canonical\n").unwrap();
    fs::write(&generated, "must not be read\n").unwrap();
    let generated_tree = root.path().join("node_modules");
    fs::set_permissions(&generated_tree, fs::Permissions::from_mode(0o000)).unwrap();

    let analysis = analyze_migration(root.path()).unwrap();
    fs::set_permissions(&generated_tree, fs::Permissions::from_mode(0o755)).unwrap();

    assert_eq!(analysis.file_count, 1);
    assert_eq!(analysis.reconstructable_trees.len(), 1);
}

#[cfg(unix)]
#[test]
fn generated_dependency_trees_are_not_hashed() {
    let root = fixture();
    let generated = root.path().join("dashboard/node_modules/pkg/index.js");
    fs::set_permissions(&generated, fs::Permissions::from_mode(0o000)).unwrap();

    let analysis = analyze_migration(root.path()).unwrap();
    let plan = plan_migration(analysis, answer_all_for(root.path()), "Organized").unwrap();

    assert!(plan.exclusions.iter().any(|exclusion| {
        exclusion.path == Path::new("dashboard/node_modules")
            && exclusion.reason.contains("reconstructable")
    }));
}

#[test]
fn migration_analysis_stops_at_valid_or_malformed_nested_folderbase() {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("README.md"), "parent\n").unwrap();
    create_nested_folderbase(
        root.path().join("valid-child"),
        r#"{"protocol_version":"0.2.0","folderbase":{"id":"folderbase_nested"}}"#,
    );
    create_nested_folderbase(root.path().join("malformed-child"), "{not-json");

    let analysis = analyze_migration(root.path()).unwrap();

    assert_eq!(analysis.file_count, 1);
    assert_eq!(analysis.nested_folderbases.len(), 2);
    assert!(analysis.nested_folderbases.iter().any(|boundary| {
        boundary.path == Path::new("valid-child")
            && boundary.state == NestedFolderbaseState::Unchecked
    }));
    assert!(analysis.nested_folderbases.iter().any(|boundary| {
        boundary.path == Path::new("malformed-child")
            && boundary.state == NestedFolderbaseState::Unchecked
    }));
}

#[test]
fn case_folded_nested_markers_still_fail_closed() {
    let root = tempfile::tempdir().unwrap();
    let nested = root.path().join("child");
    fs::create_dir_all(nested.join(".FOLDERBASE")).unwrap();
    fs::write(nested.join("folderbase.MD"), "# Nested folderbase\n").unwrap();
    fs::write(
        nested.join(".FOLDERBASE/MANIFEST.JSON"),
        r#"{"protocol_version":"0.2.0","folderbase":{"id":"folderbase_casefold"}}"#,
    )
    .unwrap();
    fs::write(nested.join("never-expose.txt"), "nested secret bytes\n").unwrap();

    let analysis = analyze_migration(root.path()).unwrap();

    assert_eq!(analysis.file_count, 0);
    assert_eq!(analysis.nested_folderbases.len(), 1);
    assert_eq!(analysis.nested_folderbases[0].path, Path::new("child"));
    assert_eq!(
        analysis.nested_folderbases[0].state,
        NestedFolderbaseState::Unchecked
    );
}

#[test]
fn migration_analysis_treats_markerless_context_as_inert() {
    let root = tempfile::tempdir().unwrap();
    let nested = root.path().join("child");
    fs::create_dir_all(nested.join(".folderbase/questions")).unwrap();
    fs::write(nested.join(".folderbase/summary.md"), "ordinary context\n").unwrap();
    fs::write(nested.join("ordinary.txt"), "visible ordinary bytes\n").unwrap();

    let analysis = analyze_migration(root.path()).unwrap();

    assert!(analysis.nested_folderbases.is_empty());
    assert_eq!(analysis.file_count, 1);
}

#[cfg(unix)]
#[test]
fn migration_analysis_fails_closed_on_a_symlink_shaped_marker_without_attesting_it() {
    let root = tempfile::tempdir().unwrap();
    let nested = root.path().join("child");
    fs::create_dir(&nested).unwrap();
    std::os::unix::fs::symlink(
        root.path().join("missing-state"),
        nested.join(".folderbase"),
    )
    .unwrap();
    fs::write(nested.join("never-expose.txt"), "nested secret bytes\n").unwrap();

    let analysis = analyze_migration(root.path()).unwrap();

    assert_eq!(analysis.file_count, 0);
    assert_eq!(analysis.nested_folderbases.len(), 1);
    assert_eq!(analysis.nested_folderbases[0].path, Path::new("child"));
    assert_eq!(
        analysis.nested_folderbases[0].state,
        NestedFolderbaseState::Unchecked
    );
}

#[test]
fn ambiguous_case_folded_state_aliases_fail_closed() {
    let root = tempfile::tempdir().unwrap();
    let nested = root.path().join("child");
    fs::create_dir_all(nested.join(".folderbase")).unwrap();
    fs::create_dir_all(nested.join(".FOLDERBASE")).unwrap();
    fs::write(nested.join("FOLDERBASE.md"), "# Nested folderbase\n").unwrap();
    fs::write(
        nested.join(".FOLDERBASE/manifest.json"),
        r#"{"protocol_version":"0.2.0"}"#,
    )
    .unwrap();
    fs::write(nested.join("never-expose.txt"), "nested secret bytes\n").unwrap();

    let analysis = analyze_migration(root.path()).unwrap();

    assert_eq!(analysis.file_count, 0);
    assert_eq!(analysis.nested_folderbases.len(), 1);
    assert_eq!(analysis.nested_folderbases[0].path, Path::new("child"));
}

#[cfg(unix)]
#[test]
fn opaque_nested_manifest_contents_are_never_opened() {
    let root = tempfile::tempdir().unwrap();
    let nested = root.path().join("child");
    fs::create_dir_all(nested.join(".folderbase")).unwrap();
    fs::write(nested.join("FOLDERBASE.md"), "# Nested folderbase\n").unwrap();
    let manifest = nested.join(".folderbase/manifest.json");
    let file = fs::File::create(&manifest).unwrap();
    file.set_len(1024 * 1024 * 1024).unwrap();
    drop(file);
    fs::set_permissions(&manifest, fs::Permissions::from_mode(0o000)).unwrap();

    let analysis = analyze_migration(root.path()).unwrap();
    fs::set_permissions(&manifest, fs::Permissions::from_mode(0o644)).unwrap();

    assert_eq!(analysis.file_count, 0);
    assert_eq!(analysis.nested_folderbases.len(), 1);
    assert_eq!(
        analysis.nested_folderbases[0].state,
        NestedFolderbaseState::Unchecked
    );
}

#[test]
fn nested_descendant_names_bytes_and_digests_never_appear() {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("README.md"), "parent\n").unwrap();
    create_nested_folderbase(
        root.path().join("node_modules"),
        r#"{"protocol_version":"0.2.0","folderbase":{"id":"folderbase_generated_name"}}"#,
    );
    fs::write(
        root.path().join("node_modules/private-payroll-secret.bin"),
        "ULTRA_SECRET_NESTED_CONTENT",
    )
    .unwrap();

    let analysis = analyze_migration(root.path()).unwrap();
    let report = serde_json::to_string_pretty(&analysis).unwrap();

    assert_eq!(analysis.nested_folderbases.len(), 1);
    assert!(analysis.reconstructable_trees.is_empty());
    assert!(!report.contains("private-payroll-secret.bin"));
    assert!(!report.contains("ULTRA_SECRET_NESTED_CONTENT"));

    let plan = plan_migration(analysis, answer_all_for(root.path()), "Organized").unwrap();
    let plan_json = serde_json::to_string_pretty(&plan).unwrap();
    assert!(!plan_json.contains("private-payroll-secret.bin"));
    assert!(!plan_json.contains("ULTRA_SECRET_NESTED_CONTENT"));
}

#[cfg(unix)]
#[test]
fn nested_folderbase_created_after_analysis_invalidates_planning_before_content_reads() {
    let root = tempfile::tempdir().unwrap();
    let descendant = root.path().join("child/private.txt");
    fs::create_dir_all(descendant.parent().unwrap()).unwrap();
    fs::write(&descendant, "must never be read\n").unwrap();
    let analysis = analyze_migration(root.path()).unwrap();
    let answers = answer_all(&analysis);
    create_nested_folderbase(
        root.path().join("child"),
        r#"{"protocol_version":"0.2.0","folderbase":{"id":"folderbase_late"}}"#,
    );
    fs::set_permissions(&descendant, fs::Permissions::from_mode(0o000)).unwrap();

    let error = plan_migration(analysis, answers, "Organized").unwrap_err();
    fs::set_permissions(&descendant, fs::Permissions::from_mode(0o644)).unwrap();

    assert!(matches!(error, FolderbaseError::MigrationSourceChanged(_)));
}

#[test]
fn preview_and_apply_copy_only_canonical_content() {
    let root = fixture();
    let analysis = analyze_migration(root.path()).unwrap();
    let answers = answer_all(&analysis);
    let plan = plan_migration(analysis, answers, "Organized").unwrap();
    let preview = preview_migration(&plan).unwrap();

    assert!(preview.source_files_remain);
    assert_eq!(preview.copies.len(), 2);
    assert!(
        preview
            .copies
            .iter()
            .all(|copy| !copy.source_path.to_string_lossy().contains("node_modules"))
    );

    let result = apply_migration(approve_migration(plan).unwrap()).unwrap();
    assert_eq!(result.state, MigrationState::Verified);
    assert_eq!(
        fs::read(root.path().join("Organized/README.md")).unwrap(),
        b"source of truth\n"
    );
    assert!(root.path().join("README.md").exists());
    assert!(!root.path().join("Organized/config/api_key.txt").exists());
    assert!(root.path().join(&result.journal_path).exists());
}

#[test]
fn source_change_invalidates_approval_without_writes() {
    let root = fixture();
    let analysis = analyze_migration(root.path()).unwrap();
    let answers = answer_all(&analysis);
    let approved =
        approve_migration(plan_migration(analysis, answers, "Organized").unwrap()).unwrap();
    fs::write(root.path().join("README.md"), "changed\n").unwrap();

    let error = apply_migration(approved).unwrap_err();
    assert!(matches!(error, FolderbaseError::MigrationSourceChanged(_)));
    assert!(!root.path().join("Organized").exists());
}

#[test]
fn additive_apply_refuses_nested_folderbase_created_after_approval_without_writes() {
    let root = fixture();
    let analysis = analyze_migration(root.path()).unwrap();
    let answers = answer_all(&analysis);
    let plan = plan_migration(analysis, answers, "Organized").unwrap();
    let migration_id = plan.id.clone();
    let approved = approve_migration(plan).unwrap();
    let nested = root.path().join("Client-Shared");
    fs::create_dir_all(nested.join(".folderbase")).unwrap();
    fs::write(nested.join("FOLDERBASE.md"), "# Nested folderbase\n").unwrap();
    fs::write(
        nested.join(".folderbase/manifest.json"),
        r#"{"protocol_version":"0.2.0","folderbase":{"id":"folderbase_late"}}"#,
    )
    .unwrap();

    let error = apply_migration(approved).unwrap_err();

    assert!(
        matches!(error, FolderbaseError::UnsafePath(path) if path == Path::new("Client-Shared"))
    );
    assert!(!root.path().join("Organized").exists());
    assert_eq!(
        fs::read(root.path().join("Client-Shared/Overview.md")).unwrap(),
        b"client-safe\n"
    );
    assert!(nested.join("FOLDERBASE.md").is_file());
    assert!(nested.join(".folderbase/manifest.json").is_file());
    assert_eq!(
        MigrationPlan::reopen(root.path(), &migration_id)
            .unwrap()
            .state,
        MigrationState::Approved
    );
}

#[test]
fn additive_apply_refuses_unplanned_canonical_source_without_writes() {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("README.md"), "approved\n").unwrap();
    let analysis = analyze_migration(root.path()).unwrap();
    let answers = answer_all(&analysis);
    let plan = plan_migration(analysis, answers, "Organized").unwrap();
    let migration_id = plan.id.clone();
    let approved = approve_migration(plan).unwrap();
    fs::write(root.path().join("late.md"), "late canonical work\n").unwrap();

    let error = apply_migration(approved).unwrap_err();

    assert!(
        matches!(error, FolderbaseError::MigrationSourceChanged(path) if path == Path::new("late.md"))
    );
    assert!(!root.path().join("Organized").exists());
    assert_eq!(
        fs::read(root.path().join("README.md")).unwrap(),
        b"approved\n"
    );
    assert_eq!(
        fs::read(root.path().join("late.md")).unwrap(),
        b"late canonical work\n"
    );
    assert_eq!(
        MigrationPlan::reopen(root.path(), &migration_id)
            .unwrap()
            .state,
        MigrationState::Approved
    );
}

#[test]
fn pre_execution_collision_creates_no_output_or_transaction_state() {
    let root = fixture();
    fs::create_dir_all(root.path().join("Organized/Client-Shared")).unwrap();
    fs::write(
        root.path().join("Organized/Client-Shared/Overview.md"),
        "do not overwrite\n",
    )
    .unwrap();
    let analysis = analyze_migration(root.path()).unwrap();
    let answers = answer_all(&analysis);
    let plan = plan_migration(analysis, answers, "Migrated").unwrap();
    let migration_id = plan.id.clone();
    let approved = approve_migration(plan).unwrap();
    fs::create_dir_all(root.path().join("Migrated/Client-Shared")).unwrap();
    fs::write(
        root.path().join("Migrated/Client-Shared/Overview.md"),
        "appeared after planning\n",
    )
    .unwrap();

    let error = apply_migration(approved).unwrap_err();
    assert!(matches!(
        error,
        FolderbaseError::InvalidRecord { ref message, .. }
            if message.contains("materialization target collides")
    ));
    assert!(!root.path().join("Migrated/README.md").exists());
    assert_eq!(
        fs::read(root.path().join("Migrated/Client-Shared/Overview.md")).unwrap(),
        b"appeared after planning\n"
    );
    assert_eq!(
        folderbase_core::MigrationPlan::reopen(root.path(), &migration_id)
            .unwrap()
            .state,
        MigrationState::Approved
    );
    assert!(matches!(
        MigrationResult::reopen(root.path(), &migration_id),
        Err(FolderbaseError::InvalidMigrationState {
            expected: "applying",
            ref actual,
        }) if actual == "missing_execution_state"
    ));
}

#[test]
fn verified_migration_can_be_rolled_back_without_touching_sources() {
    let root = fixture();
    let analysis = analyze_migration(root.path()).unwrap();
    let answers = answer_all(&analysis);
    let plan = plan_migration(analysis, answers, "Organized").unwrap();
    let result = apply_migration(approve_migration(plan).unwrap()).unwrap();

    let rollback = rollback_migration(&result).unwrap();
    assert_eq!(rollback.state, MigrationState::RolledBack);
    assert!(!root.path().join("Organized").exists());
    assert!(root.path().join("README.md").exists());
}

#[test]
fn additive_rollback_refuses_nested_folderbase_created_after_apply_without_deletions() {
    let root = fixture();
    let analysis = analyze_migration(root.path()).unwrap();
    let plan = plan_migration(analysis, answer_all_for(root.path()), "Organized").unwrap();
    let migration_id = plan.id.clone();
    let result = apply_migration(approve_migration(plan).unwrap()).unwrap();
    let nested = root.path().join("Organized/Client-Shared");
    fs::create_dir_all(nested.join(".folderbase")).unwrap();
    fs::write(nested.join("FOLDERBASE.md"), "# Nested folderbase\n").unwrap();
    fs::write(
        nested.join(".folderbase/manifest.json"),
        r#"{"protocol_version":"0.2.0","folderbase":{"id":"folderbase_late"}}"#,
    )
    .unwrap();

    let outcome = MigrationExecution::run(
        RootClaim::Current {
            display_root: root.path(),
        },
        MigrationCommand::Rollback {
            migration_id: &result.migration_id,
        },
    )
    .unwrap();
    let MigrationOutcome::Conflicted { conflicts, .. } = outcome else {
        panic!("new nested boundary must return durable conflict data");
    };
    assert!(!conflicts.is_empty());
    assert_eq!(
        fs::read(root.path().join("Organized/README.md")).unwrap(),
        b"source of truth\n"
    );
    assert_eq!(
        fs::read(root.path().join("Organized/Client-Shared/Overview.md")).unwrap(),
        b"client-safe\n"
    );
    assert!(root.path().join("Organized/FOLDERBASE.md").is_file());
    assert!(nested.join("FOLDERBASE.md").is_file());
    assert!(nested.join(".folderbase/manifest.json").is_file());
    assert_eq!(
        MigrationResult::reopen(root.path(), &migration_id)
            .unwrap()
            .state,
        MigrationState::Conflicted
    );
}

#[test]
fn reopening_and_rollback_by_id_do_not_require_an_in_memory_result() {
    let root = fixture();
    let analysis = analyze_migration(root.path()).unwrap();
    let plan = plan_migration(analysis, answer_all_for(root.path()), "Organized").unwrap();
    let migration_id = plan.id.clone();
    drop(approve_migration(plan).unwrap());
    let reopened_approval =
        folderbase_core::ApprovedMigration::reopen(root.path(), &migration_id).unwrap();
    drop(apply_migration(reopened_approval).unwrap());

    let reopened = MigrationResult::reopen(root.path(), &migration_id).unwrap();
    assert_eq!(reopened.state, MigrationState::Verified);
    let rollback = MigrationResult::rollback_by_id(root.path(), &migration_id).unwrap();
    assert_eq!(rollback.state, MigrationState::RolledBack);
    assert!(!root.path().join("Organized").exists());
    assert!(root.path().join("README.md").exists());
    assert_eq!(
        MigrationResult::reopen(root.path(), &migration_id)
            .unwrap()
            .state,
        MigrationState::RolledBack
    );
    assert_eq!(
        folderbase_core::MigrationPlan::reopen(root.path(), &migration_id)
            .unwrap()
            .state,
        MigrationState::RolledBack
    );
}

#[test]
fn rollback_refuses_to_delete_outputs_changed_after_migration() {
    let root = fixture();
    let analysis = analyze_migration(root.path()).unwrap();
    let plan = plan_migration(analysis, answer_all_for(root.path()), "Organized").unwrap();
    let migration_id = plan.id.clone();
    apply_migration(approve_migration(plan).unwrap()).unwrap();
    fs::write(root.path().join("Organized/README.md"), "new user work\n").unwrap();

    let outcome = MigrationExecution::run(
        RootClaim::Current {
            display_root: root.path(),
        },
        MigrationCommand::Rollback {
            migration_id: &migration_id,
        },
    )
    .unwrap();
    let MigrationOutcome::Conflicted { conflicts, .. } = outcome else {
        panic!("edited additive output must return durable conflict data");
    };
    assert!(!conflicts.is_empty());
    assert_eq!(
        fs::read(root.path().join("Organized/README.md")).unwrap(),
        b"new user work\n"
    );
    assert!(
        root.path()
            .join("Organized/Client-Shared/Overview.md")
            .exists()
    );
}

#[test]
fn accepted_option_ids_materially_change_topology() {
    let contract_root = fixture();
    let contract_analysis = analyze_migration(contract_root.path()).unwrap();
    let contract_json = serde_json::to_value(&contract_analysis).unwrap();
    let scope_question = contract_json["questions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|question| question["id"] == "question_canonical_scope")
        .unwrap();
    assert_eq!(
        scope_question["options"]
            .as_array()
            .unwrap()
            .iter()
            .map(|option| option["id"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["one_folderbase", "proposed_boundaries"]
    );
    assert_eq!(scope_question["recommended_option_id"], "one_folderbase");

    let one_root = fixture();
    let one_analysis = analyze_migration(one_root.path()).unwrap();
    let one_plan =
        plan_migration(one_analysis, answer_all_for(one_root.path()), "Organized").unwrap();
    assert!(one_plan.operations.iter().any(|operation| matches!(
        operation,
        MigrationOperation::CopyFile {
            destination_path,
            ..
        } if destination_path == Path::new("Organized/Client-Shared/Overview.md")
    )));
    assert!(!one_plan.operations.iter().any(|operation| matches!(
        operation,
        MigrationOperation::CopyFile { source_path, .. }
            if source_path.to_string_lossy().contains("node_modules")
    )));

    let boundary_root = fixture();
    fs::create_dir_all(boundary_root.path().join("Private-Project")).unwrap();
    fs::write(
        boundary_root.path().join("Private-Project/Plan.md"),
        "restricted\n",
    )
    .unwrap();
    let boundary_analysis = analyze_migration(boundary_root.path()).unwrap();
    let private_target_id = boundary_analysis
        .proposed_targets
        .iter()
        .find(|target| target.path == Path::new("Private-Project"))
        .unwrap()
        .id
        .clone();
    let private_assignment =
        assignment_question_id(&boundary_analysis, Path::new("Private-Project/Plan.md"));
    let generated_assignment =
        assignment_question_id(&boundary_analysis, Path::new("dashboard/node_modules"));
    let mut boundary_answers = answer_all(&boundary_analysis);
    for answer in &mut boundary_answers {
        match answer.question_id.as_str() {
            "question_canonical_scope" => answer.answer = "proposed_boundaries".to_owned(),
            "question_generated_content" => answer.answer = "include_generated".to_owned(),
            id if id == private_assignment => answer.answer = private_target_id.clone(),
            id if id == generated_assignment => {
                answer.answer = "target_primary_folderbase".to_owned()
            }
            _ => {}
        }
    }
    let boundary_plan = plan_migration(boundary_analysis, boundary_answers, "Organized").unwrap();
    assert!(boundary_plan.operations.iter().any(|operation| matches!(
        operation,
        MigrationOperation::CopyFile {
            destination_path,
            ..
        } if destination_path == Path::new("Organized/Private-Project.folderbase/Plan.md")
    )));
    assert!(boundary_plan.operations.iter().any(|operation| matches!(
        operation,
        MigrationOperation::CopyFile {
            source_path,
            destination_path,
            ..
        } if source_path.to_string_lossy().contains("node_modules")
            && destination_path.starts_with("Organized/Primary.folderbase")
    )));
}

#[test]
fn unknown_or_missing_consequential_option_blocks_planning() {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("README.md"), "canonical\n").unwrap();
    let analysis = analyze_migration(root.path()).unwrap();
    let mut answers = answer_all(&analysis);
    answers
        .iter_mut()
        .find(|answer| answer.question_id == "question_canonical_scope")
        .unwrap()
        .answer = "one folderbase".to_owned();

    let error = plan_migration(analysis, answers, "Organized").unwrap_err();

    assert!(matches!(error, FolderbaseError::InvalidRecord { .. }));
    assert!(!root.path().join("Organized").exists());
}

fn flat_file_analysis(count: usize, reverse_creation: bool) -> folderbase_core::MigrationAnalysis {
    let container = tempfile::tempdir().unwrap();
    let root = container.path().join("Folder");
    fs::create_dir(&root).unwrap();
    let mut indexes = (0..count).collect::<Vec<_>>();
    if reverse_creation {
        indexes.reverse();
    }
    for index in indexes {
        fs::write(root.join(format!("item-{index:02}.md")), "canonical\n").unwrap();
    }
    analyze_migration(&root).unwrap()
}

#[test]
fn assignment_grouping_starts_after_thirty_two_scopes_and_is_creation_order_stable() {
    let small = flat_file_analysis(32, false);
    let small_assignments = small
        .questions
        .iter()
        .filter(|question| !matches!(question.kind, MigrationQuestionKind::Decision))
        .collect::<Vec<_>>();
    assert_eq!(small_assignments.len(), 32);
    assert!(
        small_assignments
            .iter()
            .all(|question| matches!(question.kind, MigrationQuestionKind::Assignment { .. }))
    );

    let grouped_forward = flat_file_analysis(33, false);
    let grouped_reverse = flat_file_analysis(33, true);
    let forward_questions = grouped_forward
        .questions
        .iter()
        .filter(|question| !matches!(question.kind, MigrationQuestionKind::Decision))
        .collect::<Vec<_>>();
    let reverse_questions = grouped_reverse
        .questions
        .iter()
        .filter(|question| !matches!(question.kind, MigrationQuestionKind::Decision))
        .collect::<Vec<_>>();

    assert_eq!(forward_questions.len(), 1);
    assert!(matches!(
        forward_questions[0].kind,
        MigrationQuestionKind::AssignmentGroup { .. }
    ));
    assert_eq!(forward_questions, reverse_questions);
}

#[test]
fn grouped_assignment_plan_round_trips_and_conforms_to_v02_schema() {
    let root = tempfile::tempdir().unwrap();
    for index in 0..33 {
        fs::write(
            root.path().join(format!("item-{index:02}.md")),
            "canonical\n",
        )
        .unwrap();
    }
    let analysis = analyze_migration(root.path()).unwrap();
    let plan = plan_migration(analysis, answer_all_for(root.path()), "Organized").unwrap();
    let migration_id = plan.id.clone();
    let encoded = serde_json::to_value(&plan).unwrap();
    assert_eq!(
        encoded["x-folderbase-grouped-assignments-v1"]["version"],
        "1"
    );

    let schema_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../protocol/schemas/0.2/migration.schema.json");
    let schema: serde_json::Value =
        serde_json::from_slice(&fs::read(&schema_path).unwrap()).unwrap();
    let validator = jsonschema::draft202012::options()
        .should_validate_formats(true)
        .build(&schema)
        .unwrap();
    assert!(
        validator.is_valid(&encoded),
        "grouped proposal must conform to Migration Protocol 0.2"
    );

    let reopened = MigrationPlan::reopen(root.path(), &migration_id).unwrap();
    assert_eq!(serde_json::to_value(reopened).unwrap(), encoded);
}

#[test]
fn tampered_group_question_is_rejected_before_planning_writes() {
    let root = tempfile::tempdir().unwrap();
    for index in 0..33 {
        fs::write(
            root.path().join(format!("item-{index:02}.md")),
            "canonical\n",
        )
        .unwrap();
    }
    let mut analysis = analyze_migration(root.path()).unwrap();
    let answers = answer_all(&analysis);
    let group = analysis
        .questions
        .iter_mut()
        .find(|question| matches!(question.kind, MigrationQuestionKind::AssignmentGroup { .. }))
        .unwrap();
    let MigrationQuestionKind::AssignmentGroup {
        coverage_digest, ..
    } = &mut group.kind
    else {
        unreachable!()
    };
    *coverage_digest = "0".repeat(64);

    let error = plan_migration(analysis, answers, "Organized").unwrap_err();

    assert!(matches!(error, FolderbaseError::InvalidRecord { .. }));
    assert!(!root.path().join(".folderbase").exists());
    assert!(!root.path().join("Organized").exists());
}

#[test]
fn tampered_group_contract_is_rejected_before_approval_or_apply_writes() {
    let proposed_root = tempfile::tempdir().unwrap();
    for index in 0..33 {
        fs::write(
            proposed_root.path().join(format!("item-{index:02}.md")),
            "canonical\n",
        )
        .unwrap();
    }
    let analysis = analyze_migration(proposed_root.path()).unwrap();
    let plan = plan_migration(analysis, answer_all_for(proposed_root.path()), "Organized").unwrap();
    let migration_id = plan.id.clone();
    let plan_path = proposed_root
        .path()
        .join(".folderbase/migrations")
        .join(&migration_id)
        .join("plan.json");
    let mut stored: serde_json::Value =
        serde_json::from_slice(&fs::read(&plan_path).unwrap()).unwrap();
    stored["x-folderbase-grouped-assignments-v1"]["groups"][0]["members"][0]["source_kind"] =
        serde_json::json!("reconstructable_tree");
    fs::write(&plan_path, serde_json::to_vec_pretty(&stored).unwrap()).unwrap();

    let error = MigrationPlan::reopen(proposed_root.path(), &migration_id).unwrap_err();

    assert!(matches!(error, FolderbaseError::InvalidRecord { .. }));
    assert!(!proposed_root.path().join("Organized").exists());

    let approved_root = tempfile::tempdir().unwrap();
    for index in 0..33 {
        fs::write(
            approved_root.path().join(format!("item-{index:02}.md")),
            "canonical\n",
        )
        .unwrap();
    }
    let analysis = analyze_migration(approved_root.path()).unwrap();
    let plan = plan_migration(analysis, answer_all_for(approved_root.path()), "Organized").unwrap();
    let migration_id = plan.id.clone();
    let approved = approve_migration(plan).unwrap();
    let plan_path = approved_root
        .path()
        .join(".folderbase/migrations")
        .join(&migration_id)
        .join("plan.json");
    let mut stored: serde_json::Value =
        serde_json::from_slice(&fs::read(&plan_path).unwrap()).unwrap();
    stored["x-folderbase-grouped-assignments-v1"]["groups"][0]["coverage_digest"] =
        serde_json::json!("0".repeat(64));
    fs::write(&plan_path, serde_json::to_vec_pretty(&stored).unwrap()).unwrap();

    let error = apply_migration(approved).unwrap_err();

    assert!(matches!(error, FolderbaseError::MigrationApprovalMismatch));
    assert!(!approved_root.path().join("Organized").exists());
    assert!(!plan_path.with_file_name("result.json").exists());
}

#[test]
fn grouped_included_tree_cannot_drop_expanded_membership_before_approval() {
    let root = fixture();
    for index in 0..30 {
        fs::write(
            root.path().join(format!("extra-{index:02}.md")),
            "canonical\n",
        )
        .unwrap();
    }
    let analysis = analyze_migration(root.path()).unwrap();
    let generated_group = assignment_question_id(&analysis, Path::new("dashboard/node_modules"));
    let mut answers = answer_all(&analysis);
    for answer in &mut answers {
        match answer.question_id.as_str() {
            "question_generated_content" => answer.answer = "include_generated".to_owned(),
            id if id == generated_group => answer.answer = "target_primary_folderbase".to_owned(),
            _ => {}
        }
    }
    let plan = plan_migration(analysis, answers, "Organized").unwrap();
    let migration_id = plan.id.clone();
    let plan_path = root
        .path()
        .join(".folderbase/migrations")
        .join(&migration_id)
        .join("plan.json");
    let mut stored: serde_json::Value =
        serde_json::from_slice(&fs::read(&plan_path).unwrap()).unwrap();
    stored
        .as_object_mut()
        .unwrap()
        .remove("x-folderbase-expanded-reconstructable-trees-v1");
    fs::write(&plan_path, serde_json::to_vec_pretty(&stored).unwrap()).unwrap();

    let error = MigrationPlan::reopen(root.path(), &migration_id).unwrap_err();

    assert!(matches!(error, FolderbaseError::InvalidRecord { .. }));
    assert!(!root.path().join("Organized").exists());
}

#[test]
fn typed_answer_input_round_trips_the_canonical_wire_key() {
    let answer: MigrationAnswer = serde_json::from_value(serde_json::json!({
        "question_id": "question_canonical_scope",
        "answer": "one_folderbase"
    }))
    .unwrap();

    assert_eq!(answer.answer, "one_folderbase");
    assert_eq!(
        serde_json::to_value(answer).unwrap(),
        serde_json::json!({
            "question_id": "question_canonical_scope",
            "answer": "one_folderbase"
        })
    );
}

#[test]
fn planner_rejects_overlapping_or_unassigned_content() {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("README.md"), "canonical\n").unwrap();
    let analysis = analyze_migration(root.path()).unwrap();
    let answers = answer_all(&analysis)
        .into_iter()
        .filter(|answer| !answer.question_id.starts_with("question_assignment_"))
        .collect();

    let error = plan_migration(analysis, answers, "Organized").unwrap_err();

    assert!(matches!(error, FolderbaseError::InvalidRecord { .. }));
    assert!(!root.path().join("Organized").exists());

    let overlapping_root = tempfile::tempdir().unwrap();
    fs::write(overlapping_root.path().join("README.md"), "canonical\n").unwrap();
    let mut overlapping_analysis = analyze_migration(overlapping_root.path()).unwrap();
    let mut duplicate_assignment = overlapping_analysis
        .questions
        .iter()
        .find(|question| question.id.starts_with("question_assignment_"))
        .unwrap()
        .clone();
    duplicate_assignment.id.push_str("_overlap");
    overlapping_analysis.questions.push(duplicate_assignment);
    let overlapping_answers = answer_all(&overlapping_analysis);

    let error = plan_migration(overlapping_analysis, overlapping_answers, "Organized").unwrap_err();

    assert!(matches!(error, FolderbaseError::InvalidRecord { .. }));
    assert!(!overlapping_root.path().join("Organized").exists());

    let collision_root = tempfile::tempdir().unwrap();
    fs::create_dir_all(collision_root.path().join("Private-One")).unwrap();
    fs::create_dir_all(collision_root.path().join("Private-Two")).unwrap();
    fs::write(collision_root.path().join("Private-One/A.md"), "one\n").unwrap();
    fs::write(collision_root.path().join("Private-Two/B.md"), "two\n").unwrap();
    let mut collision_analysis = analyze_migration(collision_root.path()).unwrap();
    let first_target = collision_analysis
        .proposed_targets
        .iter()
        .find(|target| target.path == Path::new("Private-One"))
        .unwrap()
        .id
        .clone();
    let second_target = collision_analysis
        .proposed_targets
        .iter()
        .find(|target| target.path == Path::new("Private-Two"))
        .unwrap()
        .id
        .clone();
    for target in &mut collision_analysis.proposed_targets {
        if target.id == first_target || target.id == second_target {
            target.suggested_name = "Same Name".to_owned();
        }
    }
    let first_assignment =
        assignment_question_id(&collision_analysis, Path::new("Private-One/A.md"));
    let second_assignment =
        assignment_question_id(&collision_analysis, Path::new("Private-Two/B.md"));
    let mut collision_answers = answer_all(&collision_analysis);
    for answer in &mut collision_answers {
        match answer.question_id.as_str() {
            "question_canonical_scope" => answer.answer = "proposed_boundaries".to_owned(),
            id if id == first_assignment => answer.answer = first_target.clone(),
            id if id == second_assignment => answer.answer = second_target.clone(),
            _ => {}
        }
    }

    let error = plan_migration(collision_analysis, collision_answers, "Organized").unwrap_err();

    assert!(matches!(error, FolderbaseError::InvalidRecord { .. }));
    assert!(!collision_root.path().join("Organized").exists());

    let portable_target_collision_root = tempfile::tempdir().unwrap();
    fs::create_dir_all(portable_target_collision_root.path().join("Private-One")).unwrap();
    fs::create_dir_all(portable_target_collision_root.path().join("Private-Two")).unwrap();
    fs::write(
        portable_target_collision_root
            .path()
            .join("Private-One/A.md"),
        "one\n",
    )
    .unwrap();
    fs::write(
        portable_target_collision_root
            .path()
            .join("Private-Two/B.md"),
        "two\n",
    )
    .unwrap();
    let mut portable_target_collision_analysis =
        analyze_migration(portable_target_collision_root.path()).unwrap();
    let first_target = portable_target_collision_analysis
        .proposed_targets
        .iter()
        .find(|target| target.path == Path::new("Private-One"))
        .unwrap()
        .id
        .clone();
    let second_target = portable_target_collision_analysis
        .proposed_targets
        .iter()
        .find(|target| target.path == Path::new("Private-Two"))
        .unwrap()
        .id
        .clone();
    for target in &mut portable_target_collision_analysis.proposed_targets {
        if target.id == first_target {
            target.suggested_name = "Private Folderbase".to_owned();
        } else if target.id == second_target {
            target.suggested_name = "PRIVATE FOLDERBASE".to_owned();
        }
    }
    let first_assignment = assignment_question_id(
        &portable_target_collision_analysis,
        Path::new("Private-One/A.md"),
    );
    let second_assignment = assignment_question_id(
        &portable_target_collision_analysis,
        Path::new("Private-Two/B.md"),
    );
    let mut portable_target_collision_answers = answer_all(&portable_target_collision_analysis);
    for answer in &mut portable_target_collision_answers {
        match answer.question_id.as_str() {
            "question_canonical_scope" => answer.answer = "proposed_boundaries".to_owned(),
            id if id == first_assignment => answer.answer = first_target.clone(),
            id if id == second_assignment => answer.answer = second_target.clone(),
            _ => {}
        }
    }

    let error = plan_migration(
        portable_target_collision_analysis,
        portable_target_collision_answers,
        "Organized",
    )
    .unwrap_err();

    assert!(matches!(error, FolderbaseError::InvalidRecord { .. }));
    assert!(
        !portable_target_collision_root
            .path()
            .join("Organized")
            .exists()
    );

    let file_collision_root = tempfile::tempdir().unwrap();
    fs::create_dir_all(file_collision_root.path().join("Private")).unwrap();
    fs::write(file_collision_root.path().join("A.md"), "root\n").unwrap();
    fs::write(file_collision_root.path().join("Private/A.md"), "private\n").unwrap();
    let file_collision_analysis = analyze_migration(file_collision_root.path()).unwrap();
    let private_target = file_collision_analysis
        .proposed_targets
        .iter()
        .find(|target| target.path == Path::new("Private"))
        .unwrap()
        .id
        .clone();
    let root_assignment = assignment_question_id(&file_collision_analysis, Path::new("A.md"));
    let private_assignment =
        assignment_question_id(&file_collision_analysis, Path::new("Private/A.md"));
    let mut file_collision_answers = answer_all(&file_collision_analysis);
    for answer in &mut file_collision_answers {
        match answer.question_id.as_str() {
            "question_canonical_scope" => answer.answer = "proposed_boundaries".to_owned(),
            id if id == root_assignment || id == private_assignment => {
                answer.answer = private_target.clone()
            }
            _ => {}
        }
    }

    let error =
        plan_migration(file_collision_analysis, file_collision_answers, "Organized").unwrap_err();

    assert!(matches!(error, FolderbaseError::InvalidRecord { .. }));
    assert!(!file_collision_root.path().join("Organized").exists());

    let tree_collision_root = tempfile::tempdir().unwrap();
    fs::create_dir_all(tree_collision_root.path().join("Private/A")).unwrap();
    fs::write(tree_collision_root.path().join("A"), "root file\n").unwrap();
    fs::write(
        tree_collision_root.path().join("Private/A/B.md"),
        "nested file\n",
    )
    .unwrap();
    let tree_collision_analysis = analyze_migration(tree_collision_root.path()).unwrap();
    let private_target = tree_collision_analysis
        .proposed_targets
        .iter()
        .find(|target| target.path == Path::new("Private"))
        .unwrap()
        .id
        .clone();
    let root_assignment = assignment_question_id(&tree_collision_analysis, Path::new("A"));
    let nested_assignment =
        assignment_question_id(&tree_collision_analysis, Path::new("Private/A/B.md"));
    let mut tree_collision_answers = answer_all(&tree_collision_analysis);
    for answer in &mut tree_collision_answers {
        match answer.question_id.as_str() {
            "question_canonical_scope" => answer.answer = "proposed_boundaries".to_owned(),
            id if id == root_assignment || id == nested_assignment => {
                answer.answer = private_target.clone()
            }
            _ => {}
        }
    }

    let error =
        plan_migration(tree_collision_analysis, tree_collision_answers, "Organized").unwrap_err();

    assert!(matches!(error, FolderbaseError::InvalidRecord { .. }));
    assert!(!tree_collision_root.path().join("Organized").exists());

    let unicode_collision_root = tempfile::tempdir().unwrap();
    fs::create_dir_all(unicode_collision_root.path().join("Private")).unwrap();
    fs::write(unicode_collision_root.path().join("STRASSE"), "root file\n").unwrap();
    fs::write(
        unicode_collision_root.path().join("Private/Straße"),
        "private file\n",
    )
    .unwrap();
    let unicode_collision_analysis = analyze_migration(unicode_collision_root.path()).unwrap();
    let private_target = unicode_collision_analysis
        .proposed_targets
        .iter()
        .find(|target| target.path == Path::new("Private"))
        .unwrap()
        .id
        .clone();
    let root_assignment = assignment_question_id(&unicode_collision_analysis, Path::new("STRASSE"));
    let private_assignment =
        assignment_question_id(&unicode_collision_analysis, Path::new("Private/Straße"));
    let mut unicode_collision_answers = answer_all(&unicode_collision_analysis);
    for answer in &mut unicode_collision_answers {
        match answer.question_id.as_str() {
            "question_canonical_scope" => answer.answer = "proposed_boundaries".to_owned(),
            id if id == root_assignment || id == private_assignment => {
                answer.answer = private_target.clone()
            }
            _ => {}
        }
    }

    let error = plan_migration(
        unicode_collision_analysis,
        unicode_collision_answers,
        "Organized",
    )
    .unwrap_err();

    assert!(matches!(error, FolderbaseError::InvalidRecord { .. }));
    assert!(!unicode_collision_root.path().join("Organized").exists());
}

#[test]
fn generated_content_is_a_proposal_not_an_automatic_exclusion() {
    let root = fixture();
    let analysis = analyze_migration(root.path()).unwrap();
    let generated_assignment =
        assignment_question_id(&analysis, Path::new("dashboard/node_modules"));
    let mut answers = answer_all(&analysis);
    answers
        .iter_mut()
        .find(|answer| answer.question_id == "question_generated_content")
        .unwrap()
        .answer = "include_generated".to_owned();
    answers
        .iter_mut()
        .find(|answer| answer.question_id == generated_assignment)
        .unwrap()
        .answer = "target_exclusion".to_owned();

    let plan = plan_migration(analysis, answers, "Organized").unwrap();

    assert!(plan.exclusions.iter().any(|exclusion| {
        exclusion.path == Path::new("dashboard/node_modules")
            && exclusion.reason.contains("Explicit")
    }));
    assert!(!plan.operations.iter().any(|operation| matches!(
        operation,
        MigrationOperation::CopyFile { source_path, .. }
            if source_path.starts_with("dashboard/node_modules")
    )));

    let nested_root = tempfile::tempdir().unwrap();
    create_nested_folderbase(
        nested_root.path().join("node_modules/child"),
        r#"{"protocol_version":"0.2.0","folderbase":{"id":"folderbase_hidden"}}"#,
    );
    let nested_analysis = analyze_migration(nested_root.path()).unwrap();
    assert!(nested_analysis.nested_folderbases.is_empty());
    let nested_assignment = assignment_question_id(&nested_analysis, Path::new("node_modules"));
    let mut nested_answers = answer_all(&nested_analysis);
    for answer in &mut nested_answers {
        match answer.question_id.as_str() {
            "question_generated_content" => answer.answer = "include_generated".to_owned(),
            id if id == nested_assignment => answer.answer = "target_primary_folderbase".to_owned(),
            _ => {}
        }
    }

    let error = plan_migration(nested_analysis, nested_answers, "Organized").unwrap_err();

    assert!(matches!(error, FolderbaseError::InvalidRecord { .. }));
    assert!(!nested_root.path().join("Organized").exists());
}

#[test]
fn included_reconstructable_tree_rejects_new_descendant_before_apply_writes() {
    let root = fixture();
    let analysis = analyze_migration(root.path()).unwrap();
    let generated_assignment =
        assignment_question_id(&analysis, Path::new("dashboard/node_modules"));
    let mut answers = answer_all(&analysis);
    for answer in &mut answers {
        match answer.question_id.as_str() {
            "question_generated_content" => answer.answer = "include_generated".to_owned(),
            id if id == generated_assignment => {
                answer.answer = "target_primary_folderbase".to_owned()
            }
            _ => {}
        }
    }
    let plan = plan_migration(analysis, answers, "Organized").unwrap();
    let migration_id = plan.id.clone();
    let approved = approve_migration(plan).unwrap();
    fs::write(
        root.path().join("dashboard/node_modules/pkg/unreviewed.js"),
        "new generated member\n",
    )
    .unwrap();

    let error = apply_migration(approved).unwrap_err();

    assert!(matches!(error, FolderbaseError::MigrationSourceChanged(_)));
    assert!(!root.path().join("Organized").exists());
    assert!(
        !root
            .path()
            .join(".folderbase/migrations")
            .join(&migration_id)
            .join("result.json")
            .exists()
    );
    assert_eq!(
        MigrationPlan::reopen(root.path(), &migration_id)
            .unwrap()
            .state,
        MigrationState::Approved
    );
}

fn approved_included_reconstructable_tree() -> (TempDir, folderbase_core::ApprovedMigration, String)
{
    let root = fixture();
    let analysis = analyze_migration(root.path()).unwrap();
    let generated_assignment =
        assignment_question_id(&analysis, Path::new("dashboard/node_modules"));
    let mut answers = answer_all(&analysis);
    for answer in &mut answers {
        match answer.question_id.as_str() {
            "question_generated_content" => answer.answer = "include_generated".to_owned(),
            id if id == generated_assignment => {
                answer.answer = "target_primary_folderbase".to_owned()
            }
            _ => {}
        }
    }
    let plan = plan_migration(analysis, answers, "Organized").unwrap();
    let migration_id = plan.id.clone();
    let approved = approve_migration(plan).unwrap();
    (root, approved, migration_id)
}

#[test]
fn included_reconstructable_tree_rejects_removed_nested_or_secret_descendants() {
    let (removed_root, removed_approval, _) = approved_included_reconstructable_tree();
    fs::remove_file(
        removed_root
            .path()
            .join("dashboard/node_modules/pkg/index.js"),
    )
    .unwrap();
    assert!(matches!(
        apply_migration(removed_approval).unwrap_err(),
        FolderbaseError::MigrationSourceChanged(_)
    ));
    assert!(!removed_root.path().join("Organized").exists());

    let (nested_root, nested_approval, nested_id) = approved_included_reconstructable_tree();
    create_nested_folderbase(
        nested_root.path().join("dashboard/node_modules/pkg/nested"),
        r#"{"protocol_version":"0.2.0","folderbase":{"id":"folderbase_hidden"}}"#,
    );
    assert!(matches!(
        apply_migration(nested_approval).unwrap_err(),
        FolderbaseError::MigrationSourceChanged(_)
    ));
    assert!(!nested_root.path().join("Organized").exists());
    assert!(
        !nested_root
            .path()
            .join(".folderbase/migrations")
            .join(nested_id)
            .join("result.json")
            .exists()
    );

    let (secret_root, secret_approval, _) = approved_included_reconstructable_tree();
    fs::write(
        secret_root.path().join("dashboard/node_modules/pkg/.env"),
        "SECRET=new\n",
    )
    .unwrap();
    assert!(matches!(
        apply_migration(secret_approval).unwrap_err(),
        FolderbaseError::MigrationSourceChanged(_)
    ));
    assert!(!secret_root.path().join("Organized").exists());
}

#[test]
fn included_empty_reconstructable_tree_is_bound_before_later_descendants() {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join("node_modules")).unwrap();
    fs::write(root.path().join("README.md"), "canonical\n").unwrap();
    let analysis = analyze_migration(root.path()).unwrap();
    let generated_assignment = assignment_question_id(&analysis, Path::new("node_modules"));
    let mut answers = answer_all(&analysis);
    for answer in &mut answers {
        match answer.question_id.as_str() {
            "question_generated_content" => answer.answer = "include_generated".to_owned(),
            id if id == generated_assignment => {
                answer.answer = "target_primary_folderbase".to_owned()
            }
            _ => {}
        }
    }
    let plan = plan_migration(analysis, answers, "Organized").unwrap();
    let migration_id = plan.id.clone();
    let approved = approve_migration(plan).unwrap();
    fs::write(
        root.path().join("node_modules/appeared-later.js"),
        "new generated member\n",
    )
    .unwrap();

    let error = apply_migration(approved).unwrap_err();

    assert!(matches!(error, FolderbaseError::MigrationSourceChanged(_)));
    assert!(!root.path().join("Organized").exists());
    assert!(
        !root
            .path()
            .join(".folderbase/migrations")
            .join(migration_id)
            .join("result.json")
            .exists()
    );
}

#[test]
fn secret_shaped_content_requires_explicit_local_policy() {
    let root = fixture();
    let analysis = analyze_migration(root.path()).unwrap();
    let analysis_json = serde_json::to_value(&analysis).unwrap();
    let secret_question = analysis_json["questions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|question| question["id"] == "question_secrets")
        .unwrap();
    assert_eq!(secret_question["recommended_option_id"], "local_only");
    assert_eq!(secret_question["options"][0]["id"], "local_only");
    let secret_assignment = assignment_question_id(&analysis, Path::new("config/api_key.txt"));
    let assignment_question = analysis_json["questions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|question| question["id"] == secret_assignment)
        .unwrap();
    assert_eq!(
        assignment_question["options"]
            .as_array()
            .unwrap()
            .iter()
            .map(|option| option["id"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["target_retained_source"]
    );

    let plan = plan_migration(analysis, answer_all_for(root.path()), "Organized").unwrap();

    assert!(plan.exclusions.iter().any(|exclusion| {
        exclusion.path == Path::new("config/api_key.txt") && exclusion.reason.contains("retained")
    }));

    let collapsed_root = tempfile::tempdir().unwrap();
    fs::create_dir_all(collapsed_root.path().join("node_modules/pkg")).unwrap();
    fs::write(
        collapsed_root.path().join("node_modules/pkg/.env"),
        "SECRET=never-copy\n",
    )
    .unwrap();
    let collapsed_analysis = analyze_migration(collapsed_root.path()).unwrap();
    assert!(
        !collapsed_analysis
            .questions
            .iter()
            .any(|question| question.id == "question_secrets")
    );
    let generated_assignment =
        assignment_question_id(&collapsed_analysis, Path::new("node_modules"));
    let mut collapsed_answers = answer_all(&collapsed_analysis);
    for answer in &mut collapsed_answers {
        match answer.question_id.as_str() {
            "question_generated_content" => answer.answer = "include_generated".to_owned(),
            id if id == generated_assignment => {
                answer.answer = "target_primary_folderbase".to_owned()
            }
            _ => {}
        }
    }

    let error = plan_migration(collapsed_analysis, collapsed_answers, "Organized").unwrap_err();

    assert!(matches!(error, FolderbaseError::InvalidRecord { .. }));
    assert!(!collapsed_root.path().join("Organized").exists());

    let mut tampered_analysis = analyze_migration(root.path()).unwrap();
    let tampered_assignment =
        assignment_question_id(&tampered_analysis, Path::new("config/api_key.txt"));
    let question = tampered_analysis
        .questions
        .iter_mut()
        .find(|question| question.id == tampered_assignment)
        .unwrap();
    let MigrationQuestionKind::Assignment { content_kind, .. } = &mut question.kind else {
        panic!("expected assignment question");
    };
    *content_kind = MigrationContentKind::Canonical;
    question.options.push(MigrationOption {
        id: "target_primary_folderbase".to_owned(),
        label: "Tampered target".to_owned(),
        consequence: "Must not weaken the private analyzer classification.".to_owned(),
    });
    let mut tampered_answers = answer_all(&tampered_analysis);
    tampered_answers
        .iter_mut()
        .find(|answer| answer.question_id == tampered_assignment)
        .unwrap()
        .answer = "target_primary_folderbase".to_owned();

    let error = plan_migration(tampered_analysis, tampered_answers, "Tampered").unwrap_err();

    assert!(matches!(error, FolderbaseError::InvalidRecord { .. }));
    assert!(!root.path().join("Tampered").exists());
}

#[test]
fn workspace_and_client_shared_targets_never_become_implicit_folderbases() {
    let root = fixture();
    let analysis = analyze_migration(root.path()).unwrap();
    let targets = serde_json::to_value(&analysis.proposed_targets).unwrap();
    assert!(
        targets
            .as_array()
            .unwrap()
            .iter()
            .any(|target| { target["path"] == "Client-Shared" && target["kind"] == "scoped_view" })
    );
    assert!(
        targets
            .as_array()
            .unwrap()
            .iter()
            .any(|target| { target["path"] == "Client-Shared" && target["kind"] == "folderbase" })
    );
    assert!(
        targets
            .as_array()
            .unwrap()
            .iter()
            .any(|target| target["kind"] == "workspace")
    );
    let mut answers = answer_all(&analysis);
    answers
        .iter_mut()
        .find(|answer| answer.question_id == "question_canonical_scope")
        .unwrap()
        .answer = "proposed_boundaries".to_owned();

    let plan = plan_migration(analysis, answers, "Organized").unwrap();
    let preview = preview_migration(&plan).unwrap();

    assert!(preview.targets.iter().any(|target| {
        target.path == Path::new("Client-Shared")
            && target.kind == folderbase_core::MigrationTargetKind::ScopedView
    }));
    assert!(!plan.operations.iter().any(|operation| matches!(
        operation,
        MigrationOperation::CreateFolder { path }
            if path == Path::new("Organized/Client-Shared.folderbase")
    )));
    assert!(plan.operations.iter().any(|operation| matches!(
        operation,
        MigrationOperation::CopyFile {
            source_path,
            destination_path,
            ..
        } if source_path == Path::new("Client-Shared/Overview.md")
            && destination_path
                == Path::new("Organized/Primary.folderbase/Client-Shared/Overview.md")
    )));
}

fn initialized_folderbase_fixture() -> TempDir {
    let root = tempfile::tempdir().unwrap();
    initialize(
        &plan_initialization(
            root.path(),
            InitializationOptions {
                name: Some("Structural Test Folderbase".to_owned()),
                kind: FolderbaseKind::Project,
                create_agent_adapters: true,
            },
        )
        .unwrap(),
    )
    .unwrap();
    root
}

#[test]
fn move_object_requires_digest_bound_approval() {
    let root = initialized_folderbase_fixture();
    fs::create_dir(root.path().join("Archive")).unwrap();
    fs::write(root.path().join("notes.md"), "approved bytes\n").unwrap();
    let plan = MigrationPlan::propose_structural(
        root.path(),
        vec![MigrationOperation::move_object(
            "notes.md",
            "Archive/notes.md",
        )],
    )
    .unwrap();
    let preview = preview_migration(&plan).unwrap();
    assert_eq!(preview.structural_operations.len(), 1);
    let migration_id = plan.id.clone();
    let approved = approve_migration(plan).unwrap();
    let plan_path = root
        .path()
        .join(".folderbase/migrations")
        .join(migration_id)
        .join("plan.json");
    let mut stored: serde_json::Value =
        serde_json::from_slice(&fs::read(&plan_path).unwrap()).unwrap();
    stored["operations"][0]["destination_path"] = serde_json::json!("Archive/tampered.md");
    fs::write(&plan_path, serde_json::to_vec_pretty(&stored).unwrap()).unwrap();

    let error = apply_migration(approved).unwrap_err();

    assert!(matches!(error, FolderbaseError::MigrationApprovalMismatch));
    assert!(root.path().join("notes.md").exists());
    assert!(!root.path().join("Archive/notes.md").exists());
}

#[test]
fn verified_move_rolls_back_byte_for_byte() {
    let root = initialized_folderbase_fixture();
    fs::create_dir(root.path().join("Archive")).unwrap();
    let original = b"byte-for-byte rollback\n";
    fs::write(root.path().join("notes.md"), original).unwrap();
    let plan = MigrationPlan::propose_structural(
        root.path(),
        vec![MigrationOperation::move_object(
            "notes.md",
            "Archive/notes.md",
        )],
    )
    .unwrap();

    let result = apply_migration(approve_migration(plan).unwrap()).unwrap();
    rollback_migration(&result).unwrap();

    assert_eq!(fs::read(root.path().join("notes.md")).unwrap(), original);
    assert!(!root.path().join("Archive/notes.md").exists());
}

#[test]
fn rollback_preserves_edited_destination_and_restores_source() {
    let root = initialized_folderbase_fixture();
    fs::create_dir(root.path().join("Archive")).unwrap();
    fs::write(root.path().join("notes.md"), "approved source\n").unwrap();
    let plan = MigrationPlan::propose_structural(
        root.path(),
        vec![MigrationOperation::move_object(
            "notes.md",
            "Archive/notes.md",
        )],
    )
    .unwrap();
    let result = apply_migration(approve_migration(plan).unwrap()).unwrap();
    fs::write(
        root.path().join("Archive/notes.md"),
        "user edit after move\n",
    )
    .unwrap();

    let outcome = MigrationExecution::run(
        RootClaim::Current {
            display_root: root.path(),
        },
        MigrationCommand::Rollback {
            migration_id: &result.migration_id,
        },
    )
    .unwrap();
    let MigrationOutcome::Conflicted { conflicts, .. } = outcome else {
        panic!("edited Move destination must return durable conflict data");
    };
    assert!(!conflicts.is_empty());
    assert!(!root.path().join("notes.md").exists());
    assert_eq!(
        fs::read(root.path().join("Archive/notes.md")).unwrap(),
        b"user edit after move\n"
    );
}

#[cfg(unix)]
#[test]
fn snapshot_restore_is_inode_isolated_from_user_content() {
    use std::os::unix::fs::MetadataExt;

    let root = initialized_folderbase_fixture();
    fs::create_dir(root.path().join("Archive")).unwrap();
    fs::write(root.path().join("notes.md"), "approved source\n").unwrap();
    let plan = MigrationPlan::propose_structural(
        root.path(),
        vec![MigrationOperation::move_object(
            "notes.md",
            "Archive/notes.md",
        )],
    )
    .unwrap();
    let migration_id = plan.id.clone();
    let result = apply_migration(approve_migration(plan).unwrap()).unwrap();
    rollback_migration(&result).unwrap();

    let source = root.path().join("notes.md");
    let program_path = root
        .path()
        .join(".folderbase/migrations")
        .join(&migration_id)
        .join("transaction-v1/program.json");
    let program: serde_json::Value =
        serde_json::from_slice(&fs::read(program_path).unwrap()).unwrap();
    let snapshot_id = program["steps"]
        .as_array()
        .unwrap()
        .iter()
        .find(|step| step["kind"] == "move_file")
        .and_then(|step| step["rollback_snapshot"].as_str())
        .unwrap();
    let snapshot = program["blobs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|blob| blob["id"] == snapshot_id)
        .and_then(|blob| blob["path"].as_str())
        .map(|path| root.path().join(path))
        .unwrap();
    let source_metadata = fs::metadata(&source).unwrap();
    let snapshot_metadata = fs::metadata(&snapshot).unwrap();
    assert_ne!(
        (source_metadata.dev(), source_metadata.ino()),
        (snapshot_metadata.dev(), snapshot_metadata.ino())
    );
    fs::write(&source, "later source edit\n").unwrap();
    assert_eq!(fs::read(snapshot).unwrap(), b"approved source\n");
    assert!(!root.path().join("Archive/notes.md").exists());
}

#[cfg(unix)]
#[test]
fn rollback_recovers_reverse_move_hard_link_interruption() {
    let root = initialized_folderbase_fixture();
    fs::create_dir(root.path().join("Archive")).unwrap();
    fs::write(root.path().join("notes.md"), "approved source\n").unwrap();
    let plan = MigrationPlan::propose_structural(
        root.path(),
        vec![MigrationOperation::move_object(
            "notes.md",
            "Archive/notes.md",
        )],
    )
    .unwrap();
    let migration_id = plan.id.clone();
    apply_migration(approve_migration(plan).unwrap()).unwrap();
    fs::hard_link(
        root.path().join("Archive/notes.md"),
        root.path().join("notes.md"),
    )
    .unwrap();
    let source_identity = fs::metadata(root.path().join("notes.md")).unwrap();
    let destination_identity = fs::metadata(root.path().join("Archive/notes.md")).unwrap();

    let outcome = MigrationExecution::run(
        RootClaim::Current {
            display_root: root.path(),
        },
        MigrationCommand::Rollback {
            migration_id: &migration_id,
        },
    )
    .unwrap();
    let MigrationOutcome::Conflicted { conflicts, .. } = outcome else {
        panic!("unexpected Move hard-link alias must return durable conflict data");
    };
    assert!(!conflicts.is_empty());
    assert_eq!(
        fs::read(root.path().join("notes.md")).unwrap(),
        b"approved source\n"
    );
    assert_eq!(
        fs::read(root.path().join("Archive/notes.md")).unwrap(),
        b"approved source\n"
    );
    assert_eq!(
        fs::metadata(root.path().join("notes.md")).unwrap().ino(),
        source_identity.ino()
    );
    assert_eq!(
        fs::metadata(root.path().join("Archive/notes.md"))
            .unwrap()
            .ino(),
        destination_identity.ino()
    );
}

#[test]
fn structural_apply_refuses_without_verified_snapshot() {
    let root = initialized_folderbase_fixture();
    fs::create_dir(root.path().join("Archive")).unwrap();
    fs::write(root.path().join("notes.md"), "snapshot me\n").unwrap();
    let plan = MigrationPlan::propose_structural(
        root.path(),
        vec![MigrationOperation::move_object(
            "notes.md",
            "Archive/notes.md",
        )],
    )
    .unwrap();
    let migration_id = plan.id.clone();
    let approved = approve_migration(plan).unwrap();
    fs::remove_file(
        root.path()
            .join(".folderbase/migrations")
            .join(migration_id)
            .join("snapshots/0.bin"),
    )
    .unwrap();

    assert!(apply_migration(approved).is_err());
    assert_eq!(
        fs::read(root.path().join("notes.md")).unwrap(),
        b"snapshot me\n"
    );
    assert!(!root.path().join("Archive/notes.md").exists());
}

#[test]
fn destination_collision_causes_zero_source_loss() {
    let root = initialized_folderbase_fixture();
    fs::create_dir(root.path().join("Archive")).unwrap();
    fs::write(root.path().join("notes.md"), "source\n").unwrap();
    let plan = MigrationPlan::propose_structural(
        root.path(),
        vec![MigrationOperation::move_object(
            "notes.md",
            "Archive/notes.md",
        )],
    )
    .unwrap();
    let approved = approve_migration(plan).unwrap();
    fs::write(root.path().join("Archive/notes.md"), "third party\n").unwrap();

    let error = apply_migration(approved).unwrap_err();

    assert!(matches!(error, FolderbaseError::WouldOverwrite(_)));
    assert_eq!(fs::read(root.path().join("notes.md")).unwrap(), b"source\n");
    assert_eq!(
        fs::read(root.path().join("Archive/notes.md")).unwrap(),
        b"third party\n"
    );
}

#[test]
fn adapter_merge_preserves_user_text_outside_managed_block() {
    let root = initialized_folderbase_fixture();
    let original = "# User preface\n\n<!-- folderbase:begin -->\nold\n<!-- folderbase:end -->\n\n# User suffix\n";
    fs::write(root.path().join("AGENTS.md"), original).unwrap();
    let plan = MigrationPlan::propose_structural(
        root.path(),
        vec![MigrationOperation::update_adapter(
            "AGENTS.md",
            "Read `FOLDERBASE.md` first.\n",
        )],
    )
    .unwrap();
    let result = apply_migration(approve_migration(plan).unwrap()).unwrap();
    let merged = fs::read_to_string(root.path().join("AGENTS.md")).unwrap();

    assert!(merged.starts_with("# User preface\n\n"));
    assert!(merged.ends_with("\n# User suffix\n"));
    assert!(merged.contains("Read `FOLDERBASE.md` first."));
    assert!(!merged.contains("\nold\n"));

    rollback_migration(&result).unwrap();
    assert_eq!(
        fs::read_to_string(root.path().join("AGENTS.md")).unwrap(),
        original
    );
}

#[test]
fn migration_adapter_body_only_reserves_the_released_canonical_markers() {
    let root = initialized_folderbase_fixture();
    let body = "Keep this legacy annotation: <!-- folderbase:custom -->\n";
    let plan = MigrationPlan::propose_structural(
        root.path(),
        vec![MigrationOperation::update_adapter("AGENTS.md", body)],
    )
    .expect("Migration 0.2 permits noncanonical folderbase comments");

    apply_migration(approve_migration(plan).expect("approve"))
        .expect("Migration 0.2 preserves its released managed-block grammar");

    let merged = fs::read_to_string(root.path().join("AGENTS.md")).expect("merged adapter");
    assert!(merged.contains(body.trim_end()));
}

#[test]
fn migration_adapter_body_retains_its_legacy_utf8_byte_limit() {
    let root = initialized_folderbase_fixture();
    let error = MigrationPlan::propose_structural(
        root.path(),
        vec![MigrationOperation::update_adapter(
            "AGENTS.md",
            "é".repeat(1_100_000),
        )],
    )
    .expect_err("legacy migration adapter bodies remain bounded by UTF-8 bytes");

    assert!(
        error
            .to_string()
            .contains("managed adapter body is invalid")
    );
}

#[test]
fn changing_ignore_policy_is_structural() {
    let root = initialized_folderbase_fixture();
    fs::write(root.path().join(".folderbaseignore"), "").unwrap();
    let policy = "node_modules/\n.next/\nDerived/\n";
    let plan = MigrationPlan::propose_structural(
        root.path(),
        vec![MigrationOperation::update_ignore_policy(policy)],
    )
    .unwrap();

    assert!(matches!(
        preview_migration(&plan).unwrap().structural_operations[0],
        MigrationOperation::UpdateIgnorePolicy { .. }
    ));
    apply_migration(approve_migration(plan).unwrap()).unwrap();
    assert_eq!(
        fs::read_to_string(root.path().join(".folderbaseignore")).unwrap(),
        policy
    );
}

#[test]
fn kind_change_is_structural() {
    let root = initialized_folderbase_fixture();
    let plan = MigrationPlan::propose_structural(
        root.path(),
        vec![MigrationOperation::change_kind(FolderbaseKind::Customer)],
    )
    .unwrap();

    assert!(matches!(
        preview_migration(&plan).unwrap().structural_operations[0],
        MigrationOperation::ChangeKind {
            new_kind: FolderbaseKind::Customer,
            ..
        }
    ));
    apply_migration(approve_migration(plan).unwrap()).unwrap();
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(root.path().join(".folderbase/manifest.json")).unwrap())
            .unwrap();
    assert_eq!(manifest["folderbase"]["kind"], "customer");
}

#[test]
fn source_change_after_approval_blocks_apply() {
    let root = initialized_folderbase_fixture();
    fs::create_dir(root.path().join("Archive")).unwrap();
    fs::write(root.path().join("notes.md"), "approved\n").unwrap();
    let plan = MigrationPlan::propose_structural(
        root.path(),
        vec![MigrationOperation::move_object(
            "notes.md",
            "Archive/notes.md",
        )],
    )
    .unwrap();
    let approved = approve_migration(plan).unwrap();
    fs::write(root.path().join("notes.md"), "changed later\n").unwrap();

    let error = apply_migration(approved).unwrap_err();

    assert!(matches!(error, FolderbaseError::MigrationSourceChanged(_)));
    assert!(!root.path().join("Archive/notes.md").exists());
}

#[test]
fn lifecycle_and_relationship_changes_are_typed_and_reversible() {
    let root = initialized_folderbase_fixture();
    let objects = root.path().join(".folderbase/objects");
    fs::create_dir_all(&objects).unwrap();
    for path in [
        "canonical.md",
        "superseded.md",
        "archived.md",
        "relationship.md",
        "dependency.md",
    ] {
        fs::write(root.path().join(path), format!("{path}\n")).unwrap();
    }
    let fixtures = [
        (
            "canonical.json",
            serde_json::json!({
                "id": "obj_019f9b75-4f42-7f65-a012-2bfecdd8c473",
                "type": "file",
                "path": "canonical.md",
                "lifecycle": {"status": "draft"},
                "provenance": {
                    "created_at": "2026-07-27T00:00:00Z",
                    "source": "test"
                },
                "relationships": []
            }),
        ),
        (
            "superseded.json",
            serde_json::json!({
                "id": "obj_019f9b75-4f42-7f65-a012-2bfecdd8c474",
                "type": "file",
                "path": "superseded.md",
                "lifecycle": {"status": "canonical"},
                "provenance": {
                    "created_at": "2026-07-27T00:00:00Z",
                    "source": "test"
                },
                "relationships": []
            }),
        ),
        (
            "archived.json",
            serde_json::json!({
                "id": "obj_019f9b75-4f42-7f65-a012-2bfecdd8c475",
                "type": "file",
                "path": "archived.md",
                "lifecycle": {
                    "status": "canonical",
                    "remote_size": 12,
                    "expected_restore_size": 12
                },
                "provenance": {
                    "created_at": "2026-07-27T00:00:00Z",
                    "source": "test"
                },
                "relationships": []
            }),
        ),
        (
            "relationship.json",
            serde_json::json!({
                "id": "obj_019f9b75-4f42-7f65-a012-2bfecdd8c476",
                "type": "file",
                "path": "relationship.md",
                "lifecycle": {"status": "canonical"},
                "provenance": {
                    "created_at": "2026-07-27T00:00:00Z",
                    "source": "test"
                },
                "relationships": []
            }),
        ),
        (
            "dependency.json",
            serde_json::json!({
                "id": "obj_019f9b75-4f42-7f65-a012-2bfecdd8c477",
                "type": "file",
                "path": "dependency.md",
                "lifecycle": {"status": "canonical"},
                "provenance": {
                    "created_at": "2026-07-27T00:00:00Z",
                    "source": "test"
                },
                "relationships": []
            }),
        ),
    ];
    for (name, record) in &fixtures {
        fs::write(
            objects.join(name),
            serde_json::to_vec_pretty(record).unwrap(),
        )
        .unwrap();
    }
    let originals = fixtures
        .iter()
        .map(|(name, _)| ((*name).to_owned(), fs::read(objects.join(name)).unwrap()))
        .collect::<Vec<_>>();
    let plan = MigrationPlan::propose_structural(
        root.path(),
        vec![
            MigrationOperation::mark_canonical(".folderbase/objects/canonical.json"),
            MigrationOperation::mark_superseded(
                ".folderbase/objects/superseded.json",
                "obj_019f9b75-4f42-7f65-a012-2bfecdd8c478",
            ),
            MigrationOperation::archive_object(".folderbase/objects/archived.json"),
            MigrationOperation::add_relationship(
                ".folderbase/objects/relationship.json",
                "depends_on",
                "obj_019f9b75-4f42-7f65-a012-2bfecdd8c477",
            ),
        ],
    )
    .unwrap();

    let result = apply_migration(approve_migration(plan).unwrap()).unwrap();
    let read_record = |name: &str| -> serde_json::Value {
        serde_json::from_slice(&fs::read(objects.join(name)).unwrap()).unwrap()
    };
    assert_eq!(
        read_record("canonical.json")["lifecycle"]["status"],
        "canonical"
    );
    assert_eq!(
        read_record("superseded.json")["lifecycle"],
        serde_json::json!({
            "status": "superseded",
            "superseded_by": "obj_019f9b75-4f42-7f65-a012-2bfecdd8c478"
        })
    );
    assert_eq!(
        read_record("archived.json")["lifecycle"]["status"],
        "archived"
    );
    assert_eq!(
        read_record("relationship.json")["relationships"][0],
        serde_json::json!({
            "type": "depends_on",
            "target": "obj_019f9b75-4f42-7f65-a012-2bfecdd8c477"
        })
    );

    rollback_migration(&result).unwrap();
    for (name, original) in originals {
        assert_eq!(fs::read(objects.join(name)).unwrap(), original);
    }
}

#[test]
fn archive_requires_verified_restore_metadata() {
    let root = initialized_folderbase_fixture();
    let record_path = root
        .path()
        .join(".folderbase/objects/archive-candidate.json");
    fs::create_dir_all(record_path.parent().unwrap()).unwrap();
    fs::write(root.path().join("archive-candidate.md"), "durable bytes\n").unwrap();
    fs::write(
        &record_path,
        serde_json::to_vec_pretty(&serde_json::json!({
            "id": "obj_019f9b75-4f42-7f65-a012-2bfecdd8c479",
            "type": "file",
            "path": "archive-candidate.md",
            "lifecycle": {"status": "canonical"},
            "provenance": {
                "created_at": "2026-07-27T00:00:00Z",
                "source": "test"
            },
            "relationships": []
        }))
        .unwrap(),
    )
    .unwrap();

    let error = MigrationPlan::propose_structural(
        root.path(),
        vec![MigrationOperation::archive_object(
            ".folderbase/objects/archive-candidate.json",
        )],
    )
    .unwrap_err();

    assert!(matches!(
        error,
        FolderbaseError::InvalidRecord { message, .. }
            if message.contains("expected_restore_size")
    ));
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&fs::read(record_path).unwrap()).unwrap()["lifecycle"]
            ["status"],
        "canonical"
    );
}

#[test]
fn structural_plan_refuses_implicit_nested_folderbase_transfer() {
    let root = initialized_folderbase_fixture();
    let nested = root.path().join("Client");
    let nested_fixture = tempfile::tempdir().unwrap();
    initialize(
        &plan_initialization(
            nested_fixture.path(),
            InitializationOptions {
                name: Some("Client Folderbase".to_owned()),
                kind: FolderbaseKind::Customer,
                create_agent_adapters: false,
            },
        )
        .unwrap(),
    )
    .unwrap();
    fs::create_dir_all(nested.join(".folderbase")).unwrap();
    fs::copy(
        nested_fixture.path().join(".folderbase/manifest.json"),
        nested.join(".folderbase/manifest.json"),
    )
    .unwrap();
    fs::write(root.path().join("notes.md"), "parent-owned\n").unwrap();

    let error = MigrationPlan::propose_structural(
        root.path(),
        vec![MigrationOperation::move_object(
            "notes.md",
            "Client/notes.md",
        )],
    )
    .unwrap_err();

    assert!(matches!(error, FolderbaseError::UnsafePath(path) if path == Path::new("Client")));
    assert!(root.path().join("notes.md").exists());
    assert!(!nested.join("notes.md").exists());
}

#[test]
fn structural_plan_refuses_case_folded_nested_folderbase_marker() {
    let root = initialized_folderbase_fixture();
    fs::create_dir_all(root.path().join("Client/.FOLDERBASE")).unwrap();
    fs::write(root.path().join("Client/folderbase.MD"), "# Child\n").unwrap();
    fs::write(
        root.path().join("Client/.FOLDERBASE/manifest.JSON"),
        "malformed but still a boundary\n",
    )
    .unwrap();
    fs::write(root.path().join("notes.md"), "parent-owned\n").unwrap();

    let error = MigrationPlan::propose_structural(
        root.path(),
        vec![MigrationOperation::move_object(
            "notes.md",
            "Client/notes.md",
        )],
    )
    .unwrap_err();

    assert!(matches!(error, FolderbaseError::UnsafePath(path) if path == Path::new("Client")));
    assert!(root.path().join("notes.md").exists());
    assert!(!root.path().join("Client/notes.md").exists());
}

#[test]
fn rollback_refuses_to_restore_parent_history_into_a_new_nested_folderbase() {
    let root = initialized_folderbase_fixture();
    fs::create_dir_all(root.path().join("Client")).unwrap();
    fs::create_dir_all(root.path().join("Archive")).unwrap();
    fs::write(root.path().join("Client/notes.md"), "parent-owned\n").unwrap();
    let plan = MigrationPlan::propose_structural(
        root.path(),
        vec![MigrationOperation::move_object(
            "Client/notes.md",
            "Archive/notes.md",
        )],
    )
    .unwrap();
    let result = apply_migration(approve_migration(plan).unwrap()).unwrap();
    fs::create_dir_all(root.path().join("Client/.folderbase")).unwrap();
    fs::write(root.path().join("Client/FOLDERBASE.md"), "# Child\n").unwrap();
    fs::write(
        root.path().join("Client/.folderbase/manifest.json"),
        "malformed but still a boundary\n",
    )
    .unwrap();

    let outcome = MigrationExecution::run(
        RootClaim::Current {
            display_root: root.path(),
        },
        MigrationCommand::Rollback {
            migration_id: &result.migration_id,
        },
    )
    .unwrap();
    let MigrationOutcome::Conflicted { conflicts, .. } = outcome else {
        panic!("new nested boundary must return durable conflict data");
    };
    assert!(!conflicts.is_empty());
    assert!(!root.path().join("Client/notes.md").exists());
    assert_eq!(
        fs::read(root.path().join("Archive/notes.md")).unwrap(),
        b"parent-owned\n"
    );
}

#[test]
fn rollback_fails_closed_on_case_folded_aliases_without_granting_them_authority() {
    let root = initialized_folderbase_fixture();
    fs::create_dir_all(root.path().join("Client")).unwrap();
    fs::create_dir_all(root.path().join("Archive")).unwrap();
    fs::write(root.path().join("Client/notes.md"), "parent-owned\n").unwrap();
    let plan = MigrationPlan::propose_structural(
        root.path(),
        vec![MigrationOperation::move_object(
            "Client/notes.md",
            "Archive/notes.md",
        )],
    )
    .unwrap();
    let result = apply_migration(approve_migration(plan).unwrap()).unwrap();
    fs::create_dir_all(root.path().join("Client/.FOLDERBASE")).unwrap();
    fs::write(root.path().join("Client/folderbase.MD"), "# Child\n").unwrap();
    fs::write(
        root.path().join("Client/.FOLDERBASE/manifest.JSON"),
        "malformed but still a boundary\n",
    )
    .unwrap();

    let outcome = MigrationExecution::run(
        RootClaim::Current {
            display_root: root.path(),
        },
        MigrationCommand::Rollback {
            migration_id: &result.migration_id,
        },
    )
    .unwrap();
    let MigrationOutcome::Conflicted { conflicts, .. } = outcome else {
        panic!("case-folded nested-boundary aliases must return durable conflict data");
    };
    assert!(!conflicts.is_empty());
    assert!(!root.path().join("Client/notes.md").exists());
    assert_eq!(
        fs::read(root.path().join("Archive/notes.md")).unwrap(),
        b"parent-owned\n"
    );
}

#[test]
fn ordinary_moves_refuse_protocol_and_repository_control_paths() {
    let source_root = initialized_folderbase_fixture();
    fs::create_dir_all(source_root.path().join("Archive")).unwrap();
    let source_error = MigrationPlan::propose_structural(
        source_root.path(),
        vec![MigrationOperation::move_object(
            ".folderbase/manifest.json",
            "Archive/manifest.json",
        )],
    )
    .unwrap_err();
    assert!(matches!(source_error, FolderbaseError::UnsafePath(_)));
    assert!(
        source_root
            .path()
            .join(".folderbase/manifest.json")
            .exists()
    );

    let destination_root = initialized_folderbase_fixture();
    fs::write(destination_root.path().join("notes.md"), "content\n").unwrap();
    let destination_error = MigrationPlan::propose_structural(
        destination_root.path(),
        vec![MigrationOperation::move_object("notes.md", ".git/notes.md")],
    )
    .unwrap_err();
    assert!(matches!(destination_error, FolderbaseError::UnsafePath(_)));
    assert!(destination_root.path().join("notes.md").exists());
}

#[test]
fn ordinary_move_can_reorganize_an_optional_v05_folderbase_md() {
    let root = initialized_folderbase_fixture();
    fs::create_dir(root.path().join("Archive")).unwrap();
    fs::write(root.path().join("FOLDERBASE.md"), "# Optional narrative\n").unwrap();
    let plan = MigrationPlan::propose_structural(
        root.path(),
        vec![MigrationOperation::move_object(
            "FOLDERBASE.md",
            "Archive/FOLDERBASE.md",
        )],
    )
    .expect("ordinary narrative move plan");

    apply_migration(approve_migration(plan).expect("approve"))
        .expect("apply ordinary narrative move");

    assert!(!root.path().join("FOLDERBASE.md").exists());
    assert_eq!(
        fs::read(root.path().join("Archive/FOLDERBASE.md")).unwrap(),
        b"# Optional narrative\n"
    );
}

#[test]
fn ordinary_move_refuses_a_version_tracked_object() {
    let root = initialized_folderbase_fixture();
    fs::create_dir(root.path().join("Archive")).unwrap();
    fs::write(root.path().join("notes.md"), "tracked\n").unwrap();
    LocalVersionStore::open(root.path())
        .unwrap()
        .capture_file("notes.md")
        .unwrap();

    let error = MigrationPlan::propose_structural(
        root.path(),
        vec![MigrationOperation::move_object(
            "notes.md",
            "Archive/notes.md",
        )],
    )
    .unwrap_err();

    assert!(matches!(
        error,
        FolderbaseError::InvalidRecord { message, .. }
            if message.contains("tracked")
    ));
    assert!(root.path().join("notes.md").exists());
    assert!(!root.path().join("Archive/notes.md").exists());
}

#[test]
fn move_object_streams_files_larger_than_structural_text_records() {
    let root = initialized_folderbase_fixture();
    fs::create_dir(root.path().join("Archive")).unwrap();
    let bytes = vec![0x5a; (8 * 1024 * 1024) + 1];
    fs::write(root.path().join("video.bin"), &bytes).unwrap();
    let plan = MigrationPlan::propose_structural(
        root.path(),
        vec![MigrationOperation::move_object(
            "video.bin",
            "Archive/video.bin",
        )],
    )
    .unwrap();

    let result = apply_migration(approve_migration(plan).unwrap()).unwrap();

    assert_eq!(
        fs::read(root.path().join("Archive/video.bin")).unwrap(),
        bytes
    );
    rollback_migration(&result).unwrap();
    assert!(root.path().join("video.bin").exists());
}

#[cfg(unix)]
#[test]
fn structural_snapshot_preserves_restrictive_source_permissions() {
    let root = initialized_folderbase_fixture();
    fs::create_dir(root.path().join("Archive")).unwrap();
    let source = root.path().join("private.txt");
    fs::write(&source, "private\n").unwrap();
    fs::set_permissions(&source, fs::Permissions::from_mode(0o600)).unwrap();
    let plan = MigrationPlan::propose_structural(
        root.path(),
        vec![MigrationOperation::move_object(
            "private.txt",
            "Archive/private.txt",
        )],
    )
    .unwrap();
    let migration_id = plan.id.clone();

    approve_migration(plan).unwrap();

    let snapshot = root
        .path()
        .join(".folderbase/migrations")
        .join(migration_id)
        .join("snapshots/0.bin");
    assert_eq!(
        fs::metadata(snapshot).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

#[test]
fn approval_recovers_a_complete_snapshot_set_after_restart() {
    let root = initialized_folderbase_fixture();
    fs::create_dir(root.path().join("Archive")).unwrap();
    fs::write(root.path().join("notes.md"), "recover approval\n").unwrap();
    let plan = MigrationPlan::propose_structural(
        root.path(),
        vec![MigrationOperation::move_object(
            "notes.md",
            "Archive/notes.md",
        )],
    )
    .unwrap();
    let migration_id = plan.id.clone();
    approve_migration(plan).unwrap();
    let plan_path = root
        .path()
        .join(".folderbase/migrations")
        .join(&migration_id)
        .join("plan.json");
    let mut interrupted: serde_json::Value =
        serde_json::from_slice(&fs::read(&plan_path).unwrap()).unwrap();
    interrupted["state"] = serde_json::json!("proposed");
    interrupted
        .as_object_mut()
        .unwrap()
        .remove("approval_digest");
    interrupted["operations"][0]["snapshot_path"] = serde_json::Value::Null;
    interrupted["operations"][0]["snapshot_sha256"] = serde_json::Value::Null;
    fs::write(&plan_path, serde_json::to_vec_pretty(&interrupted).unwrap()).unwrap();

    let reopened = MigrationPlan::reopen(root.path(), &migration_id).unwrap();
    let approved = approve_migration(reopened).unwrap();

    assert_eq!(
        apply_migration(approved).unwrap().state,
        MigrationState::Verified
    );
}

#[test]
fn structural_operations_conform_to_schema_without_a_delete_primitive() {
    let root = fixture();
    let analysis = analyze_migration(root.path()).unwrap();
    let plan = plan_migration(analysis, answer_all_for(root.path()), "Organized").unwrap();
    let base = serde_json::to_value(plan).unwrap();
    let schema_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../protocol/schemas/0.2/migration.schema.json");
    let schema: serde_json::Value =
        serde_json::from_slice(&fs::read(&schema_path).unwrap()).unwrap();
    let validator = jsonschema::draft202012::options()
        .should_validate_formats(true)
        .build(&schema)
        .unwrap();
    let operations = [
        MigrationOperation::move_object("notes.md", "Archive/notes.md"),
        MigrationOperation::update_adapter("AGENTS.md", "Read FOLDERBASE.md first."),
        MigrationOperation::update_ignore_policy("node_modules/\n"),
        MigrationOperation::update_policy("archive_after_days", serde_json::json!(90)),
        MigrationOperation::change_kind(FolderbaseKind::Organization),
        MigrationOperation::mark_canonical(".folderbase/objects/canonical.json"),
        MigrationOperation::mark_superseded(
            ".folderbase/objects/superseded.json",
            "obj_019f9b75-4f42-7f65-a012-2bfecdd8c478",
        ),
        MigrationOperation::archive_object(".folderbase/objects/archived.json"),
        MigrationOperation::add_relationship(
            ".folderbase/objects/relationship.json",
            "depends_on",
            "obj_019f9b75-4f42-7f65-a012-2bfecdd8c477",
        ),
    ];
    let digest = "0".repeat(64);

    for operation in operations {
        let mut encoded_operation = serde_json::to_value(operation).unwrap();
        for field in ["expected_sha256", "expected_result_sha256"] {
            if encoded_operation.get(field).is_some() {
                encoded_operation[field] = serde_json::Value::String(digest.clone());
            }
        }
        let operation_type = encoded_operation["type"].as_str().unwrap().to_owned();
        let mut document = base.clone();
        document["operations"] = serde_json::json!([encoded_operation]);
        assert!(
            validator.is_valid(&document),
            "{operation_type} must conform to Migration Protocol 0.2"
        );
    }

    let mut delete_document = base;
    delete_document["operations"] = serde_json::json!([{
        "type": "delete_object",
        "path": "notes.md"
    }]);
    assert!(
        !validator.is_valid(&delete_document),
        "the protocol must not expose a delete-only primitive"
    );
}

fn answer_all_for(root: &Path) -> Vec<MigrationAnswer> {
    let analysis = analyze_migration(root).unwrap();
    answer_all(&analysis)
}

fn assignment_question_id(
    analysis: &folderbase_core::MigrationAnalysis,
    source_path: &Path,
) -> String {
    serde_json::to_value(&analysis.questions)
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .find(|question| {
            (question["kind"]["type"] == "assignment"
                && question["kind"]["source_path"] == source_path.to_string_lossy().as_ref())
                || (question["kind"]["type"] == "assignment_group"
                    && question["kind"]["source_paths"]
                        .as_array()
                        .is_some_and(|paths| {
                            paths
                                .iter()
                                .any(|path| path == source_path.to_string_lossy().as_ref())
                        }))
        })
        .and_then(|question| question["id"].as_str())
        .unwrap()
        .to_owned()
}

fn tree(root: &Path) -> Vec<String> {
    let mut paths = walkdir::WalkDir::new(root)
        .sort_by_file_name()
        .into_iter()
        .filter_map(Result::ok)
        .filter_map(|entry| {
            entry
                .path()
                .strip_prefix(root)
                .ok()
                .map(|path| path.to_string_lossy().into_owned())
        })
        .collect::<Vec<_>>();
    paths.sort();
    paths
}

fn create_nested_folderbase(root: impl AsRef<Path>, manifest: &str) {
    let root = root.as_ref();
    fs::create_dir_all(root.join(".folderbase")).unwrap();
    fs::write(root.join("FOLDERBASE.md"), "# Nested folderbase\n").unwrap();
    fs::write(root.join(".folderbase/manifest.json"), manifest).unwrap();
    fs::write(root.join("never-expose.txt"), "nested secret bytes\n").unwrap();
}

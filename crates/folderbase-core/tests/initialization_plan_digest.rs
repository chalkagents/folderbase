use std::collections::BTreeMap;
use std::fs;

use folderbase_core::{
    FolderbaseError, FolderbaseKind, InitializationOptions, InitializationPlanDigest,
    TemplateAnswerValue, initialize_with_expected_plan_digest, load_builtin_template,
    plan_initialization, plan_template_initialization,
};

#[test]
fn unchanged_repeated_plans_have_the_same_digest_despite_volatile_identity() {
    let root = tempfile::tempdir().expect("ordinary folder");
    fs::write(root.path().join("notes.md"), "# Existing work\n").expect("existing file");

    let first =
        plan_initialization(root.path(), InitializationOptions::default()).expect("first plan");
    let second =
        plan_initialization(root.path(), InitializationOptions::default()).expect("second plan");

    assert_ne!(
        first.folderbase_id(),
        second.folderbase_id(),
        "the fixture must prove volatile initialization identity changed"
    );
    assert_eq!(first.plan_digest(), second.plan_digest());
    assert_eq!(first.plan_digest().algorithm(), "sha256");
    assert_eq!(first.plan_digest().digest().len(), 64);
}

#[test]
fn request_semantics_change_the_plan_digest() {
    let root = tempfile::tempdir().expect("ordinary folder");
    let baseline =
        plan_initialization(root.path(), InitializationOptions::default()).expect("baseline plan");

    let changed = plan_initialization(
        root.path(),
        InitializationOptions {
            name: Some("Different name".to_owned()),
            kind: FolderbaseKind::Organization,
            create_agent_adapters: false,
        },
    )
    .expect("changed plan");

    assert_ne!(baseline.plan_digest(), changed.plan_digest());
}

#[test]
fn visible_destination_changes_change_the_plan_digest() {
    let root = tempfile::tempdir().expect("ordinary folder");
    fs::write(root.path().join("notes.md"), "before\n").expect("existing file");
    let baseline =
        plan_initialization(root.path(), InitializationOptions::default()).expect("baseline plan");

    fs::write(root.path().join("late.md"), "arrived later\n").expect("late file");
    let with_late_file =
        plan_initialization(root.path(), InitializationOptions::default()).expect("late file plan");
    assert_ne!(baseline.plan_digest(), with_late_file.plan_digest());

    fs::write(root.path().join("notes.md"), "after\n").expect("changed file");
    let with_changed_target = plan_initialization(root.path(), InitializationOptions::default())
        .expect("changed target plan");
    assert_ne!(
        with_late_file.plan_digest(),
        with_changed_target.plan_digest()
    );
}

#[test]
fn nested_folderbase_boundaries_change_the_plan_digest_without_hashing_their_contents() {
    let root = tempfile::tempdir().expect("ordinary folder");
    let nested = root.path().join("client");
    fs::create_dir(&nested).expect("nested directory");
    fs::write(nested.join("private.md"), "private context\n").expect("nested content");
    let before = plan_initialization(root.path(), InitializationOptions::default())
        .expect("before boundary");

    fs::write(nested.join("FOLDERBASE.md"), "# Client\n").expect("nested entry");
    fs::create_dir(nested.join(".folderbase")).expect("nested state");
    fs::write(nested.join(".folderbase/manifest.json"), "{}\n").expect("nested marker");
    let bounded =
        plan_initialization(root.path(), InitializationOptions::default()).expect("bounded plan");
    assert_ne!(before.plan_digest(), bounded.plan_digest());

    fs::write(nested.join("private.md"), "changed behind boundary\n").expect("nested edit");
    let changed_behind_boundary =
        plan_initialization(root.path(), InitializationOptions::default()).expect("bounded replan");
    assert_eq!(bounded.plan_digest(), changed_behind_boundary.plan_digest());
}

#[test]
fn reconstructable_tree_contents_do_not_create_approval_churn() {
    let root = tempfile::tempdir().expect("ordinary folder");
    fs::create_dir(root.path().join("node_modules")).expect("reconstructable directory");
    fs::write(root.path().join("node_modules/cache"), "one\n").expect("cache");
    let before =
        plan_initialization(root.path(), InitializationOptions::default()).expect("before");

    fs::write(root.path().join("node_modules/cache"), "two\n").expect("cache update");
    fs::write(root.path().join("node_modules/late"), "late\n").expect("late cache");
    let after = plan_initialization(root.path(), InitializationOptions::default()).expect("after");

    assert_eq!(before.plan_digest(), after.plan_digest());
}

#[test]
fn template_identity_and_answers_change_the_plan_digest() {
    let root = tempfile::tempdir().expect("ordinary folder");
    let package = load_builtin_template("folderbase.project", "0.2.2").expect("project template");
    let baseline_answers = project_answers("Ship the approval binding.");
    let baseline = plan_template_initialization(
        root.path(),
        InitializationOptions::default(),
        &package,
        &baseline_answers,
    )
    .expect("baseline template plan");

    let changed_answers = project_answers("Ship a different decision.");
    let changed = plan_template_initialization(
        root.path(),
        InitializationOptions::default(),
        &package,
        &changed_answers,
    )
    .expect("changed template plan");

    assert_ne!(baseline.plan_digest(), changed.plan_digest());

    let prior_package =
        load_builtin_template("folderbase.project", "0.2.1").expect("prior project template");
    let prior_package_plan = plan_template_initialization(
        root.path(),
        InitializationOptions::default(),
        &prior_package,
        &baseline_answers,
    )
    .expect("prior package plan");
    assert_ne!(baseline.plan_digest(), prior_package_plan.plan_digest());
}

#[test]
fn exact_approved_digest_replans_then_applies_and_returns_the_digest() {
    let root = tempfile::tempdir().expect("ordinary folder");
    fs::write(root.path().join("notes.md"), "preserve me\n").expect("existing file");
    let plan =
        plan_initialization(root.path(), InitializationOptions::default()).expect("approved plan");
    let approved = plan.plan_digest().clone();

    let result = initialize_with_expected_plan_digest(&plan, &approved).expect("approved apply");

    assert_eq!(result.applied_plan_digest, approved);
    assert!(root.path().join(".folderbase/manifest.json").is_file());
    assert_eq!(
        fs::read_to_string(root.path().join("notes.md")).expect("preserved file"),
        "preserve me\n"
    );
}

#[test]
fn stale_or_wrong_approved_digest_refuses_before_any_write() {
    let stale_root = tempfile::tempdir().expect("stale folder");
    let stale_plan = plan_initialization(stale_root.path(), InitializationOptions::default())
        .expect("approved plan");
    let approved = stale_plan.plan_digest().clone();
    fs::write(stale_root.path().join("late.md"), "late\n").expect("late file");

    let error = initialize_with_expected_plan_digest(&stale_plan, &approved)
        .expect_err("destination changed after approval");
    assert!(matches!(
        error,
        FolderbaseError::InitializationPlanChanged { .. }
    ));
    assert_no_protocol_writes(stale_root.path());

    let wrong_root = tempfile::tempdir().expect("wrong digest folder");
    let wrong_plan = plan_initialization(wrong_root.path(), InitializationOptions::default())
        .expect("current plan");
    let wrong = InitializationPlanDigest::parse_sha256("0".repeat(64)).expect("valid wrong digest");
    let error = initialize_with_expected_plan_digest(&wrong_plan, &wrong)
        .expect_err("wrong digest must not apply");
    assert!(matches!(
        error,
        FolderbaseError::InitializationPlanChanged { .. }
    ));
    assert_no_protocol_writes(wrong_root.path());
}

#[test]
fn changed_content_nested_boundary_and_template_request_refuse_approved_apply() {
    let changed_root = tempfile::tempdir().expect("changed folder");
    fs::write(changed_root.path().join("notes.md"), "before\n").expect("existing file");
    let changed_plan = plan_initialization(changed_root.path(), InitializationOptions::default())
        .expect("approved content plan");
    let approved = changed_plan.plan_digest().clone();
    fs::write(changed_root.path().join("notes.md"), "after\n").expect("changed content");
    assert!(matches!(
        initialize_with_expected_plan_digest(&changed_plan, &approved),
        Err(FolderbaseError::InitializationPlanChanged { .. })
    ));
    assert_no_protocol_writes(changed_root.path());

    let boundary_root = tempfile::tempdir().expect("boundary folder");
    let nested = boundary_root.path().join("client");
    fs::create_dir(&nested).expect("nested directory");
    let boundary_plan = plan_initialization(boundary_root.path(), InitializationOptions::default())
        .expect("approved boundary plan");
    let approved = boundary_plan.plan_digest().clone();
    fs::write(nested.join("FOLDERBASE.md"), "# Client\n").expect("nested entry");
    fs::create_dir(nested.join(".folderbase")).expect("nested state");
    fs::write(nested.join(".folderbase/manifest.json"), "{}\n").expect("nested marker");
    assert!(matches!(
        initialize_with_expected_plan_digest(&boundary_plan, &approved),
        Err(FolderbaseError::InitializationPlanChanged { .. })
    ));
    assert_no_protocol_writes(boundary_root.path());

    let template_root = tempfile::tempdir().expect("template folder");
    let package = load_builtin_template("folderbase.project", "0.2.2").expect("project template");
    let reviewed = plan_template_initialization(
        template_root.path(),
        InitializationOptions::default(),
        &package,
        &project_answers("Reviewed action."),
    )
    .expect("reviewed template plan");
    let changed_request = plan_template_initialization(
        template_root.path(),
        InitializationOptions::default(),
        &package,
        &project_answers("Unreviewed action."),
    )
    .expect("changed template plan");
    assert!(matches!(
        initialize_with_expected_plan_digest(&changed_request, reviewed.plan_digest()),
        Err(FolderbaseError::InitializationPlanChanged { .. })
    ));
    assert_no_protocol_writes(template_root.path());
}

#[test]
fn malformed_digest_is_typed_and_cannot_write() {
    let root = tempfile::tempdir().expect("ordinary folder");

    let error = InitializationPlanDigest::parse_sha256("NOT-A-SHA256")
        .expect_err("malformed digest must be refused");

    assert!(matches!(
        error,
        FolderbaseError::InvalidInitializationPlanDigest
    ));
    assert_no_protocol_writes(root.path());

    let plan =
        plan_initialization(root.path(), InitializationOptions::default()).expect("current plan");
    let deserialized: InitializationPlanDigest = serde_json::from_value(serde_json::json!({
        "algorithm": "md5",
        "digest": "0".repeat(64)
    }))
    .expect("public digest JSON shape");
    let error = initialize_with_expected_plan_digest(&plan, &deserialized)
        .expect_err("deserialized digest must be validated by Core");
    assert!(matches!(
        error,
        FolderbaseError::InvalidInitializationPlanDigest
    ));
    assert_no_protocol_writes(root.path());
}

fn project_answers(next_action: &str) -> BTreeMap<String, TemplateAnswerValue> {
    BTreeMap::from([
        (
            "purpose".to_owned(),
            TemplateAnswerValue::Text("Prove approved initialization plans.".to_owned()),
        ),
        (
            "current_state".to_owned(),
            TemplateAnswerValue::Text("The Core owns the decision.".to_owned()),
        ),
        (
            "next_action".to_owned(),
            TemplateAnswerValue::Text(next_action.to_owned()),
        ),
    ])
}

fn assert_no_protocol_writes(root: &std::path::Path) {
    for path in [
        ".folderbase",
        "FOLDERBASE.md",
        ".folderbaseignore",
        "AGENTS.md",
        "CLAUDE.md",
    ] {
        assert!(
            !root.join(path).exists(),
            "{path} must not exist after refusal"
        );
    }
}

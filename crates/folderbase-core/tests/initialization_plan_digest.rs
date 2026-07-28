use std::collections::BTreeMap;
use std::fs;
use std::io::{Seek, SeekFrom, Write};

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
fn visible_destination_membership_changes_but_preserved_file_contents_do_not_change_the_plan_digest()
 {
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
    assert_eq!(
        with_late_file.plan_digest(),
        with_changed_target.plan_digest(),
        "Core never writes a preserved ordinary file, so its content is not part of approval"
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
fn every_canonical_reconstructable_tree_is_collapsed_for_initialization_approval() {
    for name in [
        "node_modules",
        ".next",
        ".nuxt",
        ".sites",
        ".svelte-kit",
        ".wrangler",
        "dist",
        "build",
        "coverage",
        ".build",
        ".swiftpm",
        ".venv",
        "__pycache__",
        ".dart_tool",
        "Pods",
        "DerivedData",
        "target",
    ] {
        let root = tempfile::tempdir().expect("ordinary folder");
        let tree = root.path().join(name);
        fs::create_dir(&tree).expect("reconstructable directory");
        fs::write(tree.join("cache"), "one\n").expect("cache");
        let before =
            plan_initialization(root.path(), InitializationOptions::default()).expect("before");

        fs::write(tree.join("cache"), "two\n").expect("cache update");
        fs::write(tree.join("late"), "late\n").expect("late cache");
        let after =
            plan_initialization(root.path(), InitializationOptions::default()).expect("after");

        assert_eq!(
            before.plan_digest(),
            after.plan_digest(),
            "{name} must use the same reconstructable policy as inspection and workspace listing"
        );
    }
}

#[test]
fn a_large_sparse_preserved_file_is_metadata_only_and_can_change_before_apply() {
    const MOVIE_BYTES: u64 = 10 * 1024 * 1024 * 1024;
    const SAMPLE_OFFSET: u64 = 5 * 1024 * 1024 * 1024;
    let root = tempfile::tempdir().expect("ordinary folder");
    let movie_path = root.path().join("feature-film.mov");
    let mut movie = fs::File::create(&movie_path).expect("sparse movie");
    movie.set_len(MOVIE_BYTES).expect("sparse length");
    movie.seek(SeekFrom::Start(SAMPLE_OFFSET)).expect("seek");
    movie.write_all(b"before").expect("sample bytes");
    movie.sync_all().expect("movie synced");

    let plan =
        plan_initialization(root.path(), InitializationOptions::default()).expect("approved plan");
    let approved = plan.plan_digest().clone();

    movie.seek(SeekFrom::Start(SAMPLE_OFFSET)).expect("seek");
    movie.write_all(b"after!").expect("same-length user edit");
    movie.sync_all().expect("movie synced");

    let result = initialize_with_expected_plan_digest(&plan, &approved)
        .expect("preserved movie contents are outside the write set");
    assert_eq!(result.applied_plan_digest, approved);
    assert_eq!(
        fs::metadata(movie_path).expect("preserved movie").len(),
        MOVIE_BYTES
    );
}

#[test]
fn traversal_depth_is_bounded_with_a_typed_no_write_refusal() {
    let root = tempfile::tempdir().expect("ordinary folder");
    let mut deepest = root.path().to_path_buf();
    for index in 0..66 {
        deepest.push(format!("d{index}"));
        fs::create_dir(&deepest).expect("nested directory");
    }

    let error = plan_initialization(root.path(), InitializationOptions::default())
        .expect_err("over-deep inventory must be refused");
    assert!(matches!(
        error,
        FolderbaseError::InitializationInventoryLimitExceeded { limit: "depth", .. }
    ));
    assert_no_protocol_writes(root.path());
}

#[cfg(unix)]
#[test]
fn a_preserved_file_replaced_by_an_outside_symlink_is_refused_without_following_it() {
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir().expect("ordinary folder");
    let outside = tempfile::tempdir().expect("outside folder");
    let outside_file = outside.path().join("private.md");
    fs::write(&outside_file, "outside bytes\n").expect("outside file");
    let preserved = root.path().join("notes.md");
    fs::write(&preserved, "inside bytes\n").expect("inside file");

    let plan =
        plan_initialization(root.path(), InitializationOptions::default()).expect("approved plan");
    let approved = plan.plan_digest().clone();
    fs::remove_file(&preserved).expect("replace preserved file");
    symlink(&outside_file, &preserved).expect("outside symlink");

    let error = initialize_with_expected_plan_digest(&plan, &approved)
        .expect_err("file-to-symlink swap must be refused");
    assert!(matches!(
        error,
        FolderbaseError::InitializationDestinationChanged(_)
    ));
    assert_no_protocol_writes(root.path());
    assert_eq!(
        fs::read_to_string(outside_file).expect("outside bytes preserved"),
        "outside bytes\n"
    );
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
fn exact_approved_digest_applies_the_single_core_plan_and_returns_the_digest() {
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
        FolderbaseError::InitializationDestinationChanged(_)
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
fn nested_boundary_and_template_request_changes_refuse_approved_apply() {
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
        Err(FolderbaseError::InitializationDestinationChanged(_))
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

use assert_cmd::Command;
use predicates::prelude::*;

fn folderbase() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("folderbase"))
}

fn migration_assignment_question(root: &std::path::Path, source_path: &str) -> String {
    let output = folderbase()
        .args([
            "migrate",
            root.to_str().unwrap(),
            "--destination",
            "Organized",
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let analysis: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    analysis["questions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|question| {
            question["kind"]["type"] == "assignment"
                && question["kind"]["source_path"] == source_path
        })
        .and_then(|question| question["id"].as_str())
        .unwrap()
        .to_owned()
}

#[test]
fn inspect_json_returns_a_report() {
    let root = tempfile::tempdir().expect("temporary folderbase root");

    folderbase()
        .args(["inspect", root.path().to_str().unwrap(), "--json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"inventory\""));
}

#[test]
fn init_dry_run_is_read_only() {
    let root = tempfile::tempdir().expect("temporary folderbase root");

    folderbase()
        .args(["init", root.path().to_str().unwrap(), "--dry-run", "--json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"writes\""));

    assert!(!root.path().join("FOLDERBASE.md").exists());
    assert!(!root.path().join(".folderbase").exists());
}

#[test]
fn init_dry_run_json_exposes_a_stable_core_plan_digest() {
    let root = tempfile::tempdir().expect("ordinary folder");
    std::fs::write(root.path().join("notes.md"), "existing\n").expect("existing file");

    let first = init_dry_run_json(root.path(), &[]);
    let second = init_dry_run_json(root.path(), &[]);

    assert_ne!(first["folderbase_id"], second["folderbase_id"]);
    assert_eq!(first["plan_digest"], second["plan_digest"]);
    assert_eq!(first["plan_digest"]["algorithm"], "sha256");
    assert_eq!(
        first["plan_digest"]["digest"]
            .as_str()
            .expect("digest")
            .len(),
        64
    );
    assert!(!root.path().join(".folderbase").exists());
}

#[test]
fn init_digest_refuses_a_same_path_same_shape_root_replacement_across_processes() {
    let parent = tempfile::tempdir().expect("parent directory");
    let root = parent.path().join("workspace");
    let reviewed = parent.path().join("reviewed-original");
    std::fs::create_dir(&root).expect("reviewed root");
    std::fs::write(root.join("notes.md"), "same visible shape\n").expect("reviewed file");
    let plan = init_dry_run_json(&root, &[]);
    let digest = plan["plan_digest"]["digest"].as_str().expect("digest");

    std::fs::rename(&root, &reviewed).expect("move reviewed root");
    std::fs::create_dir(&root).expect("replacement root");
    std::fs::write(root.join("notes.md"), "same visible shape\n").expect("replacement file");

    folderbase()
        .args([
            "init",
            root.to_str().unwrap(),
            "--expected-plan-digest",
            digest,
            "--json",
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("initialization_plan_changed"));

    assert_no_protocol_writes(&root);
    assert_no_protocol_writes(&reviewed);
}

#[test]
fn init_applies_only_the_exact_approved_digest_and_returns_it() {
    let root = tempfile::tempdir().expect("ordinary folder");
    let plan = init_dry_run_json(root.path(), &[]);
    let digest = plan["plan_digest"]["digest"].as_str().expect("digest");

    let output = folderbase()
        .args([
            "init",
            root.path().to_str().unwrap(),
            "--expected-plan-digest",
            digest,
            "--json",
        ])
        .output()
        .expect("approved apply");
    assert!(output.status.success(), "{output:?}");
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).expect("result JSON");

    assert_eq!(result["applied_plan_digest"], plan["plan_digest"]);
    assert!(root.path().join(".folderbase/manifest.json").is_file());
}

#[test]
fn init_refuses_stale_wrong_and_malformed_digests_without_writes() {
    let stale_root = tempfile::tempdir().expect("stale folder");
    let plan = init_dry_run_json(stale_root.path(), &[]);
    let digest = plan["plan_digest"]["digest"].as_str().expect("digest");
    std::fs::write(stale_root.path().join("late.md"), "late\n").expect("late file");

    folderbase()
        .args([
            "init",
            stale_root.path().to_str().unwrap(),
            "--expected-plan-digest",
            digest,
            "--json",
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains(
            "\"code\": \"initialization_plan_changed\"",
        ));
    assert_no_protocol_writes(stale_root.path());

    for invalid in ["0".repeat(64), "NOT-A-SHA256".to_owned()] {
        let root = tempfile::tempdir().expect("invalid digest folder");
        folderbase()
            .args([
                "init",
                root.path().to_str().unwrap(),
                "--expected-plan-digest",
                &invalid,
                "--json",
            ])
            .assert()
            .code(2);
        assert_no_protocol_writes(root.path());
    }
}

#[test]
fn init_digest_binds_the_exact_request_semantics() {
    let root = tempfile::tempdir().expect("ordinary folder");
    let plan = init_dry_run_json(root.path(), &[]);
    let digest = plan["plan_digest"]["digest"].as_str().expect("digest");

    folderbase()
        .args([
            "init",
            root.path().to_str().unwrap(),
            "--name",
            "Changed request",
            "--expected-plan-digest",
            digest,
            "--json",
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("initialization_plan_changed"));

    assert_no_protocol_writes(root.path());
}

#[test]
fn generated_folderbase_entry_is_immediately_useful() {
    let root = tempfile::tempdir().expect("ordinary project");

    folderbase()
        .args([
            "init",
            root.path().to_str().unwrap(),
            "--template",
            "folderbase.project@0.2.1",
            "--answer",
            "purpose=Ship a useful folder-to-folderbase flow.",
            "--answer",
            "current_state=Template rendering is ready.",
            "--answer",
            "next_action=Adopt this folder in place.",
            "--json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"folderbase_id\""));

    assert_eq!(
        std::fs::read_to_string(root.path().join("FOLDERBASE.md"))
            .expect("generated folderbase entry"),
        "# Folderbase\n\n## Purpose\nShip a useful folder-to-folderbase flow.\n\n## Current state\nTemplate rendering is ready.\n\n## Next action\nAdopt this folder in place.\n"
    );
    assert!(root.path().join("Decisions").is_dir());
    assert!(root.path().join("Deliverables").is_dir());
}

#[test]
fn template_dry_run_lists_directories_and_existing_template_targets() {
    let root = tempfile::tempdir().expect("ordinary project");
    std::fs::create_dir(root.path().join("Decisions")).expect("existing template target");

    folderbase()
        .args([
            "init",
            root.path().to_str().unwrap(),
            "--template",
            "folderbase.project@0.2.1",
            "--answer",
            "purpose=Preview a useful folderbase.",
            "--answer",
            "current_state=One template directory already exists.",
            "--answer",
            "next_action=Review the additive plan.",
            "--dry-run",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("2 directories"))
        .stdout(predicate::str::contains("create directory Deliverables"))
        .stdout(predicate::str::contains(
            "preserve existing directory Decisions",
        ));

    assert!(!root.path().join(".folderbase").exists());
    assert!(!root.path().join("FOLDERBASE.md").exists());
    assert!(root.path().join("Decisions").is_dir());
}

#[test]
fn every_shipped_starter_is_available_to_the_installed_cli() {
    for (template, kind) in [
        ("folderbase.person@0.2.0", "person"),
        ("folderbase.organization@0.2.0", "organization"),
        ("folderbase.engagement@0.2.0", "engagement"),
        ("folderbase.project@0.2.2", "project"),
        ("folderbase.customer@0.2.0", "customer"),
        ("folderbase.temporary@0.2.0", "temporary"),
        ("folderbase.custom@0.2.0", "custom"),
    ] {
        let root = tempfile::tempdir().expect("ordinary folder");
        let folderbase_name = format!("Starter {kind}");
        let mut arguments = vec![
            "init".to_owned(),
            root.path().to_string_lossy().into_owned(),
            "--name".to_owned(),
            folderbase_name.clone(),
            "--kind".to_owned(),
            kind.to_owned(),
            "--template".to_owned(),
            template.to_owned(),
            "--answer".to_owned(),
            "purpose=Make this folder understandable.".to_owned(),
            "--answer".to_owned(),
            "current_state=The starter is being previewed.".to_owned(),
            "--answer".to_owned(),
            "next_action=Review the additive plan.".to_owned(),
        ];
        if kind == "customer" {
            arguments.extend([
                "--answer".to_owned(),
                "boundary_reason=This context has a distinct retention boundary.".to_owned(),
            ]);
        }
        arguments.push("--json".to_owned());

        folderbase()
            .args(arguments)
            .assert()
            .success()
            .stdout(predicate::str::contains("\"folderbase_id\""));

        let folderbase_entry = std::fs::read_to_string(root.path().join("FOLDERBASE.md"))
            .expect("installed folderbase entry");
        assert!(
            folderbase_entry.starts_with(&format!("# {folderbase_name}\n")),
            "{template} must render the manifest display name"
        );
    }
}

fn init_dry_run_json(root: &std::path::Path, extra: &[&str]) -> serde_json::Value {
    let mut arguments = vec!["init", root.to_str().unwrap(), "--dry-run", "--json"];
    arguments.extend_from_slice(extra);
    let output = folderbase()
        .args(arguments)
        .output()
        .expect("initialization dry run");
    assert!(output.status.success(), "{output:?}");
    serde_json::from_slice(&output.stdout).expect("plan JSON")
}

fn assert_no_protocol_writes(root: &std::path::Path) {
    for path in [
        ".folderbase",
        "FOLDERBASE.md",
        ".folderbaseignore",
        "AGENTS.md",
        "CLAUDE.md",
    ] {
        assert!(!root.join(path).exists(), "{path} must not be written");
    }
}

#[test]
fn invalid_folderbase_exits_one() {
    let root = tempfile::tempdir().expect("temporary folderbase root");

    folderbase()
        .args(["validate", root.path().to_str().unwrap(), "--json"])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("\"valid\": false"));
}

#[test]
fn operational_error_exits_two() {
    let root = tempfile::tempdir().expect("temporary parent");
    let missing = root.path().join("missing");

    folderbase()
        .args(["inspect", missing.to_str().unwrap()])
        .assert()
        .code(2)
        .stderr(predicate::str::starts_with("error:"));
}

#[test]
fn migrate_without_answers_is_read_only_and_prints_questions() {
    let root = tempfile::tempdir().expect("temporary source");
    std::fs::write(root.path().join("README.md"), "keep me\n").unwrap();

    folderbase()
        .args([
            "migrate",
            root.path().to_str().unwrap(),
            "--destination",
            "Organized",
            "--json",
        ])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("\"questions\""))
        .stdout(predicate::str::contains("\"recommended_option_id\""))
        .stdout(predicate::str::contains("\"proposed_targets\""));
    assert!(!root.path().join("Organized").exists());
}

#[test]
fn migrate_preview_is_read_only() {
    let root = tempfile::tempdir().expect("temporary source");
    std::fs::write(root.path().join("README.md"), "keep me\n").unwrap();
    let assignment = migration_assignment_question(root.path(), "README.md");

    folderbase()
        .args([
            "migrate",
            root.path().to_str().unwrap(),
            "--destination",
            "Organized",
            "--answer",
            "question_canonical_scope=one_folderbase",
            "--answer",
            "question_generated_content=exclude_generated",
            "--answer",
            &format!("{assignment}=target_primary_folderbase"),
            "--json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"source_files_remain\": true"));
    assert!(!root.path().join("Organized").exists());
}

#[test]
fn migrate_preview_accepts_typed_answers_json_on_stdin() {
    let root = tempfile::tempdir().expect("temporary source");
    std::fs::write(root.path().join("README.md"), "keep me\n").unwrap();
    let assignment = migration_assignment_question(root.path(), "README.md");
    let answers = serde_json::json!([
        {
            "question_id": "question_canonical_scope",
            "answer": "one_folderbase"
        },
        {
            "question_id": "question_generated_content",
            "answer": "exclude_generated"
        },
        {
            "question_id": assignment,
            "answer": "target_primary_folderbase"
        }
    ]);

    folderbase()
        .args([
            "migrate",
            root.path().to_str().unwrap(),
            "--destination",
            "Organized",
            "--answers-stdin",
            "--json",
        ])
        .write_stdin(serde_json::to_vec(&answers).unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("\"source_files_remain\": true"));
    assert!(!root.path().join("Organized").exists());
}

#[test]
fn migrate_apply_creates_verified_additive_copy() {
    let root = tempfile::tempdir().expect("temporary source");
    std::fs::write(root.path().join("README.md"), "keep me\n").unwrap();
    let assignment = migration_assignment_question(root.path(), "README.md");

    folderbase()
        .args([
            "migrate",
            root.path().to_str().unwrap(),
            "--destination",
            "Organized",
            "--answer",
            "question_canonical_scope=one_folderbase",
            "--answer",
            "question_generated_content=exclude_generated",
            "--answer",
            &format!("{assignment}=target_primary_folderbase"),
            "--apply",
            "--json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"state\": \"verified\""));
    assert_eq!(
        std::fs::read(root.path().join("Organized/README.md")).unwrap(),
        b"keep me\n"
    );
    assert_eq!(
        std::fs::read(root.path().join("README.md")).unwrap(),
        b"keep me\n"
    );
}

#[test]
fn version_capture_history_and_restore_round_trip() {
    let root = tempfile::tempdir().expect("temporary folderbase");
    std::fs::write(root.path().join("Decision.md"), "first\n").unwrap();

    let output = folderbase()
        .args([
            "version",
            "capture",
            root.path().to_str().unwrap(),
            "Decision.md",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    let capture: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let version = capture["version"]["id"].as_str().unwrap();

    std::fs::write(root.path().join("Decision.md"), "second\n").unwrap();
    folderbase()
        .args([
            "version",
            "restore",
            root.path().to_str().unwrap(),
            version,
            "Restored/Decision.md",
            "--json",
        ])
        .assert()
        .success();
    assert_eq!(
        std::fs::read(root.path().join("Restored/Decision.md")).unwrap(),
        b"first\n"
    );

    folderbase()
        .args([
            "version",
            "history",
            root.path().to_str().unwrap(),
            "--json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("version.restored"));
}

#[test]
fn version_restore_tombstone_round_trips_exact_head_bytes_in_a_fresh_process() {
    use folderbase_core::FolderbaseVersionStore;

    let root = tempfile::tempdir().expect("temporary folderbase");
    std::fs::write(root.path().join("proposal.docx"), [0_u8, 255, 7, 0]).unwrap();
    folderbase()
        .args([
            "init",
            root.path().to_str().unwrap(),
            "--name",
            "Restore CLI",
        ])
        .assert()
        .success();
    let store = FolderbaseVersionStore::open(root.path()).expect("open");
    store
        .seal_capture(store.plan_capture().expect("genesis plan"))
        .expect("genesis");
    std::fs::remove_file(root.path().join("proposal.docx")).unwrap();
    let deletion = store
        .seal_capture(store.plan_capture().expect("deletion plan"))
        .expect("deletion");
    drop(store);

    let output = folderbase()
        .args([
            "version",
            "restore-tombstone",
            root.path().to_str().unwrap(),
            "proposal.docx",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(output.status.success(), "{:?}", output);
    let restored: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(restored["path"], "proposal.docx");
    assert_eq!(restored["created"], true);
    assert!(
        restored["version_id"]
            .as_str()
            .unwrap()
            .starts_with("fbversion_")
    );
    assert_eq!(
        std::fs::read(root.path().join("proposal.docx")).unwrap(),
        [0_u8, 255, 7, 0]
    );
    let current = FolderbaseVersionStore::open(root.path())
        .unwrap()
        .read_version(restored["version_id"].as_str().unwrap())
        .unwrap();
    assert_eq!(current.parents(), &[deletion.version_id().to_owned()]);
}

#[test]
fn workspace_list_json_returns_the_sorted_flat_file_navigation_shape() {
    let root = tempfile::tempdir().expect("temporary folderbase");
    std::fs::create_dir(root.path().join("docs")).unwrap();
    std::fs::write(root.path().join("FOLDERBASE.md"), "folderbase\n").unwrap();
    std::fs::write(root.path().join("docs/note.md"), "note\n").unwrap();

    let output = folderbase()
        .args(["workspace", "list", root.path().to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let listing: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        listing["root"],
        root.path().canonicalize().unwrap().to_str().unwrap()
    );
    assert_eq!(
        listing["entries"],
        serde_json::json!([
            {
                "path": "FOLDERBASE.md",
                "name": "FOLDERBASE.md",
                "kind": "file",
                "bytes": 11,
                "editable": true,
                "reconstructable": false
            },
            {
                "path": "docs",
                "name": "docs",
                "kind": "directory",
                "bytes": 0,
                "editable": false,
                "reconstructable": false
            },
            {
                "path": "docs/note.md",
                "name": "note.md",
                "kind": "file",
                "bytes": 5,
                "editable": true,
                "reconstructable": false
            }
        ])
    );
}

#[test]
fn workspace_list_json_marks_reconstructable_roots_and_nested_folderbase_boundaries() {
    let root = tempfile::tempdir().expect("temporary folderbase");
    std::fs::create_dir_all(root.path().join("node_modules/pkg")).unwrap();
    std::fs::write(root.path().join("node_modules/pkg/index.js"), "generated\n").unwrap();
    std::fs::create_dir_all(root.path().join("nested/.folderbase")).unwrap();
    std::fs::write(root.path().join("nested/FOLDERBASE.md"), "nested\n").unwrap();
    std::fs::write(
        root.path().join("nested/.folderbase/manifest.json"),
        "malformed\n",
    )
    .unwrap();
    std::fs::write(root.path().join("nested/private.md"), "private\n").unwrap();

    let output = folderbase()
        .args(["workspace", "list", root.path().to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let listing: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        listing["entries"],
        serde_json::json!([
            {
                "path": "nested",
                "name": "nested",
                "kind": "folderbase",
                "bytes": 0,
                "editable": false,
                "reconstructable": false
            },
            {
                "path": "node_modules",
                "name": "node_modules",
                "kind": "directory",
                "bytes": 0,
                "editable": false,
                "reconstructable": true
            }
        ])
    );

    folderbase()
        .args([
            "workspace",
            "read",
            root.path().to_str().unwrap(),
            "nested/private.md",
            "--json",
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("path escapes the folderbase root"));
}

#[test]
fn workspace_and_version_commands_enforce_the_same_nested_folderbase_boundary() {
    let root = tempfile::tempdir().expect("temporary parent folderbase");
    std::fs::write(root.path().join("source.txt"), "parent content").unwrap();
    std::fs::create_dir_all(root.path().join("nested/.folderbase")).unwrap();
    std::fs::write(root.path().join("nested/FOLDERBASE.md"), "# Nested\n").unwrap();
    std::fs::write(
        root.path().join("nested/.folderbase/manifest.json"),
        "malformed\n",
    )
    .unwrap();
    std::fs::write(root.path().join("nested/private.txt"), "private\n").unwrap();

    folderbase()
        .args([
            "workspace",
            "read",
            root.path().to_str().unwrap(),
            "nested/private.txt",
            "--json",
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("path escapes the folderbase root"));
    folderbase()
        .args([
            "version",
            "capture",
            root.path().to_str().unwrap(),
            "nested/private.txt",
            "--json",
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("path escapes the folderbase root"));

    let capture = folderbase()
        .args([
            "version",
            "capture",
            root.path().to_str().unwrap(),
            "source.txt",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(capture.status.success());
    let captured: serde_json::Value = serde_json::from_slice(&capture.stdout).unwrap();
    let version = captured["version"]["id"].as_str().unwrap();

    folderbase()
        .args([
            "version",
            "restore",
            root.path().to_str().unwrap(),
            version,
            "nested/restored.txt",
            "--json",
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("path escapes the folderbase root"));
    assert!(!root.path().join("nested/restored.txt").exists());
    assert_eq!(
        std::fs::read(root.path().join("nested/private.txt")).unwrap(),
        b"private\n"
    );
}

#[test]
fn version_commands_reject_reserved_aliases_and_reuse_canonical_file_identity() {
    let root = tempfile::tempdir().expect("temporary folderbase");
    std::fs::create_dir(root.path().join("docs")).unwrap();
    std::fs::write(root.path().join("docs/Note.md"), "first\n").unwrap();
    std::fs::create_dir(root.path().join(".Git")).unwrap();
    std::fs::write(root.path().join(".Git/config"), "git\n").unwrap();

    folderbase()
        .args([
            "version",
            "capture",
            root.path().to_str().unwrap(),
            ".Git/config",
            "--json",
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("path escapes the folderbase root"));

    let first = folderbase()
        .args([
            "version",
            "capture",
            root.path().to_str().unwrap(),
            "docs//Note.md",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(first.status.success());
    let first: serde_json::Value = serde_json::from_slice(&first.stdout).unwrap();
    let object_id = first["object"]["id"].as_str().unwrap();
    let version_id = first["version"]["id"].as_str().unwrap();
    assert_eq!(first["object"]["path"], "docs/Note.md");

    if root.path().join("docs/note.md").exists() {
        let alias = folderbase()
            .args([
                "version",
                "capture",
                root.path().to_str().unwrap(),
                "docs/note.md",
                "--json",
            ])
            .output()
            .unwrap();
        assert!(alias.status.success());
        let alias: serde_json::Value = serde_json::from_slice(&alias.stdout).unwrap();
        assert_eq!(alias["object"]["id"], object_id);
        assert_eq!(alias["object"]["path"], "docs/Note.md");
    }

    folderbase()
        .args([
            "version",
            "restore",
            root.path().to_str().unwrap(),
            version_id,
            ".FOLDERBASE/restored.txt",
            "--json",
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("path escapes the folderbase root"));
    assert!(!root.path().join(".folderbase/restored.txt").exists());
}

#[test]
fn workspace_read_json_returns_the_text_document_shape() {
    let root = tempfile::tempdir().expect("temporary folderbase");
    std::fs::write(root.path().join("note.md"), "hello\n").unwrap();

    folderbase()
        .args([
            "workspace",
            "read",
            root.path().to_str().unwrap(),
            "note.md",
            "--json",
        ])
        .assert()
        .success()
        .stdout(predicate::eq(
            "{\n  \"path\": \"note.md\",\n  \"content\": \"hello\\n\",\n  \"sha256\": \"5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03\",\n  \"bytes\": 6\n}\n",
        ));
}

#[test]
fn workspace_save_reads_stdin_and_returns_metadata_without_echoing_content() {
    let root = tempfile::tempdir().expect("temporary folderbase");
    std::fs::write(root.path().join("note.md"), "first\n").unwrap();

    let output = folderbase()
        .args([
            "workspace",
            "save",
            root.path().to_str().unwrap(),
            "note.md",
            "--expected-sha256",
            "b640e840b19d378660b32fb51ae18d67dccb4a8596a29e7bd72c1b2ae5928f41",
            "--stdin",
            "--json",
        ])
        .write_stdin("second\n")
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(!String::from_utf8_lossy(&output.stdout).contains("second"));
    let saved: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(saved["path"], "note.md");
    assert_eq!(
        saved["previous_sha256"],
        "b640e840b19d378660b32fb51ae18d67dccb4a8596a29e7bd72c1b2ae5928f41"
    );
    assert_eq!(
        saved["document"],
        serde_json::json!({
            "path": "note.md",
            "sha256": "480c2336b410f1ad5f8bf1b28944490255804b65350c527787e74ebdd511e3a4",
            "bytes": 7
        })
    );
    assert!(saved["object_id"].as_str().unwrap().starts_with("obj_"));
    assert!(
        saved["version_id"]
            .as_str()
            .unwrap()
            .starts_with("version_")
    );
    assert_eq!(
        std::fs::read(root.path().join("note.md")).unwrap(),
        b"second\n"
    );
}

#[test]
fn stale_workspace_save_leaves_content_and_journal_byte_for_byte_unchanged() {
    let root = tempfile::tempdir().expect("temporary folderbase");
    std::fs::write(root.path().join("note.md"), "first\n").unwrap();
    folderbase()
        .args([
            "workspace",
            "save",
            root.path().to_str().unwrap(),
            "note.md",
            "--expected-sha256",
            "b640e840b19d378660b32fb51ae18d67dccb4a8596a29e7bd72c1b2ae5928f41",
            "--stdin",
            "--json",
        ])
        .write_stdin("second\n")
        .assert()
        .success();
    let journal_path = root.path().join(".folderbase/journal/objects.ndjson");
    let journal_before = std::fs::read(&journal_path).unwrap();

    folderbase()
        .args([
            "workspace",
            "save",
            root.path().to_str().unwrap(),
            "note.md",
            "--expected-sha256",
            "b640e840b19d378660b32fb51ae18d67dccb4a8596a29e7bd72c1b2ae5928f41",
            "--stdin",
            "--json",
        ])
        .write_stdin("third\n")
        .assert()
        .code(2)
        .stderr(predicate::str::contains("workspace content changed"));

    assert_eq!(
        std::fs::read(root.path().join("note.md")).unwrap(),
        b"second\n"
    );
    assert_eq!(std::fs::read(journal_path).unwrap(), journal_before);
}

#[test]
fn every_durable_workspace_save_checkpoint_recovers_idempotently_on_reopen() {
    for checkpoint in [
        "intent-durable",
        "versions-durable",
        "content-replaced",
        "projection-durable",
        "journal-durable",
    ] {
        let root = tempfile::tempdir().expect("temporary folderbase");
        std::fs::write(root.path().join("note.md"), "first\n").unwrap();

        folderbase()
            .env(
                "FOLDERBASE_TEST_FAIL_AFTER_WORKSPACE_CHECKPOINT",
                checkpoint,
            )
            .args([
                "workspace",
                "save",
                root.path().to_str().unwrap(),
                "note.md",
                "--expected-sha256",
                "b640e840b19d378660b32fb51ae18d67dccb4a8596a29e7bd72c1b2ae5928f41",
                "--stdin",
                "--json",
            ])
            .write_stdin("second\n")
            .assert()
            .code(2)
            .stderr(predicate::str::contains("simulated interruption"));

        let output = folderbase()
            .args([
                "version",
                "history",
                root.path().to_str().unwrap(),
                "--json",
            ])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "recovery failed after {checkpoint}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let events: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(events.len(), 3, "checkpoint {checkpoint}");
        assert_eq!(
            std::fs::read(root.path().join("note.md")).unwrap(),
            b"second\n",
            "checkpoint {checkpoint}"
        );
        assert_eq!(
            std::fs::read_dir(root.path().join(".folderbase/transactions"))
                .unwrap()
                .filter_map(Result::ok)
                .filter(|entry| {
                    entry.path().extension().and_then(|value| value.to_str()) == Some("json")
                })
                .count(),
            0,
            "checkpoint {checkpoint}"
        );
    }
}

#[test]
fn recovery_refuses_to_overwrite_a_third_party_edit_after_an_interrupted_save() {
    let root = tempfile::tempdir().expect("temporary folderbase");
    std::fs::write(root.path().join("note.md"), "first\n").unwrap();
    folderbase()
        .env(
            "FOLDERBASE_TEST_FAIL_AFTER_WORKSPACE_CHECKPOINT",
            "content-replaced",
        )
        .args([
            "workspace",
            "save",
            root.path().to_str().unwrap(),
            "note.md",
            "--expected-sha256",
            "b640e840b19d378660b32fb51ae18d67dccb4a8596a29e7bd72c1b2ae5928f41",
            "--stdin",
            "--json",
        ])
        .write_stdin("second\n")
        .assert()
        .code(2);
    std::fs::write(root.path().join("note.md"), "third-party\n").unwrap();

    folderbase()
        .args([
            "version",
            "history",
            root.path().to_str().unwrap(),
            "--json",
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("workspace content changed"));
    assert_eq!(
        std::fs::read(root.path().join("note.md")).unwrap(),
        b"third-party\n"
    );
}

#[test]
fn restore_publication_checkpoint_recovers_once_after_process_interruption() {
    let root = tempfile::tempdir().expect("temporary folderbase");
    std::fs::write(root.path().join("source.txt"), "durable restore").unwrap();
    let capture = folderbase()
        .args([
            "version",
            "capture",
            root.path().to_str().unwrap(),
            "source.txt",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(capture.status.success());
    let captured: serde_json::Value = serde_json::from_slice(&capture.stdout).unwrap();
    let version = captured["version"]["id"].as_str().unwrap();

    folderbase()
        .env(
            "FOLDERBASE_TEST_FAIL_AFTER_WORKSPACE_CHECKPOINT",
            "restore-published",
        )
        .args([
            "version",
            "restore",
            root.path().to_str().unwrap(),
            version,
            "recovered/restored.txt",
            "--json",
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("simulated interruption"));
    assert_eq!(
        std::fs::read(root.path().join("recovered/restored.txt")).unwrap(),
        b"durable restore"
    );

    let history = folderbase()
        .args([
            "version",
            "history",
            root.path().to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert!(history.status.success());
    let events: Vec<serde_json::Value> = serde_json::from_slice(&history.stdout).unwrap();
    assert_eq!(
        events
            .iter()
            .filter(|event| {
                event["action"] == "version.restored"
                    && event["version_id"] == version
                    && event["path"] == "recovered/restored.txt"
            })
            .count(),
        1
    );
    assert_eq!(
        std::fs::read_dir(root.path().join(".folderbase/transactions"))
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| {
                entry.path().extension().and_then(|value| value.to_str()) == Some("json")
            })
            .count(),
        0
    );
}

#[test]
fn restore_recovery_stops_if_its_destination_becomes_a_nested_folderbase() {
    let root = tempfile::tempdir().expect("temporary parent folderbase");
    std::fs::write(root.path().join("source.txt"), "durable restore").unwrap();
    let capture = folderbase()
        .args([
            "version",
            "capture",
            root.path().to_str().unwrap(),
            "source.txt",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(capture.status.success());
    let captured: serde_json::Value = serde_json::from_slice(&capture.stdout).unwrap();
    let version = captured["version"]["id"].as_str().unwrap();

    folderbase()
        .env(
            "FOLDERBASE_TEST_FAIL_AFTER_WORKSPACE_CHECKPOINT",
            "restore-published",
        )
        .args([
            "version",
            "restore",
            root.path().to_str().unwrap(),
            version,
            "future-folderbase/restored.txt",
            "--json",
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("simulated interruption"));
    assert_eq!(
        std::fs::read(root.path().join("future-folderbase/restored.txt")).unwrap(),
        b"durable restore"
    );

    std::fs::create_dir(root.path().join("future-folderbase/.folderbase")).unwrap();
    std::fs::write(
        root.path().join("future-folderbase/FOLDERBASE.md"),
        "# Future Folderbase\n",
    )
    .unwrap();
    std::fs::write(
        root.path()
            .join("future-folderbase/.folderbase/manifest.json"),
        "malformed\n",
    )
    .unwrap();

    folderbase()
        .args([
            "version",
            "history",
            root.path().to_str().unwrap(),
            "--json",
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("path escapes the folderbase root"));
    assert_eq!(
        std::fs::read(root.path().join("future-folderbase/restored.txt")).unwrap(),
        b"durable restore"
    );
    assert_eq!(
        std::fs::read_dir(root.path().join(".folderbase/transactions"))
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| {
                entry.path().extension().and_then(|value| value.to_str()) == Some("json")
            })
            .count(),
        1
    );
}

#[test]
fn pending_restore_replay_rejects_reserved_case_aliases() {
    for reserved_destination in [".FOLDERBASE/replayed.txt", ".GiT/replayed.txt"] {
        let root = tempfile::tempdir().expect("temporary folderbase");
        std::fs::write(root.path().join("source.txt"), "durable restore").unwrap();
        let capture = folderbase()
            .args([
                "version",
                "capture",
                root.path().to_str().unwrap(),
                "source.txt",
                "--json",
            ])
            .output()
            .unwrap();
        assert!(capture.status.success());
        let captured: serde_json::Value = serde_json::from_slice(&capture.stdout).unwrap();
        let version = captured["version"]["id"].as_str().unwrap();

        folderbase()
            .env(
                "FOLDERBASE_TEST_FAIL_AFTER_WORKSPACE_CHECKPOINT",
                "restore-published",
            )
            .args([
                "version",
                "restore",
                root.path().to_str().unwrap(),
                version,
                "staging/restored.txt",
                "--json",
            ])
            .assert()
            .code(2)
            .stderr(predicate::str::contains("simulated interruption"));

        let transaction_path = std::fs::read_dir(root.path().join(".folderbase/transactions"))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| path.extension().and_then(|value| value.to_str()) == Some("json"))
            .unwrap();
        let mut transaction: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&transaction_path).unwrap()).unwrap();
        transaction["restore"]["destination"] =
            serde_json::Value::String(reserved_destination.to_owned());
        transaction["events"][0]["path"] =
            serde_json::Value::String(reserved_destination.to_owned());
        std::fs::write(
            &transaction_path,
            serde_json::to_vec_pretty(&transaction).unwrap(),
        )
        .unwrap();

        folderbase()
            .args([
                "version",
                "history",
                root.path().to_str().unwrap(),
                "--json",
            ])
            .assert()
            .code(2)
            .stderr(predicate::str::contains(
                "pending restore has an unsafe destination",
            ));
        assert!(!root.path().join(reserved_destination).exists());
        assert_eq!(
            std::fs::read(root.path().join("staging/restored.txt")).unwrap(),
            b"durable restore"
        );
    }
}

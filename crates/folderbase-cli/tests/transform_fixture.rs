use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use assert_cmd::Command;
use predicates::prelude::*;

fn folderbase() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("folderbase"))
}

fn fixture() -> tempfile::TempDir {
    let root = tempfile::tempdir().expect("temporary transform source");
    fs::create_dir(root.path().join("Client-Shared")).unwrap();
    fs::write(root.path().join("README.md"), "source of truth\n").unwrap();
    fs::write(
        root.path().join("Client-Shared/Overview.md"),
        "client-safe\n",
    )
    .unwrap();
    root
}

fn analyze(root: &Path) -> serde_json::Value {
    let output = folderbase()
        .args(["transform", "analyze", root.to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "analysis failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

fn multi_folderbase_answers(analysis: &serde_json::Value) -> serde_json::Value {
    let client_target = analysis["proposed_targets"]
        .as_array()
        .unwrap()
        .iter()
        .find(|target| target["kind"] == "folderbase" && target["path"] == "Client-Shared")
        .and_then(|target| target["id"].as_str())
        .unwrap();
    serde_json::Value::Array(
        analysis["questions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|question| {
                let option_id = if question["id"] == "question_canonical_scope" {
                    "proposed_boundaries"
                } else if question["kind"]["type"] == "assignment"
                    && question["kind"]["source_path"]
                        .as_str()
                        .is_some_and(|path| path.starts_with("Client-Shared"))
                {
                    client_target
                } else {
                    question["recommended_option_id"].as_str().unwrap()
                };
                serde_json::json!({
                    "question_id": question["id"],
                    "answer": option_id,
                })
            })
            .collect(),
    )
}

fn plan_transform(root: &Path, answers: &serde_json::Value) -> serde_json::Value {
    let output = folderbase()
        .args([
            "transform",
            "plan",
            root.to_str().unwrap(),
            "--destination",
            "Organized",
            "--answers-stdin",
            "--json",
        ])
        .write_stdin(serde_json::to_vec(answers).unwrap())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "planning failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

fn plan_transform_failure(root: &Path, answers: &serde_json::Value) -> String {
    let output = folderbase()
        .args([
            "transform",
            "plan",
            root.to_str().unwrap(),
            "--destination",
            "Organized",
            "--answers-stdin",
            "--json",
        ])
        .write_stdin(serde_json::to_vec(answers).unwrap())
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "invalid grouped answers unexpectedly planned: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    String::from_utf8(output.stderr).unwrap()
}

fn approve(root: &Path, migration_id: &str) {
    folderbase()
        .args([
            "transform",
            "approve",
            root.to_str().unwrap(),
            migration_id,
            "--json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"state\": \"approved\""));
}

#[test]
fn separate_processes_can_analyze_plan_apply_reopen_and_rollback() {
    let root = fixture();
    let analysis = analyze(root.path());
    assert!(!root.path().join(".folderbase").exists());
    let answers = multi_folderbase_answers(&analysis);
    let plan = plan_transform(root.path(), &answers);
    let migration_id = plan["id"].as_str().unwrap();
    assert_eq!(plan["state"], "proposed");

    folderbase()
        .args([
            "transform",
            "preview",
            root.path().to_str().unwrap(),
            migration_id,
            "--json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"source_files_remain\": true"));
    approve(root.path(), migration_id);
    folderbase()
        .args([
            "transform",
            "apply",
            root.path().to_str().unwrap(),
            migration_id,
            "--json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"state\": \"verified\""));
    folderbase()
        .args([
            "transform",
            "reopen",
            root.path().to_str().unwrap(),
            migration_id,
            "--json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"state\": \"verified\""));
    folderbase()
        .args([
            "transform",
            "recover",
            root.path().to_str().unwrap(),
            migration_id,
            "--json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"state\": \"verified\""));
    folderbase()
        .args([
            "transform",
            "rollback",
            root.path().to_str().unwrap(),
            migration_id,
            "--json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"state\": \"rolled_back\""));
    assert!(!root.path().join("Organized").exists());
    assert_eq!(
        fs::read(root.path().join("README.md")).unwrap(),
        b"source of truth\n"
    );
}

#[test]
fn typed_answers_are_read_from_stdin_not_argv() {
    let root = fixture();
    let analysis = analyze(root.path());
    let mut answers = multi_folderbase_answers(&analysis);
    answers[0]["answer"] = serde_json::json!("SENTINEL_PRIVATE_ANSWER");

    let help = folderbase()
        .args(["transform", "plan", "--help"])
        .output()
        .unwrap();
    assert!(help.status.success());
    let help = String::from_utf8(help.stdout).unwrap();
    assert!(help.contains("--answers-stdin"));
    assert!(!help.contains("--answer <"));

    folderbase()
        .args([
            "transform",
            "plan",
            root.path().to_str().unwrap(),
            "--destination",
            "Organized",
            "--answers-stdin",
            "--json",
        ])
        .write_stdin(serde_json::to_vec(&answers).unwrap())
        .assert()
        .code(2)
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains("\"code\": \"invalid_record\""))
        .stderr(predicate::str::contains("SENTINEL_PRIVATE_ANSWER").not());
}

#[test]
fn apply_returns_created_folderbase_roots_and_workspace() {
    let root = fixture();
    let analysis = analyze(root.path());
    let plan = plan_transform(root.path(), &multi_folderbase_answers(&analysis));
    let migration_id = plan["id"].as_str().unwrap();
    approve(root.path(), migration_id);

    let output = folderbase()
        .args([
            "transform",
            "apply",
            root.path().to_str().unwrap(),
            migration_id,
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "apply failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let created = result["created_paths"].as_array().unwrap();
    for expected in [
        "Organized/Primary.folderbase/.folderbase/manifest.json",
        "Organized/Client-Shared.folderbase/.folderbase/manifest.json",
        "Organized/WORKSPACE.md",
        "Organized/.folderbase-workspace.json",
    ] {
        assert!(
            created.iter().any(|path| path == expected),
            "apply output must include {expected}"
        );
        assert!(root.path().join(expected).exists());
    }
}

#[test]
fn stale_or_tampered_plan_has_stable_nonzero_exit_without_writes() {
    let tampered_root = fixture();
    let analysis = analyze(tampered_root.path());
    let plan = plan_transform(tampered_root.path(), &multi_folderbase_answers(&analysis));
    let migration_id = plan["id"].as_str().unwrap();
    approve(tampered_root.path(), migration_id);
    let plan_path = tampered_root
        .path()
        .join(".folderbase/migrations")
        .join(migration_id)
        .join("plan.json");
    let mut stored: serde_json::Value =
        serde_json::from_slice(&fs::read(&plan_path).unwrap()).unwrap();
    stored["answers"][0]["answer"] = serde_json::json!("tampered");
    fs::write(&plan_path, serde_json::to_vec_pretty(&stored).unwrap()).unwrap();

    folderbase()
        .args([
            "transform",
            "apply",
            tampered_root.path().to_str().unwrap(),
            migration_id,
            "--json",
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains(
            "\"code\": \"migration_approval_mismatch\"",
        ));
    assert!(!tampered_root.path().join("Organized").exists());

    let stale_root = fixture();
    let analysis = analyze(stale_root.path());
    let plan = plan_transform(stale_root.path(), &multi_folderbase_answers(&analysis));
    let migration_id = plan["id"].as_str().unwrap();
    approve(stale_root.path(), migration_id);
    fs::write(stale_root.path().join("README.md"), "changed later\n").unwrap();

    folderbase()
        .args([
            "transform",
            "apply",
            stale_root.path().to_str().unwrap(),
            migration_id,
            "--json",
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains(
            "\"code\": \"migration_source_changed\"",
        ));
    assert!(!stale_root.path().join("Organized").exists());
}

#[test]
fn rollback_is_idempotent_after_restart() {
    let root = fixture();
    let analysis = analyze(root.path());
    let plan = plan_transform(root.path(), &multi_folderbase_answers(&analysis));
    let migration_id = plan["id"].as_str().unwrap();
    approve(root.path(), migration_id);
    folderbase()
        .args([
            "transform",
            "apply",
            root.path().to_str().unwrap(),
            migration_id,
            "--json",
        ])
        .assert()
        .success();

    for _ in 0..2 {
        folderbase()
            .args([
                "transform",
                "rollback",
                root.path().to_str().unwrap(),
                migration_id,
                "--json",
            ])
            .assert()
            .success()
            .stdout(predicate::str::contains("\"state\": \"rolled_back\""));
    }
    assert!(!root.path().join("Organized").exists());
    assert!(root.path().join("README.md").exists());
}

const LIVE_OKADA_PATH: &str = "/Users/jerel/Work/Chalk/Okada";
const GOLDEN_BOUNDARIES: &[&str] = &[
    "ChalkAgents-Prosperna-Client-Engagement",
    "Client-Shared",
    "Commercial-Restricted",
    "Loyalty-Revamp-Project",
    "Security-Remediation",
    "Support-and-Maintenance-Project",
];
const GOLDEN_FOLDERBASES: &[&str] = &[
    "Primary.folderbase",
    "ChalkAgents-Prosperna-Client-Engagement.folderbase",
    "Client-Shared.folderbase",
    "Commercial-Restricted.folderbase",
    "Loyalty-Revamp-Project.folderbase",
    "Security-Remediation.folderbase",
    "Support-And-Maintenance-Project.folderbase",
];

struct GoldenFixture {
    _temp: tempfile::TempDir,
    root: PathBuf,
}

fn committed_golden_fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/client-company-2-shaped-unmanaged")
        .canonicalize()
        .expect("committed synthetic fixture")
}

fn committed_golden_expectations() -> serde_json::Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/client-company-2-shaped-unmanaged.expected.json");
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

fn guarded_fixture_source(source: &Path) -> Result<PathBuf, String> {
    let live = Path::new(LIVE_OKADA_PATH);
    if source == live || source.starts_with(live) {
        return Err("live Okada path is forbidden in the golden test harness".to_owned());
    }
    let canonical = source
        .canonicalize()
        .map_err(|error| format!("fixture source is unavailable: {error}"))?;
    if canonical != committed_golden_fixture() {
        return Err(format!(
            "golden tests accept only the committed synthetic fixture: {}",
            canonical.display()
        ));
    }
    Ok(canonical)
}

fn copy_tree(source: &Path, destination: &Path) {
    fs::create_dir_all(destination).unwrap();
    let mut entries = fs::read_dir(source)
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        let file_type = entry.file_type().unwrap();
        if file_type.is_dir() {
            copy_tree(&source_path, &destination_path);
        } else if file_type.is_file() {
            fs::copy(&source_path, &destination_path).unwrap();
        } else {
            panic!(
                "synthetic fixture must contain only regular files and directories: {}",
                source_path.display()
            );
        }
    }
}

fn golden_fixture() -> GoldenFixture {
    let source = guarded_fixture_source(&committed_golden_fixture()).unwrap();
    let temp = tempfile::tempdir().expect("temporary golden fixture");
    let root = temp.path().join("Okada-Account");
    copy_tree(&source, &root);
    for (source, boundary) in [
        (
            "Engagement-Provenance",
            "ChalkAgents-Prosperna-Client-Engagement",
        ),
        ("Loyalty-Revamp", "Loyalty-Revamp-Project"),
        ("Support-and-Maintenance", "Support-and-Maintenance-Project"),
    ] {
        fs::rename(root.join(source), root.join(boundary)).unwrap();
    }
    GoldenFixture { _temp: temp, root }
}

fn target_id(analysis: &serde_json::Value, path: &str) -> String {
    analysis["proposed_targets"]
        .as_array()
        .unwrap()
        .iter()
        .find(|target| target["kind"] == "folderbase" && target["path"] == path)
        .and_then(|target| target["id"].as_str())
        .unwrap_or_else(|| panic!("missing folderbase target for {path}"))
        .to_owned()
}

fn golden_answers(analysis: &serde_json::Value) -> serde_json::Value {
    let boundary_targets = GOLDEN_BOUNDARIES
        .iter()
        .map(|path| ((*path).to_owned(), target_id(analysis, path)))
        .collect::<BTreeMap<_, _>>();
    serde_json::Value::Array(
        analysis["questions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|question| {
                let option_id = match question["id"].as_str().unwrap() {
                    "question_canonical_scope" => "proposed_boundaries".to_owned(),
                    "question_generated_content" => "exclude_generated".to_owned(),
                    "question_secrets" => "local_only".to_owned(),
                    _ => {
                        let kind = &question["kind"];
                        let source = match kind["type"].as_str().unwrap() {
                            "assignment" => kind["source_path"].as_str().unwrap(),
                            "assignment_group" => kind["source_root"].as_str().unwrap(),
                            other => panic!("unexpected migration question kind: {other}"),
                        };
                        match kind["content_kind"].as_str().unwrap() {
                            "secret_shaped" => "target_retained_source".to_owned(),
                            "generated" | "temporary" => "target_exclusion".to_owned(),
                            _ if source.starts_with("Client-Shared") => {
                                boundary_targets["Client-Shared"].clone()
                            }
                            _ if source.starts_with("Commercial-Restricted") => {
                                boundary_targets["Commercial-Restricted"].clone()
                            }
                            _ if source.starts_with("Security-Remediation") => {
                                boundary_targets["Security-Remediation"].clone()
                            }
                            _ if source.starts_with("Engagement-Provenance")
                                || source
                                    .starts_with("ChalkAgents-Prosperna-Client-Engagement") =>
                            {
                                boundary_targets["ChalkAgents-Prosperna-Client-Engagement"].clone()
                            }
                            _ if source.starts_with("Loyalty-Revamp") => {
                                boundary_targets["Loyalty-Revamp-Project"].clone()
                            }
                            _ if source.starts_with("Support-and-Maintenance") => {
                                boundary_targets["Support-and-Maintenance-Project"].clone()
                            }
                            _ => "target_primary_folderbase".to_owned(),
                        }
                    }
                };
                serde_json::json!({
                    "question_id": question["id"],
                    "answer": option_id,
                })
            })
            .collect(),
    )
}

fn golden_plan(root: &Path, analysis: &serde_json::Value) -> serde_json::Value {
    plan_transform(root, &golden_answers(analysis))
}

fn golden_apply(root: &Path, analysis: &serde_json::Value) -> (String, serde_json::Value) {
    let plan = golden_plan(root, analysis);
    let migration_id = plan["id"].as_str().unwrap().to_owned();
    folderbase()
        .args([
            "transform",
            "preview",
            root.to_str().unwrap(),
            &migration_id,
            "--json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"source_files_remain\": true"));
    approve(root, &migration_id);
    let output = folderbase()
        .args([
            "transform",
            "apply",
            root.to_str().unwrap(),
            &migration_id,
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "golden apply failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    (
        migration_id,
        serde_json::from_slice(&output.stdout).unwrap(),
    )
}

fn source_snapshot(root: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    fn collect(root: &Path, current: &Path, snapshot: &mut Vec<(PathBuf, Vec<u8>)>) {
        let mut entries = fs::read_dir(current)
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            let path = entry.path();
            let relative = path.strip_prefix(root).unwrap();
            if relative.starts_with(".folderbase") || relative.starts_with("Organized") {
                continue;
            }
            if entry.file_type().unwrap().is_dir() {
                collect(root, &path, snapshot);
            } else {
                snapshot.push((relative.to_path_buf(), fs::read(path).unwrap()));
            }
        }
    }

    let mut snapshot = Vec::new();
    collect(root, root, &mut snapshot);
    snapshot
}

#[test]
fn okada_shaped_fixture_produces_expected_questions_without_writes() {
    let fixture = golden_fixture();
    let before = source_snapshot(&fixture.root);
    let analysis = analyze(&fixture.root);

    assert_eq!(analysis["file_count"], 39);
    for boundary in GOLDEN_BOUNDARIES {
        assert!(
            analysis["proposed_targets"]
                .as_array()
                .unwrap()
                .iter()
                .any(|target| target["kind"] == "folderbase" && target["path"] == *boundary),
            "missing explicit folderbase target for {boundary}"
        );
    }
    for decision in [
        "question_canonical_scope",
        "question_generated_content",
        "question_secrets",
    ] {
        assert!(
            analysis["questions"]
                .as_array()
                .unwrap()
                .iter()
                .any(|question| question["id"] == decision)
        );
    }
    assert_eq!(source_snapshot(&fixture.root), before);
    assert!(!fixture.root.join(".folderbase").exists());
    assert!(!fixture.root.join("Organized").exists());
}

#[test]
fn okada_shaped_fixture_groups_every_assignment_into_twenty_bounded_questions() {
    let fixture = golden_fixture();
    let analysis = analyze(&fixture.root);
    let questions = analysis["questions"].as_array().unwrap();
    let groups = questions
        .iter()
        .filter(|question| question["kind"]["type"] == "assignment_group")
        .map(|question| {
            serde_json::json!({
                "source_root": question["kind"]["source_root"],
                "content_kind": question["kind"]["content_kind"],
                "source_paths": question["kind"]["source_paths"],
            })
        })
        .collect::<Vec<_>>();
    let expected = committed_golden_expectations();
    let grouping = &expected["migration_grouping_v1"];

    assert_eq!(
        questions.len(),
        grouping["question_count"].as_u64().unwrap() as usize
    );
    assert_eq!(groups, grouping["groups"].as_array().unwrap().clone());
    let mut grouped_paths = questions
        .iter()
        .filter(|question| question["kind"]["type"] == "assignment_group")
        .flat_map(|question| question["kind"]["source_paths"].as_array().unwrap())
        .map(|path| path.as_str().unwrap().to_owned())
        .collect::<Vec<_>>();
    assert_eq!(
        grouped_paths.len(),
        grouping["assignment_scope_count"].as_u64().unwrap() as usize
    );
    grouped_paths.sort();
    grouped_paths.dedup();
    assert_eq!(
        grouped_paths.len(),
        grouping["assignment_scope_count"].as_u64().unwrap() as usize
    );
    assert!(
        questions
            .iter()
            .all(|question| question["kind"]["type"] != "assignment")
    );
}

#[test]
fn grouped_default_answers_plan_every_source_scope_exactly_once() {
    let fixture = golden_fixture();
    let analysis = analyze(&fixture.root);
    let plan = golden_plan(&fixture.root, &analysis);
    let mut accounted_paths = plan["operations"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|operation| operation["type"] == "copy_file")
        .map(|operation| operation["source_path"].as_str().unwrap().to_owned())
        .chain(
            plan["exclusions"]
                .as_array()
                .unwrap()
                .iter()
                .map(|exclusion| exclusion["path"].as_str().unwrap().to_owned()),
        )
        .collect::<Vec<_>>();

    assert_eq!(
        plan["operations"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|operation| operation["type"] == "copy_file")
            .count(),
        36
    );
    assert_eq!(plan["exclusions"].as_array().unwrap().len(), 8);
    assert_eq!(accounted_paths.len(), 44);
    accounted_paths.sort();
    let mut expected_paths = committed_golden_expectations()["migration_grouping_v1"]["groups"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|group| group["source_paths"].as_array().unwrap())
        .map(|path| path.as_str().unwrap().to_owned())
        .collect::<Vec<_>>();
    expected_paths.sort();
    assert_eq!(accounted_paths, expected_paths);
}

#[test]
fn grouped_answer_exact_override_wins_for_one_member_only() {
    let fixture = golden_fixture();
    let analysis = analyze(&fixture.root);
    let overridden_path = "Commercial-Restricted/Invoices/Synthetic-Invoice.pdf";
    let question_id = analysis["questions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|question| {
            question["kind"]["type"] == "assignment_group"
                && question["kind"]["source_paths"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|path| path == overridden_path)
        })
        .unwrap()["id"]
        .as_str()
        .unwrap();
    let mut answers = golden_answers(&analysis);
    let answer = answers
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|answer| answer["question_id"] == question_id)
        .unwrap();
    answer["exceptions"] = serde_json::json!([{
        "source_path": overridden_path,
        "target_id": "target_retained_source",
    }]);
    let plan = plan_transform(&fixture.root, &answers);
    let copied_paths = plan["operations"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|operation| operation["type"] == "copy_file")
        .map(|operation| operation["source_path"].as_str().unwrap())
        .collect::<Vec<_>>();
    let excluded_paths = plan["exclusions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|exclusion| exclusion["path"].as_str().unwrap())
        .collect::<Vec<_>>();

    assert_eq!(copied_paths.len(), 35);
    assert!(!copied_paths.contains(&overridden_path));
    assert_eq!(excluded_paths.len(), 9);
    assert!(excluded_paths.contains(&overridden_path));
}

#[test]
fn grouped_answer_contract_is_explicit_and_bound_into_the_plan() {
    let fixture = golden_fixture();
    let analysis = analyze(&fixture.root);
    let groups = analysis["questions"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|question| question["kind"]["type"] == "assignment_group")
        .collect::<Vec<_>>();
    assert_eq!(groups.len(), 17);
    assert!(groups.iter().all(|question| {
        question["kind"]["rule_version"] == "top_level_content_kind_v1"
            && question["kind"]["coverage_digest"]
                .as_str()
                .is_some_and(|digest| digest.len() == 64)
    }));

    let overridden_path = "Commercial-Restricted/Invoices/Synthetic-Invoice.pdf";
    let question_id = groups
        .iter()
        .find(|question| {
            question["kind"]["source_paths"]
                .as_array()
                .unwrap()
                .iter()
                .any(|path| path == overridden_path)
        })
        .unwrap()["id"]
        .as_str()
        .unwrap();
    let mut answers = golden_answers(&analysis);
    let answer = answers
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|answer| answer["question_id"] == question_id)
        .unwrap();
    answer["exceptions"] = serde_json::json!([{
        "source_path": overridden_path,
        "target_id": "target_retained_source",
    }]);
    let expected_default = answer["answer"].clone();
    let expected_exceptions = answer["exceptions"].clone();

    let plan = plan_transform(&fixture.root, &answers);
    let contract = &plan["x-folderbase-grouped-assignments-v1"];
    assert_eq!(contract["version"], "1");
    assert_eq!(contract["groups"].as_array().unwrap().len(), 17);
    let commercial = contract["groups"]
        .as_array()
        .unwrap()
        .iter()
        .find(|group| group["question_id"] == question_id)
        .unwrap();
    assert_eq!(commercial["default_target_id"], expected_default);
    assert_eq!(commercial["exceptions"], expected_exceptions);
    assert_eq!(
        commercial["coverage_digest"],
        groups
            .iter()
            .find(|group| group["id"] == question_id)
            .unwrap()["kind"]["coverage_digest"]
    );
}

fn golden_answers_with_group_exceptions(
    analysis: &serde_json::Value,
    member: &str,
    exceptions: serde_json::Value,
) -> serde_json::Value {
    let question_id = analysis["questions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|question| {
            question["kind"]["type"] == "assignment_group"
                && question["kind"]["source_paths"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|path| path == member)
        })
        .unwrap()["id"]
        .as_str()
        .unwrap();
    let mut answers = golden_answers(analysis);
    answers
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|answer| answer["question_id"] == question_id)
        .unwrap()["exceptions"] = exceptions;
    answers
}

#[test]
fn grouped_answer_rejects_duplicate_exception_without_writes() {
    let fixture = golden_fixture();
    let analysis = analyze(&fixture.root);
    let member = "Commercial-Restricted/Invoices/Synthetic-Invoice.pdf";
    let exception = serde_json::json!({
        "source_path": member,
        "target_id": "target_retained_source",
    });
    let answers = golden_answers_with_group_exceptions(
        &analysis,
        member,
        serde_json::json!([exception.clone(), exception,]),
    );

    let error = plan_transform_failure(&fixture.root, &answers);

    assert!(error.contains("duplicate exception"));
    assert!(!fixture.root.join(".folderbase").exists());
    assert!(!fixture.root.join("Organized").exists());
}

#[test]
fn grouped_answer_rejects_prefix_nonmember_exception_without_writes() {
    let fixture = golden_fixture();
    let analysis = analyze(&fixture.root);
    let member = "Commercial-Restricted/Invoices/Synthetic-Invoice.pdf";
    let answers = golden_answers_with_group_exceptions(
        &analysis,
        member,
        serde_json::json!([{
            "source_path": format!("{member}.bak"),
            "target_id": "target_retained_source",
        }]),
    );

    let error = plan_transform_failure(&fixture.root, &answers);

    assert!(error.contains("nonmember exception"));
    assert!(!fixture.root.join(".folderbase").exists());
    assert!(!fixture.root.join("Organized").exists());
}

#[test]
fn grouped_answer_rejects_disallowed_exception_target_without_writes() {
    let fixture = golden_fixture();
    let analysis = analyze(&fixture.root);
    let member = "Commercial-Restricted/Invoices/Synthetic-Invoice.pdf";
    let answers = golden_answers_with_group_exceptions(
        &analysis,
        member,
        serde_json::json!([{
            "source_path": member,
            "target_id": "target_exclusion",
        }]),
    );

    let error = plan_transform_failure(&fixture.root, &answers);

    assert!(error.contains("accepted option IDs"));
    assert!(!fixture.root.join(".folderbase").exists());
    assert!(!fixture.root.join("Organized").exists());
}

#[test]
fn approved_decisions_create_valid_independent_folderbases() {
    let fixture = golden_fixture();
    let analysis = analyze(&fixture.root);
    let (_, result) = golden_apply(&fixture.root, &analysis);
    assert_eq!(result["state"], "verified");

    let created_paths = result["created_paths"].as_array().unwrap();
    for folderbase_name in GOLDEN_FOLDERBASES {
        let expected_entry = format!("Organized/{folderbase_name}/FOLDERBASE.md");
        assert!(
            created_paths.iter().any(|path| path == &expected_entry),
            "apply output must preserve the portable path spelling for {folderbase_name}"
        );
        let root = fixture.root.join("Organized").join(folderbase_name);
        folderbase()
            .args(["validate", root.to_str().unwrap(), "--json"])
            .assert()
            .success()
            .stdout(predicate::str::contains("\"valid\": true"));
    }
    assert!(fixture.root.join("Organized/WORKSPACE.md").exists());
    assert!(
        fixture
            .root
            .join("Organized/.folderbase-workspace.json")
            .exists()
    );
}

#[test]
fn node_modules_is_reconstructable_and_not_copied() {
    let fixture = golden_fixture();
    let analysis = analyze(&fixture.root);
    let (_, result) = golden_apply(&fixture.root, &analysis);

    assert!(
        analysis["reconstructable_trees"]
            .as_array()
            .unwrap()
            .iter()
            .any(|tree| tree["path"] == "dashboard/node_modules")
    );
    assert!(
        result["created_paths"]
            .as_array()
            .unwrap()
            .iter()
            .all(|path| !path.as_str().unwrap().contains("node_modules"))
    );
    assert!(
        fixture
            .root
            .join("dashboard/node_modules/example-package/package.json")
            .exists()
    );
    for folderbase in GOLDEN_FOLDERBASES {
        assert!(
            !fixture
                .root
                .join("Organized")
                .join(folderbase)
                .join("dashboard/node_modules")
                .exists()
        );
    }
}

#[test]
fn commercial_content_is_absent_from_client_shared_scope() {
    let fixture = golden_fixture();
    let analysis = analyze(&fixture.root);
    golden_apply(&fixture.root, &analysis);
    let shared = fixture.root.join("Organized/Client-Shared.folderbase");

    assert!(shared.join("Project-Overview.md").exists());
    assert!(shared.join("Candidate-Scope.md").exists());
    assert!(!shared.join("Agreement_Final_v4.md").exists());
    assert!(!shared.join("Invoices/Synthetic-Invoice.pdf").exists());
    assert!(
        fixture
            .root
            .join("Organized/Commercial-Restricted.folderbase/Agreement_Final_v4.md")
            .exists()
    );
}

#[test]
fn generated_adapters_use_the_exact_manifest_and_existing_adapter_is_preserved() {
    let fixture = golden_fixture();
    let analysis = analyze(&fixture.root);
    golden_apply(&fixture.root, &analysis);

    for folderbase in GOLDEN_FOLDERBASES {
        let folderbase = fixture.root.join("Organized").join(folderbase);
        let adapter = fs::read_to_string(folderbase.join("AGENTS.md")).unwrap();
        if adapter.contains("<!-- folderbase:begin -->") {
            assert!(adapter.contains("`.folderbase/manifest.json`"));
            assert!(adapter.contains("ordinary files"));
        } else {
            assert!(adapter.contains("# Existing project instructions"));
            assert!(adapter.contains("read `FOLDERBASE.md`"));
        }
        assert!(!adapter.contains("../"));
        // The selected migration template may still add this ordinary guide.
        assert!(folderbase.join("FOLDERBASE.md").exists());
    }
}

#[test]
fn full_transformation_reopens_after_restart() {
    let fixture = golden_fixture();
    let analysis = analyze(&fixture.root);
    let (migration_id, applied) = golden_apply(&fixture.root, &analysis);
    let output = folderbase()
        .args([
            "transform",
            "reopen",
            fixture.root.to_str().unwrap(),
            &migration_id,
            "--json",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    let reopened: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(reopened["state"], "verified");
    assert_eq!(reopened["created_paths"], applied["created_paths"]);
    assert!(
        fs::read_to_string(fixture.root.join("Organized/WORKSPACE.md"))
            .unwrap()
            .contains("This workspace is navigation only. It does not grant access")
    );
}

#[test]
fn full_rollback_restores_original_fixture_tree() {
    let fixture = golden_fixture();
    let before = source_snapshot(&fixture.root);
    let analysis = analyze(&fixture.root);
    let (migration_id, _) = golden_apply(&fixture.root, &analysis);
    folderbase()
        .args([
            "transform",
            "rollback",
            fixture.root.to_str().unwrap(),
            &migration_id,
            "--json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"state\": \"rolled_back\""));

    assert!(!fixture.root.join("Organized").exists());
    assert_eq!(source_snapshot(&fixture.root), before);
}

#[test]
fn test_harness_rejects_live_okada_path() {
    let live = Path::new(LIVE_OKADA_PATH);
    let error = guarded_fixture_source(live).unwrap_err();
    assert!(error.contains("live Okada path is forbidden"));
}

#[test]
fn okada_shaped_folder_to_folderbase_journey_preserves_restart_and_agent_entry_contract() {
    let fixture = golden_fixture();
    let source_before = source_snapshot(&fixture.root);
    let started = Instant::now();

    // Each command launches a fresh CLI process, matching the native bridge's
    // process and ordinary-file boundary instead of relying on in-memory state.
    let analysis = analyze(&fixture.root);
    assert!(!analysis["questions"].as_array().unwrap().is_empty());
    let plan = golden_plan(&fixture.root, &analysis);
    let migration_id = plan["id"].as_str().unwrap().to_owned();

    let preview = folderbase()
        .args([
            "transform",
            "preview",
            fixture.root.to_str().unwrap(),
            &migration_id,
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        preview.status.success(),
        "preview failed: {}",
        String::from_utf8_lossy(&preview.stderr)
    );
    let preview: serde_json::Value = serde_json::from_slice(&preview.stdout).unwrap();
    assert_eq!(preview["source_files_remain"], true);

    approve(&fixture.root, &migration_id);
    let applied = folderbase()
        .args([
            "transform",
            "apply",
            fixture.root.to_str().unwrap(),
            &migration_id,
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        applied.status.success(),
        "apply failed: {}",
        String::from_utf8_lossy(&applied.stderr)
    );
    let applied: serde_json::Value = serde_json::from_slice(&applied.stdout).unwrap();
    assert_eq!(applied["state"], "verified");

    let folderbase_path = fixture.root.join("Organized/Client-Shared.folderbase");
    folderbase()
        .args(["validate", folderbase_path.to_str().unwrap(), "--json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"valid\": true"));

    let listing = folderbase()
        .args([
            "workspace",
            "list",
            folderbase_path.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        listing.status.success(),
        "workspace list failed: {}",
        String::from_utf8_lossy(&listing.stderr)
    );
    let listing: serde_json::Value = serde_json::from_slice(&listing.stdout).unwrap();
    assert!(
        listing["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["path"] == "FOLDERBASE.md" && entry["editable"] == true)
    );
    assert!(
        listing["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["path"] == "Project-Overview.md" && entry["editable"] == true)
    );

    let original = folderbase()
        .args([
            "workspace",
            "read",
            folderbase_path.to_str().unwrap(),
            "Project-Overview.md",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        original.status.success(),
        "workspace read failed: {}",
        String::from_utf8_lossy(&original.stderr)
    );
    let original: serde_json::Value = serde_json::from_slice(&original.stdout).unwrap();
    let original_digest = original["sha256"].as_str().unwrap();
    let edited = format!(
        "{}\n\nAcceptance run: ordinary project work continued after transformation.\n",
        original["content"].as_str().unwrap().trim_end()
    );

    let saved = folderbase()
        .args([
            "workspace",
            "save",
            folderbase_path.to_str().unwrap(),
            "Project-Overview.md",
            "--expected-sha256",
            original_digest,
            "--stdin",
            "--json",
        ])
        .write_stdin(edited.as_bytes())
        .output()
        .unwrap();
    assert!(
        saved.status.success(),
        "workspace save failed: {}",
        String::from_utf8_lossy(&saved.stderr)
    );
    let saved: serde_json::Value = serde_json::from_slice(&saved.stdout).unwrap();
    let version_id = saved["version_id"].as_str().unwrap();

    // Prove that a fresh Codex/Claude session gets the exact root boundary and
    // ordinary-file contract without an MCP or manual context export.
    let adapter = fs::read_to_string(folderbase_path.join("AGENTS.md")).unwrap();
    assert!(adapter.contains("`.folderbase/manifest.json`"));
    assert!(adapter.contains("ordinary files"));
    assert!(!adapter.contains("../"));
    let claude_adapter = fs::read_to_string(folderbase_path.join("CLAUDE.md")).unwrap();
    assert!(claude_adapter.contains("`.folderbase/manifest.json`"));
    assert!(claude_adapter.contains("ordinary files"));
    assert!(!claude_adapter.contains("../"));
    assert!(
        !fs::read_to_string(folderbase_path.join("FOLDERBASE.md"))
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        fs::read_to_string(folderbase_path.join("Project-Overview.md")).unwrap(),
        edited
    );
    assert_eq!(source_snapshot(&fixture.root), source_before);

    let reopened = folderbase()
        .args([
            "transform",
            "reopen",
            fixture.root.to_str().unwrap(),
            &migration_id,
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        reopened.status.success(),
        "reopen failed: {}",
        String::from_utf8_lossy(&reopened.stderr)
    );
    let reopened: serde_json::Value = serde_json::from_slice(&reopened.stdout).unwrap();
    assert_eq!(reopened["state"], "verified");

    let fresh_read = folderbase()
        .args([
            "workspace",
            "read",
            folderbase_path.to_str().unwrap(),
            "Project-Overview.md",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(fresh_read.status.success());
    let fresh_read: serde_json::Value = serde_json::from_slice(&fresh_read.stdout).unwrap();
    assert_eq!(fresh_read["content"], edited);

    let history = folderbase()
        .args([
            "version",
            "history",
            folderbase_path.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert!(history.status.success());
    let history: Vec<serde_json::Value> = serde_json::from_slice(&history.stdout).unwrap();
    assert!(history.iter().any(|event| {
        event["version_id"] == version_id && event["path"] == "Project-Overview.md"
    }));

    let elapsed = started.elapsed();
    eprintln!("automated folder-to-folderbase acceptance elapsed: {elapsed:?}");
    assert!(
        elapsed <= Duration::from_secs(300),
        "automated acceptance exceeded five minutes: {elapsed:?}"
    );
}

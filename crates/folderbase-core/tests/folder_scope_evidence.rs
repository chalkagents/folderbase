use std::{fs, path::Path};

use folderbase_core::{FolderScopeEvidenceError, FolderbaseVersionStore, observe_folder_scope};
use serde_json::Value;
use tempfile::{TempDir, tempdir};
use uuid::Uuid;

const FOLDERBASE_ID: &str = "folderbase_019fb97e-9c5f-73ca-9bb2-03dc80f9478c";
const MANIFEST: &[u8] = br#"{
  "protocol_version": "0.1.0",
  "folderbase": {
    "id": "folderbase_019fb97e-9c5f-73ca-9bb2-03dc80f9478c"
  }
}
"#;

fn folderbase() -> TempDir {
    let root = tempdir().expect("temporary Folderbase");
    write_folderbase(root.path());
    root
}

fn write_folderbase(root: &Path) {
    fs::create_dir_all(root.join(".folderbase")).expect("state directory");
    fs::write(root.join(".folderbase/manifest.json"), MANIFEST).expect("manifest");
    fs::write(root.join(".folderbaseignore"), "").expect("ignore policy");
    fs::write(root.join("FOLDERBASE.md"), "# Folderbase\n").expect("entry marker");
    fs::create_dir_all(root.join("Client Work/Briefs")).expect("selected folder");
    fs::write(
        root.join("Client Work/Briefs/current.md"),
        "current brief\n",
    )
    .expect("ordinary file");
}

fn nested_manifest(folderbase_id: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "$schema": "https://folderbase.ai/protocol/0.5/folderbase.schema.json",
        "protocol_version": "0.5.0",
        "folderbase": {
            "id": folderbase_id,
            "name": "Nested project",
            "kind": "project",
            "status": "active",
            "created_at": "2026-08-10T00:00:00Z"
        },
        "adapters": [],
        "policies": {
            "availability": "keep_local",
            "structural_changes": "approve",
            "archive": "manual",
            "cloud_sync": "disabled",
            "capture_ignore": {
                "format": "folderbase-capture-ignore-v1",
                "rules": []
            }
        }
    }))
    .expect("nested Folderbase manifest")
}

fn copy_tree(source: &Path, destination: &Path) {
    fs::create_dir_all(destination).expect("copy destination directory");
    for entry in fs::read_dir(source).expect("read copied tree") {
        let entry = entry.expect("copied tree entry");
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        if entry.file_type().expect("copied entry type").is_dir() {
            copy_tree(&source_path, &destination_path);
        } else {
            fs::copy(&source_path, &destination_path).expect("copy ordinary tree file");
        }
    }
}

#[test]
fn first_exact_folder_observation_is_replayed_idempotently() {
    let root = folderbase();

    let first = observe_folder_scope(root.path(), Path::new("Client Work"))
        .expect("first exact-folder observation");
    let repeated = observe_folder_scope(root.path(), Path::new("Client Work"))
        .expect("idempotent repeated observation");

    assert_eq!(first, repeated);
    assert_eq!(first.format, "folderbase-folder-scope-evidence-v1");
    assert_eq!(first.folderbase_id, FOLDERBASE_ID);
    assert_eq!(first.selected_path, "Client Work");
    assert_eq!(first.device_sequence, 1);
    assert!(first.event_id.starts_with("folder_scope_event_"));
    assert_eq!(first.event_id.len(), "folder_scope_event_".len() + 64);
    assert!(
        first
            .opaque_binding_proof
            .starts_with("fb_scope_binding_v1_")
    );
    assert_eq!(
        first.opaque_binding_proof.len(),
        "fb_scope_binding_v1_".len() + 64
    );
    assert!(first.nested_boundaries.is_empty());
}

#[test]
fn observation_reports_exact_nested_folderbase_boundaries_without_reading_file_contents() {
    let root = folderbase();
    fs::create_dir_all(root.path().join("Client Work/Repository/.git"))
        .expect("repository metadata");
    fs::write(
        root.path().join("Client Work/Repository/archive.bin"),
        [0_u8, 159, 146, 150, 255],
    )
    .expect("opaque binary file");
    fs::write(
        root.path().join("Client Work/Repository/records.csv"),
        "name,value\nalpha,1\n",
    )
    .expect("csv file");
    fs::create_dir_all(root.path().join("Client Work/Partner/.folderbase"))
        .expect("nested state directory");
    fs::write(
        root.path()
            .join("Client Work/Partner/.folderbase/manifest.json"),
        nested_manifest("folderbase_019fb97e-9c5f-73ca-9bb2-03dc80f9478d"),
    )
    .expect("nested manifest");
    fs::create_dir_all(root.path().join("Client Work/Partner/Inside/Deeper"))
        .expect("opaque nested contents");

    let evidence = observe_folder_scope(root.path(), Path::new("Client Work"))
        .expect("observe heterogeneous selected folder");

    assert_eq!(
        evidence.nested_boundaries,
        vec!["Client Work/Partner".to_owned()]
    );
}

#[test]
fn a_new_local_head_advances_evidence_without_changing_folder_continuity() {
    let root = folderbase();
    let genesis =
        observe_folder_scope(root.path(), Path::new("Client Work")).expect("genesis observation");

    let store = FolderbaseVersionStore::open(root.path()).expect("open version store");
    let plan = store.plan_capture().expect("plan first capture");
    store.seal_capture(plan).expect("publish first Local Head");

    let captured = observe_folder_scope(root.path(), Path::new("Client Work"))
        .expect("non-genesis observation");
    let repeated = observe_folder_scope(root.path(), Path::new("Client Work"))
        .expect("repeat non-genesis observation");

    assert_eq!(captured, repeated);
    assert_eq!(captured.device_sequence, 2);
    assert_ne!(captured.event_id, genesis.event_id);
    assert_eq!(
        captured.opaque_binding_proof, genesis.opaque_binding_proof,
        "version progress must not erase physical folder continuity"
    );
}

#[test]
fn a_physical_folder_rename_preserves_continuity_and_advances_the_journal() {
    let root = folderbase();
    let before = observe_folder_scope(root.path(), Path::new("Client Work"))
        .expect("observe original folder path");
    fs::rename(
        root.path().join("Client Work"),
        root.path().join("Active Client Work"),
    )
    .expect("rename selected folder");

    let after = observe_folder_scope(root.path(), Path::new("Active Client Work"))
        .expect("observe renamed physical folder");

    assert_eq!(after.selected_path, "Active Client Work");
    assert_eq!(after.device_sequence, 2);
    assert_ne!(after.event_id, before.event_id);
    assert_eq!(after.opaque_binding_proof, before.opaque_binding_proof);
}

#[test]
fn a_different_folder_at_an_observed_path_cannot_inherit_scope_continuity() {
    let root = folderbase();
    observe_folder_scope(root.path(), Path::new("Client Work"))
        .expect("observe original physical folder");
    fs::rename(
        root.path().join("Client Work"),
        root.path().join("Original Client Work"),
    )
    .expect("retain original elsewhere");
    fs::create_dir(root.path().join("Client Work")).expect("replacement folder");

    let error = observe_folder_scope(root.path(), Path::new("Client Work"))
        .expect_err("replacement must not inherit the observed path");

    assert!(matches!(
        error,
        FolderScopeEvidenceError::SelectedFolderReplaced { path }
            if path == Path::new("Client Work")
    ));
}

#[test]
fn replay_stays_idempotent_after_another_folder_advances_the_device_journal() {
    let root = folderbase();
    fs::create_dir(root.path().join("Personal")).expect("second selected folder");

    let client =
        observe_folder_scope(root.path(), Path::new("Client Work")).expect("observe client folder");
    let personal =
        observe_folder_scope(root.path(), Path::new("Personal")).expect("observe personal folder");
    let client_replay =
        observe_folder_scope(root.path(), Path::new("Client Work")).expect("replay client folder");

    assert_eq!(client.device_sequence, 1);
    assert_eq!(personal.device_sequence, 2);
    assert_eq!(client_replay, client);
}

#[test]
fn copied_state_cannot_authorize_a_replacement_physical_root() {
    let root = folderbase();
    observe_folder_scope(root.path(), Path::new("Client Work"))
        .expect("observe original physical root");
    let original_head = fs::read(
        root.path()
            .join(".folderbase/local/folder-scope-evidence-v1/head.json"),
    )
    .expect("original scope journal head");
    let backup = tempdir().expect("root backup");
    copy_tree(root.path(), backup.path());
    fs::remove_dir_all(root.path()).expect("remove original physical root");
    fs::create_dir(root.path()).expect("replacement physical root");
    copy_tree(backup.path(), root.path());

    let result = observe_folder_scope(root.path(), Path::new("Client Work"));

    assert!(
        result.is_err(),
        "copied state must not bind a replacement root"
    );
    assert_eq!(
        fs::read(
            root.path()
                .join(".folderbase/local/folder-scope-evidence-v1/head.json")
        )
        .expect("replacement journal head remains present"),
        original_head,
        "failed observation must not rewrite the copied journal"
    );
}

#[cfg(unix)]
#[test]
fn escaping_symlink_fails_before_the_scope_journal_is_created() {
    let root = folderbase();
    let outside = tempdir().expect("outside directory");
    fs::write(outside.path().join("secret.txt"), "outside\n").expect("outside file");
    std::os::unix::fs::symlink(
        outside.path().join("secret.txt"),
        root.path().join("Client Work/escape"),
    )
    .expect("escaping symlink");

    let error = observe_folder_scope(root.path(), Path::new("Client Work"))
        .expect_err("escaping symlink must fail closed");

    assert_eq!(error.code(), "folder_scope_capture_invalid");
    assert!(
        !root
            .path()
            .join(".folderbase/local/folder-scope-evidence-v1")
            .exists(),
        "failed observation must not create its journal"
    );
}

#[cfg(unix)]
#[test]
fn unsupported_node_fails_before_the_scope_journal_is_created() {
    use std::{ffi::CString, os::unix::ffi::OsStrExt};

    let root = folderbase();
    let fifo = root.path().join("Client Work/agent.pipe");
    let fifo_c = CString::new(fifo.as_os_str().as_bytes()).expect("fifo path");
    assert_eq!(unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o600) }, 0);

    let error = observe_folder_scope(root.path(), Path::new("Client Work"))
        .expect_err("unsupported node must fail closed");

    assert!(matches!(
        error,
        FolderScopeEvidenceError::UnsupportedSelectedNode { path }
            if path == Path::new("Client Work/agent.pipe")
    ));
    assert!(
        !root
            .path()
            .join(".folderbase/local/folder-scope-evidence-v1")
            .exists(),
        "failed observation must not create its journal"
    );
}

#[test]
fn changing_nested_folderbase_boundaries_requires_a_new_explicit_scope() {
    let root = folderbase();
    observe_folder_scope(root.path(), Path::new("Client Work"))
        .expect("observe scope without nested boundary");
    let head_path = root
        .path()
        .join(".folderbase/local/folder-scope-evidence-v1/head.json");
    let original_head = fs::read(&head_path).expect("original journal head");
    fs::create_dir_all(root.path().join("Client Work/Partner/.folderbase"))
        .expect("nested Folderbase state");
    fs::write(
        root.path()
            .join("Client Work/Partner/.folderbase/manifest.json"),
        nested_manifest("folderbase_019fb97e-9c5f-73ca-9bb2-03dc80f9478e"),
    )
    .expect("nested manifest");

    let error = observe_folder_scope(root.path(), Path::new("Client Work"))
        .expect_err("boundary change must not silently widen or narrow the scope");

    assert!(matches!(
        error,
        FolderScopeEvidenceError::NestedBoundaryChanged { path }
            if path == Path::new("Client Work")
    ));
    assert_eq!(
        fs::read(head_path).expect("journal head remains readable"),
        original_head
    );
    assert!(
        !root
            .path()
            .join(".folderbase/local/folder-scope-evidence-v1/events/00000000000000000002.json")
            .exists(),
        "boundary rejection must not append an event"
    );
}

#[test]
fn renaming_a_scope_rebases_unchanged_nested_boundary_paths() {
    let root = folderbase();
    fs::create_dir_all(root.path().join("Client Work/Partner/.folderbase"))
        .expect("nested Folderbase state");
    fs::write(
        root.path()
            .join("Client Work/Partner/.folderbase/manifest.json"),
        nested_manifest("folderbase_019fb97e-9c5f-73ca-9bb2-03dc80f9478f"),
    )
    .expect("nested manifest");
    let before = observe_folder_scope(root.path(), Path::new("Client Work"))
        .expect("observe original path and boundary");
    fs::rename(
        root.path().join("Client Work"),
        root.path().join("Active Client Work"),
    )
    .expect("rename selected folder");

    let after = observe_folder_scope(root.path(), Path::new("Active Client Work"))
        .expect("rename preserves the same relative boundary topology");

    assert_eq!(after.device_sequence, 2);
    assert_eq!(after.opaque_binding_proof, before.opaque_binding_proof);
    assert_eq!(
        after.nested_boundaries,
        vec!["Active Client Work/Partner".to_owned()]
    );
}

#[test]
fn replacing_a_nested_folderbase_at_the_same_path_invalidates_scope_continuity() {
    let root = folderbase();
    let nested_manifest_path = root
        .path()
        .join("Client Work/Partner/.folderbase/manifest.json");
    fs::create_dir_all(nested_manifest_path.parent().expect("nested state parent"))
        .expect("nested Folderbase state");
    fs::write(
        &nested_manifest_path,
        nested_manifest("folderbase_019fb97e-9c5f-73ca-9bb2-03dc80f9478f"),
    )
    .expect("original nested manifest");
    observe_folder_scope(root.path(), Path::new("Client Work"))
        .expect("observe original nested boundary authority");
    let head_path = root
        .path()
        .join(".folderbase/local/folder-scope-evidence-v1/head.json");
    let original_head = fs::read(&head_path).expect("original journal head");
    fs::write(
        &nested_manifest_path,
        nested_manifest("folderbase_019fb97e-9c5f-73ca-9bb2-03dc80f94791"),
    )
    .expect("replacement nested manifest");

    let error = observe_folder_scope(root.path(), Path::new("Client Work"))
        .expect_err("same-path nested Folderbase replacement must invalidate scope continuity");

    assert!(matches!(
        error,
        FolderScopeEvidenceError::NestedBoundaryChanged { path }
            if path == Path::new("Client Work")
    ));
    assert_eq!(
        fs::read(head_path).expect("journal head remains readable"),
        original_head
    );
}

#[test]
fn binding_proof_is_bound_to_a_core_owned_non_reusable_nonce() {
    let root = folderbase();
    observe_folder_scope(root.path(), Path::new("Client Work")).expect("initial observation");
    let event_path = root
        .path()
        .join(".folderbase/local/folder-scope-evidence-v1/events/00000000000000000001.json");
    let mut event: Value = serde_json::from_slice(&fs::read(&event_path).expect("journal event"))
        .expect("closed journal event JSON");
    let nonce = event["binding_nonce"]
        .as_str()
        .expect("Core-owned binding nonce is recorded privately");
    let suffix = nonce
        .strip_prefix("folder_scope_binding_nonce_")
        .expect("binding nonce prefix");
    Uuid::parse_str(suffix).expect("binding nonce UUID");
    event["binding_nonce"] =
        Value::String(format!("folder_scope_binding_nonce_{}", Uuid::now_v7()));
    fs::write(
        &event_path,
        serde_json::to_vec(&event).expect("tampered event JSON"),
    )
    .expect("tamper private binding nonce");

    let error = observe_folder_scope(root.path(), Path::new("Client Work"))
        .expect_err("changing the Core-owned nonce must invalidate the proof");

    assert!(matches!(
        error,
        FolderScopeEvidenceError::InvalidJournal { .. }
    ));
}

#[test]
fn tampered_journal_event_fails_closed_without_rewriting_the_head() {
    let root = folderbase();
    observe_folder_scope(root.path(), Path::new("Client Work")).expect("initial observation");
    let journal = root
        .path()
        .join(".folderbase/local/folder-scope-evidence-v1");
    let head_path = journal.join("head.json");
    let event_path = journal.join("events/00000000000000000001.json");
    let original_head = fs::read(&head_path).expect("original head");
    let event = fs::read_to_string(&event_path).expect("original event");
    assert!(event.contains("Client Work"));
    fs::write(&event_path, event.replacen("Client Work", "Client W0rk", 1))
        .expect("tamper event bytes");

    let error = observe_folder_scope(root.path(), Path::new("Client Work"))
        .expect_err("tampered journal must fail closed");

    assert!(matches!(
        error,
        FolderScopeEvidenceError::InvalidJournal { .. }
    ));
    assert_eq!(
        fs::read(head_path).expect("head remains readable"),
        original_head
    );
}

#[test]
fn restart_recovers_an_identical_event_published_before_its_head() {
    let root = folderbase();
    fs::create_dir(root.path().join("Personal")).expect("second selected folder");
    observe_folder_scope(root.path(), Path::new("Client Work")).expect("first observation");
    let head_path = root
        .path()
        .join(".folderbase/local/folder-scope-evidence-v1/head.json");
    let first_head = fs::read(&head_path).expect("first head");
    let personal =
        observe_folder_scope(root.path(), Path::new("Personal")).expect("second event and head");
    let second_head = fs::read(&head_path).expect("second head");
    fs::write(&head_path, first_head).expect("simulate crash before head publication");

    let recovered = observe_folder_scope(root.path(), Path::new("Personal"))
        .expect("recover matching orphan event");

    assert_eq!(recovered, personal);
    assert_eq!(fs::read(head_path).expect("recovered head"), second_head);
}

#[test]
fn unexpected_journal_entries_fail_closed_instead_of_hiding_unbounded_work() {
    let root = folderbase();
    let original =
        observe_folder_scope(root.path(), Path::new("Client Work")).expect("initial observation");
    let journal = root
        .path()
        .join(".folderbase/local/folder-scope-evidence-v1");
    let head_path = journal.join("head.json");
    let original_head = fs::read(&head_path).expect("original head");
    fs::write(journal.join("events/rogue.json"), b"{}").expect("unexpected journal entry");

    let error = observe_folder_scope(root.path(), Path::new("Client Work"))
        .expect_err("unexpected entry must invalidate the bounded journal");

    assert!(matches!(
        error,
        FolderScopeEvidenceError::InvalidJournal { .. }
    ));
    assert_eq!(
        fs::read(head_path).expect("head remains readable"),
        original_head
    );
    assert_eq!(original.device_sequence, 1);
}

#[test]
fn unexpected_journal_root_entries_fail_closed_instead_of_hiding_unbounded_work() {
    let root = folderbase();
    let original =
        observe_folder_scope(root.path(), Path::new("Client Work")).expect("initial observation");
    let journal = root
        .path()
        .join(".folderbase/local/folder-scope-evidence-v1");
    let head_path = journal.join("head.json");
    let original_head = fs::read(&head_path).expect("original head");
    fs::write(journal.join("rogue.bin"), vec![0_u8; 128]).expect("unexpected journal root entry");

    let error = observe_folder_scope(root.path(), Path::new("Client Work"))
        .expect_err("unexpected root entry must invalidate the bounded journal");

    assert!(matches!(
        error,
        FolderScopeEvidenceError::InvalidJournal { .. }
    ));
    assert_eq!(
        fs::read(head_path).expect("head remains readable"),
        original_head
    );
    assert_eq!(original.device_sequence, 1);
}

#[test]
fn deleting_a_committed_journal_directory_cannot_restart_scope_authority_at_genesis() {
    let root = folderbase();
    let original =
        observe_folder_scope(root.path(), Path::new("Client Work")).expect("initial observation");
    let journal = root
        .path()
        .join(".folderbase/local/folder-scope-evidence-v1");
    let removed = root
        .path()
        .join(".folderbase/local/folder-scope-evidence-v1.removed-for-test");
    fs::rename(&journal, &removed).expect("retain the removed journal outside its authority path");

    let error = observe_folder_scope(root.path(), Path::new("Client Work"))
        .expect_err("lost committed continuity must not become a new genesis");

    assert!(matches!(
        error,
        FolderScopeEvidenceError::InvalidJournal { .. }
    ));
    assert!(!journal.exists(), "refusal must not recreate the journal");
    assert_eq!(original.device_sequence, 1);
}

#[test]
fn deleting_the_independent_authority_cannot_adopt_a_committed_journal() {
    let root = folderbase();
    observe_folder_scope(root.path(), Path::new("Client Work")).expect("initial observation");
    let authority = root
        .path()
        .join(".folderbase/local/folder-scope-evidence-authority-v1.json");
    let removed = root
        .path()
        .join(".folderbase/local/folder-scope-evidence-authority-v1.removed-for-test");
    let head = root
        .path()
        .join(".folderbase/local/folder-scope-evidence-v1/head.json");
    let original_head = fs::read(&head).expect("committed journal head");
    fs::rename(&authority, &removed).expect("retain removed authority for the fixture");

    let error = observe_folder_scope(root.path(), Path::new("Client Work"))
        .expect_err("a committed journal without its authority must fail closed");

    assert!(matches!(
        error,
        FolderScopeEvidenceError::InvalidJournal { .. }
    ));
    assert!(
        !authority.exists(),
        "refusal must not replace the authority"
    );
    assert_eq!(fs::read(head).expect("journal head remains"), original_head);
}

#[test]
fn nested_boundary_limit_accepts_the_advertised_edge_and_refuses_one_more() {
    const ADVERTISED_BOUNDARY_LIMIT: usize = 256;

    let accepted = folderbase();
    for index in 0..ADVERTISED_BOUNDARY_LIMIT {
        let manifest = accepted.path().join(format!(
            "Client Work/Boundary {index:03}/.folderbase/manifest.json"
        ));
        fs::create_dir_all(manifest.parent().expect("nested state parent"))
            .expect("nested state directory");
        fs::write(
            manifest,
            nested_manifest(&format!("folderbase_{}", Uuid::now_v7())),
        )
        .expect("nested manifest");
    }
    let evidence = observe_folder_scope(accepted.path(), Path::new("Client Work"))
        .expect("the advertised nested-boundary edge must fit its journal event");
    assert_eq!(evidence.nested_boundaries.len(), ADVERTISED_BOUNDARY_LIMIT);

    let rejected = folderbase();
    for index in 0..=ADVERTISED_BOUNDARY_LIMIT {
        let manifest = rejected.path().join(format!(
            "Client Work/Boundary {index:03}/.folderbase/manifest.json"
        ));
        fs::create_dir_all(manifest.parent().expect("nested state parent"))
            .expect("nested state directory");
        fs::write(
            manifest,
            nested_manifest(&format!("folderbase_{}", Uuid::now_v7())),
        )
        .expect("nested manifest");
    }

    let error = observe_folder_scope(rejected.path(), Path::new("Client Work"))
        .expect_err("one boundary beyond the public maximum must fail before publication");
    assert!(matches!(
        error,
        FolderScopeEvidenceError::ScopeLimitExceeded {
            maximum: ADVERTISED_BOUNDARY_LIMIT
        }
    ));
    assert!(
        !rejected
            .path()
            .join(".folderbase/local/folder-scope-evidence-v1")
            .exists(),
        "over-limit topology must not create a journal"
    );
}

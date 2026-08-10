use std::{fs, path::Path};

use folderbase_core::{FolderScopeEvidenceError, FolderbaseVersionStore, observe_folder_scope};
use tempfile::{TempDir, tempdir};

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
        root.path().join("Client Work/Partner/.folderbase/manifest.json"),
        br#"{"protocol_version":"0.5.0","folderbase":{"id":"folderbase_019fb97e-9c5f-73ca-9bb2-03dc80f9478d"},"capture":{"ignore_rules":[]}}"#,
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
        root.path().join("Client Work/Partner/.folderbase/manifest.json"),
        br#"{"protocol_version":"0.5.0","folderbase":{"id":"folderbase_019fb97e-9c5f-73ca-9bb2-03dc80f9478e"},"capture":{"ignore_rules":[]}}"#,
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
        root.path().join("Client Work/Partner/.folderbase/manifest.json"),
        br#"{"protocol_version":"0.5.0","folderbase":{"id":"folderbase_019fb97e-9c5f-73ca-9bb2-03dc80f9478f"},"capture":{"ignore_rules":[]}}"#,
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

use std::{fs, path::Path};

use folderbase_core::{FolderbaseVersionStore, observe_folder_scope};
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
    fs::create_dir(root.path().join(".folderbase")).expect("state directory");
    fs::write(root.path().join(".folderbase/manifest.json"), MANIFEST).expect("manifest");
    fs::write(root.path().join(".folderbaseignore"), "").expect("ignore policy");
    fs::write(root.path().join("FOLDERBASE.md"), "# Folderbase\n").expect("entry marker");
    fs::create_dir_all(root.path().join("Client Work/Briefs")).expect("selected folder");
    fs::write(
        root.path().join("Client Work/Briefs/current.md"),
        "current brief\n",
    )
    .expect("ordinary file");
    root
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

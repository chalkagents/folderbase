use std::fs;

use folderbase_core::{
    FolderbaseError, FolderbaseVersionStore, apply_protocol_upgrade, plan_protocol_upgrade,
};
use tempfile::{TempDir, tempdir};

const LEGACY_MANIFEST: &[u8] = br#"{
  "$schema": "https://folderbase.ai/protocol/0.1/folderbase.schema.json",
  "protocol_version": "0.1.0",
  "folderbase": {
    "id": "folderbase_019f9b75-4f42-7f65-a012-2bfecdd8c475",
    "name": "Legacy Folderbase",
    "kind": "project",
    "status": "active",
    "created_at": "2026-07-26T00:00:00Z",
    "entry": "FOLDERBASE.md"
  },
  "policies": {
    "availability": "keep_local",
    "structural_changes": "approve",
    "archive": "approve",
    "cloud_sync": "disabled"
  }
}
"#;

fn legacy_root() -> TempDir {
    let root = tempdir().expect("legacy root");
    fs::create_dir(root.path().join(".folderbase")).expect("state");
    fs::write(
        root.path().join(".folderbase/manifest.json"),
        LEGACY_MANIFEST,
    )
    .expect("manifest");
    fs::write(root.path().join("FOLDERBASE.md"), b"# User narrative\n").expect("entry");
    fs::write(root.path().join(".folderbaseignore"), b"node_modules/\n").expect("ignore");
    root
}

#[cfg(unix)]
#[test]
fn upgrade_refuses_a_supplied_symlink_root_before_canonicalization() {
    let root = legacy_root();
    let links = tempdir().expect("link parent");
    let link = links.path().join("linked-root");
    std::os::unix::fs::symlink(root.path(), &link).expect("root symlink");

    assert!(plan_protocol_upgrade(&link).is_err());
    assert_eq!(
        fs::read(root.path().join(".folderbase/manifest.json")).unwrap(),
        LEGACY_MANIFEST
    );
}

#[test]
fn upgrade_planning_is_metadata_only_for_a_sparse_ten_gibibyte_narrative() {
    let root = legacy_root();
    fs::File::options()
        .write(true)
        .open(root.path().join("FOLDERBASE.md"))
        .expect("entry")
        .set_len(10 * 1024 * 1024 * 1024)
        .expect("sparse narrative");

    let plan = plan_protocol_upgrade(root.path()).expect("metadata-only upgrade plan");
    assert_eq!(plan.plan_digest().digest().len(), 64);
}

#[test]
fn manifest_activation_is_an_idempotent_applied_upgrade_receipt() {
    let root = legacy_root();
    fs::write(root.path().join("notes.md"), b"ordinary").expect("content");
    let store = FolderbaseVersionStore::open(root.path()).expect("legacy opens");
    store
        .seal_capture(store.plan_capture().expect("legacy capture plan"))
        .expect("legacy parent");
    let plan = plan_protocol_upgrade(root.path()).expect("upgrade plan");
    let expected = plan.plan_digest().clone();
    let first = apply_protocol_upgrade(&plan, &expected).expect("manifest activation");

    let retry = plan_protocol_upgrade(root.path()).expect("reopen applied receipt");
    assert_eq!(retry.plan_digest(), &expected);
    let second = apply_protocol_upgrade(&retry, &expected).expect("idempotent retry");
    assert_eq!(second.applied_plan_digest, first.applied_plan_digest);
    assert_eq!(
        fs::read(root.path().join("FOLDERBASE.md")).unwrap(),
        b"# User narrative\n"
    );
}

#[test]
fn an_applied_receipt_cannot_make_a_mutated_target_match_the_reviewed_plan() {
    let root = legacy_root();
    let plan = plan_protocol_upgrade(root.path()).expect("upgrade plan");
    let expected = plan.plan_digest().clone();
    apply_protocol_upgrade(&plan, &expected).expect("manifest activation");

    let manifest_path = root.path().join(".folderbase/manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(&manifest_path).expect("activated manifest"))
            .expect("manifest JSON");
    manifest["policies"]["availability"] = serde_json::json!("cloud_only");
    fs::write(
        &manifest_path,
        format!("{}\n", serde_json::to_string_pretty(&manifest).unwrap()),
    )
    .expect("foreign target mutation");

    assert!(
        apply_protocol_upgrade(&plan, &expected).is_err(),
        "the durable receipt cannot authorize a different target manifest"
    );
}

#[test]
fn upgrade_refuses_active_capture_restore_migration_and_reorganization_work() {
    for (relative, label) in [
        (
            ".folderbase/transactions/folderbase-version-captures/active.json",
            "capture",
        ),
        (
            ".folderbase/transactions/folderbase-version-restores/active.json",
            "restore",
        ),
        (
            ".folderbase/migrations/migration_pending/plan.json",
            "migration",
        ),
        (".folderbase/reorganizations/active.json", "reorganization"),
    ] {
        let root = legacy_root();
        let path = root.path().join(relative);
        fs::create_dir_all(path.parent().unwrap()).expect("pending parent");
        let bytes = if label == "migration" {
            br#"{"state":"applying"}"#.as_slice()
        } else {
            b"{}".as_slice()
        };
        fs::write(&path, bytes).expect("pending record");
        assert!(
            matches!(
                plan_protocol_upgrade(root.path()),
                Err(FolderbaseError::ProtocolUpgradeBlocked(_))
            ),
            "{label} blocks the protocol transition"
        );
        assert_eq!(
            fs::read(root.path().join(".folderbase/manifest.json")).unwrap(),
            LEGACY_MANIFEST
        );
    }
}

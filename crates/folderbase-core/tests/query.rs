use std::fs;

use folderbase_core::{
    FolderbaseQueryEngine, QueryEntryKind, QueryExecution, QueryRequest, QuerySource,
};
use tempfile::{TempDir, tempdir};

const MANIFEST: &[u8] = br#"{
  "$schema": "https://folderbase.ai/protocol/0.5/folderbase.schema.json",
  "protocol_version": "0.5.0",
  "folderbase": {
    "id": "folderbase_019f9b75-4f42-7f65-a012-2bfecdd8c473",
    "name": "Query fixture",
    "kind": "project",
    "status": "active",
    "created_at": "2026-08-04T00:00:00Z"
  },
  "adapters": [],
  "policies": {
    "availability": "keep_local",
    "structural_changes": "approve",
    "archive": "manual",
    "cloud_sync": "disabled",
    "capture_ignore": {
      "format": "folderbase-capture-ignore-v1",
      "rules": ["ignored/"]
    }
  }
}
"#;

fn folderbase() -> TempDir {
    let root = tempdir().expect("temporary Folderbase");
    fs::create_dir(root.path().join(".folderbase")).expect("state directory");
    fs::write(root.path().join(".folderbase/manifest.json"), MANIFEST).expect("manifest");
    root
}

#[test]
fn live_query_projects_the_capture_plan_without_opening_ordinary_file_bytes() {
    let root = folderbase();
    fs::create_dir_all(root.path().join("data")).expect("data directory");
    fs::write(root.path().join("data/table.csv"), b"a,b\none,two\n").expect("CSV");
    fs::create_dir_all(root.path().join("ignored/private")).expect("ignored tree");
    fs::write(root.path().join("ignored/private/secret.txt"), b"secret").expect("ignored file");
    fs::create_dir_all(root.path().join("clients/acme/.folderbase")).expect("nested state");
    fs::write(
        root.path().join("clients/acme/.folderbase/manifest.json"),
        b"opaque nested marker",
    )
    .expect("nested manifest");
    fs::write(root.path().join("clients/acme/private.bin"), b"opaque").expect("nested file");

    let engine = FolderbaseQueryEngine::open(root.path()).expect("open query engine");
    let result = engine
        .run(&QueryRequest::live(1000))
        .expect("metadata-only live query");

    assert_eq!(result.execution(), QueryExecution::BoundedScan);
    assert_eq!(
        result
            .entries()
            .iter()
            .map(|entry| (
                entry.path(),
                entry.kind(),
                entry.bytes(),
                entry.source(),
            ))
            .collect::<Vec<_>>(),
        vec![
            ("clients", QueryEntryKind::Directory, None, QuerySource::CapturePlan),
            (
                "clients/acme",
                QueryEntryKind::NestedFolderbase,
                None,
                QuerySource::CapturePlan,
            ),
            ("data", QueryEntryKind::Directory, None, QuerySource::CapturePlan),
            (
                "data/table.csv",
                QueryEntryKind::RegularFile,
                Some(12),
                QuerySource::CapturePlan,
            ),
        ]
    );
    assert!(
        result
            .exclusions()
            .iter()
            .any(|exclusion| exclusion.path() == "ignored")
    );
    assert!(
        result
            .entries()
            .iter()
            .all(|entry| !entry.path().starts_with("clients/acme/"))
    );
}

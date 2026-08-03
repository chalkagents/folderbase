use std::fs;

use folderbase_core::{
    FolderbaseQueryEngine, QueryEntryKind, QueryError, QueryExecution, QueryLifecycle,
    QueryRequest, QuerySource,
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

fn request(value: serde_json::Value) -> QueryRequest {
    serde_json::from_value(value).expect("query request shape")
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
            .map(|entry| (entry.path(), entry.kind(), entry.bytes(), entry.source(),))
            .collect::<Vec<_>>(),
        vec![
            (
                "clients",
                QueryEntryKind::Directory,
                None,
                QuerySource::CapturePlan
            ),
            (
                "clients/acme",
                QueryEntryKind::NestedFolderbase,
                None,
                QuerySource::CapturePlan,
            ),
            (
                "data",
                QueryEntryKind::Directory,
                None,
                QuerySource::CapturePlan
            ),
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

#[test]
fn historical_query_projects_one_verified_version_with_exact_identity() {
    const VERSION_ID: &str = "fbversion_019f0000-0000-7000-8000-000000000001";
    let root = folderbase();
    fs::write(
        root.path().join(".folderbase/manifest.json"),
        String::from_utf8_lossy(MANIFEST).replace(
            "folderbase_019f9b75-4f42-7f65-a012-2bfecdd8c473",
            "folderbase_018f43c2-9a1b-7def-8123-456789abcdef",
        ),
    )
    .expect("matching historical Folderbase identity");
    let versions = root.path().join(".folderbase/versions/folderbase");
    fs::create_dir_all(&versions).expect("Folderbase Version directory");
    fs::copy(
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../protocol/conformance/capabilities/query-index-0.1/fixtures/historical-version.json"
        ),
        versions.join(format!("{VERSION_ID}.json")),
    )
    .expect("historical fixture");

    let engine = FolderbaseQueryEngine::open(root.path()).expect("query engine");
    let result = engine
        .run(&request(serde_json::json!({
            "format": "folderbase-query-request-v1",
            "scope": {"kind": "historical", "folderbase_version_id": VERSION_ID},
            "filters": {
                "lifecycles": ["deleted"],
                "object_ids": ["obj_019f0000-0000-7000-8000-000000000010"]
            },
            "page": {"limit": 10}
        })))
        .expect("verified historical query");

    assert_eq!(result.entries().len(), 1);
    let deleted = &result.entries()[0];
    assert_eq!(deleted.path(), "archive/approved-proposal.docx");
    assert_eq!(deleted.lifecycle(), QueryLifecycle::Deleted);
    assert_eq!(
        deleted.object_id(),
        Some("obj_019f0000-0000-7000-8000-000000000010")
    );
    assert_eq!(
        deleted.object_version_id(),
        Some("version_019f0000-0000-7000-8000-000000000011")
    );
    assert_eq!(deleted.folderbase_version_id(), Some(VERSION_ID));
    assert_eq!(deleted.source(), QuerySource::FolderbaseVersion);

    let missing = engine
        .run(&request(serde_json::json!({
            "format": "folderbase-query-request-v1",
            "scope": {
                "kind": "historical",
                "folderbase_version_id": "fbversion_019f0000-0000-7000-8000-000000000099"
            },
            "page": {"limit": 10}
        })))
        .expect_err("missing exact Version");
    assert!(matches!(missing, QueryError::ScopeVersionMissing { .. }));

    fs::write(versions.join(format!("{VERSION_ID}.json")), b"{not json").expect("tamper Version");
    let invalid = engine
        .run(&request(serde_json::json!({
            "format": "folderbase-query-request-v1",
            "scope": {"kind": "historical", "folderbase_version_id": VERSION_ID},
            "page": {"limit": 10}
        })))
        .expect_err("invalid exact Version");
    assert!(matches!(invalid, QueryError::ScopeVersionInvalid { .. }));
}

#[test]
fn filters_intersect_families_and_or_values_with_component_aware_prefixes() {
    let root = folderbase();
    fs::create_dir(root.path().join("data")).expect("data");
    fs::write(root.path().join("data/app.sqlite"), b"SQLite format 3\0").expect("SQLite");
    fs::write(root.path().join("data/table.csv"), b"a,b\n1,2\n").expect("CSV");
    fs::write(root.path().join("database.md"), b"# sibling\n").expect("sibling");
    fs::write(root.path().join("notes.md"), b"# Notes\n").expect("notes");
    let engine = FolderbaseQueryEngine::open(root.path()).expect("query engine");

    let filtered = engine
        .run(&request(serde_json::json!({
            "format": "folderbase-query-request-v1",
            "scope": {"kind": "live"},
            "filters": {
                "paths": ["data/app.sqlite", "data/table.csv", "data/app.sqlite"],
                "path_prefixes": ["data"],
                "kinds": ["regular_file"],
                "lifecycles": ["live"],
                "minimum_bytes": 10,
                "maximum_bytes": 20
            },
            "page": {"limit": 100}
        })))
        .expect("filtered query");
    assert_eq!(
        filtered
            .entries()
            .iter()
            .map(|entry| entry.path())
            .collect::<Vec<_>>(),
        vec!["data/app.sqlite"]
    );

    let prefix = engine
        .run(&request(serde_json::json!({
            "format": "folderbase-query-request-v1",
            "scope": {"kind": "live"},
            "filters": {"path_prefixes": ["data"]},
            "page": {"limit": 100}
        })))
        .expect("prefix query");
    assert_eq!(
        prefix
            .entries()
            .iter()
            .map(|entry| entry.path())
            .collect::<Vec<_>>(),
        vec!["data", "data/app.sqlite", "data/table.csv"]
    );

    let collision = engine
        .run(&request(serde_json::json!({
            "format": "folderbase-query-request-v1",
            "scope": {"kind": "live"},
            "filters": {"paths": ["Notes.md", "notes.md"]},
            "page": {"limit": 10}
        })))
        .expect_err("full-fold collision");
    assert!(matches!(collision, QueryError::InvalidQueryRequest(_)));
}

fn live_page(limit: usize, cursor: Option<&str>) -> QueryRequest {
    request(serde_json::json!({
        "format": "folderbase-query-request-v1",
        "scope": {"kind": "live"},
        "page": {
            "limit": limit,
            "cursor": cursor
        }
    }))
}

#[test]
fn opaque_cursors_are_snapshot_safe_and_bound_to_root_request_and_sort_key() {
    let root = folderbase();
    for name in ["a.md", "b.md", "c.md"] {
        fs::write(root.path().join(name), format!("{name}\n")).expect("query row");
    }
    let engine = FolderbaseQueryEngine::open(root.path()).expect("query engine");

    let mut paths = Vec::new();
    let mut cursor = None;
    loop {
        let page = engine
            .run(&live_page(1, cursor.as_deref()))
            .expect("stable continuation");
        paths.extend(page.entries().iter().map(|entry| entry.path().to_owned()));
        cursor = page.page().next_cursor().map(str::to_owned);
        if cursor.is_none() {
            break;
        }
    }
    assert_eq!(paths, ["a.md", "b.md", "c.md"]);

    let first = engine.run(&live_page(1, None)).expect("first page");
    let cursor = first.page().next_cursor().expect("continuation cursor");
    fs::write(root.path().join("b.md"), b"changed\n").expect("bound metadata mutation");
    let changed = engine
        .run(&live_page(1, Some(cursor)))
        .expect_err("snapshot changed");
    assert!(matches!(changed, QueryError::QuerySnapshotChanged));

    let other = folderbase();
    fs::write(other.path().join("a.md"), b"a.md\n").expect("other root row");
    let other_engine = FolderbaseQueryEngine::open(other.path()).expect("other query engine");
    let cross_root = other_engine
        .run(&live_page(1, Some(cursor)))
        .expect_err("cursor is root-bound");
    assert!(matches!(cross_root, QueryError::InvalidQueryCursor));

    let cross_request = engine
        .run(&request(serde_json::json!({
            "format": "folderbase-query-request-v1",
            "scope": {"kind": "live"},
            "filters": {"paths": ["a.md"]},
            "page": {"limit": 1, "cursor": cursor}
        })))
        .expect_err("cursor is request-bound");
    assert!(matches!(cross_request, QueryError::InvalidQueryCursor));

    let malformed = engine
        .run(&live_page(1, Some("fbq1_not-a-cursor")))
        .expect_err("malformed cursor");
    assert!(matches!(malformed, QueryError::InvalidQueryCursor));
}

#[test]
fn normalized_request_digest_matches_the_independent_fixed_vectors() {
    let root = folderbase();
    let engine = FolderbaseQueryEngine::open(root.path()).expect("query engine");
    let fixtures = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../protocol/conformance/capabilities/query-index-0.1/fixtures/requests/valid"
    );
    for stem in ["canonical-request", "canonical-unicode-request"] {
        let encoded = fs::read(format!("{fixtures}/{stem}.json")).expect("request vector");
        let request = serde_json::from_slice(&encoded).expect("typed request vector");
        let expected =
            fs::read_to_string(format!("{fixtures}/{stem}.sha256")).expect("digest vector");
        assert_eq!(
            engine
                .run(&request)
                .expect("query with fixed request")
                .request_sha256(),
            expected.trim(),
            "{stem}"
        );
    }
}

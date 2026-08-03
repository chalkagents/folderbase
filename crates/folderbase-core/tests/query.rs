use std::{collections::BTreeMap, fs, path::Path};

use folderbase_core::{
    FolderbaseQueryEngine, FolderbaseVersionStore, QueryEntryKind, QueryError, QueryExecution,
    QueryIndexState, QueryLifecycle, QueryRequest, QuerySource,
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

fn initialize_folderbase(root: &Path) {
    fs::create_dir_all(root.join(".folderbase")).expect("state directory");
    fs::write(root.join(".folderbase/manifest.json"), MANIFEST).expect("manifest");
}

fn request(value: serde_json::Value) -> QueryRequest {
    serde_json::from_value(value).expect("query request shape")
}

#[test]
fn an_open_engine_never_crosses_into_a_replacement_root() {
    let owner = tempdir().expect("root owner");
    let root = owner.path().join("workspace");
    initialize_folderbase(&root);
    fs::write(root.join("original.md"), b"original\n").expect("original row");
    let engine = FolderbaseQueryEngine::open(&root).expect("query engine");

    fs::rename(&root, owner.path().join("detached-original")).expect("replace opened root");
    initialize_folderbase(&root);
    fs::write(root.join("replacement.md"), b"replacement\n").expect("replacement row");

    let historical = request(serde_json::json!({
        "format": "folderbase-query-request-v1",
        "scope": {
            "kind": "historical",
            "folderbase_version_id": "fbversion_019f0000-0000-7000-8000-000000000099"
        },
        "page": {"limit": 10}
    }));
    for result in [
        engine.run(&QueryRequest::live(10)).map(|_| ()),
        engine.run(&historical).map(|_| ()),
        engine.explain(&QueryRequest::live(10)).map(|_| ()),
        engine.index_status().map(|_| ()),
        engine.rebuild_index().map(|_| ()),
    ] {
        assert!(matches!(result, Err(QueryError::RootAuthorityChanged)));
    }
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
fn query_and_explain_cap_exclusions_in_deterministic_path_order() {
    let root = folderbase();
    let manifest = String::from_utf8_lossy(MANIFEST)
        .replace(r#""rules": ["ignored/"]"#, r#""rules": ["ignored-*.txt"]"#);
    fs::write(root.path().join(".folderbase/manifest.json"), manifest)
        .expect("large-ignore manifest");
    for index in 0..1_005 {
        fs::write(
            root.path().join(format!("ignored-{index:04}.txt")),
            b"ignored\n",
        )
        .expect("ignored fixture");
    }
    let engine = FolderbaseQueryEngine::open(root.path()).expect("query engine");

    let result = engine
        .run(&QueryRequest::live(1_000))
        .expect("bounded exclusions");
    assert_eq!(result.exclusions().len(), 1_000);
    assert!(result.exclusions_truncated());
    assert_eq!(result.exclusions()[0].path(), "ignored-0000.txt");
    assert_eq!(result.exclusions()[999].path(), "ignored-0999.txt");

    let explain = engine
        .explain(&QueryRequest::live(1_000))
        .expect("bounded explain exclusions");
    assert_eq!(explain.excluded().len(), 1_000);
    assert!(explain.excluded_truncated());
    assert_eq!(explain.excluded()[0].path(), "ignored-0000.txt");
    assert_eq!(explain.excluded()[999].path(), "ignored-0999.txt");
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
fn historical_scope_classifies_missing_ancestors_without_weakening_invalid_records() {
    const REQUESTED: &str = "fbversion_019f0000-0000-7000-8000-000000000099";
    let historical = |version_id: &str| {
        request(serde_json::json!({
            "format": "folderbase-query-request-v1",
            "scope": {"kind": "historical", "folderbase_version_id": version_id},
            "page": {"limit": 10}
        }))
    };

    let missing_root = folderbase();
    let missing_engine =
        FolderbaseQueryEngine::open(missing_root.path()).expect("missing query engine");
    assert!(matches!(
        missing_engine.run(&historical(REQUESTED)),
        Err(QueryError::ScopeVersionMissing { .. })
    ));

    let unsafe_root = folderbase();
    fs::write(
        unsafe_root.path().join(".folderbase/versions"),
        b"not a directory\n",
    )
    .expect("unsafe Version ancestor");
    let unsafe_engine =
        FolderbaseQueryEngine::open(unsafe_root.path()).expect("unsafe query engine");
    assert!(matches!(
        unsafe_engine.run(&historical(REQUESTED)),
        Err(QueryError::ScopeVersionInvalid { .. })
    ));

    #[cfg(unix)]
    {
        let alias_root = folderbase();
        fs::create_dir(alias_root.path().join(".folderbase/versions")).expect("Version parent");
        let outside = tempdir().expect("outside Version store");
        std::os::unix::fs::symlink(
            outside.path(),
            alias_root.path().join(".folderbase/versions/folderbase"),
        )
        .expect("unsafe Version alias");
        let alias_engine =
            FolderbaseQueryEngine::open(alias_root.path()).expect("alias query engine");
        assert!(matches!(
            alias_engine.run(&historical(REQUESTED)),
            Err(QueryError::ScopeVersionInvalid { .. })
        ));
    }

    let malformed = missing_engine
        .run(&historical("not-a-version-id"))
        .expect_err("malformed Version ID");
    assert!(matches!(malformed, QueryError::InvalidQueryRequest(_)));

    const FIXTURE_ID: &str = "fbversion_019f0000-0000-7000-8000-000000000001";
    let invalid_root = folderbase();
    fs::write(
        invalid_root.path().join(".folderbase/manifest.json"),
        String::from_utf8_lossy(MANIFEST).replace(
            "folderbase_019f9b75-4f42-7f65-a012-2bfecdd8c473",
            "folderbase_018f43c2-9a1b-7def-8123-456789abcdef",
        ),
    )
    .expect("fixture Folderbase identity");
    let versions = invalid_root.path().join(".folderbase/versions/folderbase");
    fs::create_dir_all(&versions).expect("Version namespace");
    let fixture = fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../protocol/conformance/capabilities/query-index-0.1/fixtures/historical-version.json"
    ))
    .expect("historical fixture");
    fs::write(versions.join(format!("{REQUESTED}.json")), &fixture)
        .expect("identity-mismatched Version");
    let invalid_engine =
        FolderbaseQueryEngine::open(invalid_root.path()).expect("invalid query engine");
    assert!(matches!(
        invalid_engine.run(&historical(REQUESTED)),
        Err(QueryError::ScopeVersionInvalid { .. })
    ));

    let mut schema_invalid: serde_json::Value =
        serde_json::from_slice(&fixture).expect("fixture JSON");
    schema_invalid["future_field"] = serde_json::json!(true);
    fs::write(
        versions.join(format!("{FIXTURE_ID}.json")),
        serde_json::to_vec(&schema_invalid).unwrap(),
    )
    .expect("schema-invalid Version");
    assert!(matches!(
        invalid_engine.run(&historical(FIXTURE_ID)),
        Err(QueryError::ScopeVersionInvalid { .. })
    ));

    let mut semantic_invalid: serde_json::Value =
        serde_json::from_slice(&fixture).expect("fixture JSON");
    semantic_invalid["parents"] = serde_json::json!([FIXTURE_ID]);
    fs::write(
        versions.join(format!("{FIXTURE_ID}.json")),
        serde_json::to_vec(&semantic_invalid).unwrap(),
    )
    .expect("semantic-invalid Version");
    assert!(matches!(
        invalid_engine.run(&historical(FIXTURE_ID)),
        Err(QueryError::ScopeVersionInvalid { .. })
    ));
}

#[test]
fn historical_recreation_rows_page_by_a_total_row_key() {
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
    let fixture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../protocol/conformance/capabilities/query-index-0.1/fixtures/historical-version.json"
    );
    fs::copy(fixture, versions.join(format!("{VERSION_ID}.json")))
        .expect("historical recreation fixture");
    let engine = FolderbaseQueryEngine::open(root.path()).expect("query engine");

    let make_request = |cursor: Option<&str>| {
        request(serde_json::json!({
            "format": "folderbase-query-request-v1",
            "scope": {"kind": "historical", "folderbase_version_id": VERSION_ID},
            "filters": {"paths": ["data/table.csv"]},
            "page": {"limit": 1, "cursor": cursor}
        }))
    };
    let first = engine
        .run(&make_request(None))
        .expect("first recreation row");
    let cursor = first.page().next_cursor().expect("same-path continuation");
    let second = engine
        .run(&make_request(Some(cursor)))
        .expect("second recreation row");

    assert_eq!(first.entries()[0].path(), "data/table.csv");
    assert_eq!(second.entries()[0].path(), "data/table.csv");
    assert_eq!(first.entries()[0].lifecycle(), QueryLifecycle::Live);
    assert_eq!(second.entries()[0].lifecycle(), QueryLifecycle::Deleted);
    assert!(!second.page().has_more());
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

fn sealed_cursor_fixture() -> (TempDir, FolderbaseQueryEngine, String, String) {
    let root = folderbase();
    for name in ["a.md", "b.md"] {
        fs::write(root.path().join(name), format!("{name}\n")).expect("query row");
    }
    let store = FolderbaseVersionStore::open(root.path()).expect("version store");
    let sealed = store
        .seal_capture(store.plan_capture().expect("capture plan"))
        .expect("sealed identity source");
    let version_id = sealed.version_id().to_owned();
    let engine = FolderbaseQueryEngine::open(root.path()).expect("query engine");
    let cursor = engine
        .run(&live_page(1, None))
        .expect("first page")
        .page()
        .next_cursor()
        .expect("continuation cursor")
        .to_owned();
    (root, engine, cursor, version_id)
}

#[test]
fn live_cursors_bind_protocol_metadata_local_head_bytes_and_identity_projection() {
    let (root, engine, cursor, _) = sealed_cursor_fixture();
    let manifest = root.path().join(".folderbase/manifest.json");
    let replacement = root.path().join(".folderbase/manifest.replacement");
    fs::write(&replacement, fs::read(&manifest).expect("manifest bytes"))
        .expect("replacement manifest");
    fs::rename(replacement, manifest).expect("change manifest metadata only");
    assert!(matches!(
        engine.run(&live_page(1, Some(&cursor))),
        Err(QueryError::QuerySnapshotChanged)
    ));

    let (root, engine, cursor, _) = sealed_cursor_fixture();
    let head = root.path().join(".folderbase/local/head.json");
    let decoded: serde_json::Value =
        serde_json::from_slice(&fs::read(&head).expect("Local Head bytes"))
            .expect("Local Head JSON");
    fs::write(
        &head,
        serde_json::to_vec_pretty(&decoded).expect("alternate exact encoding"),
    )
    .expect("rewrite equivalent Local Head");
    assert!(matches!(
        engine.run(&live_page(1, Some(&cursor))),
        Err(QueryError::QuerySnapshotChanged)
    ));

    let (root, engine, cursor, version_id) = sealed_cursor_fixture();
    fs::remove_file(
        root.path()
            .join(".folderbase/versions/folderbase")
            .join(format!("{version_id}.json")),
    )
    .expect("remove resolved identity source");
    assert!(matches!(
        engine.run(&live_page(1, Some(&cursor))),
        Err(QueryError::QuerySnapshotChanged)
    ));
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

#[test]
fn disposable_index_is_explicit_bounded_and_never_required_for_correctness() {
    let root = folderbase();
    fs::create_dir_all(root.path().join(".folderbase/local/other-engine")).expect("sibling state");
    fs::write(
        root.path()
            .join(".folderbase/local/other-engine/sentinel.txt"),
        b"preserve me\n",
    )
    .expect("sibling sentinel");
    for name in ["a.md", "b.md"] {
        fs::write(root.path().join(name), format!("{name}\n")).expect("query row");
    }
    let engine = FolderbaseQueryEngine::open(root.path()).expect("query engine");
    let index_root = root.path().join(".folderbase/local/query-index-v1");

    let absent = engine.index_status().expect("read-only absent status");
    assert_eq!(absent.state(), QueryIndexState::Absent);
    assert!(!index_root.exists(), "status must not create private state");

    let scan = engine.run(&live_page(100, None)).expect("fallback scan");
    assert_eq!(scan.execution(), QueryExecution::BoundedScan);
    let expected = scan
        .entries()
        .iter()
        .map(|entry| entry.path().to_owned())
        .collect::<Vec<_>>();

    let rebuilt = engine.rebuild_index().expect("explicit rebuild");
    assert_eq!(rebuilt.storage_path(), ".folderbase/local/query-index-v1");
    assert!(!rebuilt.ordinary_files_changed());
    assert!(!rebuilt.portable_files_changed());
    assert_eq!(
        engine.index_status().expect("fresh status").state(),
        QueryIndexState::Fresh
    );
    assert_eq!(
        fs::read(
            root.path()
                .join(".folderbase/local/other-engine/sentinel.txt")
        )
        .unwrap(),
        b"preserve me\n"
    );

    let reopened = FolderbaseQueryEngine::open(root.path()).expect("restart query engine");
    let indexed = reopened
        .run(&live_page(100, None))
        .expect("fresh private index");
    assert_eq!(indexed.execution(), QueryExecution::PrivateIndex);
    assert_eq!(
        indexed
            .entries()
            .iter()
            .map(|entry| entry.path().to_owned())
            .collect::<Vec<_>>(),
        expected
    );
    let explained = reopened
        .explain(&live_page(100, None))
        .expect("query explanation");
    assert_eq!(explained.scope_source(), QuerySource::CapturePlan);
    assert_eq!(explained.index_strategy(), QueryExecution::PrivateIndex);
    assert_eq!(explained.ordering(), "query_row_key_v1");
    assert_eq!(explained.ordinary_content_access(), "metadata_only");

    fs::write(root.path().join("c.md"), b"c.md\n").expect("stale observation");
    assert_eq!(
        reopened.index_status().expect("stale status").state(),
        QueryIndexState::Stale
    );
    assert_eq!(
        reopened
            .run(&live_page(100, None))
            .expect("stale fallback")
            .execution(),
        QueryExecution::BoundedScan
    );

    reopened.rebuild_index().expect("refresh stale index");
    fs::write(index_root.join("index.json"), b"{corrupt").expect("corrupt index");
    assert_eq!(
        reopened.index_status().expect("corrupt status").state(),
        QueryIndexState::Stale
    );
    assert_eq!(
        reopened
            .run(&live_page(100, None))
            .expect("corrupt fallback")
            .execution(),
        QueryExecution::BoundedScan
    );
    reopened.rebuild_index().expect("recover corrupt index");

    let oversized = fs::File::create(index_root.join("index.json")).expect("oversize index");
    oversized
        .set_len(64 * 1024 * 1024 + 1)
        .expect("bounded oversize");
    drop(oversized);
    assert_eq!(
        reopened.index_status().expect("oversize status").state(),
        QueryIndexState::Stale
    );
    assert_eq!(
        reopened
            .run(&live_page(100, None))
            .expect("oversize fallback")
            .execution(),
        QueryExecution::BoundedScan
    );
    reopened.rebuild_index().expect("recover oversized index");

    fs::remove_dir_all(&index_root).expect("delete disposable index");
    let deleted = reopened
        .run(&live_page(100, None))
        .expect("deleted fallback");
    assert_eq!(deleted.execution(), QueryExecution::BoundedScan);
    assert_eq!(
        deleted
            .entries()
            .iter()
            .map(|entry| entry.path().to_owned())
            .collect::<Vec<_>>(),
        ["a.md", "b.md", "c.md"]
    );
}

#[test]
fn rebuild_sanitizes_the_complete_private_index_namespace_without_following_links() {
    let root = folderbase();
    fs::write(root.path().join("a.md"), b"a\n").expect("query row");
    fs::create_dir_all(root.path().join(".folderbase/local/other-engine"))
        .expect("sibling private state");
    fs::write(
        root.path()
            .join(".folderbase/local/other-engine/sentinel.txt"),
        b"preserve sibling\n",
    )
    .expect("sibling sentinel");
    let engine = FolderbaseQueryEngine::open(root.path()).expect("query engine");
    engine.rebuild_index().expect("initial index");
    let index_root = root.path().join(".folderbase/local/query-index-v1");

    let oversized =
        fs::File::create(index_root.join("oversized-junk.bin")).expect("oversized namespace child");
    oversized
        .set_len(64 * 1024 * 1024 + 1)
        .expect("sparse oversized junk");
    drop(oversized);
    fs::create_dir_all(index_root.join("orphan/nested")).expect("crash directories");
    fs::write(
        index_root.join("orphan/nested/.replace-crash.tmp"),
        b"partial\n",
    )
    .expect("nested crash leftover");
    fs::write(index_root.join(".replace-orphan.tmp"), b"partial\n").expect("orphan replacement");

    let outside = tempdir().expect("outside target");
    fs::write(outside.path().join("sentinel"), b"outside\n").expect("outside sentinel");
    #[cfg(unix)]
    std::os::unix::fs::symlink(outside.path(), index_root.join("hostile-link"))
        .expect("hostile namespace symlink");

    for round in 0..2 {
        engine.rebuild_index().expect("bounded namespace recovery");
        let names = fs::read_dir(&index_root)
            .expect("rebuilt namespace")
            .map(|entry| entry.expect("namespace entry").file_name())
            .collect::<Vec<_>>();
        assert_eq!(names, [std::ffi::OsString::from("index.json")]);
        assert_eq!(
            fs::read(
                root.path()
                    .join(".folderbase/local/other-engine/sentinel.txt")
            )
            .unwrap(),
            b"preserve sibling\n"
        );
        assert_eq!(
            fs::read(outside.path().join("sentinel")).unwrap(),
            b"outside\n"
        );
        if round == 0 {
            fs::write(index_root.join(".replace-interrupted.tmp"), b"partial\n")
                .expect("repeated interrupted replacement");
        }
    }
}

#[cfg(unix)]
#[test]
fn index_symlink_is_never_followed_and_explicit_rebuild_recovers_it() {
    let root = folderbase();
    fs::write(root.path().join("a.md"), b"a\n").expect("query row");
    fs::create_dir_all(root.path().join(".folderbase/local")).expect("local state");
    let outside = tempdir().expect("outside target");
    fs::write(outside.path().join("sentinel"), b"outside\n").expect("outside sentinel");
    std::os::unix::fs::symlink(
        outside.path(),
        root.path().join(".folderbase/local/query-index-v1"),
    )
    .expect("hostile index symlink");
    let engine = FolderbaseQueryEngine::open(root.path()).expect("query engine");

    assert_eq!(
        engine.index_status().expect("symlink status").state(),
        QueryIndexState::Stale
    );
    assert_eq!(
        engine
            .run(&live_page(10, None))
            .expect("symlink fallback")
            .execution(),
        QueryExecution::BoundedScan
    );
    engine.rebuild_index().expect("replace exact index symlink");
    assert!(
        fs::symlink_metadata(root.path().join(".folderbase/local/query-index-v1"))
            .expect("rebuilt index root")
            .is_dir()
    );
    assert_eq!(
        fs::read(outside.path().join("sentinel")).unwrap(),
        b"outside\n"
    );
}

fn tree_snapshot_without_index(root: &Path) -> BTreeMap<String, (String, Vec<u8>)> {
    let mut snapshot = BTreeMap::new();
    for entry in walkdir::WalkDir::new(root).follow_links(false) {
        let entry = entry.expect("snapshot entry");
        let relative = entry.path().strip_prefix(root).expect("relative path");
        if relative.as_os_str().is_empty() {
            continue;
        }
        let portable = relative.to_string_lossy().replace('\\', "/");
        if portable == ".folderbase/local/query-index-v1"
            || portable.starts_with(".folderbase/local/query-index-v1/")
        {
            continue;
        }
        let metadata = fs::symlink_metadata(entry.path()).expect("snapshot metadata");
        let record = if metadata.file_type().is_symlink() {
            (
                "symlink".to_owned(),
                fs::read_link(entry.path())
                    .expect("symlink target")
                    .to_string_lossy()
                    .as_bytes()
                    .to_vec(),
            )
        } else if metadata.is_file() {
            (
                "file".to_owned(),
                fs::read(entry.path()).expect("snapshot bytes"),
            )
        } else {
            ("directory".to_owned(), Vec::new())
        };
        snapshot.insert(portable, record);
    }
    snapshot
}

#[test]
fn repeated_rebuild_and_read_only_operations_are_whole_tree_confined() {
    let root = folderbase();
    fs::create_dir_all(root.path().join(".folderbase/local")).expect("existing local parent");
    fs::create_dir_all(root.path().join("ignored/private")).expect("ignored tree");
    fs::write(root.path().join("ignored/private/secret.txt"), b"ignored\n").expect("ignored bytes");
    fs::create_dir_all(root.path().join("nested/.folderbase")).expect("nested state");
    fs::write(
        root.path().join("nested/.folderbase/manifest.json"),
        b"opaque nested bytes\n",
    )
    .expect("nested marker");
    fs::write(root.path().join("nested/private.bin"), b"nested bytes\n").expect("nested bytes");
    fs::write(root.path().join("ordinary.md"), b"ordinary bytes\n").expect("ordinary bytes");
    let engine = FolderbaseQueryEngine::open(root.path()).expect("query engine");
    let before = tree_snapshot_without_index(root.path());

    engine.run(&live_page(100, None)).expect("scan");
    engine.explain(&live_page(100, None)).expect("explain");
    engine.index_status().expect("status");
    assert_eq!(tree_snapshot_without_index(root.path()), before);

    engine.rebuild_index().expect("first rebuild");
    assert_eq!(tree_snapshot_without_index(root.path()), before);
    let index_path = root
        .path()
        .join(".folderbase/local/query-index-v1/index.json");
    let first_index = fs::read(&index_path).expect("first index bytes");
    let first_metadata = fs::metadata(&index_path).expect("first index metadata");

    engine.run(&live_page(100, None)).expect("indexed run");
    engine
        .explain(&live_page(100, None))
        .expect("indexed explain");
    engine.index_status().expect("indexed status");
    assert_eq!(fs::read(&index_path).unwrap(), first_index);
    assert_eq!(
        fs::metadata(&index_path).unwrap().modified().unwrap(),
        first_metadata.modified().unwrap()
    );
    assert_eq!(tree_snapshot_without_index(root.path()), before);

    engine
        .rebuild_index()
        .expect("deterministic repeated rebuild");
    assert_eq!(fs::read(&index_path).unwrap(), first_index);
    assert_eq!(tree_snapshot_without_index(root.path()), before);

    let indexed_paths = engine
        .run(&live_page(100, None))
        .expect("indexed query")
        .entries()
        .iter()
        .map(|entry| entry.path().to_owned())
        .collect::<Vec<_>>();
    fs::remove_dir_all(root.path().join(".folderbase/local/query-index-v1"))
        .expect("delete disposable state");
    let scanned_paths = engine
        .run(&live_page(100, None))
        .expect("fallback query")
        .entries()
        .iter()
        .map(|entry| entry.path().to_owned())
        .collect::<Vec<_>>();
    assert_eq!(scanned_paths, indexed_paths);
    assert_eq!(tree_snapshot_without_index(root.path()), before);
}

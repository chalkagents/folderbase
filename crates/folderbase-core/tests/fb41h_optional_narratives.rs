use std::{fs, io::Cursor, path::Path};

use folderbase_core::{
    ChunkTransferProfile, FolderbaseKind, FolderbaseVersionStore, InitializationOptions,
    LocalVersionStore, ValidationLevel, attest_folderbase_root, initialize, plan_initialization,
    validate,
};
use serde_json::Value;
use tempfile::{TempDir, tempdir};

const LEGACY_FOLDERBASE_ID: &str = "folderbase_019f9b75-4f42-7f65-a012-2bfecdd8c475";
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

fn ordinary_options() -> InitializationOptions {
    InitializationOptions {
        name: Some("Ordinary files".to_owned()),
        kind: FolderbaseKind::Project,
        create_agent_adapters: false,
    }
}

fn planned_paths(plan: &folderbase_core::CapturePlan) -> Vec<&str> {
    plan.entries().iter().map(|entry| entry.path()).collect()
}

fn initialize_ordinary(root: &Path) {
    let plan = plan_initialization(root, ordinary_options()).expect("ordinary-folder plan");
    assert!(
        plan.writes()
            .iter()
            .all(|write| write.path().starts_with(".folderbase")),
        "ordinary initialization writes only engine-managed .folderbase state"
    );
    initialize(&plan).expect("ordinary-folder initialization");
}

fn legacy_folderbase() -> TempDir {
    let root = tempdir().expect("legacy Folderbase");
    fs::create_dir(root.path().join(".folderbase")).expect("legacy state directory");
    fs::write(
        root.path().join(".folderbase/manifest.json"),
        LEGACY_MANIFEST,
    )
    .expect("legacy manifest");
    fs::write(root.path().join(".folderbaseignore"), b"node_modules/\n").expect("legacy ignore");
    fs::write(root.path().join("FOLDERBASE.md"), b"# Legacy Folderbase\n").expect("legacy entry");
    root
}

#[test]
fn ordinary_mixed_folder_runs_the_full_local_lifecycle_without_root_narrative_files() {
    let root = tempdir().expect("ordinary folder");
    let original_files = [
        ("brief.docx", b"PK\x03\x04opaque-docx".as_slice()),
        ("reference.pdf", b"%PDF opaque".as_slice()),
        ("movie.mov", b"opaque-video".as_slice()),
        ("data.csv", b"a,b\n1,2\n".as_slice()),
        ("database.sqlite", b"SQLite format 3\0opaque".as_slice()),
        (".git/objects/pack/test.pack", b"opaque-git-pack".as_slice()),
    ];
    for (path, bytes) in original_files {
        let path = root.path().join(path);
        fs::create_dir_all(path.parent().expect("file parent")).expect("parent");
        fs::write(path, bytes).expect("ordinary bytes");
    }

    initialize_ordinary(root.path());

    assert!(!root.path().join("FOLDERBASE.md").exists());
    assert!(!root.path().join(".folderbaseignore").exists());
    assert!(
        validate(root.path(), ValidationLevel::Shallow)
            .expect("validation report")
            .valid
    );
    let attestation = attest_folderbase_root(root.path()).expect("attested ordinary root");
    assert_eq!(attestation.protocol_version, "0.5.0");

    let store = FolderbaseVersionStore::open(root.path()).expect("open ordinary Folderbase");
    let plan = store.plan_capture().expect("metadata-first capture plan");
    let planned = plan
        .entries()
        .iter()
        .map(|entry| entry.path())
        .collect::<Vec<_>>();
    for expected in [
        "brief.docx",
        "reference.pdf",
        "movie.mov",
        "data.csv",
        "database.sqlite",
        ".git/objects/pack/test.pack",
    ] {
        assert!(planned.contains(&expected), "{expected} remains ordinary");
    }

    let genesis = store.seal_capture(plan).expect("seal genesis");
    let encoded_version = fs::read(
        root.path()
            .join(".folderbase/versions/folderbase")
            .join(format!("{}.json", genesis.version_id())),
    )
    .expect("durable Folderbase Version");
    let wire: Value = serde_json::from_slice(&encoded_version).expect("version JSON");
    assert_eq!(wire["format"], "folderbase-version-v1");
    assert_eq!(wire["protocol_version"], "0.5");
    assert!(
        wire["bindings"]
            .as_array()
            .expect("bindings")
            .iter()
            .all(|binding| binding["path"] != "FOLDERBASE.md"
                && binding["path"] != ".folderbaseignore")
    );

    let version = store
        .read_version(genesis.version_id())
        .expect("read v0.5 version");
    let movie = version.lookup_binding("movie.mov").expect("movie binding");
    let movie_object_version = movie.object_version_id().expect("movie Object Version");
    let local = LocalVersionStore::open(root.path()).expect("local version store");
    let mut source = local
        .open_chunk_transfer(
            &folderbase_core::VersionId::parse(movie_object_version).expect("version id"),
            ChunkTransferProfile::StandardV1,
        )
        .expect("open immutable transfer");
    let expected_manifest = source.manifest_digest().to_owned();
    let mut transferred = Vec::new();
    for index in 0..source.manifest().chunks.len() as u32 {
        source
            .copy_chunk(index, &mut transferred)
            .expect("verified chunk");
    }
    assert_eq!(transferred, b"opaque-video");
    local
        .reopen_chunk_transfer(
            &folderbase_core::VersionId::parse(movie_object_version).expect("version id"),
            ChunkTransferProfile::StandardV1,
            &expected_manifest,
        )
        .expect("reopen exact transfer");

    let exact_docx = fs::read(root.path().join("brief.docx")).expect("docx before deletion");
    fs::remove_file(root.path().join("brief.docx")).expect("delete docx");
    let deletion = store
        .seal_capture(store.plan_capture().expect("deletion plan"))
        .expect("seal tombstone");
    assert!(
        store
            .read_version(deletion.version_id())
            .expect("tombstone version")
            .tombstones()
            .iter()
            .any(|tombstone| tombstone.path() == "brief.docx")
    );
    store
        .restore_tombstone("brief.docx")
        .expect("restore exact ordinary file");
    assert_eq!(
        fs::read(root.path().join("brief.docx")).expect("restored docx"),
        exact_docx
    );
    for (path, bytes) in original_files
        .into_iter()
        .filter(|(path, _)| *path != "brief.docx")
    {
        assert_eq!(
            fs::read(root.path().join(path)).expect("untouched ordinary bytes"),
            bytes,
            "{path} remains byte-exact"
        );
    }
}

#[test]
fn optional_root_files_are_preserved_and_captured_as_ordinary_user_content() {
    let root = tempdir().expect("ordinary folder");
    let entry = b"\xff\x00not markdown";
    let ignore = b"*.tmp\n";
    fs::write(root.path().join("FOLDERBASE.md"), entry).expect("user entry");
    fs::write(root.path().join(".folderbaseignore"), ignore).expect("user ignore");

    let plan = plan_initialization(root.path(), ordinary_options()).expect("plan");
    assert!(
        plan.writes().iter().all(|write| {
            write.path() != Path::new("FOLDERBASE.md")
                && write.path() != Path::new(".folderbaseignore")
        }),
        "initialization never owns the optional root files"
    );
    initialize(&plan).expect("initialize");
    assert_eq!(fs::read(root.path().join("FOLDERBASE.md")).unwrap(), entry);
    assert_eq!(
        fs::read(root.path().join(".folderbaseignore")).unwrap(),
        ignore
    );
    assert!(
        validate(root.path(), ValidationLevel::Shallow)
            .expect("validate")
            .valid,
        "invalid Markdown is still valid ordinary content"
    );

    let store = FolderbaseVersionStore::open(root.path()).expect("open");
    let sealed = store
        .seal_capture(store.plan_capture().expect("plan capture"))
        .expect("seal");
    let version = store.read_version(sealed.version_id()).expect("version");
    for path in ["FOLDERBASE.md", ".folderbaseignore"] {
        assert!(
            version.lookup_binding(path).is_some(),
            "{path} is a normal captured Path Binding"
        );
    }
}

#[test]
fn only_an_exact_nested_manifest_establishes_a_boundary_and_inert_context_never_overwrites() {
    let root = tempdir().expect("parent folder");
    fs::create_dir_all(root.path().join("notes/.folderbase/questions")).expect("inert state shape");
    fs::write(
        root.path().join("notes/.folderbase/summary.md"),
        b"user-owned summary",
    )
    .expect("summary");
    fs::write(
        root.path().join("notes/.folderbase/questions/open.md"),
        b"user-owned question",
    )
    .expect("question");
    fs::write(root.path().join("notes/FOLDERBASE.md"), b"ordinary note").expect("ordinary entry");

    fs::create_dir_all(root.path().join("client/.folderbase/questions"))
        .expect("nested state shape");
    fs::write(
        root.path().join("client/.folderbase/manifest.json"),
        br#"{"protocol_version":"0.5.0","folderbase":{"id":"folderbase_019f9b75-4f42-7f65-a012-2bfecdd8c474"}}"#,
    )
    .expect("nested authority");
    fs::write(
        root.path().join("client/.folderbase/summary.md"),
        b"nested private summary",
    )
    .expect("nested summary");
    fs::write(
        root.path().join("client/private.pdf"),
        b"nested private bytes",
    )
    .expect("nested content");

    initialize_ordinary(root.path());

    assert_eq!(
        fs::read(root.path().join("notes/.folderbase/summary.md")).unwrap(),
        b"user-owned summary"
    );
    assert_eq!(
        fs::read(root.path().join("notes/.folderbase/questions/open.md")).unwrap(),
        b"user-owned question"
    );
    let plan = FolderbaseVersionStore::open(root.path())
        .expect("parent opens")
        .plan_capture()
        .expect("parent capture plan");
    assert!(
        !plan
            .exclusions()
            .iter()
            .any(|exclusion| exclusion.path() == "notes"),
        "summary/questions/FOLDERBASE.md alone grant no nested authority"
    );
    assert!(
        plan.exclusions()
            .iter()
            .any(|exclusion| exclusion.path() == "client"),
        "the exact nested manifest establishes the independent boundary"
    );
    assert!(
        plan.entries()
            .iter()
            .all(|entry| !entry.path().starts_with("client/")),
        "parent authority never crosses the nested boundary"
    );
}

#[test]
fn released_v04_fixture_and_root_keep_their_exact_protocol_semantics() {
    let fixture_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../protocol/conformance/folderbase-version/valid/minimal-restorable-v1.json");
    let fixture_bytes = fs::read(&fixture_path).expect("released v0.4 fixture");
    let released = folderbase_core::folderbase_version::FolderbaseVersion::decode_bounded(
        Cursor::new(&fixture_bytes),
    )
    .expect("released fixture still verifies");
    assert_eq!(
        released.canonical_digest().expect("released digest"),
        fs::read_to_string(fixture_path.with_extension("sha256"))
            .expect("independent released sidecar")
            .trim()
    );
    let mut missing_entry: Value = serde_json::from_slice(&fixture_bytes).expect("fixture JSON");
    missing_entry["bindings"]
        .as_array_mut()
        .expect("bindings")
        .retain(|binding| binding["path"] != "FOLDERBASE.md");
    assert!(
        folderbase_core::folderbase_version::FolderbaseVersion::decode_bounded(Cursor::new(
            serde_json::to_vec(&missing_entry).expect("changed fixture")
        ))
        .is_err(),
        "v0.4 is not silently reinterpreted with optional marker semantics"
    );

    let root = legacy_folderbase();
    fs::write(root.path().join("proposal.docx"), b"released bytes").expect("legacy content");
    let attested = attest_folderbase_root(root.path()).expect("released root still attests");
    assert_eq!(attested.folderbase_id, LEGACY_FOLDERBASE_ID);
    let store = FolderbaseVersionStore::open(root.path()).expect("released root opens");
    let genesis = store
        .seal_capture(store.plan_capture().expect("legacy genesis plan"))
        .expect("legacy genesis");
    let encoded = fs::read(
        root.path()
            .join(".folderbase/versions/folderbase")
            .join(format!("{}.json", genesis.version_id())),
    )
    .expect("legacy version");
    assert_eq!(
        serde_json::from_slice::<Value>(&encoded).unwrap()["protocol_version"],
        "0.4"
    );
    fs::remove_file(root.path().join("proposal.docx")).expect("legacy delete");
    store
        .seal_capture(store.plan_capture().expect("legacy deletion plan"))
        .expect("legacy tombstone");
    store
        .restore_tombstone("proposal.docx")
        .expect("legacy restore");
    assert_eq!(
        fs::read(root.path().join("proposal.docx")).expect("legacy restored bytes"),
        b"released bytes"
    );
}

#[test]
fn default_initialization_is_engine_state_only_and_agent_adapters_are_opt_in() {
    let root = tempdir().expect("ordinary folder");
    let options = InitializationOptions::default();
    assert!(
        !options.create_agent_adapters,
        "agent adapters are an explicit opt-in"
    );
    let plan = plan_initialization(root.path(), options).expect("default plan");
    assert!(
        plan.writes()
            .iter()
            .all(|write| write.path().starts_with(".folderbase"))
    );
    initialize(&plan).expect("default initialization");
    for path in [
        "FOLDERBASE.md",
        ".folderbaseignore",
        "AGENTS.md",
        "CLAUDE.md",
    ] {
        assert!(!root.path().join(path).exists(), "{path} is not implicit");
    }
}

#[test]
fn absent_and_empty_ignore_policies_are_distinct_stable_and_stale_in_both_directions() {
    let root = tempdir().expect("ordinary folder");
    initialize_ordinary(root.path());
    fs::write(root.path().join("FOLDERBASE.md"), b"ordinary narrative").expect("ordinary file");
    let store = FolderbaseVersionStore::open(root.path()).expect("open");

    let absent = store.plan_capture().expect("absent policy");
    let absent_digest = absent.ignore_policy_sha256().to_owned();
    assert!(planned_paths(&absent).contains(&"FOLDERBASE.md"));

    fs::write(root.path().join(".folderbaseignore"), b"").expect("empty policy");
    assert!(
        store.seal_capture(absent).is_err(),
        "an absent-policy plan is stale after an empty policy appears"
    );
    let empty = store.plan_capture().expect("empty policy");
    let empty_digest = empty.ignore_policy_sha256().to_owned();
    assert_ne!(
        absent_digest, empty_digest,
        "missing and present-empty are separately committed"
    );
    assert!(planned_paths(&empty).contains(&".folderbaseignore"));

    fs::remove_file(root.path().join(".folderbaseignore")).expect("remove policy");
    assert!(
        store.seal_capture(empty).is_err(),
        "a present-policy plan is stale after the policy disappears"
    );
    assert_eq!(
        store
            .plan_capture()
            .expect("absent policy again")
            .ignore_policy_sha256(),
        absent_digest,
        "absence has a stable domain-separated commitment"
    );

    fs::write(root.path().join(".folderbaseignore"), b"FOLDERBASE.md\n")
        .expect("policy that ignores ordinary narrative");
    let ignored = store.plan_capture().expect("present policy");
    assert!(planned_paths(&ignored).contains(&".folderbaseignore"));
    assert!(
        !planned_paths(&ignored).contains(&"FOLDERBASE.md"),
        "FOLDERBASE.md has no force-inclusion or authority privilege"
    );
}

#[test]
fn a_present_v05_ignore_policy_cannot_be_an_unsupported_hardlink() {
    let root = tempdir().expect("ordinary folder");
    fs::write(root.path().join("policy-source"), b"*.tmp\n").expect("policy source");
    fs::hard_link(
        root.path().join("policy-source"),
        root.path().join(".folderbaseignore"),
    )
    .expect("hard-linked active policy");
    initialize_ordinary(root.path());

    assert!(
        FolderbaseVersionStore::open(root.path())
            .expect("open")
            .plan_capture()
            .is_err(),
        "a controlling policy cannot be silently excluded from the captured state"
    );
}

#[test]
fn v05_has_a_separate_conformance_tree_while_the_released_v04_tree_stays_exact() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../protocol");
    let v05 =
        fs::read(root.join("conformance/folderbase-version-0.5/valid/minimal-ordinary-v1.json"))
            .expect("separate v0.5 fixture");
    let version =
        folderbase_core::folderbase_version::FolderbaseVersion::decode_bounded(Cursor::new(v05))
            .expect("valid v0.5 ordinary-folder version");
    assert!(version.lookup_binding("FOLDERBASE.md").is_none());
    assert!(version.lookup_binding(".folderbaseignore").is_none());

    let released_manifest: Value = serde_json::from_slice(
        &fs::read(root.join("releases/0.4/folderbase-version-v1.json"))
            .expect("released v0.4 inventory"),
    )
    .expect("v0.4 release manifest");
    assert_eq!(
        released_manifest["files"].as_array().expect("files").len(),
        32,
        "the released v0.4 fixture distribution remains frozen"
    );
    assert!(
        root.join("releases/0.5/folderbase-version-v1.json")
            .is_file(),
        "v0.5 has an independent release inventory"
    );
}

#[test]
fn v05_default_capture_exclusions_are_declared_engine_policy_not_a_hidden_root_file() {
    let root = tempdir().expect("ordinary folder");
    let plan = plan_initialization(root.path(), ordinary_options()).expect("initialization plan");
    let encoded_plan = serde_json::to_value(&plan).expect("serialized plan");
    let manifest = encoded_plan["writes"]
        .as_array()
        .expect("planned writes")
        .iter()
        .find(|write| write["path"] == ".folderbase/manifest.json")
        .expect("planned manifest");
    let manifest: Value =
        serde_json::from_str(manifest["content"].as_str().expect("manifest content"))
            .expect("manifest JSON");
    assert_eq!(
        manifest["policies"]["capture_ignore"]["format"],
        "folderbase-capture-ignore-v1"
    );
    let rules = manifest["policies"]["capture_ignore"]["rules"]
        .as_array()
        .expect("ordered engine rules");
    for required in [
        "node_modules/",
        ".next/",
        "dist/",
        "build/",
        "coverage/",
        ".venv/",
        "__pycache__/",
        ".dart_tool/",
        "Pods/",
    ] {
        assert!(
            rules.iter().any(|rule| rule == required),
            "{required} is declared by the portable root policy"
        );
    }

    initialize(&plan).expect("initialize");
    assert!(!root.path().join(".folderbaseignore").exists());
    for path in [
        "node_modules/pkg/index.js",
        ".next/cache/data.bin",
        "dist/app.js",
    ] {
        let path = root.path().join(path);
        fs::create_dir_all(path.parent().unwrap()).expect("generated parent");
        fs::write(path, b"reconstructable").expect("generated bytes");
    }
    fs::create_dir_all(root.path().join(".git/objects")).expect("Git parent");
    fs::write(root.path().join(".git/objects/object"), b"Git bytes").expect("Git bytes");
    fs::write(root.path().join("ordinary.pdf"), b"%PDF ordinary").expect("ordinary bytes");
    let capture = FolderbaseVersionStore::open(root.path())
        .expect("open")
        .plan_capture()
        .expect("capture plan");
    let paths = planned_paths(&capture);
    assert!(paths.contains(&".git/objects/object"));
    assert!(paths.contains(&"ordinary.pdf"));
    assert!(!paths.iter().any(|path| path.starts_with("node_modules/")));
    assert!(!paths.iter().any(|path| path.starts_with(".next/")));
    assert!(!paths.iter().any(|path| path.starts_with("dist/")));
}

#[test]
fn live_v05_admission_matches_required_shape_and_safe_adapter_paths() {
    for mutation in [
        ("missing name", serde_json::json!(null)),
        ("invalid availability", serde_json::json!("sometimes")),
        ("capture policy extension", serde_json::json!(true)),
        ("drive-relative adapter", serde_json::json!("C:AGENTS.md")),
        (
            "private-state adapter",
            serde_json::json!(".folderbase/AGENTS.md"),
        ),
        ("Git-internal adapter", serde_json::json!(".git/AGENTS.md")),
    ] {
        let root = tempdir().expect("ordinary root");
        initialize_ordinary(root.path());
        let path = root.path().join(".folderbase/manifest.json");
        let mut manifest: Value =
            serde_json::from_slice(&fs::read(&path).expect("manifest")).expect("manifest JSON");
        match mutation.0 {
            "missing name" => {
                manifest["folderbase"]
                    .as_object_mut()
                    .expect("folderbase")
                    .remove("name");
            }
            "invalid availability" => {
                manifest["policies"]["availability"] = mutation.1;
            }
            "capture policy extension" => {
                manifest["policies"]["capture_ignore"]["extension"] = mutation.1;
            }
            _ => {
                manifest["adapters"] = serde_json::json!([{
                    "agent": "codex",
                    "path": mutation.1
                }]);
            }
        }
        fs::write(
            &path,
            format!("{}\n", serde_json::to_string_pretty(&manifest).unwrap()),
        )
        .expect("mutated manifest");

        assert!(
            attest_folderbase_root(root.path()).is_err(),
            "{} is rejected by live admission",
            mutation.0
        );
        assert!(
            FolderbaseVersionStore::open(root.path()).is_err(),
            "{} cannot capture a Folderbase Version",
            mutation.0
        );
    }
}

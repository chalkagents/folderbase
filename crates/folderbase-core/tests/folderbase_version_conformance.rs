use std::{
    fs,
    io::{Cursor, Read},
    path::{Path, PathBuf},
};

use folderbase_core::folderbase_version::{
    FolderbaseVersion, FolderbaseVersionChange, MAX_ENCODED_VERSION_BYTES, MAX_PATH_BYTES,
    MAX_PATH_COMPONENT_BYTES, MAX_PATH_DEPTH, MAX_VERSION_ENTRIES, PathBindingKind,
};
use serde_json::Value;

const VERSION_SCHEMA: &str = "schemas/0.4/folderbase-version.schema.json";

trait AmbiguousIfDeserialize<A> {
    fn marker() {}
}

impl<T: ?Sized> AmbiguousIfDeserialize<()> for T {}

struct ImplementsDeserialize;

impl<T> AmbiguousIfDeserialize<ImplementsDeserialize> for T where T: for<'de> serde::Deserialize<'de>
{}

const _: fn() = || {
    let _ = <FolderbaseVersion as AmbiguousIfDeserialize<_>>::marker;
};

fn protocol_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../protocol")
}

fn decode_fixture(relative: &str) -> Result<FolderbaseVersion, String> {
    let path = protocol_root().join(relative);
    let encoded =
        fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    FolderbaseVersion::decode_bounded(Cursor::new(encoded)).map_err(|error| error.to_string())
}

fn decode_value(value: &Value) -> Result<FolderbaseVersion, String> {
    FolderbaseVersion::decode_bounded(Cursor::new(serde_json::to_vec(value).unwrap()))
        .map_err(|error| error.to_string())
}

fn directory_binding(path: String, suffix: usize) -> Value {
    serde_json::json!({
        "path": path,
        "object_id": format!("obj_0198ee40-b222-7bbb-8000-{suffix:012x}"),
        "lifecycle": "live",
        "kind": "directory"
    })
}

fn regular_file_binding(path: &str, object_suffix: usize, version_suffix: usize) -> Value {
    serde_json::json!({
        "path": path,
        "object_id": format!("obj_0198ee40-b222-7bbb-8000-{object_suffix:012x}"),
        "lifecycle": "live",
        "kind": "regular_file",
        "object_version_id": format!(
            "version_0198ee40-c333-7ccc-8000-{version_suffix:012x}"
        ),
        "content_sha256": format!("{version_suffix:064x}"),
        "bytes": version_suffix,
        "executable": false
    })
}

fn read_json(relative: &str) -> Value {
    let path = protocol_root().join(relative);
    serde_json::from_slice(
        &fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display())),
    )
    .unwrap_or_else(|error| panic!("parse {}: {error}", path.display()))
}

#[test]
fn bounded_decoder_accepts_the_minimal_restorable_public_version() {
    let version = decode_fixture("conformance/folderbase-version/valid/minimal-restorable-v1.json")
        .expect("valid v1");

    assert_eq!(
        version.version_id(),
        "fbversion_0198ee40-a111-7aaa-8000-000000000001"
    );
    assert_eq!(
        version.root_manifest().object_version_id(),
        "version_0198ee40-c333-7ccc-8000-000000000100"
    );
    assert_eq!(version.root_manifest().bytes(), 512);
    assert_eq!(version.binding_count(), 2);
    assert_eq!(
        version
            .lookup_binding(".folderbaseignore")
            .expect("required ignore policy")
            .kind(),
        PathBindingKind::RegularFile
    );
    assert_eq!(
        version
            .lookup_binding("FOLDERBASE.md")
            .expect("required agent entry")
            .kind(),
        PathBindingKind::RegularFile
    );
}

#[test]
fn public_schema_is_closed_draft_2020_12_and_accepts_the_minimal_vector() {
    let schema = read_json(VERSION_SCHEMA);
    let validator = jsonschema::draft202012::options()
        .should_validate_formats(true)
        .build(&schema)
        .expect("compile canonical Folderbase Version schema");

    assert_eq!(
        schema["$schema"],
        "https://json-schema.org/draft/2020-12/schema"
    );
    assert_eq!(schema["additionalProperties"], false);
    assert!(validator.is_valid(&read_json(
        "conformance/folderbase-version/valid/minimal-restorable-v1.json"
    )));
    assert!(validator.is_valid(&read_json(
        "conformance/folderbase-version/valid/fidelity-and-lifecycle-v1.json"
    )));
    assert_every_object_schema_is_closed(&schema, "$");
}

fn assert_every_object_schema_is_closed(value: &Value, location: &str) {
    match value {
        Value::Object(object) => {
            if object.get("type") == Some(&Value::String("object".to_owned())) {
                assert_eq!(
                    object.get("additionalProperties"),
                    Some(&Value::Bool(false)),
                    "object schema at {location} must be closed"
                );
            }
            for (key, child) in object {
                assert_every_object_schema_is_closed(child, &format!("{location}/{key}"));
            }
        }
        Value::Array(array) => {
            for (index, child) in array.iter().enumerate() {
                assert_every_object_schema_is_closed(child, &format!("{location}/{index}"));
            }
        }
        _ => {}
    }
}

#[test]
fn fidelity_vector_models_large_opaque_files_symlinks_empty_directories_and_deletions() {
    let version =
        decode_fixture("conformance/folderbase-version/valid/fidelity-and-lifecycle-v1.json")
            .expect("valid fidelity vector");

    assert_eq!(version.binding_count(), 8);
    assert_eq!(version.tombstone_count(), 3);
    assert_eq!(version.exclusion_count(), 3);

    let large_file = version.lookup_binding("bin/tool").expect("large file");
    assert_eq!(large_file.kind(), PathBindingKind::RegularFile);
    assert_eq!(large_file.bytes(), Some(10 * 1024 * 1024 * 1024));
    assert_eq!(large_file.executable(), Some(true));
    assert_eq!(
        large_file.object_version_id(),
        Some("version_0198ee40-c333-7ccc-8000-000000000001")
    );

    let directory = version.lookup_binding("assets").expect("empty directory");
    assert_eq!(directory.kind(), PathBindingKind::Directory);
    assert_eq!(directory.object_version_id(), None);

    let symlink = version
        .lookup_binding("links/readme")
        .expect("safe symlink record");
    assert_eq!(symlink.kind(), PathBindingKind::Symlink);
    assert_eq!(symlink.symlink_target(), Some("../readme.md"));
    assert!(version.lookup_binding("FOLDERBASE.md").is_some());
    assert!(version.lookup_binding(".folderbaseignore").is_some());
    assert!(version.lookup_binding("missing").is_none());
}

#[test]
fn schema_rejects_closed_shape_and_fidelity_mismatches() {
    let schema = read_json(VERSION_SCHEMA);
    let validator = jsonschema::draft202012::options()
        .should_validate_formats(true)
        .build(&schema)
        .expect("compile canonical Folderbase Version schema");

    for relative in [
        "conformance/folderbase-version/invalid/unknown-top-level-field.json",
        "conformance/folderbase-version/invalid/missing-folderbase-entry.json",
        "conformance/folderbase-version/invalid/missing-folderbaseignore.json",
        "conformance/folderbase-version/invalid/self-capture.json",
        "conformance/folderbase-version/invalid/unsupported-exclusion-reason.json",
    ] {
        assert!(
            !validator.is_valid(&read_json(relative)),
            "{relative} must not conform to the schema"
        );
    }

    let mut unsupported_live =
        read_json("conformance/folderbase-version/valid/fidelity-and-lifecycle-v1.json");
    unsupported_live["bindings"][2]["kind"] = Value::String("hard_link".to_owned());
    assert!(!validator.is_valid(&unsupported_live));

    let mut unverified_file =
        read_json("conformance/folderbase-version/valid/fidelity-and-lifecycle-v1.json");
    unverified_file["bindings"][3]
        .as_object_mut()
        .unwrap()
        .remove("object_version_id");
    assert!(!validator.is_valid(&unverified_file));
}

#[test]
fn semantic_decoder_rejects_order_collisions_boundaries_symlink_escape_and_identity_reuse() {
    for (relative, expected_error) in [
        (
            "conformance/folderbase-version/invalid/unsorted-bindings.json",
            "strictly sorted",
        ),
        (
            "conformance/folderbase-version/invalid/nfc-collision.json",
            "NFC normalization",
        ),
        (
            "conformance/folderbase-version/invalid/casefold-collision.json",
            "case folding",
        ),
        (
            "conformance/folderbase-version/invalid/nfc-unicode17-combining-collision.json",
            "NFC normalization",
        ),
        (
            "conformance/folderbase-version/invalid/casefold-unicode9-osage-collision.json",
            "case folding",
        ),
        (
            "conformance/folderbase-version/invalid/missing-folderbase-entry.json",
            "FOLDERBASE.md must",
        ),
        (
            "conformance/folderbase-version/invalid/missing-folderbaseignore.json",
            ".folderbaseignore must",
        ),
        (
            "conformance/folderbase-version/invalid/object-version-owner-collision.json",
            "different Object IDs",
        ),
        (
            "conformance/folderbase-version/invalid/root-object-version-reuse.json",
            "different Object IDs",
        ),
        (
            "conformance/folderbase-version/invalid/self-capture.json",
            "unsafe portable path component",
        ),
        (
            "conformance/folderbase-version/invalid/self-parent.json",
            "own parent",
        ),
        (
            "conformance/folderbase-version/invalid/nested-boundary-descendant.json",
            "enters an excluded nested",
        ),
        (
            "conformance/folderbase-version/invalid/nested-boundary-overlap.json",
            "overlaps its ancestor",
        ),
        (
            "conformance/folderbase-version/invalid/unsafe-symlink-target.json",
            "escapes the Folderbase root",
        ),
        (
            "conformance/folderbase-version/invalid/same-object-recreation.json",
            "same-path recreation",
        ),
        (
            "conformance/folderbase-version/invalid/unsupported-exclusion-reason.json",
            "kind and reason do not match",
        ),
        (
            "conformance/folderbase-version/invalid/windows-dos-superscript-device.json",
            "Windows-reserved",
        ),
    ] {
        let error = decode_fixture(relative).expect_err("invalid vector must be rejected");
        assert!(
            error.contains(expected_error),
            "{relative} reported {error:?}, expected {expected_error:?}"
        );
    }
}

#[test]
fn decoder_rejects_hostile_and_nonportable_path_spellings_without_renaming() {
    let base = read_json("conformance/folderbase-version/valid/minimal-restorable-v1.json");
    let hostile_paths = [
        ".".to_owned(),
        "../outside".to_owned(),
        "/absolute".to_owned(),
        "C:/drive".to_owned(),
        "with\\backslash".to_owned(),
        "double//separator".to_owned(),
        "contains\0nul".to_owned(),
        "bad<name".to_owned(),
        "control\u{1}".to_owned(),
        "CON".to_owned(),
        "aux.txt".to_owned(),
        "COM¹".to_owned(),
        "com².log".to_owned(),
        "CoM³.data".to_owned(),
        "LPT¹".to_owned(),
        "lpt².txt".to_owned(),
        "LpT³.archive".to_owned(),
        "trailing-dot.".to_owned(),
        "trailing-space ".to_owned(),
        "x".repeat(MAX_PATH_COMPONENT_BYTES + 1),
        format!("{}/x", "a".repeat(MAX_PATH_BYTES)),
        std::iter::repeat_n("x", MAX_PATH_DEPTH + 1)
            .collect::<Vec<_>>()
            .join("/"),
    ];

    for (index, path) in hostile_paths.into_iter().enumerate() {
        let mut version = base.clone();
        let mut bindings = base["bindings"].as_array().unwrap().clone();
        bindings.push(directory_binding(path.clone(), 200 + index));
        bindings.sort_by(|left, right| {
            left["path"]
                .as_str()
                .unwrap()
                .as_bytes()
                .cmp(right["path"].as_str().unwrap().as_bytes())
        });
        version["bindings"] = Value::Array(bindings);
        assert!(
            decode_value(&version).is_err(),
            "hostile path must be rejected exactly: {path:?}"
        );
    }
}

#[test]
fn decoder_enforces_aggregate_entry_and_encoded_representation_bounds() {
    let mut version = read_json("conformance/folderbase-version/valid/minimal-restorable-v1.json");
    version["bindings"] = Value::Array(
        (0..=MAX_VERSION_ENTRIES)
            .map(|index| directory_binding(format!("p{index:05}"), 1_000 + index))
            .collect(),
    );
    assert!(
        decode_value(&version)
            .unwrap_err()
            .contains("entry count exceeds")
    );

    let mut split = read_json("conformance/folderbase-version/valid/minimal-restorable-v1.json");
    let mut split_bindings = split["bindings"].as_array().unwrap().clone();
    split_bindings.extend(
        (0..8_191).map(|index| directory_binding(format!("b{index:05}"), 0x10_000 + index)),
    );
    split["bindings"] = Value::Array(split_bindings);
    split["tombstones"] = Value::Array(
        (0..8_192)
            .map(|index| {
                serde_json::json!({
                    "path": format!("t{index:05}"),
                    "object_id": format!(
                        "obj_0198ee40-b222-7bbb-8000-{:012x}",
                        0x20_000 + index
                    ),
                    "lifecycle": "deleted",
                    "deleted_kind": "directory",
                    "last_object_version_id": null
                })
            })
            .collect(),
    );
    assert_eq!(
        split["bindings"].as_array().unwrap().len(),
        8_193,
        "each split array stays below the per-array schema cap"
    );
    assert_eq!(split["tombstones"].as_array().unwrap().len(), 8_192);
    assert!(
        decode_value(&split)
            .unwrap_err()
            .contains("entry count exceeds"),
        "the aggregate cap must be enforced before fully decoding split arrays"
    );

    let oversized = std::io::repeat(b' ').take(MAX_ENCODED_VERSION_BYTES + 1);
    assert!(
        FolderbaseVersion::decode_bounded(oversized)
            .unwrap_err()
            .to_string()
            .contains("exceeds")
    );
}

#[test]
fn schema_and_runtime_enforce_distinct_character_and_utf8_path_limits() {
    let schema = read_json(VERSION_SCHEMA);
    let validator = jsonschema::draft202012::options()
        .should_validate_formats(true)
        .build(&schema)
        .expect("compile canonical Folderbase Version schema");
    let base = read_json("conformance/folderbase-version/valid/minimal-restorable-v1.json");

    let with_path = |path: String, suffix: usize| {
        let mut version = base.clone();
        let mut bindings = base["bindings"].as_array().unwrap().clone();
        bindings.push(directory_binding(path, suffix));
        bindings.sort_by(|left, right| {
            left["path"]
                .as_str()
                .unwrap()
                .as_bytes()
                .cmp(right["path"].as_str().unwrap().as_bytes())
        });
        version["bindings"] = Value::Array(bindings);
        version
    };

    let exact_component = with_path("x".repeat(MAX_PATH_COMPONENT_BYTES), 0x501);
    assert!(validator.is_valid(&exact_component));
    assert!(decode_value(&exact_component).is_ok());

    let unicode_component_over_bytes = with_path("é".repeat(128), 0x502);
    assert!(
        validator.is_valid(&unicode_component_over_bytes),
        "schema maxLength counts Unicode code points"
    );
    assert!(
        decode_value(&unicode_component_over_bytes).is_err(),
        "runtime component cap counts exact UTF-8 bytes"
    );

    let exact_path = std::iter::repeat_n("é".repeat(120), 17)
        .collect::<Vec<_>>()
        .join("/");
    assert_eq!(exact_path.len(), MAX_PATH_BYTES);
    let exact_path = with_path(exact_path, 0x503);
    assert!(validator.is_valid(&exact_path));
    assert!(decode_value(&exact_path).is_ok());

    let mut path_over_bytes = std::iter::repeat_n("é".repeat(120), 17).collect::<Vec<_>>();
    path_over_bytes.last_mut().unwrap().push('x');
    let path_over_bytes = with_path(path_over_bytes.join("/"), 0x504);
    assert!(validator.is_valid(&path_over_bytes));
    assert!(decode_value(&path_over_bytes).is_err());

    let depth_over_runtime = with_path(
        std::iter::repeat_n("d", MAX_PATH_DEPTH + 1)
            .collect::<Vec<_>>()
            .join("/"),
        0x505,
    );
    assert!(validator.is_valid(&depth_over_runtime));
    assert!(decode_value(&depth_over_runtime).is_err());

    let schema_over_characters = with_path("x".repeat(MAX_PATH_BYTES + 1), 0x506);
    assert!(!validator.is_valid(&schema_over_characters));
    assert!(decode_value(&schema_over_characters).is_err());
}

#[test]
fn root_manifest_is_the_only_reserved_state_reference_and_is_not_a_binding() {
    let version = read_json("conformance/folderbase-version/valid/minimal-restorable-v1.json");
    assert_eq!(
        version["root_manifest"]["path"],
        ".folderbase/manifest.json"
    );

    let mut self_capture = version.clone();
    self_capture["bindings"] = Value::Array(vec![serde_json::json!({
        "path": ".folderbase/manifest.json",
        "object_id": "obj_0198ee40-b222-7bbb-8000-000000000900",
        "lifecycle": "live",
        "kind": "regular_file",
        "object_version_id": "version_0198ee40-c333-7ccc-8000-000000000900",
        "content_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "bytes": 512,
        "executable": false
    })]);
    assert!(decode_value(&self_capture).is_err());

    let mut chunk_identity = version;
    chunk_identity["root_manifest"]["chunk_manifest_sha256"] = Value::String("a".repeat(64));
    assert!(decode_value(&chunk_identity).is_err());

    let mut object_namespace =
        read_json("conformance/folderbase-version/valid/minimal-restorable-v1.json");
    object_namespace["version_id"] =
        Value::String("version_0198ee40-a111-7aaa-8000-000000000001".to_owned());
    assert!(decode_value(&object_namespace).is_err());

    let mut folderbase_namespace =
        read_json("conformance/folderbase-version/valid/minimal-restorable-v1.json");
    folderbase_namespace["root_manifest"]["object_version_id"] =
        Value::String("fbversion_0198ee40-c333-7ccc-8000-000000000100".to_owned());
    assert!(decode_value(&folderbase_namespace).is_err());
}

#[test]
fn decoder_requires_both_visible_root_markers_as_regular_file_bindings() {
    let base = read_json("conformance/folderbase-version/valid/minimal-restorable-v1.json");

    for required_path in [".folderbaseignore", "FOLDERBASE.md"] {
        let mut missing = base.clone();
        missing["bindings"]
            .as_array_mut()
            .unwrap()
            .retain(|binding| binding["path"] != required_path);
        assert!(
            decode_value(&missing).is_err(),
            "{required_path} must be required for a restorable Folderbase"
        );
    }

    let mut wrong_kind = base;
    wrong_kind["bindings"][1] = directory_binding("FOLDERBASE.md".to_owned(), 0x404);
    assert!(
        decode_value(&wrong_kind).is_err(),
        "FOLDERBASE.md must restore as an opaque regular file"
    );
}

#[test]
fn canonical_digests_match_independently_generated_public_sidecars() {
    for stem in ["minimal-restorable-v1", "fidelity-and-lifecycle-v1"] {
        let relative = format!("conformance/folderbase-version/valid/{stem}");
        let version = decode_fixture(&format!("{relative}.json")).expect("valid digest vector");
        let expected = fs::read_to_string(protocol_root().join(format!("{relative}.sha256")))
            .expect("read independent digest sidecar");

        assert_eq!(version.canonical_digest().unwrap(), expected.trim());
    }
}

#[test]
fn exact_integral_json_number_spellings_preserve_identity_and_fractions_fail() {
    let path =
        protocol_root().join("conformance/folderbase-version/valid/fidelity-and-lifecycle-v1.json");
    let plain_encoded = fs::read_to_string(path).unwrap();
    let alternate_encoded = plain_encoded
        .replace("\"bytes\": 512", "\"bytes\": 512.0")
        .replace("\"bytes\": 10737418240", "\"bytes\": 1.073741824e10");
    let plain = FolderbaseVersion::decode_bounded(Cursor::new(plain_encoded.as_bytes())).unwrap();
    let alternate =
        FolderbaseVersion::decode_bounded(Cursor::new(alternate_encoded.as_bytes())).unwrap();
    assert_eq!(
        alternate.canonical_digest().unwrap(),
        plain.canonical_digest().unwrap()
    );

    let fractional = alternate_encoded.replace("\"bytes\": 512.0", "\"bytes\": 512.5");
    assert!(FolderbaseVersion::decode_bounded(Cursor::new(fractional)).is_err());
}

#[test]
fn deterministic_diff_distinguishes_move_recreation_deletion_and_tombstone_state() {
    let mut old = read_json("conformance/folderbase-version/valid/minimal-restorable-v1.json");
    old["bindings"] = Value::Array(vec![
        regular_file_binding(".folderbaseignore", 0x101, 0x101),
        regular_file_binding("FOLDERBASE.md", 0x102, 0x102),
        regular_file_binding("a.md", 0x1001, 0x2001),
        regular_file_binding("delete.md", 0x1002, 0x2002),
        regular_file_binding("move.md", 0x1003, 0x2003),
        directory_binding("stable".to_owned(), 0x1004),
    ]);
    old["exclusions"] = Value::Array(vec![serde_json::json!({
        "path": "hard",
        "kind": "hard_link",
        "reason": "unsupported-v1"
    })]);
    let old = decode_value(&old).unwrap();

    let mut new = read_json("conformance/folderbase-version/valid/minimal-restorable-v1.json");
    new["version_id"] = Value::String("fbversion_0198ee40-a111-7aaa-8000-000000000099".to_owned());
    new["parents"] = Value::Array(vec![Value::String(old.version_id().to_owned())]);
    new["root_manifest"]["object_version_id"] =
        Value::String("version_0198ee40-c333-7ccc-8000-000000000900".to_owned());
    new["root_manifest"]["content_sha256"] = Value::String("1".repeat(64));
    new["bindings"] = Value::Array(vec![
        regular_file_binding(".folderbaseignore", 0x101, 0x101),
        regular_file_binding("FOLDERBASE.md", 0x102, 0x102),
        regular_file_binding("a.md", 0x1005, 0x2005),
        regular_file_binding("moved.md", 0x1003, 0x2006),
        directory_binding("stable".to_owned(), 0x1004),
    ]);
    new["tombstones"] = Value::Array(vec![
        serde_json::json!({
            "path": "a.md",
            "object_id": "obj_0198ee40-b222-7bbb-8000-000000001001",
            "lifecycle": "deleted",
            "deleted_kind": "regular_file",
            "last_object_version_id": "version_0198ee40-c333-7ccc-8000-000000002001"
        }),
        serde_json::json!({
            "path": "delete.md",
            "object_id": "obj_0198ee40-b222-7bbb-8000-000000001002",
            "lifecycle": "deleted",
            "deleted_kind": "regular_file",
            "last_object_version_id": "version_0198ee40-c333-7ccc-8000-000000002002"
        }),
        serde_json::json!({
            "path": "move.md",
            "object_id": "obj_0198ee40-b222-7bbb-8000-000000001003",
            "lifecycle": "deleted",
            "deleted_kind": "regular_file",
            "last_object_version_id": "version_0198ee40-c333-7ccc-8000-000000002003"
        }),
    ]);
    new["exclusions"] = Value::Array(vec![serde_json::json!({
        "path": "nested",
        "kind": "nested_folderbase",
        "reason": "nested-folderbase-boundary"
    })]);
    let new = decode_value(&new).unwrap();

    let first = old.diff(&new).unwrap();
    let repeated = old.diff(&new).unwrap();
    assert_eq!(first, repeated);
    assert!(first.changes().iter().any(|change| matches!(
        change,
        FolderbaseVersionChange::Moved {
            object_id,
            from_path,
            to_path,
        } if object_id.ends_with("001003")
            && from_path == "move.md"
            && to_path == "moved.md"
    )));
    assert!(first.changes().iter().any(|change| matches!(
        change,
        FolderbaseVersionChange::Updated {
            path,
            object_id,
            previous_object_version_id: Some(previous),
            object_version_id: Some(current),
        } if path == "moved.md"
            && object_id.ends_with("001003")
            && previous.ends_with("002003")
            && current.ends_with("002006")
    )));
    assert!(first.changes().iter().any(|change| matches!(
        change,
        FolderbaseVersionChange::Recreated {
            path,
            previous_object_id,
            object_id,
        } if path == "a.md"
            && previous_object_id.ends_with("001001")
            && object_id.ends_with("001005")
    )));
    assert!(first.changes().iter().any(|change| matches!(
        change,
        FolderbaseVersionChange::Deleted {
            path,
            tombstone_present: true,
            ..
        } if path == "delete.md"
    )));
    assert_eq!(
        first
            .changes()
            .iter()
            .filter(|change| matches!(change, FolderbaseVersionChange::TombstoneAdded { .. }))
            .count(),
        3
    );
}

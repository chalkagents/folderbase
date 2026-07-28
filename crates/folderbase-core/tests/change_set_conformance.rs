use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};

use serde_json::{Value, json};

const CHANGE_SET_SCHEMA: &str = "schemas/0.1/change-set.schema.json";
const CHANGE_SET_SCHEMA_ID: &str = "https://folderbase.ai/protocol/0.1/change-set.schema.json";
const CHANGE_SET_ID: &str = "changeset_619f9b75-0b22-7a18-8f40-3f29f1438b62";
const CHECKOUT_ID: &str = "checkout_619f9b75-0b22-7a18-8f40-3f29f1438b63";
const BASE_VERSION_ID: &str = "version_619f9b77-fdfa-78fb-8ca5-4ff25e6cc4b0";
const CREATED_OBJECT_ID: &str = "obj_619f9b75-4f42-7f65-a012-2bfecdd8c471";
const UPDATED_OBJECT_ID: &str = "obj_619f9b75-4f42-7f65-a012-2bfecdd8c472";
const MOVED_OBJECT_ID: &str = "obj_619f9b75-4f42-7f65-a012-2bfecdd8c473";
const DELETED_OBJECT_ID: &str = "obj_619f9b75-4f42-7f65-a012-2bfecdd8c474";
const CREATED_VERSION_ID: &str = "version_619f9b77-fdfa-78fb-8ca5-4ff25e6cc4b1";
const UPDATED_BASE_VERSION_ID: &str = "version_619f9b77-fdfa-78fb-8ca5-4ff25e6cc4b2";
const UPDATED_VERSION_ID: &str = "version_619f9b77-fdfa-78fb-8ca5-4ff25e6cc4b5";
const MOVED_VERSION_ID: &str = "version_619f9b77-fdfa-78fb-8ca5-4ff25e6cc4b3";
const DELETED_VERSION_ID: &str = "version_619f9b77-fdfa-78fb-8ca5-4ff25e6cc4b4";

fn protocol_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../protocol")
}

fn read_json(relative: &str) -> Value {
    let path = protocol_root().join(relative);
    serde_json::from_slice(
        &fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display())),
    )
    .unwrap_or_else(|error| panic!("parse {}: {error}", path.display()))
}

fn schema_accepts(change_set: &Value) -> bool {
    let schema = read_json(CHANGE_SET_SCHEMA);
    jsonschema::draft202012::options()
        .should_validate_formats(true)
        .build(&schema)
        .unwrap_or_else(|error| panic!("compile {CHANGE_SET_SCHEMA}: {error}"))
        .is_valid(change_set)
}

fn protocol_accepts(change_set: &Value) -> bool {
    if !schema_accepts(change_set) {
        return false;
    }
    // Draft 2020-12 cannot compare one property across array items, so
    // protocol conformance adds the declarative one-object/one-final-state
    // invariant beside structural schema validation.
    let Some(operations) = change_set.get("operations").and_then(Value::as_array) else {
        return false;
    };
    let mut object_ids = BTreeSet::new();
    operations.iter().all(|operation| {
        operation
            .get("object_id")
            .and_then(Value::as_str)
            .is_some_and(|object_id| object_ids.insert(object_id))
    })
}

fn change_set(operations: Vec<Value>) -> Value {
    json!({
        "$schema": CHANGE_SET_SCHEMA_ID,
        "protocol_version": "0.1.0",
        "id": CHANGE_SET_ID,
        "checkout_id": CHECKOUT_ID,
        "base_version": BASE_VERSION_ID,
        "operations": operations,
        "status": "proposed"
    })
}

fn create_operation(object_id: &str, version_id: &str, relative_path: &str) -> Value {
    json!({
        "type": "create",
        "object_id": object_id,
        "relative_path": relative_path,
        "version_id": version_id,
        "sha256": "a".repeat(64),
        "bytes": 8,
        "media_type": "text/plain",
        "content_base64": "Y3JlYXRlZAo="
    })
}

fn update_operation() -> Value {
    json!({
        "type": "update",
        "object_id": UPDATED_OBJECT_ID,
        "base_version_id": UPDATED_BASE_VERSION_ID,
        "relative_path": "overview.md",
        "version_id": UPDATED_VERSION_ID,
        "sha256": "b".repeat(64),
        "bytes": 8,
        "media_type": "text/plain",
        "content_base64": "dXBkYXRlZAo="
    })
}

fn move_operation() -> Value {
    json!({
        "type": "move",
        "object_id": MOVED_OBJECT_ID,
        "base_version_id": MOVED_VERSION_ID,
        "relative_path": "old-name.md",
        "destination_relative_path": "new-name.md"
    })
}

fn delete_operation() -> Value {
    json!({
        "type": "delete",
        "object_id": DELETED_OBJECT_ID,
        "base_version_id": DELETED_VERSION_ID,
        "relative_path": "archive.md"
    })
}

fn assert_schema_rejects_cases(cases: Vec<(&str, Value)>) {
    let accepted = cases
        .into_iter()
        .filter_map(|(label, candidate)| schema_accepts(&candidate).then_some(label))
        .collect::<Vec<_>>();
    assert!(
        accepted.is_empty(),
        "Change Set Protocol 0.1 accepted invalid cases: {}",
        accepted.join(", ")
    );
}

#[test]
fn exact_create_update_move_and_delete_shapes_are_valid() {
    assert!(protocol_accepts(&change_set(vec![
        create_operation(CREATED_OBJECT_ID, CREATED_VERSION_ID, "created.md"),
        update_operation(),
        move_operation(),
        delete_operation(),
    ])));
}

#[test]
fn create_shape_requires_new_content_and_has_no_base() {
    let mut missing_content_version =
        create_operation(CREATED_OBJECT_ID, CREATED_VERSION_ID, "created.md");
    missing_content_version
        .as_object_mut()
        .expect("create operation")
        .remove("version_id");

    let mut with_base = create_operation(CREATED_OBJECT_ID, CREATED_VERSION_ID, "created.md");
    with_base["base_version_id"] = json!(BASE_VERSION_ID);

    assert_schema_rejects_cases(vec![
        (
            "create without version_id",
            change_set(vec![missing_content_version]),
        ),
        ("create with base_version_id", change_set(vec![with_base])),
    ]);
}

#[test]
fn update_shape_requires_a_base_and_cannot_also_move() {
    let mut missing_base = update_operation();
    missing_base
        .as_object_mut()
        .expect("update operation")
        .remove("base_version_id");

    let mut with_destination = update_operation();
    with_destination["destination_relative_path"] = json!("renamed.md");

    assert_schema_rejects_cases(vec![
        (
            "update without base_version_id",
            change_set(vec![missing_base]),
        ),
        (
            "update with destination_relative_path",
            change_set(vec![with_destination]),
        ),
    ]);
}

#[test]
fn move_shape_requires_a_destination_and_cannot_create_content() {
    let mut missing_destination = move_operation();
    missing_destination
        .as_object_mut()
        .expect("move operation")
        .remove("destination_relative_path");

    let mut with_content = move_operation();
    with_content["version_id"] = json!(CREATED_VERSION_ID);
    with_content["sha256"] = json!("a".repeat(64));
    with_content["bytes"] = json!(8);
    with_content["content_base64"] = json!("Y3JlYXRlZAo=");

    assert_schema_rejects_cases(vec![
        (
            "move without destination_relative_path",
            change_set(vec![missing_destination]),
        ),
        (
            "move with candidate content",
            change_set(vec![with_content]),
        ),
    ]);
}

#[test]
fn delete_shape_has_neither_a_destination_nor_candidate_content() {
    let mut with_destination = delete_operation();
    with_destination["destination_relative_path"] = json!("elsewhere.md");

    let mut with_content = delete_operation();
    with_content["version_id"] = json!(CREATED_VERSION_ID);
    with_content["sha256"] = json!("a".repeat(64));
    with_content["bytes"] = json!(8);
    with_content["content_base64"] = json!("Y3JlYXRlZAo=");

    assert_schema_rejects_cases(vec![
        (
            "delete with destination_relative_path",
            change_set(vec![with_destination]),
        ),
        (
            "delete with candidate content",
            change_set(vec![with_content]),
        ),
    ]);
}

#[test]
fn unsupported_imperative_operation_types_are_invalid() {
    let copy = json!({
        "type": "copy",
        "object_id": CREATED_OBJECT_ID,
        "relative_path": "source.md",
        "destination_relative_path": "copy.md"
    });
    assert!(!schema_accepts(&change_set(vec![copy])));
}

#[test]
fn change_sets_contain_between_one_and_sixty_four_operations() {
    assert!(schema_accepts(&change_set(vec![create_operation(
        CREATED_OBJECT_ID,
        CREATED_VERSION_ID,
        "created.md",
    )])));

    let sixty_four = (0..64)
        .map(|index| {
            create_operation(
                &format!("obj_619f9b75-4f42-7f65-a012-{index:012x}"),
                &format!("version_619f9b77-fdfa-78fb-8ca5-{index:012x}"),
                &format!("created-{index}.md"),
            )
        })
        .collect();
    assert!(schema_accepts(&change_set(sixty_four)));

    let sixty_five = (0..65)
        .map(|index| {
            create_operation(
                &format!("obj_719f9b75-4f42-7f65-a012-{index:012x}"),
                &format!("version_719f9b77-fdfa-78fb-8ca5-{index:012x}"),
                &format!("overflow-{index}.md"),
            )
        })
        .collect();
    assert_schema_rejects_cases(vec![
        ("zero operations", change_set(vec![])),
        ("65 operations", change_set(sixty_five)),
    ]);
}

#[test]
fn declarative_change_set_has_at_most_one_final_state_per_object() {
    let duplicate_object = change_set(vec![
        update_operation(),
        json!({
            "type": "move",
            "object_id": UPDATED_OBJECT_ID,
            "base_version_id": UPDATED_BASE_VERSION_ID,
            "relative_path": "overview.md",
            "destination_relative_path": "renamed.md"
        }),
    ]);
    assert!(!protocol_accepts(&duplicate_object));
}

#[test]
fn caller_storage_keys_are_never_part_of_public_operations() {
    let mut create = create_operation(CREATED_OBJECT_ID, CREATED_VERSION_ID, "created.md");
    create["storage_key"] = json!("caller/chosen/create");
    let mut update = update_operation();
    update["storage_key"] = json!("caller/chosen/update");

    assert_schema_rejects_cases(vec![
        ("create with caller storage_key", change_set(vec![create])),
        ("update with caller storage_key", change_set(vec![update])),
    ]);
}

#[test]
fn unknown_extension_fields_remain_round_trippable() {
    let mut create = create_operation(CREATED_OBJECT_ID, CREATED_VERSION_ID, "created.md");
    create["future_client_hint"] = json!({
        "preserve": true
    });
    let mut candidate = change_set(vec![create]);
    candidate["future_protocol_extension"] = json!("preserve me");

    assert!(schema_accepts(&candidate));
}

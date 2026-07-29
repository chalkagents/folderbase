use folderbase_core::{
    ConsequentialAnswerType, ConsequentialQuestion, InitializationOptions,
    MAX_REORGANIZATION_RECORD_BYTES, NestedBoundary, ScopeEntry, decode_reorganization_draft,
    decode_reorganization_draft_slice, decode_reorganization_plan_slice, initialize,
    plan_initialization, reorganization_analysis_scope_sha256, reorganization_plan_sha256,
    seal_reorganization_draft, validate_reorganization_draft, validate_reorganization_plan,
};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

fn protocol_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../protocol")
}

fn protocol_json(relative: &str) -> serde_json::Value {
    let path = protocol_root().join(relative);
    serde_json::from_slice(
        &std::fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display())),
    )
    .unwrap_or_else(|error| panic!("parse {}: {error}", path.display()))
}

#[test]
fn a_complete_reorganization_draft_decodes_through_the_public_contract() {
    let draft = br#"{
      "protocol_version": "0.3.0",
      "profile": "folderbase-reorganization-draft-v1",
      "id": "reorg_project_cleanup",
      "generation": 1,
      "folderbase_id": "folderbase_019f9b75-0000-7000-8000-000000000002",
      "path_profile": "portable-case-sensitive-v1",
      "analysis_scope": {
        "manifest_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "ignore_policy": { "expectation": "absent", "path": ".folderbaseignore" },
        "structural_changes_policy": "approve",
        "nested_boundaries": [],
        "operation_closure": [
          { "expectation": "absent", "path": "Canonical" },
          { "expectation": "directory", "path": "Proposals" },
          {
            "expectation": "file",
            "path": "Proposals/approved.pdf",
            "sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            "byte_count": 10000000000
          },
          { "expectation": "absent", "path": "Canonical/approved.pdf" }
        ],
        "declared_entries": [
          {
            "expectation": "file",
            "path": "Notes/decision.md",
            "sha256": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            "byte_count": 512
          }
        ]
      },
      "questions": [
        {
          "id": "approved_proposal",
          "prompt": "Which proposal was approved?",
          "answer_type": "single_choice",
          "required": true,
          "options": ["june", "july"],
          "answer": { "type": "single_choice", "value": "july" }
        }
      ],
      "rationale": "Keep one current narrative while preserving every source proposal.",
      "template_references": ["folderbase.project@0.2.2"],
      "operations": [
        { "kind": "create_directory", "path": "Canonical" },
        {
          "kind": "move_file",
          "source_path": "Proposals/approved.pdf",
          "destination_path": "Canonical/approved.pdf",
          "expected_sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
          "expected_byte_count": 10000000000
        }
      ]
    }"#;

    let decoded = decode_reorganization_draft_slice(draft).expect("valid draft");

    assert_eq!(decoded.id, "reorg_project_cleanup");
    assert_eq!(decoded.operations.len(), 2);
}

#[test]
fn a_complete_draft_seals_into_an_immutable_digest_bound_plan() {
    let draft = decode_reorganization_draft_slice(include_bytes!(
        "../../../protocol/conformance/reorganization/draft/valid/project-cleanup-v1.json"
    ))
    .expect("valid draft");

    let plan = seal_reorganization_draft(draft).expect("complete draft seals");

    assert_eq!(plan.profile, "folderbase-reorganization-plan-v1");
    assert_eq!(plan.analysis_scope_digest.len(), 64);
    assert_eq!(plan.plan_digest.len(), 64);
}

#[test]
fn a_sealed_plan_round_trips_only_when_both_bound_digests_match() {
    let draft = decode_reorganization_draft_slice(include_bytes!(
        "../../../protocol/conformance/reorganization/draft/valid/project-cleanup-v1.json"
    ))
    .expect("valid draft");
    let plan = seal_reorganization_draft(draft).expect("complete draft seals");
    let encoded = serde_json::to_vec(&plan).expect("encode sealed plan");

    let decoded = decode_reorganization_plan_slice(&encoded).expect("valid sealed plan");

    assert_eq!(decoded, plan);
}

#[test]
fn reader_decode_refuses_an_oversized_record_after_one_bounded_read() {
    let oversized = vec![b' '; MAX_REORGANIZATION_RECORD_BYTES + 1];

    let error = decode_reorganization_draft(std::io::Cursor::new(oversized))
        .expect_err("oversized records must be refused");

    assert!(error.to_string().contains("8 MiB encoded-record limit"));
}

#[test]
fn parent_plans_cannot_operate_inside_a_nested_folderbase_boundary() {
    let mut draft: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../../protocol/conformance/reorganization/draft/valid/project-cleanup-v1.json"
    ))
    .expect("draft JSON");
    draft["analysis_scope"]["nested_boundaries"] = serde_json::json!([
        {
            "path": "Clients/Prosperna",
            "manifest_sha256": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
        }
    ]);
    draft["operations"][1]["source_path"] = serde_json::json!("Clients/Prosperna/approved.pdf");

    let encoded = serde_json::to_vec(&draft).expect("encode nested-boundary draft");
    let error = decode_reorganization_draft_slice(&encoded)
        .expect_err("parent plan must not reach into nested folderbase");

    assert!(error.to_string().contains("nested Folderbase boundary"));
}

#[test]
fn active_path_profile_rejects_aliasing_operation_paths() {
    let mut draft: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../../protocol/conformance/reorganization/draft/valid/project-cleanup-v1.json"
    ))
    .expect("draft JSON");
    draft["path_profile"] = serde_json::json!("portable-case-fold-v1");
    draft["operations"] = serde_json::json!([
        { "kind": "create_directory", "path": "Current" },
        { "kind": "create_directory", "path": "current" }
    ]);

    let encoded = serde_json::to_vec(&draft).expect("encode aliasing draft");
    let error =
        decode_reorganization_draft_slice(&encoded).expect_err("profile aliases must be refused");

    assert!(error.to_string().contains("aliases another operation path"));
}

#[test]
fn public_draft_schema_accepts_the_cross_client_fixture() {
    let schema = protocol_json("schemas/0.3/reorganization-draft.schema.json");
    let draft = protocol_json("conformance/reorganization/draft/valid/project-cleanup-v1.json");
    let validator = jsonschema::draft202012::options()
        .should_validate_formats(true)
        .build(&schema)
        .expect("compile public Draft schema");

    assert!(validator.is_valid(&draft));
}

#[test]
fn public_plan_schema_accepts_the_exact_record_produced_by_core() {
    let draft = decode_reorganization_draft_slice(include_bytes!(
        "../../../protocol/conformance/reorganization/draft/valid/project-cleanup-v1.json"
    ))
    .expect("valid draft");
    let plan = seal_reorganization_draft(draft).expect("complete draft seals");
    let schema = protocol_json("schemas/0.3/reorganization-plan.schema.json");
    let draft_schema = protocol_json("schemas/0.3/reorganization-draft.schema.json");
    let registry = jsonschema::Registry::new()
        .add(
            "https://folderbase.ai/protocol/0.3/reorganization-draft.schema.json",
            &draft_schema,
        )
        .expect("register Draft schema")
        .prepare()
        .expect("prepare protocol schema registry");
    let validator = jsonschema::draft202012::options()
        .should_validate_formats(true)
        .with_registry(&registry)
        .build(&schema)
        .expect("compile public Plan schema");

    assert!(validator.is_valid(&serde_json::to_value(plan).expect("plan JSON")));
}

#[test]
fn canonical_plan_digest_matches_the_independent_node_crypto_vector() {
    let plan_bytes = std::fs::read(
        protocol_root().join("conformance/reorganization/plan/valid/project-cleanup-v1.json"),
    )
    .expect("read plan digest vector");
    let expected = std::fs::read_to_string(
        protocol_root().join("conformance/reorganization/plan/valid/project-cleanup-v1.sha256"),
    )
    .expect("read independent Node crypto SHA-256");

    let plan = decode_reorganization_plan_slice(&plan_bytes).expect("valid digest vector");

    assert_eq!(plan.plan_digest, expected.trim());
    assert_eq!(
        plan.analysis_scope_digest,
        "d1593f60460548508985a2f8c712a91e0505bdd1fc0fe644a02b528a02e09b4a"
    );
}

#[test]
fn question_ids_and_single_choice_options_are_unique() {
    let mut draft: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../../protocol/conformance/reorganization/draft/valid/project-cleanup-v1.json"
    ))
    .expect("draft JSON");
    let duplicate = draft["questions"][0].clone();
    draft["questions"]
        .as_array_mut()
        .expect("questions")
        .push(duplicate);

    let encoded = serde_json::to_vec(&draft).expect("encode duplicate questions");
    let error = decode_reorganization_draft_slice(&encoded)
        .expect_err("duplicate question identifiers must be refused");

    assert!(error.to_string().contains("question id must be unique"));
}

#[test]
fn all_public_draft_vectors_match_the_schema_and_core_contract() {
    let schema = protocol_json("schemas/0.3/reorganization-draft.schema.json");
    let validator = jsonschema::draft202012::options()
        .should_validate_formats(true)
        .build(&schema)
        .expect("compile public Draft schema");

    for relative in [
        "conformance/reorganization/draft/valid/project-cleanup-v1.json",
        "conformance/reorganization/draft/valid/additive-folder-v1.json",
        "conformance/reorganization/draft/valid/all-operation-kinds-v1.json",
        "conformance/reorganization/draft/valid/mathematical-integers-v1.json",
        "conformance/reorganization/draft/valid/negative-zero-v1.json",
        "conformance/reorganization/draft/valid/unanswered-consequential-v1.json",
    ] {
        let fixture = protocol_json(relative);
        assert!(
            validator.is_valid(&fixture),
            "{relative} must satisfy schema"
        );
        let bytes = serde_json::to_vec(&fixture).expect("fixture bytes");
        decode_reorganization_draft_slice(&bytes)
            .unwrap_or_else(|error| panic!("{relative} must satisfy Core: {error}"));
    }

    for relative in [
        "conformance/reorganization/draft/invalid/authority-field.json",
        "conformance/reorganization/draft/invalid/delete-operation.json",
        "conformance/reorganization/draft/invalid/loose-folderbase-identity.json",
        "conformance/reorganization/draft/invalid/relationship-type-grammar.json",
        "conformance/reorganization/draft/invalid/reserved-operation-path.json",
        "conformance/reorganization/draft/invalid/unsafe-path.json",
        "conformance/reorganization/draft/invalid/unsupported-profile.json",
    ] {
        let fixture = protocol_json(relative);
        assert!(
            !validator.is_valid(&fixture),
            "{relative} must be rejected by schema"
        );
        let bytes = serde_json::to_vec(&fixture).expect("fixture bytes");
        assert!(
            decode_reorganization_draft_slice(&bytes).is_err(),
            "{relative} must be rejected by Core"
        );
    }

    for relative in [
        "conformance/reorganization/draft/invalid/closure-mismatch.json",
        "conformance/reorganization/draft/invalid/nested-boundary-operation.json",
        "conformance/reorganization/draft/invalid/case-alias.json",
        // Some validators round this lexeme before applying `type: integer`;
        // Core's arbitrary-precision lexical decoder must still refuse it.
        "conformance/reorganization/draft/invalid/near-limit-fractional-integer.json",
    ] {
        let fixture = protocol_json(relative);
        assert!(
            validator.is_valid(&fixture),
            "{relative} is a semantic negative and must satisfy shape"
        );
        let bytes = serde_json::to_vec(&fixture).expect("fixture bytes");
        assert!(
            decode_reorganization_draft_slice(&bytes).is_err(),
            "{relative} must be rejected by Core semantics"
        );
    }
}

#[test]
fn schema_valid_negative_zero_forms_normalize_before_nonnegative_integer_validation() {
    let relative = "conformance/reorganization/draft/valid/negative-zero-v1.json";
    let schema = protocol_json("schemas/0.3/reorganization-draft.schema.json");
    let fixture = protocol_json(relative);
    let validator = jsonschema::draft202012::options()
        .build(&schema)
        .expect("compile public Draft schema");
    assert!(
        validator.is_valid(&fixture),
        "negative zero is JSON integer zero"
    );

    let draft = decode_reorganization_draft_slice(
        &std::fs::read(protocol_root().join(relative)).expect("negative-zero vector"),
    )
    .expect("Core accepts schema-valid mathematical zero");
    let ScopeEntry::File { byte_count, .. } = &draft.analysis_scope.declared_entries[0] else {
        panic!("declared empty file");
    };
    assert_eq!(*byte_count, 0);
}

#[test]
fn analysis_scope_binds_the_real_initialized_manifest_structural_changes_policy() {
    let root = tempfile::tempdir().expect("temporary Folderbase root");
    let initialization = plan_initialization(root.path(), InitializationOptions::default())
        .expect("plan initialization");
    initialize(&initialization).expect("initialize Folderbase");
    let manifest_bytes =
        std::fs::read(root.path().join(".folderbase/manifest.json")).expect("manifest");
    let manifest: serde_json::Value =
        serde_json::from_slice(&manifest_bytes).expect("initialized manifest JSON");

    let mut draft = protocol_json("conformance/reorganization/draft/valid/additive-folder-v1.json");
    draft["folderbase_id"] = manifest["folderbase"]["id"].clone();
    draft["analysis_scope"]["manifest_sha256"] =
        serde_json::json!(format!("{:x}", Sha256::digest(&manifest_bytes)));
    draft["analysis_scope"]["structural_changes_policy"] =
        manifest["policies"]["structural_changes"].clone();

    decode_reorganization_draft_slice(&serde_json::to_vec(&draft).expect("reachable Draft"))
        .expect("initialized Folderbase policy is representable");
}

#[test]
fn unanswered_required_questions_keep_a_draft_inert_and_unsealable() {
    let draft = decode_reorganization_draft_slice(include_bytes!(
        "../../../protocol/conformance/reorganization/draft/valid/unanswered-consequential-v1.json"
    ))
    .expect("unanswered Draft remains valid inert data");

    let error = seal_reorganization_draft(draft).expect_err("required answer must precede sealing");

    assert!(
        error
            .to_string()
            .contains("required consequential questions")
    );
}

#[test]
fn shaped_but_forged_plan_vector_is_refused_by_core_digest_validation() {
    let schema = protocol_json("schemas/0.3/reorganization-plan.schema.json");
    let draft_schema = protocol_json("schemas/0.3/reorganization-draft.schema.json");
    let registry = jsonschema::Registry::new()
        .add(
            "https://folderbase.ai/protocol/0.3/reorganization-draft.schema.json",
            &draft_schema,
        )
        .expect("register Draft schema")
        .prepare()
        .expect("prepare protocol schema registry");
    let validator = jsonschema::draft202012::options()
        .with_registry(&registry)
        .build(&schema)
        .expect("compile public Plan schema");
    let relative = "conformance/reorganization/plan/invalid/forged-plan-digest.json";
    let fixture = protocol_json(relative);

    assert!(
        validator.is_valid(&fixture),
        "forged vector deliberately has valid shape"
    );
    let bytes = serde_json::to_vec(&fixture).expect("fixture bytes");
    let error = decode_reorganization_plan_slice(&bytes).expect_err("forged plan must be refused");
    assert!(error.to_string().contains("plan digest does not match"));
}

#[test]
fn the_closed_v1_operation_set_covers_text_opaque_tracked_and_protocol_changes() {
    let relative = "conformance/reorganization/draft/valid/all-operation-kinds-v1.json";
    let fixture = protocol_json(relative);
    let schema = protocol_json("schemas/0.3/reorganization-draft.schema.json");
    let validator = jsonschema::draft202012::options()
        .build(&schema)
        .expect("compile public Draft schema");

    assert!(
        validator.is_valid(&fixture),
        "all operations have public shape"
    );
    let bytes = serde_json::to_vec(&fixture).expect("fixture bytes");
    let draft = decode_reorganization_draft_slice(&bytes).expect("all operations validate");

    assert_eq!(draft.operations.len(), 10);
}

#[test]
fn typed_object_operations_match_the_released_object_protocol() {
    let fixture =
        protocol_json("conformance/reorganization/draft/valid/all-operation-kinds-v1.json");
    let operation_kinds = fixture["operations"]
        .as_array()
        .expect("operations")
        .iter()
        .filter_map(|operation| operation["kind"].as_str())
        .collect::<Vec<_>>();

    for required in [
        "mark_canonical",
        "mark_superseded",
        "archive_object",
        "add_relationship",
    ] {
        assert!(
            operation_kinds.contains(&required),
            "missing released object operation {required}"
        );
    }
    assert!(!operation_kinds.contains(&"update_object_lifecycle"));
    assert!(!operation_kinds.contains(&"update_relationship"));
    assert!(
        fixture["operations"]
            .as_array()
            .expect("operations")
            .iter()
            .all(|operation| operation.get("expected_revision").is_none()
                && operation.get("new_revision").is_none())
    );
    decode_reorganization_draft_slice(&serde_json::to_vec(&fixture).expect("object operations"))
        .expect("released object operations form a reachable Draft");

    let mut invalid_relationship = fixture;
    invalid_relationship["operations"][9]["relationship_type"] = serde_json::json!("Supports-v2");
    let schema = protocol_json("schemas/0.3/reorganization-draft.schema.json");
    let validator = jsonschema::draft202012::options()
        .build(&schema)
        .expect("compile Draft schema");
    assert!(!validator.is_valid(&invalid_relationship));
    assert!(
        decode_reorganization_draft_slice(
            &serde_json::to_vec(&invalid_relationship).expect("relationship grammar fixture")
        )
        .expect_err("relationship grammar is the released Object Protocol grammar")
        .to_string()
        .contains("lowercase protocol token")
    );
}

#[test]
fn object_protocol_operations_only_target_the_matching_canonical_object_record() {
    let mut draft =
        protocol_json("conformance/reorganization/draft/valid/all-operation-kinds-v1.json");
    draft["operations"][6]["object_record_path"] =
        serde_json::json!(".folderbase/objects/obj_019f9b75-0000-7000-8000-000000000199.json");
    draft["analysis_scope"]["operation_closure"][13]["path"] =
        serde_json::json!(".folderbase/objects/obj_019f9b75-0000-7000-8000-000000000199.json");

    let bytes = serde_json::to_vec(&draft).expect("mismatched object record fixture");
    let error = decode_reorganization_draft_slice(&bytes)
        .expect_err("protocol updates must target the named object's canonical record");

    assert!(
        error.to_string().contains("canonical object record path"),
        "unexpected error: {error}"
    );
}

#[test]
fn core_identity_fields_use_the_reachable_prefixed_uuid_grammars() {
    let mut draft = protocol_json("conformance/reorganization/draft/valid/additive-folder-v1.json");
    draft["folderbase_id"] = serde_json::json!("folderbase_019f9b75-0000-7000-8000-000000000001");
    decode_reorganization_draft_slice(&serde_json::to_vec(&draft).expect("reachable identity"))
        .expect("real Folderbase identity is accepted");

    draft["folderbase_id"] = serde_json::json!("folderbase_example");
    let error = decode_reorganization_draft_slice(
        &serde_json::to_vec(&draft).expect("loose identity fixture"),
    )
    .expect_err("loose prefixed tokens are not real Core identities");

    assert!(
        error
            .to_string()
            .contains("folderbase identifier is invalid")
    );

    let mut tracked =
        protocol_json("conformance/reorganization/draft/valid/all-operation-kinds-v1.json");
    tracked["operations"][5]["object_id"] = serde_json::json!("object_database");
    assert!(
        decode_reorganization_draft_slice(
            &serde_json::to_vec(&tracked).expect("loose object identity fixture")
        )
        .expect_err("object_* is not the released obj_<UUID> grammar")
        .to_string()
        .contains("object identifier is invalid")
    );
    tracked = protocol_json("conformance/reorganization/draft/valid/all-operation-kinds-v1.json");
    tracked["operations"][5]["expected_version_id"] = serde_json::json!("version_database_7");
    assert!(
        decode_reorganization_draft_slice(
            &serde_json::to_vec(&tracked).expect("loose version identity fixture")
        )
        .expect_err("version_* suffix must be a UUID")
        .to_string()
        .contains("version identifier is invalid")
    );
}

#[test]
fn generic_operations_cannot_mutate_reserved_protocol_git_or_root_adapter_paths() {
    let base = protocol_json("conformance/reorganization/draft/valid/additive-folder-v1.json");
    let schema = protocol_json("schemas/0.3/reorganization-draft.schema.json");
    let validator = jsonschema::draft202012::options()
        .build(&schema)
        .expect("compile Draft schema");
    for operation in [
        serde_json::json!({ "kind": "create_directory", "path": ".git/hooks" }),
        serde_json::json!({
            "kind": "create_utf8_file",
            "path": ".folderbase/private.json",
            "content": "{}"
        }),
        serde_json::json!({
            "kind": "replace_utf8_file",
            "path": "FOLDERBASE.md",
            "expected_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "content": "# replaced\n"
        }),
        serde_json::json!({
            "kind": "move_file",
            "source_path": "AGENTS.md",
            "destination_path": "Archive/AGENTS.md",
            "expected_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "expected_byte_count": 1
        }),
    ] {
        let mut draft = base.clone();
        draft["operations"] = serde_json::json!([operation]);
        assert!(
            !validator.is_valid(&draft),
            "public schema must preserve reserved operation paths"
        );
        let error = decode_reorganization_draft_slice(
            &serde_json::to_vec(&draft).expect("reserved-path fixture"),
        )
        .expect_err("generic operation must preserve reserved paths");
        assert!(
            error.to_string().contains("reserved"),
            "unexpected error: {error}"
        );
    }
}

#[test]
fn direct_struct_validation_sealing_and_digesting_enforce_the_aggregate_record_limit() {
    let base = decode_reorganization_draft_slice(include_bytes!(
        "../../../protocol/conformance/reorganization/draft/valid/additive-folder-v1.json"
    ))
    .expect("valid base Draft");
    let oversized_questions = (0..5)
        .map(|index| ConsequentialQuestion {
            id: format!("oversized_{index}"),
            prompt: "x".repeat(2 * 1024 * 1024),
            answer_type: ConsequentialAnswerType::Boolean,
            required: false,
            options: Vec::new(),
            answer: None,
        })
        .collect::<Vec<_>>();

    let mut oversized_draft = base.clone();
    oversized_draft.questions = oversized_questions.clone();
    assert!(
        validate_reorganization_draft(&oversized_draft)
            .expect_err("direct Draft validation must enforce aggregate bytes")
            .to_string()
            .contains("8 MiB")
    );
    assert!(
        seal_reorganization_draft(oversized_draft)
            .expect_err("sealing must stop before cloning oversized state")
            .to_string()
            .contains("8 MiB")
    );

    let mut oversized_plan = seal_reorganization_draft(base).expect("small plan");
    oversized_plan.questions = oversized_questions;
    assert!(
        validate_reorganization_plan(&oversized_plan)
            .expect_err("direct Plan validation must enforce aggregate bytes")
            .to_string()
            .contains("8 MiB")
    );
    assert!(
        reorganization_plan_sha256(&oversized_plan)
            .expect_err("direct Plan digesting must enforce aggregate bytes")
            .to_string()
            .contains("8 MiB")
    );
}

#[test]
fn portable_profiles_reject_unicode_normalization_aliases() {
    let mut draft = protocol_json("conformance/reorganization/draft/valid/additive-folder-v1.json");
    draft["operations"] = serde_json::json!([
        { "kind": "create_directory", "path": "Résumé" },
        { "kind": "create_directory", "path": "Résumé" }
    ]);

    let bytes = serde_json::to_vec(&draft).expect("normalization fixture");
    let error = decode_reorganization_draft_slice(&bytes)
        .expect_err("normalization aliases must be refused");

    assert!(error.to_string().contains("aliases another operation path"));
}

#[test]
fn callers_can_revalidate_mutated_public_records_before_persistence() {
    let draft = decode_reorganization_draft_slice(include_bytes!(
        "../../../protocol/conformance/reorganization/draft/valid/additive-folder-v1.json"
    ))
    .expect("valid Draft");
    validate_reorganization_draft(&draft).expect("public Draft validator");
    let plan = seal_reorganization_draft(draft).expect("sealed Plan");
    validate_reorganization_plan(&plan).expect("public Plan validator");

    let mut forged = plan;
    forged.plan_digest.replace_range(..1, "0");
    assert!(validate_reorganization_plan(&forged).is_err());
}

#[test]
fn canonical_digest_functions_expose_the_cross_client_contract() {
    let plan = decode_reorganization_plan_slice(include_bytes!(
        "../../../protocol/conformance/reorganization/plan/valid/project-cleanup-v1.json"
    ))
    .expect("digest-bound plan");

    assert_eq!(
        reorganization_analysis_scope_sha256(&plan.analysis_scope).expect("scope digest"),
        plan.analysis_scope_digest
    );
    assert_eq!(
        reorganization_plan_sha256(&plan).expect("plan digest"),
        plan.plan_digest
    );
}

#[test]
fn canonical_records_refuse_integers_larger_than_jsons_exact_range() {
    let mut draft = protocol_json("conformance/reorganization/draft/valid/project-cleanup-v1.json");
    let too_large = serde_json::json!(9_007_199_254_740_992_u64);
    draft["analysis_scope"]["operation_closure"][3]["byte_count"] = too_large.clone();
    draft["operations"][1]["expected_byte_count"] = too_large;

    let bytes = serde_json::to_vec(&draft).expect("large integer fixture");
    let error = decode_reorganization_draft_slice(&bytes)
        .expect_err("non-portable JSON integer must be refused");

    assert!(
        error.to_string().contains("canonical JSON integer"),
        "unexpected error: {error}"
    );
}

#[test]
fn v1_refuses_case_only_renames_even_under_a_case_sensitive_profile() {
    let mut draft = protocol_json("conformance/reorganization/draft/valid/additive-folder-v1.json");
    draft["analysis_scope"]["operation_closure"] = serde_json::json!([
      {
        "expectation": "file",
        "path": "Report.pdf",
        "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "byte_count": 20
      },
      { "expectation": "absent", "path": "report.pdf" }
    ]);
    draft["operations"] = serde_json::json!([
      {
        "kind": "move_file",
        "source_path": "Report.pdf",
        "destination_path": "report.pdf",
        "expected_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "expected_byte_count": 20
      }
    ]);

    let bytes = serde_json::to_vec(&draft).expect("case-only fixture");
    let error =
        decode_reorganization_draft_slice(&bytes).expect_err("case-only rename must be refused");

    assert!(error.to_string().contains("case-only rename"));
}

#[test]
fn unknown_plan_profiles_are_refused_before_digest_or_mutation_semantics() {
    let mut value = protocol_json("conformance/reorganization/plan/valid/project-cleanup-v1.json");
    value["profile"] = serde_json::json!("folderbase-reorganization-plan-v2");

    let bytes = serde_json::to_vec(&value).expect("future-profile fixture");
    let error =
        decode_reorganization_plan_slice(&bytes).expect_err("unknown Plan profile must be refused");

    assert!(
        error
            .to_string()
            .contains("unsupported reorganization plan profile")
    );
}

#[test]
fn a_created_parent_directory_must_precede_its_child_operation() {
    let mut draft = protocol_json("conformance/reorganization/draft/valid/additive-folder-v1.json");
    draft["analysis_scope"]["operation_closure"] = serde_json::json!([
      { "expectation": "absent", "path": "Current" },
      { "expectation": "absent", "path": "Current/SUMMARY.md" }
    ]);
    draft["operations"] = serde_json::json!([
      {
        "kind": "create_utf8_file",
        "path": "Current/SUMMARY.md",
        "content": "# Current\n"
      },
      { "kind": "create_directory", "path": "Current" }
    ]);

    let bytes = serde_json::to_vec(&draft).expect("misordered fixture");
    let error = decode_reorganization_draft_slice(&bytes)
        .expect_err("created parent must precede child use");

    assert!(
        error
            .to_string()
            .contains("created parent directory must precede")
    );
}

#[test]
fn ignore_policy_snapshot_is_an_exact_file_or_absence_fact() {
    let mut draft = protocol_json("conformance/reorganization/draft/valid/additive-folder-v1.json");
    draft["analysis_scope"]["ignore_policy"] = serde_json::json!({
      "expectation": "directory",
      "path": ".folderbaseignore"
    });

    let bytes = serde_json::to_vec(&draft).expect("invalid policy fact");
    let error =
        decode_reorganization_draft_slice(&bytes).expect_err("policy path cannot be a directory");

    assert!(error.to_string().contains("file or absence fact"));
}

#[test]
fn schema_integer_lexemes_decode_to_the_exact_canonical_integer_model() {
    let relative = "conformance/reorganization/draft/valid/mathematical-integers-v1.json";
    let fixture = protocol_json(relative);
    let schema = protocol_json("schemas/0.3/reorganization-draft.schema.json");
    let validator = jsonschema::draft202012::options()
        .build(&schema)
        .expect("compile public Draft schema");
    assert!(
        validator.is_valid(&fixture),
        "decimal and exponent lexemes are mathematical integers"
    );
    let bytes = std::fs::read(protocol_root().join(relative)).expect("raw integer vector");

    let draft = decode_reorganization_draft_slice(&bytes)
        .expect("schema-valid mathematical integers decode");

    assert_eq!(draft.generation, 1);
    assert_eq!(draft.operations.len(), 2);
}

#[test]
fn schema_max_length_and_runtime_count_unicode_code_points_the_same_way() {
    let mut draft = protocol_json("conformance/reorganization/draft/valid/additive-folder-v1.json");
    draft["operations"] = serde_json::json!([
      {
        "kind": "create_utf8_file",
        "path": "Current.md",
        "content": "é".repeat(1_100_000)
      }
    ]);
    draft["analysis_scope"]["operation_closure"] = serde_json::json!([
      { "expectation": "absent", "path": "Current.md" }
    ]);
    let schema = protocol_json("schemas/0.3/reorganization-draft.schema.json");
    let validator = jsonschema::draft202012::options()
        .build(&schema)
        .expect("compile public Draft schema");
    assert!(
        validator.is_valid(&draft),
        "1.1M code points are below the public maxLength"
    );
    let bytes = serde_json::to_vec(&draft).expect("Unicode-length fixture");

    decode_reorganization_draft_slice(&bytes)
        .expect("runtime must use the same code-point length rule");
}

#[test]
fn set_like_fields_are_normalized_before_sealing_and_digesting() {
    let mut draft = decode_reorganization_draft_slice(include_bytes!(
        "../../../protocol/conformance/reorganization/draft/valid/project-cleanup-v1.json"
    ))
    .expect("valid Draft");
    draft
        .template_references
        .push("folderbase.custom@0.2.0".to_owned());
    draft.analysis_scope.nested_boundaries = vec![
        NestedBoundary {
            path: "Clients/B".to_owned(),
            manifest_sha256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                .to_owned(),
        },
        NestedBoundary {
            path: "Clients/A".to_owned(),
            manifest_sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_owned(),
        },
    ];
    draft
        .analysis_scope
        .declared_entries
        .push(ScopeEntry::Absent {
            path: "Notes/future.md".to_owned(),
        });
    let mut reordered = draft.clone();
    reordered.template_references.reverse();
    reordered.analysis_scope.nested_boundaries.reverse();
    reordered.analysis_scope.operation_closure.reverse();
    reordered.analysis_scope.declared_entries.reverse();

    let baseline = seal_reorganization_draft(draft).expect("baseline seals");
    let reordered = seal_reorganization_draft(reordered).expect("reordered sets seal");

    assert_eq!(
        baseline.analysis_scope_digest,
        reordered.analysis_scope_digest
    );
    assert_eq!(baseline.plan_digest, reordered.plan_digest);
    assert_eq!(baseline.analysis_scope, reordered.analysis_scope);
    assert_eq!(baseline.template_references, reordered.template_references);
}

#[test]
fn preexisting_sources_cannot_live_below_a_directory_the_plan_creates() {
    let mut draft = protocol_json("conformance/reorganization/draft/valid/additive-folder-v1.json");
    draft["analysis_scope"]["operation_closure"] = serde_json::json!([
      { "expectation": "directory", "path": "Archive" },
      { "expectation": "absent", "path": "Archive/input.pdf" },
      { "expectation": "absent", "path": "Current" },
      {
        "expectation": "file",
        "path": "Current/input.pdf",
        "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "byte_count": 20
      }
    ]);
    draft["operations"] = serde_json::json!([
      { "kind": "create_directory", "path": "Current" },
      {
        "kind": "move_file",
        "source_path": "Current/input.pdf",
        "destination_path": "Archive/input.pdf",
        "expected_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "expected_byte_count": 20
      }
    ]);

    let bytes = serde_json::to_vec(&draft).expect("impossible source fixture");
    let error = decode_reorganization_draft_slice(&bytes)
        .expect_err("an absent parent cannot contain a preexisting source");

    assert!(
        error
            .to_string()
            .contains("preexisting source cannot be below")
    );
}

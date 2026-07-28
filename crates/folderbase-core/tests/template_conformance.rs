use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

use folderbase_core::{TemplatePackage, template_package_sha256};
use semver::Version;
use serde_json::Value;

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

fn schema_accepts(schema_relative: &str, fixture_relative: &str) -> bool {
    let schema = read_json(schema_relative);
    let fixture = read_json(fixture_relative);
    jsonschema::draft202012::options()
        .should_validate_formats(true)
        .build(&schema)
        .unwrap_or_else(|error| panic!("compile {schema_relative}: {error}"))
        .is_valid(&fixture)
}

fn template_semantic_errors(template: &Value) -> Vec<String> {
    let mut errors = Vec::new();

    let mut targets = BTreeSet::new();
    for target in template
        .get("artifacts")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|artifact| artifact.get("target").and_then(Value::as_str))
    {
        let canonical = target.to_lowercase();
        if !targets.insert(canonical) {
            errors.push(format!("duplicate artifact target: {target}"));
        }
    }

    let package_version = template.get("version").and_then(Value::as_str);
    let edges = template
        .get("upgrade_edges")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut graph: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for edge in &edges {
        let Some(from) = edge.get("from").and_then(Value::as_str) else {
            continue;
        };
        let Some(to) = edge.get("to").and_then(Value::as_str) else {
            continue;
        };
        graph.entry(from).or_default().push(to);
        if Some(to) != package_version {
            errors.push(format!(
                "upgrade edge destination {to} does not match package version"
            ));
        }
        if semantic_version(from) >= semantic_version(to) {
            errors.push(format!("upgrade edge does not advance: {from} -> {to}"));
        }
    }
    if graph_has_cycle(&graph) {
        errors.push("upgrade graph contains a cycle".to_owned());
    }

    errors
}

fn semantic_version(version: &str) -> Option<Version> {
    Version::parse(version).ok()
}

fn graph_has_cycle(graph: &BTreeMap<&str, Vec<&str>>) -> bool {
    fn visit<'a>(
        node: &'a str,
        graph: &BTreeMap<&'a str, Vec<&'a str>>,
        visiting: &mut BTreeSet<&'a str>,
        visited: &mut BTreeSet<&'a str>,
    ) -> bool {
        if visited.contains(node) {
            return false;
        }
        if !visiting.insert(node) {
            return true;
        }
        if graph.get(node).is_some_and(|neighbors| {
            neighbors
                .iter()
                .any(|neighbor| visit(neighbor, graph, visiting, visited))
        }) {
            return true;
        }
        visiting.remove(node);
        visited.insert(node);
        false
    }

    let mut visiting = BTreeSet::new();
    let mut visited = BTreeSet::new();
    graph
        .keys()
        .any(|node| visit(node, graph, &mut visiting, &mut visited))
}

fn template_conforms(fixture_relative: &str) -> bool {
    if !schema_accepts("schemas/0.2/template.schema.json", fixture_relative) {
        return false;
    }
    template_semantic_errors(&read_json(fixture_relative)).is_empty()
}

const STARTER_TEMPLATES: [(&str, &str); 7] = [
    ("person", "templates/0.2/person/template.json"),
    ("organization", "templates/0.2/organization/template.json"),
    ("engagement", "templates/0.2/engagement/template.json"),
    ("project", "templates/0.2/project-0.2.2/template.json"),
    ("customer", "templates/0.2/customer/template.json"),
    ("temporary", "templates/0.2/temporary/template.json"),
    ("custom", "templates/0.2/custom/template.json"),
];

#[test]
fn every_builtin_template_conforms() {
    for (kind, relative) in STARTER_TEMPLATES {
        assert!(
            template_conforms(relative),
            "{kind} starter template must conform to Template Protocol 0.2"
        );
        assert_eq!(
            read_json(relative)["suggested_folderbase_kind"],
            kind,
            "{kind} starter template must suggest its own kind"
        );
    }
}

#[test]
fn all_template_kinds_preserve_same_permission_invariants() {
    const AUTHORITY_FIELDS: [&str; 8] = [
        "permissions",
        "members",
        "membership",
        "grants",
        "shares",
        "hooks",
        "scripts",
        "commands",
    ];

    for (kind, relative) in STARTER_TEMPLATES {
        let template = read_json(relative);
        for field in AUTHORITY_FIELDS {
            assert!(
                template.get(field).is_none(),
                "{kind} starter template must not declare {field}"
            );
        }
        assert!(
            template["artifacts"]
                .as_array()
                .expect("starter artifacts")
                .iter()
                .all(|artifact| artifact["install"] == "create_if_missing"),
            "{kind} starter guidance must use no-clobber installation"
        );
    }
}

#[test]
fn custom_template_cannot_weaken_protocol_guardrails() {
    let schema = read_json("schemas/0.2/template.schema.json");
    let mut forged = read_json("templates/0.2/custom/template.json");
    forged["permissions"] = serde_json::json!({
        "members": ["everyone"],
        "access": "owner"
    });

    let validator = jsonschema::draft202012::options()
        .should_validate_formats(true)
        .build(&schema)
        .expect("compile Template Protocol 0.2 schema");

    assert!(
        !validator.is_valid(&forged),
        "custom starting guidance must not acquire authority fields"
    );
}

#[test]
fn customer_context_requires_an_explicit_boundary_reason() {
    let customer = read_json("templates/0.2/customer/template.json");
    let boundary_question = customer["questions"]
        .as_array()
        .expect("customer questions")
        .iter()
        .find(|question| question["id"] == "boundary_reason")
        .expect("customer boundary decision question");
    assert_eq!(boundary_question["answer_type"], "text");
    assert_eq!(boundary_question["required"], true);

    let folderbase_entry = customer["artifacts"]
        .as_array()
        .expect("customer artifacts")
        .iter()
        .find(|artifact| artifact["target"] == "FOLDERBASE.md")
        .expect("customer FOLDERBASE.md");
    assert!(
        folderbase_entry["content"]
            .as_str()
            .expect("customer folderbase entry")
            .contains("${boundary_reason}"),
        "the approved boundary reason must remain visible after creation"
    );
}

#[test]
fn data_only_project_template_conforms_to_v02() {
    let built_in = "templates/0.2/project/template.json";
    let conformance_fixture = "conformance/template/valid/project-0.2.0.json";
    assert!(template_conforms(built_in));
    assert!(template_conforms(conformance_fixture));
    assert_eq!(read_json(built_in), read_json(conformance_fixture));
    assert!(template_conforms(
        "conformance/template/valid/prerelease-upgrade-0.2.0.json"
    ));
}

#[test]
fn canonical_package_digest_matches_the_protocol_vector() {
    let fixture = protocol_root().join("conformance/template/valid/digest-vector-0.2.0.json");
    let package: TemplatePackage = serde_json::from_slice(
        &fs::read(&fixture).unwrap_or_else(|error| panic!("read {}: {error}", fixture.display())),
    )
    .expect("digest-vector template");
    let expected_path =
        protocol_root().join("conformance/template/valid/digest-vector-0.2.0.sha256");
    let expected = fs::read_to_string(&expected_path)
        .unwrap_or_else(|error| panic!("read {}: {error}", expected_path.display()));

    assert_eq!(
        template_package_sha256(&package).expect("canonical package digest"),
        expected.trim()
    );
    assert!(template_conforms(
        "conformance/template/valid/digest-vector-0.2.0.json"
    ));
}

#[test]
fn project_template_declares_typed_answers_and_explicit_interpolation() {
    let project = read_json("templates/0.2/project-0.2.1/template.json");
    let questions = project["questions"].as_array().expect("questions");
    let typed_questions = questions
        .iter()
        .map(|question| {
            (
                question["id"].as_str().expect("question id"),
                question["answer_type"].as_str().expect("answer type"),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        typed_questions,
        vec![
            ("purpose", "text"),
            ("current_state", "text"),
            ("next_action", "text")
        ]
    );

    let folderbase_entry = project["artifacts"]
        .as_array()
        .expect("artifacts")
        .iter()
        .find(|artifact| artifact["target"] == "FOLDERBASE.md")
        .expect("folderbase entry artifact");
    assert_eq!(
        folderbase_entry["content"],
        "# Folderbase\n\n## Purpose\n${purpose}\n\n## Current state\n${current_state}\n\n## Next action\n${next_action}\n"
    );
    assert!(template_conforms(
        "templates/0.2/project-0.2.1/template.json"
    ));
}

#[test]
fn v02_rejects_unsafe_artifact_paths_and_executable_hooks() {
    assert!(!template_conforms(
        "conformance/template/invalid/unsafe-artifact-path.json"
    ));
    assert!(!template_conforms(
        "conformance/template/invalid/absolute-artifact-path.json"
    ));
    assert!(!template_conforms(
        "conformance/template/invalid/backslash-artifact-path.json"
    ));
    assert!(!template_conforms(
        "conformance/template/invalid/trailing-slash-artifact-path.json"
    ));
    assert!(!template_conforms(
        "conformance/template/invalid/executable-hook.json"
    ));
}

#[test]
fn v02_rejects_duplicate_artifact_targets() {
    assert!(!template_conforms(
        "conformance/template/invalid/duplicate-artifact-target.json"
    ));
}

#[test]
fn v02_rejects_cyclic_and_unsupported_upgrade_edges() {
    let cyclic = "conformance/template/invalid/cyclic-upgrade-edges.json";
    assert!(!template_conforms(cyclic));
    assert!(
        template_semantic_errors(&read_json(cyclic))
            .iter()
            .any(|error| error == "upgrade graph contains a cycle")
    );

    let unsupported = "conformance/template/invalid/unsupported-upgrade-edge.json";
    assert!(!template_conforms(unsupported));
    assert!(
        template_semantic_errors(&read_json(unsupported))
            .iter()
            .any(|error| error.contains("does not match package version"))
    );
}

#[test]
fn template_kind_cannot_declare_permissions_or_membership() {
    assert!(!template_conforms(
        "conformance/template/invalid/organization-authority.json"
    ));
}

#[test]
fn template_provenance_is_optional_and_does_not_lock_current_layout_or_kind() {
    assert!(schema_accepts(
        "schemas/0.2/folderbase.schema.json",
        "conformance/manifest/valid/v02-with-template-provenance.json"
    ));
    assert!(schema_accepts(
        "schemas/0.2/folderbase.schema.json",
        "conformance/manifest/valid/v02-without-template-provenance.json"
    ));
}

#[test]
fn protocol_v01_manifests_and_unknown_fields_remain_readable() {
    assert!(schema_accepts(
        "schemas/0.1/folderbase.schema.json",
        "conformance/manifest/valid/v01-with-unknown-fields.json"
    ));
}

#[test]
fn verified_template_application_records_conform_to_v02() {
    assert!(schema_accepts(
        "schemas/0.2/template-application.schema.json",
        "conformance/template-application/valid/additive-project-1.1.0.json"
    ));
    assert!(!schema_accepts(
        "schemas/0.2/template-application.schema.json",
        "conformance/template-application/invalid/unverified-record.json"
    ));
}

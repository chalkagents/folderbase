use std::{
    fs,
    path::{Path, PathBuf},
    process::Command as ProcessCommand,
};

use assert_cmd::Command;

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn folderbase() -> Command {
    Command::cargo_bin("folderbase").expect("the workspace must build a folderbase executable")
}

fn template_documents(root: &Path) -> Vec<PathBuf> {
    fn visit(directory: &Path, documents: &mut Vec<PathBuf>) {
        for entry in fs::read_dir(directory)
            .unwrap_or_else(|error| panic!("read {}: {error}", directory.display()))
        {
            let entry = entry.expect("template directory entry");
            let path = entry.path();
            let file_type = entry
                .file_type()
                .unwrap_or_else(|error| panic!("inspect {}: {error}", path.display()));
            if file_type.is_dir() {
                visit(&path, documents);
            } else if file_type.is_file()
                && path.file_name().is_some_and(|name| name == "template.json")
            {
                documents.push(path);
            }
        }
    }

    let mut documents = Vec::new();
    visit(root, &mut documents);
    documents.sort();
    documents
}

#[test]
fn cargo_and_executable_surface_is_folderbase_only() {
    let output = ProcessCommand::new(env!("CARGO"))
        .args(["metadata", "--format-version", "1", "--no-deps"])
        .current_dir(workspace_root())
        .output()
        .expect("run cargo metadata");
    assert!(
        output.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let metadata: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("cargo metadata JSON");
    let mut package_names = metadata["packages"]
        .as_array()
        .expect("workspace packages")
        .iter()
        .map(|package| package["name"].as_str().expect("package name"))
        .collect::<Vec<_>>();
    package_names.sort_unstable();
    assert_eq!(package_names, ["folderbase-cli", "folderbase-core"]);

    let core = metadata["packages"]
        .as_array()
        .expect("workspace packages")
        .iter()
        .find(|package| package["name"] == "folderbase-core")
        .expect("folderbase-core package");
    assert!(
        core["targets"]
            .as_array()
            .expect("core targets")
            .iter()
            .any(|target| target["name"] == "folderbase_core"
                && target["kind"]
                    .as_array()
                    .is_some_and(|kinds| kinds.iter().any(|kind| kind == "lib"))),
        "folderbase-core must expose the folderbase_core library crate"
    );

    let cli = metadata["packages"]
        .as_array()
        .expect("workspace packages")
        .iter()
        .find(|package| package["name"] == "folderbase-cli")
        .expect("folderbase-cli package");
    assert!(
        cli["targets"]
            .as_array()
            .expect("CLI targets")
            .iter()
            .any(|target| target["name"] == "folderbase"
                && target["kind"]
                    .as_array()
                    .is_some_and(|kinds| kinds.iter().any(|kind| kind == "bin"))),
        "folderbase-cli must expose the folderbase binary"
    );

    folderbase()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicates::str::starts_with("folderbase "));
}

#[test]
fn init_materializes_only_the_folderbase_protocol_surface() {
    let root = tempfile::tempdir().expect("ordinary folder");

    let assertion = folderbase()
        .args([
            "init",
            root.path().to_str().expect("UTF-8 temporary path"),
            "--template",
            "folderbase.project@0.2.2",
            "--answer",
            "purpose=Prove the public Folderbase adoption contract.",
            "--answer",
            "current_state=The acceptance test is red.",
            "--answer",
            "next_action=Implement the full eclipse.",
            "--json",
        ])
        .assert()
        .success();
    let result: serde_json::Value =
        serde_json::from_slice(&assertion.get_output().stdout).expect("initialization JSON");
    assert!(
        result["folderbase_id"]
            .as_str()
            .is_some_and(|id| id.starts_with("folderbase_")),
        "initialization must return a folderbase_ identity"
    );

    let state_root = root.path().join(".folderbase");
    let manifest_path = state_root.join("manifest.json");
    assert!(state_root.is_dir(), ".folderbase must be a directory");
    assert!(
        manifest_path.is_file(),
        ".folderbase/manifest.json must be created"
    );
    assert!(
        !root.path().join(".folderbaseignore").exists(),
        ".folderbaseignore remains optional unless the selected template explicitly adds it"
    );
    assert!(
        root.path().join("FOLDERBASE.md").is_file(),
        "FOLDERBASE.md must be created"
    );

    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(&manifest_path).expect("read manifest"))
            .expect("manifest JSON");
    assert_eq!(
        manifest["$schema"],
        "https://folderbase.ai/protocol/0.5/folderbase.schema.json"
    );
    assert!(
        manifest["folderbase"]["id"]
            .as_str()
            .is_some_and(|id| id.starts_with("folderbase_"))
    );
    assert!(
        manifest["folderbase"].get("entry").is_none(),
        "template-created FOLDERBASE.md is ordinary guidance, not root authority"
    );
    assert_eq!(
        manifest["folderbase"]["template_provenance"]["id"],
        "folderbase.project"
    );

    assert_eq!(manifest["adapters"], serde_json::json!([]));
    for adapter_path in ["AGENTS.md", "CLAUDE.md"] {
        assert!(
            !root.path().join(adapter_path).exists(),
            "{adapter_path} remains opt-in"
        );
    }

    let former_state = format!(".{}{}", "tenth", "brain");
    let former_entry = format!("{}{}.md", "BRA", "IN");
    assert!(!root.path().join(former_state).exists());
    assert!(!root.path().join(former_entry).exists());
}

#[test]
fn protocol_schemas_and_templates_are_folderbase_native() {
    let protocol = workspace_root().join("protocol");

    for version in ["0.1", "0.2", "0.5"] {
        let schema_path = protocol
            .join("schemas")
            .join(version)
            .join("folderbase.schema.json");
        let schema: serde_json::Value =
            serde_json::from_slice(&fs::read(&schema_path).unwrap_or_else(|error| {
                panic!("read expected schema {}: {error}", schema_path.display())
            }))
            .expect("schema JSON");
        assert_eq!(
            schema["$id"],
            format!("https://folderbase.ai/protocol/{version}/folderbase.schema.json")
        );
        assert!(
            schema["properties"].get("folderbase").is_some(),
            "manifest schema must define the folderbase record"
        );
    }

    let templates = template_documents(&protocol.join("templates/0.2"));
    assert!(!templates.is_empty(), "shipped template registry is empty");
    for path in templates {
        let package: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).expect("read template"))
                .expect("template JSON");
        assert!(
            package["id"]
                .as_str()
                .is_some_and(|id| id.starts_with("folderbase.")),
            "{} must use a folderbase.* package ID",
            path.display()
        );
        let artifact_targets = package["artifacts"]
            .as_array()
            .expect("template artifacts")
            .iter()
            .filter_map(|artifact| artifact["target"].as_str())
            .collect::<Vec<_>>();
        assert!(
            artifact_targets.contains(&"FOLDERBASE.md"),
            "{} must provide FOLDERBASE.md",
            path.display()
        );
    }
}

use std::fs;
use std::path::{Component, Path};

use folderbase_core::{Classification, FolderbaseError, inspect};
use tempfile::tempdir;

#[test]
fn inspection_is_deterministic_relative_and_metadata_only() {
    let fixture = tempdir().unwrap();
    let root = fixture.path().join("project");
    fs::create_dir_all(root.join("target")).unwrap();
    fs::create_dir_all(root.join("tmp")).unwrap();
    fs::create_dir_all(root.join("repo/.git")).unwrap();
    fs::create_dir_all(root.join("repo/src")).unwrap();
    fs::create_dir_all(root.join("Commercial-Restricted")).unwrap();

    fs::write(root.join("README.md"), "one").unwrap();
    fs::write(root.join("target/bundle.js"), "generated").unwrap();
    fs::write(root.join(".env.local"), "ignored").unwrap();
    fs::write(root.join("tmp/notes.swp"), "temp").unwrap();
    fs::write(root.join("Proposal_v2.md"), "draft").unwrap();
    fs::write(root.join("repo/.git/config"), "git internals").unwrap();
    fs::write(root.join("repo/AGENTS.md"), "agents").unwrap();
    fs::write(root.join("repo/src/lib.rs"), "ok").unwrap();
    fs::write(root.join("Commercial-Restricted/api_key.txt"), "fake").unwrap();
    let large = fs::File::create(root.join("reference.mov")).unwrap();
    large.set_len(100 * 1024 * 1024).unwrap();

    #[cfg(unix)]
    {
        let outside = fixture.path().join("outside");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("must-not-count.txt"), "outside").unwrap();
        std::os::unix::fs::symlink(&outside, root.join("linked-outside")).unwrap();
    }

    let first = inspect(&root).unwrap();
    let second = inspect(&root).unwrap();
    assert_eq!(first, second);

    assert_eq!(first.inventory.file_count, 8);
    assert_eq!(first.inventory.generated_file_count, 0);
    assert_eq!(first.inventory.reconstructable_tree_count, 1);
    assert_eq!(first.inventory.secret_shaped_file_count, 2);
    assert_eq!(first.inventory.temporary_file_count, 1);
    assert_eq!(first.inventory.large_file_count, 1);
    assert_eq!(first.inventory.versioned_file_count, 1);
    assert_eq!(first.git_repositories, vec![Path::new("repo")]);
    assert_eq!(
        first.context_files,
        vec![Path::new("README.md"), Path::new("repo/AGENTS.md")]
    );

    assert_eq!(first.reconstructable_trees[0].path, Path::new("target"));
    assert!(first.classified_paths.iter().any(|item| {
        item.path == Path::new(".env.local") && item.classification == Classification::SecretShaped
    }));
    assert!(first.classified_paths.iter().any(|item| {
        item.path == Path::new("Commercial-Restricted/api_key.txt")
            && item.classification == Classification::SecretShaped
    }));
    assert!(first.classified_paths.iter().any(|item| {
        item.path == Path::new("Proposal_v2.md") && item.classification == Classification::Versioned
    }));
    assert!(first.boundary_hints.iter().any(|hint| {
        hint.path == Path::new("Commercial-Restricted") && hint.kind == "permission"
    }));

    for path in first
        .classified_paths
        .iter()
        .map(|item| item.path.as_path())
        .chain(first.git_repositories.iter().map(|path| path.as_path()))
        .chain(first.context_files.iter().map(|path| path.as_path()))
        .chain(first.boundary_hints.iter().map(|hint| hint.path.as_path()))
    {
        assert!(!path.is_absolute());
        assert!(!path.components().any(|component| matches!(
            component,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        )));
    }

    #[cfg(unix)]
    assert!(
        first
            .warnings
            .iter()
            .any(|warning| warning.contains("linked-outside"))
    );
}

#[test]
fn fixture_report_is_deterministic_and_contains_no_secret_contents() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/client-company-2-shaped-unmanaged")
        .canonicalize()
        .unwrap();

    let first = inspect(&root).unwrap();
    let second = inspect(&root).unwrap();
    let first_json = serde_json::to_string_pretty(&first).unwrap();
    let second_json = serde_json::to_string_pretty(&second).unwrap();

    assert_eq!(first_json, second_json);
    assert_eq!(first.inventory.file_count, 39);
    assert_eq!(first.inventory.reconstructable_tree_count, 5);
    assert!(!first_json.contains("FAKE_DO_NOT_USE_FOLDERBASE_FIXTURE_API_KEY"));
    assert!(!first_json.contains("FOLDERBASE_FIXTURE_TOKEN=FAKE_DO_NOT_USE"));
}

#[test]
fn inspection_rejects_missing_files_and_symlink_roots() {
    let fixture = tempdir().unwrap();
    let missing = fixture.path().join("missing");
    assert!(matches!(
        inspect(&missing),
        Err(FolderbaseError::InvalidRoot(path)) if path == missing
    ));

    let file = fixture.path().join("file.txt");
    fs::write(&file, "not a directory").unwrap();
    assert!(matches!(
        inspect(&file),
        Err(FolderbaseError::InvalidRoot(path)) if path == file
    ));

    #[cfg(unix)]
    {
        let directory = fixture.path().join("directory");
        let link = fixture.path().join("directory-link");
        fs::create_dir(&directory).unwrap();
        std::os::unix::fs::symlink(&directory, &link).unwrap();
        assert!(matches!(
            inspect(&link),
            Err(FolderbaseError::InvalidRoot(path)) if path == link
        ));
    }
}

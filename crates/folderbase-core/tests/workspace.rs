use std::{
    fs,
    path::PathBuf,
    sync::{Arc, Barrier},
    thread,
};

use folderbase_core::{
    JournalAction, LocalVersionStore, MAX_WORKSPACE_TEXT_BYTES, WorkspaceEntryKind, list_workspace,
    read_workspace_text, save_workspace_text,
};
use tempfile::tempdir;

#[cfg(unix)]
use std::os::unix::fs::symlink;

#[test]
fn workspace_listing_keeps_reconstructable_directories_visible_but_collapsed() {
    let fixture = tempdir().unwrap();
    fs::create_dir_all(fixture.path().join("docs")).unwrap();
    fs::create_dir_all(fixture.path().join("node_modules/pkg")).unwrap();
    fs::create_dir_all(fixture.path().join("target/debug")).unwrap();
    fs::create_dir_all(fixture.path().join(".git/objects")).unwrap();
    fs::create_dir_all(fixture.path().join(".folderbase/objects")).unwrap();
    fs::write(fixture.path().join("FOLDERBASE.md"), "folderbase\n").unwrap();
    fs::write(fixture.path().join("docs/notes.md"), "notes\n").unwrap();
    fs::write(
        fixture.path().join("node_modules/pkg/index.js"),
        "generated\n",
    )
    .unwrap();
    fs::write(fixture.path().join("target/debug/app"), "generated\n").unwrap();
    fs::write(fixture.path().join(".git/objects/internal"), "git\n").unwrap();
    fs::write(
        fixture.path().join(".folderbase/objects/internal"),
        "protocol\n",
    )
    .unwrap();

    #[cfg(unix)]
    symlink("docs", fixture.path().join("linked-docs")).unwrap();

    let listing = list_workspace(fixture.path()).unwrap();

    assert_eq!(listing.root, fixture.path().canonicalize().unwrap());
    let observed = listing
        .entries
        .iter()
        .map(|entry| {
            (
                entry.path.as_str(),
                entry.name.as_str(),
                entry.kind,
                entry.bytes,
                entry.editable,
                entry.reconstructable,
            )
        })
        .collect::<Vec<_>>();

    #[cfg(unix)]
    assert_eq!(
        observed,
        vec![
            (
                "FOLDERBASE.md",
                "FOLDERBASE.md",
                WorkspaceEntryKind::File,
                11,
                true,
                false,
            ),
            (
                "docs",
                "docs",
                WorkspaceEntryKind::Directory,
                0,
                false,
                false,
            ),
            (
                "docs/notes.md",
                "notes.md",
                WorkspaceEntryKind::File,
                6,
                true,
                false,
            ),
            (
                "linked-docs",
                "linked-docs",
                WorkspaceEntryKind::Symlink,
                0,
                false,
                false,
            ),
            (
                "node_modules",
                "node_modules",
                WorkspaceEntryKind::Directory,
                0,
                false,
                true,
            ),
            (
                "target",
                "target",
                WorkspaceEntryKind::Directory,
                0,
                false,
                true,
            ),
        ]
    );

    #[cfg(not(unix))]
    assert_eq!(
        observed,
        vec![
            (
                "FOLDERBASE.md",
                "FOLDERBASE.md",
                WorkspaceEntryKind::File,
                11,
                true,
                false,
            ),
            (
                "docs",
                "docs",
                WorkspaceEntryKind::Directory,
                0,
                false,
                false,
            ),
            (
                "docs/notes.md",
                "notes.md",
                WorkspaceEntryKind::File,
                6,
                true,
                false,
            ),
            (
                "node_modules",
                "node_modules",
                WorkspaceEntryKind::Directory,
                0,
                false,
                true,
            ),
            (
                "target",
                "target",
                WorkspaceEntryKind::Directory,
                0,
                false,
                true,
            ),
        ]
    );
}

#[test]
fn rust_swift_javascript_and_python_generated_roots_are_explicit_collapsed_entries() {
    let fixture = tempdir().unwrap();
    let generated_roots = [
        ".build",
        ".next",
        ".swiftpm",
        ".venv",
        "DerivedData",
        "__pycache__",
        "node_modules",
        "target",
    ];
    for root in generated_roots {
        fs::create_dir_all(fixture.path().join(root).join("cache")).unwrap();
        fs::write(
            fixture.path().join(root).join("cache/artifact.txt"),
            "generated\n",
        )
        .unwrap();
    }

    let listing = list_workspace(fixture.path()).unwrap();
    assert_eq!(
        listing
            .entries
            .iter()
            .map(|entry| (entry.path.as_str(), entry.kind, entry.reconstructable,))
            .collect::<Vec<_>>(),
        vec![
            (".build", WorkspaceEntryKind::Directory, true),
            (".next", WorkspaceEntryKind::Directory, true),
            (".swiftpm", WorkspaceEntryKind::Directory, true),
            (".venv", WorkspaceEntryKind::Directory, true),
            ("DerivedData", WorkspaceEntryKind::Directory, true),
            ("__pycache__", WorkspaceEntryKind::Directory, true),
            ("node_modules", WorkspaceEntryKind::Directory, true),
            ("target", WorkspaceEntryKind::Directory, true),
        ]
    );
    for root in generated_roots {
        assert_eq!(
            read_workspace_text(
                fixture.path(),
                PathBuf::from(root).join("cache/artifact.txt")
            )
            .unwrap()
            .content,
            "generated\n"
        );
    }
}

#[test]
fn workspace_listing_exposes_a_nested_folderbase_root_without_entering_its_boundary() {
    let fixture = tempdir().unwrap();
    fs::create_dir_all(fixture.path().join("client/.folderbase")).unwrap();
    fs::write(
        fixture.path().join("client/.folderbase/manifest.json"),
        "{}\n",
    )
    .unwrap();
    fs::write(
        fixture.path().join("client/FOLDERBASE.md"),
        "client folderbase\n",
    )
    .unwrap();
    fs::write(fixture.path().join("client/private.md"), "private\n").unwrap();
    fs::write(fixture.path().join("root.md"), "root\n").unwrap();

    let listing = list_workspace(fixture.path()).unwrap();
    assert_eq!(
        listing
            .entries
            .iter()
            .map(|entry| entry.path.as_str())
            .collect::<Vec<_>>(),
        vec!["client", "root.md"]
    );
    assert_eq!(listing.entries[0].kind, WorkspaceEntryKind::Folderbase);
}

#[test]
fn nested_folderbase_boundary_overrides_a_reconstructable_directory_name() {
    let fixture = tempdir().unwrap();
    fs::create_dir_all(fixture.path().join("node_modules/.folderbase")).unwrap();
    fs::write(
        fixture
            .path()
            .join("node_modules/.folderbase/manifest.json"),
        "{}\n",
    )
    .unwrap();
    fs::write(
        fixture.path().join("node_modules/FOLDERBASE.md"),
        "dependency folderbase\n",
    )
    .unwrap();
    fs::write(
        fixture.path().join("node_modules/canonical.md"),
        "must not be treated as generated\n",
    )
    .unwrap();

    let listing = list_workspace(fixture.path()).unwrap();
    assert_eq!(listing.entries.len(), 1);
    assert_eq!(listing.entries[0].path, "node_modules");
    assert_eq!(listing.entries[0].kind, WorkspaceEntryKind::Folderbase);
    assert!(!listing.entries[0].reconstructable);
}

#[test]
fn nested_folderbase_discovery_case_folds_markers_without_following_state_symlinks() {
    let fixture = tempdir().unwrap();
    fs::create_dir_all(fixture.path().join("casefolded/.FOLDERBASE")).unwrap();
    fs::write(
        fixture.path().join("casefolded/FOLDERBASE.MD"),
        "case-folded folderbase\n",
    )
    .unwrap();
    fs::write(
        fixture.path().join("casefolded/.FOLDERBASE/MANIFEST.JSON"),
        "malformed\n",
    )
    .unwrap();
    fs::write(
        fixture.path().join("casefolded/private.md"),
        "must stay behind the boundary\n",
    )
    .unwrap();

    fs::create_dir(fixture.path().join("ordinary")).unwrap();
    fs::write(
        fixture.path().join("ordinary/FOLDERBASE.MD"),
        "entry without manifest\n",
    )
    .unwrap();
    fs::write(fixture.path().join("ordinary/private.md"), "ordinary\n").unwrap();

    #[cfg(unix)]
    {
        fs::create_dir(fixture.path().join("symlink-marker")).unwrap();
        fs::write(
            fixture.path().join("symlink-marker/FOLDERBASE.md"),
            "invalid nested folderbase\n",
        )
        .unwrap();
        symlink(
            fixture.path().join("missing-state-directory"),
            fixture.path().join("symlink-marker/.FOLDERBASE"),
        )
        .unwrap();
        fs::write(
            fixture.path().join("symlink-marker/private.md"),
            "must fail closed\n",
        )
        .unwrap();
    }

    let listing = list_workspace(fixture.path()).unwrap();
    let observed = listing
        .entries
        .iter()
        .map(|entry| (entry.path.as_str(), entry.kind))
        .collect::<Vec<_>>();
    #[cfg(unix)]
    assert_eq!(
        observed,
        vec![
            ("casefolded", WorkspaceEntryKind::Folderbase),
            ("ordinary", WorkspaceEntryKind::Directory),
            ("ordinary/FOLDERBASE.MD", WorkspaceEntryKind::File),
            ("ordinary/private.md", WorkspaceEntryKind::File),
            ("symlink-marker", WorkspaceEntryKind::Folderbase),
        ]
    );
    #[cfg(not(unix))]
    assert_eq!(
        observed,
        vec![
            ("casefolded", WorkspaceEntryKind::Folderbase),
            ("ordinary", WorkspaceEntryKind::Directory),
            ("ordinary/FOLDERBASE.MD", WorkspaceEntryKind::File),
            ("ordinary/private.md", WorkspaceEntryKind::File),
        ]
    );

    assert!(matches!(
        read_workspace_text(fixture.path(), "casefolded/private.md"),
        Err(folderbase_core::FolderbaseError::UnsafePath(_))
    ));
    #[cfg(unix)]
    assert!(matches!(
        read_workspace_text(fixture.path(), "symlink-marker/private.md"),
        Err(folderbase_core::FolderbaseError::UnsafePath(_))
    ));
}

#[test]
fn malformed_nested_folderbase_marker_still_fails_closed_for_listing_read_and_save() {
    let fixture = tempdir().unwrap();
    fs::create_dir_all(fixture.path().join("nested/.folderbase")).unwrap();
    fs::write(
        fixture.path().join("nested/.folderbase/manifest.json"),
        "not json\n",
    )
    .unwrap();
    fs::write(
        fixture.path().join("nested/FOLDERBASE.md"),
        "nested folderbase\n",
    )
    .unwrap();
    fs::write(fixture.path().join("nested/secret.md"), "secret\n").unwrap();

    let listing = list_workspace(fixture.path()).unwrap();
    assert_eq!(listing.entries.len(), 1);
    assert_eq!(listing.entries[0].path, "nested");
    assert_eq!(listing.entries[0].kind, WorkspaceEntryKind::Folderbase);

    for path in ["nested/FOLDERBASE.md", "nested/secret.md"] {
        assert!(matches!(
            read_workspace_text(fixture.path(), path),
            Err(folderbase_core::FolderbaseError::UnsafePath(_))
        ));
        assert!(matches!(
            save_workspace_text(
                fixture.path(),
                path,
                "0000000000000000000000000000000000000000000000000000000000000000",
                "replacement\n",
            ),
            Err(folderbase_core::FolderbaseError::UnsafePath(_))
        ));
    }
    assert_eq!(
        fs::read(fixture.path().join("nested/secret.md")).unwrap(),
        b"secret\n"
    );
}

#[test]
fn workspace_read_returns_utf8_content_with_a_known_digest() {
    let fixture = tempdir().unwrap();
    fs::create_dir(fixture.path().join("docs")).unwrap();
    fs::write(fixture.path().join("docs/note.md"), "hello\n").unwrap();

    let document = read_workspace_text(fixture.path(), "docs/note.md").unwrap();

    assert_eq!(document.path, "docs/note.md");
    assert_eq!(document.content, "hello\n");
    assert_eq!(
        document.sha256,
        "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03"
    );
    assert_eq!(document.bytes, 6);
}

#[test]
fn workspace_save_atomically_versions_the_previous_and_new_text_under_one_identity() {
    let fixture = tempdir().unwrap();
    fs::write(fixture.path().join("note.md"), "first\n").unwrap();

    let saved = save_workspace_text(
        fixture.path(),
        "note.md",
        "b640e840b19d378660b32fb51ae18d67dccb4a8596a29e7bd72c1b2ae5928f41",
        "second\n",
    )
    .unwrap();

    assert_eq!(
        fs::read(fixture.path().join("note.md")).unwrap(),
        b"second\n"
    );
    assert_eq!(saved.path, "note.md");
    assert_eq!(
        saved.previous_sha256,
        "b640e840b19d378660b32fb51ae18d67dccb4a8596a29e7bd72c1b2ae5928f41"
    );
    assert_eq!(saved.document.path, "note.md");
    assert_eq!(
        saved.document.sha256,
        "480c2336b410f1ad5f8bf1b28944490255804b65350c527787e74ebdd511e3a4"
    );
    assert_eq!(saved.document.bytes, 7);
    assert!(saved.object_id.as_str().starts_with("obj_"));
    assert!(saved.version_id.as_str().starts_with("version_"));

    let store = LocalVersionStore::open(fixture.path()).unwrap();
    let object = store.read_object(&saved.object_id).unwrap();
    assert_eq!(object.path, "note.md");
    assert_eq!(object.current_version, saved.version_id);
    assert_eq!(object.versions.len(), 2);

    let previous = store.read_version(&object.versions[0]).unwrap();
    let current = store.read_version(&object.versions[1]).unwrap();
    assert_eq!(previous.object_id, saved.object_id);
    assert_eq!(current.object_id, saved.object_id);
    assert_eq!(
        previous.content.digest,
        "b640e840b19d378660b32fb51ae18d67dccb4a8596a29e7bd72c1b2ae5928f41"
    );
    assert_eq!(
        current.content.digest,
        "480c2336b410f1ad5f8bf1b28944490255804b65350c527787e74ebdd511e3a4"
    );
    assert_eq!(
        store
            .journal_events()
            .unwrap()
            .iter()
            .map(|event| event.action)
            .collect::<Vec<_>>(),
        vec![
            JournalAction::ObjectTracked,
            JournalAction::VersionCaptured,
            JournalAction::VersionCaptured,
        ]
    );
}

#[test]
fn concurrent_workspace_saves_have_one_winner_and_leave_no_poisoned_intent() {
    let fixture = tempdir().unwrap();
    fs::write(fixture.path().join("note.md"), "first\n").unwrap();
    let root = Arc::new(fixture.path().to_path_buf());
    let barrier = Arc::new(Barrier::new(8));
    let handles = (0..8)
        .map(|index| {
            let root = Arc::clone(&root);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                save_workspace_text(
                    root.as_path(),
                    "note.md",
                    "b640e840b19d378660b32fb51ae18d67dccb4a8596a29e7bd72c1b2ae5928f41",
                    &format!("replacement-{index}\n"),
                )
            })
        })
        .collect::<Vec<_>>();

    let results = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert!(
        results
            .iter()
            .filter_map(|result| result.as_ref().err())
            .all(|error| matches!(
                error,
                folderbase_core::FolderbaseError::WorkspaceContentChanged(_)
            ))
    );

    let pending = fs::read_dir(fixture.path().join(".folderbase/transactions"))
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| entry.path().extension().and_then(|value| value.to_str()) == Some("json"))
        .count();
    assert_eq!(pending, 0);
    LocalVersionStore::open(fixture.path()).unwrap();
}

#[test]
fn workspace_save_and_version_capture_share_one_transaction_boundary() {
    let fixture = tempdir().unwrap();
    fs::write(fixture.path().join("note.md"), "first\n").unwrap();
    let root = Arc::new(fixture.path().to_path_buf());
    let barrier = Arc::new(Barrier::new(8));

    let save_handles = (0..4)
        .map(|index| {
            let root = Arc::clone(&root);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                save_workspace_text(
                    root.as_path(),
                    "note.md",
                    "b640e840b19d378660b32fb51ae18d67dccb4a8596a29e7bd72c1b2ae5928f41",
                    &format!("saved-{index}\n"),
                )
            })
        })
        .collect::<Vec<_>>();
    let capture_handles = (0..4)
        .map(|_| {
            let root = Arc::clone(&root);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                LocalVersionStore::open(root.as_path())?.capture_file("note.md")
            })
        })
        .collect::<Vec<_>>();

    let saves = save_handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect::<Vec<_>>();
    let captures = capture_handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(saves.iter().filter(|result| result.is_ok()).count(), 1);
    assert!(
        saves
            .iter()
            .filter_map(|result| result.as_ref().err())
            .all(|error| matches!(
                error,
                folderbase_core::FolderbaseError::WorkspaceContentChanged(_)
            ))
    );
    assert!(captures.iter().all(Result::is_ok));

    let pending = fs::read_dir(fixture.path().join(".folderbase/transactions"))
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| entry.path().extension().and_then(|value| value.to_str()) == Some("json"))
        .count();
    assert_eq!(pending, 0);
    LocalVersionStore::open(fixture.path()).unwrap();
}

#[test]
fn direct_workspace_operations_allow_reconstructable_paths_but_reject_protocol_and_git_paths() {
    let fixture = tempdir().unwrap();
    fs::create_dir_all(fixture.path().join("node_modules/pkg")).unwrap();
    fs::create_dir_all(fixture.path().join(".git")).unwrap();
    fs::create_dir_all(fixture.path().join(".folderbase")).unwrap();
    fs::write(
        fixture.path().join("node_modules/pkg/index.js"),
        "generated\n",
    )
    .unwrap();
    fs::write(fixture.path().join(".git/config"), "git\n").unwrap();
    fs::write(fixture.path().join(".folderbase/internal"), "protocol\n").unwrap();

    let generated = read_workspace_text(fixture.path(), "node_modules/pkg/index.js").unwrap();
    assert_eq!(generated.content, "generated\n");
    let saved = save_workspace_text(
        fixture.path(),
        "node_modules/pkg/index.js",
        "9f5936ff15d3a2ba7d3d8f21858338a6c1e2adc9fe34c685c7de5b4a00caa29a",
        "replacement\n",
    )
    .unwrap();
    assert_eq!(
        saved.document.sha256,
        "1d054714357ce5ee01723ed91fcaa69206e221faaf9c1fad64f73be2e5d051da"
    );

    for path in [".git/config", ".folderbase/internal"] {
        assert!(matches!(
            read_workspace_text(fixture.path(), path),
            Err(folderbase_core::FolderbaseError::UnsafePath(_))
        ));
        assert!(matches!(
            save_workspace_text(
                fixture.path(),
                path,
                "0000000000000000000000000000000000000000000000000000000000000000",
                "replacement\n",
            ),
            Err(folderbase_core::FolderbaseError::UnsafePath(_))
        ));
    }
    assert_eq!(
        fs::read(fixture.path().join("node_modules/pkg/index.js")).unwrap(),
        b"replacement\n"
    );
}

#[test]
fn reserved_protocol_and_git_components_are_rejected_case_insensitively() {
    let fixture = tempdir().unwrap();
    fs::create_dir(fixture.path().join(".Git")).unwrap();
    fs::create_dir(fixture.path().join(".FOLDERBASE")).unwrap();
    fs::write(fixture.path().join(".Git/config"), "git\n").unwrap();
    fs::write(fixture.path().join(".FOLDERBASE/internal"), "protocol\n").unwrap();

    assert!(list_workspace(fixture.path()).unwrap().entries.is_empty());
    for path in [".Git/config", ".FOLDERBASE/internal"] {
        assert!(matches!(
            read_workspace_text(fixture.path(), path),
            Err(folderbase_core::FolderbaseError::UnsafePath(_))
        ));
        assert!(matches!(
            save_workspace_text(
                fixture.path(),
                path,
                "0000000000000000000000000000000000000000000000000000000000000000",
                "replacement\n",
            ),
            Err(folderbase_core::FolderbaseError::UnsafePath(_))
        ));
    }
}

#[test]
fn workspace_text_accepts_exactly_two_mib_and_rejects_larger_binary_or_nul_content() {
    let fixture = tempdir().unwrap();
    let exact = vec![b'a'; MAX_WORKSPACE_TEXT_BYTES as usize];
    fs::write(fixture.path().join("exact.txt"), &exact).unwrap();
    fs::write(
        fixture.path().join("too-large.txt"),
        vec![b'a'; MAX_WORKSPACE_TEXT_BYTES as usize + 1],
    )
    .unwrap();
    fs::write(fixture.path().join("binary.txt"), [0xff, 0xfe]).unwrap();
    fs::write(fixture.path().join("nul.txt"), b"before\0after").unwrap();

    let exact_document = read_workspace_text(fixture.path(), "exact.txt").unwrap();
    assert_eq!(exact_document.bytes, MAX_WORKSPACE_TEXT_BYTES);
    assert_eq!(
        exact_document.content.len(),
        MAX_WORKSPACE_TEXT_BYTES as usize
    );
    for path in ["too-large.txt", "binary.txt", "nul.txt"] {
        assert!(matches!(
            read_workspace_text(fixture.path(), path),
            Err(folderbase_core::FolderbaseError::InvalidRecord { .. })
        ));
    }

    let listing = list_workspace(fixture.path()).unwrap();
    for path in ["too-large.txt", "binary.txt", "nul.txt"] {
        assert!(
            !listing
                .entries
                .iter()
                .find(|entry| entry.path == path)
                .unwrap()
                .editable
        );
    }
}

#[test]
fn workspace_listing_reports_depth_limit_instead_of_silently_truncating() {
    let fixture = tempdir().unwrap();
    let mut directory = fixture.path().to_path_buf();
    for index in 0..65 {
        directory.push(format!("d{index:02}"));
    }
    fs::create_dir_all(&directory).unwrap();
    fs::write(directory.join("hidden-by-depth.txt"), "must not vanish\n").unwrap();

    let error = list_workspace(fixture.path()).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("workspace traversal exceeds the 64 level depth limit")
    );
}

#[test]
fn equivalent_relative_path_spellings_keep_one_stable_object_identity() {
    let fixture = tempdir().unwrap();
    fs::create_dir(fixture.path().join("docs")).unwrap();
    fs::write(fixture.path().join("docs/note.md"), "first\n").unwrap();

    let first = save_workspace_text(
        fixture.path(),
        "docs//note.md",
        "b640e840b19d378660b32fb51ae18d67dccb4a8596a29e7bd72c1b2ae5928f41",
        "second\n",
    )
    .unwrap();
    let second = save_workspace_text(
        fixture.path(),
        "docs/note.md",
        "480c2336b410f1ad5f8bf1b28944490255804b65350c527787e74ebdd511e3a4",
        "third\n",
    )
    .unwrap();

    assert_eq!(first.path, "docs/note.md");
    assert_eq!(second.path, "docs/note.md");
    assert_eq!(first.object_id, second.object_id);
    let object = LocalVersionStore::open(fixture.path())
        .unwrap()
        .read_object(&second.object_id)
        .unwrap();
    assert_eq!(object.versions.len(), 3);
    assert_eq!(object.current_version, second.version_id);
    assert_eq!(
        second.document.sha256,
        "5eef8098ed6ec0a16249fc7c12422027fc9fd75b16130cc9382cf09102014796"
    );
}

#[test]
fn case_insensitive_filesystem_aliases_use_the_canonical_relative_spelling_and_identity() {
    let fixture = tempdir().unwrap();
    fs::write(fixture.path().join("Notes.md"), "first\n").unwrap();
    if !fixture.path().join("notes.md").exists() {
        // The behavior only exists on case-insensitive filesystems.
        return;
    }

    let opened = read_workspace_text(fixture.path(), "notes.md").unwrap();
    assert_eq!(opened.path, "Notes.md");

    let first = save_workspace_text(
        fixture.path(),
        "notes.md",
        "b640e840b19d378660b32fb51ae18d67dccb4a8596a29e7bd72c1b2ae5928f41",
        "second\n",
    )
    .unwrap();
    let second = save_workspace_text(
        fixture.path(),
        "Notes.md",
        "480c2336b410f1ad5f8bf1b28944490255804b65350c527787e74ebdd511e3a4",
        "third\n",
    )
    .unwrap();

    assert_eq!(first.path, "Notes.md");
    assert_eq!(second.path, "Notes.md");
    assert_eq!(first.object_id, second.object_id);
    let object = LocalVersionStore::open(fixture.path())
        .unwrap()
        .read_object(&second.object_id)
        .unwrap();
    assert_eq!(object.path, "Notes.md");
    assert_eq!(object.versions.len(), 3);
}

#[cfg(unix)]
#[test]
fn workspace_read_and_save_never_follow_file_parent_or_root_symlinks() {
    let fixture = tempdir().unwrap();
    let outside = tempdir().unwrap();
    fs::write(outside.path().join("sentinel.md"), "outside\n").unwrap();
    symlink(
        outside.path().join("sentinel.md"),
        fixture.path().join("linked-file.md"),
    )
    .unwrap();
    symlink(outside.path(), fixture.path().join("linked-parent")).unwrap();

    for path in ["linked-file.md", "linked-parent/sentinel.md"] {
        assert!(matches!(
            read_workspace_text(fixture.path(), path),
            Err(folderbase_core::FolderbaseError::UnsafePath(_))
        ));
        assert!(matches!(
            save_workspace_text(
                fixture.path(),
                path,
                "0000000000000000000000000000000000000000000000000000000000000000",
                "replacement\n",
            ),
            Err(folderbase_core::FolderbaseError::UnsafePath(_))
        ));
    }

    let root_link_parent = tempdir().unwrap();
    let root_link = root_link_parent.path().join("folderbase-link");
    symlink(fixture.path(), &root_link).unwrap();
    assert!(matches!(
        list_workspace(&root_link),
        Err(folderbase_core::FolderbaseError::InvalidRoot(_))
    ));
    assert_eq!(
        fs::read(outside.path().join("sentinel.md")).unwrap(),
        b"outside\n"
    );
}

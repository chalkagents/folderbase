use std::{fs, io::Write};

use folderbase_core::{
    ContentDigest, FolderbaseError, FolderbaseKind, HistoryTransferPlan, HistoryTransferResult,
    HistoryTransferState, InitializationOptions, JournalAction, LocalVersionRecord,
    LocalVersionStore, MigrationOperation, MigrationPlan, ObjectJournalEvent, VersionId,
    apply_history_transfer, apply_migration, approve_history_transfer, approve_migration,
    initialize, list_workspace, plan_initialization, save_workspace_text,
};
use sha2::{Digest, Sha256};
use tempfile::tempdir;

#[test]
fn stable_identity_survives_path_changes_and_content_versions_are_immutable() {
    let fixture = tempdir().unwrap();
    fs::create_dir(fixture.path().join("work")).unwrap();
    let original_path = fixture.path().join("work/notes.bin");
    let first_bytes = b"first version\0with binary bytes";
    fs::write(&original_path, first_bytes).unwrap();

    let store = LocalVersionStore::open(fixture.path()).unwrap();
    let first = store.capture_file("work/notes.bin").unwrap();
    assert!(first.object_created);
    assert!(first.version_created);
    assert!(first.object.id.as_str().starts_with("obj_"));
    assert_eq!(first.object.id, first.version.object_id);
    assert_eq!(first.version.content.algorithm, "sha256");
    assert_eq!(first.version.content.digest.len(), 64);
    assert_eq!(first.version.content.bytes, first_bytes.len() as u64);

    fs::create_dir(fixture.path().join("archive")).unwrap();
    fs::rename(&original_path, fixture.path().join("archive/notes.bin")).unwrap();
    let relocated = store
        .record_path_change(&first.object.id, "archive/notes.bin")
        .unwrap();
    assert_eq!(relocated.id, first.object.id);
    assert_eq!(relocated.path, "archive/notes.bin");
    assert_eq!(relocated.current_version, first.version.id);

    let second_bytes = b"second version is different";
    fs::write(fixture.path().join("archive/notes.bin"), second_bytes).unwrap();
    let second = store.capture_file("archive/notes.bin").unwrap();
    assert!(!second.object_created);
    assert!(second.version_created);
    assert_eq!(second.object.id, first.object.id);
    assert_ne!(second.version.id, first.version.id);
    assert_ne!(second.version.content.digest, first.version.content.digest);
    assert_eq!(
        second.object.versions,
        vec![first.version.id.clone(), second.version.id.clone()]
    );

    store
        .restore_version(&first.version.id, "restored/first.bin")
        .unwrap();
    store
        .restore_version(&second.version.id, "restored/second.bin")
        .unwrap();
    assert_eq!(
        fs::read(fixture.path().join("restored/first.bin")).unwrap(),
        first_bytes
    );
    assert_eq!(
        fs::read(fixture.path().join("restored/second.bin")).unwrap(),
        second_bytes
    );

    let first_record = store.read_version(&first.version.id).unwrap();
    let second_record = store.read_version(&second.version.id).unwrap();
    assert_eq!(first_record.content, first.version.content);
    assert_eq!(second_record.content, second.version.content);
}

#[test]
fn path_change_rejects_a_moved_file_edited_before_rebinding() {
    let fixture = tempdir().unwrap();
    fs::create_dir(fixture.path().join("work")).unwrap();
    fs::write(fixture.path().join("work/note.md"), "captured\n").unwrap();
    let store = LocalVersionStore::open(fixture.path()).unwrap();
    let captured = store.capture_file("work/note.md").unwrap();
    let journal_before =
        fs::read(fixture.path().join(".folderbase/journal/objects.ndjson")).unwrap();

    fs::create_dir(fixture.path().join("archive")).unwrap();
    fs::rename(
        fixture.path().join("work/note.md"),
        fixture.path().join("archive/note.md"),
    )
    .unwrap();
    fs::write(
        fixture.path().join("archive/note.md"),
        "edited while moving\n",
    )
    .unwrap();

    let error = store
        .record_path_change(&captured.object.id, "archive/note.md")
        .unwrap_err();
    assert!(matches!(error, FolderbaseError::WorkspaceContentChanged(_)));
    assert_eq!(
        store.read_object(&captured.object.id).unwrap().path,
        "work/note.md"
    );
    assert_eq!(
        fs::read(fixture.path().join(".folderbase/journal/objects.ndjson")).unwrap(),
        journal_before
    );
}

#[test]
fn path_change_rejects_a_copy_while_the_tracked_path_still_exists() {
    let fixture = tempdir().unwrap();
    fs::create_dir(fixture.path().join("work")).unwrap();
    fs::write(fixture.path().join("work/note.md"), "captured\n").unwrap();
    let store = LocalVersionStore::open(fixture.path()).unwrap();
    let captured = store.capture_file("work/note.md").unwrap();
    let journal_before =
        fs::read(fixture.path().join(".folderbase/journal/objects.ndjson")).unwrap();

    fs::create_dir(fixture.path().join("archive")).unwrap();
    fs::copy(
        fixture.path().join("work/note.md"),
        fixture.path().join("archive/note.md"),
    )
    .unwrap();

    let error = store
        .record_path_change(&captured.object.id, "archive/note.md")
        .unwrap_err();
    assert!(matches!(error, FolderbaseError::InvalidRecord { .. }));
    assert_eq!(
        store.read_object(&captured.object.id).unwrap().path,
        "work/note.md"
    );
    assert_eq!(
        fs::read(fixture.path().join(".folderbase/journal/objects.ndjson")).unwrap(),
        journal_before
    );
}

#[cfg(unix)]
#[test]
fn path_change_rejects_unrelated_same_byte_file_after_tracked_path_disappears() {
    use std::os::unix::fs::MetadataExt;

    let fixture = tempdir().unwrap();
    fs::create_dir(fixture.path().join("work")).unwrap();
    fs::create_dir(fixture.path().join("archive")).unwrap();
    fs::write(fixture.path().join("work/note.md"), "captured\n").unwrap();
    let store = LocalVersionStore::open(fixture.path()).unwrap();
    let captured = store.capture_file("work/note.md").unwrap();

    fs::write(fixture.path().join("archive/note.md"), "captured\n").unwrap();
    assert_ne!(
        fs::metadata(fixture.path().join("work/note.md"))
            .unwrap()
            .ino(),
        fs::metadata(fixture.path().join("archive/note.md"))
            .unwrap()
            .ino()
    );
    fs::remove_file(fixture.path().join("work/note.md")).unwrap();
    drop(store);
    let store = LocalVersionStore::open(fixture.path()).unwrap();

    let error = store
        .record_path_change(&captured.object.id, "archive/note.md")
        .unwrap_err();
    assert!(matches!(error, FolderbaseError::WorkspaceContentChanged(_)));
    assert_eq!(
        store.read_object(&captured.object.id).unwrap().path,
        "work/note.md"
    );
}

#[cfg(unix)]
#[test]
fn portable_folderbase_copy_does_not_carry_file_identity_across_devices() {
    let source = tempdir().unwrap();
    fs::write(source.path().join("note.md"), "portable\n").unwrap();
    let source_store = LocalVersionStore::open(source.path()).unwrap();
    let captured = source_store.capture_file("note.md").unwrap();

    let object_record_path = source
        .path()
        .join(format!(".folderbase/objects/{}.json", captured.object.id));
    let portable_record: serde_json::Value =
        serde_json::from_slice(&fs::read(&object_record_path).unwrap()).unwrap();
    assert!(
        portable_record
            .get("x-folderbase-local-file-identity")
            .is_none()
    );
    assert!(
        source
            .path()
            .join(format!(
                ".folderbase/local/path-identities/{}.json",
                captured.object.id
            ))
            .is_file()
    );

    let clean_device = tempdir().unwrap();
    fs::write(clean_device.path().join("note.md"), "portable\n").unwrap();
    copy_portable_protocol_state(source.path(), clean_device.path());
    assert!(!clean_device.path().join(".folderbase/local").exists());

    let clean_store = LocalVersionStore::open(clean_device.path()).unwrap();
    fs::create_dir(clean_device.path().join("moved")).unwrap();
    fs::rename(
        clean_device.path().join("note.md"),
        clean_device.path().join("moved/note.md"),
    )
    .unwrap();
    assert!(matches!(
        clean_store.record_path_change(&captured.object.id, "moved/note.md"),
        Err(FolderbaseError::InvalidRecord { .. })
    ));

    fs::rename(
        clean_device.path().join("moved/note.md"),
        clean_device.path().join("note.md"),
    )
    .unwrap();
    let observed = clean_store.capture_file("note.md").unwrap();
    assert_eq!(observed.object.id, captured.object.id);
    fs::rename(
        clean_device.path().join("note.md"),
        clean_device.path().join("moved/note.md"),
    )
    .unwrap();
    assert_eq!(
        clean_store
            .record_path_change(&captured.object.id, "moved/note.md")
            .unwrap()
            .path,
        "moved/note.md"
    );
}

#[test]
fn unchanged_capture_is_idempotent_and_journal_only_appends_complete_lines() {
    let fixture = tempdir().unwrap();
    fs::write(fixture.path().join("note.md"), "unchanged").unwrap();
    let store = LocalVersionStore::open(fixture.path()).unwrap();

    let first = store.capture_file("note.md").unwrap();
    let journal_path = fixture.path().join(".folderbase/journal/objects.ndjson");
    let first_journal = fs::read(&journal_path).unwrap();
    assert!(first_journal.ends_with(b"\n"));

    let repeated = store.capture_file("note.md").unwrap();
    assert!(!repeated.object_created);
    assert!(!repeated.version_created);
    assert_eq!(repeated.object.id, first.object.id);
    assert_eq!(repeated.version.id, first.version.id);
    assert_eq!(fs::read(&journal_path).unwrap(), first_journal);

    fs::write(fixture.path().join("note.md"), "changed").unwrap();
    let changed = store.capture_file("note.md").unwrap();
    let second_journal = fs::read(&journal_path).unwrap();
    assert!(second_journal.starts_with(&first_journal));
    assert!(second_journal.ends_with(b"\n"));

    let events = store.journal_events().unwrap();
    assert_eq!(
        events.iter().map(|event| event.action).collect::<Vec<_>>(),
        vec![
            JournalAction::ObjectTracked,
            JournalAction::VersionCaptured,
            JournalAction::VersionCaptured
        ]
    );
    assert_eq!(
        events.last().unwrap().version_id.as_ref(),
        Some(&changed.version.id)
    );
}

#[cfg(unix)]
#[test]
fn version_store_creates_private_state_by_default() {
    use std::os::unix::fs::PermissionsExt;

    let fixture = tempdir().unwrap();
    fs::write(fixture.path().join("note.md"), "private state").unwrap();

    LocalVersionStore::open(fixture.path())
        .unwrap()
        .capture_file("note.md")
        .unwrap();

    let state_root = fixture.path().join(".folderbase");
    let mut pending = vec![state_root.clone()];
    while let Some(path) = pending.pop() {
        let metadata = fs::symlink_metadata(&path).unwrap();
        let permissions = metadata.permissions().mode() & 0o777;
        if metadata.is_dir() {
            assert_eq!(
                permissions,
                0o700,
                "state directory should be private: {}",
                path.display()
            );
            pending.extend(
                fs::read_dir(&path)
                    .unwrap()
                    .map(|entry| entry.unwrap().path()),
            );
        } else if metadata.is_file() {
            assert_eq!(
                permissions,
                0o600,
                "state file should be private: {}",
                path.display()
            );
        }
    }
}

#[cfg(unix)]
#[test]
fn workspace_save_preserves_the_existing_file_mode() {
    use std::os::unix::fs::PermissionsExt;

    let fixture = tempdir().unwrap();
    let path = fixture.path().join("script.sh");
    fs::write(&path, "#!/bin/sh\necho old\n").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o751)).unwrap();

    let expected = format!("{:x}", Sha256::digest(fs::read(&path).unwrap()));
    save_workspace_text(
        fixture.path(),
        "script.sh",
        &expected,
        "#!/bin/sh\necho new\n",
    )
    .unwrap();

    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o751
    );
}

#[cfg(target_os = "macos")]
#[test]
fn workspace_save_preserves_extended_attributes() {
    use std::process::Command;

    let fixture = tempdir().unwrap();
    let path = fixture.path().join("tagged.txt");
    fs::write(&path, "old\n").unwrap();
    let attribute = "com.folderbase.tests.origin";
    let value = "preserve-me";
    assert!(
        Command::new("xattr")
            .args(["-w", attribute, value])
            .arg(&path)
            .status()
            .unwrap()
            .success()
    );

    let expected = format!("{:x}", Sha256::digest(fs::read(&path).unwrap()));
    save_workspace_text(fixture.path(), "tagged.txt", &expected, "new\n").unwrap();

    let output = Command::new("xattr")
        .args(["-p", attribute])
        .arg(&path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "extended attribute should survive an accepted save"
    );
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        format!("{value}\n")
    );
}

#[test]
#[ignore = "subprocess helper for interrupted workspace-save tests"]
fn interrupted_workspace_save_process_helper() {
    let Some(root) = std::env::var_os("FOLDERBASE_TEST_WORKSPACE_ROOT") else {
        return;
    };
    let error = save_workspace_text(
        root,
        "note.md",
        "b640e840b19d378660b32fb51ae18d67dccb4a8596a29e7bd72c1b2ae5928f41",
        "second\n",
    )
    .unwrap_err();
    assert!(
        error.to_string().contains("simulated interruption"),
        "helper should stop only at the requested durability checkpoint: {error}"
    );
}

#[cfg(unix)]
#[test]
fn recovery_rejects_same_byte_file_identity_replacement_after_save_intent() {
    use std::{
        os::unix::fs::{MetadataExt, PermissionsExt},
        process::Command,
    };

    let fixture = tempdir().unwrap();
    let destination = fixture.path().join("note.md");
    fs::write(&destination, "first\n").unwrap();
    let original_inode = fs::metadata(&destination).unwrap().ino();

    let status = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "interrupted_workspace_save_process_helper",
            "--ignored",
            "--nocapture",
        ])
        .env("FOLDERBASE_TEST_WORKSPACE_ROOT", fixture.path())
        .env(
            "FOLDERBASE_TEST_FAIL_AFTER_WORKSPACE_CHECKPOINT",
            "versions-durable",
        )
        .status()
        .unwrap();
    assert!(
        status.success(),
        "save helper should leave a durable intent"
    );
    let pending = fs::read_dir(fixture.path().join(".folderbase/transactions"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| path.extension().and_then(|extension| extension.to_str()) == Some("json"))
        .expect("interrupted save should retain its durable transaction");
    assert_eq!(
        fs::metadata(pending).unwrap().permissions().mode() & 0o777,
        0o600
    );

    let competing = fixture.path().join("competing-note.md");
    fs::write(&competing, "first\n").unwrap();
    fs::rename(&competing, &destination).unwrap();
    assert_ne!(fs::metadata(&destination).unwrap().ino(), original_inode);

    let error = LocalVersionStore::open(fixture.path()).unwrap_err();
    assert!(matches!(error, FolderbaseError::WorkspaceContentChanged(_)));
    assert_eq!(fs::read(&destination).unwrap(), b"first\n");
}

#[test]
fn reopening_replays_a_durable_capture_transaction_after_interruption() {
    let fixture = tempdir().unwrap();
    fs::write(fixture.path().join("note.md"), "first").unwrap();
    let store = LocalVersionStore::open(fixture.path()).unwrap();
    let first = store.capture_file("note.md").unwrap();

    let second_bytes = b"second after interruption";
    fs::write(fixture.path().join("note.md"), second_bytes).unwrap();
    let digest = format!("{:x}", Sha256::digest(second_bytes));
    let content = ContentDigest {
        algorithm: "sha256".to_owned(),
        digest: digest.clone(),
        bytes: second_bytes.len() as u64,
    };
    let version_id = VersionId::parse("version_019f9cf0-b627-7c58-8945-394fdd9fa926").unwrap();
    let version = LocalVersionRecord {
        id: version_id.clone(),
        object_id: first.object.id.clone(),
        content: content.clone(),
        captured_at: "2026-07-25T12:00:00Z".to_owned(),
        extensions: Default::default(),
    };
    let mut projection = first.object.clone();
    projection.current_version = version_id.clone();
    projection.versions.push(version_id.clone());
    let event = ObjectJournalEvent {
        id: "event_019f9cf0-b627-7c58-8945-394fdd9fa927".to_owned(),
        at: "2026-07-25T12:00:00Z".to_owned(),
        action: JournalAction::VersionCaptured,
        object_id: first.object.id.clone(),
        path: "note.md".to_owned(),
        previous_path: None,
        version_id: Some(version_id.clone()),
        content: Some(content),
    };

    let blob_path = fixture
        .path()
        .join(".folderbase/versions/blobs/sha256")
        .join(digest);
    fs::write(&blob_path, second_bytes).unwrap();
    let transaction_id = "transaction_019f9cf0-b627-7c58-8945-394fdd9fa928";
    let transaction_path = fixture
        .path()
        .join(".folderbase/transactions")
        .join(format!("{transaction_id}.json"));
    let transaction_bytes = serde_json::to_vec_pretty(&serde_json::json!({
        "protocol_version": "0.1.0",
        "id": transaction_id,
        "version": version,
        "object": projection,
        "events": [event],
    }))
    .unwrap();
    fs::write(&transaction_path, &transaction_bytes).unwrap();
    drop(store);

    let recovered = LocalVersionStore::open(fixture.path()).unwrap();
    assert!(!transaction_path.exists());
    assert_eq!(
        recovered
            .read_object(&first.object.id)
            .unwrap()
            .current_version,
        version_id
    );
    assert_eq!(
        recovered.read_version(&version_id).unwrap().content.digest,
        format!("{:x}", Sha256::digest(second_bytes))
    );
    let repeated = recovered.capture_file("note.md").unwrap();
    assert!(!repeated.version_created);
    assert_eq!(repeated.version.id, version_id);
    drop(recovered);

    // A crash after journal sync but before intent removal replays safely
    // without duplicating the already committed event.
    fs::write(&transaction_path, transaction_bytes).unwrap();
    let recovered_again = LocalVersionStore::open(fixture.path()).unwrap();
    assert_eq!(
        recovered_again
            .journal_events()
            .unwrap()
            .iter()
            .filter(|journal_event| journal_event.version_id.as_ref() == Some(&version_id))
            .count(),
        1
    );
}

#[test]
fn pending_capture_replay_stops_if_its_path_becomes_a_nested_folderbase() {
    let fixture = tempdir().unwrap();
    fs::create_dir(fixture.path().join("future-folderbase")).unwrap();
    fs::write(fixture.path().join("future-folderbase/note.md"), "first").unwrap();
    let store = LocalVersionStore::open(fixture.path()).unwrap();
    let first = store.capture_file("future-folderbase/note.md").unwrap();

    let second_bytes = b"second after interruption";
    fs::write(
        fixture.path().join("future-folderbase/note.md"),
        second_bytes,
    )
    .unwrap();
    let digest = format!("{:x}", Sha256::digest(second_bytes));
    let content = ContentDigest {
        algorithm: "sha256".to_owned(),
        digest: digest.clone(),
        bytes: second_bytes.len() as u64,
    };
    let version_id = VersionId::parse("version_019f9cf0-b627-7c58-8945-394fdd9fa929").unwrap();
    let version = LocalVersionRecord {
        id: version_id.clone(),
        object_id: first.object.id.clone(),
        content: content.clone(),
        captured_at: "2026-07-25T12:00:00Z".to_owned(),
        extensions: Default::default(),
    };
    let mut projection = first.object.clone();
    projection.current_version = version_id.clone();
    projection.versions.push(version_id.clone());
    let event_id = "event_019f9cf0-b627-7c58-8945-394fdd9fa930";
    let event = ObjectJournalEvent {
        id: event_id.to_owned(),
        at: "2026-07-25T12:00:00Z".to_owned(),
        action: JournalAction::VersionCaptured,
        object_id: first.object.id.clone(),
        path: "future-folderbase/note.md".to_owned(),
        previous_path: None,
        version_id: Some(version_id.clone()),
        content: Some(content),
    };

    let blob_path = fixture
        .path()
        .join(".folderbase/versions/blobs/sha256")
        .join(digest);
    fs::write(&blob_path, second_bytes).unwrap();
    let transaction_id = "transaction_019f9cf0-b627-7c58-8945-394fdd9fa931";
    let transaction_path = fixture
        .path()
        .join(".folderbase/transactions")
        .join(format!("{transaction_id}.json"));
    fs::write(
        &transaction_path,
        serde_json::to_vec_pretty(&serde_json::json!({
            "protocol_version": "0.1.0",
            "id": transaction_id,
            "version": version,
            "object": projection,
            "events": [event],
        }))
        .unwrap(),
    )
    .unwrap();
    drop(store);

    fs::create_dir(fixture.path().join("future-folderbase/.folderbase")).unwrap();
    fs::write(
        fixture.path().join("future-folderbase/FOLDERBASE.md"),
        "# Future Folderbase\n",
    )
    .unwrap();
    fs::write(
        fixture
            .path()
            .join("future-folderbase/.folderbase/manifest.json"),
        "malformed\n",
    )
    .unwrap();

    let error = LocalVersionStore::open(fixture.path()).unwrap_err();
    assert!(matches!(error, FolderbaseError::UnsafePath(_)));
    assert!(transaction_path.exists());
    assert!(
        !fixture
            .path()
            .join(".folderbase/versions/records")
            .join(format!("{version_id}.json"))
            .exists()
    );
    assert!(
        !String::from_utf8(
            fs::read(fixture.path().join(".folderbase/journal/objects.ndjson")).unwrap()
        )
        .unwrap()
        .contains(event_id)
    );
}

#[test]
fn pending_capture_replay_refuses_an_external_edit_before_projection() {
    let fixture = tempdir().unwrap();
    fs::write(fixture.path().join("note.md"), "first").unwrap();
    let store = LocalVersionStore::open(fixture.path()).unwrap();
    let first = store.capture_file("note.md").unwrap();

    let captured_bytes = b"captured before interruption";
    let digest = format!("{:x}", Sha256::digest(captured_bytes));
    let content = ContentDigest {
        algorithm: "sha256".to_owned(),
        digest: digest.clone(),
        bytes: captured_bytes.len() as u64,
    };
    let version_id = VersionId::parse("version_019f9cf0-b627-7c58-8945-394fdd9fa932").unwrap();
    let version = LocalVersionRecord {
        id: version_id.clone(),
        object_id: first.object.id.clone(),
        content: content.clone(),
        captured_at: "2026-07-25T12:00:00Z".to_owned(),
        extensions: Default::default(),
    };
    let mut projection = first.object.clone();
    projection.current_version = version_id.clone();
    projection.versions.push(version_id.clone());
    let event_id = "event_019f9cf0-b627-7c58-8945-394fdd9fa933";
    let event = ObjectJournalEvent {
        id: event_id.to_owned(),
        at: "2026-07-25T12:00:00Z".to_owned(),
        action: JournalAction::VersionCaptured,
        object_id: first.object.id.clone(),
        path: "note.md".to_owned(),
        previous_path: None,
        version_id: Some(version_id.clone()),
        content: Some(content),
    };

    let blob_path = fixture
        .path()
        .join(".folderbase/versions/blobs/sha256")
        .join(digest);
    fs::write(&blob_path, captured_bytes).unwrap();
    let transaction_id = "transaction_019f9cf0-b627-7c58-8945-394fdd9fa934";
    let transaction_path = fixture
        .path()
        .join(".folderbase/transactions")
        .join(format!("{transaction_id}.json"));
    fs::write(
        &transaction_path,
        serde_json::to_vec_pretty(&serde_json::json!({
            "protocol_version": "0.1.0",
            "id": transaction_id,
            "version": version,
            "object": projection,
            "events": [event],
        }))
        .unwrap(),
    )
    .unwrap();
    fs::write(fixture.path().join("note.md"), "third-party edit").unwrap();
    drop(store);

    let error = LocalVersionStore::open(fixture.path()).unwrap_err();
    assert!(matches!(error, FolderbaseError::WorkspaceContentChanged(_)));
    assert_eq!(
        fs::read(fixture.path().join("note.md")).unwrap(),
        b"third-party edit"
    );
    assert!(transaction_path.exists());
    assert!(
        !fixture
            .path()
            .join(".folderbase/versions/records")
            .join(format!("{version_id}.json"))
            .exists()
    );
    let projection: serde_json::Value = serde_json::from_slice(
        &fs::read(
            fixture
                .path()
                .join(format!(".folderbase/objects/{}.json", first.object.id)),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(projection["current_version"], first.version.id.as_str());
    assert!(
        !String::from_utf8(
            fs::read(fixture.path().join(".folderbase/journal/objects.ndjson")).unwrap()
        )
        .unwrap()
        .contains(event_id)
    );
}

#[test]
fn pending_relocation_replay_refuses_an_external_edit_before_projection() {
    let fixture = tempdir().unwrap();
    fs::create_dir(fixture.path().join("work")).unwrap();
    fs::write(fixture.path().join("work/note.md"), "captured").unwrap();
    let store = LocalVersionStore::open(fixture.path()).unwrap();
    let captured = store.capture_file("work/note.md").unwrap();

    fs::create_dir(fixture.path().join("archive")).unwrap();
    fs::rename(
        fixture.path().join("work/note.md"),
        fixture.path().join("archive/note.md"),
    )
    .unwrap();
    let mut projection = captured.object.clone();
    projection.path = "archive/note.md".to_owned();
    let event_id = "event_019f9cf0-b627-7c58-8945-394fdd9fa935";
    let event = ObjectJournalEvent {
        id: event_id.to_owned(),
        at: "2026-07-25T12:00:00Z".to_owned(),
        action: JournalAction::ObjectRelocated,
        object_id: captured.object.id.clone(),
        path: "archive/note.md".to_owned(),
        previous_path: Some("work/note.md".to_owned()),
        version_id: Some(captured.version.id.clone()),
        content: None,
    };
    let transaction_id = "transaction_019f9cf0-b627-7c58-8945-394fdd9fa936";
    let transaction_path = fixture
        .path()
        .join(".folderbase/transactions")
        .join(format!("{transaction_id}.json"));
    fs::write(
        &transaction_path,
        serde_json::to_vec_pretty(&serde_json::json!({
            "protocol_version": "0.1.0",
            "id": transaction_id,
            "version": null,
            "object": projection,
            "events": [event],
        }))
        .unwrap(),
    )
    .unwrap();
    fs::write(fixture.path().join("archive/note.md"), "third-party edit").unwrap();
    drop(store);

    let error = LocalVersionStore::open(fixture.path()).unwrap_err();
    assert!(matches!(error, FolderbaseError::WorkspaceContentChanged(_)));
    assert_eq!(
        fs::read(fixture.path().join("archive/note.md")).unwrap(),
        b"third-party edit"
    );
    assert!(transaction_path.exists());
    let projection: serde_json::Value = serde_json::from_slice(
        &fs::read(
            fixture
                .path()
                .join(format!(".folderbase/objects/{}.json", captured.object.id)),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(projection["path"], "work/note.md");
    assert!(
        !String::from_utf8(
            fs::read(fixture.path().join(".folderbase/journal/objects.ndjson")).unwrap()
        )
        .unwrap()
        .contains(event_id)
    );
}

#[test]
fn an_interrupted_final_journal_append_is_quarantined_before_replay() {
    let fixture = tempdir().unwrap();
    fs::write(fixture.path().join("note.md"), "first").unwrap();
    let store = LocalVersionStore::open(fixture.path()).unwrap();
    store.capture_file("note.md").unwrap();

    let journal_path = fixture.path().join(".folderbase/journal/objects.ndjson");
    let mut journal = fs::OpenOptions::new()
        .append(true)
        .open(&journal_path)
        .unwrap();
    let interrupted_tail = br#"{"id":"event_interrupted""#;
    journal.write_all(interrupted_tail).unwrap();
    journal.sync_all().unwrap();
    drop(journal);

    assert_eq!(store.journal_events().unwrap().len(), 2);
    fs::write(fixture.path().join("note.md"), "second").unwrap();
    store.capture_file("note.md").unwrap();

    let repaired = fs::read(&journal_path).unwrap();
    assert!(repaired.ends_with(b"\n"));
    assert!(
        !repaired
            .windows(interrupted_tail.len())
            .any(|window| window == interrupted_tail)
    );
    assert_eq!(store.journal_events().unwrap().len(), 3);

    let quarantined = fs::read_dir(fixture.path().join(".folderbase/journal/quarantine"))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(quarantined.len(), 1);
    assert_eq!(fs::read(quarantined[0].path()).unwrap(), interrupted_tail);
}

#[test]
fn corrupted_journal_fails_restore_preflight_without_destination_mutation() {
    let fixture = tempdir().unwrap();
    fs::write(fixture.path().join("source.txt"), "durable restore").unwrap();
    let store = LocalVersionStore::open(fixture.path()).unwrap();
    let captured = store.capture_file("source.txt").unwrap();

    let journal_path = fixture.path().join(".folderbase/journal/objects.ndjson");
    let saved_journal_path = fixture.path().join(".folderbase/journal/saved.ndjson");
    fs::rename(&journal_path, &saved_journal_path).unwrap();
    fs::create_dir(&journal_path).unwrap();

    let restore_error = store
        .restore_version(&captured.version.id, "recovered/restored.txt")
        .unwrap_err();
    assert!(matches!(restore_error, FolderbaseError::UnsafePath(_)));
    assert!(!fixture.path().join("recovered/restored.txt").exists());

    fs::remove_dir(&journal_path).unwrap();
    fs::rename(&saved_journal_path, &journal_path).unwrap();
    store
        .restore_version(&captured.version.id, "recovered/restored.txt")
        .unwrap();
    let restored_events = store
        .journal_events()
        .unwrap()
        .into_iter()
        .filter(|event| {
            event.action == JournalAction::VersionRestored
                && event.version_id.as_ref() == Some(&captured.version.id)
                && event.path == "recovered/restored.txt"
        })
        .count();
    assert_eq!(restored_events, 1);
    assert_eq!(
        fs::read(fixture.path().join("recovered/restored.txt")).unwrap(),
        b"durable restore"
    );
}

#[test]
fn equal_bytes_deduplicate_blobs_without_merging_object_identity() {
    let fixture = tempdir().unwrap();
    fs::write(fixture.path().join("one.txt"), "same bytes").unwrap();
    fs::write(fixture.path().join("two.txt"), "same bytes").unwrap();
    let store = LocalVersionStore::open(fixture.path()).unwrap();

    let one = store.capture_file("one.txt").unwrap();
    let two = store.capture_file("two.txt").unwrap();
    assert_ne!(one.object.id, two.object.id);
    assert_ne!(one.version.id, two.version.id);
    assert_eq!(one.version.content, two.version.content);

    let blobs = fs::read_dir(fixture.path().join(".folderbase/versions/blobs/sha256"))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(blobs.len(), 1);
}

#[test]
fn restore_refuses_overwrite_and_detects_blob_corruption_before_writing() {
    let fixture = tempdir().unwrap();
    fs::write(fixture.path().join("source.txt"), "trusted bytes").unwrap();
    let store = LocalVersionStore::open(fixture.path()).unwrap();
    let captured = store.capture_file("source.txt").unwrap();

    fs::write(fixture.path().join("occupied.txt"), "keep me").unwrap();
    let overwrite = store
        .restore_version(&captured.version.id, "occupied.txt")
        .unwrap_err();
    assert!(matches!(overwrite, FolderbaseError::WouldOverwrite(_)));
    assert_eq!(
        fs::read(fixture.path().join("occupied.txt")).unwrap(),
        b"keep me"
    );

    let blob_path = fixture
        .path()
        .join(".folderbase/versions/blobs/sha256")
        .join(&captured.version.content.digest);
    let mut blob = fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&blob_path)
        .unwrap();
    blob.write_all(b"tampered").unwrap();
    blob.sync_all().unwrap();

    let corrupted = store
        .restore_version(&captured.version.id, "should-not-exist.txt")
        .unwrap_err();
    assert!(matches!(corrupted, FolderbaseError::InvalidRecord { .. }));
    assert!(!fixture.path().join("should-not-exist.txt").exists());
}

#[cfg(unix)]
#[test]
fn restore_rejects_a_matching_blob_symlink_without_creating_the_destination() {
    use std::os::unix::fs::symlink;

    let fixture = tempdir().unwrap();
    let outside = tempdir().unwrap();
    fs::write(fixture.path().join("source.txt"), "outside bytes").unwrap();
    let store = LocalVersionStore::open(fixture.path()).unwrap();
    let captured = store.capture_file("source.txt").unwrap();
    let blob_path = fixture
        .path()
        .join(".folderbase/versions/blobs/sha256")
        .join(&captured.version.content.digest);
    let outside_blob = outside.path().join("matching-blob");
    fs::rename(&blob_path, &outside_blob).unwrap();
    symlink(&outside_blob, &blob_path).unwrap();

    let error = store
        .restore_version(&captured.version.id, "restored.txt")
        .unwrap_err();
    assert!(matches!(
        error,
        FolderbaseError::UnsafePath(_) | FolderbaseError::Io { .. }
    ));
    assert!(!fixture.path().join("restored.txt").exists());
}

#[cfg(unix)]
#[test]
fn protocol_record_and_journal_reads_reject_symlinks() {
    use std::os::unix::fs::symlink;

    let fixture = tempdir().unwrap();
    let outside = tempdir().unwrap();
    fs::write(fixture.path().join("source.txt"), "source").unwrap();
    let store = LocalVersionStore::open(fixture.path()).unwrap();
    let captured = store.capture_file("source.txt").unwrap();

    let object_path = fixture
        .path()
        .join(format!(".folderbase/objects/{}.json", captured.object.id));
    let outside_object = outside.path().join("object.json");
    fs::rename(&object_path, &outside_object).unwrap();
    symlink(&outside_object, &object_path).unwrap();
    assert!(store.read_object(&captured.object.id).is_err());
    fs::remove_file(&object_path).unwrap();
    fs::rename(&outside_object, &object_path).unwrap();

    let version_path = fixture.path().join(format!(
        ".folderbase/versions/records/{}.json",
        captured.version.id
    ));
    let outside_version = outside.path().join("version.json");
    fs::rename(&version_path, &outside_version).unwrap();
    symlink(&outside_version, &version_path).unwrap();
    assert!(store.read_version(&captured.version.id).is_err());
    fs::remove_file(&version_path).unwrap();
    fs::rename(&outside_version, &version_path).unwrap();

    let journal_path = fixture.path().join(".folderbase/journal/objects.ndjson");
    let outside_journal = outside.path().join("objects.ndjson");
    fs::rename(&journal_path, &outside_journal).unwrap();
    symlink(&outside_journal, &journal_path).unwrap();
    assert!(store.journal_events().is_err());
}

#[cfg(unix)]
#[test]
fn pending_transaction_reads_reject_symlinks_instead_of_skipping_them() {
    use std::os::unix::fs::symlink;

    let fixture = tempdir().unwrap();
    let outside = tempdir().unwrap();
    fs::write(fixture.path().join("source.txt"), "source").unwrap();
    let store = LocalVersionStore::open(fixture.path()).unwrap();
    store.capture_file("source.txt").unwrap();
    let outside_transaction = outside.path().join("transaction.json");
    fs::write(&outside_transaction, "{}").unwrap();
    let transaction_path = fixture
        .path()
        .join(".folderbase/transactions")
        .join("transaction_019f9cf0-b627-7c58-8945-394fdd9fa937.json");
    symlink(&outside_transaction, &transaction_path).unwrap();
    drop(store);

    assert!(LocalVersionStore::open(fixture.path()).is_err());
}

#[test]
fn content_paths_cannot_escape_or_enter_protocol_state() {
    let fixture = tempdir().unwrap();
    fs::write(fixture.path().join("safe.txt"), "safe").unwrap();
    let store = LocalVersionStore::open(fixture.path()).unwrap();

    for unsafe_path in ["../escape.txt", "./safe.txt", ".folderbase/manifest.json"] {
        let error = store.capture_file(unsafe_path).unwrap_err();
        assert!(matches!(error, FolderbaseError::UnsafePath(_)));
    }

    let captured = store.capture_file("safe.txt").unwrap();
    let restore_error = store
        .restore_version(&captured.version.id, "../restored.txt")
        .unwrap_err();
    assert!(matches!(restore_error, FolderbaseError::UnsafePath(_)));
}

#[test]
fn version_paths_reject_reserved_components_case_insensitively_at_every_depth() {
    let fixture = tempdir().unwrap();
    fs::write(fixture.path().join("safe.txt"), "safe").unwrap();
    fs::create_dir_all(fixture.path().join(".Git")).unwrap();
    fs::write(fixture.path().join(".Git/config"), "git").unwrap();
    fs::create_dir_all(fixture.path().join("nested/.gIt")).unwrap();
    fs::write(fixture.path().join("nested/.gIt/config"), "nested git").unwrap();

    let store = LocalVersionStore::open(fixture.path()).unwrap();
    let captured = store.capture_file("safe.txt").unwrap();

    for unsafe_path in [
        ".FOLDERBASE/journal/objects.ndjson",
        ".Git/config",
        "nested/.gIt/config",
    ] {
        let error = store.capture_file(unsafe_path).unwrap_err();
        assert!(
            matches!(error, FolderbaseError::UnsafePath(_)),
            "{unsafe_path} should be reserved: {error}"
        );
    }

    for unsafe_destination in [
        ".FOLDERBASE/restored.txt",
        ".Git/restored.txt",
        "nested/.gIt/restored.txt",
    ] {
        let error = store
            .restore_version(&captured.version.id, unsafe_destination)
            .unwrap_err();
        assert!(
            matches!(error, FolderbaseError::UnsafePath(_)),
            "{unsafe_destination} should be reserved: {error}"
        );
        assert!(!fixture.path().join(unsafe_destination).exists());
    }
}

#[test]
fn direct_capture_uses_the_filesystem_spelling_and_workspace_object_identity() {
    let fixture = tempdir().unwrap();
    fs::create_dir(fixture.path().join("docs")).unwrap();
    fs::write(fixture.path().join("docs/Note.md"), "first\n").unwrap();
    if !fixture.path().join("docs/note.md").exists() {
        // Case aliases only resolve to one inode on a case-insensitive filesystem.
        return;
    }

    let store = LocalVersionStore::open(fixture.path()).unwrap();
    let direct = store.capture_file("docs/note.md").unwrap();
    assert_eq!(direct.object.path, "docs/Note.md");
    assert_eq!(
        store
            .record_path_change(&direct.object.id, "docs/note.md")
            .unwrap()
            .path,
        "docs/Note.md"
    );

    let saved = save_workspace_text(
        fixture.path(),
        "docs/Note.md",
        "b640e840b19d378660b32fb51ae18d67dccb4a8596a29e7bd72c1b2ae5928f41",
        "second\n",
    )
    .unwrap();
    assert_eq!(saved.object_id, direct.object.id);
    assert_eq!(
        store.read_object(&direct.object.id).unwrap().versions.len(),
        2
    );

    fs::create_dir(fixture.path().join("Archive")).unwrap();
    fs::rename(
        fixture.path().join("docs/Note.md"),
        fixture.path().join("Archive/Final.md"),
    )
    .unwrap();
    let moved_alias = if fixture.path().join("archive/final.md").exists() {
        "archive/final.md"
    } else {
        "Archive//Final.md"
    };
    let relocated = store
        .record_path_change(&direct.object.id, moved_alias)
        .unwrap();
    assert_eq!(relocated.path, "Archive/Final.md");
    assert_eq!(
        store.capture_file(moved_alias).unwrap().object.id,
        direct.object.id
    );
}

#[test]
fn legacy_stored_path_alias_reuses_one_object_identity() {
    let fixture = tempdir().unwrap();
    fs::create_dir(fixture.path().join("docs")).unwrap();
    fs::write(fixture.path().join("docs/Note.md"), "captured\n").unwrap();
    let store = LocalVersionStore::open(fixture.path()).unwrap();
    let first = store.capture_file("docs/Note.md").unwrap();

    let object_record_path = fixture
        .path()
        .join(format!(".folderbase/objects/{}.json", first.object.id));
    let mut legacy_record: serde_json::Value =
        serde_json::from_slice(&fs::read(&object_record_path).unwrap()).unwrap();
    let legacy_alias = if fixture.path().join("docs/note.md").exists() {
        "docs/note.md"
    } else {
        "docs//Note.md"
    };
    legacy_record["path"] = serde_json::Value::String(legacy_alias.to_owned());
    fs::write(
        &object_record_path,
        serde_json::to_vec_pretty(&legacy_record).unwrap(),
    )
    .unwrap();

    let repeated = store.capture_file("docs/Note.md").unwrap();
    assert_eq!(repeated.object.id, first.object.id);
    assert!(!repeated.object_created);
    assert_eq!(
        store.read_object(&first.object.id).unwrap().path,
        "docs/Note.md"
    );
    assert_eq!(
        fs::read_dir(fixture.path().join(".folderbase/objects"))
            .unwrap()
            .filter_map(Result::ok)
            .filter(
                |entry| entry.path().extension().and_then(|value| value.to_str()) == Some("json")
            )
            .count(),
        1
    );
}

#[test]
fn restore_normalizes_lexical_paths_and_existing_parent_spelling() {
    let fixture = tempdir().unwrap();
    fs::write(fixture.path().join("source.txt"), "restore me").unwrap();
    fs::create_dir(fixture.path().join("Output")).unwrap();
    let store = LocalVersionStore::open(fixture.path()).unwrap();
    let captured = store.capture_file("source.txt").unwrap();

    let lexical = store
        .restore_version(&captured.version.id, "Output//lexical.txt")
        .unwrap();
    assert_eq!(lexical.path, std::path::PathBuf::from("Output/lexical.txt"));

    if fixture.path().join("output").exists() {
        let canonical = store
            .restore_version(&captured.version.id, "output/canonical.txt")
            .unwrap();
        assert_eq!(
            canonical.path,
            std::path::PathBuf::from("Output/canonical.txt")
        );
        assert_eq!(
            store
                .journal_events()
                .unwrap()
                .last()
                .map(|event| event.path.as_str()),
            Some("Output/canonical.txt")
        );
    }
}

#[test]
fn version_operations_stop_at_a_nested_folderbase_even_when_its_manifest_is_malformed() {
    let fixture = tempdir().unwrap();
    fs::write(fixture.path().join("source.txt"), "parent content").unwrap();
    fs::create_dir_all(fixture.path().join("child/.folderbase")).unwrap();
    fs::write(fixture.path().join("child/FOLDERBASE.md"), "# Child\n").unwrap();
    fs::write(
        fixture.path().join("child/.folderbase/manifest.json"),
        "not json\n",
    )
    .unwrap();
    fs::write(fixture.path().join("child/private.txt"), "child content").unwrap();

    let store = LocalVersionStore::open(fixture.path()).unwrap();
    let captured = store.capture_file("source.txt").unwrap();

    let capture_error = store.capture_file("child/private.txt").unwrap_err();
    assert!(matches!(capture_error, FolderbaseError::UnsafePath(_)));

    let relocate_error = store
        .record_path_change(&captured.object.id, "child/private.txt")
        .unwrap_err();
    assert!(matches!(relocate_error, FolderbaseError::UnsafePath(_)));
    assert_eq!(
        store.read_object(&captured.object.id).unwrap().path,
        "source.txt"
    );

    let restore_error = store
        .restore_version(&captured.version.id, "child/restored.txt")
        .unwrap_err();
    assert!(matches!(restore_error, FolderbaseError::UnsafePath(_)));
    assert!(!fixture.path().join("child/restored.txt").exists());
}

#[test]
fn nested_folderbase_creation_revokes_parent_object_history_and_restore_access() {
    let fixture = tempdir().unwrap();
    fs::create_dir(fixture.path().join("child")).unwrap();
    fs::write(fixture.path().join("child/private.txt"), "private history").unwrap();
    let store = LocalVersionStore::open(fixture.path()).unwrap();
    let captured = store.capture_file("child/private.txt").unwrap();

    fs::create_dir(fixture.path().join("child/.folderbase")).unwrap();
    fs::write(fixture.path().join("child/FOLDERBASE.md"), "# Child\n").unwrap();
    fs::write(
        fixture.path().join("child/.folderbase/manifest.json"),
        "not json\n",
    )
    .unwrap();

    let object_read = store.read_object(&captured.object.id);
    let version_read = store.read_version(&captured.version.id);
    let history_read = store.journal_events();
    let restore = store.restore_version(&captured.version.id, "restored-private.txt");

    assert_eq!(
        (
            matches!(object_read, Err(FolderbaseError::UnsafePath(_))),
            matches!(version_read, Err(FolderbaseError::UnsafePath(_))),
            matches!(history_read, Err(FolderbaseError::UnsafePath(_))),
            matches!(restore, Err(FolderbaseError::UnsafePath(_))),
        ),
        (true, true, true, true)
    );
    assert!(!fixture.path().join("restored-private.txt").exists());
}

#[test]
fn history_transfer_requires_explicit_folderbase_ids() {
    let fixture = tempdir().unwrap();
    let parent = initialize(
        &plan_initialization(
            fixture.path(),
            InitializationOptions {
                name: Some("Parent".to_owned()),
                kind: FolderbaseKind::Organization,
                create_agent_adapters: false,
            },
        )
        .unwrap(),
    )
    .unwrap();
    fs::create_dir(fixture.path().join("Client")).unwrap();
    fs::write(fixture.path().join("Client/private.txt"), "v1\n").unwrap();
    let parent_store = LocalVersionStore::open(fixture.path()).unwrap();
    let captured = parent_store.capture_file("Client/private.txt").unwrap();

    let child_fixture = tempdir().unwrap();
    let child = initialize(
        &plan_initialization(
            child_fixture.path(),
            InitializationOptions {
                name: Some("Client".to_owned()),
                kind: FolderbaseKind::Project,
                create_agent_adapters: false,
            },
        )
        .unwrap(),
    )
    .unwrap();
    fs::create_dir_all(fixture.path().join("Client/.folderbase")).unwrap();
    fs::copy(
        child_fixture.path().join("FOLDERBASE.md"),
        fixture.path().join("Client/FOLDERBASE.md"),
    )
    .unwrap();
    fs::copy(
        child_fixture.path().join(".folderbase/manifest.json"),
        fixture.path().join("Client/.folderbase/manifest.json"),
    )
    .unwrap();
    let child_store = LocalVersionStore::open(fixture.path().join("Client")).unwrap();

    let wrong_source = parent_store.propose_history_transfer(
        &child_store,
        "folderbase_019f9b75-0b22-7a18-8f40-3f29f1438b62",
        &child.folderbase_id,
        &captured.object.id,
        "private.txt",
    );
    let wrong_destination = parent_store.propose_history_transfer(
        &child_store,
        &parent.folderbase_id,
        "folderbase_019f9b75-0b22-7a18-8f40-3f29f1438b63",
        &captured.object.id,
        "private.txt",
    );

    assert!(matches!(
        wrong_source,
        Err(FolderbaseError::InvalidRecord { .. })
    ));
    assert!(matches!(
        wrong_destination,
        Err(FolderbaseError::InvalidRecord { .. })
    ));
    assert!(
        !fixture
            .path()
            .join(".folderbase/history-transfers")
            .exists()
    );
}

#[test]
fn approved_transfer_preserves_identity_and_all_versions() {
    let (fixture, parent_store, child_store, parent_id, child_id, object_id, version_ids) =
        nested_history_transfer_fixture();
    let plan = parent_store
        .propose_history_transfer(
            &child_store,
            &parent_id,
            &child_id,
            &object_id,
            "private.txt",
        )
        .unwrap();
    assert_eq!(plan.state(), HistoryTransferState::Proposed);

    let result = apply_history_transfer(approve_history_transfer(plan).unwrap()).unwrap();

    assert_eq!(result.state, HistoryTransferState::Verified);
    assert_eq!(result.object_id, object_id);
    assert_eq!(result.version_ids, version_ids);
    let object = child_store.read_object(&object_id).unwrap();
    assert_eq!(object.id, object_id);
    assert_eq!(object.path, "private.txt");
    assert_eq!(object.versions, version_ids);
    assert_eq!(object.current_version, version_ids[1]);
    for (index, (version_id, expected)) in version_ids
        .iter()
        .zip([b"v1\n".as_slice(), b"v2\n".as_slice()])
        .enumerate()
    {
        let version = child_store.read_version(version_id).unwrap();
        assert_eq!(version.id, *version_id);
        child_store
            .restore_version(version_id, format!("restored-{index}.txt"))
            .unwrap();
        assert_eq!(
            fs::read(fixture.path().join(format!("Client/restored-{index}.txt"))).unwrap(),
            expected
        );
    }
}

#[test]
fn parent_cannot_read_transferred_history() {
    let (fixture, parent_store, child_store, parent_id, child_id, object_id, version_ids) =
        nested_history_transfer_fixture();
    let plan = parent_store
        .propose_history_transfer(
            &child_store,
            &parent_id,
            &child_id,
            &object_id,
            "private.txt",
        )
        .unwrap();
    apply_history_transfer(approve_history_transfer(plan).unwrap()).unwrap();

    let object_read = parent_store.read_object(&object_id);
    let version_read = parent_store.read_version(&version_ids[0]);
    let journal_read = parent_store.journal_events();
    let restore = parent_store.restore_version(&version_ids[0], "leaked.txt");

    assert_eq!(
        (
            matches!(object_read, Err(FolderbaseError::InvalidRecord { .. })),
            matches!(version_read, Err(FolderbaseError::InvalidRecord { .. })),
            matches!(journal_read, Err(FolderbaseError::UnsafePath(_)))
                || matches!(journal_read, Err(FolderbaseError::InvalidRecord { .. })),
            matches!(restore, Err(FolderbaseError::InvalidRecord { .. })),
        ),
        (true, true, true, true)
    );
    assert!(!fixture.path().join("leaked.txt").exists());
    assert_eq!(
        child_store.read_object(&object_id).unwrap().versions,
        version_ids
    );
}

#[test]
fn relationship_or_nesting_cannot_trigger_history_transfer() {
    let (fixture, _parent_store, _child_store, _parent_id, _child_id, object_id, _) =
        nested_history_transfer_fixture();
    assert!(
        !fixture
            .path()
            .join(".folderbase/history-transfers")
            .exists()
    );
    assert!(
        !fixture
            .path()
            .join("Client/.folderbase/history-transfers")
            .exists()
    );

    let plan = MigrationPlan::propose_structural(
        fixture.path(),
        vec![MigrationOperation::add_relationship(
            format!(".folderbase/objects/{object_id}.json"),
            "related_to",
            object_id.to_string(),
        )],
    )
    .unwrap();
    apply_migration(approve_migration(plan).unwrap()).unwrap();

    assert!(
        !fixture
            .path()
            .join(".folderbase/history-transfers")
            .exists()
    );
    assert!(
        !fixture
            .path()
            .join("Client/.folderbase/history-transfers")
            .exists()
    );
}

#[test]
fn tampered_history_transfer_intent_fails_closed() {
    let (fixture, parent_store, child_store, parent_id, child_id, object_id, _) =
        nested_history_transfer_fixture();
    let plan = parent_store
        .propose_history_transfer(
            &child_store,
            &parent_id,
            &child_id,
            &object_id,
            "private.txt",
        )
        .unwrap();
    let transfer_id = plan.id().to_owned();
    let approved = approve_history_transfer(plan).unwrap();
    let intent_path = fixture
        .path()
        .join(".folderbase/history-transfers/intents")
        .join(format!("{transfer_id}.json"));
    let mut intent: serde_json::Value =
        serde_json::from_slice(&fs::read(&intent_path).unwrap()).unwrap();
    intent["destination_path"] = serde_json::json!("tampered.txt");
    fs::write(&intent_path, serde_json::to_vec_pretty(&intent).unwrap()).unwrap();

    let error = apply_history_transfer(approved).unwrap_err();

    assert!(matches!(error, FolderbaseError::MigrationApprovalMismatch));
    assert!(
        !fixture
            .path()
            .join(".folderbase/history-transfers/outgoing")
            .exists()
    );
    assert!(
        !fixture
            .path()
            .join("Client/.folderbase/history-transfers")
            .exists()
    );
    assert!(child_store.read_object(&object_id).is_err());
}

#[test]
fn destination_collision_after_transfer_proposal_fails_before_source_release() {
    let (fixture, parent_store, child_store, parent_id, child_id, object_id, _) =
        nested_history_transfer_fixture();
    let plan = parent_store
        .propose_history_transfer(
            &child_store,
            &parent_id,
            &child_id,
            &object_id,
            "private.txt",
        )
        .unwrap();
    let transfer_id = plan.id().to_owned();
    let approved = approve_history_transfer(plan).unwrap();
    let child_capture = child_store.capture_file("private.txt").unwrap();

    let error = apply_history_transfer(approved).unwrap_err();

    assert!(matches!(error, FolderbaseError::WouldOverwrite(_)));
    assert_eq!(
        HistoryTransferPlan::reopen(fixture.path(), &transfer_id)
            .unwrap()
            .state(),
        HistoryTransferState::Conflicted
    );
    assert!(
        !fixture
            .path()
            .join(".folderbase/history-transfers/outgoing")
            .join(format!("{object_id}.json"))
            .exists()
    );
    assert_eq!(
        child_store
            .read_object(&child_capture.object.id)
            .unwrap()
            .path,
        "private.txt"
    );
}

#[test]
fn verified_transfer_recovery_allows_child_evolution_and_manifest_reformatting() {
    let (fixture, parent_store, child_store, parent_id, child_id, object_id, version_ids) =
        nested_history_transfer_fixture();
    let plan = parent_store
        .propose_history_transfer(
            &child_store,
            &parent_id,
            &child_id,
            &object_id,
            "private.txt",
        )
        .unwrap();
    let transfer_id = plan.id().to_owned();
    apply_history_transfer(approve_history_transfer(plan).unwrap()).unwrap();

    fs::write(fixture.path().join("Client/private.txt"), "v3\n").unwrap();
    let evolved = child_store.capture_file("private.txt").unwrap();
    let manifest_path = fixture.path().join("Client/.folderbase/manifest.json");
    let mut manifest = fs::read(&manifest_path).unwrap();
    manifest.push(b'\n');
    fs::write(&manifest_path, manifest).unwrap();

    let recovered = HistoryTransferResult::recover(fixture.path(), &transfer_id).unwrap();

    assert_eq!(recovered.state, HistoryTransferState::Verified);
    assert_eq!(recovered.object_id, object_id);
    assert_eq!(recovered.version_ids, version_ids);
    assert_eq!(evolved.object.id, object_id);
    assert_eq!(evolved.object.versions.len(), version_ids.len() + 1);
    assert!(evolved.object.versions.starts_with(&version_ids));
    assert_eq!(
        child_store.read_object(&object_id).unwrap().current_version,
        evolved.version.id
    );
}

#[test]
fn case_only_parent_rename_to_nested_folderbase_revokes_parent_history() {
    let fixture = tempdir().unwrap();
    fs::create_dir(fixture.path().join("Child")).unwrap();
    if fixture.path().join("child").exists() {
        // The distinct spellings required by this regression only exist on a
        // case-sensitive filesystem.
        return;
    }
    fs::write(fixture.path().join("Child/private.txt"), "private history").unwrap();
    let store = LocalVersionStore::open(fixture.path()).unwrap();
    let captured = store.capture_file("Child/private.txt").unwrap();

    fs::rename(fixture.path().join("Child"), fixture.path().join("child")).unwrap();
    fs::create_dir(fixture.path().join("child/.folderbase")).unwrap();
    fs::write(fixture.path().join("child/FOLDERBASE.md"), "# Child\n").unwrap();
    fs::write(
        fixture.path().join("child/.folderbase/manifest.json"),
        "{}\n",
    )
    .unwrap();

    let object_read = store.read_object(&captured.object.id);
    let version_read = store.read_version(&captured.version.id);
    let history_read = store.journal_events();
    let restore = store.restore_version(&captured.version.id, "restored-private.txt");

    assert_eq!(
        (
            matches!(object_read, Err(FolderbaseError::UnsafePath(_))),
            matches!(version_read, Err(FolderbaseError::UnsafePath(_))),
            matches!(history_read, Err(FolderbaseError::UnsafePath(_))),
            matches!(restore, Err(FolderbaseError::UnsafePath(_))),
        ),
        (true, true, true, true)
    );
    assert!(!fixture.path().join("restored-private.txt").exists());
}

#[cfg(unix)]
#[test]
fn stale_case_spelling_alias_cannot_hide_a_retroactive_nested_folderbase_boundary() {
    use std::os::unix::fs::MetadataExt;

    let fixture = tempdir().unwrap();
    fs::create_dir(fixture.path().join("Child")).unwrap();
    if fixture.path().join("child").exists() {
        return;
    }
    fs::create_dir(fixture.path().join("child")).unwrap();
    let upper = fs::metadata(fixture.path().join("Child")).unwrap();
    let lower = fs::metadata(fixture.path().join("child")).unwrap();
    assert_ne!((upper.dev(), upper.ino()), (lower.dev(), lower.ino()));
    fs::write(fixture.path().join("Child/private.txt"), "private history").unwrap();
    fs::write(fixture.path().join("child/private.txt"), "decoy").unwrap();
    let store = LocalVersionStore::open(fixture.path()).unwrap();
    let captured = store.capture_file("Child/private.txt").unwrap();

    let object_record_path = fixture
        .path()
        .join(format!(".folderbase/objects/{}.json", captured.object.id));
    let mut stale_record: serde_json::Value =
        serde_json::from_slice(&fs::read(&object_record_path).unwrap()).unwrap();
    stale_record["path"] = serde_json::Value::String("child/private.txt".to_owned());
    fs::write(
        &object_record_path,
        serde_json::to_vec_pretty(&stale_record).unwrap(),
    )
    .unwrap();

    fs::create_dir(fixture.path().join("Child/.folderbase")).unwrap();
    fs::write(fixture.path().join("Child/FOLDERBASE.md"), "# Child\n").unwrap();
    fs::write(
        fixture.path().join("Child/.folderbase/manifest.json"),
        "{}\n",
    )
    .unwrap();

    assert!(matches!(
        store.read_object(&captured.object.id),
        Err(FolderbaseError::UnsafePath(_))
    ));
    assert!(matches!(
        store.read_version(&captured.version.id),
        Err(FolderbaseError::UnsafePath(_))
    ));
    assert!(matches!(
        store.journal_events(),
        Err(FolderbaseError::UnsafePath(_))
    ));
}

#[test]
fn deleted_source_history_remains_readable_and_restorable() {
    let fixture = tempdir().unwrap();
    fs::write(fixture.path().join("deleted.txt"), "recoverable history").unwrap();
    let store = LocalVersionStore::open(fixture.path()).unwrap();
    let captured = store.capture_file("deleted.txt").unwrap();
    fs::remove_file(fixture.path().join("deleted.txt")).unwrap();

    assert_eq!(
        store.read_object(&captured.object.id).unwrap().id,
        captured.object.id
    );
    assert_eq!(
        store.read_version(&captured.version.id).unwrap().id,
        captured.version.id
    );
    assert!(!store.journal_events().unwrap().is_empty());
    store
        .restore_version(&captured.version.id, "recovered.txt")
        .unwrap();
    assert_eq!(
        fs::read(fixture.path().join("recovered.txt")).unwrap(),
        b"recoverable history"
    );
}

#[cfg(unix)]
#[test]
fn content_paths_reject_symlinked_parents() {
    use std::os::unix::fs::symlink;

    let fixture = tempdir().unwrap();
    let outside = tempdir().unwrap();
    fs::write(outside.path().join("outside.txt"), "outside").unwrap();
    symlink(outside.path(), fixture.path().join("linked")).unwrap();
    let store = LocalVersionStore::open(fixture.path()).unwrap();

    let error = store.capture_file("linked/outside.txt").unwrap_err();
    assert!(matches!(error, FolderbaseError::UnsafePath(_)));
}

#[cfg(unix)]
#[test]
fn workspace_and_version_store_share_one_symlink_root_policy() {
    use std::os::unix::fs::symlink;

    let fixture = tempdir().unwrap();
    let target = tempdir().unwrap();
    fs::write(target.path().join("note.md"), "outside").unwrap();
    let linked_root = fixture.path().join("folderbase-link");
    symlink(target.path(), &linked_root).unwrap();

    let error = LocalVersionStore::open(&linked_root).unwrap_err();
    assert!(matches!(error, FolderbaseError::InvalidRoot(_)));
    assert!(matches!(
        list_workspace(&linked_root),
        Err(FolderbaseError::InvalidRoot(_))
    ));
    assert!(!target.path().join(".folderbase").exists());
}

fn copy_portable_protocol_state(source_root: &std::path::Path, destination_root: &std::path::Path) {
    fn copy_directory(source: &std::path::Path, destination: &std::path::Path) {
        fs::create_dir_all(destination).unwrap();
        for entry in fs::read_dir(source).unwrap() {
            let entry = entry.unwrap();
            let destination = destination.join(entry.file_name());
            if entry.file_type().unwrap().is_dir() {
                copy_directory(&entry.path(), &destination);
            } else {
                fs::copy(entry.path(), destination).unwrap();
            }
        }
    }

    for portable_directory in ["objects", "versions", "journal"] {
        copy_directory(
            &source_root.join(".folderbase").join(portable_directory),
            &destination_root
                .join(".folderbase")
                .join(portable_directory),
        );
    }
}

fn nested_history_transfer_fixture() -> (
    tempfile::TempDir,
    LocalVersionStore,
    LocalVersionStore,
    String,
    String,
    folderbase_core::ObjectId,
    Vec<VersionId>,
) {
    let fixture = tempdir().unwrap();
    let parent = initialize(
        &plan_initialization(
            fixture.path(),
            InitializationOptions {
                name: Some("Parent".to_owned()),
                kind: FolderbaseKind::Organization,
                create_agent_adapters: false,
            },
        )
        .unwrap(),
    )
    .unwrap();
    fs::create_dir(fixture.path().join("Client")).unwrap();
    fs::write(fixture.path().join("Client/private.txt"), "v1\n").unwrap();
    let parent_store = LocalVersionStore::open(fixture.path()).unwrap();
    let first = parent_store.capture_file("Client/private.txt").unwrap();
    fs::write(fixture.path().join("Client/private.txt"), "v2\n").unwrap();
    let second = parent_store.capture_file("Client/private.txt").unwrap();

    let child_fixture = tempdir().unwrap();
    let child = initialize(
        &plan_initialization(
            child_fixture.path(),
            InitializationOptions {
                name: Some("Client".to_owned()),
                kind: FolderbaseKind::Project,
                create_agent_adapters: false,
            },
        )
        .unwrap(),
    )
    .unwrap();
    fs::create_dir_all(fixture.path().join("Client/.folderbase")).unwrap();
    fs::copy(
        child_fixture.path().join("FOLDERBASE.md"),
        fixture.path().join("Client/FOLDERBASE.md"),
    )
    .unwrap();
    fs::copy(
        child_fixture.path().join(".folderbase/manifest.json"),
        fixture.path().join("Client/.folderbase/manifest.json"),
    )
    .unwrap();
    let child_store = LocalVersionStore::open(fixture.path().join("Client")).unwrap();
    (
        fixture,
        parent_store,
        child_store,
        parent.folderbase_id,
        child.folderbase_id,
        first.object.id,
        vec![first.version.id, second.version.id],
    )
}

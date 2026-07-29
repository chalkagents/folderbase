use std::{fs, path::Path};

use folderbase_core::{
    CaptureEntryKind, FolderbaseCaptureError, FolderbaseVersionStore, LocalVersionStore,
    PathBindingKind, VersionId, folderbase_version::DeletedKind,
};
use sha2::{Digest, Sha256};
use tempfile::{TempDir, tempdir};

const FOLDERBASE_ID: &str = "folderbase_019f9b75-4f42-7f65-a012-2bfecdd8c473";
const MANIFEST: &[u8] = br#"{
  "protocol_version": "0.4.0",
  "folderbase": {
    "id": "folderbase_019f9b75-4f42-7f65-a012-2bfecdd8c473"
  }
}
"#;

fn folderbase() -> TempDir {
    let root = tempdir().expect("temporary Folderbase");
    fs::create_dir(root.path().join(".folderbase")).expect("state directory");
    fs::write(root.path().join(".folderbase/manifest.json"), MANIFEST).expect("manifest");
    fs::write(root.path().join(".folderbaseignore"), "node_modules/\n").expect("ignore policy");
    fs::write(root.path().join("FOLDERBASE.md"), "# Folderbase\n").expect("entry");
    root
}

#[test]
fn genesis_seals_mixed_opaque_bytes_and_fidelity_before_advancing_local_head() {
    let root = folderbase();
    fs::create_dir(root.path().join("empty")).expect("empty directory");
    for (path, contents) in [
        ("reference.pdf", b"%PDF opaque".as_slice()),
        ("movie.mov", b"opaque video".as_slice()),
        ("data.csv", b"a,b\n1,2\n".as_slice()),
        ("database.sqlite", b"SQLite format 3\0opaque".as_slice()),
        (".git/objects/pack/test.pack", b"git pack opaque".as_slice()),
    ] {
        let path = root.path().join(path);
        fs::create_dir_all(path.parent().unwrap()).expect("opaque parent");
        fs::write(path, contents).expect("opaque bytes");
    }
    fs::create_dir_all(root.path().join("node_modules/pkg")).expect("ignored tree");
    fs::write(root.path().join("node_modules/pkg/index.js"), "generated").expect("ignored file");
    let large = root.path().join("bounded-large.bin");
    fs::File::create(&large)
        .expect("large fixture")
        .set_len(8 * 1024 * 1024)
        .expect("practical sparse length");

    #[cfg(unix)]
    {
        use std::os::unix::fs::{PermissionsExt, symlink};

        fs::set_permissions(
            root.path().join("data.csv"),
            fs::Permissions::from_mode(0o755),
        )
        .expect("executable fidelity");
        fs::create_dir(root.path().join("links")).expect("links");
        symlink("../reference.pdf", root.path().join("links/reference")).expect("safe symlink");
    }

    let store = FolderbaseVersionStore::open(root.path()).expect("open");
    let plan = store.plan_capture().expect("metadata-first plan");
    assert!(
        plan.entries()
            .iter()
            .any(|entry| entry.path() == "bounded-large.bin"
                && entry.bytes() == Some(8 * 1024 * 1024))
    );
    let sealed = store.seal_capture(plan).expect("sealed capture");

    assert!(sealed.created());
    assert_eq!(sealed.version_sha256().len(), 64);
    let version = store
        .read_version(sealed.version_id())
        .expect("durable Folderbase Version");
    assert_eq!(version.folderbase_id(), FOLDERBASE_ID);
    assert_eq!(version.parents(), &[] as &[String]);
    assert_eq!(
        version.canonical_digest().expect("canonical digest"),
        sealed.version_sha256()
    );
    assert_eq!(
        version
            .lookup_binding("empty")
            .expect("empty directory")
            .kind(),
        PathBindingKind::Directory
    );
    assert!(
        version
            .bindings()
            .iter()
            .all(|binding| !binding.path().starts_with(".folderbase/"))
    );
    assert!(
        version
            .lookup_binding("node_modules/pkg/index.js")
            .is_none()
    );

    for path in [
        ".folderbaseignore",
        "FOLDERBASE.md",
        "reference.pdf",
        "movie.mov",
        "data.csv",
        "database.sqlite",
        "bounded-large.bin",
    ] {
        let binding = version.lookup_binding(path).expect("regular binding");
        assert_eq!(binding.kind(), PathBindingKind::RegularFile);
        let object_version =
            VersionId::parse(binding.object_version_id().expect("Object Version")).unwrap();
        let local = LocalVersionStore::open(root.path())
            .expect("local store")
            .read_version(&object_version)
            .expect("existing LocalVersionStore record");
        assert_eq!(local.object_id.as_str(), binding.object_id());
        assert_eq!(
            local.content.digest,
            binding.content_sha256().expect("content digest")
        );
    }
    assert!(
        version
            .lookup_binding(".git/objects/pack/test.pack")
            .is_some(),
        "Git repository bytes remain in the Folderbase Version even though the legacy workspace projection collapses .git"
    );

    #[cfg(unix)]
    {
        let executable = version.lookup_binding("data.csv").expect("CSV");
        assert_eq!(executable.executable(), Some(true));
        let link = version
            .lookup_binding("links/reference")
            .expect("symlink binding");
        assert_eq!(link.kind(), PathBindingKind::Symlink);
        assert_eq!(link.symlink_target(), Some("../reference.pdf"));
    }

    let next_plan = store.plan_capture().expect("post-capture plan");
    let head = next_plan.current_local_head().expect("Local Head");
    assert_eq!(head.version_id(), sealed.version_id());
    assert_eq!(head.version_sha256(), sealed.version_sha256());
}

#[test]
fn update_reuses_only_prior_verified_head_bindings_and_noop_retry_converges() {
    let root = folderbase();
    fs::create_dir(root.path().join("docs")).expect("docs");
    fs::write(root.path().join("docs/notes.md"), "first\n").expect("notes");

    let store = FolderbaseVersionStore::open(root.path()).expect("open");
    let genesis = store
        .seal_capture(store.plan_capture().expect("genesis plan"))
        .expect("genesis");
    let first = store
        .read_version(genesis.version_id())
        .expect("genesis version");
    let first_docs_id = first.lookup_binding("docs").unwrap().object_id().to_owned();
    let first_note = first.lookup_binding("docs/notes.md").unwrap();
    let first_note_id = first_note.object_id().to_owned();
    let first_note_version = first_note.object_version_id().unwrap().to_owned();

    fs::write(root.path().join("docs/notes.md"), "second\n").expect("update in place");
    fs::write(root.path().join("docs/new.pdf"), "%PDF new").expect("new opaque file");

    let update = store
        .seal_capture(store.plan_capture().expect("update plan"))
        .expect("update");
    let second = store
        .read_version(update.version_id())
        .expect("updated version");
    assert_eq!(second.parents(), &[genesis.version_id().to_owned()]);
    assert_eq!(
        second.lookup_binding("docs").unwrap().object_id(),
        first_docs_id
    );
    let second_note = second.lookup_binding("docs/notes.md").unwrap();
    assert_eq!(second_note.object_id(), first_note_id);
    assert_ne!(second_note.object_version_id().unwrap(), first_note_version);
    assert!(second.lookup_binding("docs/new.pdf").is_some());

    let retry = store
        .seal_capture(store.plan_capture().expect("no-op retry plan"))
        .expect("idempotent retry");
    assert!(!retry.created());
    assert_eq!(retry.version_id(), update.version_id());
    assert_eq!(retry.version_sha256(), update.version_sha256());
}

#[test]
fn stale_plan_or_concurrent_edit_fails_without_moving_local_head() {
    let root = folderbase();
    fs::write(root.path().join("active.sqlite"), b"SQLite first").expect("database");
    let store = FolderbaseVersionStore::open(root.path()).expect("open");
    let plan = store.plan_capture().expect("plan");
    fs::write(root.path().join("active.sqlite"), b"SQLite second").expect("concurrent edit");

    assert!(matches!(
        store.seal_capture(plan),
        Err(FolderbaseCaptureError::CaptureStateChanged(path))
            if path == Path::new("active.sqlite")
    ));
    assert!(!root.path().join(".folderbase/local/head.json").exists());
}

#[test]
fn deletion_seals_a_durable_tombstone_and_advances_local_head() {
    let root = folderbase();
    fs::write(root.path().join("proposal.docx"), b"opaque document").expect("document");
    let store = FolderbaseVersionStore::open(root.path()).expect("open");
    let genesis = store
        .seal_capture(store.plan_capture().expect("genesis plan"))
        .expect("genesis");
    let prior = store
        .read_version(genesis.version_id())
        .expect("genesis version");
    let prior_binding = prior
        .lookup_binding("proposal.docx")
        .expect("prior binding");
    let prior_object_id = prior_binding.object_id().to_owned();
    let prior_object_version_id = prior_binding
        .object_version_id()
        .expect("prior Object Version")
        .to_owned();
    fs::remove_file(root.path().join("proposal.docx")).expect("delete live document");

    let deletion = store
        .seal_capture(store.plan_capture().expect("deletion plan"))
        .expect("deletion capture");
    assert!(deletion.created());
    let deleted = store
        .read_version(deletion.version_id())
        .expect("Tombstone-bearing version");
    assert_eq!(deleted.parents(), &[genesis.version_id().to_owned()]);
    assert!(deleted.lookup_binding("proposal.docx").is_none());
    assert_eq!(deleted.tombstones().len(), 1);
    let tombstone = &deleted.tombstones()[0];
    assert_eq!(tombstone.path(), "proposal.docx");
    assert_eq!(tombstone.object_id(), prior_object_id);
    assert_eq!(tombstone.deleted_kind(), DeletedKind::RegularFile);
    assert_eq!(
        tombstone.last_object_version_id(),
        Some(prior_object_version_id.as_str())
    );

    let head = store
        .plan_capture()
        .expect("new Head remains readable")
        .current_local_head()
        .expect("new Head")
        .version_id()
        .to_owned();
    assert_eq!(head, deletion.version_id());

    let retry = store
        .seal_capture(store.plan_capture().expect("retry plan"))
        .expect("idempotent Tombstone retry");
    assert!(!retry.created());
    assert_eq!(retry.version_id(), deletion.version_id());
}

#[test]
fn restore_tombstone_reinstates_exact_sealed_bytes_metadata_and_local_head() {
    let root = folderbase();
    let path = root.path().join("proposal.docx");
    let exact_bytes = [0_u8, 255, 17, 42, 0, 99];
    fs::write(&path, exact_bytes).expect("opaque document");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("executable fidelity");
    }

    let store = FolderbaseVersionStore::open(root.path()).expect("open");
    let genesis = store
        .seal_capture(store.plan_capture().expect("genesis plan"))
        .expect("genesis");
    let prior = store
        .read_version(genesis.version_id())
        .expect("genesis version");
    let prior_binding = prior
        .lookup_binding("proposal.docx")
        .expect("prior live binding");
    let prior_object_id = prior_binding.object_id().to_owned();
    let prior_object_version_id = prior_binding
        .object_version_id()
        .expect("prior Object Version")
        .to_owned();
    let prior_sha256 = prior_binding
        .content_sha256()
        .expect("prior content digest")
        .to_owned();
    let prior_executable = prior_binding.executable();

    fs::remove_file(&path).expect("delete live document");
    let deletion = store
        .seal_capture(store.plan_capture().expect("deletion plan"))
        .expect("deletion");
    let deleted = store
        .read_version(deletion.version_id())
        .expect("Tombstone-bearing version");
    assert!(deleted.lookup_binding("proposal.docx").is_none());
    assert_eq!(deleted.tombstones().len(), 1);

    let restored = store
        .restore_tombstone("proposal.docx")
        .expect("restore exact Tombstone bytes");

    assert!(restored.created());
    assert_eq!(restored.path(), Path::new("proposal.docx"));
    assert_eq!(restored.object_id(), prior_object_id);
    assert_eq!(restored.object_version_id(), prior_object_version_id);
    assert_eq!(fs::read(&path).expect("restored bytes"), exact_bytes);
    let current = store
        .read_version(restored.version_id())
        .expect("restored Folderbase Version");
    assert_eq!(current.parents(), &[deletion.version_id().to_owned()]);
    let current_binding = current
        .lookup_binding("proposal.docx")
        .expect("restored live binding");
    assert_eq!(current_binding.object_id(), prior_object_id);
    assert_eq!(
        current_binding.object_version_id(),
        Some(prior_object_version_id.as_str())
    );
    assert_eq!(
        current_binding.content_sha256(),
        Some(prior_sha256.as_str())
    );
    assert_eq!(current_binding.bytes(), Some(exact_bytes.len() as u64));
    assert_eq!(current_binding.executable(), prior_executable);
    assert!(
        current
            .tombstones()
            .iter()
            .all(|tombstone| tombstone.path() != "proposal.docx")
    );
    assert_eq!(
        store
            .plan_capture()
            .expect("restored Head remains readable")
            .current_local_head()
            .expect("restored Head")
            .version_id(),
        restored.version_id()
    );
    assert_eq!(
        store
            .read_version(deletion.version_id())
            .expect("immutable deletion history remains")
            .tombstones()
            .len(),
        1
    );
}

#[test]
fn restore_refuses_every_existing_target_without_mutating_history_or_intent() {
    let root = folderbase();
    for (path, bytes) in [
        ("same.bin", b"same".as_slice()),
        ("different.bin", b"sealed".as_slice()),
        ("occupied-dir", b"was a file".as_slice()),
    ] {
        fs::write(root.path().join(path), bytes).expect("live file");
    }
    #[cfg(unix)]
    for (path, bytes) in [
        ("occupied-link", b"was a link target".as_slice()),
        ("dangling-link", b"was a dangling link".as_slice()),
    ] {
        fs::write(root.path().join(path), bytes).expect("live file");
    }
    let store = FolderbaseVersionStore::open(root.path()).expect("open");
    store
        .seal_capture(store.plan_capture().expect("genesis plan"))
        .expect("genesis");
    for path in ["same.bin", "different.bin", "occupied-dir"] {
        fs::remove_file(root.path().join(path)).expect("delete");
    }
    #[cfg(unix)]
    for path in ["occupied-link", "dangling-link"] {
        fs::remove_file(root.path().join(path)).expect("delete");
    }
    let deletion = store
        .seal_capture(store.plan_capture().expect("deletion plan"))
        .expect("deletion");

    fs::write(root.path().join("same.bin"), b"same").expect("same-byte foreign file");
    fs::write(root.path().join("different.bin"), b"foreign").expect("different foreign file");
    fs::create_dir(root.path().join("occupied-dir")).expect("foreign directory");
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;

        symlink("same.bin", root.path().join("occupied-link")).expect("foreign symlink");
        symlink("missing.bin", root.path().join("dangling-link"))
            .expect("foreign dangling symlink");
    }

    let head_path = root.path().join(".folderbase/local/head.json");
    let head_before = fs::read(&head_path).expect("Head");
    let versions = root.path().join(".folderbase/versions/folderbase");
    let version_count_before = fs::read_dir(&versions).expect("versions").count();
    let mut targets = vec![
        ("same.bin", "same-byte foreign file"),
        ("different.bin", "different foreign file"),
        ("occupied-dir", "foreign directory"),
    ];
    #[cfg(unix)]
    targets.extend([
        ("occupied-link", "foreign symlink"),
        ("dangling-link", "foreign dangling symlink"),
    ]);
    for (path, label) in targets {
        assert!(matches!(
            store.restore_tombstone(path),
            Err(FolderbaseCaptureError::RestoreTargetOccupied(ref occupied))
                if occupied.ends_with(path)
        ));
        assert_eq!(
            fs::read(&head_path).expect("unchanged Head"),
            head_before,
            "{label}"
        );
        assert_eq!(
            fs::read_dir(&versions).expect("versions").count(),
            version_count_before,
            "{label}"
        );
        assert!(
            !root
                .path()
                .join(".folderbase/transactions/folderbase-version-restores/active.json")
                .exists(),
            "{label}"
        );
    }
    assert_eq!(fs::read(root.path().join("same.bin")).unwrap(), b"same");
    assert_eq!(
        fs::read(root.path().join("different.bin")).unwrap(),
        b"foreign"
    );
    assert!(root.path().join("occupied-dir").is_dir());
    assert_eq!(
        store
            .read_version(deletion.version_id())
            .expect("immutable deletion version")
            .tombstones()
            .len(),
        if cfg!(unix) { 5 } else { 3 }
    );
}

#[test]
fn carried_tombstone_restores_from_nearest_verified_live_ancestor_only() {
    let root = folderbase();
    let path = root.path().join("proposal.docx");
    fs::write(&path, b"approved exact proposal").expect("proposal");
    fs::write(root.path().join("activity.md"), b"first").expect("activity");
    let store = FolderbaseVersionStore::open(root.path()).expect("open");
    let genesis = store
        .seal_capture(store.plan_capture().expect("genesis plan"))
        .expect("genesis");
    let original = store
        .read_version(genesis.version_id())
        .expect("genesis")
        .lookup_binding("proposal.docx")
        .expect("proposal")
        .clone();
    fs::remove_file(&path).expect("delete proposal");
    let deletion = store
        .seal_capture(store.plan_capture().expect("deletion plan"))
        .expect("deletion");
    fs::write(root.path().join("activity.md"), b"second").expect("unrelated update");
    let carried = store
        .seal_capture(store.plan_capture().expect("carried plan"))
        .expect("carried Tombstone");
    assert_eq!(
        store
            .read_version(carried.version_id())
            .unwrap()
            .tombstones()
            .len(),
        1
    );

    let restored = store
        .restore_tombstone("proposal.docx")
        .expect("restore across carried Tombstone");
    let current = store.read_version(restored.version_id()).unwrap();
    assert_eq!(current.parents(), &[carried.version_id().to_owned()]);
    assert_eq!(
        current.lookup_binding("proposal.docx"),
        Some(&original),
        "restore must recover exact Object Version and fidelity from genesis, not fabricate it from the Tombstone"
    );
    assert_eq!(fs::read(path).unwrap(), b"approved exact proposal");
    assert_eq!(
        store
            .read_version(deletion.version_id())
            .unwrap()
            .tombstones()
            .len(),
        1
    );
}

#[test]
fn delete_recreate_delete_restores_only_the_newest_tombstone_generation() {
    let root = folderbase();
    let path = root.path().join("proposal.docx");
    fs::write(&path, b"first generation").expect("first");
    let store = FolderbaseVersionStore::open(root.path()).expect("open");
    let first = store
        .seal_capture(store.plan_capture().expect("first plan"))
        .expect("first");
    let first_object = store
        .read_version(first.version_id())
        .unwrap()
        .lookup_binding("proposal.docx")
        .unwrap()
        .object_id()
        .to_owned();
    fs::remove_file(&path).expect("first delete");
    store
        .seal_capture(store.plan_capture().expect("first delete plan"))
        .expect("first delete");
    fs::write(&path, b"second generation").expect("second");
    let second = store
        .seal_capture(store.plan_capture().expect("second plan"))
        .expect("second");
    let second_binding = store
        .read_version(second.version_id())
        .unwrap()
        .lookup_binding("proposal.docx")
        .unwrap()
        .clone();
    assert_ne!(second_binding.object_id(), first_object);
    fs::remove_file(&path).expect("second delete");
    let second_deletion = store
        .seal_capture(store.plan_capture().expect("second delete plan"))
        .expect("second delete");
    let tombstone = store
        .read_version(second_deletion.version_id())
        .unwrap()
        .tombstones()[0]
        .clone();
    assert_eq!(tombstone.object_id(), second_binding.object_id());

    let restored = store
        .restore_tombstone("proposal.docx")
        .expect("restore newest generation");
    assert_eq!(restored.object_id(), second_binding.object_id());
    assert_eq!(
        restored.object_version_id(),
        second_binding.object_version_id().unwrap()
    );
    assert_eq!(fs::read(path).unwrap(), b"second generation");
}

#[test]
fn missing_immutable_restore_bytes_fail_before_journal_workspace_or_head_mutation() {
    let root = folderbase();
    let path = root.path().join("proposal.docx");
    fs::write(&path, b"sealed bytes").expect("proposal");
    let store = FolderbaseVersionStore::open(root.path()).expect("open");
    let genesis = store
        .seal_capture(store.plan_capture().expect("genesis plan"))
        .expect("genesis");
    let digest = store
        .read_version(genesis.version_id())
        .unwrap()
        .lookup_binding("proposal.docx")
        .unwrap()
        .content_sha256()
        .unwrap()
        .to_owned();
    fs::remove_file(&path).expect("delete proposal");
    store
        .seal_capture(store.plan_capture().expect("deletion plan"))
        .expect("deletion");
    let head_path = root.path().join(".folderbase/local/head.json");
    let head_before = fs::read(&head_path).unwrap();
    fs::remove_file(
        root.path()
            .join(".folderbase/versions/blobs/sha256")
            .join(digest),
    )
    .expect("remove immutable blob");

    assert!(store.restore_tombstone("proposal.docx").is_err());
    assert!(!path.exists());
    assert_eq!(fs::read(head_path).unwrap(), head_before);
    assert!(
        !root
            .path()
            .join(".folderbase/transactions/folderbase-version-restores/active.json")
            .exists()
    );
}

#[test]
fn corrupt_object_version_record_fails_before_restore_intent_or_head_mutation() {
    let root = folderbase();
    let path = root.path().join("proposal.docx");
    fs::write(&path, b"sealed bytes").expect("proposal");
    let store = FolderbaseVersionStore::open(root.path()).expect("open");
    let genesis = store
        .seal_capture(store.plan_capture().expect("genesis plan"))
        .expect("genesis");
    let object_version = store
        .read_version(genesis.version_id())
        .unwrap()
        .lookup_binding("proposal.docx")
        .unwrap()
        .object_version_id()
        .unwrap()
        .to_owned();
    fs::remove_file(&path).expect("delete proposal");
    store
        .seal_capture(store.plan_capture().expect("deletion plan"))
        .expect("deletion");
    let head_path = root.path().join(".folderbase/local/head.json");
    let head_before = fs::read(&head_path).unwrap();
    fs::write(
        root.path()
            .join(".folderbase/versions/records")
            .join(format!("{object_version}.json")),
        b"{\"corrupt\":true}\n",
    )
    .expect("corrupt immutable Object Version record");

    assert!(store.restore_tombstone("proposal.docx").is_err());
    assert!(!path.exists());
    assert_eq!(fs::read(head_path).unwrap(), head_before);
    assert!(
        !root
            .path()
            .join(".folderbase/transactions/folderbase-version-restores/active.json")
            .exists()
    );
}

#[test]
fn restore_removes_only_the_selected_tombstone_and_rejects_reserved_state() {
    let root = folderbase();
    fs::write(root.path().join("one.bin"), b"one").expect("one");
    fs::write(root.path().join("two.bin"), b"two").expect("two");
    let store = FolderbaseVersionStore::open(root.path()).expect("open");
    store
        .seal_capture(store.plan_capture().expect("genesis plan"))
        .expect("genesis");
    fs::remove_file(root.path().join("one.bin")).expect("delete one");
    fs::remove_file(root.path().join("two.bin")).expect("delete two");
    store
        .seal_capture(store.plan_capture().expect("deletion plan"))
        .expect("deletion");

    assert!(
        store
            .restore_tombstone(".folderbase/manifest.json")
            .is_err()
    );
    let restored = store.restore_tombstone("one.bin").expect("restore one");
    let current = store.read_version(restored.version_id()).unwrap();
    assert!(current.lookup_binding("one.bin").is_some());
    assert!(current.lookup_binding("two.bin").is_none());
    assert_eq!(current.tombstones().len(), 1);
    assert_eq!(current.tombstones()[0].path(), "two.bin");
}

#[test]
fn v1_restore_refuses_directory_tombstones_without_mutation() {
    let root = folderbase();
    fs::create_dir(root.path().join("archive")).expect("archive");
    let store = FolderbaseVersionStore::open(root.path()).expect("open");
    store
        .seal_capture(store.plan_capture().expect("genesis plan"))
        .expect("genesis");
    fs::remove_dir(root.path().join("archive")).expect("delete archive");
    let deletion = store
        .seal_capture(store.plan_capture().expect("deletion plan"))
        .expect("deletion");
    let head_path = root.path().join(".folderbase/local/head.json");
    let before = fs::read(&head_path).unwrap();

    assert!(matches!(
        store.restore_tombstone("archive"),
        Err(FolderbaseCaptureError::UnsupportedTombstoneKind(path))
            if path == Path::new("archive")
    ));
    assert_eq!(fs::read(head_path).unwrap(), before);
    assert_eq!(
        store
            .read_version(deletion.version_id())
            .unwrap()
            .tombstones()
            .len(),
        1
    );
}

#[cfg(unix)]
#[test]
fn v1_restore_refuses_symlink_tombstones_without_mutation() {
    use std::os::unix::fs::symlink;

    let root = folderbase();
    fs::write(root.path().join("target"), b"target").expect("target");
    symlink("target", root.path().join("reference")).expect("reference");
    let store = FolderbaseVersionStore::open(root.path()).expect("open");
    store
        .seal_capture(store.plan_capture().expect("genesis plan"))
        .expect("genesis");
    fs::remove_file(root.path().join("reference")).expect("delete symlink");
    let deletion = store
        .seal_capture(store.plan_capture().expect("deletion plan"))
        .expect("deletion");
    let head_path = root.path().join(".folderbase/local/head.json");
    let before = fs::read(&head_path).unwrap();

    assert!(matches!(
        store.restore_tombstone("reference"),
        Err(FolderbaseCaptureError::UnsupportedTombstoneKind(path))
            if path == Path::new("reference")
    ));
    assert_eq!(fs::read(head_path).unwrap(), before);
    assert_eq!(
        store
            .read_version(deletion.version_id())
            .unwrap()
            .tombstones()
            .iter()
            .find(|tombstone| tombstone.path() == "reference")
            .unwrap()
            .deleted_kind(),
        DeletedKind::Symlink
    );
}

#[test]
fn same_kind_atomic_replacement_preserves_logical_identity() {
    let root = folderbase();
    let path = root.path().join("proposal.docx");
    fs::write(&path, b"first opaque document").expect("document");
    let store = FolderbaseVersionStore::open(root.path()).expect("open");
    let genesis = store
        .seal_capture(store.plan_capture().expect("genesis plan"))
        .expect("genesis");
    let prior = store
        .read_version(genesis.version_id())
        .expect("genesis version");
    let prior_binding = prior
        .lookup_binding("proposal.docx")
        .expect("prior binding");
    let prior_object_id = prior_binding.object_id().to_owned();
    let prior_object_version_id = prior_binding
        .object_version_id()
        .expect("prior Object Version")
        .to_owned();

    let replacement = root.path().join("replacement.docx");
    fs::write(&replacement, b"second opaque document").expect("replacement");
    fs::remove_file(&path).expect("remove original identity");
    fs::rename(&replacement, &path).expect("move replacement onto same path");

    let replacement = store
        .seal_capture(store.plan_capture().expect("replacement plan"))
        .expect("same-kind atomic replacement");
    assert!(replacement.created());
    let current = store
        .read_version(replacement.version_id())
        .expect("replacement version");
    let current_binding = current
        .lookup_binding("proposal.docx")
        .expect("current binding");
    assert_eq!(current_binding.object_id(), prior_object_id);
    assert_ne!(
        current_binding
            .object_version_id()
            .expect("current Object Version"),
        prior_object_version_id
    );
    assert!(current.tombstones().is_empty());
}

#[cfg(unix)]
#[test]
fn fidelity_only_change_creates_a_new_object_version_under_the_same_object_id() {
    use std::os::unix::fs::PermissionsExt;

    let root = folderbase();
    let path = root.path().join("script.sh");
    fs::write(&path, b"#!/bin/sh\n").expect("script");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("initial mode");
    let store = FolderbaseVersionStore::open(root.path()).expect("open");
    let genesis = store
        .seal_capture(store.plan_capture().expect("genesis plan"))
        .expect("genesis");
    let prior = store
        .read_version(genesis.version_id())
        .expect("genesis version");
    let prior_binding = prior.lookup_binding("script.sh").expect("prior binding");
    let prior_object_id = prior_binding.object_id().to_owned();
    let prior_object_version_id = prior_binding
        .object_version_id()
        .expect("prior Object Version")
        .to_owned();
    assert_eq!(prior_binding.executable(), Some(false));

    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("executable mode");
    let changed = store
        .seal_capture(store.plan_capture().expect("fidelity plan"))
        .expect("fidelity capture");
    let current = store
        .read_version(changed.version_id())
        .expect("fidelity version");
    let current_binding = current
        .lookup_binding("script.sh")
        .expect("current binding");
    assert_eq!(current_binding.object_id(), prior_object_id);
    assert_ne!(
        current_binding
            .object_version_id()
            .expect("current Object Version"),
        prior_object_version_id
    );
    assert_eq!(current_binding.executable(), Some(true));
    assert!(current.tombstones().is_empty());
}

#[test]
fn supported_kind_replacements_tombstone_old_identity_and_assign_new_identity() {
    fn create_regular(path: &Path) {
        fs::write(path, b"opaque file").expect("regular file");
    }

    fn replace_regular_with_directory(path: &Path) {
        fs::remove_file(path).expect("remove regular file");
        fs::create_dir(path).expect("replacement directory");
    }

    fn create_directory(path: &Path) {
        fs::create_dir(path).expect("directory");
    }

    fn replace_directory_with_regular(path: &Path) {
        fs::remove_dir(path).expect("remove directory");
        fs::write(path, b"replacement file").expect("replacement regular file");
    }

    for (create_initial, replace, deleted_kind, current_kind) in [
        (
            create_regular as fn(&Path),
            replace_regular_with_directory as fn(&Path),
            DeletedKind::RegularFile,
            PathBindingKind::Directory,
        ),
        (
            create_directory,
            replace_directory_with_regular,
            DeletedKind::Directory,
            PathBindingKind::RegularFile,
        ),
    ] {
        let root = folderbase();
        let path = root.path().join("kind-switch");
        create_initial(&path);
        let store = FolderbaseVersionStore::open(root.path()).expect("open");
        let genesis = store
            .seal_capture(store.plan_capture().expect("genesis plan"))
            .expect("genesis");
        let prior = store
            .read_version(genesis.version_id())
            .expect("genesis version");
        let prior_binding = prior.lookup_binding("kind-switch").expect("prior binding");
        let prior_object_id = prior_binding.object_id().to_owned();
        let prior_object_version_id = prior_binding.object_version_id().map(str::to_owned);

        replace(&path);
        let replacement = store
            .seal_capture(store.plan_capture().expect("replacement plan"))
            .expect("kind replacement");
        let current = store
            .read_version(replacement.version_id())
            .expect("replacement version");
        let current_binding = current
            .lookup_binding("kind-switch")
            .expect("replacement binding");
        assert_eq!(current_binding.kind(), current_kind);
        assert_ne!(current_binding.object_id(), prior_object_id);
        assert_eq!(current.tombstones().len(), 1);
        let tombstone = &current.tombstones()[0];
        assert_eq!(tombstone.path(), "kind-switch");
        assert_eq!(tombstone.object_id(), prior_object_id);
        assert_eq!(tombstone.deleted_kind(), deleted_kind);
        assert_eq!(
            tombstone.last_object_version_id(),
            prior_object_version_id.as_deref()
        );
    }
}

#[test]
fn delete_recreate_delete_keeps_only_the_newest_tombstone_for_the_path() {
    let root = folderbase();
    let path = root.path().join("proposal.docx");
    fs::write(&path, b"first proposal").expect("first proposal");
    let store = FolderbaseVersionStore::open(root.path()).expect("open");
    let genesis = store
        .seal_capture(store.plan_capture().expect("genesis plan"))
        .expect("genesis");
    let genesis_version = store
        .read_version(genesis.version_id())
        .expect("genesis version");
    let first_binding = genesis_version
        .lookup_binding("proposal.docx")
        .expect("first binding");
    let first_object_id = first_binding.object_id().to_owned();

    fs::remove_file(&path).expect("first deletion");
    let first_deletion = store
        .seal_capture(store.plan_capture().expect("first deletion plan"))
        .expect("first deletion");
    let first_deleted = store
        .read_version(first_deletion.version_id())
        .expect("first Tombstone version");
    assert_eq!(first_deleted.tombstones().len(), 1);
    assert_eq!(first_deleted.tombstones()[0].object_id(), first_object_id);

    fs::write(&path, b"replacement proposal").expect("replacement proposal");
    let recreation = store
        .seal_capture(store.plan_capture().expect("recreation plan"))
        .expect("recreation");
    let recreated = store
        .read_version(recreation.version_id())
        .expect("recreated version");
    let replacement_binding = recreated
        .lookup_binding("proposal.docx")
        .expect("replacement binding");
    let replacement_object_id = replacement_binding.object_id().to_owned();
    let replacement_object_version_id = replacement_binding
        .object_version_id()
        .expect("replacement Object Version")
        .to_owned();
    assert_ne!(replacement_object_id, first_object_id);
    assert_eq!(recreated.tombstones().len(), 1);
    assert_eq!(recreated.tombstones()[0].object_id(), first_object_id);

    fs::remove_file(&path).expect("second deletion");
    let second_deletion = store
        .seal_capture(store.plan_capture().expect("second deletion plan"))
        .expect("second deletion");
    let final_version = store
        .read_version(second_deletion.version_id())
        .expect("final Tombstone version");
    assert!(final_version.lookup_binding("proposal.docx").is_none());
    assert_eq!(final_version.tombstones().len(), 1);
    let newest = &final_version.tombstones()[0];
    assert_eq!(newest.path(), "proposal.docx");
    assert_eq!(newest.object_id(), replacement_object_id);
    assert_eq!(
        newest.last_object_version_id(),
        Some(replacement_object_version_id.as_str())
    );
    assert_eq!(
        final_version.parents(),
        &[recreation.version_id().to_owned()]
    );
}

fn assert_hidden_prior_path_is_refused_without_capture_mutation(
    root: &Path,
    store: &FolderbaseVersionStore,
    genesis_version_id: &str,
    expected_path: &Path,
) {
    let head_path = root.join(".folderbase/local/head.json");
    let head_before = fs::read(&head_path).expect("prior Head bytes");
    let versions = root.join(".folderbase/versions/folderbase");
    let version_count_before = fs::read_dir(&versions)
        .expect("Folderbase Versions")
        .count();

    let error = store
        .seal_capture(store.plan_capture().expect("scope-change plan"))
        .expect_err("hidden prior binding must be refused");
    assert!(
        matches!(
            &error,
            FolderbaseCaptureError::PriorBindingHidden(path)
                if path == expected_path
        ),
        "unexpected scope-change error: {error:?}"
    );
    assert_eq!(
        fs::read(&head_path).expect("Head remains readable"),
        head_before
    );
    assert_eq!(
        fs::read_dir(&versions)
            .expect("Folderbase Versions")
            .count(),
        version_count_before
    );
    assert!(
        !root
            .join(".folderbase/transactions/folderbase-version-captures/active.json")
            .exists()
    );
    assert_eq!(
        store
            .plan_capture()
            .expect("prior Head remains valid")
            .current_local_head()
            .expect("prior Head")
            .version_id(),
        genesis_version_id
    );
}

#[test]
fn newly_ignored_prior_path_is_refused_before_journal_or_head_mutation() {
    let root = folderbase();
    fs::create_dir(root.path().join("private")).expect("private directory");
    fs::write(root.path().join("private/notes.md"), "private").expect("private notes");
    let store = FolderbaseVersionStore::open(root.path()).expect("open");
    let genesis = store
        .seal_capture(store.plan_capture().expect("genesis plan"))
        .expect("genesis");

    fs::write(
        root.path().join(".folderbaseignore"),
        "node_modules/\nprivate/\n",
    )
    .expect("hide prior path");
    assert_hidden_prior_path_is_refused_without_capture_mutation(
        root.path(),
        &store,
        genesis.version_id(),
        Path::new("private"),
    );
}

#[test]
fn new_nested_folderbase_hiding_prior_content_is_refused_before_mutation() {
    let root = folderbase();
    fs::create_dir(root.path().join("client")).expect("client directory");
    fs::write(root.path().join("client/notes.md"), "client notes").expect("client notes");
    let store = FolderbaseVersionStore::open(root.path()).expect("open");
    let genesis = store
        .seal_capture(store.plan_capture().expect("genesis plan"))
        .expect("genesis");

    fs::create_dir(root.path().join("client/.folderbase")).expect("nested state");
    fs::write(
        root.path().join("client/.folderbase/manifest.json"),
        br#"{
  "protocol_version": "0.4.0",
  "folderbase": {
    "id": "folderbase_019f9b75-4f42-7f65-a012-2bfecdd8c474"
  }
}
"#,
    )
    .expect("nested manifest");
    fs::write(
        root.path().join("client/FOLDERBASE.md"),
        "# Nested Folderbase\n",
    )
    .expect("nested entry");
    assert_hidden_prior_path_is_refused_without_capture_mutation(
        root.path(),
        &store,
        genesis.version_id(),
        Path::new("client"),
    );
}

#[test]
fn unsupported_node_hiding_a_prior_binding_is_refused_before_mutation() {
    let root = folderbase();
    fs::write(root.path().join("asset.bin"), b"first asset").expect("asset");
    let store = FolderbaseVersionStore::open(root.path()).expect("open");
    let genesis = store
        .seal_capture(store.plan_capture().expect("genesis plan"))
        .expect("genesis");

    let anchor = root.path().join("anchor.bin");
    fs::write(&anchor, b"replacement asset").expect("anchor");
    fs::remove_file(root.path().join("asset.bin")).expect("remove prior asset");
    fs::hard_link(&anchor, root.path().join("asset.bin")).expect("unsupported hard link");
    assert_hidden_prior_path_is_refused_without_capture_mutation(
        root.path(),
        &store,
        genesis.version_id(),
        Path::new("asset.bin"),
    );
}

#[test]
fn sealed_bytes_use_sha256_without_file_format_interpretation() {
    let root = folderbase();
    let bytes = [0_u8, 255, 17, 42, 0, 99];
    fs::write(root.path().join("unknown.bin"), bytes).expect("opaque bytes");
    let store = FolderbaseVersionStore::open(root.path()).expect("open");
    let sealed = store
        .seal_capture(store.plan_capture().expect("plan"))
        .expect("seal");
    let version = store.read_version(sealed.version_id()).expect("version");
    assert_eq!(
        version
            .lookup_binding("unknown.bin")
            .unwrap()
            .content_sha256(),
        Some(format!("{:x}", Sha256::digest(bytes)).as_str())
    );
    assert_eq!(
        version.lookup_binding("unknown.bin").unwrap().kind(),
        PathBindingKind::RegularFile
    );
    assert!(store.plan_capture().unwrap().entries().iter().any(|entry| {
        entry.path() == "unknown.bin" && entry.kind() == CaptureEntryKind::RegularFile
    }));
}

#[cfg(windows)]
#[test]
fn read_version_needs_no_windows_directory_write_authority() {
    use std::os::windows::fs::OpenOptionsExt;

    use windows_sys::Win32::{
        Foundation::GENERIC_READ,
        Storage::FileSystem::{
            FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
        },
    };

    fn hold_read_only_directory(path: &Path) -> fs::File {
        let mut options = fs::OpenOptions::new();
        options
            .read(true)
            .access_mode(GENERIC_READ)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .share_mode(FILE_SHARE_READ);
        options.open(path).expect("read-only directory handle")
    }

    let root = folderbase();
    fs::write(root.path().join("proof.pdf"), b"%PDF opaque").expect("proof");
    let store = FolderbaseVersionStore::open(root.path()).expect("open");
    let sealed = store
        .seal_capture(store.plan_capture().expect("plan"))
        .expect("seal");

    let _root_read_only = hold_read_only_directory(root.path());
    let _state_read_only = hold_read_only_directory(&root.path().join(".folderbase"));
    let version = store
        .read_version(sealed.version_id())
        .expect("read-only version verification");
    assert_eq!(version.version_id(), sealed.version_id());
}

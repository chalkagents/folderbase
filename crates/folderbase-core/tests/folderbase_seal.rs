use std::{fs, path::Path};

use folderbase_core::{
    CaptureEntryKind, FolderbaseCaptureError, FolderbaseVersionStore, LocalVersionStore,
    PathBindingKind, VersionId,
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
fn deletion_that_requires_a_tombstone_is_explicitly_refused_without_head_movement() {
    let root = folderbase();
    fs::write(root.path().join("proposal.docx"), b"opaque document").expect("document");
    let store = FolderbaseVersionStore::open(root.path()).expect("open");
    let genesis = store
        .seal_capture(store.plan_capture().expect("genesis plan"))
        .expect("genesis");
    fs::remove_file(root.path().join("proposal.docx")).expect("delete live document");

    assert!(matches!(
        store.seal_capture(store.plan_capture().expect("deletion plan")),
        Err(FolderbaseCaptureError::TombstonesRequired(path))
            if path == Path::new("proposal.docx")
    ));
    let head = store
        .plan_capture()
        .expect("head remains readable")
        .current_local_head()
        .expect("prior Head")
        .version_id()
        .to_owned();
    assert_eq!(head, genesis.version_id());
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

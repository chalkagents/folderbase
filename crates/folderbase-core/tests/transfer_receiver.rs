use std::{
    cell::Cell,
    io::{Cursor, Read},
    path::Path,
    rc::Rc,
    sync::{Arc, Barrier, mpsc},
    time::Duration,
};

use cap_std::{ambient_authority, fs::Dir};
use folderbase_core::transfer_manifest::{
    CHUNKING_ALGORITHM_V1, ChunkDescriptor, ChunkManifest, MANIFEST_FORMAT_V1,
    ObjectVerificationError, STANDARD_PROFILE_V1,
};
use folderbase_core::transfer_receiver::{
    ChunkAcceptance, PersistentTransfer, TransferReceiverError,
};
use folderbase_core::{ChunkTransferProfile, LocalVersionStore};
use sha2::{Digest, Sha256};

fn single_chunk_manifest() -> ChunkManifest {
    ChunkManifest {
        format: MANIFEST_FORMAT_V1.to_owned(),
        algorithm: CHUNKING_ALGORITHM_V1.to_owned(),
        profile: STANDARD_PROFILE_V1.to_owned(),
        minimum_chunk_bytes: 256 * 1024,
        average_chunk_bytes: 1024 * 1024,
        maximum_chunk_bytes: 4 * 1024 * 1024,
        object_sha256: "e77167d6e908b85a0d0f07e44b7e18c34e8ef5765ce12f533ba35600db0d0805"
            .to_owned(),
        object_bytes: 16,
        chunks: vec![ChunkDescriptor {
            index: 0,
            offset: 0,
            bytes: 16,
            sha256: "e77167d6e908b85a0d0f07e44b7e18c34e8ef5765ce12f533ba35600db0d0805".to_owned(),
        }],
    }
}

fn multi_chunk_fixture(chunk_count: usize) -> (Vec<u8>, ChunkManifest) {
    let chunk_bytes = 256 * 1024;
    let mut object = Vec::with_capacity(chunk_count * chunk_bytes);
    let mut chunks = Vec::with_capacity(chunk_count);
    for index in 0..chunk_count {
        let bytes = (0_u8..=250)
            .cycle()
            .skip(index * 37)
            .take(chunk_bytes)
            .collect::<Vec<_>>();
        object.extend_from_slice(&bytes);
        chunks.push(ChunkDescriptor {
            index: index as u32,
            offset: (index * chunk_bytes) as u64,
            bytes: chunk_bytes as u64,
            sha256: format!("{:x}", Sha256::digest(&bytes)),
        });
    }
    let manifest = ChunkManifest {
        format: MANIFEST_FORMAT_V1.to_owned(),
        algorithm: CHUNKING_ALGORITHM_V1.to_owned(),
        profile: STANDARD_PROFILE_V1.to_owned(),
        minimum_chunk_bytes: 256 * 1024,
        average_chunk_bytes: 1024 * 1024,
        maximum_chunk_bytes: 4 * 1024 * 1024,
        object_sha256: format!("{:x}", Sha256::digest(&object)),
        object_bytes: object.len() as u64,
        chunks,
    };
    manifest.validate().unwrap();
    (object, manifest)
}

struct RequestBoundedReader {
    inner: Cursor<Vec<u8>>,
    maximum_requested: Rc<Cell<usize>>,
}

impl RequestBoundedReader {
    fn new(bytes: Vec<u8>, maximum_requested: Rc<Cell<usize>>) -> Self {
        Self {
            inner: Cursor::new(bytes),
            maximum_requested,
        }
    }
}

impl Read for RequestBoundedReader {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.maximum_requested
            .set(self.maximum_requested.get().max(buffer.len()));
        self.inner.read(buffer)
    }
}

struct BlockingReader {
    inner: Cursor<Vec<u8>>,
    paused: Option<mpsc::SyncSender<()>>,
    resume: mpsc::Receiver<()>,
}

impl Read for BlockingReader {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if let Some(paused) = self.paused.take() {
            paused.send(()).unwrap();
            self.resume.recv().unwrap();
        }
        self.inner.read(buffer)
    }
}

struct PanickingReader;

impl Read for PanickingReader {
    fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
        panic!("simulated receiver crash")
    }
}

#[test]
fn canonical_manifest_verifies_an_exact_streamed_object() {
    let manifest = single_chunk_manifest();
    let manifest_digest = manifest.canonical_digest().unwrap();

    let verified = manifest
        .verify_object(Cursor::new(b"hello folderbase"))
        .unwrap();

    assert_eq!(verified.manifest_format, MANIFEST_FORMAT_V1);
    assert_eq!(verified.manifest_digest, manifest_digest);
    assert_eq!(
        verified.object_sha256,
        "e77167d6e908b85a0d0f07e44b7e18c34e8ef5765ce12f533ba35600db0d0805"
    );
    assert_eq!(verified.object_bytes, 16);
}

#[test]
fn canonical_empty_object_returns_an_exact_verification_receipt() {
    let manifest = ChunkManifest {
        format: MANIFEST_FORMAT_V1.to_owned(),
        algorithm: CHUNKING_ALGORITHM_V1.to_owned(),
        profile: STANDARD_PROFILE_V1.to_owned(),
        minimum_chunk_bytes: 256 * 1024,
        average_chunk_bytes: 1024 * 1024,
        maximum_chunk_bytes: 4 * 1024 * 1024,
        object_sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            .to_owned(),
        object_bytes: 0,
        chunks: Vec::new(),
    };

    let verified = manifest.verify_object(Cursor::new([])).unwrap();

    assert_eq!(verified.manifest_format, MANIFEST_FORMAT_V1);
    assert_eq!(
        verified.manifest_digest,
        manifest.canonical_digest().unwrap()
    );
    assert_eq!(verified.object_sha256, manifest.object_sha256);
    assert_eq!(verified.object_bytes, 0);
}

#[test]
fn receiver_creates_a_capability_rooted_durable_checkpoint() {
    let temporary = tempfile::tempdir().unwrap();
    let root = Dir::open_ambient_dir(temporary.path(), ambient_authority()).unwrap();
    let manifest = single_chunk_manifest();
    let digest = manifest.canonical_digest().unwrap();

    let transfer = PersistentTransfer::create(&root, "inbound", manifest.clone()).unwrap();

    assert_eq!(transfer.manifest(), &manifest);
    assert_eq!(transfer.manifest_digest(), digest);
    let page = transfer.missing_chunks(None, 16).unwrap();
    assert_eq!(page.chunk_indices, vec![0]);
    assert_eq!(page.next_cursor, None);
}

#[test]
fn reopen_rejects_installed_chunks_outside_the_bound_manifest() {
    let temporary = tempfile::tempdir().unwrap();
    let root = Dir::open_ambient_dir(temporary.path(), ambient_authority()).unwrap();
    let manifest = single_chunk_manifest();
    let digest = manifest.canonical_digest().unwrap();
    drop(PersistentTransfer::create(&root, "inbound", manifest).unwrap());
    std::fs::write(
        temporary.path().join("inbound/chunks/999.chunk"),
        b"not part of this transfer",
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            temporary.path().join("inbound/chunks/999.chunk"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
    }

    let error = PersistentTransfer::open(&root, "inbound", &digest).unwrap_err();
    assert!(
        matches!(error, TransferReceiverError::UnrecognizedCheckpointEntry),
        "{error:?}"
    );
}

#[test]
fn chunk_acceptance_is_streamed_exact_and_idempotent() {
    let temporary = tempfile::tempdir().unwrap();
    let root = Dir::open_ambient_dir(temporary.path(), ambient_authority()).unwrap();
    let manifest = single_chunk_manifest();
    let transfer = PersistentTransfer::create(&root, "inbound", manifest).unwrap();

    assert_eq!(
        transfer
            .accept_chunk_from(0, Cursor::new(b"hello folderbase"))
            .unwrap(),
        ChunkAcceptance::Accepted
    );
    assert_eq!(
        transfer
            .accept_chunk_from(0, Cursor::new(b"hello folderbase"))
            .unwrap(),
        ChunkAcceptance::AlreadyPresent
    );
    assert!(matches!(
        transfer.accept_chunk_from(0, Cursor::new(b"HELLO FOLDERBASE")),
        Err(TransferReceiverError::ChunkDigestMismatch(0))
    ));
    assert!(
        transfer
            .missing_chunks(None, 1)
            .unwrap()
            .chunk_indices
            .is_empty()
    );
    assert_eq!(
        std::fs::read(temporary.path().join("inbound/chunks/0.chunk")).unwrap(),
        b"hello folderbase"
    );
}

#[test]
fn replacing_the_verified_staging_path_never_accepts_the_replacement() {
    let temporary = tempfile::tempdir().unwrap();
    let root = Dir::open_ambient_dir(temporary.path(), ambient_authority()).unwrap();
    let transfer =
        Arc::new(PersistentTransfer::create(&root, "inbound", single_chunk_manifest()).unwrap());
    let (paused_sender, paused_receiver) = mpsc::sync_channel(0);
    let (resume_sender, resume_receiver) = mpsc::sync_channel(0);
    let accepting = {
        let transfer = Arc::clone(&transfer);
        std::thread::spawn(move || {
            transfer.accept_chunk_from(
                0,
                BlockingReader {
                    inner: Cursor::new(b"hello folderbase".to_vec()),
                    paused: Some(paused_sender),
                    resume: resume_receiver,
                },
            )
        })
    };

    paused_receiver.recv().unwrap();
    let chunks = temporary.path().join("inbound/chunks");
    let staging = std::fs::read_dir(&chunks)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(".chunk-") && name.ends_with(".part"))
        })
        .expect("accept must create its staging file before reading");
    std::fs::remove_file(&staging).unwrap();
    std::fs::write(&staging, b"corrupt replacement").unwrap();
    #[cfg(unix)]
    set_mode(&staging, 0o600);
    resume_sender.send(()).unwrap();

    let result = accepting.join().unwrap();
    assert!(
        matches!(result, Err(TransferReceiverError::CheckpointStateChanged)),
        "{result:?}"
    );
    assert!(!chunks.join("0.chunk").exists());
    assert_eq!(
        std::fs::read(staging).unwrap(),
        b"corrupt replacement",
        "a path replacement must not be mistaken for operation-owned cleanup"
    );
}

#[test]
fn rejected_chunk_inputs_do_not_accumulate_staging_or_accepted_state() {
    let temporary = tempfile::tempdir().unwrap();
    let root = Dir::open_ambient_dir(temporary.path(), ambient_authority()).unwrap();
    let manifest = single_chunk_manifest();
    let digest = manifest.canonical_digest().unwrap();
    drop(PersistentTransfer::create(&root, "inbound", manifest).unwrap());
    let stale = temporary.path().join(format!(
        "inbound/chunks/.chunk-{}.part",
        uuid::Uuid::now_v7()
    ));
    std::fs::write(&stale, b"crash residue").unwrap();
    #[cfg(unix)]
    set_mode(&stale, 0o600);
    let transfer = PersistentTransfer::open(&root, "inbound", &digest).unwrap();
    assert!(
        stale.exists(),
        "opening alone must not mutate crash-recovery state without the writer lease"
    );

    assert!(matches!(
        transfer.accept_chunk_from(0, Cursor::new(b"short")),
        Err(TransferReceiverError::ChunkLengthMismatch(0))
    ));
    assert!(
        !stale.exists(),
        "the next receipt must reclaim exact stale staging while it owns the lease"
    );
    assert!(matches!(
        transfer.accept_chunk_from(0, Cursor::new(b"hello folderbase!")),
        Err(TransferReceiverError::ChunkLengthMismatch(0))
    ));
    assert!(matches!(
        transfer.accept_chunk_from(0, Cursor::new(b"HELLO FOLDERBASE")),
        Err(TransferReceiverError::ChunkDigestMismatch(0))
    ));
    assert!(matches!(
        transfer.accept_chunk_from(4, Cursor::new(b"ignored")),
        Err(TransferReceiverError::UnknownChunk(4))
    ));

    assert_eq!(
        transfer.missing_chunks(None, 8).unwrap().chunk_indices,
        vec![0]
    );
    assert!(!temporary.path().join("inbound/chunks/0.chunk").exists());
    let retained = std::fs::read_dir(temporary.path().join("inbound/chunks"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        retained,
        Vec::<String>::new(),
        "rejected retries must not consume unbounded checkpoint storage"
    );
    drop(transfer);

    let reopened = PersistentTransfer::open(&root, "inbound", &digest).unwrap();
    assert_eq!(
        reopened.missing_chunks(None, 8).unwrap().chunk_indices,
        vec![0],
        "rejected staging must not become accepted state during resume"
    );
}

#[test]
fn receiver_and_object_verifier_bound_each_read_to_64_kib() {
    let temporary = tempfile::tempdir().unwrap();
    let root = Dir::open_ambient_dir(temporary.path(), ambient_authority()).unwrap();
    let (object, manifest) = multi_chunk_fixture(2);
    let transfer = PersistentTransfer::create(&root, "inbound", manifest.clone()).unwrap();
    let requested = Rc::new(Cell::new(0));

    transfer
        .accept_chunk_from(
            0,
            RequestBoundedReader::new(object[..256 * 1024].to_vec(), Rc::clone(&requested)),
        )
        .unwrap();
    assert!(requested.get() <= 64 * 1024);

    requested.set(0);
    manifest
        .verify_object(RequestBoundedReader::new(object, Rc::clone(&requested)))
        .unwrap_err();
    assert!(requested.get() <= 64 * 1024);
}

#[test]
fn missing_chunks_are_bounded_and_resume_with_an_explicit_cursor() {
    let temporary = tempfile::tempdir().unwrap();
    let root = Dir::open_ambient_dir(temporary.path(), ambient_authority()).unwrap();
    let (object, manifest) = multi_chunk_fixture(4);
    let transfer = PersistentTransfer::create(&root, "inbound", manifest).unwrap();
    transfer
        .accept_chunk_from(1, Cursor::new(&object[256 * 1024..512 * 1024]))
        .unwrap();

    let first = transfer.missing_chunks(None, 2).unwrap();
    assert_eq!(first.chunk_indices, vec![0]);
    assert_eq!(first.next_cursor, Some(2));
    let second = transfer.missing_chunks(first.next_cursor, 2).unwrap();
    assert_eq!(second.chunk_indices, vec![2, 3]);
    assert_eq!(second.next_cursor, None);
    assert!(matches!(
        transfer.missing_chunks(None, 0),
        Err(TransferReceiverError::InvalidPageLimit { .. })
    ));
}

#[test]
fn reopen_binds_the_expected_digest_and_revalidates_installed_chunks() {
    let temporary = tempfile::tempdir().unwrap();
    let root = Dir::open_ambient_dir(temporary.path(), ambient_authority()).unwrap();
    let manifest = single_chunk_manifest();
    let digest = manifest.canonical_digest().unwrap();
    let transfer = PersistentTransfer::create(&root, "inbound", manifest).unwrap();
    transfer
        .accept_chunk_from(0, Cursor::new(b"hello folderbase"))
        .unwrap();
    drop(transfer);

    let reopened = PersistentTransfer::open(&root, "inbound", &digest).unwrap();
    assert!(
        reopened
            .missing_chunks(None, 1)
            .unwrap()
            .chunk_indices
            .is_empty()
    );
    drop(reopened);
    assert!(matches!(
        PersistentTransfer::open(
            &root,
            "inbound",
            "0000000000000000000000000000000000000000000000000000000000000000"
        ),
        Err(TransferReceiverError::ManifestDigestMismatch { .. })
    ));

    std::fs::write(temporary.path().join("inbound/chunks/0.chunk"), b"corrupt").unwrap();
    assert!(matches!(
        PersistentTransfer::open(&root, "inbound", &digest),
        Err(TransferReceiverError::ChunkLengthMismatch(0))
            | Err(TransferReceiverError::ChunkDigestMismatch(0))
    ));
}

#[test]
fn checkpoint_names_are_single_capability_relative_components() {
    let temporary = tempfile::tempdir().unwrap();
    let root = Dir::open_ambient_dir(temporary.path(), ambient_authority()).unwrap();
    let digest = single_chunk_manifest().canonical_digest().unwrap();
    for unsafe_name in [
        "",
        ".",
        "..",
        "inbound/",
        "inbound//",
        "inbound/.",
        "nested/inbound",
        "/tmp/inbound",
    ] {
        assert!(matches!(
            PersistentTransfer::create(&root, Path::new(unsafe_name), single_chunk_manifest()),
            Err(TransferReceiverError::UnsafeCheckpointPath)
        ));
        assert!(matches!(
            PersistentTransfer::open(&root, Path::new(unsafe_name), &digest),
            Err(TransferReceiverError::UnsafeCheckpointPath)
        ));
    }

    std::fs::create_dir(temporary.path().join("occupied")).unwrap();
    std::fs::write(temporary.path().join("occupied/sentinel"), b"keep").unwrap();
    assert!(matches!(
        PersistentTransfer::create(&root, "occupied", single_chunk_manifest()),
        Err(TransferReceiverError::CheckpointAlreadyExists)
    ));
    assert_eq!(
        std::fs::read(temporary.path().join("occupied/sentinel")).unwrap(),
        b"keep"
    );
}

#[cfg(unix)]
#[test]
fn symlinked_checkpoint_names_are_never_followed() {
    use std::os::unix::fs::symlink;

    let temporary = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let root = Dir::open_ambient_dir(temporary.path(), ambient_authority()).unwrap();
    symlink(outside.path(), temporary.path().join("inbound")).unwrap();

    assert!(matches!(
        PersistentTransfer::create(&root, "inbound", single_chunk_manifest()),
        Err(TransferReceiverError::CheckpointAlreadyExists)
    ));
    assert!(
        PersistentTransfer::open(
            &root,
            "inbound",
            "0000000000000000000000000000000000000000000000000000000000000000"
        )
        .is_err()
    );
    assert_eq!(std::fs::read_dir(outside.path()).unwrap().count(), 0);
}

#[test]
fn whole_object_verification_uses_the_sources_exact_canonical_chunk_plan() {
    let temporary = tempfile::tempdir().unwrap();
    let bytes = (0_u8..=250).cycle().take(900_000).collect::<Vec<_>>();
    std::fs::write(temporary.path().join("archive.zip"), &bytes).unwrap();
    let store = LocalVersionStore::open(temporary.path()).unwrap();
    let captured = store.capture_file("archive.zip").unwrap();
    let source = store
        .open_chunk_transfer(&captured.version.id, ChunkTransferProfile::StandardV1)
        .unwrap();
    assert_eq!(source.manifest().chunks.len(), 2);

    let verified = source
        .manifest()
        .verify_object(Cursor::new(&bytes))
        .unwrap();

    assert_eq!(verified.manifest_digest, source.manifest_digest());
    assert_eq!(verified.object_sha256, captured.version.content.digest);
    assert_eq!(verified.object_bytes, 900_000);
}

#[test]
fn whole_object_verification_requires_exact_eof_digest_and_boundaries() {
    let manifest = single_chunk_manifest();
    assert!(matches!(
        manifest.verify_object(Cursor::new(b"hello folderbas")),
        Err(ObjectVerificationError::ObjectLengthMismatch {
            expected: 16,
            actual: 15
        })
    ));
    assert!(matches!(
        manifest.verify_object(Cursor::new(b"hello folderbase!")),
        Err(ObjectVerificationError::ObjectLengthMismatch {
            expected: 16,
            actual: 17
        })
    ));
    assert!(matches!(
        manifest.verify_object(Cursor::new(b"HELLO FOLDERBASE")),
        Err(ObjectVerificationError::ObjectDigestMismatch)
    ));

    let (object, structurally_valid_noncanonical_plan) = multi_chunk_fixture(2);
    assert!(matches!(
        structurally_valid_noncanonical_plan.verify_object(Cursor::new(object)),
        Err(ObjectVerificationError::ChunkPlanMismatch)
    ));
}

#[test]
fn reopen_fails_closed_on_manifest_tampering_and_legacy_checkpoints() {
    let temporary = tempfile::tempdir().unwrap();
    let root = Dir::open_ambient_dir(temporary.path(), ambient_authority()).unwrap();
    let manifest = single_chunk_manifest();
    let expected = manifest.canonical_digest().unwrap();
    drop(PersistentTransfer::create(&root, "canonical", manifest).unwrap());

    let manifest_path = temporary.path().join("canonical/manifest.json");
    let mut value: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&manifest_path).unwrap()).unwrap();
    value["object_sha256"] = serde_json::Value::String("0".repeat(64));
    std::fs::write(&manifest_path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
    #[cfg(unix)]
    set_mode(&manifest_path, 0o600);
    assert!(matches!(
        PersistentTransfer::open(&root, "canonical", &expected),
        Err(TransferReceiverError::ManifestDigestMismatch { .. })
    ));

    let legacy = temporary.path().join("legacy");
    std::fs::create_dir(&legacy).unwrap();
    std::fs::create_dir(legacy.join("chunks")).unwrap();
    #[cfg(unix)]
    {
        set_mode(&legacy, 0o700);
        set_mode(&legacy.join("chunks"), 0o700);
    }
    std::fs::write(
        legacy.join("manifest.json"),
        br#"{
          "algorithm":"folderbase-cdc-v1+sha256",
          "object_digest":"00",
          "bytes":0,
          "chunks":[]
        }"#,
    )
    .unwrap();
    std::fs::write(
        legacy.join("chunks/.550e8400-e29b-41d4-a716-446655440000.part"),
        b"legacy incomplete chunk",
    )
    .unwrap();
    #[cfg(unix)]
    {
        set_mode(&legacy.join("manifest.json"), 0o600);
        set_mode(
            &legacy.join("chunks/.550e8400-e29b-41d4-a716-446655440000.part"),
            0o600,
        );
    }
    assert!(matches!(
        PersistentTransfer::open(&root, "legacy", &"0".repeat(64)),
        Err(TransferReceiverError::UnsupportedLegacyCheckpoint)
    ));
}

#[test]
fn reopen_ignores_only_exact_operation_staging_names() {
    let temporary = tempfile::tempdir().unwrap();
    let root = Dir::open_ambient_dir(temporary.path(), ambient_authority()).unwrap();
    let manifest = single_chunk_manifest();
    let digest = manifest.canonical_digest().unwrap();
    drop(PersistentTransfer::create(&root, "inbound", manifest).unwrap());
    let chunks = temporary.path().join("inbound/chunks");
    let valid_staging = chunks.join(format!(".chunk-{}.part", uuid::Uuid::now_v7()));
    std::fs::write(&valid_staging, b"incomplete").unwrap();
    #[cfg(unix)]
    set_mode(&valid_staging, 0o600);
    drop(PersistentTransfer::open(&root, "inbound", &digest).unwrap());

    let wrong_version = chunks.join(".chunk-550e8400-e29b-41d4-a716-446655440000.part");
    std::fs::write(&wrong_version, b"lookalike").unwrap();
    #[cfg(unix)]
    set_mode(&wrong_version, 0o600);
    let error = PersistentTransfer::open(&root, "inbound", &digest).unwrap_err();
    assert!(
        matches!(error, TransferReceiverError::UnrecognizedCheckpointEntry),
        "{error:?}"
    );
}

#[cfg(unix)]
#[test]
fn private_checkpoint_modes_are_set_and_revalidated() {
    use std::os::unix::fs::PermissionsExt;

    let temporary = tempfile::tempdir().unwrap();
    let root = Dir::open_ambient_dir(temporary.path(), ambient_authority()).unwrap();
    let manifest = single_chunk_manifest();
    let digest = manifest.canonical_digest().unwrap();
    let transfer = PersistentTransfer::create(&root, "inbound", manifest).unwrap();
    transfer
        .accept_chunk_from(0, Cursor::new(b"hello folderbase"))
        .unwrap();
    drop(transfer);

    assert_eq!(
        std::fs::metadata(temporary.path().join("inbound"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert_eq!(
        std::fs::metadata(temporary.path().join("inbound/manifest.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(
        std::fs::metadata(temporary.path().join("inbound/receiver.lock"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert!(
        std::fs::read(temporary.path().join("inbound/receiver.lock"))
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        std::fs::metadata(temporary.path().join("inbound/chunks/0.chunk"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );

    let staging = temporary.path().join(format!(
        "inbound/chunks/.chunk-{}.part",
        uuid::Uuid::now_v7()
    ));
    std::fs::write(&staging, b"incomplete").unwrap();
    set_mode(&staging, 0o600);

    for (path, exact_mode, invalid_modes) in [
        (temporary.path().join("inbound"), 0o700, [0o500, 0o750]),
        (
            temporary.path().join("inbound/chunks"),
            0o700,
            [0o500, 0o750],
        ),
        (
            temporary.path().join("inbound/manifest.json"),
            0o600,
            [0o400, 0o640],
        ),
        (
            temporary.path().join("inbound/receiver.lock"),
            0o600,
            [0o400, 0o640],
        ),
        (
            temporary.path().join("inbound/chunks/0.chunk"),
            0o600,
            [0o400, 0o640],
        ),
        (staging, 0o600, [0o400, 0o640]),
    ] {
        for invalid_mode in invalid_modes {
            set_mode(&path, invalid_mode);
            assert!(
                matches!(
                    PersistentTransfer::open(&root, "inbound", &digest),
                    Err(TransferReceiverError::InsecureCheckpointPermissions)
                ),
                "{} mode {invalid_mode:o} must be rejected",
                path.display()
            );
            set_mode(&path, exact_mode);
        }
    }

    drop(PersistentTransfer::open(&root, "inbound", &digest).unwrap());
}

#[test]
fn receiver_lock_is_required_and_unknown_checkpoint_entries_fail_closed() {
    let temporary = tempfile::tempdir().unwrap();
    let root = Dir::open_ambient_dir(temporary.path(), ambient_authority()).unwrap();
    let manifest = single_chunk_manifest();
    let digest = manifest.canonical_digest().unwrap();
    drop(PersistentTransfer::create(&root, "inbound", manifest).unwrap());

    std::fs::write(temporary.path().join("inbound/unknown"), b"unowned").unwrap();
    #[cfg(unix)]
    set_mode(&temporary.path().join("inbound/unknown"), 0o600);
    assert!(matches!(
        PersistentTransfer::open(&root, "inbound", &digest),
        Err(TransferReceiverError::UnrecognizedCheckpointEntry)
    ));
    std::fs::remove_file(temporary.path().join("inbound/unknown")).unwrap();

    std::fs::remove_file(temporary.path().join("inbound/receiver.lock")).unwrap();
    assert!(PersistentTransfer::open(&root, "inbound", &digest).is_err());
}

#[cfg(unix)]
#[test]
fn receiver_lock_symlinks_and_path_replacements_are_never_trusted() {
    use std::os::unix::fs::symlink;

    let temporary = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let root = Dir::open_ambient_dir(temporary.path(), ambient_authority()).unwrap();
    let manifest = single_chunk_manifest();
    let digest = manifest.canonical_digest().unwrap();
    let lock_path = temporary.path().join("inbound/receiver.lock");
    let transfer = PersistentTransfer::create(&root, "inbound", manifest).unwrap();

    std::fs::rename(&lock_path, temporary.path().join("inbound/original.lock")).unwrap();
    std::fs::write(&lock_path, b"replacement").unwrap();
    set_mode(&lock_path, 0o600);
    assert!(matches!(
        transfer.accept_chunk_from(0, Cursor::new(b"hello folderbase")),
        Err(TransferReceiverError::CheckpointStateChanged)
    ));
    assert_eq!(std::fs::read(&lock_path).unwrap(), b"replacement");
    assert_eq!(
        std::fs::read_dir(temporary.path().join("inbound/chunks"))
            .unwrap()
            .count(),
        0
    );
    drop(transfer);

    std::fs::remove_file(&lock_path).unwrap();
    std::fs::remove_file(temporary.path().join("inbound/original.lock")).unwrap();
    let outside_lock = outside.path().join("receiver.lock");
    std::fs::write(&outside_lock, b"outside").unwrap();
    set_mode(&outside_lock, 0o600);
    symlink(&outside_lock, &lock_path).unwrap();
    assert!(PersistentTransfer::open(&root, "inbound", &digest).is_err());
    assert_eq!(std::fs::read(outside_lock).unwrap(), b"outside");
}

#[test]
fn concurrent_accepts_install_exactly_one_chunk_without_clobbering() {
    let temporary = tempfile::tempdir().unwrap();
    let root = Dir::open_ambient_dir(temporary.path(), ambient_authority()).unwrap();
    let manifest = single_chunk_manifest();
    let digest = manifest.canonical_digest().unwrap();
    let transfer = Arc::new(PersistentTransfer::create(&root, "inbound", manifest).unwrap());
    let barrier = Arc::new(Barrier::new(8));
    let mut threads = Vec::new();
    for _ in 0..8 {
        let transfer = Arc::clone(&transfer);
        let barrier = Arc::clone(&barrier);
        threads.push(std::thread::spawn(move || {
            barrier.wait();
            transfer
                .accept_chunk_from(0, Cursor::new(b"hello folderbase"))
                .unwrap()
        }));
    }
    let outcomes = threads
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| **outcome == ChunkAcceptance::Accepted)
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| **outcome == ChunkAcceptance::AlreadyPresent)
            .count(),
        7
    );
    assert_eq!(
        std::fs::read(temporary.path().join("inbound/chunks/0.chunk")).unwrap(),
        b"hello folderbase"
    );
    assert_eq!(
        std::fs::read_dir(temporary.path().join("inbound/chunks"))
            .unwrap()
            .count(),
        1,
        "accepted and already-present retries leave only the installed chunk"
    );
    drop(transfer);

    let reopened = PersistentTransfer::open(&root, "inbound", &digest).unwrap();
    assert_eq!(
        reopened.missing_chunks(None, 1).unwrap().chunk_indices,
        Vec::<u32>::new(),
        "bounded resume must report the installed chunk"
    );
}

#[test]
fn independently_opened_receivers_serialize_chunk_acceptance() {
    let temporary = tempfile::tempdir().unwrap();
    let root = Dir::open_ambient_dir(temporary.path(), ambient_authority()).unwrap();
    let manifest = single_chunk_manifest();
    let digest = manifest.canonical_digest().unwrap();
    let first = PersistentTransfer::create(&root, "inbound", manifest).unwrap();
    let second = PersistentTransfer::open(&root, "inbound", &digest).unwrap();
    let (first_paused_sender, first_paused_receiver) = mpsc::sync_channel(0);
    let (first_resume_sender, first_resume_receiver) = mpsc::sync_channel(0);
    let (second_started_sender, second_started_receiver) = mpsc::sync_channel(0);
    let (second_read_sender, second_read_receiver) = mpsc::sync_channel(0);
    let (second_resume_sender, second_resume_receiver) = mpsc::sync_channel(0);

    let first_accept = std::thread::spawn(move || {
        first.accept_chunk_from(
            0,
            BlockingReader {
                inner: Cursor::new(b"hello folderbase".to_vec()),
                paused: Some(first_paused_sender),
                resume: first_resume_receiver,
            },
        )
    });
    first_paused_receiver.recv().unwrap();

    let second_accept = std::thread::spawn(move || {
        second_started_sender.send(()).unwrap();
        second.accept_chunk_from(
            0,
            BlockingReader {
                inner: Cursor::new(b"hello folderbase".to_vec()),
                paused: Some(second_read_sender),
                resume: second_resume_receiver,
            },
        )
    });
    second_started_receiver.recv().unwrap();

    assert!(
        second_read_receiver
            .recv_timeout(Duration::from_millis(150))
            .is_err(),
        "the second receiver must wait for the checkpoint lease before creating staging or reading"
    );
    assert_eq!(
        std::fs::read_dir(temporary.path().join("inbound/chunks"))
            .unwrap()
            .count(),
        1,
        "only the lease holder may create a staging file"
    );

    first_resume_sender.send(()).unwrap();
    assert_eq!(
        first_accept.join().unwrap().unwrap(),
        ChunkAcceptance::Accepted
    );
    second_read_receiver
        .recv_timeout(Duration::from_secs(2))
        .unwrap();
    second_resume_sender.send(()).unwrap();
    assert_eq!(
        second_accept.join().unwrap().unwrap(),
        ChunkAcceptance::AlreadyPresent
    );
    assert_eq!(
        std::fs::read_dir(temporary.path().join("inbound/chunks"))
            .unwrap()
            .count(),
        1,
        "accepted bytes remain without retained staging"
    );
}

#[test]
fn a_panicking_receipt_releases_its_lease_and_stale_staging_is_reclaimed() {
    let temporary = tempfile::tempdir().unwrap();
    let root = Dir::open_ambient_dir(temporary.path(), ambient_authority()).unwrap();
    let transfer =
        Arc::new(PersistentTransfer::create(&root, "inbound", single_chunk_manifest()).unwrap());
    let crashing = {
        let transfer = Arc::clone(&transfer);
        std::thread::spawn(move || transfer.accept_chunk_from(0, PanickingReader))
    };
    assert!(crashing.join().is_err());
    assert_eq!(
        std::fs::read_dir(temporary.path().join("inbound/chunks"))
            .unwrap()
            .count(),
        1,
        "the simulated crash must leave an exact staging entry"
    );

    assert_eq!(
        transfer
            .accept_chunk_from(0, Cursor::new(b"hello folderbase"))
            .unwrap(),
        ChunkAcceptance::Accepted
    );
    assert_eq!(
        std::fs::read_dir(temporary.path().join("inbound/chunks"))
            .unwrap()
            .count(),
        1,
        "the next lease holder reclaims crash residue before receiving"
    );
}

#[cfg(unix)]
#[test]
fn an_open_receiver_never_follows_a_replaced_chunks_directory() {
    use std::os::unix::fs::symlink;

    let temporary = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let root = Dir::open_ambient_dir(temporary.path(), ambient_authority()).unwrap();
    let manifest = single_chunk_manifest();
    let digest = manifest.canonical_digest().unwrap();
    let transfer = PersistentTransfer::create(&root, "inbound", manifest).unwrap();
    std::fs::rename(
        temporary.path().join("inbound/chunks"),
        temporary.path().join("inbound/original-chunks"),
    )
    .unwrap();
    symlink(outside.path(), temporary.path().join("inbound/chunks")).unwrap();

    transfer
        .accept_chunk_from(0, Cursor::new(b"hello folderbase"))
        .unwrap();
    assert_eq!(std::fs::read_dir(outside.path()).unwrap().count(), 0);
    assert_eq!(
        std::fs::read(temporary.path().join("inbound/original-chunks/0.chunk")).unwrap(),
        b"hello folderbase"
    );
    drop(transfer);
    assert!(PersistentTransfer::open(&root, "inbound", &digest).is_err());
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

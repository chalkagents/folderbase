use std::{
    cell::Cell,
    io::{Cursor, Read},
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus},
    rc::Rc,
    sync::{Arc, Barrier, mpsc},
    time::{Duration, Instant},
};

use cap_std::{ambient_authority, fs::Dir};
use folderbase_core::transfer_manifest::{
    CHUNKING_ALGORITHM_V1, ChunkDescriptor, ChunkManifest, MANIFEST_FORMAT_V1,
    ObjectVerificationError, STANDARD_PROFILE_V1,
};
use folderbase_core::transfer_receiver::{
    ChunkAcceptance, PersistentTransfer, TransferReceiverError,
};
use folderbase_core::transfer_source::ChunkTransferSource;
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

fn empty_manifest() -> ChunkManifest {
    ChunkManifest {
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
    }
}

fn one_standard_chunk_manifest(bytes: &[u8]) -> ChunkManifest {
    let digest = format!("{:x}", Sha256::digest(bytes));
    ChunkManifest {
        format: MANIFEST_FORMAT_V1.to_owned(),
        algorithm: CHUNKING_ALGORITHM_V1.to_owned(),
        profile: STANDARD_PROFILE_V1.to_owned(),
        minimum_chunk_bytes: 256 * 1024,
        average_chunk_bytes: 1024 * 1024,
        maximum_chunk_bytes: 4 * 1024 * 1024,
        object_sha256: digest.clone(),
        object_bytes: bytes.len() as u64,
        chunks: vec![ChunkDescriptor {
            index: 0,
            offset: 0,
            bytes: bytes.len() as u64,
            sha256: digest,
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

fn write_repeated_file(path: &Path, byte: u8, bytes: u64) {
    let mut file = std::fs::File::create(path).unwrap();
    std::io::copy(&mut std::io::repeat(byte).take(bytes), &mut file).unwrap();
    file.sync_all().unwrap();
}

fn sha256_file(path: &Path) -> String {
    let mut file = std::fs::File::open(path).unwrap();
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).unwrap();
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    format!("{:x}", hasher.finalize())
}

fn accept_source_chunk_disk_backed(
    source: &mut ChunkTransferSource,
    transfer: &PersistentTransfer,
    index: u32,
) {
    let mut staged = tempfile::NamedTempFile::new().unwrap();
    source.copy_chunk(index, staged.as_file_mut()).unwrap();
    staged.as_file().sync_all().unwrap();
    transfer
        .accept_chunk_from(index, staged.reopen().unwrap())
        .unwrap();
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

struct ProcessMarkerReader {
    inner: Cursor<Vec<u8>>,
    entered: PathBuf,
    release: Option<PathBuf>,
    marked: bool,
}

impl Read for ProcessMarkerReader {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if !self.marked {
            std::fs::write(&self.entered, b"entered")?;
            self.marked = true;
            if let Some(release) = &self.release
                && !wait_for_path(release, Duration::from_secs(10))
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "receiver helper timed out waiting for release",
                ));
            }
        }
        self.inner.read(buffer)
    }
}

fn wait_for_path(path: &Path, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if path.exists() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn wait_for_child(child: &mut Child, timeout: Duration) -> ExitStatus {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            let _ = child.wait();
            panic!("receiver helper process timed out");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn assert_no_materialization_staging(directory: &Path) {
    let retained = std::fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .filter(|name| {
            name.to_str().is_some_and(|name| {
                name.starts_with(".folderbase-materialize-") && name.ends_with(".part")
            })
        })
        .collect::<Vec<_>>();
    assert!(
        retained.is_empty(),
        "materialization must not retain operation-owned staging: {retained:?}"
    );
}

fn spawn_receiver_process_helper(
    root: &Path,
    digest: &str,
    entered: &Path,
    release: Option<&Path>,
    outcome: &Path,
    started: Option<&Path>,
) -> Child {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "receiver_process_lock_helper",
            "--ignored",
            "--nocapture",
        ])
        .env("FOLDERBASE_TEST_RECEIVER_ROOT", root)
        .env("FOLDERBASE_TEST_RECEIVER_DIGEST", digest)
        .env("FOLDERBASE_TEST_RECEIVER_ENTERED", entered)
        .env("FOLDERBASE_TEST_RECEIVER_OUTCOME", outcome);
    if let Some(release) = release {
        command.env("FOLDERBASE_TEST_RECEIVER_RELEASE", release);
    }
    if let Some(started) = started {
        command.env("FOLDERBASE_TEST_RECEIVER_STARTED", started);
    }
    command.spawn().unwrap()
}

fn run_receiver_process_helper_from_environment() {
    let Some(root) = std::env::var_os("FOLDERBASE_TEST_RECEIVER_ROOT") else {
        return;
    };
    let digest = std::env::var("FOLDERBASE_TEST_RECEIVER_DIGEST").unwrap();
    let entered = PathBuf::from(std::env::var_os("FOLDERBASE_TEST_RECEIVER_ENTERED").unwrap());
    let release = std::env::var_os("FOLDERBASE_TEST_RECEIVER_RELEASE").map(PathBuf::from);
    let outcome = PathBuf::from(std::env::var_os("FOLDERBASE_TEST_RECEIVER_OUTCOME").unwrap());

    let root = Dir::open_ambient_dir(root, ambient_authority()).unwrap();
    let transfer = PersistentTransfer::open(&root, "inbound", &digest).unwrap();
    if let Some(started) = std::env::var_os("FOLDERBASE_TEST_RECEIVER_STARTED") {
        std::fs::write(started, b"started").unwrap();
    }
    let acceptance = transfer
        .accept_chunk_from(
            0,
            ProcessMarkerReader {
                inner: Cursor::new(b"hello folderbase".to_vec()),
                entered,
                release,
                marked: false,
            },
        )
        .unwrap();
    let encoded = match acceptance {
        ChunkAcceptance::Accepted => "accepted",
        ChunkAcceptance::AlreadyPresent => "already-present",
    };
    std::fs::write(outcome, encoded).unwrap();
}

fn spawn_materializer_process_helper(
    root: &Path,
    checkpoint: &str,
    digest: &str,
    started: &Path,
    release: &Path,
    outcome: &Path,
) -> Child {
    Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "materializer_process_helper",
            "--ignored",
            "--nocapture",
        ])
        .env("FOLDERBASE_TEST_MATERIALIZER_ROOT", root)
        .env("FOLDERBASE_TEST_MATERIALIZER_CHECKPOINT", checkpoint)
        .env("FOLDERBASE_TEST_MATERIALIZER_DIGEST", digest)
        .env("FOLDERBASE_TEST_MATERIALIZER_STARTED", started)
        .env("FOLDERBASE_TEST_MATERIALIZER_RELEASE", release)
        .env("FOLDERBASE_TEST_MATERIALIZER_OUTCOME", outcome)
        .spawn()
        .unwrap()
}

fn run_materializer_process_helper_from_environment() {
    let Some(root) = std::env::var_os("FOLDERBASE_TEST_MATERIALIZER_ROOT") else {
        return;
    };
    let root = PathBuf::from(root);
    let checkpoint = std::env::var("FOLDERBASE_TEST_MATERIALIZER_CHECKPOINT").unwrap();
    let digest = std::env::var("FOLDERBASE_TEST_MATERIALIZER_DIGEST").unwrap();
    let started = PathBuf::from(std::env::var_os("FOLDERBASE_TEST_MATERIALIZER_STARTED").unwrap());
    let release = PathBuf::from(std::env::var_os("FOLDERBASE_TEST_MATERIALIZER_RELEASE").unwrap());
    let outcome = PathBuf::from(std::env::var_os("FOLDERBASE_TEST_MATERIALIZER_OUTCOME").unwrap());
    let receiver_root = Dir::open_ambient_dir(&root, ambient_authority()).unwrap();
    let destination_root =
        Dir::open_ambient_dir(root.join("destination"), ambient_authority()).unwrap();
    let transfer = PersistentTransfer::open(&receiver_root, checkpoint, &digest).unwrap();
    std::fs::write(&started, b"started").unwrap();
    assert!(wait_for_path(&release, Duration::from_secs(10)));
    let encoded = match transfer.materialize_to(&destination_root, "winner.bin") {
        Ok(_) => "installed",
        Err(TransferReceiverError::DestinationAlreadyExists) => "already-exists",
        Err(error) => panic!("unexpected materialization result: {error:?}"),
    };
    std::fs::write(outcome, encoded).unwrap();
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
fn complete_receiver_materializes_exact_bytes_and_receipt() {
    let temporary = tempfile::tempdir().unwrap();
    std::fs::create_dir(temporary.path().join("receiver")).unwrap();
    std::fs::create_dir(temporary.path().join("destination")).unwrap();
    let receiver_root =
        Dir::open_ambient_dir(temporary.path().join("receiver"), ambient_authority()).unwrap();
    let destination_root =
        Dir::open_ambient_dir(temporary.path().join("destination"), ambient_authority()).unwrap();
    let manifest = single_chunk_manifest();
    let expected_manifest_digest = manifest.canonical_digest().unwrap();
    let expected_object_digest = manifest.object_sha256.clone();
    let transfer = PersistentTransfer::create(&receiver_root, "inbound", manifest).unwrap();
    transfer
        .accept_chunk_from(0, Cursor::new(b"hello folderbase"))
        .unwrap();

    let materialized = transfer
        .materialize_to(&destination_root, "restored.bin")
        .unwrap();

    assert_eq!(
        std::fs::read(temporary.path().join("destination/restored.bin")).unwrap(),
        b"hello folderbase"
    );
    assert_eq!(
        materialized.relative_destination,
        PathBuf::from("restored.bin")
    );
    assert_eq!(materialized.object.manifest_format, MANIFEST_FORMAT_V1);
    assert_eq!(
        materialized.object.manifest_digest,
        expected_manifest_digest
    );
    assert_eq!(materialized.object.object_sha256, expected_object_digest);
    assert_eq!(materialized.object.object_bytes, 16);
}

#[test]
fn empty_receiver_materializes_an_empty_regular_file() {
    let temporary = tempfile::tempdir().unwrap();
    std::fs::create_dir(temporary.path().join("receiver")).unwrap();
    std::fs::create_dir(temporary.path().join("destination")).unwrap();
    let receiver_root =
        Dir::open_ambient_dir(temporary.path().join("receiver"), ambient_authority()).unwrap();
    let destination_root =
        Dir::open_ambient_dir(temporary.path().join("destination"), ambient_authority()).unwrap();
    let manifest = empty_manifest();
    let expected_digest = manifest.canonical_digest().unwrap();
    let transfer = PersistentTransfer::create(&receiver_root, "inbound", manifest).unwrap();

    let materialized = transfer
        .materialize_to(&destination_root, "empty.db")
        .unwrap();

    let installed = std::fs::metadata(temporary.path().join("destination/empty.db")).unwrap();
    assert!(installed.is_file());
    assert_eq!(installed.len(), 0);
    assert_eq!(materialized.object.manifest_digest, expected_digest);
    assert_eq!(materialized.object.object_bytes, 0);
}

#[test]
fn incomplete_receiver_leaves_destination_and_staging_absent() {
    let temporary = tempfile::tempdir().unwrap();
    std::fs::create_dir(temporary.path().join("receiver")).unwrap();
    std::fs::create_dir(temporary.path().join("destination")).unwrap();
    let receiver_root =
        Dir::open_ambient_dir(temporary.path().join("receiver"), ambient_authority()).unwrap();
    let destination_root =
        Dir::open_ambient_dir(temporary.path().join("destination"), ambient_authority()).unwrap();
    let transfer =
        PersistentTransfer::create(&receiver_root, "inbound", single_chunk_manifest()).unwrap();

    let result = transfer.materialize_to(&destination_root, "missing.bin");

    assert!(matches!(
        result,
        Err(TransferReceiverError::IncompleteTransfer {
            first_missing_chunk: 0
        })
    ));
    assert!(!temporary.path().join("destination/missing.bin").exists());
    assert_no_materialization_staging(&temporary.path().join("destination"));
}

#[test]
fn multi_chunk_incomplete_receiver_reports_the_first_missing_chunk_without_side_effects() {
    let (object, manifest) = multi_chunk_fixture(3);
    let chunk_bytes = 256 * 1024;

    for missing in [0_usize, 1, 2] {
        let temporary = tempfile::tempdir().unwrap();
        std::fs::create_dir(temporary.path().join("receiver")).unwrap();
        std::fs::create_dir(temporary.path().join("destination")).unwrap();
        let receiver_root =
            Dir::open_ambient_dir(temporary.path().join("receiver"), ambient_authority()).unwrap();
        let destination_root =
            Dir::open_ambient_dir(temporary.path().join("destination"), ambient_authority())
                .unwrap();
        let transfer = PersistentTransfer::create(
            &receiver_root,
            format!("inbound-{missing}"),
            manifest.clone(),
        )
        .unwrap();
        for index in 0..3 {
            if index == missing {
                continue;
            }
            let start = index * chunk_bytes;
            let end = start + chunk_bytes;
            transfer
                .accept_chunk_from(index as u32, Cursor::new(&object[start..end]))
                .unwrap();
        }
        let destination = format!("missing-{missing}.bin");

        let result = transfer.materialize_to(&destination_root, &destination);

        assert!(
            matches!(
                result,
                Err(TransferReceiverError::IncompleteTransfer {
                    first_missing_chunk
                }) if first_missing_chunk == missing as u32
            ),
            "missing {missing}: {result:?}"
        );
        assert!(
            !temporary
                .path()
                .join("destination")
                .join(destination)
                .exists()
        );
        assert_no_materialization_staging(&temporary.path().join("destination"));
    }
}

#[test]
fn corrupt_or_truncated_chunks_never_materialize() {
    for replacement in [
        b"HELLO FOLDERBASE".as_slice(),
        b"short".as_slice(),
        b"hello folderbase!".as_slice(),
    ] {
        let temporary = tempfile::tempdir().unwrap();
        std::fs::create_dir(temporary.path().join("receiver")).unwrap();
        std::fs::create_dir(temporary.path().join("destination")).unwrap();
        let receiver_root =
            Dir::open_ambient_dir(temporary.path().join("receiver"), ambient_authority()).unwrap();
        let destination_root =
            Dir::open_ambient_dir(temporary.path().join("destination"), ambient_authority())
                .unwrap();
        let transfer =
            PersistentTransfer::create(&receiver_root, "inbound", single_chunk_manifest()).unwrap();
        transfer
            .accept_chunk_from(0, Cursor::new(b"hello folderbase"))
            .unwrap();
        std::fs::write(
            temporary.path().join("receiver/inbound/chunks/0.chunk"),
            replacement,
        )
        .unwrap();

        let result = transfer.materialize_to(&destination_root, "corrupt.bin");

        assert!(
            matches!(result, Err(TransferReceiverError::ObjectVerification(_))),
            "{result:?}"
        );
        assert!(!temporary.path().join("destination/corrupt.bin").exists());
        assert_no_materialization_staging(&temporary.path().join("destination"));
    }
}

#[test]
fn accepted_chunks_remain_reusable_after_failed_and_successful_materialization() {
    let temporary = tempfile::tempdir().unwrap();
    std::fs::create_dir(temporary.path().join("receiver")).unwrap();
    std::fs::create_dir(temporary.path().join("destination")).unwrap();
    std::fs::write(
        temporary.path().join("destination/occupied.bin"),
        b"preserve",
    )
    .unwrap();
    let receiver_root =
        Dir::open_ambient_dir(temporary.path().join("receiver"), ambient_authority()).unwrap();
    let destination_root =
        Dir::open_ambient_dir(temporary.path().join("destination"), ambient_authority()).unwrap();
    let transfer =
        PersistentTransfer::create(&receiver_root, "inbound", single_chunk_manifest()).unwrap();
    transfer
        .accept_chunk_from(0, Cursor::new(b"hello folderbase"))
        .unwrap();

    assert!(matches!(
        transfer.materialize_to(&destination_root, "occupied.bin"),
        Err(TransferReceiverError::DestinationAlreadyExists)
    ));
    transfer
        .materialize_to(&destination_root, "first.bin")
        .unwrap();
    transfer
        .materialize_to(&destination_root, "second.bin")
        .unwrap();

    assert_eq!(
        transfer.missing_chunks(None, 1).unwrap().chunk_indices,
        Vec::<u32>::new()
    );
    assert_eq!(
        std::fs::read(temporary.path().join("receiver/inbound/chunks/0.chunk")).unwrap(),
        b"hello folderbase"
    );
    assert_eq!(
        std::fs::read(temporary.path().join("destination/occupied.bin")).unwrap(),
        b"preserve"
    );
    assert_eq!(
        std::fs::read(temporary.path().join("destination/first.bin")).unwrap(),
        b"hello folderbase"
    );
    assert_eq!(
        std::fs::read(temporary.path().join("destination/second.bin")).unwrap(),
        b"hello folderbase"
    );
}

#[cfg(unix)]
#[test]
fn symlinked_chunks_never_materialize() {
    use std::os::unix::fs::symlink;

    let temporary = tempfile::tempdir().unwrap();
    std::fs::create_dir(temporary.path().join("receiver")).unwrap();
    std::fs::create_dir(temporary.path().join("destination")).unwrap();
    let outside = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(outside.path(), b"hello folderbase").unwrap();
    let receiver_root =
        Dir::open_ambient_dir(temporary.path().join("receiver"), ambient_authority()).unwrap();
    let destination_root =
        Dir::open_ambient_dir(temporary.path().join("destination"), ambient_authority()).unwrap();
    let transfer =
        PersistentTransfer::create(&receiver_root, "inbound", single_chunk_manifest()).unwrap();
    transfer
        .accept_chunk_from(0, Cursor::new(b"hello folderbase"))
        .unwrap();
    let chunk = temporary.path().join("receiver/inbound/chunks/0.chunk");
    std::fs::remove_file(&chunk).unwrap();
    symlink(outside.path(), &chunk).unwrap();

    let result = transfer.materialize_to(&destination_root, "symlink.bin");

    assert!(result.is_err(), "{result:?}");
    assert!(!temporary.path().join("destination/symlink.bin").exists());
    assert_no_materialization_staging(&temporary.path().join("destination"));
}

#[test]
fn unsafe_destination_spellings_are_rejected_before_side_effects() {
    let temporary = tempfile::tempdir().unwrap();
    std::fs::create_dir(temporary.path().join("receiver")).unwrap();
    std::fs::create_dir(temporary.path().join("destination")).unwrap();
    let receiver_root =
        Dir::open_ambient_dir(temporary.path().join("receiver"), ambient_authority()).unwrap();
    let destination_root =
        Dir::open_ambient_dir(temporary.path().join("destination"), ambient_authority()).unwrap();
    let transfer =
        PersistentTransfer::create(&receiver_root, "inbound", single_chunk_manifest()).unwrap();
    transfer
        .accept_chunk_from(0, Cursor::new(b"hello folderbase"))
        .unwrap();

    for unsafe_path in [
        "",
        ".",
        "..",
        "./artifact.bin",
        "nested//artifact.bin",
        "nested/./artifact.bin",
        "nested/../artifact.bin",
        "artifact.bin/",
        "/tmp/artifact.bin",
    ] {
        let result = transfer.materialize_to(&destination_root, Path::new(unsafe_path));
        assert!(
            matches!(result, Err(TransferReceiverError::UnsafeDestinationPath)),
            "{unsafe_path:?}: {result:?}"
        );
    }
    assert_eq!(
        std::fs::read_dir(temporary.path().join("destination"))
            .unwrap()
            .count(),
        0
    );
}

#[cfg(windows)]
#[test]
fn windows_unsafe_destination_spellings_are_rejected_exactly() {
    let temporary = tempfile::tempdir().unwrap();
    std::fs::create_dir(temporary.path().join("receiver")).unwrap();
    std::fs::create_dir(temporary.path().join("destination")).unwrap();
    let receiver_root =
        Dir::open_ambient_dir(temporary.path().join("receiver"), ambient_authority()).unwrap();
    let destination_root =
        Dir::open_ambient_dir(temporary.path().join("destination"), ambient_authority()).unwrap();
    let transfer =
        PersistentTransfer::create(&receiver_root, "inbound", single_chunk_manifest()).unwrap();
    transfer
        .accept_chunk_from(0, Cursor::new(b"hello folderbase"))
        .unwrap();

    for unsafe_path in [
        r"C:artifact.bin",
        r"C:\artifact.bin",
        r"\artifact.bin",
        r"\\server\share\artifact.bin",
        r"\\?\C:\artifact.bin",
        r"\\.\NUL",
        r"nested\\artifact.bin",
        "nested\\",
    ] {
        let result = transfer.materialize_to(&destination_root, Path::new(unsafe_path));
        assert!(
            matches!(result, Err(TransferReceiverError::UnsafeDestinationPath)),
            "{unsafe_path:?}: {result:?}"
        );
    }
    assert_eq!(
        std::fs::read_dir(temporary.path().join("destination"))
            .unwrap()
            .count(),
        0
    );
}

#[cfg(windows)]
#[test]
fn windows_nested_forward_and_backslash_destinations_are_both_supported() {
    let temporary = tempfile::tempdir().unwrap();
    std::fs::create_dir(temporary.path().join("receiver")).unwrap();
    std::fs::create_dir_all(temporary.path().join("destination/nested")).unwrap();
    let receiver_root =
        Dir::open_ambient_dir(temporary.path().join("receiver"), ambient_authority()).unwrap();
    let destination_root =
        Dir::open_ambient_dir(temporary.path().join("destination"), ambient_authority()).unwrap();
    let transfer =
        PersistentTransfer::create(&receiver_root, "inbound", single_chunk_manifest()).unwrap();
    transfer
        .accept_chunk_from(0, Cursor::new(b"hello folderbase"))
        .unwrap();

    for destination in ["nested/forward.bin", r"nested\back.bin"] {
        let materialized = transfer
            .materialize_to(&destination_root, destination)
            .unwrap();

        assert_eq!(
            materialized.relative_destination,
            PathBuf::from(destination)
        );
        assert_eq!(
            std::fs::read(temporary.path().join("destination").join(destination)).unwrap(),
            b"hello folderbase"
        );
    }
    assert_no_materialization_staging(&temporary.path().join("destination/nested"));
}

#[test]
fn missing_destination_parents_are_never_created() {
    let temporary = tempfile::tempdir().unwrap();
    std::fs::create_dir(temporary.path().join("receiver")).unwrap();
    std::fs::create_dir(temporary.path().join("destination")).unwrap();
    let receiver_root =
        Dir::open_ambient_dir(temporary.path().join("receiver"), ambient_authority()).unwrap();
    let destination_root =
        Dir::open_ambient_dir(temporary.path().join("destination"), ambient_authority()).unwrap();
    let transfer =
        PersistentTransfer::create(&receiver_root, "inbound", single_chunk_manifest()).unwrap();
    transfer
        .accept_chunk_from(0, Cursor::new(b"hello folderbase"))
        .unwrap();

    let result = transfer.materialize_to(&destination_root, "missing/artifact.bin");

    assert!(result.is_err(), "{result:?}");
    assert!(!temporary.path().join("destination/missing").exists());
}

#[cfg(unix)]
#[test]
fn symlinked_destination_parents_are_never_followed() {
    use std::os::unix::fs::symlink;

    let temporary = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    std::fs::create_dir(temporary.path().join("receiver")).unwrap();
    std::fs::create_dir(temporary.path().join("destination")).unwrap();
    symlink(outside.path(), temporary.path().join("destination/shared")).unwrap();
    let receiver_root =
        Dir::open_ambient_dir(temporary.path().join("receiver"), ambient_authority()).unwrap();
    let destination_root =
        Dir::open_ambient_dir(temporary.path().join("destination"), ambient_authority()).unwrap();
    let transfer =
        PersistentTransfer::create(&receiver_root, "inbound", single_chunk_manifest()).unwrap();
    transfer
        .accept_chunk_from(0, Cursor::new(b"hello folderbase"))
        .unwrap();

    let result = transfer.materialize_to(&destination_root, "shared/artifact.bin");

    assert!(result.is_err(), "{result:?}");
    assert_eq!(std::fs::read_dir(outside.path()).unwrap().count(), 0);
    assert_no_materialization_staging(&temporary.path().join("destination"));
}

#[test]
fn existing_regular_and_directory_leaves_are_never_overwritten() {
    for directory_leaf in [false, true] {
        let temporary = tempfile::tempdir().unwrap();
        std::fs::create_dir(temporary.path().join("receiver")).unwrap();
        std::fs::create_dir(temporary.path().join("destination")).unwrap();
        let leaf = temporary.path().join("destination/occupied");
        if directory_leaf {
            std::fs::create_dir(&leaf).unwrap();
            std::fs::write(leaf.join("sentinel"), b"directory").unwrap();
        } else {
            std::fs::write(&leaf, b"regular").unwrap();
        }
        let receiver_root =
            Dir::open_ambient_dir(temporary.path().join("receiver"), ambient_authority()).unwrap();
        let destination_root =
            Dir::open_ambient_dir(temporary.path().join("destination"), ambient_authority())
                .unwrap();
        let transfer =
            PersistentTransfer::create(&receiver_root, "inbound", single_chunk_manifest()).unwrap();
        transfer
            .accept_chunk_from(0, Cursor::new(b"hello folderbase"))
            .unwrap();

        let result = transfer.materialize_to(&destination_root, "occupied");

        assert!(matches!(
            result,
            Err(TransferReceiverError::DestinationAlreadyExists)
        ));
        if directory_leaf {
            assert_eq!(std::fs::read(leaf.join("sentinel")).unwrap(), b"directory");
        } else {
            assert_eq!(std::fs::read(&leaf).unwrap(), b"regular");
        }
        assert_no_materialization_staging(&temporary.path().join("destination"));
    }
}

#[cfg(unix)]
#[test]
fn existing_symlink_and_dangling_symlink_leaves_are_never_overwritten() {
    use std::os::unix::fs::symlink;

    for dangling in [false, true] {
        let temporary = tempfile::tempdir().unwrap();
        std::fs::create_dir(temporary.path().join("receiver")).unwrap();
        std::fs::create_dir(temporary.path().join("destination")).unwrap();
        let target = temporary.path().join("target");
        if !dangling {
            std::fs::write(&target, b"outside").unwrap();
        }
        symlink(&target, temporary.path().join("destination/occupied")).unwrap();
        let receiver_root =
            Dir::open_ambient_dir(temporary.path().join("receiver"), ambient_authority()).unwrap();
        let destination_root =
            Dir::open_ambient_dir(temporary.path().join("destination"), ambient_authority())
                .unwrap();
        let transfer =
            PersistentTransfer::create(&receiver_root, "inbound", single_chunk_manifest()).unwrap();
        transfer
            .accept_chunk_from(0, Cursor::new(b"hello folderbase"))
            .unwrap();

        let result = transfer.materialize_to(&destination_root, "occupied");

        assert!(matches!(
            result,
            Err(TransferReceiverError::DestinationAlreadyExists)
        ));
        assert!(
            std::fs::symlink_metadata(temporary.path().join("destination/occupied"))
                .unwrap()
                .file_type()
                .is_symlink()
        );
        if !dangling {
            assert_eq!(std::fs::read(&target).unwrap(), b"outside");
        }
        assert_no_materialization_staging(&temporary.path().join("destination"));
    }
}

#[cfg(unix)]
#[test]
fn materialization_staging_is_private_and_removed_after_ordinary_results() {
    use std::os::unix::fs::PermissionsExt;

    let temporary = tempfile::tempdir().unwrap();
    std::fs::create_dir(temporary.path().join("receiver")).unwrap();
    std::fs::create_dir(temporary.path().join("destination")).unwrap();
    let receiver_root =
        Dir::open_ambient_dir(temporary.path().join("receiver"), ambient_authority()).unwrap();
    let destination_root =
        Dir::open_ambient_dir(temporary.path().join("destination"), ambient_authority()).unwrap();
    let transfer =
        PersistentTransfer::create(&receiver_root, "inbound", single_chunk_manifest()).unwrap();
    transfer
        .accept_chunk_from(0, Cursor::new(b"hello folderbase"))
        .unwrap();

    transfer
        .materialize_to(&destination_root, "private.bin")
        .unwrap();

    assert_eq!(
        std::fs::metadata(temporary.path().join("destination/private.bin"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600,
        "the installed hard link must retain the staging inode's private mode"
    );
    assert_no_materialization_staging(&temporary.path().join("destination"));
}

#[test]
fn concurrent_materializers_produce_one_exact_winner() {
    let temporary = tempfile::tempdir().unwrap();
    std::fs::create_dir(temporary.path().join("receiver")).unwrap();
    std::fs::create_dir(temporary.path().join("destination")).unwrap();
    let receiver_root =
        Dir::open_ambient_dir(temporary.path().join("receiver"), ambient_authority()).unwrap();
    let destination_root =
        Dir::open_ambient_dir(temporary.path().join("destination"), ambient_authority()).unwrap();
    let transfer = Arc::new(
        PersistentTransfer::create(&receiver_root, "inbound", single_chunk_manifest()).unwrap(),
    );
    transfer
        .accept_chunk_from(0, Cursor::new(b"hello folderbase"))
        .unwrap();
    let barrier = Arc::new(Barrier::new(8));
    let mut materializers = Vec::new();
    for _ in 0..8 {
        let transfer = Arc::clone(&transfer);
        let barrier = Arc::clone(&barrier);
        let destination_root = destination_root.try_clone().unwrap();
        materializers.push(std::thread::spawn(move || {
            barrier.wait();
            transfer.materialize_to(&destination_root, "winner.bin")
        }));
    }
    let outcomes = materializers
        .into_iter()
        .map(|materializer| materializer.join().unwrap())
        .collect::<Vec<_>>();

    assert_eq!(
        outcomes.iter().filter(|result| result.is_ok()).count(),
        1,
        "{outcomes:?}"
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|result| matches!(result, Err(TransferReceiverError::DestinationAlreadyExists)))
            .count(),
        7,
        "{outcomes:?}"
    );
    assert_eq!(
        std::fs::read(temporary.path().join("destination/winner.bin")).unwrap(),
        b"hello folderbase"
    );
    assert_no_materialization_staging(&temporary.path().join("destination"));
}

#[test]
fn independent_processes_with_independent_checkpoints_produce_one_exact_winner() {
    let temporary = tempfile::tempdir().unwrap();
    std::fs::create_dir(temporary.path().join("destination")).unwrap();
    let root = Dir::open_ambient_dir(temporary.path(), ambient_authority()).unwrap();
    let manifest = single_chunk_manifest();
    let digest = manifest.canonical_digest().unwrap();
    for checkpoint in ["left", "right"] {
        let transfer = PersistentTransfer::create(&root, checkpoint, manifest.clone()).unwrap();
        transfer
            .accept_chunk_from(0, Cursor::new(b"hello folderbase"))
            .unwrap();
    }
    let release = temporary.path().join("release");
    let left_started = temporary.path().join("left-started");
    let right_started = temporary.path().join("right-started");
    let left_outcome = temporary.path().join("left-outcome");
    let right_outcome = temporary.path().join("right-outcome");
    let mut left = spawn_materializer_process_helper(
        temporary.path(),
        "left",
        &digest,
        &left_started,
        &release,
        &left_outcome,
    );
    let mut right = spawn_materializer_process_helper(
        temporary.path(),
        "right",
        &digest,
        &right_started,
        &release,
        &right_outcome,
    );
    assert!(wait_for_path(&left_started, Duration::from_secs(5)));
    assert!(wait_for_path(&right_started, Duration::from_secs(5)));
    std::fs::write(&release, b"go").unwrap();

    assert!(wait_for_child(&mut left, Duration::from_secs(10)).success());
    assert!(wait_for_child(&mut right, Duration::from_secs(10)).success());
    let mut outcomes = [
        std::fs::read_to_string(left_outcome).unwrap(),
        std::fs::read_to_string(right_outcome).unwrap(),
    ];
    outcomes.sort();
    assert_eq!(outcomes, ["already-exists", "installed"]);
    assert_eq!(
        std::fs::read(temporary.path().join("destination/winner.bin")).unwrap(),
        b"hello folderbase"
    );
    assert_no_materialization_staging(&temporary.path().join("destination"));
}

#[test]
#[ignore = "subprocess helper for materializer no-clobber tests"]
fn materializer_process_helper() {
    run_materializer_process_helper_from_environment();
}

#[test]
fn opaque_file_matrix_round_trips_without_type_specific_behavior() {
    let formats = [
        ("notes.md", b"# Agent notes\n\n- exact bytes\n".as_slice()),
        ("records.csv", b"id,name\n1,Folderbase\n".as_slice()),
        ("paper.pdf", b"%PDF-1.7\nopaque-pdf-bytes\n%%EOF".as_slice()),
        ("proposal.docx", b"PK\x03\x04opaque-office-zip".as_slice()),
        (
            "state.sqlite",
            b"SQLite format 3\0opaque-database-capture".as_slice(),
        ),
        (
            "image.png",
            b"\x89PNG\r\n\x1a\nopaque-image-bytes".as_slice(),
        ),
        ("audio.mp3", b"ID3\x04\0\0opaque-audio-bytes".as_slice()),
        (
            "movie.mp4",
            b"\0\0\0\x18ftypmp42opaque-video-bytes".as_slice(),
        ),
        ("objects.pack", b"PACK\0\0\0\x02opaque-git-pack".as_slice()),
        (
            "unknown.bin",
            b"\0\xff\x80folderbase\0opaque\0bytes".as_slice(),
        ),
        (
            "Project brief \u{2014} \u{30c7}\u{30fc}\u{30bf}.txt",
            b"spaces and Unicode path".as_slice(),
        ),
    ];
    let temporary = tempfile::tempdir().unwrap();
    std::fs::create_dir(temporary.path().join("receiver")).unwrap();
    std::fs::create_dir(temporary.path().join("destination")).unwrap();
    let receiver_root =
        Dir::open_ambient_dir(temporary.path().join("receiver"), ambient_authority()).unwrap();
    let destination_root =
        Dir::open_ambient_dir(temporary.path().join("destination"), ambient_authority()).unwrap();

    for (index, (name, bytes)) in formats.iter().enumerate() {
        let checkpoint = format!("inbound-{index}");
        let transfer = PersistentTransfer::create(
            &receiver_root,
            &checkpoint,
            one_standard_chunk_manifest(bytes),
        )
        .unwrap();
        transfer.accept_chunk_from(0, Cursor::new(bytes)).unwrap();

        let materialized = transfer.materialize_to(&destination_root, name).unwrap();

        assert_eq!(
            std::fs::read(temporary.path().join("destination").join(name)).unwrap(),
            *bytes,
            "{name}"
        );
        assert_eq!(materialized.relative_destination, PathBuf::from(name));
    }
    assert_no_materialization_staging(&temporary.path().join("destination"));
}

#[cfg(all(unix, not(target_vendor = "apple")))]
#[test]
fn non_utf8_destination_names_round_trip_without_loss() {
    // The proof applies where the Unix filesystem/API accepts opaque non-UTF-8
    // leaf bytes. Tested macOS/APFS rejects this spelling with EILSEQ before
    // Core can create the hard link, so Apple is excluded rather than claiming
    // support the platform does not provide.
    use std::os::unix::ffi::OsStringExt;

    let temporary = tempfile::tempdir().unwrap();
    std::fs::create_dir(temporary.path().join("receiver")).unwrap();
    std::fs::create_dir(temporary.path().join("destination")).unwrap();
    let receiver_root =
        Dir::open_ambient_dir(temporary.path().join("receiver"), ambient_authority()).unwrap();
    let destination_root =
        Dir::open_ambient_dir(temporary.path().join("destination"), ambient_authority()).unwrap();
    let bytes = b"opaque bytes at a non-UTF-8 path";
    let transfer = PersistentTransfer::create(
        &receiver_root,
        "inbound",
        one_standard_chunk_manifest(bytes),
    )
    .unwrap();
    transfer.accept_chunk_from(0, Cursor::new(bytes)).unwrap();
    let destination = PathBuf::from(std::ffi::OsString::from_vec(b"artifact-\xff.bin".to_vec()));

    let materialized = transfer
        .materialize_to(&destination_root, &destination)
        .unwrap();

    assert_eq!(
        std::fs::read(temporary.path().join("destination").join(&destination)).unwrap(),
        bytes
    );
    assert_eq!(materialized.relative_destination, destination);
}

#[test]
fn multi_megabyte_binary_materializes_without_type_sniffing() {
    let temporary = tempfile::tempdir().unwrap();
    let source_root = temporary.path().join("source");
    let receiver_root_path = temporary.path().join("receiver");
    let destination_root_path = temporary.path().join("destination");
    std::fs::create_dir(&source_root).unwrap();
    std::fs::create_dir(&receiver_root_path).unwrap();
    std::fs::create_dir(&destination_root_path).unwrap();
    write_repeated_file(&source_root.join("large.unknown"), 0xa5, 8 * 1024 * 1024);
    let store = LocalVersionStore::open(&source_root).unwrap();
    let captured = store.capture_file("large.unknown").unwrap();
    let expected_digest = captured.version.content.digest.clone();
    let mut source = store
        .open_chunk_transfer(&captured.version.id, ChunkTransferProfile::StandardV1)
        .unwrap();
    let receiver_root = Dir::open_ambient_dir(&receiver_root_path, ambient_authority()).unwrap();
    let destination_root =
        Dir::open_ambient_dir(&destination_root_path, ambient_authority()).unwrap();
    let transfer =
        PersistentTransfer::create(&receiver_root, "inbound", source.manifest().clone()).unwrap();
    for index in 0..source.manifest().chunks.len() as u32 {
        accept_source_chunk_disk_backed(&mut source, &transfer, index);
    }

    let materialized = transfer
        .materialize_to(&destination_root, "large.unknown")
        .unwrap();

    assert_eq!(
        sha256_file(&destination_root_path.join("large.unknown")),
        expected_digest
    );
    assert_eq!(materialized.object.object_sha256, expected_digest);
    assert_eq!(materialized.object.object_bytes, 8 * 1024 * 1024);
}

#[test]
fn captured_source_receiver_restart_and_materializer_complete_end_to_end() {
    let temporary = tempfile::tempdir().unwrap();
    let source_root = temporary.path().join("source");
    let receiver_root_path = temporary.path().join("receiver");
    let destination_root_path = temporary.path().join("destination");
    std::fs::create_dir(&source_root).unwrap();
    std::fs::create_dir(&receiver_root_path).unwrap();
    std::fs::create_dir(&destination_root_path).unwrap();
    write_repeated_file(
        &source_root.join("captured.repo-pack"),
        0x5a,
        6 * 1024 * 1024,
    );
    let store = LocalVersionStore::open(&source_root).unwrap();
    let captured = store.capture_file("captured.repo-pack").unwrap();
    let expected_digest = captured.version.content.digest.clone();
    let mut source = store
        .open_chunk_transfer(&captured.version.id, ChunkTransferProfile::StandardV1)
        .unwrap();
    assert!(
        source.manifest().chunks.len() > 1,
        "the restart fixture must cross a chunk boundary"
    );
    let manifest = source.manifest().clone();
    let manifest_digest = source.manifest_digest().to_owned();
    let receiver_root = Dir::open_ambient_dir(&receiver_root_path, ambient_authority()).unwrap();
    let transfer = PersistentTransfer::create(&receiver_root, "inbound", manifest.clone()).unwrap();
    accept_source_chunk_disk_backed(&mut source, &transfer, 0);
    drop(source);
    drop(transfer);

    let mut source = store
        .reopen_chunk_transfer(
            &captured.version.id,
            ChunkTransferProfile::StandardV1,
            &manifest_digest,
        )
        .unwrap();
    let transfer = PersistentTransfer::open(&receiver_root, "inbound", &manifest_digest).unwrap();
    for index in 1..manifest.chunks.len() as u32 {
        accept_source_chunk_disk_backed(&mut source, &transfer, index);
    }
    drop(source);
    drop(transfer);

    let transfer = PersistentTransfer::open(&receiver_root, "inbound", &manifest_digest).unwrap();
    let destination_root =
        Dir::open_ambient_dir(&destination_root_path, ambient_authority()).unwrap();
    let materialized = transfer
        .materialize_to(&destination_root, "captured.repo-pack")
        .unwrap();

    assert_eq!(
        sha256_file(&destination_root_path.join("captured.repo-pack")),
        expected_digest
    );
    assert_eq!(materialized.object.manifest_digest, manifest_digest);
    assert_eq!(materialized.object.object_sha256, expected_digest);
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
fn independent_processes_serialize_chunk_acceptance() {
    let temporary = tempfile::tempdir().unwrap();
    let root = Dir::open_ambient_dir(temporary.path(), ambient_authority()).unwrap();
    let manifest = single_chunk_manifest();
    let digest = manifest.canonical_digest().unwrap();
    drop(PersistentTransfer::create(&root, "inbound", manifest).unwrap());
    let holder_entered = temporary.path().join("holder-entered");
    let holder_release = temporary.path().join("holder-release");
    let holder_outcome = temporary.path().join("holder-outcome");
    let waiter_started = temporary.path().join("waiter-started");
    let waiter_entered = temporary.path().join("waiter-entered");
    let waiter_outcome = temporary.path().join("waiter-outcome");

    let mut holder = spawn_receiver_process_helper(
        temporary.path(),
        &digest,
        &holder_entered,
        Some(&holder_release),
        &holder_outcome,
        None,
    );
    assert!(
        wait_for_path(&holder_entered, Duration::from_secs(5)),
        "the holder process must enter its reader while owning the lease"
    );
    let mut waiter = spawn_receiver_process_helper(
        temporary.path(),
        &digest,
        &waiter_entered,
        None,
        &waiter_outcome,
        Some(&waiter_started),
    );
    assert!(
        wait_for_path(&waiter_started, Duration::from_secs(5)),
        "the waiter process must report immediately before requesting receipt"
    );

    let waiter_was_blocked = !wait_for_path(&waiter_entered, Duration::from_secs(1));
    std::fs::write(&holder_release, b"release").unwrap();
    let holder_status = wait_for_child(&mut holder, Duration::from_secs(5));
    let waiter_status = wait_for_child(&mut waiter, Duration::from_secs(5));

    assert!(
        waiter_was_blocked,
        "the waiter process must not enter its reader while another process owns the lease"
    );
    assert!(holder_status.success(), "holder helper failed");
    assert!(waiter_status.success(), "waiter helper failed");
    assert_eq!(std::fs::read_to_string(holder_outcome).unwrap(), "accepted");
    assert_eq!(
        std::fs::read_to_string(waiter_outcome).unwrap(),
        "already-present"
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
#[ignore = "subprocess helper for receiver lease tests"]
fn receiver_process_lock_helper() {
    run_receiver_process_helper_from_environment();
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

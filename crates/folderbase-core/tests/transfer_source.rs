use std::{
    fs,
    io::{self, Cursor, Write},
};

use folderbase_core::{
    ChunkTransferProfile, FolderbaseKind, InitializationOptions, LocalVersionStore, ObjectId,
    TransferSourceError, VersionId, apply_history_transfer, approve_history_transfer, initialize,
    plan_initialization,
    transfer_manifest::{ChunkManifest, LARGE_PROFILE_V1, STANDARD_PROFILE_V1},
};
use tempfile::tempdir;

struct InterruptAfter {
    remaining: usize,
}

impl Write for InterruptAfter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.remaining == 0 {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "simulated transport interruption",
            ));
        }
        let accepted = bytes.len().min(self.remaining);
        self.remaining -= accepted;
        Ok(accepted)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Default)]
struct RecordingWriter {
    bytes: Vec<u8>,
    largest_write: usize,
}

impl Write for RecordingWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.largest_write = self.largest_write.max(bytes.len());
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn transfer_source_plans_and_streams_the_exact_captured_version() {
    let fixture = tempdir().unwrap();
    let original = (0_u8..=255)
        .cycle()
        .take(5 * 1024 * 1024 + 17)
        .collect::<Vec<_>>();
    fs::write(fixture.path().join("movie.bin"), &original).unwrap();
    let store = LocalVersionStore::open(fixture.path()).unwrap();
    let captured = store.capture_file("movie.bin").unwrap();
    fs::write(
        fixture.path().join("movie.bin"),
        b"a newer captured workspace version",
    )
    .unwrap();
    let newer = store.capture_file("movie.bin").unwrap();
    assert_ne!(captured.version.id, newer.version.id);

    let mut source = store
        .open_chunk_transfer(&captured.version.id, ChunkTransferProfile::StandardV1)
        .unwrap();
    assert_eq!(source.version_id(), &captured.version.id);
    assert_eq!(source.manifest().profile, STANDARD_PROFILE_V1);
    assert_eq!(
        source.manifest().object_sha256,
        captured.version.content.digest
    );
    assert_eq!(source.manifest().object_bytes, original.len() as u64);
    source.manifest().validate().unwrap();
    let encoded = serde_json::to_vec(source.manifest()).unwrap();
    assert_eq!(
        ChunkManifest::decode_bounded(Cursor::new(encoded)).unwrap(),
        *source.manifest()
    );

    fs::write(fixture.path().join("movie.bin"), b"mutable workspace edit").unwrap();
    let mut streamed = Vec::new();
    for index in 0..source.manifest().chunks.len() as u32 {
        let verified = source.copy_chunk(index, &mut streamed).unwrap();
        assert_eq!(verified.chunk_index, index);
        assert_eq!(verified.manifest_digest, source.manifest_digest());
    }
    assert_eq!(streamed, original);
}

#[test]
fn managed_profile_uses_large_file_metadata_without_reading_or_allocating_the_payload() {
    let fixture = tempdir().unwrap();
    let sparse_path = fixture.path().join("ten-gibibytes.bin");
    let sparse = fs::File::create(&sparse_path).unwrap();
    sparse.set_len(10 * 1024 * 1024 * 1024).unwrap();
    let object_bytes = sparse.metadata().unwrap().len();

    assert_eq!(
        ChunkTransferProfile::Managed
            .selected_profile_for_bytes(object_bytes)
            .unwrap(),
        LARGE_PROFILE_V1
    );
    assert_eq!(
        ChunkTransferProfile::StandardV1
            .selected_profile_for_bytes(object_bytes)
            .unwrap(),
        STANDARD_PROFILE_V1
    );
    assert!(matches!(
        ChunkTransferProfile::Managed.selected_profile_for_bytes(1024 * 1024 * 1024 * 1024 + 1),
        Err(TransferSourceError::ObjectTooLarge { .. })
    ));
}

#[test]
fn interrupted_copy_reopens_only_against_the_same_manifest_digest() {
    let fixture = tempdir().unwrap();
    let bytes = (0_u8..=250).cycle().take(900_000).collect::<Vec<_>>();
    fs::write(fixture.path().join("archive.zip"), &bytes).unwrap();
    let store = LocalVersionStore::open(fixture.path()).unwrap();
    let captured = store.capture_file("archive.zip").unwrap();
    let mut source = store
        .open_chunk_transfer(&captured.version.id, ChunkTransferProfile::StandardV1)
        .unwrap();
    let expected_manifest_digest = source.manifest_digest().to_owned();
    assert_eq!(
        source.manifest().object_sha256,
        "ed855898ab94ea51ab5ee302a2d7fe6d8aa87087ac8d36265bd365a22e84af37"
    );
    assert_eq!(
        source.manifest_digest(),
        "3c54c96d44bc0360d6cd49527074de9079f14738614aa5789f93f898981aba90"
    );
    assert_eq!(source.manifest().chunks.len(), 2);
    assert_eq!(source.manifest().chunks[0].bytes, 740_103);
    assert_eq!(
        source.manifest().chunks[0].sha256,
        "c0c5aaca08281f612bfe907f89d85b93a7274540d498b3e41429d203dcb4af9b"
    );

    let error = source
        .copy_chunk(0, InterruptAfter { remaining: 17_000 })
        .unwrap_err();
    assert!(matches!(error, TransferSourceError::Writer(_)));

    let reopened = store
        .reopen_chunk_transfer(
            &captured.version.id,
            ChunkTransferProfile::StandardV1,
            &expected_manifest_digest,
        )
        .unwrap();
    assert_eq!(reopened.manifest(), source.manifest());

    let error = store
        .reopen_chunk_transfer(
            &captured.version.id,
            ChunkTransferProfile::StandardV1,
            &"0".repeat(64),
        )
        .unwrap_err();
    assert!(matches!(
        error,
        TransferSourceError::ManifestDigestMismatch { .. }
    ));

    assert!(matches!(
        store.reopen_chunk_transfer(
            &captured.version.id,
            ChunkTransferProfile::StandardV1,
            "not-a-digest",
        ),
        Err(TransferSourceError::InvalidExpectedManifestDigest)
    ));

    let error = store
        .reopen_chunk_transfer(
            &captured.version.id,
            ChunkTransferProfile::LargeV1,
            &expected_manifest_digest,
        )
        .unwrap_err();
    assert!(matches!(
        error,
        TransferSourceError::ManifestDigestMismatch { .. }
    ));
}

#[test]
fn chunk_copy_is_bounded_and_unknown_indices_write_nothing() {
    let fixture = tempdir().unwrap();
    let bytes = (0_u8..=255)
        .cycle()
        .take(6 * 1024 * 1024 + 31)
        .collect::<Vec<_>>();
    fs::write(fixture.path().join("database.sqlite"), &bytes).unwrap();
    let store = LocalVersionStore::open(fixture.path()).unwrap();
    let captured = store.capture_file("database.sqlite").unwrap();
    let mut source = store
        .open_chunk_transfer(&captured.version.id, ChunkTransferProfile::LargeV1)
        .unwrap();

    let unknown = source.manifest().chunks.len() as u32;
    let mut untouched = Vec::new();
    assert!(matches!(
        source.copy_chunk(unknown, &mut untouched),
        Err(TransferSourceError::UnknownChunk(index)) if index == unknown
    ));
    assert!(untouched.is_empty());

    let descriptor = source.manifest().chunks[0].clone();
    let mut output = RecordingWriter::default();
    let verified = source.copy_chunk(0, &mut output).unwrap();
    assert!(output.largest_write <= folderbase_core::TRANSFER_IO_BUFFER_BYTES);
    assert_eq!(
        output.bytes,
        bytes[descriptor.offset as usize..(descriptor.offset + descriptor.bytes) as usize]
    );
    assert_eq!(verified.chunk_bytes, descriptor.bytes);
    assert_eq!(verified.chunk_sha256, descriptor.sha256);
}

#[test]
fn corrupted_or_replaced_immutable_blobs_never_produce_a_verified_chunk() {
    let corrupted_fixture = tempdir().unwrap();
    let bytes = (0_u8..=255).cycle().take(400_000).collect::<Vec<_>>();
    fs::write(corrupted_fixture.path().join("video.mov"), &bytes).unwrap();
    let corrupted_store = LocalVersionStore::open(corrupted_fixture.path()).unwrap();
    let corrupted = corrupted_store.capture_file("video.mov").unwrap();
    let corrupted_blob = corrupted_fixture
        .path()
        .join(".folderbase/versions/blobs/sha256")
        .join(&corrupted.version.content.digest);
    let mut changed = bytes.clone();
    changed[0] ^= 0xff;
    fs::write(&corrupted_blob, changed).unwrap();
    assert!(matches!(
        corrupted_store
            .open_chunk_transfer(&corrupted.version.id, ChunkTransferProfile::StandardV1),
        Err(TransferSourceError::SourceChanged)
    ));

    let replaced_fixture = tempdir().unwrap();
    fs::write(replaced_fixture.path().join("video.mov"), &bytes).unwrap();
    let replaced_store = LocalVersionStore::open(replaced_fixture.path()).unwrap();
    let replaced = replaced_store.capture_file("video.mov").unwrap();
    let mut source = replaced_store
        .open_chunk_transfer(&replaced.version.id, ChunkTransferProfile::StandardV1)
        .unwrap();
    let blob = replaced_fixture
        .path()
        .join(".folderbase/versions/blobs/sha256")
        .join(&replaced.version.content.digest);
    let detached = blob.with_extension("detached");
    fs::rename(&blob, &detached).unwrap();
    fs::write(&blob, &bytes).unwrap();
    let mut output = Vec::new();
    assert!(matches!(
        source.copy_chunk(0, &mut output),
        Err(TransferSourceError::SourceChanged)
    ));
    assert!(output.is_empty());
}

#[test]
fn replacing_the_immutable_version_record_revokes_an_open_source() {
    let fixture = tempdir().unwrap();
    let bytes = (0_u8..=127).cycle().take(300_000).collect::<Vec<_>>();
    fs::write(fixture.path().join("proposal.docx"), &bytes).unwrap();
    let store = LocalVersionStore::open(fixture.path()).unwrap();
    let captured = store.capture_file("proposal.docx").unwrap();
    let mut source = store
        .open_chunk_transfer(&captured.version.id, ChunkTransferProfile::StandardV1)
        .unwrap();
    let record = fixture
        .path()
        .join(".folderbase/versions/records")
        .join(format!("{}.json", captured.version.id));
    let encoded = fs::read(&record).unwrap();
    let detached = record.with_extension("detached");
    fs::rename(&record, detached).unwrap();
    fs::write(&record, encoded).unwrap();

    let mut output = Vec::new();
    assert!(matches!(
        source.copy_chunk(0, &mut output),
        Err(TransferSourceError::SourceChanged)
    ));
    assert!(output.is_empty());
}

#[test]
fn a_new_nested_folderbase_boundary_revokes_parent_transfer_access() {
    let fixture = tempdir().unwrap();
    fs::create_dir(fixture.path().join("client")).unwrap();
    let bytes = (0_u8..=63).cycle().take(300_000).collect::<Vec<_>>();
    fs::write(fixture.path().join("client/private.pdf"), &bytes).unwrap();
    let store = LocalVersionStore::open(fixture.path()).unwrap();
    let captured = store.capture_file("client/private.pdf").unwrap();
    let mut source = store
        .open_chunk_transfer(&captured.version.id, ChunkTransferProfile::StandardV1)
        .unwrap();

    fs::create_dir_all(fixture.path().join("client/.folderbase")).unwrap();
    fs::write(fixture.path().join("client/FOLDERBASE.md"), b"# Client\n").unwrap();
    fs::write(
        fixture.path().join("client/.folderbase/manifest.json"),
        b"{not-json",
    )
    .unwrap();
    let mut output = Vec::new();
    assert!(source.copy_chunk(0, &mut output).is_err());
    assert!(output.is_empty());
}

#[test]
fn markerless_context_does_not_revoke_parent_transfer_access() {
    let (fixture, mut source, bytes) = client_transfer_fixture();
    fs::create_dir_all(fixture.path().join("client/.folderbase/questions")).unwrap();
    fs::write(
        fixture.path().join("client/.folderbase/summary.md"),
        b"ordinary context",
    )
    .unwrap();

    let mut output = Vec::new();
    source.copy_chunk(0, &mut output).unwrap();
    assert_eq!(output, bytes);
}

#[test]
fn case_folded_marker_alias_revokes_transfer_without_becoming_authority() {
    let (fixture, mut source, _) = client_transfer_fixture();
    fs::create_dir_all(fixture.path().join("client/.FOLDERBASE")).unwrap();
    fs::write(
        fixture.path().join("client/.FOLDERBASE/MANIFEST.JSON"),
        b"opaque",
    )
    .unwrap();

    let mut output = Vec::new();
    assert!(matches!(
        source.copy_chunk(0, &mut output),
        Err(TransferSourceError::SourceChanged)
    ));
    assert!(output.is_empty());
}

#[cfg(unix)]
#[test]
fn symlink_shaped_marker_revokes_transfer_without_being_followed() {
    use std::os::unix::fs::symlink;

    let (fixture, mut source, _) = client_transfer_fixture();
    symlink(
        fixture.path().join("missing-state"),
        fixture.path().join("client/.folderbase"),
    )
    .unwrap();

    let mut output = Vec::new();
    assert!(matches!(
        source.copy_chunk(0, &mut output),
        Err(TransferSourceError::SourceChanged)
    ));
    assert!(output.is_empty());
}

fn client_transfer_fixture() -> (
    tempfile::TempDir,
    folderbase_core::ChunkTransferSource,
    Vec<u8>,
) {
    let fixture = tempdir().unwrap();
    fs::create_dir(fixture.path().join("client")).unwrap();
    let bytes = (0_u8..=63).cycle().take(300_000).collect::<Vec<_>>();
    fs::write(fixture.path().join("client/private.pdf"), &bytes).unwrap();
    let store = LocalVersionStore::open(fixture.path()).unwrap();
    let captured = store.capture_file("client/private.pdf").unwrap();
    let source = store
        .open_chunk_transfer(&captured.version.id, ChunkTransferProfile::StandardV1)
        .unwrap();
    (fixture, source, bytes)
}

#[test]
fn replacing_the_root_path_revokes_its_open_capability() {
    let fixture = tempdir().unwrap();
    let root = fixture.path().join("workspace");
    fs::create_dir(&root).unwrap();
    let bytes = (0_u8..=63).cycle().take(300_000).collect::<Vec<_>>();
    fs::write(root.join("audio.wav"), &bytes).unwrap();
    let store = LocalVersionStore::open(&root).unwrap();
    let captured = store.capture_file("audio.wav").unwrap();
    let mut source = store
        .open_chunk_transfer(&captured.version.id, ChunkTransferProfile::StandardV1)
        .unwrap();

    fs::rename(&root, fixture.path().join("detached-workspace")).unwrap();
    fs::create_dir(&root).unwrap();
    let mut output = Vec::new();
    assert!(matches!(
        source.copy_chunk(0, &mut output),
        Err(TransferSourceError::SourceChanged)
    ));
    assert!(output.is_empty());
}

#[cfg(unix)]
#[test]
fn symlinked_internal_blob_directories_are_never_followed() {
    use std::os::unix::fs::symlink;

    let fixture = tempdir().unwrap();
    let outside = tempdir().unwrap();
    let bytes = (0_u8..=63).cycle().take(300_000).collect::<Vec<_>>();
    fs::write(fixture.path().join("image.raw"), &bytes).unwrap();
    let store = LocalVersionStore::open(fixture.path()).unwrap();
    let captured = store.capture_file("image.raw").unwrap();
    let blob_directory = fixture.path().join(".folderbase/versions/blobs/sha256");
    fs::copy(
        blob_directory.join(&captured.version.content.digest),
        outside.path().join(&captured.version.content.digest),
    )
    .unwrap();
    fs::remove_dir_all(&blob_directory).unwrap();
    symlink(outside.path(), &blob_directory).unwrap();

    assert!(
        store
            .open_chunk_transfer(&captured.version.id, ChunkTransferProfile::StandardV1)
            .is_err()
    );
}

#[cfg(unix)]
#[test]
fn symlinked_outgoing_authority_cannot_hide_a_transfer_revocation() {
    assert_symlinked_transfer_authority_fails_closed("outgoing");
}

#[cfg(unix)]
#[test]
fn symlinked_history_transfer_authority_cannot_hide_a_transfer_revocation() {
    assert_symlinked_transfer_authority_fails_closed("history-transfers");
}

#[cfg(unix)]
#[test]
fn corrupt_transfer_authority_cannot_hide_a_transfer_revocation() {
    let (fixture, store, object_id, version_id, mut opened_source) = transferred_out_fixture();
    fs::write(
        fixture
            .path()
            .join(".folderbase/history-transfers/outgoing")
            .join(format!("{object_id}.json")),
        b"{not valid json",
    )
    .unwrap();

    assert_transfer_source_changed(&store, &version_id, &mut opened_source);
}

#[cfg(unix)]
fn assert_symlinked_transfer_authority_fails_closed(authority_directory: &str) {
    use std::os::unix::fs::symlink;

    let (fixture, store, _, version_id, mut opened_source) = transferred_out_fixture();
    let empty_authority = tempdir().unwrap();
    let authority = match authority_directory {
        "outgoing" => fixture
            .path()
            .join(".folderbase/history-transfers/outgoing"),
        "history-transfers" => fixture.path().join(".folderbase/history-transfers"),
        other => panic!("unknown transfer authority directory {other}"),
    };
    let detached = authority.with_extension("detached");
    fs::rename(&authority, &detached).unwrap();
    symlink(empty_authority.path(), &authority).unwrap();

    assert_transfer_source_changed(&store, &version_id, &mut opened_source);
}

#[cfg(unix)]
fn assert_transfer_source_changed(
    store: &LocalVersionStore,
    version_id: &VersionId,
    opened_source: &mut folderbase_core::ChunkTransferSource,
) {
    assert!(matches!(
        store.open_chunk_transfer(version_id, ChunkTransferProfile::StandardV1),
        Err(TransferSourceError::SourceChanged)
    ));

    let mut output = Vec::new();
    assert!(matches!(
        opened_source.copy_chunk(0, &mut output),
        Err(TransferSourceError::SourceChanged)
    ));
    assert!(output.is_empty());
}

#[cfg(unix)]
fn transferred_out_fixture() -> (
    tempfile::TempDir,
    LocalVersionStore,
    ObjectId,
    VersionId,
    folderbase_core::ChunkTransferSource,
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
    fs::write(
        fixture.path().join("Client/private.txt"),
        b"revoked bytes\n",
    )
    .unwrap();
    let store = LocalVersionStore::open(fixture.path()).unwrap();
    let captured = store.capture_file("Client/private.txt").unwrap();
    let source = store
        .open_chunk_transfer(&captured.version.id, ChunkTransferProfile::StandardV1)
        .unwrap();

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
        child_fixture.path().join(".folderbase/manifest.json"),
        fixture.path().join("Client/.folderbase/manifest.json"),
    )
    .unwrap();
    let child_store = LocalVersionStore::open(fixture.path().join("Client")).unwrap();
    let plan = store
        .propose_history_transfer(
            &child_store,
            &parent.folderbase_id,
            &child.folderbase_id,
            &captured.object.id,
            "private.txt",
        )
        .unwrap();
    apply_history_transfer(approve_history_transfer(plan).unwrap()).unwrap();
    assert!(
        fixture
            .path()
            .join(".folderbase/history-transfers/outgoing")
            .join(format!("{}.json", captured.object.id))
            .is_file()
    );

    fs::remove_dir_all(fixture.path().join("Client/.folderbase")).unwrap();

    (
        fixture,
        store,
        captured.object.id,
        captured.version.id,
        source,
    )
}

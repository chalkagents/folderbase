use crate::folderbase_version::{
    DeletedKind, Exclusion, ExclusionKind, ExclusionReason, FolderbaseVersion,
    FolderbaseVersionEntries, FolderbaseVersionParts, PathBinding, RootManifest, Tombstone,
};

#[test]
fn sibling_producer_constructs_a_minimal_validated_version_without_raw_deserialization() {
    let root_manifest = RootManifest::from_verified_producer(
        "version_0198ee40-c333-7ccc-8000-000000000100",
        "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        512,
    );
    let bindings = vec![
        PathBinding::regular_file_from_verified_producer(
            ".folderbaseignore",
            "obj_0198ee40-b222-7bbb-8000-000000000101",
            "version_0198ee40-c333-7ccc-8000-000000000101",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            64,
            false,
        ),
        PathBinding::regular_file_from_verified_producer(
            "FOLDERBASE.md",
            "obj_0198ee40-b222-7bbb-8000-000000000102",
            "version_0198ee40-c333-7ccc-8000-000000000102",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            128,
            false,
        ),
        PathBinding::directory_from_verified_producer(
            "docs",
            "obj_0198ee40-b222-7bbb-8000-000000000103",
        ),
        PathBinding::symlink_from_verified_producer(
            "latest",
            "obj_0198ee40-b222-7bbb-8000-000000000104",
            "version_0198ee40-c333-7ccc-8000-000000000104",
            "FOLDERBASE.md",
        ),
    ];
    let tombstones = vec![Tombstone::from_verified_producer(
        "retired.txt",
        "obj_0198ee40-b222-7bbb-8000-000000000105",
        DeletedKind::RegularFile,
        Some("version_0198ee40-c333-7ccc-8000-000000000105".to_owned()),
    )];
    let exclusions = vec![Exclusion::from_verified_producer(
        "vendor-special",
        ExclusionKind::HardLink,
        ExclusionReason::UnsupportedV1,
    )];
    let parts = FolderbaseVersionParts::portable_v1_from_verified_producer(
        "folderbase_018f43c2-9a1b-7def-8123-456789abcdef",
        "fbversion_0198ee40-a111-7aaa-8000-000000000001",
        Vec::new(),
        "2026-07-29T00:00:00Z",
        root_manifest,
        FolderbaseVersionEntries::from_verified_producer(bindings, tombstones, exclusions),
    );

    let version =
        FolderbaseVersion::from_verified_parts(parts).expect("producer parts validate completely");
    let mut encoded = Vec::new();
    version
        .encode_bounded(&mut encoded)
        .expect("controlled encoding");
    let decoded =
        FolderbaseVersion::decode_bounded(encoded.as_slice()).expect("public bounded decode");

    assert_eq!(decoded.folderbase_id(), version.folderbase_id());
    assert_eq!(decoded.version_id(), version.version_id());
    assert_eq!(
        decoded.canonical_digest().expect("decoded digest"),
        version.canonical_digest().expect("producer digest")
    );
}

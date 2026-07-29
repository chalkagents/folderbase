use std::fs;

use folderbase_core::{
    FolderbaseRootMarker, MAX_FOLDERBASE_MANIFEST_BYTES, ROOT_INSTANCE_FORMAT_V1,
    RootAttestationError, attest_folderbase_root,
};
use tempfile::{TempDir, tempdir};

const FOLDERBASE_ID: &str = "folderbase_019f9b75-4f42-7f65-a012-2bfecdd8c473";
const MANIFEST: &[u8] = br#"{
  "protocol_version": "0.2.0+attestation",
  "folderbase": {
    "id": "folderbase_019f9b75-4f42-7f65-a012-2bfecdd8c473"
  }
}
"#;

fn root_with_manifest(manifest: &[u8]) -> TempDir {
    let root = tempdir().expect("temporary root");
    fs::create_dir(root.path().join(".folderbase")).expect("state directory");
    fs::write(root.path().join(".folderbase/manifest.json"), manifest).expect("manifest");
    fs::write(root.path().join("FOLDERBASE.md"), "# Folderbase\n").expect("entry");
    root
}

#[test]
fn attests_exact_manifest_bytes_and_one_physical_root_instance() {
    let root = root_with_manifest(MANIFEST);

    let first = attest_folderbase_root(root.path()).expect("valid exact root");
    let second = attest_folderbase_root(root.path()).expect("stable repeated receipt");

    assert_eq!(first.root, root.path());
    assert_eq!(first.folderbase_id, FOLDERBASE_ID);
    assert_eq!(first.protocol_version, "0.2.0+attestation");
    assert_eq!(
        first.manifest_sha256,
        "29a1ad6f2d1c5591b35951a39bc38603728527f8be808510f080db1922c3f8be"
    );
    assert_eq!(first.root_instance_sha256.len(), 64);
    assert!(
        first
            .root_instance_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    );
    assert_eq!(first, second);
    assert_eq!(
        ROOT_INSTANCE_FORMAT_V1,
        "folderbase-physical-root-instance-v1"
    );

    let physical_copy = root_with_manifest(MANIFEST);
    let copied = attest_folderbase_root(physical_copy.path()).expect("valid copied root");
    assert_eq!(copied.folderbase_id, first.folderbase_id);
    assert_eq!(copied.protocol_version, first.protocol_version);
    assert_eq!(copied.manifest_sha256, first.manifest_sha256);
    assert_ne!(copied.root_instance_sha256, first.root_instance_sha256);

    assert_eq!(
        fs::read_dir(root.path().join(".folderbase"))
            .expect("state listing")
            .count(),
        1,
        "attestation must not write state"
    );
}

#[test]
fn rejects_duplicate_object_keys_at_every_json_depth() {
    let duplicate_manifests = [
        br#"{
          "protocol_version": "0.2.0",
          "protocol_version": "0.3.0",
          "folderbase": {"id": "folderbase_019f9b75-4f42-7f65-a012-2bfecdd8c473"}
        }"#
        .as_slice(),
        br#"{
          "protocol_version": "0.2.0",
          "folderbase": {
            "id": "folderbase_019f9b75-4f42-7f65-a012-2bfecdd8c473",
            "id": "folderbase_019f9b75-4f42-7f65-a012-2bfecdd8c474"
          }
        }"#
        .as_slice(),
        br#"{
          "protocol_version": "0.2.0",
          "folderbase": {"id": "folderbase_019f9b75-4f42-7f65-a012-2bfecdd8c473"},
          "extensions": [{"nested": {"mode": true, "mode": false}}]
        }"#
        .as_slice(),
    ];

    for manifest in duplicate_manifests {
        let root = root_with_manifest(manifest);
        assert!(matches!(
            attest_folderbase_root(root.path()),
            Err(RootAttestationError::ManifestDuplicateField)
        ));
    }
}

#[test]
fn exposes_stable_kiss_error_names_and_codes() {
    let cases = [
        (
            RootAttestationError::ManifestInvalidJson,
            "manifest_invalid_json",
        ),
        (
            RootAttestationError::ManifestDuplicateField,
            "manifest_duplicate_field",
        ),
        (
            RootAttestationError::RootChangedDuringAttestation,
            "root_changed_during_attestation",
        ),
    ];

    for (error, expected) in cases {
        assert_eq!(error.code(), expected);
    }
}

#[test]
fn classifies_root_failures_without_collapsing_them() {
    let missing_parent = tempdir().expect("missing parent");
    let missing = missing_parent.path().join("missing");
    assert!(matches!(
        attest_folderbase_root(&missing),
        Err(RootAttestationError::RootNotFound { root }) if root == missing
    ));

    let regular_file_parent = tempdir().expect("regular file parent");
    let regular_file = regular_file_parent.path().join("not-a-directory");
    fs::write(&regular_file, b"file").expect("regular file");
    assert!(matches!(
        attest_folderbase_root(&regular_file),
        Err(RootAttestationError::RootNotDirectory { root }) if root == regular_file
    ));
}

#[cfg(unix)]
#[test]
fn rejects_a_symlink_root_and_linked_markers_by_name() {
    use std::os::unix::fs::symlink;

    let target = root_with_manifest(MANIFEST);
    let links = tempdir().expect("link parent");
    let root_link = links.path().join("root");
    symlink(target.path(), &root_link).expect("root symlink");
    assert!(matches!(
        attest_folderbase_root(&root_link),
        Err(RootAttestationError::RootSymlink { root }) if root == root_link
    ));

    let state_link_root = tempdir().expect("state link root");
    symlink(target.path().join(".folderbase"), state_link_root.path().join(".folderbase"))
        .expect("state symlink");
    fs::write(state_link_root.path().join("FOLDERBASE.md"), b"# Entry\n").expect("entry");
    assert!(matches!(
        attest_folderbase_root(state_link_root.path()),
        Err(RootAttestationError::MarkerSymlink {
            marker: FolderbaseRootMarker::StateDirectory
        })
    ));

    let manifest_link_root = tempdir().expect("manifest link root");
    fs::create_dir(manifest_link_root.path().join(".folderbase")).expect("state");
    symlink(
        target.path().join(".folderbase/manifest.json"),
        manifest_link_root.path().join(".folderbase/manifest.json"),
    )
    .expect("manifest symlink");
    fs::write(manifest_link_root.path().join("FOLDERBASE.md"), b"# Entry\n").expect("entry");
    assert!(matches!(
        attest_folderbase_root(manifest_link_root.path()),
        Err(RootAttestationError::MarkerSymlink {
            marker: FolderbaseRootMarker::Manifest
        })
    ));

    let entry_link_root = tempdir().expect("entry link root");
    fs::create_dir(entry_link_root.path().join(".folderbase")).expect("state");
    fs::write(
        entry_link_root.path().join(".folderbase/manifest.json"),
        MANIFEST,
    )
    .expect("manifest");
    symlink(
        target.path().join("FOLDERBASE.md"),
        entry_link_root.path().join("FOLDERBASE.md"),
    )
    .expect("entry symlink");
    assert!(matches!(
        attest_folderbase_root(entry_link_root.path()),
        Err(RootAttestationError::MarkerSymlink {
            marker: FolderbaseRootMarker::Entry
        })
    ));
}

#[test]
fn classifies_missing_and_wrong_type_markers() {
    let missing_state = tempdir().expect("missing state root");
    assert!(matches!(
        attest_folderbase_root(missing_state.path()),
        Err(RootAttestationError::MarkerMissing {
            marker: FolderbaseRootMarker::StateDirectory
        })
    ));

    let wrong_state = tempdir().expect("wrong state root");
    fs::write(wrong_state.path().join(".folderbase"), b"not a directory").expect("state file");
    assert!(matches!(
        attest_folderbase_root(wrong_state.path()),
        Err(RootAttestationError::MarkerWrongType {
            marker: FolderbaseRootMarker::StateDirectory
        })
    ));

    let missing_manifest = tempdir().expect("missing manifest root");
    fs::create_dir(missing_manifest.path().join(".folderbase")).expect("state");
    assert!(matches!(
        attest_folderbase_root(missing_manifest.path()),
        Err(RootAttestationError::MarkerMissing {
            marker: FolderbaseRootMarker::Manifest
        })
    ));

    let wrong_manifest = tempdir().expect("wrong manifest root");
    fs::create_dir_all(wrong_manifest.path().join(".folderbase/manifest.json"))
        .expect("manifest directory");
    assert!(matches!(
        attest_folderbase_root(wrong_manifest.path()),
        Err(RootAttestationError::MarkerWrongType {
            marker: FolderbaseRootMarker::Manifest
        })
    ));

    let missing_entry = root_with_manifest(MANIFEST);
    fs::remove_file(missing_entry.path().join("FOLDERBASE.md")).expect("remove entry");
    assert!(matches!(
        attest_folderbase_root(missing_entry.path()),
        Err(RootAttestationError::MarkerMissing {
            marker: FolderbaseRootMarker::Entry
        })
    ));

    let wrong_entry = root_with_manifest(MANIFEST);
    fs::remove_file(wrong_entry.path().join("FOLDERBASE.md")).expect("remove entry");
    fs::create_dir(wrong_entry.path().join("FOLDERBASE.md")).expect("entry directory");
    assert!(matches!(
        attest_folderbase_root(wrong_entry.path()),
        Err(RootAttestationError::MarkerWrongType {
            marker: FolderbaseRootMarker::Entry
        })
    ));
}

#[test]
fn distinguishes_missing_manifest_fields_from_wrong_field_types() {
    let cases = [
        (
            br#"{"folderbase":{"id":"folderbase_019f9b75-4f42-7f65-a012-2bfecdd8c473"}}"#
                .as_slice(),
            "protocol_version",
            true,
        ),
        (
            br#"{"protocol_version":2,"folderbase":{"id":"folderbase_019f9b75-4f42-7f65-a012-2bfecdd8c473"}}"#
                .as_slice(),
            "protocol_version",
            false,
        ),
        (
            br#"{"protocol_version":"0.2.0","folderbase":{}}"#.as_slice(),
            "folderbase.id",
            true,
        ),
        (
            br#"{"protocol_version":"0.2.0","folderbase":{"id":7}}"#.as_slice(),
            "folderbase.id",
            false,
        ),
    ];

    for (manifest, expected_field, missing) in cases {
        let root = root_with_manifest(manifest);
        let result = attest_folderbase_root(root.path());
        if missing {
            assert!(matches!(
                result,
                Err(RootAttestationError::ManifestFieldMissing { field })
                    if field == expected_field
            ));
        } else {
            assert!(matches!(
                result,
                Err(RootAttestationError::ManifestFieldWrongType { field })
                    if field == expected_field
            ));
        }
    }
}

#[test]
fn applies_the_public_manifest_byte_bound_before_json_parsing() {
    assert_eq!(MAX_FOLDERBASE_MANIFEST_BYTES, 16 * 1024 * 1024);
    let root = root_with_manifest(MANIFEST);
    let manifest = fs::OpenOptions::new()
        .write(true)
        .open(root.path().join(".folderbase/manifest.json"))
        .expect("open manifest");
    manifest
        .set_len(MAX_FOLDERBASE_MANIFEST_BYTES + 1)
        .expect("oversized sparse manifest");

    assert!(matches!(
        attest_folderbase_root(root.path()),
        Err(RootAttestationError::ManifestTooLarge {
            maximum_bytes: MAX_FOLDERBASE_MANIFEST_BYTES
        })
    ));
}

use std::{fs, path::Path};

use folderbase_core::{
    FolderbaseRootAttestation, FolderbaseRootMarker, MAX_FOLDERBASE_MANIFEST_BYTES,
    ROOT_INSTANCE_FORMAT_V1, ROOT_INSTANCE_FORMAT_V2, RootAttestationError, attest_folderbase_root,
};
use sha2::{Digest, Sha256};
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
    write_root(root.path(), manifest);
    root
}

fn write_root(root: &Path, manifest: &[u8]) {
    fs::create_dir_all(root.join(".folderbase")).expect("state directory");
    fs::write(root.join(".folderbase/manifest.json"), manifest).expect("manifest");
    fs::write(root.join("FOLDERBASE.md"), "# Folderbase\n").expect("entry");
}

fn expected_current_physical_digest(root: &Path) -> String {
    let mut digest = Sha256::new();

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        digest.update(b"folderbase-physical-root-instance-v1\0");
        let metadata = fs::metadata(root).expect("root metadata");
        digest.update(b"unix\0");
        digest.update(metadata.dev().to_be_bytes());
        digest.update(metadata.ino().to_be_bytes());
    }

    #[cfg(windows)]
    {
        use std::{
            mem::size_of,
            os::windows::{fs::OpenOptionsExt, io::AsRawHandle},
        };
        use windows_sys::Win32::{
            Foundation::HANDLE,
            Storage::FileSystem::{
                FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_ID_INFO,
                FILE_SHARE_READ, FILE_SHARE_WRITE, FileIdInfo, GetFileInformationByHandleEx,
            },
        };

        let root_file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .open(root)
            .expect("open physical root");
        let mut information = FILE_ID_INFO::default();
        assert_ne!(
            unsafe {
                GetFileInformationByHandleEx(
                    root_file.as_raw_handle() as HANDLE,
                    FileIdInfo,
                    (&raw mut information).cast(),
                    size_of::<FILE_ID_INFO>() as u32,
                )
            },
            0,
            "query full FILE_ID_INFO: {}",
            std::io::Error::last_os_error()
        );
        digest.update(b"folderbase-physical-root-instance-v2\0");
        digest.update(b"windows\0");
        digest.update(information.VolumeSerialNumber.to_be_bytes());
        digest.update(information.FileId.Identifier);
    }

    format!("{:x}", digest.finalize())
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
    assert_eq!(
        ROOT_INSTANCE_FORMAT_V2,
        "folderbase-physical-root-instance-v2"
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
fn physical_root_instance_matches_the_independent_platform_encoding() {
    let root = root_with_manifest(MANIFEST);
    let receipt = attest_folderbase_root(root.path()).expect("attested root");

    assert_eq!(
        receipt.root_instance_sha256,
        expected_current_physical_digest(root.path())
    );
}

#[test]
fn physical_root_instance_survives_rename_but_changes_for_same_path_replacement() {
    let parent = tempdir().expect("parent");
    let original = parent.path().join("workspace");
    write_root(&original, MANIFEST);
    let before_rename = attest_folderbase_root(&original).expect("original");

    let renamed = parent.path().join("renamed-workspace");
    fs::rename(&original, &renamed).expect("rename root");
    let after_rename = attest_folderbase_root(&renamed).expect("renamed");
    assert_eq!(
        before_rename.root_instance_sha256,
        after_rename.root_instance_sha256
    );
    assert_ne!(before_rename.root, after_rename.root);

    let displaced = parent.path().join("displaced-workspace");
    fs::rename(&renamed, &displaced).expect("displace original root");
    write_root(&renamed, MANIFEST);
    let replacement = attest_folderbase_root(&renamed).expect("same-path replacement");
    assert_eq!(replacement.folderbase_id, after_rename.folderbase_id);
    assert_eq!(replacement.manifest_sha256, after_rename.manifest_sha256);
    assert_ne!(
        replacement.root_instance_sha256,
        after_rename.root_instance_sha256
    );
}

#[cfg(unix)]
#[test]
fn public_receipt_serializes_a_non_utf8_root_as_display_only_text() {
    use std::{ffi::OsString, os::unix::ffi::OsStringExt, path::PathBuf};

    let root = PathBuf::from(OsString::from_vec(b"/tmp/folderbase-\xff-root".to_vec()));
    let receipt = FolderbaseRootAttestation {
        root: root.clone(),
        folderbase_id: FOLDERBASE_ID.to_owned(),
        protocol_version: "0.2.0".to_owned(),
        manifest_sha256: "1".repeat(64),
        root_instance_sha256: "2".repeat(64),
    };

    let value = serde_json::to_value(receipt).expect("display-only receipt must serialize");
    assert_eq!(value["root"], root.to_string_lossy().as_ref());
    assert_eq!(value.as_object().expect("flat receipt").len(), 5);
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
    symlink(
        target.path().join(".folderbase"),
        state_link_root.path().join(".folderbase"),
    )
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
    fs::write(
        manifest_link_root.path().join("FOLDERBASE.md"),
        b"# Entry\n",
    )
    .expect("entry");
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

#[cfg(windows)]
#[test]
fn rejects_windows_symlink_and_reparse_markers_without_skipping() {
    use std::os::windows::fs::{symlink_dir, symlink_file};

    let target = root_with_manifest(MANIFEST);
    let links = tempdir().expect("link parent");
    let root_link = links.path().join("root");
    symlink_dir(target.path(), &root_link).expect("GitHub Windows runner can create dir symlink");
    assert!(matches!(
        attest_folderbase_root(&root_link),
        Err(RootAttestationError::RootSymlink { root }) if root == root_link
    ));

    let state_link_root = tempdir().expect("state link root");
    symlink_dir(
        target.path().join(".folderbase"),
        state_link_root.path().join(".folderbase"),
    )
    .expect("state directory symlink");
    fs::write(state_link_root.path().join("FOLDERBASE.md"), b"# Entry\n").expect("entry");
    assert!(matches!(
        attest_folderbase_root(state_link_root.path()),
        Err(RootAttestationError::MarkerSymlink {
            marker: FolderbaseRootMarker::StateDirectory
        })
    ));

    let manifest_link_root = tempdir().expect("manifest link root");
    fs::create_dir(manifest_link_root.path().join(".folderbase")).expect("state");
    symlink_file(
        target.path().join(".folderbase/manifest.json"),
        manifest_link_root.path().join(".folderbase/manifest.json"),
    )
    .expect("manifest file symlink");
    fs::write(
        manifest_link_root.path().join("FOLDERBASE.md"),
        b"# Entry\n",
    )
    .expect("entry");
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
    symlink_file(
        target.path().join("FOLDERBASE.md"),
        entry_link_root.path().join("FOLDERBASE.md"),
    )
    .expect("entry file symlink");
    assert!(matches!(
        attest_folderbase_root(entry_link_root.path()),
        Err(RootAttestationError::MarkerSymlink {
            marker: FolderbaseRootMarker::Entry
        })
    ));
}

#[cfg(windows)]
fn create_windows_junction_reparse_point(target: &Path, link: &Path) {
    use std::os::windows::fs::MetadataExt;

    let output = std::process::Command::new("cmd.exe")
        .args(["/D", "/C", "mklink", "/J"])
        .arg(link)
        .arg(target)
        .output()
        .expect("run mklink");
    assert!(
        output.status.success(),
        "mklink /J failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let metadata = fs::symlink_metadata(link).expect("junction metadata");
    assert!(
        metadata.file_attributes() & 0x0000_0400 != 0,
        "mklink /J must create a reparse point"
    );
}

#[cfg(windows)]
#[test]
fn rejects_junction_reparse_points_at_every_folderbase_marker() {
    let target = root_with_manifest(MANIFEST);
    let links = tempdir().expect("junction parent");
    let root_junction = links.path().join("root");
    create_windows_junction_reparse_point(target.path(), &root_junction);
    assert!(matches!(
        attest_folderbase_root(&root_junction),
        Err(RootAttestationError::RootSymlink { root }) if root == root_junction
    ));

    let state_junction_root = tempdir().expect("state junction root");
    create_windows_junction_reparse_point(
        &target.path().join(".folderbase"),
        &state_junction_root.path().join(".folderbase"),
    );
    fs::write(
        state_junction_root.path().join("FOLDERBASE.md"),
        b"# Entry\n",
    )
    .expect("entry");
    assert!(matches!(
        attest_folderbase_root(state_junction_root.path()),
        Err(RootAttestationError::MarkerSymlink {
            marker: FolderbaseRootMarker::StateDirectory
        })
    ));

    let directory_target = tempdir().expect("directory target");
    let manifest_junction_root = tempdir().expect("manifest junction root");
    fs::create_dir(manifest_junction_root.path().join(".folderbase")).expect("state");
    create_windows_junction_reparse_point(
        directory_target.path(),
        &manifest_junction_root
            .path()
            .join(".folderbase")
            .join("manifest.json"),
    );
    fs::write(
        manifest_junction_root.path().join("FOLDERBASE.md"),
        b"# Entry\n",
    )
    .expect("entry");
    assert!(matches!(
        attest_folderbase_root(manifest_junction_root.path()),
        Err(RootAttestationError::MarkerSymlink {
            marker: FolderbaseRootMarker::Manifest
        })
    ));

    let entry_junction_root = tempdir().expect("entry junction root");
    fs::create_dir(entry_junction_root.path().join(".folderbase")).expect("state");
    fs::write(
        entry_junction_root.path().join(".folderbase/manifest.json"),
        MANIFEST,
    )
    .expect("manifest");
    create_windows_junction_reparse_point(
        directory_target.path(),
        &entry_junction_root.path().join("FOLDERBASE.md"),
    );
    assert!(matches!(
        attest_folderbase_root(entry_junction_root.path()),
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

#[test]
fn rejects_malformed_json_noncanonical_ids_and_invalid_semver() {
    let malformed = root_with_manifest(br#"{"protocol_version":"0.2.0""#);
    assert!(matches!(
        attest_folderbase_root(malformed.path()),
        Err(RootAttestationError::ManifestInvalidJson)
    ));

    let invalid_ids = [
        "019f9b75-4f42-7f65-a012-2bfecdd8c473",
        "folderbase_019F9B75-4F42-7F65-A012-2BFECDD8C473",
        "folderbase_019f9b754f427f65a0122bfecdd8c473",
        "folderbase_not-a-uuid",
    ];
    for id in invalid_ids {
        let manifest = format!(r#"{{"protocol_version":"0.2.0","folderbase":{{"id":"{id}"}}}}"#);
        let root = root_with_manifest(manifest.as_bytes());
        assert!(matches!(
            attest_folderbase_root(root.path()),
            Err(RootAttestationError::InvalidFolderbaseId)
        ));
    }

    for version in ["v0.2.0", "0.2", "01.2.3", "later"] {
        let manifest = format!(
            r#"{{"protocol_version":"{version}","folderbase":{{"id":"{FOLDERBASE_ID}"}}}}"#
        );
        let root = root_with_manifest(manifest.as_bytes());
        assert!(matches!(
            attest_folderbase_root(root.path()),
            Err(RootAttestationError::InvalidProtocolVersion)
        ));
    }
}

#[test]
fn exact_maximum_manifest_is_accepted_and_hashed_as_raw_bytes() {
    let mut manifest = MANIFEST.to_vec();
    manifest.resize(MAX_FOLDERBASE_MANIFEST_BYTES as usize, b' ');
    let root = root_with_manifest(&manifest);

    let attestation = attest_folderbase_root(root.path()).expect("exact maximum is allowed");
    assert_eq!(attestation.manifest_sha256.len(), 64);
}

#[test]
fn nested_roots_attest_independently_and_never_fall_back_to_an_ancestor() {
    let parent = root_with_manifest(MANIFEST);
    let valid_child = parent.path().join("Clients/Prosperna/Project 2");
    write_root(&valid_child, MANIFEST);

    let parent_receipt = attest_folderbase_root(parent.path()).expect("valid parent");
    let child_receipt = attest_folderbase_root(&valid_child).expect("valid exact child");
    assert_eq!(parent_receipt.folderbase_id, child_receipt.folderbase_id);
    assert_ne!(
        parent_receipt.root_instance_sha256,
        child_receipt.root_instance_sha256
    );
    assert_eq!(child_receipt.root, valid_child);

    let invalid_child = parent.path().join("Clients/Prosperna/Broken");
    fs::create_dir_all(invalid_child.join(".folderbase")).expect("partial child marker");
    fs::write(invalid_child.join("FOLDERBASE.md"), b"# Broken\n").expect("partial child entry");
    assert!(matches!(
        attest_folderbase_root(&invalid_child),
        Err(RootAttestationError::MarkerMissing {
            marker: FolderbaseRootMarker::Manifest
        })
    ));
    assert!(
        attest_folderbase_root(parent.path()).is_ok(),
        "the invalid child does not invalidate or substitute its parent"
    );
}

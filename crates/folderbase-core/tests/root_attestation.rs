use std::fs;

use folderbase_core::{
    ROOT_INSTANCE_FORMAT_V1, RootAttestationError, attest_folderbase_root,
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
            Err(RootAttestationError::DuplicateManifestKey)
        ));
    }
}

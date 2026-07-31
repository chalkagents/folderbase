use std::{fs, io::Cursor, path::PathBuf};

use folderbase_core::folderbase_version::FolderbaseVersion;

fn conformance_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../protocol/conformance/folderbase-version-0.5/valid")
}

#[test]
fn rust_runtime_validates_and_digests_both_protocol_05_vectors() {
    let root = conformance_root();
    for stem in ["minimal-ordinary-v1", "optional-root-files-v1"] {
        let fixture = root.join(format!("{stem}.json"));
        let sidecar = root.join(format!("{stem}.sha256"));
        let version = FolderbaseVersion::decode_bounded(Cursor::new(
            fs::read(&fixture).expect("protocol 0.5 conformance fixture"),
        ))
        .expect("Rust runtime validates protocol 0.5 fixture");
        let expected = fs::read_to_string(&sidecar).expect("independent digest sidecar");

        assert_eq!(version.protocol_version(), "0.5");
        assert_eq!(
            version.canonical_digest().expect("Rust canonical digest"),
            expected.trim(),
            "{stem} must match its independently generated sidecar"
        );
    }
}

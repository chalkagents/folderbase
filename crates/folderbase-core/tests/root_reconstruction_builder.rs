use std::{collections::BTreeMap, io::Cursor};

use folderbase_core::{
    root_reconstruction::{
        ManifestInput, RetainedReconstructionDestination, RetainedReconstructionPackage,
        RootReconstructionObjectAssociation, RootReconstructionOperation,
        RootReconstructionTombstoneFidelity, build_root_reconstruction_package,
        execute_root_reconstruction, plan_retained_package,
    },
    transfer_manifest::{
        CHUNKING_ALGORITHM_V1, ChunkDescriptor, ChunkManifest, MANIFEST_FORMAT_V1,
        STANDARD_PROFILE_V1,
    },
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const FOLDERBASE_ID: &str = "folderbase_019f0000-0000-7000-8000-000000000001";
const VERSION_ID: &str = "fbversion_019f0000-0000-7000-8000-000000000001";

#[test]
fn public_builder_produces_the_mixed_opaque_package_consumed_by_core() {
    let root_manifest = serde_json::to_vec_pretty(&json!({
        "$schema": "https://folderbase.ai/protocol/0.5/folderbase.schema.json",
        "protocol_version": "0.5.0",
        "folderbase": {
            "id": FOLDERBASE_ID,
            "name": "Public builder mixed fixture",
            "kind": "project",
            "status": "active",
            "created_at": "2026-08-06T00:00:00Z"
        },
        "adapters": [],
        "policies": {
            "availability": "keep_local",
            "structural_changes": "approve",
            "archive": "manual",
            "cloud_sync": "disabled",
            "capture_ignore": {
                "format": "folderbase-capture-ignore-v1",
                "rules": []
            }
        }
    }))
    .expect("root manifest");
    let regular = vec![
        ("README.md", "010", b"# mixed fixture\n".to_vec(), false),
        (
            "archives/bundle.zip",
            "020",
            vec![0x50, 0x4b, 0x03, 0x04],
            false,
        ),
        ("data/empty.csv", "025", Vec::new(), false),
        (
            "data/table.csv",
            "030",
            b"name,value\nalpha,1\n".to_vec(),
            false,
        ),
        (
            "databases/state.sqlite",
            "040",
            b"SQLite format 3\0opaque".to_vec(),
            false,
        ),
        (
            "documents/Brief.pdf",
            "050",
            b"%PDF-1.7\n%%EOF\n".to_vec(),
            false,
        ),
        (
            "media/clip.mp4",
            "060",
            vec![0, 0, 0, 24, b'f', b't', b'y', b'p'],
            false,
        ),
        (
            "notes/Moved.md",
            "070",
            b"same immutable bytes after a move\n".to_vec(),
            false,
        ),
        (
            "office/Proposal.docx",
            "080",
            vec![0x50, 0x4b, 0x03, 0x04, b'd', b'o', b'c', b'x'],
            false,
        ),
        (
            "opaque/unknown.bin",
            "090",
            vec![0x00, 0xff, 0x7f, 0x42],
            false,
        ),
        (
            "repo/.git/HEAD",
            "0a0",
            b"ref: refs/heads/main\n".to_vec(),
            false,
        ),
        (
            "scripts/run.sh",
            "0b0",
            b"#!/bin/sh\nprintf '%s\\n' reconstructed\n".to_vec(),
            true,
        ),
    ];
    let deleted = (
        "deleted/approved-proposal.docx",
        "0c0",
        vec![0x50, 0x4b, 0x03, 0x04, b'o', b'l', b'd'],
        true,
    );
    let directories = [
        ("archives", "101"),
        ("data", "102"),
        ("databases", "103"),
        ("documents", "104"),
        ("empty", "105"),
        ("links", "106"),
        ("media", "107"),
        ("notes", "108"),
        ("office", "109"),
        ("opaque", "10a"),
        ("repo", "10b"),
        ("repo/.git", "10c"),
        ("scripts", "10d"),
    ];

    let mut bindings = directories
        .iter()
        .map(|(path, suffix)| {
            json!({
                "path": path,
                "object_id": protocol_id("obj_", suffix, ""),
                "lifecycle": "live",
                "kind": "directory"
            })
        })
        .collect::<Vec<_>>();
    let mut associations = Vec::new();
    let mut manifests = BTreeMap::new();
    let mut chunks = BTreeMap::new();
    let root_object_version_id = protocol_id("version_", "001", "");
    add_object(
        &mut associations,
        &mut manifests,
        &mut chunks,
        root_object_version_id.clone(),
        &root_manifest,
    );
    for (path, suffix, bytes, executable) in &regular {
        let object_id = protocol_id("obj_", suffix, "");
        let object_version_id = protocol_id("version_", suffix, "1");
        bindings.push(json!({
            "path": path,
            "object_id": object_id,
            "lifecycle": "live",
            "kind": "regular_file",
            "object_version_id": object_version_id,
            "content_sha256": sha256(bytes),
            "bytes": bytes.len(),
            "executable": executable
        }));
        add_object(
            &mut associations,
            &mut manifests,
            &mut chunks,
            object_version_id,
            bytes,
        );
    }
    let moved_object_id = protocol_id("obj_", "070", "");
    let moved_version_id = protocol_id("version_", "070", "1");
    let deleted_object_id = protocol_id("obj_", deleted.1, "");
    let deleted_version_id = protocol_id("version_", deleted.1, "1");
    add_object(
        &mut associations,
        &mut manifests,
        &mut chunks,
        deleted_version_id.clone(),
        &deleted.2,
    );
    bindings.push(json!({
        "path": "links/brief-link",
        "object_id": protocol_id("obj_", "0d0", ""),
        "lifecycle": "live",
        "kind": "symlink",
        "object_version_id": protocol_id("version_", "0d0", "1"),
        "target": "../documents/Brief.pdf",
        "target_safety": "relative-within-folderbase"
    }));
    bindings.sort_by(|left, right| json_path(left).as_bytes().cmp(json_path(right).as_bytes()));
    associations.sort_by(|left, right| {
        left.object_version_id()
            .as_bytes()
            .cmp(right.object_version_id().as_bytes())
    });

    let version = serde_json::to_vec(&json!({
        "format": "folderbase-version-v1",
        "protocol_version": "0.5",
        "folderbase_id": FOLDERBASE_ID,
        "version_id": VERSION_ID,
        "parents": [],
        "created_at": "2026-08-06T00:00:00Z",
        "path_policy": {
            "format": "folderbase-portable-path-v1",
            "normalization": "NFC",
            "normalization_unicode_version": "17.0.0",
            "case_folding": "full-default",
            "case_folding_unicode_version": "9.0.0"
        },
        "root_manifest": {
            "path": ".folderbase/manifest.json",
            "object_version_id": root_object_version_id,
            "content_sha256": sha256(&root_manifest),
            "bytes": root_manifest.len()
        },
        "bindings": bindings,
        "tombstones": [
            {
                "path": "archive/Moved.md",
                "object_id": moved_object_id,
                "lifecycle": "deleted",
                "deleted_kind": "regular_file",
                "last_object_version_id": moved_version_id
            },
            {
                "path": deleted.0,
                "object_id": deleted_object_id,
                "lifecycle": "deleted",
                "deleted_kind": "regular_file",
                "last_object_version_id": deleted_version_id
            }
        ],
        "exclusions": [{
            "path": "vendors/nested",
            "kind": "nested_folderbase",
            "reason": "nested-folderbase-boundary"
        }]
    }))
    .expect("Version");
    let manifest_inputs = manifests
        .iter()
        .map(|(digest, encoded)| ManifestInput::new(digest.clone(), Cursor::new(encoded.clone())))
        .collect::<Vec<_>>();
    let package = build_root_reconstruction_package(
        version.as_slice(),
        associations,
        [
            RootReconstructionTombstoneFidelity::new(
                "archive/Moved.md",
                protocol_id("obj_", "070", ""),
                protocol_id("version_", "070", "1"),
                false,
            ),
            RootReconstructionTombstoneFidelity::new(
                deleted.0,
                protocol_id("obj_", deleted.1, ""),
                protocol_id("version_", deleted.1, "1"),
                deleted.3,
            ),
        ],
        manifest_inputs,
    )
    .expect("Core-built mixed package");

    assert_eq!(package.plan().version().bindings().len(), 26);
    assert_eq!(package.plan().version().exclusions().len(), 1);
    assert_eq!(package.plan().references().len(), 14);
    assert_eq!(package.plan().derived_symlinks().len(), 1);
    assert_eq!(package.plan().tombstone_fidelity().len(), 2);

    let temporary = tempfile::tempdir().expect("package parent");
    let source = temporary.path().join("package");
    std::fs::create_dir(&source).expect("package root");
    std::fs::create_dir(source.join("manifests")).expect("manifest directory");
    std::fs::create_dir(source.join("chunks")).expect("chunk directory");
    std::fs::write(source.join("index.json"), package.encoded_index()).expect("index");
    std::fs::write(source.join("version.json"), package.encoded_version()).expect("Version");
    for (digest, encoded) in manifests {
        std::fs::write(
            source.join("manifests").join(format!("{digest}.json")),
            encoded,
        )
        .expect("manifest");
    }
    for (digest, bytes) in chunks {
        std::fs::write(source.join("chunks").join(digest), bytes).expect("chunk");
    }
    let retained = RetainedReconstructionPackage::open(&source).expect("retained package");
    let consumed =
        plan_retained_package(&retained).expect("public consumer accepts builder output");
    assert_eq!(
        consumed.package_index_sha256(),
        package.plan().package_index_sha256()
    );

    let destination_parent = temporary.path().join("destinations");
    std::fs::create_dir(&destination_parent).expect("destination parent");
    let destination = RetainedReconstructionDestination::open(&destination_parent, "restored")
        .expect("retained destination");
    execute_root_reconstruction(
        RootReconstructionOperation::new(
            &consumed,
            "reconstruction_019f0000-0000-7000-8000-000000000099",
            consumed.package_index_sha256(),
        )
        .expect("reconstruction operation"),
        &retained,
        &destination,
    )
    .expect("mixed package reconstruction");
    let restored = destination_parent.join("restored");
    assert_eq!(
        std::fs::read(restored.join("README.md")).expect("Markdown bytes"),
        b"# mixed fixture\n"
    );
    assert_eq!(
        std::fs::read(restored.join("documents/Brief.pdf")).expect("PDF bytes"),
        b"%PDF-1.7\n%%EOF\n"
    );
    assert_eq!(
        std::fs::metadata(restored.join("data/empty.csv"))
            .expect("empty file")
            .len(),
        0
    );
    assert!(!restored.join(deleted.0).exists());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        assert_eq!(
            std::fs::read_link(restored.join("links/brief-link")).expect("safe symlink"),
            std::path::Path::new("../documents/Brief.pdf")
        );
        assert_ne!(
            std::fs::metadata(restored.join("scripts/run.sh"))
                .expect("executable")
                .permissions()
                .mode()
                & 0o111,
            0
        );
    }
}

fn add_object(
    associations: &mut Vec<RootReconstructionObjectAssociation>,
    manifests: &mut BTreeMap<String, Vec<u8>>,
    chunks: &mut BTreeMap<String, Vec<u8>>,
    object_version_id: String,
    bytes: &[u8],
) {
    let manifest = manifest(bytes);
    let digest = manifest.canonical_digest().expect("manifest digest");
    associations.push(RootReconstructionObjectAssociation::new(
        object_version_id,
        digest.clone(),
    ));
    manifests.insert(digest, serde_json::to_vec(&manifest).expect("manifest"));
    if !bytes.is_empty() {
        chunks.insert(sha256(bytes), bytes.to_vec());
    }
}

fn manifest(bytes: &[u8]) -> ChunkManifest {
    ChunkManifest {
        format: MANIFEST_FORMAT_V1.to_owned(),
        algorithm: CHUNKING_ALGORITHM_V1.to_owned(),
        profile: STANDARD_PROFILE_V1.to_owned(),
        minimum_chunk_bytes: 256 * 1024,
        average_chunk_bytes: 1024 * 1024,
        maximum_chunk_bytes: 4 * 1024 * 1024,
        object_sha256: sha256(bytes),
        object_bytes: bytes.len() as u64,
        chunks: if bytes.is_empty() {
            Vec::new()
        } else {
            vec![ChunkDescriptor {
                index: 0,
                offset: 0,
                bytes: bytes.len() as u64,
                sha256: sha256(bytes),
            }]
        },
    }
}

fn protocol_id(prefix: &str, suffix: &str, tail: &str) -> String {
    let identifier_suffix = format!("{suffix}{tail}");
    format!("{prefix}019f0000-0000-7000-8000-{identifier_suffix:0>12}")
}

fn json_path(value: &Value) -> &str {
    value["path"].as_str().expect("binding path")
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

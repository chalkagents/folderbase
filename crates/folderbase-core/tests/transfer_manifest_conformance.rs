use std::{
    fs,
    io::Cursor,
    path::{Path, PathBuf},
};

use folderbase_core::transfer_manifest::{
    ChunkDescriptor, ChunkManifest, MANIFEST_FORMAT_V1, MAX_CHUNK_DESCRIPTORS,
    MAX_ENCODED_MANIFEST_BYTES, MAX_OBJECT_BYTES, ManifestError, ManifestViolation,
};
use serde_json::Value;

const MANIFEST_SCHEMA: &str = "schemas/0.3/chunk-manifest.schema.json";

fn protocol_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../protocol")
}

fn read_json(relative: &str) -> Value {
    let path = protocol_root().join(relative);
    serde_json::from_slice(
        &fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display())),
    )
    .unwrap_or_else(|error| panic!("parse {}: {error}", path.display()))
}

fn schema_accepts(fixture_relative: &str) -> bool {
    let schema = read_json(MANIFEST_SCHEMA);
    let fixture = read_json(fixture_relative);
    jsonschema::draft202012::options()
        .should_validate_formats(true)
        .build(&schema)
        .unwrap_or_else(|error| panic!("compile {MANIFEST_SCHEMA}: {error}"))
        .is_valid(&fixture)
}

fn decode_fixture(relative: &str) -> Result<ChunkManifest, String> {
    let path = protocol_root().join(relative);
    let encoded =
        fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    ChunkManifest::decode_bounded(Cursor::new(encoded)).map_err(|error| error.to_string())
}

#[test]
fn public_chunk_manifest_schema_is_draft_2020_12() {
    let schema = read_json(MANIFEST_SCHEMA);

    assert_eq!(
        schema["$schema"],
        "https://json-schema.org/draft/2020-12/schema"
    );
    jsonschema::draft202012::options()
        .should_validate_formats(true)
        .build(&schema)
        .expect("compile canonical chunk manifest schema");
}

#[test]
fn published_positive_vectors_conform_to_the_schema() {
    let published = [
        "conformance/chunk-manifest/valid/empty-standard-v1.json",
        "conformance/chunk-manifest/valid/two-chunk-standard-v1.json",
        "conformance/chunk-manifest/valid/single-chunk-large-v1.json",
    ];
    for relative in published {
        assert!(schema_accepts(relative), "{relative} must conform");
    }

    let valid_directory = protocol_root().join("conformance/chunk-manifest/valid");
    let inventory = fs::read_dir(&valid_directory)
        .unwrap_or_else(|error| panic!("read {}: {error}", valid_directory.display()))
        .map(|entry| entry.expect("conformance directory entry").path())
        .collect::<Vec<_>>();
    assert_eq!(inventory.len(), 4, "unexpected valid-directory artifact");
    assert_eq!(
        inventory
            .iter()
            .filter(|path| path
                .extension()
                .is_some_and(|extension| extension == "json"))
            .count(),
        published.len(),
        "unexpected positive-vector inventory"
    );
    assert_eq!(
        inventory
            .iter()
            .filter(|path| path
                .extension()
                .is_some_and(|extension| extension == "sha256"))
            .count(),
        1,
        "unexpected canonical-digest inventory"
    );
}

#[test]
fn bounded_decoder_accepts_a_valid_public_vector() {
    let path = protocol_root().join("conformance/chunk-manifest/valid/two-chunk-standard-v1.json");
    let encoded =
        fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));

    let manifest = ChunkManifest::decode_bounded(Cursor::new(encoded))
        .expect("decode and validate canonical chunk manifest");

    assert_eq!(manifest.chunks.len(), 2);
    assert_eq!(manifest.object_bytes, 262_145);
}

#[test]
fn decoder_rejects_the_unknown_format_vector() {
    let path = protocol_root().join("conformance/chunk-manifest/invalid/unknown-format.json");
    let encoded =
        fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));

    assert!(ChunkManifest::decode_bounded(Cursor::new(encoded)).is_err());
}

#[test]
fn decoder_rejects_unknown_algorithm_profile_and_mismatched_parameters() {
    for relative in [
        "conformance/chunk-manifest/invalid/unknown-algorithm.json",
        "conformance/chunk-manifest/invalid/unknown-profile.json",
        "conformance/chunk-manifest/invalid/standard-profile-parameter-mismatch.json",
        "conformance/chunk-manifest/invalid/large-profile-parameter-mismatch.json",
    ] {
        assert!(
            decode_fixture(relative).is_err(),
            "{relative} must be rejected"
        );
    }
}

#[test]
fn decoder_rejects_unknown_fields_and_noncanonical_digests() {
    for relative in [
        "conformance/chunk-manifest/invalid/unknown-manifest-field.json",
        "conformance/chunk-manifest/invalid/unknown-descriptor-field.json",
        "conformance/chunk-manifest/invalid/uppercase-object-digest.json",
        "conformance/chunk-manifest/invalid/nonhex-object-digest.json",
        "conformance/chunk-manifest/invalid/short-chunk-digest.json",
    ] {
        assert!(
            decode_fixture(relative).is_err(),
            "{relative} must be rejected"
        );
    }
}

#[test]
fn decoder_rejects_invalid_descriptor_topology_and_object_shape() {
    for relative in [
        "conformance/chunk-manifest/invalid/nonsequential-index.json",
        "conformance/chunk-manifest/invalid/offset-gap.json",
        "conformance/chunk-manifest/invalid/offset-overlap.json",
        "conformance/chunk-manifest/invalid/zero-length-chunk.json",
        "conformance/chunk-manifest/invalid/chunk-exceeds-profile-maximum.json",
        "conformance/chunk-manifest/invalid/nonfinal-chunk-below-minimum.json",
        "conformance/chunk-manifest/invalid/descriptor-arithmetic-overflow.json",
        "conformance/chunk-manifest/invalid/object-length-mismatch.json",
        "conformance/chunk-manifest/invalid/empty-object-wrong-digest.json",
        "conformance/chunk-manifest/invalid/empty-object-with-chunk.json",
        "conformance/chunk-manifest/invalid/nonempty-object-without-chunks.json",
        "conformance/chunk-manifest/invalid/object-exceeds-v1-maximum.json",
        "conformance/chunk-manifest/invalid/offset-exceeds-v1-maximum.json",
    ] {
        assert!(
            decode_fixture(relative).is_err(),
            "{relative} must be rejected"
        );
    }
}

#[test]
fn validation_rejects_descriptor_count_before_inspecting_descriptors() {
    let manifest = ChunkManifest {
        format: MANIFEST_FORMAT_V1.to_owned(),
        algorithm: "folderbase-cdc-v1+sha256".to_owned(),
        profile: "standard-v1".to_owned(),
        minimum_chunk_bytes: 262_144,
        average_chunk_bytes: 1_048_576,
        maximum_chunk_bytes: 4_194_304,
        object_sha256: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
            .to_owned(),
        object_bytes: 1,
        chunks: vec![
            ChunkDescriptor {
                index: 0,
                offset: 0,
                bytes: 0,
                sha256: String::new(),
            };
            MAX_CHUNK_DESCRIPTORS + 1
        ],
    };

    assert_eq!(
        manifest.validate(),
        Err(ManifestViolation::TooManyDescriptors {
            maximum: MAX_CHUNK_DESCRIPTORS
        })
    );
}

#[test]
fn validation_caps_v1_object_and_offset_identity_at_one_tib() {
    let digest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let maximum_chunk_bytes = 64 * 1024 * 1024_u64;
    let mut chunks = (0..(MAX_OBJECT_BYTES / maximum_chunk_bytes))
        .map(|index| ChunkDescriptor {
            index: index as u32,
            offset: index * maximum_chunk_bytes,
            bytes: maximum_chunk_bytes,
            sha256: digest.to_owned(),
        })
        .collect::<Vec<_>>();
    chunks.push(ChunkDescriptor {
        index: chunks.len() as u32,
        offset: MAX_OBJECT_BYTES,
        bytes: 1,
        sha256: digest.to_owned(),
    });
    let oversized = ChunkManifest {
        format: MANIFEST_FORMAT_V1.to_owned(),
        algorithm: "folderbase-cdc-v1+sha256".to_owned(),
        profile: "large-v1".to_owned(),
        minimum_chunk_bytes: 4_194_304,
        average_chunk_bytes: 16_777_216,
        maximum_chunk_bytes,
        object_sha256: digest.to_owned(),
        object_bytes: MAX_OBJECT_BYTES + 1,
        chunks,
    };
    assert_eq!(
        oversized.validate(),
        Err(ManifestViolation::ObjectTooLarge {
            maximum: MAX_OBJECT_BYTES
        })
    );

    let excessive_offset = ChunkManifest {
        format: MANIFEST_FORMAT_V1.to_owned(),
        algorithm: "folderbase-cdc-v1+sha256".to_owned(),
        profile: "large-v1".to_owned(),
        minimum_chunk_bytes: 4_194_304,
        average_chunk_bytes: 16_777_216,
        maximum_chunk_bytes,
        object_sha256: digest.to_owned(),
        object_bytes: 1,
        chunks: vec![ChunkDescriptor {
            index: 0,
            offset: MAX_OBJECT_BYTES + 1,
            bytes: 1,
            sha256: digest.to_owned(),
        }],
    };
    assert_eq!(
        excessive_offset.validate(),
        Err(ManifestViolation::DescriptorOffsetTooLarge {
            index: 0,
            maximum: MAX_OBJECT_BYTES
        })
    );
}

#[test]
fn bounded_decoder_rejects_a_stream_larger_than_64_mib_without_length_metadata() {
    let error = ChunkManifest::decode_bounded(std::io::repeat(b' '))
        .expect_err("unbounded stream must stop at the protocol cap");

    assert!(matches!(
        error,
        ManifestError::EncodedManifestTooLarge {
            maximum_bytes: MAX_ENCODED_MANIFEST_BYTES
        }
    ));
}

#[test]
fn canonical_digest_matches_the_published_big_endian_vector() {
    let manifest = decode_fixture("conformance/chunk-manifest/valid/two-chunk-standard-v1.json")
        .expect("valid digest vector");
    let expected_path =
        protocol_root().join("conformance/chunk-manifest/valid/two-chunk-standard-v1.sha256");
    let expected = fs::read_to_string(&expected_path)
        .unwrap_or_else(|error| panic!("read {}: {error}", expected_path.display()));

    assert_eq!(
        manifest.canonical_digest().expect("canonical digest"),
        expected.trim()
    );
}

#[test]
fn schema_and_semantic_validation_have_explicit_conformance_roles() {
    for relative in [
        "conformance/chunk-manifest/invalid/unknown-format.json",
        "conformance/chunk-manifest/invalid/unknown-algorithm.json",
        "conformance/chunk-manifest/invalid/unknown-profile.json",
        "conformance/chunk-manifest/invalid/standard-profile-parameter-mismatch.json",
        "conformance/chunk-manifest/invalid/large-profile-parameter-mismatch.json",
        "conformance/chunk-manifest/invalid/unknown-manifest-field.json",
        "conformance/chunk-manifest/invalid/unknown-descriptor-field.json",
        "conformance/chunk-manifest/invalid/uppercase-object-digest.json",
        "conformance/chunk-manifest/invalid/nonhex-object-digest.json",
        "conformance/chunk-manifest/invalid/short-chunk-digest.json",
        "conformance/chunk-manifest/invalid/zero-length-chunk.json",
        "conformance/chunk-manifest/invalid/chunk-exceeds-profile-maximum.json",
        "conformance/chunk-manifest/invalid/empty-object-wrong-digest.json",
        "conformance/chunk-manifest/invalid/empty-object-with-chunk.json",
        "conformance/chunk-manifest/invalid/nonempty-object-without-chunks.json",
        "conformance/chunk-manifest/invalid/object-exceeds-v1-maximum.json",
        "conformance/chunk-manifest/invalid/offset-exceeds-v1-maximum.json",
        "conformance/chunk-manifest/invalid/descriptor-arithmetic-overflow.json",
    ] {
        assert!(!schema_accepts(relative), "{relative} must fail the schema");
    }

    for relative in [
        "conformance/chunk-manifest/invalid/nonsequential-index.json",
        "conformance/chunk-manifest/invalid/offset-gap.json",
        "conformance/chunk-manifest/invalid/offset-overlap.json",
        "conformance/chunk-manifest/invalid/nonfinal-chunk-below-minimum.json",
        "conformance/chunk-manifest/invalid/object-length-mismatch.json",
    ] {
        assert!(
            schema_accepts(relative),
            "{relative} must reach semantic validation"
        );
        assert!(
            decode_fixture(relative).is_err(),
            "{relative} must be rejected"
        );
    }
}

#[test]
fn every_published_negative_vector_fails_bounded_decode() {
    let invalid_directory = protocol_root().join("conformance/chunk-manifest/invalid");
    let mut vectors = fs::read_dir(&invalid_directory)
        .unwrap_or_else(|error| panic!("read {}: {error}", invalid_directory.display()))
        .map(|entry| entry.expect("conformance directory entry").path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .collect::<Vec<_>>();
    vectors.sort();

    assert_eq!(vectors.len(), 23, "unexpected negative-vector inventory");
    for path in vectors {
        let encoded =
            fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
        assert!(
            ChunkManifest::decode_bounded(Cursor::new(encoded)).is_err(),
            "{} must be rejected",
            path.display()
        );
    }
}

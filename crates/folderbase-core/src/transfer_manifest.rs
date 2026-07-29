//! Canonical, provider-neutral manifest for streaming immutable object bytes.
//!
//! This module is the portable `folderbase-chunk-manifest-v1` contract. The
//! legacy [`crate::chunk_transfer::ChunkManifest`] remains a distinct
//! small-buffer checkpoint shape and is never decoded here.

use std::io::Read;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const MAX_ENCODED_MANIFEST_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_CHUNK_DESCRIPTORS: usize = 262_144;
pub const MAX_OBJECT_BYTES: u64 = 1024 * 1024 * 1024 * 1024;
pub const MANIFEST_FORMAT_V1: &str = "folderbase-chunk-manifest-v1";
pub const CHUNKING_ALGORITHM_V1: &str = "folderbase-cdc-v1+sha256";
pub const STANDARD_PROFILE_V1: &str = "standard-v1";
pub const LARGE_PROFILE_V1: &str = "large-v1";
const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ProfileParameters {
    pub minimum_chunk_bytes: u64,
    pub average_chunk_bytes: u64,
    pub maximum_chunk_bytes: u64,
}

pub(crate) fn profile_parameters(profile: &str) -> Option<ProfileParameters> {
    match profile {
        STANDARD_PROFILE_V1 => Some(ProfileParameters {
            minimum_chunk_bytes: 256 * 1024,
            average_chunk_bytes: 1024 * 1024,
            maximum_chunk_bytes: 4 * 1024 * 1024,
        }),
        LARGE_PROFILE_V1 => Some(ProfileParameters {
            minimum_chunk_bytes: 4 * 1024 * 1024,
            average_chunk_bytes: 16 * 1024 * 1024,
            maximum_chunk_bytes: 64 * 1024 * 1024,
        }),
        _ => None,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ChunkManifest {
    pub format: String,
    pub algorithm: String,
    pub profile: String,
    #[serde(deserialize_with = "deserialize_chunk_size")]
    pub minimum_chunk_bytes: u64,
    #[serde(deserialize_with = "deserialize_chunk_size")]
    pub average_chunk_bytes: u64,
    #[serde(deserialize_with = "deserialize_chunk_size")]
    pub maximum_chunk_bytes: u64,
    pub object_sha256: String,
    #[serde(deserialize_with = "deserialize_object_size")]
    pub object_bytes: u64,
    pub chunks: Vec<ChunkDescriptor>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ChunkDescriptor {
    #[serde(deserialize_with = "deserialize_index")]
    pub index: u32,
    #[serde(deserialize_with = "deserialize_object_size")]
    pub offset: u64,
    #[serde(deserialize_with = "deserialize_chunk_size")]
    pub bytes: u64,
    pub sha256: String,
}

#[derive(Debug, thiserror::Error)]
pub enum ManifestError {
    #[error("encoded chunk manifest exceeds {maximum_bytes} bytes")]
    EncodedManifestTooLarge { maximum_bytes: u64 },

    #[error("chunk manifest is not valid JSON: {0}")]
    InvalidJson(#[from] serde_json::Error),

    #[error("chunk manifest violates the protocol: {0}")]
    InvalidManifest(#[from] ManifestViolation),
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ManifestViolation {
    #[error("unsupported manifest format")]
    UnknownFormat,

    #[error("unsupported chunking algorithm")]
    UnknownAlgorithm,

    #[error("unsupported chunking profile")]
    UnknownProfile,

    #[error("chunking parameters do not match the declared profile")]
    ProfileParameterMismatch,

    #[error("whole-object digest is not lowercase hexadecimal SHA-256")]
    InvalidObjectDigest,

    #[error("chunk {index} digest is not lowercase hexadecimal SHA-256")]
    InvalidChunkDigest { index: u32 },

    #[error("chunk manifest has more than {maximum} descriptors")]
    TooManyDescriptors { maximum: usize },

    #[error("whole-object length exceeds the v1 maximum of {maximum} bytes")]
    ObjectTooLarge { maximum: u64 },

    #[error("chunk descriptor at position {position} has index {actual}")]
    NonsequentialIndex { position: usize, actual: u32 },

    #[error("chunk {index} has zero length")]
    ZeroLengthChunk { index: u32 },

    #[error("chunk {index} exceeds the declared maximum size")]
    ChunkTooLarge { index: u32 },

    #[error("nonfinal chunk {index} is smaller than the declared minimum size")]
    NonfinalChunkTooSmall { index: u32 },

    #[error("chunk {index} offset exceeds the v1 maximum of {maximum} bytes")]
    DescriptorOffsetTooLarge { index: u32, maximum: u64 },

    #[error("chunk {index} begins at {actual}, not contiguous offset {expected}")]
    NoncontiguousOffset {
        index: u32,
        expected: u64,
        actual: u64,
    },

    #[error("chunk descriptor total {actual} differs from object length {expected}")]
    ObjectLengthMismatch { expected: u64, actual: u64 },

    #[error("empty object must have zero descriptors and the SHA-256 of empty bytes")]
    InvalidEmptyObject,
}

impl ChunkManifest {
    pub fn decode_bounded(mut reader: impl Read) -> Result<Self, ManifestError> {
        let mut encoded = Vec::new();
        reader
            .by_ref()
            .take(MAX_ENCODED_MANIFEST_BYTES + 1)
            .read_to_end(&mut encoded)
            .map_err(serde_json::Error::io)?;
        if encoded.len() as u64 > MAX_ENCODED_MANIFEST_BYTES {
            return Err(ManifestError::EncodedManifestTooLarge {
                maximum_bytes: MAX_ENCODED_MANIFEST_BYTES,
            });
        }
        let manifest: Self = serde_json::from_slice(&encoded)?;
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn validate(&self) -> Result<(), ManifestViolation> {
        if self.format != MANIFEST_FORMAT_V1 {
            return Err(ManifestViolation::UnknownFormat);
        }
        if self.algorithm != CHUNKING_ALGORITHM_V1 {
            return Err(ManifestViolation::UnknownAlgorithm);
        }
        let expected =
            profile_parameters(&self.profile).ok_or(ManifestViolation::UnknownProfile)?;
        if (
            self.minimum_chunk_bytes,
            self.average_chunk_bytes,
            self.maximum_chunk_bytes,
        ) != (
            expected.minimum_chunk_bytes,
            expected.average_chunk_bytes,
            expected.maximum_chunk_bytes,
        ) {
            return Err(ManifestViolation::ProfileParameterMismatch);
        }
        if !is_sha256(&self.object_sha256) {
            return Err(ManifestViolation::InvalidObjectDigest);
        }
        if self.chunks.len() > MAX_CHUNK_DESCRIPTORS {
            return Err(ManifestViolation::TooManyDescriptors {
                maximum: MAX_CHUNK_DESCRIPTORS,
            });
        }
        if self.object_bytes > MAX_OBJECT_BYTES {
            return Err(ManifestViolation::ObjectTooLarge {
                maximum: MAX_OBJECT_BYTES,
            });
        }

        let mut expected_offset = 0_u64;
        for (position, descriptor) in self.chunks.iter().enumerate() {
            if !is_sha256(&descriptor.sha256) {
                return Err(ManifestViolation::InvalidChunkDigest {
                    index: descriptor.index,
                });
            }
            if descriptor.index != position as u32 {
                return Err(ManifestViolation::NonsequentialIndex {
                    position,
                    actual: descriptor.index,
                });
            }
            if descriptor.bytes == 0 {
                return Err(ManifestViolation::ZeroLengthChunk {
                    index: descriptor.index,
                });
            }
            if descriptor.bytes > self.maximum_chunk_bytes {
                return Err(ManifestViolation::ChunkTooLarge {
                    index: descriptor.index,
                });
            }
            if position + 1 < self.chunks.len() && descriptor.bytes < self.minimum_chunk_bytes {
                return Err(ManifestViolation::NonfinalChunkTooSmall {
                    index: descriptor.index,
                });
            }
            if descriptor.offset > MAX_OBJECT_BYTES {
                return Err(ManifestViolation::DescriptorOffsetTooLarge {
                    index: descriptor.index,
                    maximum: MAX_OBJECT_BYTES,
                });
            }
            // Both operands are already capped at 1 TiB and 64 MiB, so this
            // addition is provably below u64::MAX.
            let end = descriptor.offset + descriptor.bytes;
            if descriptor.offset != expected_offset {
                return Err(ManifestViolation::NoncontiguousOffset {
                    index: descriptor.index,
                    expected: expected_offset,
                    actual: descriptor.offset,
                });
            }
            expected_offset = end;
        }
        if expected_offset != self.object_bytes {
            return Err(ManifestViolation::ObjectLengthMismatch {
                expected: self.object_bytes,
                actual: expected_offset,
            });
        }
        if self.object_bytes == 0 && (!self.chunks.is_empty() || self.object_sha256 != EMPTY_SHA256)
        {
            return Err(ManifestViolation::InvalidEmptyObject);
        }
        Ok(())
    }

    pub fn canonical_digest(&self) -> Result<String, ManifestViolation> {
        self.validate()?;

        let mut digest = Sha256::new();
        digest.update(MANIFEST_FORMAT_V1.as_bytes());
        digest.update([0]);
        update_identifier(&mut digest, &self.algorithm);
        update_identifier(&mut digest, &self.profile);
        digest.update(self.minimum_chunk_bytes.to_be_bytes());
        digest.update(self.average_chunk_bytes.to_be_bytes());
        digest.update(self.maximum_chunk_bytes.to_be_bytes());
        digest.update(decode_sha256(&self.object_sha256));
        digest.update(self.object_bytes.to_be_bytes());
        digest.update((self.chunks.len() as u32).to_be_bytes());
        for descriptor in &self.chunks {
            digest.update(descriptor.index.to_be_bytes());
            digest.update(descriptor.offset.to_be_bytes());
            digest.update(descriptor.bytes.to_be_bytes());
            digest.update(decode_sha256(&descriptor.sha256));
        }
        Ok(format!("{:x}", digest.finalize()))
    }
}

pub(crate) fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn update_identifier(digest: &mut Sha256, identifier: &str) {
    digest.update((identifier.len() as u32).to_be_bytes());
    digest.update(identifier.as_bytes());
}

fn decode_sha256(value: &str) -> [u8; 32] {
    let mut decoded = [0_u8; 32];
    for (destination, encoded) in decoded.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
        *destination = (hex_nibble(encoded[0]) << 4) | hex_nibble(encoded[1]);
    }
    decoded
}

fn hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => unreachable!("digest syntax is validated before canonical encoding"),
    }
}

fn deserialize_chunk_size<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_exact_unsigned(deserializer, 1, 64 * 1024 * 1024, "chunk byte count")
}

fn deserialize_object_size<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_exact_unsigned(
        deserializer,
        0,
        MAX_OBJECT_BYTES,
        "object byte count or offset",
    )
}

fn deserialize_index<'de, D>(deserializer: D) -> Result<u32, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = deserialize_exact_unsigned(deserializer, 0, u32::MAX as u64, "chunk index")?;
    Ok(value as u32)
}

fn deserialize_exact_unsigned<'de, D>(
    deserializer: D,
    minimum: u64,
    maximum: u64,
    label: &'static str,
) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let raw = Box::<serde_json::value::RawValue>::deserialize(deserializer)?;
    parse_exact_unsigned(raw.get())
        .filter(|value| (minimum..=maximum).contains(value))
        .ok_or_else(|| {
            serde::de::Error::custom(format!(
                "{label} must be an exact integer between {minimum} and {maximum}"
            ))
        })
}

fn parse_exact_unsigned(encoded: &str) -> Option<u64> {
    let (negative, unsigned) = match encoded.strip_prefix('-') {
        Some(unsigned) => (true, unsigned),
        None => (false, encoded),
    };
    let (coefficient, exponent) = unsigned
        .split_once(['e', 'E'])
        .map_or((unsigned, "0"), |parts| parts);
    let exponent = exponent.parse::<i64>().ok();
    let (integer, fraction) = coefficient
        .split_once('.')
        .map_or((coefficient, ""), |parts| parts);
    let digits = format!("{integer}{fraction}");
    let significant = digits.trim_start_matches('0');
    if significant.is_empty() {
        return Some(0);
    }
    if negative {
        return None;
    }

    let exponent = exponent?;
    let scale = exponent.checked_sub(fraction.len() as i64)?;
    let mut normalized = significant.to_owned();
    if scale >= 0 {
        let zero_count = usize::try_from(scale).ok()?;
        if normalized.len().checked_add(zero_count)? > 20 {
            return None;
        }
        normalized.extend(std::iter::repeat_n('0', zero_count));
    } else {
        let removed = usize::try_from(scale.unsigned_abs()).ok()?;
        if removed > normalized.len() {
            return None;
        }
        let retained = normalized.len() - removed;
        if !normalized.as_bytes()[retained..]
            .iter()
            .all(|byte| *byte == b'0')
        {
            return None;
        }
        normalized.truncate(retained);
        if normalized.is_empty() {
            return Some(0);
        }
    }
    normalized.parse().ok()
}

//! Process adapter for `folderbase.root-reconstruction@0.1.0`.
//!
//! The adapter owns only the closed request/result transport and error/exit
//! taxonomy. Package authority, planning, verification, restart, and
//! publication remain inside Core's retained-capability surface.

use std::{
    io::{Read, Write},
    path::PathBuf,
};

use folderbase_core::root_reconstruction::{
    ReconstructionReferenceRole, RetainedReconstructionDestination, RetainedReconstructionPackage,
    RootReconstructionError, RootReconstructionOperation, RootReconstructionPhase,
    execute_root_reconstruction_with_phase_callback, plan_retained_package,
};
use serde::{Deserialize, Serialize};

const EXIT_SUCCESS: u8 = 0;
const EXIT_ATTENTION: u8 = 1;
const EXIT_OPERATIONAL_ERROR: u8 = 2;
const MAX_REQUEST_BYTES: u64 = 64 * 1024;
const MAX_OUTPUT_BYTES: usize = 64 * 1024;
const MAX_MESSAGE_SCALARS: usize = 4_096;
const CRASH_AFTER_ENV: &str = "FOLDERBASE_ROOT_RECONSTRUCTION_CONFORMANCE_CRASH_AFTER";

pub(crate) struct RootReconstructionTransport {
    pub(crate) exit_code: u8,
    pub(crate) stdout: Vec<u8>,
    pub(crate) stderr: Vec<u8>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RootReconstructionRequest {
    format: String,
    operation_id: String,
    package_index_sha256: String,
}

struct RequestContext {
    operation_id: String,
    request_sha256: String,
    package_index_sha256: String,
}

#[derive(Serialize)]
struct ErrorDetail {
    code: &'static str,
    message: String,
}

#[derive(Serialize)]
struct ErrorDocument<'a> {
    format: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    operation_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_sha256: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    package_index_sha256: Option<&'a str>,
    error: ErrorDetail,
}

pub(crate) fn execute(
    source: PathBuf,
    destination: PathBuf,
    input: impl Read,
) -> RootReconstructionTransport {
    let request = match read_request(input) {
        Ok(request) => request,
        Err(message) => return error_transport("invalid_request", message, None),
    };
    if request.format != "folderbase-root-reconstruction-request-v1" {
        return error_transport(
            "invalid_request",
            "request format is unsupported".to_owned(),
            None,
        );
    }
    if !source.is_absolute() {
        return error_transport(
            "unsafe_package",
            "reconstruction source must be an absolute path".to_owned(),
            None,
        );
    }
    if !destination.is_absolute() {
        return error_transport(
            "unsafe_destination",
            "reconstruction destination must be an absolute path".to_owned(),
            None,
        );
    }

    let package = match RetainedReconstructionPackage::open(&source) {
        Ok(package) => package,
        Err(error) => return core_error_transport(error, None),
    };
    let plan = match plan_retained_package(&package) {
        Ok(plan) => plan,
        Err(error) => return core_error_transport(error, None),
    };
    let operation = match RootReconstructionOperation::new(
        &plan,
        request.operation_id.clone(),
        request.package_index_sha256.clone(),
    ) {
        Ok(operation) => operation,
        Err(error) => return core_error_transport(error, None),
    };
    let context = RequestContext {
        operation_id: request.operation_id,
        request_sha256: operation.request_sha256().to_owned(),
        package_index_sha256: request.package_index_sha256,
    };

    let Some(name) = destination.file_name() else {
        return error_transport(
            "unsafe_destination",
            "destination must name one absent child".to_owned(),
            Some(&context),
        );
    };
    let parent = destination
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    let destination = match RetainedReconstructionDestination::open(parent, name) {
        Ok(destination) => destination,
        Err(error) => return core_error_transport(error, Some(&context)),
    };

    let crash_after = std::env::var(CRASH_AFTER_ENV).ok();
    match execute_root_reconstruction_with_phase_callback(
        operation,
        &package,
        &destination,
        |phase| {
            if crash_after
                .as_deref()
                .is_some_and(|requested| Some(requested) == public_crash_phase(phase))
            {
                std::process::exit(86);
            }
        },
    ) {
        Ok(result) => {
            let verified_object_count = plan.externally_materialized_object_count();
            let version_authenticated_object_count = plan
                .references()
                .iter()
                .filter(|reference| {
                    reference.roles().iter().any(|role| {
                        matches!(
                            role,
                            ReconstructionReferenceRole::RootManifest
                                | ReconstructionReferenceRole::LiveRegularFile
                        )
                    })
                })
                .count();
            let retained_tombstone_object_count = plan
                .references()
                .iter()
                .filter(|reference| {
                    reference
                        .roles()
                        .contains(&ReconstructionReferenceRole::RetainedTombstone)
                })
                .count();
            success_transport(&serde_json::json!({
                "format": "folderbase-root-reconstruction-result-v1",
                "operation_id": context.operation_id,
                "request_sha256": context.request_sha256,
                "folderbase_id": plan.version().folderbase_id(),
                "folderbase_version_id": plan.version().version_id(),
                "canonical_version_sha256": plan.canonical_version_sha256(),
                "package_index_sha256": plan.package_index_sha256(),
                "verified_object_count": verified_object_count,
                "version_authenticated_object_count": version_authenticated_object_count,
                "retained_tombstone_object_count": retained_tombstone_object_count,
                "visible_entry_count": plan.visible_entry_count(),
                "verified_opaque_bytes": plan.total_object_bytes(),
                "root_attestation": result.attestation(),
                "replayed": result.replayed(),
            }))
        }
        Err(RootReconstructionError::DestinationOccupied(path)) => attention_transport(
            &context,
            "destination_occupied",
            format!("destination is already occupied: {}", path.display()),
            false,
        ),
        Err(error) => core_error_transport(error, Some(&context)),
    }
}

pub(crate) fn invalid_invocation(message: impl Into<String>) -> RootReconstructionTransport {
    error_transport("invalid_invocation", message.into(), None)
}

pub(crate) fn output_failed(message: impl Into<String>) -> RootReconstructionTransport {
    error_transport("output_failed", message.into(), None)
}

fn read_request(mut input: impl Read) -> Result<RootReconstructionRequest, String> {
    let mut bytes = Vec::new();
    input
        .by_ref()
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("failed to read reconstruction request: {error}"))?;
    if bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err(format!(
            "reconstruction request exceeds {MAX_REQUEST_BYTES} bytes"
        ));
    }
    serde_json::from_slice(&bytes)
        .map_err(|error| format!("reconstruction request is not valid closed JSON: {error}"))
}

fn public_crash_phase(phase: RootReconstructionPhase) -> Option<&'static str> {
    match phase {
        RootReconstructionPhase::StageEntryDurable => None,
        RootReconstructionPhase::PreparedJournal => Some("prepared-journal"),
        RootReconstructionPhase::VerifiedStaging => Some("verified-staging"),
        RootReconstructionPhase::Publication => Some("publication"),
        RootReconstructionPhase::CompletionDurable => Some("completion-record"),
    }
}

fn core_error_transport(
    error: RootReconstructionError,
    context: Option<&RequestContext>,
) -> RootReconstructionTransport {
    let code = match &error {
        RootReconstructionError::InvalidOperation => "invalid_request",
        RootReconstructionError::PackageIndexPinMismatch => "package_index_mismatch",
        RootReconstructionError::InvalidDestination => "unsafe_destination",
        RootReconstructionError::DestinationOccupied(_) => "reconstruction_failed",
        RootReconstructionError::OperationConflict => "operation_id_conflict",
        RootReconstructionError::PackageChanged(_) => "package_changed",
        RootReconstructionError::UnsafePackage(_) => "unsafe_package",
        RootReconstructionError::UnsupportedReconstructionFilesystem { .. } => {
            "unsupported_reconstruction_filesystem"
        }
        RootReconstructionError::IndexReader(_)
        | RootReconstructionError::IndexTooLarge { .. }
        | RootReconstructionError::InvalidIndexJson(_)
        | RootReconstructionError::LimitsMismatch
        | RootReconstructionError::UnknownFormat
        | RootReconstructionError::TooManyReferences { .. } => "invalid_package",
        RootReconstructionError::VersionReader(_)
        | RootReconstructionError::VersionTooLarge { .. }
        | RootReconstructionError::InvalidVersion(_) => "invalid_folderbase_version",
        RootReconstructionError::FolderbaseIdMismatch => "folderbase_mismatch",
        RootReconstructionError::VersionIdMismatch => "version_mismatch",
        RootReconstructionError::EncodedVersionDigestMismatch
        | RootReconstructionError::CanonicalVersionDigestMismatch => "package_changed",
        RootReconstructionError::ReferencesOutOfOrder
        | RootReconstructionError::DuplicateReference { .. }
        | RootReconstructionError::InvalidReferenceRoles { .. }
        | RootReconstructionError::UnexpectedReference { .. }
        | RootReconstructionError::MissingReference { .. }
        | RootReconstructionError::ReferenceMismatch { .. }
        | RootReconstructionError::InvalidManifestDigest { .. }
        | RootReconstructionError::TombstoneFidelityMismatch => "reference_closure_invalid",
        RootReconstructionError::TooManyManifests { .. }
        | RootReconstructionError::UnreferencedManifest { .. }
        | RootReconstructionError::DuplicateManifest { .. }
        | RootReconstructionError::MissingManifest { .. }
        | RootReconstructionError::InvalidManifest { .. }
        | RootReconstructionError::ManifestDigestMismatch { .. }
        | RootReconstructionError::TooManyDistinctChunks { .. }
        | RootReconstructionError::ManifestObjectMismatch { .. }
        | RootReconstructionError::TotalObjectBytesTooLarge { .. } => "manifest_invalid",
        RootReconstructionError::ObjectVerification(error) => match error {
            folderbase_core::transfer_manifest::ObjectVerificationError::ObjectLengthMismatch {
                ..
            }
            | folderbase_core::transfer_manifest::ObjectVerificationError::ObjectDigestMismatch
            | folderbase_core::transfer_manifest::ObjectVerificationError::ChunkPlanMismatch => {
                "chunk_invalid"
            }
            folderbase_core::transfer_manifest::ObjectVerificationError::InvalidManifest(_)
            | folderbase_core::transfer_manifest::ObjectVerificationError::Reader(_)
            | folderbase_core::transfer_manifest::ObjectVerificationError::Writer(_)
            | folderbase_core::transfer_manifest::ObjectVerificationError::ObjectTooLarge {
                ..
            } => "object_verification_failed",
        },
        RootReconstructionError::Filesystem(_)
        | RootReconstructionError::History(_)
        | RootReconstructionError::Attestation(_)
        | RootReconstructionError::Io { .. } => "reconstruction_failed",
    };
    error_transport(code, error.to_string(), context)
}

fn success_transport(document: &impl Serialize) -> RootReconstructionTransport {
    match encode_document(document) {
        Ok(stdout) => RootReconstructionTransport {
            exit_code: EXIT_SUCCESS,
            stdout,
            stderr: Vec::new(),
        },
        Err(message) => error_transport("output_failed", message, None),
    }
}

fn attention_transport(
    context: &RequestContext,
    code: &'static str,
    message: String,
    retryable: bool,
) -> RootReconstructionTransport {
    let document = serde_json::json!({
        "format": "folderbase-root-reconstruction-attention-v1",
        "operation_id": context.operation_id,
        "request_sha256": context.request_sha256,
        "package_index_sha256": context.package_index_sha256,
        "attention": {
            "code": code,
            "message": bounded_message(message),
            "retryable": retryable,
        }
    });
    match encode_document(&document) {
        Ok(stdout) => RootReconstructionTransport {
            exit_code: EXIT_ATTENTION,
            stdout,
            stderr: Vec::new(),
        },
        Err(message) => error_transport("output_failed", message, Some(context)),
    }
}

fn error_transport(
    code: &'static str,
    message: String,
    context: Option<&RequestContext>,
) -> RootReconstructionTransport {
    let document = ErrorDocument {
        format: "folderbase-root-reconstruction-error-v1",
        operation_id: context.map(|value| value.operation_id.as_str()),
        request_sha256: context.map(|value| value.request_sha256.as_str()),
        package_index_sha256: context.map(|value| value.package_index_sha256.as_str()),
        error: ErrorDetail {
            code,
            message: bounded_message(message),
        },
    };
    let stderr = encode_document(&document).unwrap_or_else(|_| {
        b"{\"format\":\"folderbase-root-reconstruction-error-v1\",\"error\":{\"code\":\"output_failed\",\"message\":\"failed to encode bounded error\"}}\n".to_vec()
    });
    RootReconstructionTransport {
        exit_code: EXIT_OPERATIONAL_ERROR,
        stdout: Vec::new(),
        stderr,
    }
}

fn encode_document(document: &impl Serialize) -> Result<Vec<u8>, String> {
    let mut encoded = serde_json::to_vec(document)
        .map_err(|error| format!("failed to serialize reconstruction output: {error}"))?;
    encoded
        .write_all(b"\n")
        .map_err(|error| format!("failed to terminate reconstruction output: {error}"))?;
    if encoded.len() > MAX_OUTPUT_BYTES {
        return Err(format!(
            "reconstruction output exceeds {MAX_OUTPUT_BYTES} bytes"
        ));
    }
    Ok(encoded)
}

fn bounded_message(message: impl Into<String>) -> String {
    message.into().chars().take(MAX_MESSAGE_SCALARS).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use folderbase_core::transfer_manifest::ObjectVerificationError;

    #[test]
    fn public_crash_seam_excludes_the_internal_stage_entry_phase() {
        assert_eq!(
            public_crash_phase(RootReconstructionPhase::StageEntryDurable),
            None
        );
        assert_eq!(
            public_crash_phase(RootReconstructionPhase::PreparedJournal),
            Some("prepared-journal")
        );
        assert_eq!(
            public_crash_phase(RootReconstructionPhase::VerifiedStaging),
            Some("verified-staging")
        );
        assert_eq!(
            public_crash_phase(RootReconstructionPhase::Publication),
            Some("publication")
        );
        assert_eq!(
            public_crash_phase(RootReconstructionPhase::CompletionDurable),
            Some("completion-record")
        );
    }

    #[test]
    fn non_chunk_object_verification_failure_uses_its_stable_public_code() {
        let transport = core_error_transport(
            RootReconstructionError::ObjectVerification(ObjectVerificationError::Reader(
                std::io::Error::other("bounded reader failed"),
            )),
            None,
        );
        let document: serde_json::Value =
            serde_json::from_slice(&transport.stderr).expect("typed error document");

        assert_eq!(transport.exit_code, EXIT_OPERATIONAL_ERROR);
        assert_eq!(document["error"]["code"], "object_verification_failed");
    }

    #[test]
    fn corrupt_chunk_verification_keeps_the_chunk_invalid_public_code() {
        let transport = core_error_transport(
            RootReconstructionError::ObjectVerification(
                ObjectVerificationError::ObjectDigestMismatch,
            ),
            None,
        );
        let document: serde_json::Value =
            serde_json::from_slice(&transport.stderr).expect("typed error document");

        assert_eq!(transport.exit_code, EXIT_OPERATIONAL_ERROR);
        assert_eq!(document["error"]["code"], "chunk_invalid");
    }
}

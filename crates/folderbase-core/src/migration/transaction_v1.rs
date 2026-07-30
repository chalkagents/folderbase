use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{MigrationOperation, MigrationPlan};
use crate::{FolderbaseError, Result};

pub(super) const FORMAT: &str = "folderbase-migration-transaction-v1";
pub(super) const PROGRAM_FORMAT: &str = "folderbase-mutation-program-v1";
pub(super) const TRANSACTION_DIRECTORY: &str = "transaction-v1";
pub(super) const MAX_PROGRAM_BYTES: u64 = 8 * 1024 * 1024;
pub(super) const MAX_JOURNAL_GENERATION_BYTES: u64 = 2 * 1024 * 1024;

const PROGRAM_DIGEST_DOMAIN: &[u8] = b"folderbase-mutation-program-v1";
const JOURNAL_CHECKSUM_DOMAIN: &[u8] = b"folderbase-migration-journal-generation-v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct MutationProgramV1 {
    format: String,
    transaction_id: String,
    approval_digest: String,
    folderbase_root: PathBuf,
    root_identity_sha256: String,
    manifest_sha256: String,
    path_profile: String,
    durability_profile: String,
    operations: Vec<MutationProgramOperationV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct MutationProgramOperationV1 {
    index: usize,
    operation: MigrationOperation,
    source_path: Option<PathBuf>,
    destination_path: Option<PathBuf>,
    expected_source_sha256: Option<String>,
    expected_result_sha256: Option<String>,
    expected_source_identity_sha256: Option<String>,
    private_stage_path: PathBuf,
    private_claim_path: PathBuf,
    private_snapshot_path: PathBuf,
}

impl MutationProgramV1 {
    pub(super) fn compile(
        plan: &MigrationPlan,
        approval_digest: &str,
        root_identity_sha256: String,
        manifest_sha256: String,
        mut source_identity: impl FnMut(&Path) -> Result<Option<String>>,
    ) -> Result<Self> {
        let operations = plan
            .operations
            .iter()
            .enumerate()
            .map(|(index, operation)| {
                let source_path = operation_source_path(operation);
                let destination_path = operation_destination_path(operation);
                let expected_source_identity_sha256 = source_path
                    .as_deref()
                    .map(&mut source_identity)
                    .transpose()?
                    .flatten();
                let operation_name = format!("{index:08}");
                Ok(MutationProgramOperationV1 {
                    index,
                    operation: operation.clone(),
                    source_path,
                    destination_path,
                    expected_source_sha256: operation_expected_source(operation),
                    expected_result_sha256: operation_expected_result(operation),
                    expected_source_identity_sha256,
                    private_stage_path: PathBuf::from("stages")
                        .join(format!("{operation_name}.stage")),
                    private_claim_path: PathBuf::from("claims")
                        .join(format!("{operation_name}.claim")),
                    private_snapshot_path: PathBuf::from("snapshots")
                        .join(format!("{operation_name}.snapshot")),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let program = Self {
            format: PROGRAM_FORMAT.to_owned(),
            transaction_id: plan.id.clone(),
            approval_digest: approval_digest.to_owned(),
            folderbase_root: plan.root.clone(),
            root_identity_sha256,
            manifest_sha256,
            path_profile: "folderbase-portable-path-v1".to_owned(),
            durability_profile: durability_profile().to_owned(),
            operations,
        };
        program.validate()?;
        Ok(program)
    }

    pub(super) fn decode(path: &Path, bytes: &[u8]) -> Result<Self> {
        if bytes.len() as u64 > MAX_PROGRAM_BYTES {
            return Err(invalid(path, "mutation program exceeds its byte bound"));
        }
        let program: Self =
            serde_json::from_slice(bytes).map_err(|source| FolderbaseError::json(path, source))?;
        program.validate()?;
        Ok(program)
    }

    pub(super) fn encode(&self, path: &Path) -> Result<Vec<u8>> {
        self.validate()?;
        let bytes =
            serde_json::to_vec(self).map_err(|source| FolderbaseError::json(path, source))?;
        if bytes.len() as u64 > MAX_PROGRAM_BYTES {
            return Err(invalid(path, "mutation program exceeds its byte bound"));
        }
        Ok(bytes)
    }

    pub(super) fn digest(&self, path: &Path) -> Result<String> {
        let bytes = self.encode(path)?;
        let mut digest = Sha256::new();
        digest.update(PROGRAM_DIGEST_DOMAIN);
        digest.update([0]);
        digest.update(bytes);
        Ok(format!("{:x}", digest.finalize()))
    }

    pub(super) fn transaction_id(&self) -> &str {
        &self.transaction_id
    }

    pub(super) fn operation_count(&self) -> usize {
        self.operations.len()
    }

    fn validate(&self) -> Result<()> {
        let path = &self.folderbase_root;
        if self.format != PROGRAM_FORMAT
            || self.transaction_id.is_empty()
            || !is_sha256(&self.approval_digest)
            || !is_sha256(&self.root_identity_sha256)
            || !is_sha256(&self.manifest_sha256)
            || self.path_profile != "folderbase-portable-path-v1"
            || self.durability_profile != durability_profile()
            || self
                .operations
                .iter()
                .enumerate()
                .any(|(index, operation)| operation.index != index)
        {
            return Err(invalid(path, "mutation program metadata is inconsistent"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum TransactionDirectionV1 {
    Apply,
    Rollback,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum TransactionPhaseV1 {
    Prepared,
    Applying,
    Applied,
    RollbackRequested,
    RollingBack,
    RolledBack,
    Conflicted,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct TransactionJournalGenerationV1 {
    format: String,
    transaction_id: String,
    program_digest: String,
    generation: u64,
    previous_checksum: Option<String>,
    direction: TransactionDirectionV1,
    phase: TransactionPhaseV1,
    operation_cursor: usize,
    in_flight_operation: Option<usize>,
    receipts: Vec<MutationReceiptV1>,
    conflicts: Vec<MutationConflictEvidenceV1>,
    checksum: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct MutationReceiptV1 {
    operation_index: usize,
    published_identity_sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct MutationConflictEvidenceV1 {
    operation_index: Option<usize>,
    affected_paths: Vec<PathBuf>,
    expected: String,
    observed: String,
    preserved_artifact: Option<PathBuf>,
}

impl TransactionJournalGenerationV1 {
    pub(super) fn prepared(program: &MutationProgramV1, program_digest: String) -> Result<Self> {
        let mut generation = Self {
            format: FORMAT.to_owned(),
            transaction_id: program.transaction_id().to_owned(),
            program_digest,
            generation: 0,
            previous_checksum: None,
            direction: TransactionDirectionV1::Apply,
            phase: TransactionPhaseV1::Prepared,
            operation_cursor: 0,
            in_flight_operation: None,
            receipts: Vec::new(),
            conflicts: Vec::new(),
            checksum: String::new(),
        };
        generation.checksum = generation.calculate_checksum()?;
        generation.validate(program)?;
        Ok(generation)
    }

    pub(super) fn decode(path: &Path, bytes: &[u8]) -> Result<Self> {
        if bytes.len() as u64 > MAX_JOURNAL_GENERATION_BYTES {
            return Err(invalid(path, "journal generation exceeds its byte bound"));
        }
        serde_json::from_slice(bytes).map_err(|source| FolderbaseError::json(path, source))
    }

    pub(super) fn encode(&self, path: &Path) -> Result<Vec<u8>> {
        let bytes =
            serde_json::to_vec(self).map_err(|source| FolderbaseError::json(path, source))?;
        if bytes.len() as u64 > MAX_JOURNAL_GENERATION_BYTES {
            return Err(invalid(path, "journal generation exceeds its byte bound"));
        }
        Ok(bytes)
    }

    pub(super) fn file_name(&self) -> String {
        format!("{:020}.json", self.generation)
    }

    pub(super) fn checksum(&self) -> &str {
        &self.checksum
    }

    pub(super) fn generation(&self) -> u64 {
        self.generation
    }

    pub(super) fn program_digest(&self) -> &str {
        &self.program_digest
    }

    fn calculate_checksum(&self) -> Result<String> {
        let path = Path::new("<migration-journal-generation-v1>");
        let controlled = (
            &self.format,
            &self.transaction_id,
            &self.program_digest,
            self.generation,
            &self.previous_checksum,
            self.direction,
            self.phase,
            self.operation_cursor,
            self.in_flight_operation,
            &self.receipts,
            &self.conflicts,
        );
        let bytes = serde_json::to_vec(&controlled)
            .map_err(|source| FolderbaseError::json(path, source))?;
        let mut checksum = Sha256::new();
        checksum.update(JOURNAL_CHECKSUM_DOMAIN);
        checksum.update([0]);
        checksum.update(bytes);
        Ok(format!("{:x}", checksum.finalize()))
    }

    fn validate(&self, program: &MutationProgramV1) -> Result<()> {
        let path = Path::new("<migration-journal-generation-v1>");
        if self.format != FORMAT
            || self.transaction_id != program.transaction_id()
            || !is_sha256(&self.program_digest)
            || self.operation_cursor > program.operation_count()
            || self
                .in_flight_operation
                .is_some_and(|index| index >= program.operation_count())
            || self
                .receipts
                .iter()
                .any(|receipt| receipt.operation_index >= program.operation_count())
            || self.checksum != self.calculate_checksum()?
        {
            return Err(invalid(path, "journal generation is inconsistent"));
        }
        Ok(())
    }
}

pub(super) fn validate_chain(
    program: &MutationProgramV1,
    program_digest: &str,
    generations: &[TransactionJournalGenerationV1],
) -> Result<()> {
    if generations.is_empty() {
        return Err(invalid(
            Path::new("<migration-journal-v1>"),
            "journal chain is empty",
        ));
    }
    let mut previous = None;
    for (index, generation) in generations.iter().enumerate() {
        generation.validate(program)?;
        if generation.generation() != index as u64
            || generation.program_digest() != program_digest
            || generation.previous_checksum.as_deref() != previous
        {
            return Err(invalid(
                Path::new("<migration-journal-v1>"),
                "journal generation chain is inconsistent",
            ));
        }
        previous = Some(generation.checksum());
    }
    Ok(())
}

fn operation_source_path(operation: &MigrationOperation) -> Option<PathBuf> {
    match operation {
        MigrationOperation::CopyFile { source_path, .. } => Some(source_path.clone()),
        operation if operation.is_structural() => {
            operation.structural_source_path().map(Path::to_path_buf)
        }
        _ => None,
    }
}

fn operation_destination_path(operation: &MigrationOperation) -> Option<PathBuf> {
    match operation {
        MigrationOperation::CreateFolder { path } => Some(path.clone()),
        MigrationOperation::CopyFile {
            destination_path, ..
        } => Some(destination_path.clone()),
        operation if operation.is_structural() => operation
            .structural_destination_path()
            .map(Path::to_path_buf),
        _ => None,
    }
}

fn operation_expected_source(operation: &MigrationOperation) -> Option<String> {
    match operation {
        MigrationOperation::CopyFile {
            expected_sha256, ..
        } => Some(expected_sha256.clone()),
        operation if operation.is_structural() => {
            operation.structural_expected_sha256().map(str::to_owned)
        }
        _ => None,
    }
}

fn operation_expected_result(operation: &MigrationOperation) -> Option<String> {
    match operation {
        MigrationOperation::CopyFile {
            expected_sha256, ..
        }
        | MigrationOperation::MoveObject {
            expected_sha256, ..
        } => Some(expected_sha256.clone()),
        operation if operation.is_structural() => operation
            .structural_expected_result_sha256()
            .map(str::to_owned),
        _ => None,
    }
}

fn durability_profile() -> &'static str {
    #[cfg(unix)]
    {
        "folderbase-unix-fsync-v1"
    }
    #[cfg(windows)]
    {
        "folderbase-windows-flush-v1"
    }
    #[cfg(not(any(unix, windows)))]
    {
        "folderbase-generic-sync-v1"
    }
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn invalid(path: &Path, message: impl Into<String>) -> FolderbaseError {
    FolderbaseError::InvalidRecord {
        path: path.to_path_buf(),
        message: message.into(),
    }
}

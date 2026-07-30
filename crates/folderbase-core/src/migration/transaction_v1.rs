use std::{
    collections::BTreeSet,
    ffi::OsString,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{MigrationOperation, MigrationPlan};
use crate::{FolderbaseError, Result};

pub(super) const FORMAT: &str = "folderbase-migration-transaction-v1";
pub(super) const PROGRAM_FORMAT: &str = "folderbase-mutation-program-v1";
pub(super) const TRANSACTION_DIRECTORY: &str = "transaction-v1";
pub(super) const MAX_PROGRAM_BYTES: u64 = 8 * 1024 * 1024;
pub(super) const MAX_JOURNAL_GENERATION_BYTES: u64 = 2 * 1024 * 1024;
const MAX_JOURNAL_GENERATIONS: usize = 65_536;
const JOURNAL_GENERATIONS_PER_OPERATION: usize = 4;
const JOURNAL_GENERATION_OVERHEAD: usize = 6;

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
        if program.encode(path)? != bytes {
            return Err(invalid(
                path,
                "mutation program is not the exact canonical admitted encoding",
            ));
        }
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

    pub(super) fn maximum_journal_generations(&self) -> usize {
        self.operations
            .len()
            .saturating_mul(JOURNAL_GENERATIONS_PER_OPERATION)
            .saturating_add(JOURNAL_GENERATION_OVERHEAD)
            .min(MAX_JOURNAL_GENERATIONS)
    }

    pub(super) fn expected_source_identities(&self) -> Vec<Option<String>> {
        self.operations
            .iter()
            .map(|operation| operation.expected_source_identity_sha256.clone())
            .collect()
    }

    pub(super) fn allowed_private_file_names(&self, directory: &str) -> BTreeSet<OsString> {
        self.operations
            .iter()
            .filter_map(|operation| {
                let path = match directory {
                    "stages" => &operation.private_stage_path,
                    "claims" => &operation.private_claim_path,
                    "snapshots" => &operation.private_snapshot_path,
                    "receipts" => {
                        return Some(OsString::from(format!("{:08}.receipt", operation.index)));
                    }
                    _ => return None,
                };
                path.file_name().map(OsString::from)
            })
            .collect()
    }

    fn validate(&self) -> Result<()> {
        let path = &self.folderbase_root;
        let journal_generation_bound = self
            .operations
            .len()
            .checked_mul(JOURNAL_GENERATIONS_PER_OPERATION)
            .and_then(|count| count.checked_add(JOURNAL_GENERATION_OVERHEAD));
        if self.format != PROGRAM_FORMAT
            || !self.transaction_id.starts_with("migration_")
            || !is_sha256(&self.approval_digest)
            || !is_sha256(&self.root_identity_sha256)
            || !is_sha256(&self.manifest_sha256)
            || self.path_profile != "folderbase-portable-path-v1"
            || self.durability_profile != durability_profile()
            || journal_generation_bound.is_none_or(|count| count > MAX_JOURNAL_GENERATIONS)
            || self
                .operations
                .iter()
                .enumerate()
                .any(|(index, operation)| operation.index != index)
        {
            return Err(invalid(path, "mutation program metadata is inconsistent"));
        }
        for (index, operation) in self.operations.iter().enumerate() {
            let operation_name = format!("{index:08}");
            let expected_stage = PathBuf::from("stages").join(format!("{operation_name}.stage"));
            let expected_claim = PathBuf::from("claims").join(format!("{operation_name}.claim"));
            let expected_snapshot =
                PathBuf::from("snapshots").join(format!("{operation_name}.snapshot"));
            if operation.source_path != operation_source_path(&operation.operation)
                || operation.destination_path != operation_destination_path(&operation.operation)
                || operation.expected_source_sha256
                    != operation_expected_source(&operation.operation)
                || operation.expected_result_sha256
                    != operation_expected_result(&operation.operation)
                || operation.private_stage_path != expected_stage
                || operation.private_claim_path != expected_claim
                || operation.private_snapshot_path != expected_snapshot
                || operation
                    .source_path
                    .as_deref()
                    .is_some_and(|path| !safe_relative(path))
                || operation
                    .destination_path
                    .as_deref()
                    .is_some_and(|path| !safe_relative(path))
                || !safe_relative(&operation.private_stage_path)
                || !safe_relative(&operation.private_claim_path)
                || !safe_relative(&operation.private_snapshot_path)
                || operation
                    .expected_source_sha256
                    .as_deref()
                    .is_some_and(|digest| !is_sha256(digest))
                || operation
                    .expected_result_sha256
                    .as_deref()
                    .is_some_and(|digest| !is_sha256(digest))
                || operation
                    .expected_source_identity_sha256
                    .as_deref()
                    .is_some_and(|digest| !is_sha256(digest))
            {
                return Err(invalid(path, "mutation program operation is inconsistent"));
            }
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
        let generation: Self =
            serde_json::from_slice(bytes).map_err(|source| FolderbaseError::json(path, source))?;
        if generation.encode(path)? != bytes {
            return Err(invalid(
                path,
                "journal generation is not the exact canonical admitted encoding",
            ));
        }
        Ok(generation)
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

    pub(super) fn next_apply_intent(
        &self,
        program: &MutationProgramV1,
        operation_index: usize,
    ) -> Result<Self> {
        if operation_index != self.operation_cursor || operation_index >= program.operation_count()
        {
            return Err(invalid(
                Path::new("<migration-journal-v1>"),
                "apply intent is outside the next program operation",
            ));
        }
        self.next(
            program,
            TransactionDirectionV1::Apply,
            TransactionPhaseV1::Applying,
            operation_index,
            Some(operation_index),
            None,
        )
    }

    pub(super) fn next_apply_receipt(
        &self,
        program: &MutationProgramV1,
        operation_index: usize,
        published_identity_sha256: Option<String>,
    ) -> Result<Self> {
        if self.in_flight_operation != Some(operation_index) {
            return Err(invalid(
                Path::new("<migration-journal-v1>"),
                "apply receipt does not match the durable in-flight operation",
            ));
        }
        self.next(
            program,
            TransactionDirectionV1::Apply,
            TransactionPhaseV1::Applying,
            operation_index + 1,
            None,
            Some(MutationReceiptV1 {
                operation_index,
                published_identity_sha256,
            }),
        )
    }

    pub(super) fn next_applied(&self, program: &MutationProgramV1) -> Result<Self> {
        if self.operation_cursor != program.operation_count() || self.in_flight_operation.is_some()
        {
            return Err(invalid(
                Path::new("<migration-journal-v1>"),
                "applied state requires every program operation receipt",
            ));
        }
        self.next(
            program,
            TransactionDirectionV1::Apply,
            TransactionPhaseV1::Applied,
            self.operation_cursor,
            None,
            None,
        )
    }

    fn next(
        &self,
        program: &MutationProgramV1,
        direction: TransactionDirectionV1,
        phase: TransactionPhaseV1,
        operation_cursor: usize,
        in_flight_operation: Option<usize>,
        receipt: Option<MutationReceiptV1>,
    ) -> Result<Self> {
        let mut receipts = self.receipts.clone();
        if let Some(receipt) = receipt {
            if receipts
                .iter()
                .any(|existing| existing.operation_index == receipt.operation_index)
            {
                return Err(invalid(
                    Path::new("<migration-journal-v1>"),
                    "journal contains a duplicate operation receipt",
                ));
            }
            receipts.push(receipt);
        }
        let mut next = Self {
            format: FORMAT.to_owned(),
            transaction_id: self.transaction_id.clone(),
            program_digest: self.program_digest.clone(),
            generation: self.generation + 1,
            previous_checksum: Some(self.checksum.clone()),
            direction,
            phase,
            operation_cursor,
            in_flight_operation,
            receipts,
            conflicts: self.conflicts.clone(),
            checksum: String::new(),
        };
        next.checksum = next.calculate_checksum()?;
        next.validate(program)?;
        Ok(next)
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
            || self
                .receipts
                .iter()
                .enumerate()
                .any(|(index, receipt)| receipt.operation_index != index)
            || self.receipts.len() != self.operation_cursor
            || self.receipts.iter().any(|receipt| {
                receipt
                    .published_identity_sha256
                    .as_deref()
                    .is_some_and(|digest| !is_sha256(digest))
            })
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
    if generations.is_empty() || generations.len() > program.maximum_journal_generations() {
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
        if index == 0 {
            if generation.direction != TransactionDirectionV1::Apply
                || generation.phase != TransactionPhaseV1::Prepared
                || generation.operation_cursor != 0
                || generation.in_flight_operation.is_some()
                || !generation.receipts.is_empty()
                || !generation.conflicts.is_empty()
            {
                return Err(invalid(
                    Path::new("<migration-journal-v1>"),
                    "journal does not begin with the prepared state",
                ));
            }
        } else {
            validate_transition(&generations[index - 1], generation, program)?;
        }
    }
    Ok(())
}

fn validate_transition(
    previous: &TransactionJournalGenerationV1,
    next: &TransactionJournalGenerationV1,
    program: &MutationProgramV1,
) -> Result<()> {
    let apply_intent = next.direction == TransactionDirectionV1::Apply
        && next.phase == TransactionPhaseV1::Applying
        && next.operation_cursor == previous.operation_cursor
        && next.in_flight_operation == Some(previous.operation_cursor)
        && next.receipts == previous.receipts
        && previous.in_flight_operation.is_none()
        && previous.operation_cursor < program.operation_count()
        && matches!(
            previous.phase,
            TransactionPhaseV1::Prepared | TransactionPhaseV1::Applying
        );
    let apply_receipt = next.direction == TransactionDirectionV1::Apply
        && next.phase == TransactionPhaseV1::Applying
        && previous.phase == TransactionPhaseV1::Applying
        && previous.in_flight_operation == Some(previous.operation_cursor)
        && next.in_flight_operation.is_none()
        && next.operation_cursor == previous.operation_cursor + 1
        && next.receipts.len() == previous.receipts.len() + 1
        && next.receipts[..previous.receipts.len()] == previous.receipts
        && next
            .receipts
            .last()
            .is_some_and(|receipt| receipt.operation_index == previous.operation_cursor);
    let applied = next.direction == TransactionDirectionV1::Apply
        && next.phase == TransactionPhaseV1::Applied
        && next.in_flight_operation.is_none()
        && next.operation_cursor == program.operation_count()
        && next.receipts == previous.receipts
        && previous.operation_cursor == program.operation_count()
        && previous.in_flight_operation.is_none()
        && matches!(
            previous.phase,
            TransactionPhaseV1::Prepared | TransactionPhaseV1::Applying
        );
    if apply_intent || apply_receipt || applied {
        return Ok(());
    }
    Err(invalid(
        Path::new("<migration-journal-v1>"),
        "journal contains an illegal state transition",
    ))
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
        "folderbase-windows-same-volume-no-directory-fsync-v1"
    }
    #[cfg(not(any(unix, windows)))]
    {
        "folderbase-generic-sync-v1"
    }
}

fn safe_relative(path: &Path) -> bool {
    !path.as_os_str().is_empty()
        && !path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, std::path::Component::Normal(_)))
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
